"""Tests for Configuration Management Use Case."""

import pytest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch, mock_open
from src.core.usecases.configuration_management import ConfigurationManagementUseCase


class TestConfigurationManagementUseCase:
    """Test suite for Configuration Management Use Case."""

    def setup_method(self):
        """Set up test fixtures."""
        # Create temporary directory for test files
        self.temp_dir = Path(tempfile.mkdtemp())
        self.config_file = str(self.temp_dir / "config.yaml")
        self.env_file = str(self.temp_dir / ".env")
        self.local_config_file = str(self.temp_dir / "config.local.yaml")
        
        # Create basic config.yaml for testing
        with open(self.config_file, 'w') as f:
            f.write("""
environment: test
debug: false
packages_feed:
  type: osv
  enabled: true
packages_registry:
  type: jfrog
  enabled: false
storage_service:
  type: file
  enabled: true
notification_service:
  type: console
  enabled: false
logging:
  level: INFO
""")
        
        self.use_case = ConfigurationManagementUseCase(
            config_file=self.config_file,
            env_file=self.env_file,
            local_config_file=self.local_config_file
        )

    def teardown_method(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir)

    @pytest.mark.asyncio
    async def test_initialize_configuration_success(self):
        """Test successful configuration initialization."""
        success, message = await self.use_case.initialize_configuration()
        
        assert success is True
        assert "Configuration initialization complete!" in message
        assert Path(self.local_config_file).exists()
        assert Path(self.env_file).exists()

    @pytest.mark.asyncio
    async def test_initialize_configuration_with_existing_files(self):
        """Test configuration initialization when files already exist."""
        # Create existing files
        Path(self.local_config_file).touch()
        Path(self.env_file).touch()
        
        success, message = await self.use_case.initialize_configuration()
        
        assert success is False
        assert "already exists" in message

    @pytest.mark.asyncio
    async def test_initialize_configuration_overwrite_existing(self):
        """Test configuration initialization with overwrite option."""
        # Create existing files
        Path(self.local_config_file).touch()
        Path(self.env_file).touch()
        
        success, message = await self.use_case.initialize_configuration(overwrite_existing=True)
        
        assert success is True
        assert "Configuration initialization complete!" in message

    @pytest.mark.asyncio
    async def test_initialize_configuration_from_template(self):
        """Test configuration initialization from template files."""
        # Create template files
        template_local = Path(f"{self.local_config_file}.example")
        template_env = Path(".env.example")
        
        template_local.write_text("# Template local config")
        template_env.write_text("# Template env file")
        
        success, message = await self.use_case.initialize_configuration()
        
        assert success is True
        assert Path(self.local_config_file).exists()
        assert Path(self.env_file).exists()
        
        # Clean up templates
        template_local.unlink()
        template_env.unlink()

    def test_create_env_file_success(self):
        """Test successful .env file creation."""
        env_path = Path(self.env_file)
        success, message = self.use_case._create_env_file(env_path)
        
        assert success is True
        assert "Created" in message
        assert env_path.exists()

    def test_create_env_file_from_template(self):
        """Test .env file creation from template."""
        # Create template
        template = Path(".env.example")
        template.write_text("TEMPLATE_VAR=value")
        
        env_path = Path(self.env_file)
        success, message = self.use_case._create_env_file(env_path)
        
        assert success is True
        assert "from template" in message
        assert env_path.exists()
        assert "TEMPLATE_VAR=value" in env_path.read_text()
        
        # Clean up template
        template.unlink()

    @pytest.mark.asyncio
    async def test_get_configuration_summary_success(self):
        """Test successful configuration summary retrieval."""
        # Mock the ConfigLoader to avoid dependency issues
        with patch('src.core.usecases.configuration_management.ConfigLoader') as mock_loader:
            mock_config = type('Config', (), {
                'environment': 'test',
                'debug': False,
                'packages_feed': type('Feed', (), {'type': 'osv', 'enabled': True})(),
                'packages_registry': type('Registry', (), {'type': 'jfrog', 'enabled': False})(),
                'storage_service': type('Storage', (), {'type': 'file', 'enabled': True})(),
                'notification_service': type('Notification', (), {'type': 'console', 'enabled': False})(),
                'logging': type('Logging', (), {'level': 'INFO'})(),
                'jfrog_base_url': 'https://test.jfrog.io',
                'jfrog_username': 'testuser',
                'jfrog_api_key': None
            })()
            
            mock_loader.return_value.load.return_value = mock_config
            
            success, summary = await self.use_case.get_configuration_summary()
            
            assert success is True
            assert 'settings' in summary
            assert 'environment_vars' in summary
            assert 'files' in summary
            assert summary['settings']['environment'] == 'test'
            assert summary['settings']['debug'] is False

    @pytest.mark.asyncio
    async def test_get_configuration_summary_error(self):
        """Test configuration summary retrieval with error."""
        with patch('src.core.usecases.configuration_management.ConfigLoader') as mock_loader:
            mock_loader.side_effect = Exception("Config load error")
            
            success, summary = await self.use_case.get_configuration_summary()
            
            assert success is False
            assert summary == {}

    def test_get_configuration_files_status(self):
        """Test configuration files status checking."""
        # Create some files
        Path(self.config_file).touch()
        Path(self.local_config_file).touch()
        
        status = self.use_case._get_configuration_files_status()
        
        assert 'config.yaml' in status
        assert status[Path(self.config_file).name]['exists'] is True
        assert status[self.local_config_file]['exists'] is True
        assert status[self.env_file]['exists'] is False

    @pytest.mark.asyncio
    async def test_validate_configuration_success(self):
        """Test successful configuration validation."""
        with patch('src.core.usecases.configuration_management.ConfigLoader') as mock_loader:
            mock_config = type('Config', (), {
                'packages_registry': type('Registry', (), {'enabled': True})(),
                'packages_feed': type('Feed', (), {'enabled': True})(),
                'storage_service': type('Storage', (), {
                    'type': 'file',
                    'config': {'data_directory': str(self.temp_dir)}
                })(),
                'jfrog_base_url': 'https://test.jfrog.io',
                'jfrog_api_key': 'test_key',
                'jfrog_username': None,
                'jfrog_password': None
            })()
            
            mock_loader.return_value.load.return_value = mock_config
            
            success, results = await self.use_case.validate_configuration()
            
            assert success is True
            assert len(results) > 0
            assert any("Configuration loaded successfully" in r['message'] for r in results)

    @pytest.mark.asyncio
    async def test_validate_configuration_missing_credentials(self):
        """Test configuration validation with missing JFrog credentials."""
        with patch('src.core.usecases.configuration_management.ConfigLoader') as mock_loader:
            mock_config = type('Config', (), {
                'packages_registry': type('Registry', (), {'enabled': True})(),
                'packages_feed': type('Feed', (), {'enabled': True})(),
                'storage_service': type('Storage', (), {
                    'type': 'file',
                    'config': {'data_directory': str(self.temp_dir)}
                })(),
                'jfrog_base_url': 'https://test.jfrog.io',
                'jfrog_api_key': None,
                'jfrog_username': None,
                'jfrog_password': None
            })()
            
            mock_loader.return_value.load.return_value = mock_config
            
            success, results = await self.use_case.validate_configuration()
            
            assert success is False
            assert any("❌" in r['status'] and "credentials not configured" in r['message'] for r in results)

    @pytest.mark.asyncio
    async def test_validate_configuration_load_error(self):
        """Test configuration validation with loading error."""
        with patch('src.core.usecases.configuration_management.ConfigLoader') as mock_loader:
            mock_loader.return_value.load.side_effect = Exception("Load error")
            
            success, results = await self.use_case.validate_configuration()
            
            assert success is False
            assert len(results) == 1
            assert "❌" in results[0]['status']
            assert "Configuration loading failed" in results[0]['message']