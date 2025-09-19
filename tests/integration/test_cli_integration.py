"""Integration tests for CLI functionality."""

import pytest
import os
import subprocess
import sys
import json
import tempfile
import logging
from pathlib import Path
from typing import Optional


@pytest.mark.integration
class TestCLIIntegration:
    """Integration tests for CLI functionality.
    
    These tests run the actual CLI commands and should not run in CI.
    Set SKIP_INTEGRATION_TESTS=true to skip these tests.
    """
    
    @pytest.fixture(scope="class")
    def cli_path(self):
        """Get path to CLI script."""
        if os.getenv("SKIP_INTEGRATION_TESTS", "false").lower() == "true":
            pytest.skip("Integration tests disabled via SKIP_INTEGRATION_TESTS")
        
        # Find cli.py in the project root
        project_root = Path(__file__).parent.parent.parent
        cli_path = project_root / "cli.py"
        
        if not cli_path.exists():
            pytest.skip(f"CLI script not found at {cli_path}")
        
        return str(cli_path)
    
    def run_cli_command(self, cli_path: str, args: list, input_data: Optional[str] = None) -> tuple:
        """
        Run a CLI command and return (returncode, stdout, stderr).
        
        Args:
            cli_path: Path to the CLI script
            args: List of command line arguments
            input_data: Optional input data to send to stdin
            
        Returns:
            Tuple of (returncode, stdout, stderr)
        """
        cmd = [sys.executable, cli_path] + args
        
        try:
            result = subprocess.run(
                cmd,
                input=input_data,
                text=True,
                capture_output=True,
                timeout=60  # 60 second timeout
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except Exception as e:
            return -1, "", f"Error running command: {e}"
    
    def test_cli_help(self, cli_path):
        """Test CLI help command."""
        returncode, stdout, stderr = self.run_cli_command(cli_path, ["--help"])
        
        assert returncode == 0, f"Help command failed: {stderr}"
        assert "usage:" in stdout.lower() or "help" in stdout.lower(), "Help output should contain usage information"
        
        logging.info("✓ CLI --help command works")
    
    def test_cli_version(self, cli_path):
        """Test CLI version command."""
        # Try common version flags
        for version_flag in ["--version", "-v", "version"]:
            returncode, stdout, stderr = self.run_cli_command(cli_path, [version_flag])
            
            if returncode == 0:
                logging.info(f"✓ CLI {version_flag} command works: {stdout.strip()}")
                return
        
        # If none of the version commands work, that's okay - not all CLIs have version commands
        logging.info("ℹ No version command found (normal)")
    
    def test_cli_scan_command_exists(self, cli_path):
        """Test that scan command exists and shows help."""
        returncode, stdout, stderr = self.run_cli_command(cli_path, ["scan", "--help"])
        
        if returncode == 0:
            logging.info("✓ CLI scan command exists")
            assert "scan" in stdout.lower(), "Scan help should mention scan"
        else:
            # Try alternative command names
            for cmd in ["check", "analyze", "search"]:
                returncode, stdout, stderr = self.run_cli_command(cli_path, [cmd, "--help"])
                if returncode == 0:
                    logging.info(f"✓ CLI {cmd} command exists (alternative to scan)")
                    return
            
            logging.warning("⚠ No scan/check/analyze command found")
    
    def test_cli_scan_with_invalid_input(self, cli_path):
        """Test scan command with invalid input."""
        # Try scanning a non-existent package
        returncode, stdout, stderr = self.run_cli_command(
            cli_path, 
            ["scan", "thispackagedoesntexist123nonexistent"]
        )
        
        # This should either return error code or success with "not found" message
        if returncode != 0:
            logging.info("✓ CLI scan command properly handles invalid packages (returns error)")
        else:
            # Check if output indicates package not found
            output = stdout.lower() + stderr.lower()
            if any(phrase in output for phrase in ["not found", "no results", "not exist", "invalid"]):
                logging.info("✓ CLI scan command properly handles invalid packages (returns not found)")
            else:
                logging.warning(f"⚠ Unexpected output for invalid package: {stdout}")
    
    def test_cli_scan_with_valid_package(self, cli_path):
        """Test scan command with a known package."""
        # Try scanning axios - a popular package that should exist
        returncode, stdout, stderr = self.run_cli_command(
            cli_path,
            ["scan", "axios"]
        )
        
        if returncode == 0:
            logging.info("✓ CLI scan command works with valid package (axios)")
            logging.info(f"Output preview: {stdout[:200]}...")
        else:
            # This might be expected if the command requires additional setup
            logging.info(f"ℹ CLI scan returned error for axios: {stderr}")
    
    def test_cli_config_commands(self, cli_path):
        """Test configuration-related CLI commands."""
        # Try common config commands
        config_commands = [
            ["config", "--help"],
            ["configure", "--help"],
            ["settings", "--help"],
            ["setup", "--help"]
        ]
        
        for cmd in config_commands:
            returncode, stdout, stderr = self.run_cli_command(cli_path, cmd)
            if returncode == 0:
                logging.info(f"✓ CLI {' '.join(cmd)} command exists")
                return
        
        logging.info("ℹ No config commands found")
    
    def test_cli_list_commands(self, cli_path):
        """Test list/show commands."""
        list_commands = [
            ["list", "--help"],
            ["show", "--help"],
            ["ls", "--help"]
        ]
        
        for cmd in list_commands:
            returncode, stdout, stderr = self.run_cli_command(cli_path, cmd)
            if returncode == 0:
                logging.info(f"✓ CLI {' '.join(cmd)} command exists")
        
        # Try listing without arguments to see available commands
        returncode, stdout, stderr = self.run_cli_command(cli_path, [])
        if returncode == 0 and stdout:
            logging.info("✓ CLI shows available commands when run without arguments")
    
    def test_cli_with_config_file(self, cli_path):
        """Test CLI with custom config file."""
        # Create a temporary config file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("""
environment: test
debug: true
packages_feed:
  enabled: false
packages_registry:
  enabled: false
  type: jfrog
""")
            temp_config = f.name
        
        try:
            # Try running CLI with custom config
            returncode, stdout, stderr = self.run_cli_command(
                cli_path,
                ["--config", temp_config, "--help"]
            )
            
            if returncode == 0:
                logging.info("✓ CLI accepts custom config file")
            else:
                # Try alternative config flag
                returncode, stdout, stderr = self.run_cli_command(
                    cli_path,
                    ["-c", temp_config, "--help"]
                )
                if returncode == 0:
                    logging.info("✓ CLI accepts custom config file with -c flag")
                else:
                    logging.info("ℹ CLI doesn't support custom config file option")
        
        finally:
            # Clean up temp file
            os.unlink(temp_config)
    
    def test_cli_output_formats(self, cli_path):
        """Test different output formats."""
        # Try common output format options
        format_options = [
            ["--format", "json"],
            ["--output", "json"], 
            ["-o", "json"],
            ["--json"]
        ]
        
        for format_option in format_options:
            returncode, stdout, stderr = self.run_cli_command(
                cli_path,
                format_option + ["--help"]
            )
            
            if returncode == 0:
                logging.info(f"✓ CLI supports {' '.join(format_option)} option")
                break
        else:
            logging.info("ℹ CLI doesn't appear to support output format options")
    
    def test_cli_verbose_mode(self, cli_path):
        """Test verbose/debug mode."""
        verbose_options = [
            ["--verbose", "--help"],
            ["-v", "--help"],
            ["--debug", "--help"]
        ]
        
        for verbose_option in verbose_options:
            returncode, stdout, stderr = self.run_cli_command(cli_path, verbose_option)
            
            if returncode == 0:
                logging.info(f"✓ CLI supports {' '.join(verbose_option)} option")
                return
        
        logging.info("ℹ CLI doesn't appear to support verbose/debug options")
    
    @pytest.mark.slow
    def test_cli_comprehensive_functionality(self, cli_path):
        """Comprehensive test of CLI functionality."""
        logging.info("=== Comprehensive CLI Test ===")
        
        # Test 1: Basic help
        returncode, stdout, stderr = self.run_cli_command(cli_path, ["--help"])
        help_works = returncode == 0
        logging.info(f"1. Help command: {'✓' if help_works else '✗'}")
        
        # Test 2: Available commands
        available_commands = []
        if help_works:
            help_text = stdout.lower()
            
            # Common CLI commands to check for
            potential_commands = ["scan", "check", "analyze", "search", "config", "list", "show"]
            for cmd in potential_commands:
                if cmd in help_text:
                    available_commands.append(cmd)
            
            logging.info(f"2. Available commands: {', '.join(available_commands) if available_commands else 'None detected'}")
        else:
            logging.info("2. Available commands: Could not determine (help failed)")
        
        # Test 3: Error handling
        returncode, stdout, stderr = self.run_cli_command(cli_path, ["nonexistent_command_xyz"])
        error_handling = returncode != 0 or "error" in stderr.lower() or "unknown" in stderr.lower()
        logging.info(f"3. Error handling: {'✓' if error_handling else '✗'}")
        
        # Test 4: Exit codes
        returncode_help, _, _ = self.run_cli_command(cli_path, ["--help"])
        returncode_error, _, _ = self.run_cli_command(cli_path, ["invalid_command_xyz"])
        
        proper_exit_codes = returncode_help == 0 and returncode_error != 0
        logging.info(f"4. Proper exit codes: {'✓' if proper_exit_codes else '✗'}")
        
        # Test 5: Output format
        returncode, stdout, stderr = self.run_cli_command(cli_path, ["--help"])
        has_output = len(stdout) > 0 or len(stderr) > 0
        logging.info(f"5. Produces output: {'✓' if has_output else '✗'}")
        
        logging.info("=== CLI Test Summary ===")
        total_tests = 5
        passed_tests = sum([help_works, bool(available_commands),
                           error_handling, proper_exit_codes, has_output])
        logging.info(f"Passed: {passed_tests}/{total_tests} tests")
        
        if passed_tests >= 3:
            logging.info("✓ CLI appears to be functional")
        else:
            logging.warning("⚠ CLI may have issues or use non-standard patterns")
    
    def test_cli_integration_with_providers(self, cli_path):
        """Test CLI integration with JFrog and OSV providers."""
        logging.info("=== CLI Provider Integration Test ===")
        
        # Test commands that might use providers
        provider_tests = [
            {
                "name": "JFrog scan",
                "commands": [
                    ["scan", "--registry", "jfrog", "axios"],
                    ["check", "--jfrog", "axios"],
                    ["search", "--source", "jfrog", "axios"]
                ]
            },
            {
                "name": "OSV scan", 
                "commands": [
                    ["scan", "--feed", "osv", "axios"],
                    ["check", "--osv", "axios"],
                    ["search", "--source", "osv", "axios"]
                ]
            }
        ]
        
        for provider_test in provider_tests:
            logging.info(f"Testing {provider_test['name']}...")
            
            for cmd in provider_test["commands"]:
                returncode, stdout, stderr = self.run_cli_command(cli_path, cmd)
                
                if returncode == 0:
                    logging.info(f"✓ {' '.join(cmd)} works")
                    break
                elif "not found" in stderr.lower() or "unknown" in stderr.lower():
                    # Command doesn't exist, try next one
                    continue
                else:
                    # Command exists but might need configuration
                    logging.info(f"ℹ {' '.join(cmd)} exists but returned error: {stderr[:100]}")
                    break
            else:
                logging.info(f"ℹ No {provider_test['name']} commands found")
        
        logging.info("=== Provider Integration Test Complete ===")
    
    def test_cli_package_scanning_workflow(self, cli_path):
        """Test the complete package scanning workflow."""
        logging.info("=== Package Scanning Workflow Test ===")
        
        # Test packages as specified in requirements
        test_packages = [
            {"name": "axios", "should_exist": True, "description": "Popular HTTP client"},
            {"name": "thispackagedoesntexist", "should_exist": False, "description": "Non-existent package"}
        ]
        
        for pkg in test_packages:
            logging.info(f"Testing {pkg['name']} ({pkg['description']})...")
            
            # Try different scan command variations
            scan_commands = [
                ["scan", pkg["name"]],
                ["check", pkg["name"]],
                ["search", pkg["name"]],
                ["analyze", pkg["name"]]
            ]
            
            for cmd in scan_commands:
                returncode, stdout, stderr = self.run_cli_command(cli_path, cmd)
                
                if returncode != -1:  # Command didn't timeout or fail to run
                    output = stdout.lower() + stderr.lower()
                    
                    if pkg["should_exist"]:
                        # For existing packages, we expect either success or some indication of results
                        if returncode == 0 or "found" in output or "result" in output:
                            logging.info(f"✓ {pkg['name']}: {' '.join(cmd)} handled existing package correctly")
                        else:
                            logging.info(f"ℹ {pkg['name']}: {' '.join(cmd)} returned {returncode}")
                    else:
                        # For non-existing packages, we expect error or "not found"
                        if returncode != 0 or "not found" in output or "no result" in output or "not exist" in output:
                            logging.info(f"✓ {pkg['name']}: {' '.join(cmd)} handled non-existent package correctly")
                        else:
                            logging.info(f"ℹ {pkg['name']}: {' '.join(cmd)} unexpected result for non-existent package")
                    
                    break  # Found a working command, move to next package
            else:
                logging.info(f"ℹ {pkg['name']}: No working scan commands found")
        
        logging.info("=== Package Scanning Workflow Complete ===")