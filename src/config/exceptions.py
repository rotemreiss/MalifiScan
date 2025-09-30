"""Configuration exceptions."""


class ConfigError(Exception):
    """Exception raised for configuration-related errors."""

    pass


class ConfigValidationError(ConfigError):
    """Exception raised when configuration validation fails."""

    pass


class ConfigFileNotFoundError(ConfigError):
    """Exception raised when configuration file is not found."""

    pass
