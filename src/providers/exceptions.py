"""Provider exceptions."""


class ProviderError(Exception):
    """Base exception for provider errors."""
    pass


class FeedError(ProviderError):
    """Exception raised by feed providers."""
    pass


class RegistryError(ProviderError):
    """Exception raised by registry providers."""
    pass


class NotificationError(ProviderError):
    """Exception raised by notification providers."""
    pass


class StorageError(ProviderError):
    """Exception raised by storage providers."""
    pass