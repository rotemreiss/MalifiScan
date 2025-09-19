"""Registry providers module."""

from .jfrog_registry import JFrogRegistry
from .null_registry import NullRegistry

__all__ = ["JFrogRegistry", "NullRegistry"]