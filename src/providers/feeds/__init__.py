"""Feeds providers module."""

from .memory_feed import MemoryFeed
from .osv_feed import OSVFeed

__all__ = ["OSVFeed", "MemoryFeed"]
