"""Feeds providers module."""

from .osv_feed import OSVFeed
from .memory_feed import MemoryFeed

__all__ = ["OSVFeed", "MemoryFeed"]