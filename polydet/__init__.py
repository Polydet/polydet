"""
    Tool to detect polyglot files: files which are valid in multiple format.
"""

from .polyglot_level import PolyglotLevel
from . import rules
from .scan import scan

__all__ = [PolyglotLevel, scan]
