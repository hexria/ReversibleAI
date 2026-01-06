"""
Plugin system for ReversibleAI framework
"""

from .base import BasePlugin
from .ida import IDAPlugin
from .ghidra import GhidraPlugin
from .radare2 import Radare2Plugin

__all__ = [
    "BasePlugin",
    "IDAPlugin",
    "GhidraPlugin", 
    "Radare2Plugin"
]
