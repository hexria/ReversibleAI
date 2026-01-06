"""
Plugin system for ReversibleAI framework
"""

from .base import BasePlugin, PluginManager
from .ida import IDAPlugin
from .ghidra import GhidraPlugin
from .radare2 import Radare2Plugin
from .registry import (
    PluginRegistry,
    get_plugin_registry,
    discover_plugins,
    load_plugin,
    list_plugins
)
from .loader import load_plugin_from_file, load_plugin_from_module

__all__ = [
    "BasePlugin",
    "PluginManager",
    "IDAPlugin",
    "GhidraPlugin", 
    "Radare2Plugin",
    "PluginRegistry",
    "get_plugin_registry",
    "discover_plugins",
    "load_plugin",
    "list_plugins",
    "load_plugin_from_file",
    "load_plugin_from_module",
]
