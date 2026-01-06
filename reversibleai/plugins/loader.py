"""
Dynamic plugin loading utilities
"""

import importlib.util
import sys
from pathlib import Path
from typing import Optional, Dict, Any, Type

from loguru import logger

from .base import BasePlugin
from ..core.exceptions import PluginError


def load_plugin_from_file(file_path: Path) -> Type[BasePlugin]:
    """
    Load plugin class from a Python file
    
    Args:
        file_path: Path to plugin file
        
    Returns:
        Plugin class
        
    Raises:
        PluginError: If loading fails
    """
    if not file_path.exists():
        raise PluginError(f"Plugin file not found: {file_path}", plugin_name=str(file_path))
    
    try:
        # Generate module name from file path
        module_name = f"reversibleai_plugin_{file_path.stem}"
        
        # Load module from file
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        if spec is None or spec.loader is None:
            raise PluginError(f"Failed to create spec for {file_path}", plugin_name=str(file_path))
        
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        
        # Find plugin class in module
        import inspect
        for name, obj in inspect.getmembers(module):
            if (inspect.isclass(obj) and 
                issubclass(obj, BasePlugin) and 
                obj != BasePlugin):
                logger.info(f"Loaded plugin class {name} from {file_path}")
                return obj
        
        raise PluginError(f"No plugin class found in {file_path}", plugin_name=str(file_path))
        
    except Exception as e:
        logger.error(f"Failed to load plugin from {file_path}: {e}")
        raise PluginError(f"Failed to load plugin: {e}", plugin_name=str(file_path)) from e


def load_plugin_from_module(module_name: str) -> Type[BasePlugin]:
    """
    Load plugin class from a module
    
    Args:
        module_name: Name of module containing plugin
        
    Returns:
        Plugin class
        
    Raises:
        PluginError: If loading fails
    """
    try:
        module = importlib.import_module(module_name)
        
        # Find plugin class in module
        import inspect
        for name, obj in inspect.getmembers(module):
            if (inspect.isclass(obj) and 
                issubclass(obj, BasePlugin) and 
                obj != BasePlugin):
                logger.info(f"Loaded plugin class {name} from {module_name}")
                return obj
        
        raise PluginError(f"No plugin class found in {module_name}", plugin_name=module_name)
        
    except ImportError as e:
        raise PluginError(f"Failed to import module {module_name}: {e}", plugin_name=module_name) from e
    except Exception as e:
        raise PluginError(f"Failed to load plugin: {e}", plugin_name=module_name) from e
