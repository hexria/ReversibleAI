"""
Plugin registry and discovery system
"""

import importlib
import importlib.util
import inspect
from pathlib import Path
from typing import Dict, List, Optional, Type, Any
import pkgutil
import sys

from loguru import logger

from .base import BasePlugin, PluginInfo, PluginManager
from ..core.exceptions import PluginError


class PluginRegistry:
    """Registry for managing plugin discovery and loading"""
    
    def __init__(self) -> None:
        self.plugins: Dict[str, Type[BasePlugin]] = {}
        self.loaded_plugins: Dict[str, BasePlugin] = {}
        self.search_paths: List[Path] = []
    
    def register_plugin(self, plugin_class: Type[BasePlugin]) -> None:
        """
        Register a plugin class
        
        Args:
            plugin_class: Plugin class to register
        """
        try:
            # Create temporary instance to get info
            temp_instance = plugin_class()
            plugin_info = temp_instance.info
            
            # Register plugin class
            self.plugins[plugin_info.name] = plugin_class
            logger.info(f"Registered plugin: {plugin_info.name} v{plugin_info.version}")
            
        except Exception as e:
            logger.error(f"Failed to register plugin {plugin_class.__name__}: {e}")
            raise PluginError(f"Failed to register plugin: {e}", plugin_name=plugin_class.__name__) from e
    
    def discover_plugins(self, search_paths: Optional[List[Path]] = None) -> List[str]:
        """
        Discover plugins in search paths
        
        Args:
            search_paths: Paths to search for plugins (None for default)
            
        Returns:
            List of discovered plugin names
        """
        if search_paths is None:
            search_paths = self._get_default_search_paths()
        
        discovered = []
        
        for search_path in search_paths:
            if not search_path.exists():
                continue
            
            logger.debug(f"Searching for plugins in {search_path}")
            
            # Search for Python modules
            for module_info in pkgutil.iter_modules([str(search_path)]):
                module_name = module_info.name
                
                # Try to import and register plugin
                try:
                    spec = importlib.util.spec_from_file_location(
                        module_name,
                        search_path / f"{module_name}.py"
                    )
                    
                    if spec and spec.loader:
                        module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(module)
                        
                        # Find plugin classes in module
                        for name, obj in inspect.getmembers(module):
                            if (inspect.isclass(obj) and 
                                issubclass(obj, BasePlugin) and 
                                obj != BasePlugin):
                                self.register_plugin(obj)
                                discovered.append(obj().info.name)
                                
                except Exception as e:
                    logger.warning(f"Failed to load plugin from {search_path}/{module_name}: {e}")
                    continue
        
        logger.info(f"Discovered {len(discovered)} plugins")
        return discovered
    
    def discover_entry_points(self) -> List[str]:
        """
        Discover plugins using entry points
        
        Returns:
            List of discovered plugin names
        """
        discovered = []
        
        try:
            import pkg_resources
            
            for entry_point in pkg_resources.iter_entry_points('reversibleai.plugins'):
                try:
                    plugin_class = entry_point.load()
                    self.register_plugin(plugin_class)
                    discovered.append(plugin_class().info.name)
                except Exception as e:
                    logger.warning(f"Failed to load entry point {entry_point.name}: {e}")
                    
        except ImportError:
            logger.debug("pkg_resources not available, skipping entry point discovery")
        
        return discovered
    
    def load_plugin(self, plugin_name: str, config: Optional[Dict[str, Any]] = None) -> BasePlugin:
        """
        Load a plugin instance
        
        Args:
            plugin_name: Name of plugin to load
            config: Plugin configuration
            
        Returns:
            Loaded plugin instance
            
        Raises:
            PluginError: If plugin not found or loading fails
        """
        if plugin_name not in self.plugins:
            raise PluginError(f"Plugin not found: {plugin_name}", plugin_name=plugin_name)
        
        if plugin_name in self.loaded_plugins:
            logger.debug(f"Plugin {plugin_name} already loaded")
            return self.loaded_plugins[plugin_name]
        
        try:
            plugin_class = self.plugins[plugin_name]
            plugin = plugin_class(config)
            
            # Validate configuration
            errors = plugin.validate_config()
            if errors:
                raise PluginError(
                    f"Plugin configuration errors: {errors}",
                    plugin_name=plugin_name
                )
            
            self.loaded_plugins[plugin_name] = plugin
            logger.info(f"Loaded plugin: {plugin_name}")
            
            return plugin
            
        except Exception as e:
            logger.error(f"Failed to load plugin {plugin_name}: {e}")
            raise PluginError(f"Failed to load plugin: {e}", plugin_name=plugin_name) from e
    
    def unload_plugin(self, plugin_name: str) -> bool:
        """
        Unload a plugin
        
        Args:
            plugin_name: Name of plugin to unload
            
        Returns:
            True if unloaded successfully
        """
        if plugin_name not in self.loaded_plugins:
            return False
        
        try:
            plugin = self.loaded_plugins[plugin_name]
            plugin.cleanup()
            del self.loaded_plugins[plugin_name]
            logger.info(f"Unloaded plugin: {plugin_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to unload plugin {plugin_name}: {e}")
            return False
    
    def get_plugin(self, plugin_name: str) -> Optional[BasePlugin]:
        """Get loaded plugin instance"""
        return self.loaded_plugins.get(plugin_name)
    
    def list_plugins(self) -> List[PluginInfo]:
        """List all registered plugins"""
        plugins = []
        for plugin_class in self.plugins.values():
            try:
                temp_instance = plugin_class()
                plugins.append(temp_instance.info)
            except Exception:
                continue
        return plugins
    
    def list_loaded_plugins(self) -> List[PluginInfo]:
        """List all loaded plugins"""
        return [plugin.info for plugin in self.loaded_plugins.values()]
    
    def _get_default_search_paths(self) -> List[Path]:
        """Get default plugin search paths"""
        paths = [
            Path.home() / ".reversibleai" / "plugins",
            Path("/usr/local/lib/reversibleai/plugins"),
            Path("/usr/lib/reversibleai/plugins"),
        ]
        
        # Add path from environment variable
        env_path = Path.cwd().parent / "reversibleai" / "plugins"
        if env_path.exists():
            paths.insert(0, env_path)
        
        return paths


# Global plugin registry instance
_plugin_registry: Optional[PluginRegistry] = None


def get_plugin_registry() -> PluginRegistry:
    """Get global plugin registry instance"""
    global _plugin_registry
    if _plugin_registry is None:
        _plugin_registry = PluginRegistry()
        # Auto-discover plugins
        _plugin_registry.discover_entry_points()
    return _plugin_registry


def discover_plugins(search_paths: Optional[List[Path]] = None) -> List[str]:
    """Discover plugins in search paths"""
    return get_plugin_registry().discover_plugins(search_paths)


def load_plugin(plugin_name: str, config: Optional[Dict[str, Any]] = None) -> BasePlugin:
    """Load a plugin"""
    return get_plugin_registry().load_plugin(plugin_name, config)


def list_plugins() -> List[PluginInfo]:
    """List all registered plugins"""
    return get_plugin_registry().list_plugins()
