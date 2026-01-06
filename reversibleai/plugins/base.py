"""
Base plugin class for ReversibleAI
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from pathlib import Path
from dataclasses import dataclass

from loguru import logger


@dataclass
class PluginInfo:
    """Plugin information"""
    name: str
    version: str
    description: str
    author: str
    supported_tools: List[str]  # ["ida", "ghidra", "radare2"]
    supported_architectures: List[str]  # ["x86", "x86_64", "arm", "aarch64"]
    capabilities: List[str]  # ["static_analysis", "dynamic_analysis", "annotations"]
    dependencies: List[str]
    config_schema: Optional[Dict[str, Any]] = None


class BasePlugin(ABC):
    """Abstract base class for all plugins"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.enabled = True
        self._tool_instance = None
        
    @property
    @abstractmethod
    def info(self) -> PluginInfo:
        """Get plugin information"""
        pass
    
    @abstractmethod
    def initialize(self, tool_instance: Any) -> bool:
        """Initialize plugin with tool instance"""
        pass
    
    @abstractmethod
    def cleanup(self) -> None:
        """Cleanup plugin resources"""
        pass
    
    def is_compatible(self, tool_name: str, architecture: str) -> bool:
        """Check if plugin is compatible with tool and architecture"""
        return (tool_name.lower() in self.info.supported_tools and
                architecture.lower() in self.info.supported_architectures)
    
    def get_config(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        return self.config.get(key, default)
    
    def set_config(self, key: str, value: Any) -> None:
        """Set configuration value"""
        self.config[key] = value
    
    def enable(self) -> None:
        """Enable plugin"""
        self.enabled = True
        logger.info(f"Plugin {self.info.name} enabled")
    
    def disable(self) -> None:
        """Disable plugin"""
        self.enabled = False
        logger.info(f"Plugin {self.info.name} disabled")
    
    def is_enabled(self) -> bool:
        """Check if plugin is enabled"""
        return self.enabled
    
    def validate_config(self) -> List[str]:
        """Validate plugin configuration"""
        errors = []
        
        if self.info.config_schema:
            schema = self.info.config_schema
            
            # Check required fields
            required = schema.get('required', [])
            for field in required:
                if field not in self.config:
                    errors.append(f"Missing required configuration field: {field}")
            
            # Check field types
            properties = schema.get('properties', {})
            for field, value in self.config.items():
                if field in properties:
                    expected_type = properties[field].get('type')
                    if expected_type and not isinstance(value, eval(expected_type)):
                        errors.append(f"Invalid type for {field}: expected {expected_type}")
        
        return errors


class AnalysisPlugin(BasePlugin):
    """Base class for analysis plugins"""
    
    @abstractmethod
    def analyze(self, target: Any, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Perform analysis on target"""
        pass
    
    @abstractmethod
    def get_supported_file_types(self) -> List[str]:
        """Get supported file types"""
        pass


class AnnotationPlugin(BasePlugin):
    """Base class for annotation plugins"""
    
    @abstractmethod
    def annotate(self, target: Any, annotations: Dict[str, Any]) -> bool:
        """Apply annotations to target"""
        pass
    
    @abstractmethod
    def extract_annotations(self, target: Any) -> Dict[str, Any]:
        """Extract annotations from target"""
        pass


class ExportPlugin(BasePlugin):
    """Base class for export plugins"""
    
    @abstractmethod
    def export(self, data: Any, output_path: Path, options: Optional[Dict[str, Any]] = None) -> bool:
        """Export data to file"""
        pass
    
    @abstractmethod
    def get_supported_formats(self) -> List[str]:
        """Get supported export formats"""
        pass


class ImportPlugin(BasePlugin):
    """Base class for import plugins"""
    
    @abstractmethod
    def import_data(self, input_path: Path, options: Optional[Dict[str, Any]] = None) -> Any:
        """Import data from file"""
        pass
    
    @abstractmethod
    def get_supported_formats(self) -> List[str]:
        """Get supported import formats"""
        pass


class UIPlugin(BasePlugin):
    """Base class for UI plugins"""
    
    @abstractmethod
    def create_ui(self, parent: Any) -> Any:
        """Create UI components"""
        pass
    
    @abstractmethod
    def get_menu_items(self) -> List[Dict[str, Any]]:
        """Get menu items for this plugin"""
        pass


class PluginManager:
    """Manages plugin lifecycle"""
    
    def __init__(self):
        self.plugins: Dict[str, BasePlugin] = {}
        self.plugin_registry: Dict[str, type] = {}
        
    def register_plugin(self, plugin_class: type) -> None:
        """Register a plugin class"""
        try:
            # Create instance to get info
            temp_instance = plugin_class()
            plugin_info = temp_instance.info
            
            # Register plugin class
            self.plugin_registry[plugin_info.name] = plugin_class
            
            logger.debug(f"Registered plugin: {plugin_info.name}")
            
        except Exception as e:
            logger.error(f"Failed to register plugin {plugin_class.__name__}: {e}")
    
    def load_plugin(self, plugin_name: str, config: Optional[Dict[str, Any]] = None) -> bool:
        """Load a plugin"""
        if plugin_name not in self.plugin_registry:
            logger.error(f"Plugin not registered: {plugin_name}")
            return False
        
        try:
            plugin_class = self.plugin_registry[plugin_name]
            plugin = plugin_class(config)
            
            # Validate configuration
            errors = plugin.validate_config()
            if errors:
                logger.error(f"Plugin configuration errors: {errors}")
                return False
            
            self.plugins[plugin_name] = plugin
            logger.info(f"Loaded plugin: {plugin_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load plugin {plugin_name}: {e}")
            return False
    
    def unload_plugin(self, plugin_name: str) -> bool:
        """Unload a plugin"""
        if plugin_name not in self.plugins:
            logger.warning(f"Plugin not loaded: {plugin_name}")
            return False
        
        try:
            plugin = self.plugins[plugin_name]
            plugin.cleanup()
            del self.plugins[plugin_name]
            logger.info(f"Unloaded plugin: {plugin_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to unload plugin {plugin_name}: {e}")
            return False
    
    def get_plugin(self, plugin_name: str) -> Optional[BasePlugin]:
        """Get loaded plugin by name"""
        return self.plugins.get(plugin_name)
    
    def get_plugins_by_tool(self, tool_name: str) -> List[BasePlugin]:
        """Get plugins compatible with specific tool"""
        compatible_plugins = []
        
        for plugin in self.plugins.values():
            if tool_name.lower() in plugin.info.supported_tools:
                compatible_plugins.append(plugin)
        
        return compatible_plugins
    
    def get_plugins_by_capability(self, capability: str) -> List[BasePlugin]:
        """Get plugins with specific capability"""
        capable_plugins = []
        
        for plugin in self.plugins.values():
            if capability in plugin.info.capabilities:
                capable_plugins.append(plugin)
        
        return capable_plugins
    
    def list_plugins(self) -> List[PluginInfo]:
        """List all registered plugins"""
        plugin_infos = []
        
        for plugin_name, plugin_class in self.plugin_registry.items():
            try:
                temp_instance = plugin_class()
                plugin_infos.append(temp_instance.info)
            except Exception as e:
                logger.error(f"Failed to get info for plugin {plugin_name}: {e}")
        
        return plugin_infos
    
    def list_loaded_plugins(self) -> List[PluginInfo]:
        """List loaded plugins"""
        return [plugin.info for plugin in self.plugins.values()]
    
    def enable_plugin(self, plugin_name: str) -> bool:
        """Enable a plugin"""
        plugin = self.get_plugin(plugin_name)
        if plugin:
            plugin.enable()
            return True
        return False
    
    def disable_plugin(self, plugin_name: str) -> bool:
        """Disable a plugin"""
        plugin = self.get_plugin(plugin_name)
        if plugin:
            plugin.disable()
            return True
        return False
    
    def initialize_plugins(self, tool_instance: Any, tool_name: str) -> int:
        """Initialize all compatible plugins"""
        initialized_count = 0
        
        for plugin in self.plugins.values():
            if plugin.is_compatible(tool_name, tool_instance.get_architecture()):
                try:
                    if plugin.initialize(tool_instance):
                        initialized_count += 1
                        logger.info(f"Initialized plugin: {plugin.info.name}")
                except Exception as e:
                    logger.error(f"Failed to initialize plugin {plugin.info.name}: {e}")
        
        logger.info(f"Initialized {initialized_count} plugins for {tool_name}")
        return initialized_count
    
    def cleanup_all_plugins(self) -> None:
        """Cleanup all loaded plugins"""
        for plugin_name in list(self.plugins.keys()):
            self.unload_plugin(plugin_name)
    
    def get_plugin_statistics(self) -> Dict[str, Any]:
        """Get plugin statistics"""
        stats = {
            'registered_plugins': len(self.plugin_registry),
            'loaded_plugins': len(self.plugins),
            'enabled_plugins': len([p for p in self.plugins.values() if p.is_enabled()]),
            'plugins_by_tool': {},
            'plugins_by_capability': {},
        }
        
        # Count by tool
        for plugin_info in self.list_plugins():
            for tool in plugin_info.supported_tools:
                stats['plugins_by_tool'][tool] = stats['plugins_by_tool'].get(tool, 0) + 1
        
        # Count by capability
        for plugin_info in self.list_plugins():
            for capability in plugin_info.capabilities:
                stats['plugins_by_capability'][capability] = stats['plugins_by_capability'].get(capability, 0) + 1
        
        return stats


# Global plugin manager instance
plugin_manager = PluginManager()
