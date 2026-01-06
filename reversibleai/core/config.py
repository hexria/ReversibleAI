"""
Configuration management for ReversibleAI
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, field

from loguru import logger
from .exceptions import ConfigurationError
from .constants import (
    DEFAULT_MIN_STRING_LENGTH,
    DEFAULT_MAX_STRING_LENGTH,
    DEFAULT_ANALYSIS_TIMEOUT,
    DEFAULT_MAX_MEMORY_MB
)


@dataclass
class LoggingConfig:
    """Logging configuration"""
    level: str = "INFO"
    file: Optional[str] = None
    format: str = "text"  # text or json
    rotation: str = "10 MB"
    retention: str = "7 days"
    enable_console: bool = True
    enable_file: bool = True


@dataclass
class AnalysisConfig:
    """Analysis configuration"""
    default_timeout: int = DEFAULT_ANALYSIS_TIMEOUT
    max_memory: int = DEFAULT_MAX_MEMORY_MB  # MB
    enable_emulation: bool = True
    max_string_length: int = DEFAULT_MAX_STRING_LENGTH
    min_string_length: int = DEFAULT_MIN_STRING_LENGTH


@dataclass
class PluginConfig:
    """Plugin configuration"""
    auto_load: bool = True
    search_paths: list[str] = field(default_factory=lambda: [
        str(Path.home() / ".reversibleai" / "plugins"),
        "/usr/local/lib/reversibleai/plugins"
    ])


@dataclass
class Config:
    """Main configuration class"""
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
    plugins: PluginConfig = field(default_factory=PluginConfig)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary"""
        return {
            "logging": {
                "level": self.logging.level,
                "file": self.logging.file,
                "format": self.logging.format,
                "rotation": self.logging.rotation,
                "retention": self.logging.retention,
                "enable_console": self.logging.enable_console,
                "enable_file": self.logging.enable_file,
            },
            "analysis": {
                "default_timeout": self.analysis.default_timeout,
                "max_memory": self.analysis.max_memory,
                "enable_emulation": self.analysis.enable_emulation,
                "max_string_length": self.analysis.max_string_length,
                "min_string_length": self.analysis.min_string_length,
            },
            "plugins": {
                "auto_load": self.plugins.auto_load,
                "search_paths": self.plugins.search_paths,
            }
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Config":
        """Create config from dictionary"""
        logging_data = data.get("logging", {})
        analysis_data = data.get("analysis", {})
        plugins_data = data.get("plugins", {})
        
        return cls(
            logging=LoggingConfig(**logging_data),
            analysis=AnalysisConfig(**analysis_data),
            plugins=PluginConfig(**plugins_data)
        )


class ConfigManager:
    """Manages configuration loading and saving"""
    
    def __init__(self, config_path: Optional[Path] = None) -> None:
        """
        Initialize config manager
        
        Args:
            config_path: Path to config file (None for default)
        """
        if config_path is None:
            config_path = self._get_default_config_path()
        
        self.config_path = Path(config_path)
        self.config: Optional[Config] = None
        self._load_config()
    
    def _get_default_config_path(self) -> Path:
        """Get default config file path"""
        # Check environment variable first
        env_path = os.getenv("REVERSIBLEAI_CONFIG_PATH")
        if env_path:
            return Path(env_path)
        
        # Use default location
        config_dir = Path.home() / ".reversibleai"
        config_dir.mkdir(parents=True, exist_ok=True)
        return config_dir / "config.yaml"
    
    def _load_config(self) -> None:
        """Load configuration from file or environment"""
        # Start with defaults
        self.config = Config()
        
        # Load from environment variables
        self._load_from_environment()
        
        # Load from config file if it exists
        if self.config_path.exists():
            try:
                self._load_from_file()
            except Exception as e:
                logger.warning(f"Failed to load config file {self.config_path}: {e}")
                logger.info("Using default configuration")
        else:
            logger.info(f"Config file not found at {self.config_path}, using defaults")
    
    def _load_from_environment(self) -> None:
        """Load configuration from environment variables"""
        if self.config is None:
            return
        
        # Logging config
        if log_level := os.getenv("REVERSIBLEAI_LOG_LEVEL"):
            self.config.logging.level = log_level
        
        if log_file := os.getenv("REVERSIBLEAI_LOG_FILE"):
            self.config.logging.file = log_file
        
        # Analysis config
        if timeout := os.getenv("REVERSIBLEAI_DEFAULT_TIMEOUT"):
            try:
                self.config.analysis.default_timeout = int(timeout)
            except ValueError:
                logger.warning(f"Invalid timeout value: {timeout}")
        
        if max_mem := os.getenv("REVERSIBLEAI_MAX_MEMORY"):
            try:
                self.config.analysis.max_memory = int(max_mem)
            except ValueError:
                logger.warning(f"Invalid max_memory value: {max_mem}")
        
        if enable_emu := os.getenv("REVERSIBLEAI_ENABLE_EMULATION"):
            self.config.analysis.enable_emulation = enable_emu.lower() in ("true", "1", "yes")
        
        # Plugin config
        if plugin_path := os.getenv("REVERSIBLEAI_PLUGIN_PATH"):
            self.config.plugins.search_paths = [plugin_path]
    
    def _load_from_file(self) -> None:
        """Load configuration from YAML file"""
        if not self.config_path.exists():
            return
        
        try:
            with open(self.config_path, 'r') as f:
                data = yaml.safe_load(f)
            
            if data:
                # Merge with defaults
                file_config = Config.from_dict(data)
                
                # Update current config with file values
                if file_config.logging.level != "INFO" or self.config_path.exists():
                    self.config.logging = file_config.logging
                if file_config.analysis.default_timeout != 300 or self.config_path.exists():
                    self.config.analysis = file_config.analysis
                if file_config.plugins.auto_load != True or self.config_path.exists():
                    self.config.plugins = file_config.plugins
                
                logger.info(f"Loaded configuration from {self.config_path}")
        except yaml.YAMLError as e:
            raise ConfigurationError(f"Invalid YAML in config file: {e}", config_key="yaml_parse")
        except Exception as e:
            raise ConfigurationError(f"Failed to load config file: {e}", config_key="file_load")
    
    def save_config(self, config: Optional[Config] = None) -> None:
        """
        Save configuration to file
        
        Args:
            config: Config to save (None to save current config)
        """
        if config is None:
            config = self.config
        
        if config is None:
            raise ConfigurationError("No configuration to save", config_key="save")
        
        # Ensure directory exists
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with open(self.config_path, 'w') as f:
                yaml.dump(config.to_dict(), f, default_flow_style=False, sort_keys=False)
            
            logger.info(f"Saved configuration to {self.config_path}")
        except Exception as e:
            raise ConfigurationError(f"Failed to save config file: {e}", config_key="file_save")
    
    def get_config(self) -> Config:
        """Get current configuration"""
        if self.config is None:
            self.config = Config()
        return self.config
    
    def reload_config(self) -> None:
        """Reload configuration from file"""
        self._load_config()
    
    def create_default_config(self) -> None:
        """Create default configuration file"""
        default_config = Config()
        self.save_config(default_config)
        logger.info(f"Created default configuration at {self.config_path}")


# Global config manager instance
_config_manager: Optional[ConfigManager] = None


def get_config_manager(config_path: Optional[Path] = None) -> ConfigManager:
    """Get global config manager instance"""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager(config_path)
    return _config_manager


def get_config() -> Config:
    """Get current configuration"""
    return get_config_manager().get_config()


def reload_config() -> None:
    """Reload configuration"""
    get_config_manager().reload_config()
