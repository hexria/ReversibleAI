"""
Configuration schema and validation for ReversibleAI
"""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field, validator

from .exceptions import ValidationError, ConfigurationError


class LoggingConfigSchema(BaseModel):
    """Logging configuration schema"""
    level: str = Field(default="INFO", regex="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    file: Optional[str] = None
    format: str = Field(default="text", regex="^(text|json)$")
    rotation: str = Field(default="10 MB")
    retention: str = Field(default="7 days")
    enable_console: bool = True
    enable_file: bool = True


class AnalysisConfigSchema(BaseModel):
    """Analysis configuration schema"""
    default_timeout: int = Field(default=300, ge=1, le=3600)
    max_memory: int = Field(default=2048, ge=64, le=32768)  # MB
    enable_emulation: bool = True
    max_string_length: int = Field(default=10000, ge=1, le=1000000)
    min_string_length: int = Field(default=4, ge=1, le=1000)
    
    @validator('max_string_length')
    def max_greater_than_min(cls, v, values):
        """Ensure max_string_length >= min_string_length"""
        if 'min_string_length' in values and v < values['min_string_length']:
            raise ValueError('max_string_length must be >= min_string_length')
        return v


class PluginConfigSchema(BaseModel):
    """Plugin configuration schema"""
    auto_load: bool = True
    search_paths: List[str] = Field(default_factory=lambda: [
        "~/.reversibleai/plugins",
        "/usr/local/lib/reversibleai/plugins"
    ])


class ConfigSchema(BaseModel):
    """Main configuration schema"""
    logging: LoggingConfigSchema = Field(default_factory=LoggingConfigSchema)
    analysis: AnalysisConfigSchema = Field(default_factory=AnalysisConfigSchema)
    plugins: PluginConfigSchema = Field(default_factory=PluginConfigSchema)


def validate_config(config_data: Dict[str, Any]) -> List[str]:
    """
    Validate configuration data
    
    Args:
        config_data: Configuration dictionary
        
    Returns:
        List of validation errors (empty if valid)
    """
    errors = []
    
    try:
        ConfigSchema(**config_data)
    except Exception as e:
        errors.append(str(e))
    
    return errors


def validate_and_raise(config_data: Dict[str, Any]) -> None:
    """
    Validate configuration and raise exception if invalid
    
    Args:
        config_data: Configuration dictionary
        
    Raises:
        ConfigurationError: If configuration is invalid
    """
    errors = validate_config(config_data)
    if errors:
        raise ConfigurationError(
            f"Configuration validation failed: {', '.join(errors)}",
            config_key="validation"
        )
