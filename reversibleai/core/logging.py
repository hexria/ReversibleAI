"""
Logging configuration and utilities for ReversibleAI
"""

import logging
import sys
from pathlib import Path
from typing import Optional, Dict, Any, Union
from datetime import datetime
import json

from loguru import logger as loguru_logger


class ReversibleAILogger:
    """Enhanced logger for ReversibleAI framework"""
    
    def __init__(self, name: str):
        self.name = name
        self.loguru_logger = loguru_logger.bind(name=name)
        self._setup_standard_handlers()
    
    def _setup_standard_handlers(self) -> None:
        """Setup standard logging handlers"""
        # Remove default handler
        loguru_logger.remove()
        
        # Add console handler
        loguru_logger.add(
            sys.stderr,
            format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
            level="INFO"
        )
    
    def debug(self, message: str, **kwargs) -> None:
        """Log debug message"""
        self.loguru_logger.debug(message, **kwargs)
    
    def info(self, message: str, **kwargs) -> None:
        """Log info message"""
        self.loguru_logger.info(message, **kwargs)
    
    def warning(self, message: str, **kwargs) -> None:
        """Log warning message"""
        self.loguru_logger.warning(message, **kwargs)
    
    def error(self, message: str, **kwargs) -> None:
        """Log error message"""
        self.loguru_logger.error(message, **kwargs)
    
    def critical(self, message: str, **kwargs) -> None:
        """Log critical message"""
        self.loguru_logger.critical(message, **kwargs)
    
    def exception(self, message: str, **kwargs) -> None:
        """Log exception with traceback"""
        self.loguru_logger.exception(message, **kwargs)


class LoggingManager:
    """Manages logging configuration for the entire framework"""
    
    def __init__(self):
        self.configured = False
        self.loggers: Dict[str, ReversibleAILogger] = {}
        self.config = {}
    
    def setup_logging(self, 
                     level: str = "INFO",
                     log_file: Optional[Path] = None,
                     format_string: Optional[str] = None,
                     rotation: str = "10 MB",
                     retention: str = "7 days",
                     enable_console: bool = True,
                     enable_file: bool = True,
                     json_format: bool = False) -> None:
        """
        Setup global logging configuration
        
        Args:
            level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            log_file: Path to log file
            format_string: Custom format string
            rotation: Log rotation settings
            retention: Log retention settings
            enable_console: Enable console logging
            enable_file: Enable file logging
            json_format: Use JSON format for logs
        """
        # Remove default handlers
        loguru_logger.remove()
        
        # Store configuration
        self.config = {
            "level": level,
            "log_file": str(log_file) if log_file else None,
            "format_string": format_string,
            "rotation": rotation,
            "retention": retention,
            "enable_console": enable_console,
            "enable_file": enable_file,
            "json_format": json_format
        }
        
        # Setup console handler
        if enable_console:
            if json_format:
                console_format = self._get_json_format()
            else:
                console_format = format_string or "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>"
            
            loguru_logger.add(
                sys.stderr,
                format=console_format,
                level=level,
                serialize=json_format
            )
        
        # Setup file handler
        if enable_file and log_file:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            
            if json_format:
                file_format = self._get_json_format()
            else:
                file_format = format_string or "{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}"
            
            loguru_logger.add(
                log_file,
                format=file_format,
                level=level,
                rotation=rotation,
                retention=retention,
                serialize=json_format,
                encoding="utf-8"
            )
        
        self.configured = True
        loguru_logger.info("ReversibleAI logging system initialized")
    
    def _get_json_format(self) -> str:
        """Get JSON log format"""
        return (
            "{{"
            '"timestamp": "{time:YYYY-MM-DD HH:mm:ss}", '
            '"level": "{level}", '
            '"name": "{name}", '
            '"function": "{function}", '
            '"line": {line}, '
            '"message": "{message}", '
            '"extra": "{extra}"'
            "}}"
        )
    
    def get_logger(self, name: str) -> ReversibleAILogger:
        """Get a logger instance"""
        if name not in self.loggers:
            self.loggers[name] = ReversibleAILogger(name)
        
        return self.loggers[name]
    
    def set_level(self, level: str) -> None:
        """Set logging level"""
        if not self.configured:
            self.setup_logging()
        
        # Update configuration
        self.config["level"] = level
        
        # Reconfigure handlers
        self._reconfigure_handlers()
    
    def add_file_handler(self, log_file: Path, level: str = None) -> None:
        """Add additional file handler"""
        if not self.configured:
            self.setup_logging()
        
        log_level = level or self.config["level"]
        log_file.parent.mkdir(parents=True, exist_ok=True)
        
        format_string = self.config.get("format_string")
        if self.config.get("json_format"):
            format_string = self._get_json_format()
        elif not format_string:
            format_string = "{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}"
        
        loguru_logger.add(
            log_file,
            format=format_string,
            level=log_level,
            rotation=self.config.get("rotation", "10 MB"),
            retention=self.config.get("retention", "7 days"),
            serialize=self.config.get("json_format", False),
            encoding="utf-8"
        )
    
    def _reconfigure_handlers(self) -> None:
        """Reconfigure all handlers with current settings"""
        # Remove all handlers
        loguru_logger.remove()
        
        # Re-add handlers with new configuration
        if self.config.get("enable_console"):
            format_string = self.config.get("format_string")
            if self.config.get("json_format"):
                format_string = self._get_json_format()
            elif not format_string:
                format_string = "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>"
            
            loguru_logger.add(
                sys.stderr,
                format=format_string,
                level=self.config["level"],
                serialize=self.config.get("json_format")
            )
        
        if self.config.get("enable_file") and self.config.get("log_file"):
            log_file = Path(self.config["log_file"])
            log_file.parent.mkdir(parents=True, exist_ok=True)
            
            format_string = self.config.get("format_string")
            if self.config.get("json_format"):
                format_string = self._get_json_format()
            elif not format_string:
                format_string = "{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}"
            
            loguru_logger.add(
                log_file,
                format=format_string,
                level=self.config["level"],
                rotation=self.config.get("rotation", "10 MB"),
                retention=self.config.get("retention", "7 days"),
                serialize=self.config.get("json_format"),
                encoding="utf-8"
            )
    
    def get_config(self) -> Dict[str, Any]:
        """Get current logging configuration"""
        return self.config.copy()
    
    def save_config(self, config_file: Path) -> None:
        """Save logging configuration to file"""
        config_data = {
            "logging": self.config,
            "saved_at": datetime.now().isoformat()
        }
        
        with open(config_file, 'w') as f:
            json.dump(config_data, f, indent=2)
    
    def load_config(self, config_file: Path) -> bool:
        """Load logging configuration from file"""
        try:
            with open(config_file, 'r') as f:
                config_data = json.load(f)
            
            logging_config = config_data.get("logging", {})
            
            self.setup_logging(**logging_config)
            return True
            
        except Exception as e:
            loguru_logger.error(f"Failed to load logging config: {e}")
            return False


class StructuredLogger:
    """Structured logger for better log analysis"""
    
    def __init__(self, name: str):
        self.name = name
        self.logger = loguru_logger.bind(name=name)
    
    def log_event(self, 
                  event_type: str,
                  message: str,
                  level: str = "INFO",
                  **kwargs) -> None:
        """Log structured event"""
        event_data = {
            "event_type": event_type,
            "message": message,
            "timestamp": datetime.now().isoformat(),
            **kwargs
        }
        
        log_method = getattr(self.logger, level.lower(), self.logger.info)
        log_method(f"[{event_type}] {message}", extra=event_data)
    
    def log_analysis_start(self, target: str, analysis_type: str, **kwargs) -> None:
        """Log analysis start event"""
        self.log_event(
            "ANALYSIS_START",
            f"Starting {analysis_type} analysis",
            target=target,
            analysis_type=analysis_type,
            **kwargs
        )
    
    def log_analysis_complete(self, target: str, analysis_type: str, duration: float, **kwargs) -> None:
        """Log analysis complete event"""
        self.log_event(
            "ANALYSIS_COMPLETE",
            f"Completed {analysis_type} analysis in {duration:.2f}s",
            target=target,
            analysis_type=analysis_type,
            duration=duration,
            **kwargs
        )
    
    def log_error_event(self, error_type: str, error_message: str, **kwargs) -> None:
        """Log error event"""
        self.log_event(
            "ERROR",
            f"{error_type}: {error_message}",
            level="ERROR",
            error_type=error_type,
            error_message=error_message,
            **kwargs
        )
    
    def log_performance(self, operation: str, duration: float, **kwargs) -> None:
        """Log performance event"""
        self.log_event(
            "PERFORMANCE",
            f"Operation '{operation}' completed in {duration:.2f}s",
            operation=operation,
            duration=duration,
            **kwargs
        )


# Global logging manager instance
logging_manager = LoggingManager()


def setup_logging(**kwargs) -> None:
    """Setup global logging configuration"""
    logging_manager.setup_logging(**kwargs)


def get_logger(name: str) -> ReversibleAILogger:
    """Get a logger instance"""
    return logging_manager.get_logger(name)


def get_structured_logger(name: str) -> StructuredLogger:
    """Get a structured logger instance"""
    return StructuredLogger(name)


# Convenience functions
def log_analysis_start(target: str, analysis_type: str, **kwargs) -> None:
    """Log analysis start event"""
    logger = get_structured_logger("reversibleai")
    logger.log_analysis_start(target, analysis_type, **kwargs)


def log_analysis_complete(target: str, analysis_type: str, duration: float, **kwargs) -> None:
    """Log analysis complete event"""
    logger = get_structured_logger("reversibleai")
    logger.log_analysis_complete(target, analysis_type, duration, **kwargs)


def log_error(error_type: str, error_message: str, **kwargs) -> None:
    """Log error event"""
    logger = get_structured_logger("reversibleai")
    logger.log_error_event(error_type, error_message, **kwargs)


def log_performance(operation: str, duration: float, **kwargs) -> None:
    """Log performance event"""
    logger = get_structured_logger("reversibleai")
    logger.log_performance(operation, duration, **kwargs)
