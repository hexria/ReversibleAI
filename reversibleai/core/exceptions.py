"""
Custom exceptions for ReversibleAI framework
"""

from typing import Optional, Any, Dict


class ReversibleAIError(Exception):
    """Base exception for all ReversibleAI errors"""
    
    def __init__(self, message: str, error_code: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or {}
    
    def __str__(self) -> str:
        if self.error_code:
            return f"[{self.error_code}] {self.message}"
        return self.message
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary"""
        return {
            "error_type": self.__class__.__name__,
            "message": self.message,
            "error_code": self.error_code,
            "details": self.details
        }


class AnalysisError(ReversibleAIError):
    """Raised when analysis operations fail"""
    
    def __init__(self, message: str, operation: Optional[str] = None, target: Optional[str] = None, **kwargs):
        super().__init__(message, **kwargs)
        self.operation = operation
        self.target = target


class LoaderError(ReversibleAIError):
    """Raised when binary loading operations fail"""
    
    def __init__(self, message: str, file_path: Optional[str] = None, file_type: Optional[str] = None, **kwargs):
        super().__init__(message, **kwargs)
        self.file_path = file_path
        self.file_type = file_type


class EmulationError(ReversibleAIError):
    """Raised when emulation operations fail"""
    
    def __init__(self, message: str, architecture: Optional[str] = None, address: Optional[int] = None, **kwargs):
        super().__init__(message, **kwargs)
        self.architecture = architecture
        self.address = address


class PluginError(ReversibleAIError):
    """Raised when plugin operations fail"""
    
    def __init__(self, message: str, plugin_name: Optional[str] = None, plugin_version: Optional[str] = None, **kwargs):
        super().__init__(message, **kwargs)
        self.plugin_name = plugin_name
        self.plugin_version = plugin_version


class ConfigurationError(ReversibleAIError):
    """Raised when configuration is invalid"""
    
    def __init__(self, message: str, config_key: Optional[str] = None, config_value: Optional[Any] = None, **kwargs):
        super().__init__(message, **kwargs)
        self.config_key = config_key
        self.config_value = config_value


class ValidationError(ReversibleAIError):
    """Raised when validation fails"""
    
    def __init__(self, message: str, field: Optional[str] = None, value: Optional[Any] = None, **kwargs):
        super().__init__(message, **kwargs)
        self.field = field
        self.value = value


class ReportError(ReversibleAIError):
    """Raised when report generation fails"""
    
    def __init__(self, message: str, report_format: Optional[str] = None, output_path: Optional[str] = None, **kwargs):
        super().__init__(message, **kwargs)
        self.report_format = report_format
        self.output_path = output_path


class NetworkError(ReversibleAIError):
    """Raised when network operations fail"""
    
    def __init__(self, message: str, url: Optional[str] = None, status_code: Optional[int] = None, **kwargs):
        super().__init__(message, **kwargs)
        self.url = url
        self.status_code = status_code


class DatabaseError(ReversibleAIError):
    """Raised when database operations fail"""
    
    def __init__(self, message: str, operation: Optional[str] = None, table: Optional[str] = None, **kwargs):
        super().__init__(message, **kwargs)
        self.operation = operation
        self.table = table


class TimeoutError(ReversibleAIError):
    """Raised when operations timeout"""
    
    def __init__(self, message: str, timeout_seconds: Optional[float] = None, operation: Optional[str] = None, **kwargs):
        super().__init__(message, **kwargs)
        self.timeout_seconds = timeout_seconds
        self.operation = operation


class PermissionError(ReversibleAIError):
    """Raised when permission is denied"""
    
    def __init__(self, message: str, resource: Optional[str] = None, required_permission: Optional[str] = None, **kwargs):
        super().__init__(message, **kwargs)
        self.resource = resource
        self.required_permission = required_permission


class ResourceError(ReversibleAIError):
    """Raised when resources are unavailable"""
    
    def __init__(self, message: str, resource_type: Optional[str] = None, resource_name: Optional[str] = None, **kwargs):
        super().__init__(message, **kwargs)
        self.resource_type = resource_type
        self.resource_name = resource_name


class DependencyError(ReversibleAIError):
    """Raised when dependencies are missing"""
    
    def __init__(self, message: str, dependency_name: Optional[str] = None, required_version: Optional[str] = None, **kwargs):
        super().__init__(message, **kwargs)
        self.dependency_name = dependency_name
        self.required_version = required_version


# Error code constants
class ErrorCodes:
    """Error code constants"""
    
    # General errors
    UNKNOWN_ERROR = "ERR_UNKNOWN"
    INVALID_INPUT = "ERR_INVALID_INPUT"
    OPERATION_FAILED = "ERR_OPERATION_FAILED"
    
    # Loader errors
    FILE_NOT_FOUND = "ERR_FILE_NOT_FOUND"
    UNSUPPORTED_FORMAT = "ERR_UNSUPPORTED_FORMAT"
    CORRUPTED_FILE = "ERR_CORRUPTED_FILE"
    
    # Analysis errors
    ANALYSIS_FAILED = "ERR_ANALYSIS_FAILED"
    MEMORY_INSUFFICIENT = "ERR_MEMORY_INSUFFICIENT"
    TIMEOUT = "ERR_TIMEOUT"
    
    # Plugin errors
    PLUGIN_NOT_FOUND = "ERR_PLUGIN_NOT_FOUND"
    PLUGIN_LOAD_FAILED = "ERR_PLUGIN_LOAD_FAILED"
    PLUGIN_INCOMPATIBLE = "ERR_PLUGIN_INCOMPATIBLE"
    
    # Configuration errors
    CONFIG_INVALID = "ERR_CONFIG_INVALID"
    CONFIG_MISSING = "ERR_CONFIG_MISSING"
    
    # Network errors
    NETWORK_UNREACHABLE = "ERR_NETWORK_UNREACHABLE"
    HTTP_ERROR = "ERR_HTTP_ERROR"
    
    # Database errors
    DATABASE_CONNECTION_FAILED = "ERR_DB_CONNECTION_FAILED"
    DATABASE_QUERY_FAILED = "ERR_DB_QUERY_FAILED"
    
    # Report errors
    REPORT_GENERATION_FAILED = "ERR_REPORT_GENERATION_FAILED"
    INVALID_FORMAT = "ERR_INVALID_FORMAT"


def handle_exception(func):
    """Decorator for handling exceptions consistently"""
    
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ReversibleAIError:
            # Re-raise our custom exceptions
            raise
        except Exception as e:
            # Convert other exceptions to our base exception
            raise ReversibleAIError(
                message=f"Unexpected error in {func.__name__}: {str(e)}",
                error_code=ErrorCodes.UNKNOWN_ERROR,
                details={"original_exception": str(e), "function": func.__name__}
            ) from e
    
    return wrapper


def safe_execute(func, default_return=None, log_errors=True):
    """Safely execute a function and handle exceptions"""
    
    try:
        return func()
    except ReversibleAIError as e:
        if log_errors:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"ReversibleAI error in {func.__name__}: {e}")
        return default_return
    except Exception as e:
        if log_errors:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Unexpected error in {func.__name__}: {e}")
        return default_return


class ErrorContext:
    """Context manager for error handling"""
    
    def __init__(self, operation: str, reraise: bool = True, default_return=None):
        self.operation = operation
        self.reraise = reraise
        self.default_return = default_return
        self.logger = None
    
    def __enter__(self):
        import logging
        self.logger = logging.getLogger(__name__)
        self.logger.debug(f"Starting operation: {self.operation}")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            self.logger.debug(f"Operation completed successfully: {self.operation}")
            return True
        
        if isinstance(exc_val, ReversibleAIError):
            self.logger.error(f"ReversibleAI error in {self.operation}: {exc_val}")
        else:
            self.logger.error(f"Unexpected error in {self.operation}: {exc_val}")
        
        if self.reraise:
            return False
        else:
            return True  # Suppress exception


class ErrorReporter:
    """Utility class for reporting errors"""
    
    def __init__(self, component: str):
        self.component = component
        self.errors = []
    
    def report_error(self, error: ReversibleAIError) -> None:
        """Report an error"""
        self.errors.append(error)
        
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"[{self.component}] {error}")
    
    def report_warning(self, message: str) -> None:
        """Report a warning"""
        import logging
        logger = logging.getLogger(__name__)
        logger.warning(f"[{self.component}] {message}")
    
    def get_error_summary(self) -> Dict[str, Any]:
        """Get summary of all errors"""
        error_types = {}
        for error in self.errors:
            error_type = error.__class__.__name__
            error_types[error_type] = error_types.get(error_type, 0) + 1
        
        return {
            "component": self.component,
            "total_errors": len(self.errors),
            "error_types": error_types,
            "errors": [error.to_dict() for error in self.errors]
        }
    
    def clear_errors(self) -> None:
        """Clear all reported errors"""
        self.errors.clear()
