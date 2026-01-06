"""
Input validation utilities for ReversibleAI
"""

from pathlib import Path
from typing import Any, Callable, Optional, Union
import functools

from .exceptions import ValidationError, LoaderError
from .security import sanitize_path


def validate_file_path(func: Callable) -> Callable:
    """Decorator to validate file path arguments"""
    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        # Check args for Path objects
        for arg in args:
            if isinstance(arg, (str, Path)):
                _validate_path(arg)
        
        # Check kwargs for path-like values
        for key, value in kwargs.items():
            if 'path' in key.lower() or 'file' in key.lower():
                if isinstance(value, (str, Path)):
                    _validate_path(value)
        
        return func(*args, **kwargs)
    return wrapper


def validate_path(file_path: Union[str, Path], base_path: Optional[Path] = None) -> Path:
    """
    Validate and normalize file path with security checks
    
    Args:
        file_path: Path to validate
        base_path: Base directory to restrict paths to (None for no restriction)
        
    Returns:
        Normalized Path object
        
    Raises:
        ValidationError: If path is invalid or contains traversal attempts
        LoaderError: If file doesn't exist
    """
    # Sanitize path to prevent traversal attacks
    path = sanitize_path(file_path, base_path)
    
    # Check if file exists
    if not path.exists():
        raise LoaderError(f"File not found: {path}", file_path=str(path))
    
    return path


def _validate_path(path: Union[str, Path]) -> None:
    """Internal path validation"""
    try:
        validate_path(path)
    except (ValidationError, LoaderError):
        raise


def validate_address(address: int, max_address: Optional[int] = None) -> int:
    """
    Validate memory address
    
    Args:
        address: Address to validate
        max_address: Maximum allowed address
        
    Returns:
        Validated address
        
    Raises:
        ValidationError: If address is invalid
    """
    if not isinstance(address, int):
        raise ValidationError(f"Address must be an integer, got {type(address)}", field="address", value=address)
    
    if address < 0:
        raise ValidationError(f"Address must be non-negative, got {address}", field="address", value=address)
    
    if max_address is not None and address > max_address:
        raise ValidationError(f"Address {address} exceeds maximum {max_address}", field="address", value=address)
    
    return address


def validate_string_length(string: str, min_length: int = 0, max_length: Optional[int] = None) -> str:
    """
    Validate string length
    
    Args:
        string: String to validate
        min_length: Minimum length
        max_length: Maximum length
        
    Returns:
        Validated string
        
    Raises:
        ValidationError: If string length is invalid
    """
    if not isinstance(string, str):
        raise ValidationError(f"Expected string, got {type(string)}", field="string", value=string)
    
    length = len(string)
    
    if length < min_length:
        raise ValidationError(
            f"String length {length} is less than minimum {min_length}",
            field="string_length",
            value=length
        )
    
    if max_length is not None and length > max_length:
        raise ValidationError(
            f"String length {length} exceeds maximum {max_length}",
            field="string_length",
            value=length
        )
    
    return string


def validate_positive_int(value: int, field_name: str = "value") -> int:
    """
    Validate positive integer
    
    Args:
        value: Value to validate
        field_name: Name of the field
        
    Returns:
        Validated integer
        
    Raises:
        ValidationError: If value is invalid
    """
    if not isinstance(value, int):
        raise ValidationError(f"{field_name} must be an integer", field=field_name, value=value)
    
    if value <= 0:
        raise ValidationError(f"{field_name} must be positive", field=field_name, value=value)
    
    return value


def validate_range(value: Union[int, float], 
                   min_val: Union[int, float], 
                   max_val: Union[int, float],
                   field_name: str = "value") -> Union[int, float]:
    """
    Validate value is within range
    
    Args:
        value: Value to validate
        min_val: Minimum value
        max_val: Maximum value
        field_name: Name of the field
        
    Returns:
        Validated value
        
    Raises:
        ValidationError: If value is out of range
    """
    if value < min_val or value > max_val:
        raise ValidationError(
            f"{field_name} {value} is out of range [{min_val}, {max_val}]",
            field=field_name,
            value=value
        )
    
    return value


def validate_enum(value: Any, allowed_values: list[Any], field_name: str = "value") -> Any:
    """
    Validate value is in allowed enum values
    
    Args:
        value: Value to validate
        allowed_values: List of allowed values
        field_name: Name of the field
        
    Returns:
        Validated value
        
    Raises:
        ValidationError: If value is not in allowed values
    """
    if value not in allowed_values:
        raise ValidationError(
            f"{field_name} {value} is not in allowed values: {allowed_values}",
            field=field_name,
            value=value
        )
    
    return value
