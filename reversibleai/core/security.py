"""
Security utilities for ReversibleAI
"""

import os
from pathlib import Path
from typing import Optional, Union
import hashlib

from .exceptions import ValidationError, PermissionError


def sanitize_path(file_path: Union[str, Path], base_path: Optional[Path] = None) -> Path:
    """
    Sanitize and validate file path to prevent path traversal attacks
    
    Args:
        file_path: Path to sanitize
        base_path: Base directory to restrict paths to (None for no restriction)
        
    Returns:
        Sanitized Path object
        
    Raises:
        ValidationError: If path contains traversal attempts
    """
    path = Path(file_path)
    
    # Resolve path to remove any relative components
    try:
        resolved = path.resolve()
    except (OSError, ValueError) as e:
        raise ValidationError(f"Invalid path: {path}", field="file_path", value=str(path)) from e
    
    # Check for path traversal attempts
    if ".." in str(path) or str(path).startswith("/"):
        # Check if resolved path is outside base_path
        if base_path:
            try:
                resolved_base = base_path.resolve()
                resolved.relative_to(resolved_base)
            except ValueError:
                raise ValidationError(
                    f"Path traversal attempt detected: {path}",
                    field="file_path",
                    value=str(path)
                )
    
    return resolved


def validate_file_size(file_path: Path, max_size: Optional[int] = None) -> int:
    """
    Validate file size
    
    Args:
        file_path: Path to file
        max_size: Maximum allowed size in bytes (None for no limit)
        
    Returns:
        File size in bytes
        
    Raises:
        ValidationError: If file is too large
        PermissionError: If file cannot be accessed
    """
    try:
        size = file_path.stat().st_size
    except OSError as e:
        raise PermissionError(f"Cannot access file: {file_path}", resource=str(file_path)) from e
    
    if max_size is not None and size > max_size:
        raise ValidationError(
            f"File size {size} exceeds maximum {max_size} bytes",
            field="file_size",
            value=size
        )
    
    return size


def validate_file_permissions(file_path: Path, required_permission: str = "read") -> None:
    """
    Validate file permissions
    
    Args:
        file_path: Path to file
        required_permission: Required permission ("read" or "write")
        
    Raises:
        PermissionError: If required permission is not available
    """
    if required_permission == "read":
        if not os.access(file_path, os.R_OK):
            raise PermissionError(
                f"Read permission denied: {file_path}",
                resource=str(file_path),
                required_permission="read"
            )
    elif required_permission == "write":
        if not os.access(file_path, os.W_OK):
            raise PermissionError(
                f"Write permission denied: {file_path}",
                resource=str(file_path),
                required_permission="write"
            )


def calculate_file_hash(file_path: Path, algorithm: str = "sha256") -> str:
    """
    Calculate file hash
    
    Args:
        file_path: Path to file
        algorithm: Hash algorithm (md5, sha1, sha256)
        
    Returns:
        Hexadecimal hash string
        
    Raises:
        ValidationError: If algorithm is invalid
    """
    valid_algorithms = ["md5", "sha1", "sha256"]
    if algorithm not in valid_algorithms:
        raise ValidationError(
            f"Invalid hash algorithm: {algorithm}",
            field="algorithm",
            value=algorithm
        )
    
    hash_obj = hashlib.new(algorithm)
    
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)
    except OSError as e:
        raise PermissionError(f"Cannot read file: {file_path}", resource=str(file_path)) from e
    
    return hash_obj.hexdigest()


def is_safe_filename(filename: str) -> bool:
    """
    Check if filename is safe (no path traversal, no special characters)
    
    Args:
        filename: Filename to check
        
    Returns:
        True if filename is safe
    """
    # Check for path traversal
    if ".." in filename or "/" in filename or "\\" in filename:
        return False
    
    # Check for null bytes
    if "\x00" in filename:
        return False
    
    # Check for other dangerous characters
    dangerous_chars = ["<", ">", ":", '"', "|", "?", "*"]
    if any(char in filename for char in dangerous_chars):
        return False
    
    return True


def validate_output_path(output_path: Path, allow_overwrite: bool = False) -> None:
    """
    Validate output path for writing
    
    Args:
        output_path: Path to validate
        allow_overwrite: Whether to allow overwriting existing files
        
    Raises:
        ValidationError: If path is invalid
        PermissionError: If write permission is denied
    """
    # Check if parent directory exists and is writable
    parent = output_path.parent
    if not parent.exists():
        try:
            parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            raise PermissionError(
                f"Cannot create directory: {parent}",
                resource=str(parent),
                required_permission="write"
            ) from e
    
    # Check write permission
    validate_file_permissions(parent, "write")
    
    # Check if file exists and overwrite is not allowed
    if output_path.exists() and not allow_overwrite:
        raise ValidationError(
            f"File already exists: {output_path}",
            field="output_path",
            value=str(output_path)
        )
