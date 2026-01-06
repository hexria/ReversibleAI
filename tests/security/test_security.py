"""
Security tests for ReversibleAI
"""

import pytest
import tempfile
from pathlib import Path

from reversibleai.core.security import (
    sanitize_path,
    validate_file_size,
    validate_file_permissions,
    calculate_file_hash,
    is_safe_filename,
    validate_output_path
)
from reversibleai.core.exceptions import ValidationError, PermissionError


class TestPathSanitization:
    """Test path sanitization and traversal protection"""
    
    def test_sanitize_normal_path(self, temp_directory: Path) -> None:
        """Test sanitizing normal path"""
        test_file = temp_directory / "test.txt"
        test_file.write_text("test")
        
        result = sanitize_path(test_file)
        assert result == test_file.resolve()
    
    def test_sanitize_path_traversal(self, temp_directory: Path) -> None:
        """Test path traversal detection"""
        # Try to access parent directory
        malicious_path = temp_directory / ".." / ".." / "etc" / "passwd"
        
        with pytest.raises(ValidationError):
            sanitize_path(malicious_path, base_path=temp_directory)
    
    def test_sanitize_with_base_path(self, temp_directory: Path) -> None:
        """Test sanitization with base path restriction"""
        test_file = temp_directory / "test.txt"
        test_file.write_text("test")
        
        result = sanitize_path(test_file, base_path=temp_directory)
        assert result.exists()
        
        # Try to access outside base path
        outside_file = temp_directory.parent / "outside.txt"
        with pytest.raises(ValidationError):
            sanitize_path(outside_file, base_path=temp_directory)


class TestFileSizeValidation:
    """Test file size validation"""
    
    def test_validate_file_size(self, temp_directory: Path) -> None:
        """Test file size validation"""
        test_file = temp_directory / "test.txt"
        test_file.write_text("test content")
        
        size = validate_file_size(test_file)
        assert size > 0
    
    def test_validate_file_size_max(self, temp_directory: Path) -> None:
        """Test file size validation with maximum"""
        test_file = temp_directory / "test.txt"
        test_file.write_text("test content")
        
        # Should pass with large max
        validate_file_size(test_file, max_size=1000000)
        
        # Should fail with small max
        with pytest.raises(ValidationError):
            validate_file_size(test_file, max_size=1)


class TestFilePermissions:
    """Test file permission validation"""
    
    def test_validate_read_permission(self, temp_directory: Path) -> None:
        """Test read permission validation"""
        test_file = temp_directory / "test.txt"
        test_file.write_text("test")
        
        # Should pass for readable file
        validate_file_permissions(test_file, "read")
    
    def test_validate_write_permission(self, temp_directory: Path) -> None:
        """Test write permission validation"""
        test_file = temp_directory / "test.txt"
        
        # Should pass for writable file
        validate_file_permissions(test_file, "write")


class TestFileHash:
    """Test file hash calculation"""
    
    def test_calculate_file_hash(self, temp_directory: Path) -> None:
        """Test file hash calculation"""
        test_file = temp_directory / "test.txt"
        test_file.write_text("test content")
        
        hash_value = calculate_file_hash(test_file, "sha256")
        assert isinstance(hash_value, str)
        assert len(hash_value) == 64  # SHA256 hex length
    
    def test_calculate_file_hash_md5(self, temp_directory: Path) -> None:
        """Test MD5 hash calculation"""
        test_file = temp_directory / "test.txt"
        test_file.write_text("test content")
        
        hash_value = calculate_file_hash(test_file, "md5")
        assert isinstance(hash_value, str)
        assert len(hash_value) == 32  # MD5 hex length
    
    def test_invalid_hash_algorithm(self, temp_directory: Path) -> None:
        """Test invalid hash algorithm"""
        test_file = temp_directory / "test.txt"
        test_file.write_text("test")
        
        with pytest.raises(ValidationError):
            calculate_file_hash(test_file, "invalid")


class TestFilenameValidation:
    """Test filename safety validation"""
    
    def test_safe_filename(self) -> None:
        """Test safe filename"""
        assert is_safe_filename("test.txt") is True
        assert is_safe_filename("my_file.exe") is True
    
    def test_unsafe_filename_traversal(self) -> None:
        """Test unsafe filename with path traversal"""
        assert is_safe_filename("../etc/passwd") is False
        assert is_safe_filename("..\\windows\\system32") is False
    
    def test_unsafe_filename_special_chars(self) -> None:
        """Test unsafe filename with special characters"""
        assert is_safe_filename("file<name>") is False
        assert is_safe_filename("file:name") is False
        assert is_safe_filename("file|name") is False


class TestOutputPathValidation:
    """Test output path validation"""
    
    def test_validate_output_path(self, temp_directory: Path) -> None:
        """Test output path validation"""
        output_file = temp_directory / "output.txt"
        
        # Should pass for new file
        validate_output_path(output_file)
    
    def test_validate_output_path_exists(self, temp_directory: Path) -> None:
        """Test output path validation with existing file"""
        output_file = temp_directory / "output.txt"
        output_file.write_text("existing")
        
        # Should fail without overwrite permission
        with pytest.raises(ValidationError):
            validate_output_path(output_file, allow_overwrite=False)
        
        # Should pass with overwrite permission
        validate_output_path(output_file, allow_overwrite=True)
