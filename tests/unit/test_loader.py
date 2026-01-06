"""
Unit tests for binary loader
"""

import pytest
from pathlib import Path

from reversibleai.core.loader.factory import LoaderFactory
from reversibleai.core.loader.base import BinaryType


class TestLoader:
    """Test binary loader functionality"""
    
    def test_detect_pe_file(self, sample_pe_file: Path) -> None:
        """Test PE file detection"""
        file_type = LoaderFactory.detect_binary_type(sample_pe_file)
        assert file_type == BinaryType.PE
    
    def test_detect_elf_file(self, sample_elf_file: Path) -> None:
        """Test ELF file detection"""
        file_type = LoaderFactory.detect_binary_type(sample_elf_file)
        assert file_type == BinaryType.ELF
    
    def test_detect_macho_file(self, sample_macho_file: Path) -> None:
        """Test Mach-O file detection"""
        file_type = LoaderFactory.detect_binary_type(sample_macho_file)
        assert file_type == BinaryType.MACHO
    
    def test_create_pe_loader(self, sample_pe_file: Path) -> None:
        """Test PE loader creation"""
        loader = LoaderFactory.create_loader(sample_pe_file)
        assert loader is not None
        assert loader.__class__.__name__ == "PELoader"
    
    def test_create_elf_loader(self, sample_elf_file: Path) -> None:
        """Test ELF loader creation"""
        loader = LoaderFactory.create_loader(sample_elf_file)
        assert loader is not None
        assert loader.__class__.__name__ == "ELFLoader"
    
    def test_unsupported_file(self, temp_directory: Path) -> None:
        """Test unsupported file handling"""
        # Create a text file
        text_file = temp_directory / "test.txt"
        text_file.write_text("Hello, World!")
        
        with pytest.raises(ValueError):
            LoaderFactory.create_loader(text_file)
    
    def test_nonexistent_file(self) -> None:
        """Test nonexistent file handling"""
        with pytest.raises(FileNotFoundError):
            LoaderFactory.create_loader(Path("nonexistent.exe"))
