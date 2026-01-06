"""
Integration tests for loader
"""

import pytest
from pathlib import Path

from reversibleai.core.loader.factory import LoaderFactory
from reversibleai.core.loader.base import BinaryType


class TestLoaderIntegration:
    """Integration tests for loader functionality"""
    
    def test_load_and_analyze_pe(self, sample_pe_file: Path) -> None:
        """Test loading and analyzing PE file"""
        loader = LoaderFactory.create_loader(sample_pe_file)
        binary_info = loader.info
        
        assert binary_info.file_type == BinaryType.PE
        assert binary_info.path == sample_pe_file
        assert binary_info.size > 0
    
    def test_load_and_analyze_elf(self, sample_elf_file: Path) -> None:
        """Test loading and analyzing ELF file"""
        loader = LoaderFactory.create_loader(sample_elf_file)
        binary_info = loader.info
        
        assert binary_info.file_type == BinaryType.ELF
        assert binary_info.path == sample_elf_file
    
    def test_load_and_get_strings(self, sample_pe_file: Path) -> None:
        """Test loading and getting strings"""
        loader = LoaderFactory.create_loader(sample_pe_file)
        strings = loader.get_strings(min_length=4)
        
        assert isinstance(strings, list)
    
    def test_load_and_get_sections(self, sample_pe_file: Path) -> None:
        """Test loading and getting sections"""
        loader = LoaderFactory.create_loader(sample_pe_file)
        binary_info = loader.info
        
        assert isinstance(binary_info.sections, list)
    
    def test_load_and_get_imports(self, sample_pe_file: Path) -> None:
        """Test loading and getting imports"""
        loader = LoaderFactory.create_loader(sample_pe_file)
        binary_info = loader.info
        
        assert isinstance(binary_info.imports, list)
    
    def test_load_and_get_exports(self, sample_pe_file: Path) -> None:
        """Test loading and getting exports"""
        loader = LoaderFactory.create_loader(sample_pe_file)
        binary_info = loader.info
        
        assert isinstance(binary_info.exports, list)
