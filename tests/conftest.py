"""
Pytest configuration and fixtures
"""

import pytest
import tempfile
from pathlib import Path
from typing import Generator

# Test fixtures
@pytest.fixture
def temp_directory() -> Generator[Path, None, None]:
    """Create temporary directory for tests"""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)

@pytest.fixture
def sample_pe_file(temp_directory: Path) -> Path:
    """Create a sample PE file for testing"""
    # Minimal PE header for testing
    pe_data = (
        b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff'
        b'\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00@'
    )
    
    pe_file = temp_directory / "sample.exe"
    pe_file.write_bytes(pe_data)
    return pe_file

@pytest.fixture
def sample_elf_file(temp_directory: Path) -> Path:
    """Create a sample ELF file for testing"""
    # Minimal ELF header for testing
    elf_data = (
        b'\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x02\x00>\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00'
    )
    
    elf_file = temp_directory / "sample.elf"
    elf_file.write_bytes(elf_data)
    return elf_file

@pytest.fixture
def sample_macho_file(temp_directory: Path) -> Path:
    """Create a sample Mach-O file for testing"""
    # Minimal Mach-O header for testing
    macho_data = (
        b'\xcf\xfa\xed\xfe\x07\x00\x00\x01\x03\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    )
    
    macho_file = temp_directory / "sample.macho"
    macho_file.write_bytes(macho_data)
    return macho_file
