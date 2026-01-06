"""
Unit tests for string extractor
"""

import pytest
from pathlib import Path

from reversibleai.core.string_extractor.extractor import StringExtractor, StringInfo
from reversibleai.core.exceptions import LoaderError


class TestStringExtractor:
    """Test string extractor functionality"""
    
    def test_extractor_initialization(self, sample_pe_file: Path) -> None:
        """Test extractor initialization"""
        extractor = StringExtractor(sample_pe_file)
        assert extractor.file_path == sample_pe_file
        assert extractor.strings == []
    
    def test_extract_strings(self, sample_pe_file: Path) -> None:
        """Test string extraction"""
        extractor = StringExtractor(sample_pe_file)
        strings = extractor.extract_strings(min_length=4)
        
        assert isinstance(strings, list)
        for string_info in strings:
            assert isinstance(string_info, StringInfo)
            assert len(string_info.value) >= 4
    
    def test_extract_strings_min_length(self, sample_pe_file: Path) -> None:
        """Test string extraction with minimum length"""
        extractor = StringExtractor(sample_pe_file)
        strings = extractor.extract_strings(min_length=8)
        
        for string_info in strings:
            assert len(string_info.value) >= 8
    
    def test_extract_strings_encoding(self, sample_pe_file: Path) -> None:
        """Test string extraction with specific encoding"""
        extractor = StringExtractor(sample_pe_file)
        strings = extractor.extract_strings(encodings=['ascii'])
        
        assert isinstance(strings, list)
    
    def test_find_suspicious_strings(self, sample_pe_file: Path) -> None:
        """Test suspicious string detection"""
        extractor = StringExtractor(sample_pe_file)
        extractor.extract_strings()
        suspicious = extractor.find_suspicious_strings()
        
        assert isinstance(suspicious, list)
    
    def test_calculate_string_entropy(self, sample_pe_file: Path) -> None:
        """Test string entropy calculation"""
        extractor = StringExtractor(sample_pe_file)
        
        # High entropy string
        high_entropy = extractor._calculate_string_entropy("aG8jK2mN9pQ")
        assert high_entropy > 3.0
        
        # Low entropy string
        low_entropy = extractor._calculate_string_entropy("aaaaaaaaaaaa")
        assert low_entropy < 2.0
    
    def test_invalid_file(self) -> None:
        """Test extractor with invalid file"""
        with pytest.raises((FileNotFoundError, LoaderError)):
            extractor = StringExtractor(Path("nonexistent.exe"))
            extractor.extract_strings()


class TestStringInfo:
    """Test StringInfo dataclass"""
    
    def test_string_info_creation(self) -> None:
        """Test StringInfo creation"""
        info = StringInfo(
            value="test",
            address=0x1000,
            section=".text",
            encoding="ascii",
            length=4,
            entropy=2.0
        )
        
        assert info.value == "test"
        assert info.address == 0x1000
        assert info.section == ".text"
        assert info.encoding == "ascii"
        assert info.length == 4
        assert info.entropy == 2.0
    
    def test_string_info_to_dict(self) -> None:
        """Test StringInfo to_dict method"""
        info = StringInfo(
            value="test",
            address=0x1000,
            section=".text",
            encoding="ascii",
            length=4,
            entropy=2.0
        )
        
        result = info.to_dict()
        assert isinstance(result, dict)
        assert result['value'] == "test"
        assert result['address'] == "0x1000"
