"""
Unit tests for static analyzer
"""

import pytest
from pathlib import Path

from reversibleai.core.static_analyzer.analyzer import StaticAnalyzer
from reversibleai.core.exceptions import LoaderError


class TestStaticAnalyzer:
    """Test static analyzer functionality"""
    
    def test_analyzer_initialization(self, sample_pe_file: Path) -> None:
        """Test analyzer initialization"""
        analyzer = StaticAnalyzer(sample_pe_file)
        assert analyzer.loader is not None
        assert analyzer.disassembler is not None
    
    def test_analyze_pe_file(self, sample_pe_file: Path) -> None:
        """Test PE file analysis"""
        analyzer = StaticAnalyzer(sample_pe_file)
        result = analyzer.analyze()
        
        assert result is not None
        assert hasattr(result, 'functions')
        assert hasattr(result, 'strings')
        assert hasattr(result, 'imports')
        assert hasattr(result, 'exports')
    
    def test_analyze_with_options(self, sample_pe_file: Path) -> None:
        """Test analysis with custom options"""
        analyzer = StaticAnalyzer(sample_pe_file)
        result = analyzer.analyze(
            analyze_functions=True,
            analyze_strings=False,
            min_string_length=8
        )
        
        assert result is not None
        assert len(result.strings) == 0  # Strings disabled
    
    def test_get_function_by_address(self, sample_pe_file: Path) -> None:
        """Test function lookup by address"""
        analyzer = StaticAnalyzer(sample_pe_file)
        analyzer.analyze()
        
        # Test with valid address
        func = analyzer.get_function_at_address(0x1000)
        # May return None for sample file
        
        # Test with invalid address
        func = analyzer.get_function_at_address(0xFFFFFFFF)
        assert func is None
    
    def test_search_functions(self, sample_pe_file: Path) -> None:
        """Test function search"""
        analyzer = StaticAnalyzer(sample_pe_file)
        analyzer.analyze()
        
        # Search for functions
        results = analyzer.search_functions("main")
        assert isinstance(results, list)
    
    def test_invalid_file(self) -> None:
        """Test analysis of invalid file"""
        with pytest.raises(LoaderError):
            StaticAnalyzer(Path("nonexistent.exe"))
