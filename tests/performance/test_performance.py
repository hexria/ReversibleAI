"""
Performance tests for ReversibleAI
"""

import pytest
import time
from pathlib import Path

from reversibleai.core.static_analyzer.analyzer import StaticAnalyzer
from reversibleai.core.string_extractor.extractor import StringExtractor


@pytest.mark.slow
class TestPerformance:
    """Performance tests"""
    
    def test_analyzer_performance(self, sample_pe_file: Path) -> None:
        """Test analyzer performance"""
        start_time = time.time()
        
        analyzer = StaticAnalyzer(sample_pe_file)
        result = analyzer.analyze()
        
        elapsed = time.time() - start_time
        
        # Should complete in reasonable time (adjust threshold as needed)
        assert elapsed < 10.0  # 10 seconds for small files
        assert result is not None
    
    def test_string_extraction_performance(self, sample_pe_file: Path) -> None:
        """Test string extraction performance"""
        start_time = time.time()
        
        extractor = StringExtractor(sample_pe_file)
        strings = extractor.extract_strings(min_length=4)
        
        elapsed = time.time() - start_time
        
        # Should complete quickly
        assert elapsed < 5.0
        assert isinstance(strings, list)
    
    def test_memory_usage(self, sample_pe_file: Path) -> None:
        """Test memory usage during analysis"""
        import tracemalloc
        
        tracemalloc.start()
        
        analyzer = StaticAnalyzer(sample_pe_file)
        result = analyzer.analyze()
        
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        
        # Peak memory should be reasonable (adjust threshold as needed)
        # Convert bytes to MB
        peak_mb = peak / (1024 * 1024)
        assert peak_mb < 500  # Less than 500 MB for small files
