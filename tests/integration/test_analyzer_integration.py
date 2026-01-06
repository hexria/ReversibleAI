"""
Integration tests for analyzer
"""

import pytest
from pathlib import Path

from reversibleai.core.static_analyzer.analyzer import StaticAnalyzer


class TestAnalyzerIntegration:
    """Integration tests for analyzer functionality"""
    
    def test_full_analysis_pipeline(self, sample_pe_file: Path) -> None:
        """Test full analysis pipeline"""
        analyzer = StaticAnalyzer(sample_pe_file)
        result = analyzer.analyze(
            analyze_functions=True,
            analyze_strings=True,
            analyze_control_flow=True,
            analyze_data_flow=True
        )
        
        assert result is not None
        assert hasattr(result, 'functions')
        assert hasattr(result, 'strings')
        assert hasattr(result, 'imports')
        assert hasattr(result, 'exports')
        assert hasattr(result, 'control_flow_graph')
        assert hasattr(result, 'data_flow_info')
        assert hasattr(result, 'metadata')
    
    def test_analysis_with_report(self, sample_pe_file: Path, temp_directory: Path) -> None:
        """Test analysis with report generation"""
        analyzer = StaticAnalyzer(sample_pe_file)
        result = analyzer.analyze()
        
        from reversibleai.core.reports.generator import ReportGenerator
        report_gen = ReportGenerator()
        
        output_path = temp_directory / "report.html"
        success = report_gen.generate_analysis_report(
            analysis_result=result.__dict__,
            output_path=output_path,
            format="html"
        )
        
        assert success is True
        assert output_path.exists()
    
    def test_analysis_summary(self, sample_pe_file: Path) -> None:
        """Test getting analysis summary"""
        analyzer = StaticAnalyzer(sample_pe_file)
        summary = analyzer.get_analysis_summary()
        
        assert isinstance(summary, dict)
        assert "file" in summary
        assert "structure" in summary
        assert "hashes" in summary
