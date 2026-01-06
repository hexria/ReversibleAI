"""
Unit tests for report generator
"""

import pytest
from pathlib import Path

from reversibleai.core.reports.generator import ReportGenerator, ReportSection
from reversibleai.core.static_analyzer.analyzer import StaticAnalyzer, AnalysisResult
import networkx as nx


class TestReportGenerator:
    """Test report generator functionality"""
    
    def test_generator_initialization(self) -> None:
        """Test generator initialization"""
        generator = ReportGenerator()
        assert generator.sections == []
        assert generator.metadata == {}
    
    def test_add_section(self) -> None:
        """Test adding report section"""
        generator = ReportGenerator()
        generator.add_section("Test Section", "Test Content", order=1)
        
        assert len(generator.sections) == 1
        assert generator.sections[0].title == "Test Section"
        assert generator.sections[0].content == "Test Content"
    
    def test_set_metadata(self) -> None:
        """Test setting metadata"""
        generator = ReportGenerator()
        generator.set_metadata("key", "value")
        
        assert generator.metadata["key"] == "value"
    
    def test_generate_json_report(self, sample_pe_file: Path, temp_directory: Path) -> None:
        """Test JSON report generation"""
        generator = ReportGenerator()
        generator.add_section("Test", {"data": "test"})
        
        output_path = temp_directory / "report.json"
        success = generator.generate_report(output_path, format="json")
        
        assert success is True
        assert output_path.exists()
    
    def test_generate_html_report(self, sample_pe_file: Path, temp_directory: Path) -> None:
        """Test HTML report generation"""
        generator = ReportGenerator()
        generator.add_section("Test", "<p>Test content</p>")
        
        output_path = temp_directory / "report.html"
        success = generator.generate_report(output_path, format="html")
        
        assert success is True
        assert output_path.exists()
    
    def test_generate_analysis_report(self, sample_pe_file: Path, temp_directory: Path) -> None:
        """Test analysis report generation"""
        analyzer = StaticAnalyzer(sample_pe_file)
        result = analyzer.analyze()
        
        generator = ReportGenerator()
        output_path = temp_directory / "analysis_report.html"
        
        success = generator.generate_analysis_report(
            analysis_result=result.__dict__,
            output_path=output_path,
            format="html"
        )
        
        assert success is True
        assert output_path.exists()
    
    def test_unsupported_format(self, temp_directory: Path) -> None:
        """Test unsupported format handling"""
        generator = ReportGenerator()
        generator.add_section("Test", "Content")
        
        output_path = temp_directory / "report.xyz"
        success = generator.generate_report(output_path, format="xyz")
        
        assert success is False


class TestReportSection:
    """Test ReportSection dataclass"""
    
    def test_section_creation(self) -> None:
        """Test ReportSection creation"""
        section = ReportSection(
            title="Test",
            content="Content",
            order=1,
            metadata={"key": "value"}
        )
        
        assert section.title == "Test"
        assert section.content == "Content"
        assert section.order == 1
        assert section.metadata == {"key": "value"}
