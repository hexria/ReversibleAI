"""
Unit tests for custom exceptions
"""

import pytest

from reversibleai.core.exceptions import (
    ReversibleAIError,
    AnalysisError,
    LoaderError,
    EmulationError,
    PluginError,
    ConfigurationError,
    ValidationError,
    ReportError,
    ErrorCodes
)


class TestReversibleAIError:
    """Test base exception class"""
    
    def test_basic_error(self) -> None:
        """Test basic error creation"""
        error = ReversibleAIError("Test error")
        assert str(error) == "Test error"
        assert error.message == "Test error"
        assert error.error_code is None
    
    def test_error_with_code(self) -> None:
        """Test error with error code"""
        error = ReversibleAIError("Test error", error_code="ERR_TEST")
        assert str(error) == "[ERR_TEST] Test error"
        assert error.error_code == "ERR_TEST"
    
    def test_error_to_dict(self) -> None:
        """Test error to_dict method"""
        error = ReversibleAIError("Test error", error_code="ERR_TEST", details={"key": "value"})
        result = error.to_dict()
        
        assert result["error_type"] == "ReversibleAIError"
        assert result["message"] == "Test error"
        assert result["error_code"] == "ERR_TEST"
        assert result["details"] == {"key": "value"}


class TestAnalysisError:
    """Test AnalysisError"""
    
    def test_analysis_error(self) -> None:
        """Test analysis error creation"""
        error = AnalysisError("Analysis failed", operation="analyze", target="binary.exe")
        assert error.operation == "analyze"
        assert error.target == "binary.exe"


class TestLoaderError:
    """Test LoaderError"""
    
    def test_loader_error(self) -> None:
        """Test loader error creation"""
        error = LoaderError("Load failed", file_path="test.exe", file_type="PE")
        assert error.file_path == "test.exe"
        assert error.file_type == "PE"


class TestEmulationError:
    """Test EmulationError"""
    
    def test_emulation_error(self) -> None:
        """Test emulation error creation"""
        error = EmulationError("Emulation failed", architecture="x86", address=0x1000)
        assert error.architecture == "x86"
        assert error.address == 0x1000


class TestPluginError:
    """Test PluginError"""
    
    def test_plugin_error(self) -> None:
        """Test plugin error creation"""
        error = PluginError("Plugin failed", plugin_name="test_plugin", plugin_version="1.0.0")
        assert error.plugin_name == "test_plugin"
        assert error.plugin_version == "1.0.0"


class TestConfigurationError:
    """Test ConfigurationError"""
    
    def test_config_error(self) -> None:
        """Test configuration error creation"""
        error = ConfigurationError("Config invalid", config_key="test_key", config_value="invalid")
        assert error.config_key == "test_key"
        assert error.config_value == "invalid"


class TestValidationError:
    """Test ValidationError"""
    
    def test_validation_error(self) -> None:
        """Test validation error creation"""
        error = ValidationError("Validation failed", field="test_field", value="invalid")
        assert error.field == "test_field"
        assert error.value == "invalid"


class TestReportError:
    """Test ReportError"""
    
    def test_report_error(self) -> None:
        """Test report error creation"""
        error = ReportError("Report failed", report_format="html", output_path="report.html")
        assert error.report_format == "html"
        assert error.output_path == "report.html"


class TestErrorCodes:
    """Test ErrorCodes constants"""
    
    def test_error_codes_exist(self) -> None:
        """Test that error codes are defined"""
        assert hasattr(ErrorCodes, "UNKNOWN_ERROR")
        assert hasattr(ErrorCodes, "FILE_NOT_FOUND")
        assert hasattr(ErrorCodes, "ANALYSIS_FAILED")
        assert hasattr(ErrorCodes, "PLUGIN_NOT_FOUND")
