"""
Integration tests for CLI
"""

import pytest
import subprocess
import json
from pathlib import Path


class TestCLI:
    """Test CLI functionality"""
    
    def test_cli_help(self) -> None:
        """Test CLI help command"""
        result = subprocess.run(
            ["python", "-m", "reversibleai.cli.main", "--help"],
            capture_output=True,
            text=True
        )
        
        assert result.returncode == 0
        assert "ReversibleAI" in result.stdout
        assert "analyze" in result.stdout
    
    def test_cli_version(self) -> None:
        """Test CLI version command"""
        result = subprocess.run(
            ["python", "-m", "reversibleai.cli.main", "--version"],
            capture_output=True,
            text=True
        )
        
        assert result.returncode == 0
        assert "0.1.0" in result.stdout
    
    def test_info_command(self, sample_pe_file: Path) -> None:
        """Test info command"""
        result = subprocess.run(
            ["python", "-m", "reversibleai.cli.main", "info", str(sample_pe_file)],
            capture_output=True,
            text=True
        )
        
        assert result.returncode == 0
        assert "PE" in result.stdout
    
    def test_strings_command(self, sample_pe_file: Path) -> None:
        """Test strings command"""
        result = subprocess.run(
            ["python", "-m", "reversibleai.cli.main", "strings", str(sample_pe_file)],
            capture_output=True,
            text=True
        )
        
        assert result.returncode == 0
    
    def test_analyze_command(self, sample_pe_file: Path, temp_directory: Path) -> None:
        """Test analyze command"""
        output_file = temp_directory / "report.html"
        
        result = subprocess.run(
            ["python", "-m", "reversibleai.cli.main", "analyze", 
             str(sample_pe_file), "-o", str(output_file)],
            capture_output=True,
            text=True
        )
        
        assert result.returncode == 0
        assert output_file.exists()
    
    def test_invalid_file(self) -> None:
        """Test CLI with invalid file"""
        result = subprocess.run(
            ["python", "-m", "reversibleai.cli.main", "info", "nonexistent.exe"],
            capture_output=True,
            text=True
        )
        
        assert result.returncode != 0
        assert "not found" in result.stderr.lower()
