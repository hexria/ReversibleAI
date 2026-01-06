"""
Unit tests for hash patterns
"""

import pytest
import tempfile
from pathlib import Path
import json

from reversibleai.core.hash_patterns.matcher import HashPatternMatcher
from reversibleai.core.hash_patterns.signatures import SignatureDatabase, Signature
from reversibleai.core.exceptions import LoaderError


class TestHashPatternMatcher:
    """Test hash pattern matcher functionality"""
    
    def test_matcher_initialization(self, temp_directory: Path) -> None:
        """Test matcher initialization"""
        # Create a temporary signature database
        db_path = temp_directory / "test.db"
        db_path.write_text("{}")
        
        matcher = HashPatternMatcher(db_path)
        assert matcher.db_path == db_path
    
    def test_match_file_hashes(self, sample_pe_file: Path, temp_directory: Path) -> None:
        """Test file hash matching"""
        db_path = temp_directory / "test.db"
        db_path.write_text("{}")
        
        matcher = HashPatternMatcher(db_path)
        matches = matcher.match_file_hashes(sample_pe_file)
        
        assert isinstance(matches, list)
    
    def test_match_string_hashes(self, temp_directory: Path) -> None:
        """Test string hash matching"""
        db_path = temp_directory / "test.db"
        db_path.write_text("{}")
        
        matcher = HashPatternMatcher(db_path)
        strings = ["test", "string", "example"]
        matches = matcher.match_string_hashes(strings)
        
        assert isinstance(matches, list)
    
    def test_match_function_hashes(self, temp_directory: Path) -> None:
        """Test function hash matching"""
        db_path = temp_directory / "test.db"
        db_path.write_text("{}")
        
        matcher = HashPatternMatcher(db_path)
        functions = [{"name": "test_func", "address": 0x1000}]
        matches = matcher.match_function_hashes(functions)
        
        assert isinstance(matches, list)
    
    def test_match_import_hashes(self, temp_directory: Path) -> None:
        """Test import hash matching"""
        db_path = temp_directory / "test.db"
        db_path.write_text("{}")
        
        matcher = HashPatternMatcher(db_path)
        imports = [{"library": "kernel32.dll", "function": "CreateFile"}]
        matches = matcher.match_import_hashes(imports)
        
        assert isinstance(matches, list)
    
    def test_invalid_database(self) -> None:
        """Test matcher with invalid database"""
        with pytest.raises((FileNotFoundError, ValueError)):
            HashPatternMatcher(Path("nonexistent.db"))


class TestSignatureDatabase:
    """Test signature database functionality"""
    
    def test_database_initialization(self, temp_directory: Path) -> None:
        """Test database initialization"""
        db_path = temp_directory / "test.db"
        db = SignatureDatabase(db_path)
        
        assert db.db_path == db_path
    
    def test_add_signature(self, temp_directory: Path) -> None:
        """Test adding signature"""
        db_path = temp_directory / "test.db"
        db = SignatureDatabase(db_path)
        
        signature = Signature(
            id="test-001",
            name="Test Signature",
            description="Test description",
            family="test",
            category="test",
            severity="low",
            confidence=0.5,
            rules=[{"type": "hash", "value": "abc123"}]
        )
        
        success = db.add_signature(signature)
        assert success is True
    
    def test_get_signature(self, temp_directory: Path) -> None:
        """Test getting signature"""
        db_path = temp_directory / "test.db"
        db = SignatureDatabase(db_path)
        
        signature = Signature(
            id="test-001",
            name="Test Signature",
            description="Test description",
            family="test",
            category="test",
            severity="low",
            confidence=0.5,
            rules=[{"type": "hash", "value": "abc123"}]
        )
        
        db.add_signature(signature)
        retrieved = db.get_signature("test-001")
        
        assert retrieved is not None
        assert retrieved.id == "test-001"
    
    def test_search_signatures(self, temp_directory: Path) -> None:
        """Test searching signatures"""
        db_path = temp_directory / "test.db"
        db = SignatureDatabase(db_path)
        
        signature = Signature(
            id="test-001",
            name="Test Signature",
            description="Test description",
            family="test",
            category="test",
            severity="low",
            confidence=0.5,
            rules=[{"type": "hash", "value": "abc123"}]
        )
        
        db.add_signature(signature)
        results = db.search_signatures("test")
        
        assert len(results) > 0
    
    def test_validate_signature(self, temp_directory: Path) -> None:
        """Test signature validation"""
        db_path = temp_directory / "test.db"
        db = SignatureDatabase(db_path)
        
        # Valid signature
        valid_sig = Signature(
            id="test-001",
            name="Test Signature",
            description="Test description",
            family="test",
            category="test",
            severity="low",
            confidence=0.5,
            rules=[{"type": "hash", "value": "abc123"}]
        )
        
        errors = db.validate_signature(valid_sig)
        assert len(errors) == 0
        
        # Invalid signature (missing required fields)
        invalid_sig = Signature(
            id="",
            name="",
            description="",
            family="",
            category="",
            severity="invalid",
            confidence=2.0,
            rules=[]
        )
        
        errors = db.validate_signature(invalid_sig)
        assert len(errors) > 0
