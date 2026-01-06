"""
Unit tests for annotations
"""

import pytest
import tempfile
from pathlib import Path

from reversibleai.core.annotations.manager import AnnotationManager, FunctionAnnotation, CommentAnnotation
from reversibleai.core.annotations.database import AnnotationDatabase


class TestAnnotationManager:
    """Test annotation manager functionality"""
    
    def test_manager_initialization(self, temp_directory: Path) -> None:
        """Test manager initialization"""
        db_path = temp_directory / "annotations.db"
        manager = AnnotationManager(db_path)
        
        assert manager.db_path == db_path
    
    def test_add_function_annotation(self, temp_directory: Path) -> None:
        """Test adding function annotation"""
        db_path = temp_directory / "annotations.db"
        manager = AnnotationManager(db_path)
        
        annotation = FunctionAnnotation(
            address=0x1000,
            name="test_func",
            description="Test function",
            parameters=[],
            return_value={},
            calling_convention="cdecl",
            tags=[],
            confidence=0.8,
            source="manual",
            metadata={}
        )
        
        success = manager.add_function_annotation(annotation)
        assert success is True
    
    def test_get_function_annotation(self, temp_directory: Path) -> None:
        """Test getting function annotation"""
        db_path = temp_directory / "annotations.db"
        manager = AnnotationManager(db_path)
        
        annotation = FunctionAnnotation(
            address=0x1000,
            name="test_func",
            description="Test function",
            parameters=[],
            return_value={},
            calling_convention="cdecl",
            tags=[],
            confidence=0.8,
            source="manual",
            metadata={}
        )
        
        manager.add_function_annotation(annotation)
        retrieved = manager.get_function_annotation(0x1000)
        
        assert retrieved is not None
        assert retrieved.name == "test_func"
    
    def test_add_comment(self, temp_directory: Path) -> None:
        """Test adding comment"""
        db_path = temp_directory / "annotations.db"
        manager = AnnotationManager(db_path)
        
        comment = CommentAnnotation(
            address=0x1000,
            comment="Test comment",
            author="test",
            timestamp="2026-01-01",
            type="inline",
            metadata={}
        )
        
        success = manager.add_comment(comment)
        assert success is True
    
    def test_search_annotations(self, temp_directory: Path) -> None:
        """Test searching annotations"""
        db_path = temp_directory / "annotations.db"
        manager = AnnotationManager(db_path)
        
        annotation = FunctionAnnotation(
            address=0x1000,
            name="test_func",
            description="Test function",
            parameters=[],
            return_value={},
            calling_convention="cdecl",
            tags=["test"],
            confidence=0.8,
            source="manual",
            metadata={}
        )
        
        manager.add_function_annotation(annotation)
        results = manager.search_function_annotations("test")
        
        assert len(results) > 0


class TestAnnotationDatabase:
    """Test annotation database functionality"""
    
    def test_database_initialization(self, temp_directory: Path) -> None:
        """Test database initialization"""
        db_path = temp_directory / "annotations.db"
        db = AnnotationDatabase(db_path)
        
        assert db.db_path == db_path
        assert db.connection is not None
    
    def test_add_function_annotation(self, temp_directory: Path) -> None:
        """Test adding function annotation to database"""
        db_path = temp_directory / "annotations.db"
        db = AnnotationDatabase(db_path)
        
        annotation = FunctionAnnotation(
            address=0x1000,
            name="test_func",
            description="Test function",
            parameters=[],
            return_value={},
            calling_convention="cdecl",
            tags=[],
            confidence=0.8,
            source="manual",
            metadata={}
        )
        
        success = db.add_function_annotation(annotation)
        assert success is True
