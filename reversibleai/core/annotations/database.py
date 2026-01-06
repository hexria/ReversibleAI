"""
Annotation database for persistent storage
"""

from pathlib import Path
from typing import Dict, List, Any, Optional
import json
import sqlite3
from datetime import datetime

from loguru import logger

from .manager import FunctionAnnotation, CommentAnnotation


class AnnotationDatabase:
    """Database for storing annotations"""
    
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.connection: Optional[sqlite3.Connection] = None
        
        # Initialize database
        self._initialize_database()
    
    def _initialize_database(self) -> None:
        """Initialize SQLite database"""
        try:
            self.connection = sqlite3.connect(str(self.db_path))
            self.connection.row_factory = sqlite3.Row
            
            # Create tables
            self._create_tables()
            
            logger.debug(f"Initialized annotation database: {self.db_path}")
            
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise
    
    def _create_tables(self) -> None:
        """Create database tables"""
        cursor = self.connection.cursor()
        
        # Function annotations table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS function_annotations (
                address INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                parameters TEXT,
                return_value TEXT,
                calling_convention TEXT,
                tags TEXT,
                confidence REAL,
                source TEXT,
                metadata TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Comments table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address INTEGER NOT NULL,
                comment TEXT NOT NULL,
                author TEXT,
                timestamp TEXT,
                type TEXT,
                metadata TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_function_annotations_name ON function_annotations(name)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_comments_address ON comments(address)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_comments_author ON comments(author)')
        
        self.connection.commit()
    
    def load_annotations(self) -> None:
        """Load annotations from database"""
        # This is handled by SQLite queries
        pass
    
    def add_function_annotation(self, annotation: FunctionAnnotation) -> bool:
        """Add a function annotation"""
        try:
            cursor = self.connection.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO function_annotations 
                (address, name, description, parameters, return_value, calling_convention, 
                 tags, confidence, source, metadata, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                annotation.address,
                annotation.name,
                annotation.description,
                json.dumps(annotation.parameters),
                json.dumps(annotation.return_value),
                annotation.calling_convention,
                json.dumps(annotation.tags),
                annotation.confidence,
                annotation.source,
                json.dumps(annotation.metadata),
                datetime.now().isoformat()
            ))
            
            self.connection.commit()
            return True
            
        except Exception as e:
            logger.error(f"Failed to add function annotation: {e}")
            return False
    
    def get_function_annotation(self, address: int) -> Optional[FunctionAnnotation]:
        """Get function annotation by address"""
        try:
            cursor = self.connection.cursor()
            
            cursor.execute('''
                SELECT * FROM function_annotations WHERE address = ?
            ''', (address,))
            
            row = cursor.fetchone()
            if row:
                return self._row_to_function_annotation(row)
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to get function annotation: {e}")
            return None
    
    def get_function_annotations_by_name(self, name: str) -> List[FunctionAnnotation]:
        """Get function annotations by name"""
        try:
            cursor = self.connection.cursor()
            
            cursor.execute('''
                SELECT * FROM function_annotations WHERE name = ?
            ''', (name,))
            
            rows = cursor.fetchall()
            return [self._row_to_function_annotation(row) for row in rows]
            
        except Exception as e:
            logger.error(f"Failed to get function annotations by name: {e}")
            return []
    
    def search_function_annotations(self, query: str) -> List[FunctionAnnotation]:
        """Search function annotations"""
        try:
            cursor = self.connection.cursor()
            
            search_pattern = f'%{query}%'
            
            cursor.execute('''
                SELECT * FROM function_annotations 
                WHERE name LIKE ? OR description LIKE ? OR tags LIKE ?
            ''', (search_pattern, search_pattern, search_pattern))
            
            rows = cursor.fetchall()
            return [self._row_to_function_annotation(row) for row in rows]
            
        except Exception as e:
            logger.error(f"Failed to search function annotations: {e}")
            return []
    
    def update_function_annotation(self, annotation: FunctionAnnotation) -> bool:
        """Update a function annotation"""
        return self.add_function_annotation(annotation)  # Uses INSERT OR REPLACE
    
    def remove_function_annotation(self, address: int) -> bool:
        """Remove a function annotation"""
        try:
            cursor = self.connection.cursor()
            
            cursor.execute('''
                DELETE FROM function_annotations WHERE address = ?
            ''', (address,))
            
            self.connection.commit()
            return cursor.rowcount > 0
            
        except Exception as e:
            logger.error(f"Failed to remove function annotation: {e}")
            return False
    
    def add_comment(self, comment: CommentAnnotation) -> bool:
        """Add a comment"""
        try:
            cursor = self.connection.cursor()
            
            cursor.execute('''
                INSERT INTO comments 
                (address, comment, author, timestamp, type, metadata)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                comment.address,
                comment.comment,
                comment.author,
                comment.timestamp,
                comment.type,
                json.dumps(comment.metadata)
            ))
            
            self.connection.commit()
            return True
            
        except Exception as e:
            logger.error(f"Failed to add comment: {e}")
            return False
    
    def get_comments(self, address: Optional[int] = None) -> List[CommentAnnotation]:
        """Get comments, optionally filtered by address"""
        try:
            cursor = self.connection.cursor()
            
            if address is not None:
                cursor.execute('''
                    SELECT * FROM comments WHERE address = ? ORDER BY created_at
                ''', (address,))
            else:
                cursor.execute('''
                    SELECT * FROM comments ORDER BY created_at
                ''')
            
            rows = cursor.fetchall()
            return [self._row_to_comment(row) for row in rows]
            
        except Exception as e:
            logger.error(f"Failed to get comments: {e}")
            return []
    
    def update_comment(self, comment: CommentAnnotation) -> bool:
        """Update a comment"""
        try:
            cursor = self.connection.cursor()
            
            cursor.execute('''
                UPDATE comments 
                SET comment = ?, author = ?, timestamp = ?, type = ?, metadata = ?, updated_at = ?
                WHERE id = ?
            ''', (
                comment.comment,
                comment.author,
                comment.timestamp,
                comment.type,
                json.dumps(comment.metadata),
                datetime.now().isoformat(),
                comment.metadata.get('id')  # Assuming ID is in metadata
            ))
            
            self.connection.commit()
            return cursor.rowcount > 0
            
        except Exception as e:
            logger.error(f"Failed to update comment: {e}")
            return False
    
    def remove_comment(self, address: int, comment_id: str) -> bool:
        """Remove a comment"""
        try:
            cursor = self.connection.cursor()
            
            cursor.execute('''
                DELETE FROM comments WHERE address = ? AND id = ?
            ''', (address, comment_id))
            
            self.connection.commit()
            return cursor.rowcount > 0
            
        except Exception as e:
            logger.error(f"Failed to remove comment: {e}")
            return False
    
    def get_all_function_annotations(self) -> List[FunctionAnnotation]:
        """Get all function annotations"""
        try:
            cursor = self.connection.cursor()
            
            cursor.execute('SELECT * FROM function_annotations')
            rows = cursor.fetchall()
            
            return [self._row_to_function_annotation(row) for row in rows]
            
        except Exception as e:
            logger.error(f"Failed to get all function annotations: {e}")
            return []
    
    def get_all_comments(self) -> List[CommentAnnotation]:
        """Get all comments"""
        try:
            cursor = self.connection.cursor()
            
            cursor.execute('SELECT * FROM comments')
            rows = cursor.fetchall()
            
            return [self._row_to_comment(row) for row in rows]
            
        except Exception as e:
            logger.error(f"Failed to get all comments: {e}")
            return []
    
    def search_by_tag(self, tag: str) -> List[FunctionAnnotation]:
        """Search function annotations by tag"""
        try:
            cursor = self.connection.cursor()
            
            search_pattern = f'%"{tag}"%'  # Search for tag in JSON array
            
            cursor.execute('''
                SELECT * FROM function_annotations WHERE tags LIKE ?
            ''', (search_pattern,))
            
            rows = cursor.fetchall()
            return [self._row_to_function_annotation(row) for row in rows]
            
        except Exception as e:
            logger.error(f"Failed to search by tag: {e}")
            return []
    
    def get_functions_by_confidence(self, min_confidence: float) -> List[FunctionAnnotation]:
        """Get functions with minimum confidence level"""
        try:
            cursor = self.connection.cursor()
            
            cursor.execute('''
                SELECT * FROM function_annotations WHERE confidence >= ?
            ''', (min_confidence,))
            
            rows = cursor.fetchall()
            return [self._row_to_function_annotation(row) for row in rows]
            
        except Exception as e:
            logger.error(f"Failed to get functions by confidence: {e}")
            return []
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics"""
        try:
            cursor = self.connection.cursor()
            
            # Function annotation stats
            cursor.execute('SELECT COUNT(*) FROM function_annotations')
            total_functions = cursor.fetchone()[0]
            
            cursor.execute('SELECT source, COUNT(*) FROM function_annotations GROUP BY source')
            functions_by_source = dict(cursor.fetchall())
            
            # Comment stats
            cursor.execute('SELECT COUNT(*) FROM comments')
            total_comments = cursor.fetchone()[0]
            
            cursor.execute('SELECT author, COUNT(*) FROM comments GROUP BY author')
            comments_by_author = dict(cursor.fetchall())
            
            return {
                'total_function_annotations': total_functions,
                'functions_by_source': functions_by_source,
                'total_comments': total_comments,
                'comments_by_author': comments_by_author,
            }
            
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
            return {}
    
    def _row_to_function_annotation(self, row) -> FunctionAnnotation:
        """Convert database row to FunctionAnnotation"""
        return FunctionAnnotation(
            address=row['address'],
            name=row['name'],
            description=row['description'] or '',
            parameters=json.loads(row['parameters'] or '[]'),
            return_value=json.loads(row['return_value'] or '{}'),
            calling_convention=row['calling_convention'] or 'unknown',
            tags=json.loads(row['tags'] or '[]'),
            confidence=row['confidence'] or 0.0,
            source=row['source'] or 'unknown',
            metadata=json.loads(row['metadata'] or '{}')
        )
    
    def _row_to_comment(self, row) -> CommentAnnotation:
        """Convert database row to CommentAnnotation"""
        return CommentAnnotation(
            address=row['address'],
            comment=row['comment'],
            author=row['author'] or '',
            timestamp=row['timestamp'] or '',
            type=row['type'] or 'inline',
            metadata=json.loads(row['metadata'] or '{}')
        )
    
    def close(self) -> None:
        """Close database connection"""
        if self.connection:
            self.connection.close()
            self.connection = None
    
    def __del__(self) -> None:
        """Cleanup on deletion"""
        self.close()
