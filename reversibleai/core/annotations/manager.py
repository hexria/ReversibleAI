"""
Annotation manager for functions and code
"""

from pathlib import Path
from typing import Dict, List, Any, Optional
import json
import sqlite3
from datetime import datetime

from loguru import logger

try:
    from .database import AnnotationDatabase
    from .api_info import APIInfo
except ImportError:
    # Handle import errors gracefully
    AnnotationDatabase = None
    APIInfo = None

# Define classes locally if imports fail
@dataclass
class FunctionAnnotation:
    """Represents a function annotation"""
    address: int
    name: str
    description: str
    parameters: List[Dict[str, Any]]
    return_value: Dict[str, Any]
    calling_convention: str
    tags: List[str]
    confidence: float
    source: str  # "manual", "automatic", "imported"
    metadata: Dict[str, Any]

@dataclass
class CommentAnnotation:
    """Represents a comment annotation"""
    address: int
    comment: str
    author: str
    timestamp: str
    type: str  # "inline", "function", "basic_block"
    metadata: Dict[str, Any]
from .manager import FunctionAnnotation, CommentAnnotation


class AnnotationManager:
    """Manages annotations for functions and code"""
    
    def __init__(self, db_path: Optional[Path] = None) -> None:
        self.db_path = db_path or Path("annotations.db")
        self.database = AnnotationDatabase(self.db_path) if AnnotationDatabase else None
        self.api_info = APIInfo() if APIInfo else None
        
        # Load existing annotations
        if self.database:
            self.database.load_annotations()
    
    def add_function_annotation(self, annotation: FunctionAnnotation) -> bool:
        """Add a function annotation"""
        if not self.database:
            logger.warning("Database not available, cannot add annotation")
            return False
        
        try:
            success = self.database.add_function_annotation(annotation)
            if success:
                logger.info(f"Added function annotation: {annotation.name} at {hex(annotation.address)}")
            return success
        except Exception as e:
            logger.error(f"Failed to add function annotation: {e}")
            return False
    
    def get_function_annotation(self, address: int) -> Optional[FunctionAnnotation]:
        """Get function annotation by address"""
        return self.database.get_function_annotation(address)
    
    def get_function_annotations_by_name(self, name: str) -> List[FunctionAnnotation]:
        """Get function annotations by name"""
        if not self.database:
            logger.warning("Database not available, cannot search functions")
            return []
        
        try:
            return self.database.get_function_annotations_by_name(name)
        except Exception as e:
            logger.error(f"Failed to search functions: {e}")
            return []
    
    def search_function_annotations(self, query: str) -> List[FunctionAnnotation]:
        """Search function annotations"""
        if not self.database:
            logger.warning("Database not available, cannot search functions")
            return []
        
        try:
            return self.database.search_function_annotations(query)
        except Exception as e:
            logger.error(f"Failed to search functions: {e}")
            return []
    
    def update_function_annotation(self, annotation: FunctionAnnotation) -> bool:
        """Update a function annotation"""
        try:
            success = self.database.update_function_annotation(annotation)
            if success:
                logger.info(f"Updated function annotation: {annotation.name}")
            return success
        except Exception as e:
            logger.error(f"Failed to update function annotation: {e}")
            return False
    
    def remove_function_annotation(self, address: int) -> bool:
        """Remove a function annotation"""
        try:
            success = self.database.remove_function_annotation(address)
            if success:
                logger.info(f"Removed function annotation at {hex(address)}")
            return success
        except Exception as e:
            logger.error(f"Failed to remove function annotation: {e}")
            return False
    
    def add_comment(self, comment: CommentAnnotation) -> bool:
        """Add a comment annotation"""
        if not self.database:
            logger.warning("Database not available, cannot add comment")
            return False
        
        try:
            success = self.database.add_comment(comment)
            if success:
                logger.debug(f"Added comment at {hex(comment.address)}")
            return success
        except Exception as e:
            logger.error(f"Failed to add comment: {e}")
            return False
    
    def get_comments(self, address: Optional[int] = None) -> List[CommentAnnotation]:
        """Get comments, optionally filtered by address"""
        if not self.database:
            logger.warning("Database not available, cannot get comments")
            return []
        
        try:
            return self.database.get_comments(address)
        except Exception as e:
            logger.error(f"Failed to get comments: {e}")
            return []
    
    def update_comment(self, comment: CommentAnnotation) -> bool:
        """Update a comment"""
        if not self.database:
            logger.warning(" Database not available, cannot update comment")
            return False
        
        try:
            success = self.database.update_comment(comment)
            if success:
                logger.info(f"Updated comment at {hex(comment.address)}")
            return success
        except Exception as e:
            logger.error(f"Failed to update comment: {e}")
            return False
    
    def remove_comment(self, address: int, comment_id: str) -> bool:
        """Remove a comment"""
        if not self.database:
            logger.warning("Database not available, cannot remove comment")
            return False
        
        try:
            success = self.database.remove_comment(address, comment_id)
            if success:
                logger.info(f"Removed comment at {hex(address)}")
            return success
        except Exception as e:
            logger.error(f"Failed to remove comment: {e}")
            return False
    
    def auto_annotate_functions(self, functions: List[Dict[str, Any]]) -> int:
        """Automatically annotate functions based on patterns and API info"""
        if not self.database:
            logger.warning("Database not available, cannot auto-annotate functions")
            return 0
        
        annotated_count = 0
        
        try:
            for func in functions:
                if self._should_annotate_by_pattern(func):
                    annotation = FunctionAnnotation(
                        address=func.get('start_address', 0),
                        name=func.get('name', ''),
                        description=self.api_info.get_function_info(func.get('name', '')),
                        parameters=func.get('parameters', []),
                        return_value=func.get('return_value', {}),
                        calling_convention=self.api_info.get_calling_convention(func.get('name', 'unknown')),
                        tags=self.api_info.get_tags(func.get('name', [])),
                        confidence=0.7,  # Default confidence
                        source='automatic',
                        metadata={'auto_annotated': True}
                    )
                    
                    success = self.add_function_annotation(annotation)
                    if success:
                        annotated_count += 1
                
            logger.info(f"Auto-annotated {annotated_count} functions")
            return annotated_count
            
        except Exception as e:
            logger.error(f"Failed to auto-annotate functions: {e}")
            return 0
    
    def _should_annotate_by_pattern(self, func: Dict[str, Any]) -> bool:
        """Check if function should be annotated based on patterns"""
        name = func.get('name', '').lower()
        
        # Check for common patterns
        if any(pattern in name for pattern in ['main', 'start', 'entry', 'dllmain', 'winmain', 'tls_callback', 'sub_', 'init', "start_"]):
            return True
        
        # Check for obfuscation patterns
        if any(pattern in name for pattern in ['sub_', 'xor', 'decode', 'encrypt', 'decrypt', 'hash', 'calc', 'compute']):
            return True
        
        return False
    
    def _create_pattern_annotation(self, func: Dict[str, Any]) -> Optional[FunctionAnnotation]:
        """Create annotation based on function patterns"""
        name = func.get('name', '')
        address = func.get('start_address', 0)
        
        if 'main' in name.lower():
            return FunctionAnnotation(
                address=address,
                name=name,
                description="Main entry point function",
                parameters=[],
                return_value={'type': 'int', 'description': 'Exit code'},
                calling_convention='cdecl',
                tags=['entry_point', 'main'],
                confidence=0.8,
                source='automatic',
                metadata={'pattern': 'main_function'}
            )
        
        elif 'dllmain' in name.lower():
            return FunctionAnnotation(
                address=address,
                name=name,
                description="DLL entry point function",
                parameters=[
                    {'name': 'hinstDLL', 'type': 'HINSTANCE', 'description': 'DLL module handle'},
                    {'name': 'fdwReason', 'type': 'DWORD', 'description': 'Reason for calling'},
                    {'name': 'lpvReserved', 'type': 'LPVOID', 'description': 'Reserved'}
                ],
                return_value={'type': 'BOOL', 'description': 'Success status'},
                calling_convention='stdcall',
                tags=['entry_point', 'dll'],
                confidence=0.8,
                source='automatic',
                metadata={'pattern': 'dll_main'}
            )
        
        return None
    
    def get_annotation_statistics(self) -> Dict[str, Any]:
        """Get annotation statistics"""
        return self.database.get_statistics()
    
    def export_annotations(self, output_path: Path, format: str = 'json') -> bool:
        """Export annotations to file"""
        try:
            annotations = {
                'function_annotations': [
                    {
                        'address': hex(ann.address),
                        'name': ann.name,
                        'description': ann.description,
                        'parameters': ann.parameters,
                        'return_value': ann.return_value,
                        'calling_convention': ann.calling_convention,
                        'tags': ann.tags,
                        'confidence': ann.confidence,
                        'source': ann.source,
                        'metadata': ann.metadata
                    }
                    for ann in self.database.get_all_function_annotations()
                ],
                'comments': [
                    {
                        'address': hex(comm.address),
                        'comment': comm.comment,
                        'author': comm.author,
                        'timestamp': comm.timestamp,
                        'type': comm.type,
                        'metadata': comm.metadata
                    }
                    for comm in self.database.get_all_comments()
                ]
            }
            
            if format.lower() == 'json':
                with open(output_path, 'w') as f:
                    json.dump(annotations, f, indent=2)
            
            logger.info(f"Exported annotations to {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export annotations: {e}")
            return False
    
    def import_annotations(self, input_path: Path) -> int:
        """Import annotations from file"""
        try:
            with open(input_path, 'r') as f:
                data = json.load(f)
            
            imported_count = 0
            
            # Import function annotations
            for ann_data in data.get('function_annotations', []):
                annotation = FunctionAnnotation(
                    address=int(ann_data['address'], 16),
                    name=ann_data['name'],
                    description=ann_data['description'],
                    parameters=ann_data['parameters'],
                    return_value=ann_data['return_value'],
                    calling_convention=ann_data['calling_convention'],
                    tags=ann_data['tags'],
                    confidence=ann_data['confidence'],
                    source=ann_data['source'],
                    metadata=ann_data['metadata']
                )
                
                if self.add_function_annotation(annotation):
                    imported_count += 1
            
            # Import comments
            for comm_data in data.get('comments', []):
                comment = CommentAnnotation(
                    address=int(comm_data['address'], 16),
                    comment=comm_data['comment'],
                    author=comm_data['author'],
                    timestamp=comm_data['timestamp'],
                    type=comm_data['type'],
                    metadata=comm_data['metadata']
                )
                
                if self.add_comment(comment):
                    imported_count += 1
            
            logger.info(f"Imported {imported_count} annotations from {input_path}")
            return imported_count
            
        except Exception as e:
            logger.error(f"Failed to import annotations: {e}")
            return 0
    
    def search_by_tag(self, tag: str) -> List[FunctionAnnotation]:
        """Search function annotations by tag"""
        return self.database.search_by_tag(tag)
    
    def get_functions_by_confidence(self, min_confidence: float) -> List[FunctionAnnotation]:
        """Get functions with minimum confidence level"""
        return self.database.get_functions_by_confidence(min_confidence)
    
    def get_unannotated_functions(self, functions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Get functions that don't have annotations"""
        unannotated = []
        
        for func in functions:
            address = func.get('start_address', 0)
            if not self.get_function_annotation(address):
                unannotated.append(func)
        
        return unannotated
    
    def suggest_annotations(self, func: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Suggest possible annotations for a function"""
        suggestions = []
        name = func.get('name', '')
        instructions = func.get('instructions', [])
        
        # Check for known API patterns
        if name:
            api_info = self.api_info.get_function_info(name)
            if api_info:
                suggestions.append({
                    'type': 'api_match',
                    'confidence': api_info.get('confidence', 0.5),
                    'annotation': api_info
                })
        
        # Check for instruction patterns
        api_calls = []
        for insn in instructions:
            mnemonic = insn.get('mnemonic', '').lower()
            operands = insn.get('operands', '').lower()
            
            if mnemonic == 'call':
                if any(api in operands for api in ['createfile', 'readfile', 'writefile']):
                    api_calls.append('file_operations')
                elif any(api in operands for api in ['createmutex', 'waitforsingleobject']):
                    api_calls.append('synchronization')
                elif any(api in operands for api in ['socket', 'connect', 'send', 'recv']):
                    api_calls.append('networking')
        
            suggestions.append({
                'type': 'api_match',
                'confidence': api_info.get('confidence', 0.5),
                'annotation': api_info
            })
        
    # Check for instruction patterns
    api_calls = []
    for insn in instructions:
        mnemonic = insn.get('mnemonic', '').lower()
        operands = insn.get('operands', '').lower()
            
        if mnemonic == 'call':
            if any(api in operands for api in ['createfile', 'readfile', 'writefile']):
                api_calls.append('file_operations')
            elif any(api in operands for api in ['createmutex', 'waitforsingleobject']):
                api_calls.append('synchronization')
            elif any(api in operands for api in ['socket', 'connect', 'send', 'recv']):
                api_calls.append('networking')
            return True
        
        return suggestions
