"""
Main static analyzer class
"""

from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass
import networkx as nx

from loguru import logger

from ..loader.factory import LoaderFactory
from ..loader.base import BaseLoader
from .disassembler import Disassembler
from .function_analyzer import FunctionAnalyzer
from .control_flow import ControlFlowAnalyzer
from .data_flow import DataFlowAnalyzer


@dataclass
class AnalysisResult:
    """Results of static analysis"""
    functions: List[Dict[str, Any]]
    strings: List[str]
    imports: List[Dict[str, Any]]
    exports: List[Dict[str, Any]]
    sections: List[Dict[str, Any]]
    control_flow_graph: nx.DiGraph
    data_flow_info: Dict[str, Any]
    metadata: Dict[str, Any]


class StaticAnalyzer:
    """Main static analyzer class that coordinates all analysis components"""
    
    def __init__(self, file_path: Path) -> None:
        self.file_path = Path(file_path)
        self.loader: Optional[BaseLoader] = None
        self.disassembler: Optional[Disassembler] = None
        self.function_analyzer: Optional[FunctionAnalyzer] = None
        self.control_flow_analyzer: Optional[ControlFlowAnalyzer] = None
        self.data_flow_analyzer: Optional[DataFlowAnalyzer] = None
        
        self._load_binary()
        self._initialize_components()
    
    def _load_binary(self) -> None:
        """Load the binary file"""
        try:
            self.loader = LoaderFactory.create_loader(self.file_path)
            logger.info(f"Loaded binary: {self.file_path}")
        except Exception as e:
            logger.error(f"Failed to load binary {self.file_path}: {e}")
            raise
    
    def _initialize_components(self) -> None:
        """Initialize analysis components"""
        if not self.loader:
            raise RuntimeError("Binary not loaded")
        
        binary_info = self.loader.info
        
        self.disassembler = Disassembler(
            architecture=binary_info.architecture,
            bits=binary_info.bits,
            endianness=binary_info.endianness
        )
        
        self.function_analyzer = FunctionAnalyzer(self.loader)
        self.control_flow_analyzer = ControlFlowAnalyzer()
        self.data_flow_analyzer = DataFlowAnalyzer()
    
    def analyze(self, 
                analyze_functions: bool = True,
                analyze_strings: bool = True,
                analyze_control_flow: bool = True,
                analyze_data_flow: bool = True,
                min_string_length: int = 4) -> AnalysisResult:
        """
        Perform comprehensive static analysis
        
        Args:
            analyze_functions: Whether to analyze functions
            analyze_strings: Whether to extract strings
            analyze_control_flow: Whether to analyze control flow
            analyze_data_flow: Whether to analyze data flow
            min_string_length: Minimum string length to extract
            
        Returns:
            AnalysisResult object with all findings
        """
        if not self.loader:
            raise RuntimeError("Binary not loaded")
        
        logger.info(f"Starting static analysis of {self.file_path}")
        
        # Get basic information
        binary_info = self.loader.info
        
        # Extract strings
        strings = []
        if analyze_strings:
            strings = self.loader.get_strings(min_string_length)
            logger.info(f"Extracted {len(strings)} strings")
        
        # Analyze functions
        functions = []
        if analyze_functions and self.function_analyzer:
            functions = self.function_analyzer.analyze_functions()
            logger.info(f"Analyzed {len(functions)} functions")
        
        # Analyze control flow
        cfg = nx.DiGraph()
        if analyze_control_flow and self.control_flow_analyzer:
            cfg = self.control_flow_analyzer.build_cfg(functions)
            logger.info(f"Built CFG with {cfg.number_of_nodes()} nodes, {cfg.number_of_edges()} edges")
        
        # Analyze data flow
        data_flow_info = {}
        if analyze_data_flow and self.data_flow_analyzer:
            data_flow_info = self.data_flow_analyzer.analyze(functions, cfg)
            logger.info("Completed data flow analysis")
        
        result = AnalysisResult(
            functions=functions,
            strings=strings,
            imports=binary_info.imports,
            exports=binary_info.exports,
            sections=binary_info.sections,
            control_flow_graph=cfg,
            data_flow_info=data_flow_info,
            metadata={
                "file_info": {
                    "path": str(binary_info.path),
                    "file_type": binary_info.file_type.value,
                    "architecture": binary_info.architecture,
                    "bits": binary_info.bits,
                    "endianness": binary_info.endianness,
                    "entry_point": hex(binary_info.entry_point),
                    "image_base": hex(binary_info.image_base),
                    "size": binary_info.size,
                    "md5": binary_info.md5,
                    "sha1": binary_info.sha1,
                    "sha256": binary_info.sha256,
                },
                "analysis_config": {
                    "analyze_functions": analyze_functions,
                    "analyze_strings": analyze_strings,
                    "analyze_control_flow": analyze_control_flow,
                    "analyze_data_flow": analyze_data_flow,
                    "min_string_length": min_string_length,
                }
            }
        )
        
        logger.info("Static analysis completed")
        return result
    
    def get_function_at_address(self, address: int) -> Optional[Dict[str, Any]]:
        """Get function information at specific address"""
        if not self.function_analyzer:
            return None
        
        return self.function_analyzer.get_function_at_address(address)
    
    def get_functions_by_name(self, name: str) -> List[Dict[str, Any]]:
        """Get functions by name (exact match)"""
        if not self.function_analyzer:
            return []
        
        return self.function_analyzer.get_functions_by_name(name)
    
    def search_functions(self, pattern: str) -> List[Dict[str, Any]]:
        """Search functions by name pattern"""
        if not self.function_analyzer:
            return []
        
        return self.function_analyzer.search_functions(pattern)
    
    def get_imports_by_library(self, library: str) -> List[Dict[str, Any]]:
        """Get imports from specific library"""
        if not self.loader:
            return []
        
        imports = self.loader.info.imports
        return [imp for imp in imports if imp.get("library", "").lower() == library.lower()]
    
    def get_sections_by_permissions(self, permissions: str) -> List[Dict[str, Any]]:
        """Get sections with specific permissions (e.g., 'RX', 'RWX')"""
        if not self.loader:
            return []
        
        sections = self.loader.info.sections
        return [sec for sec in sections if sec.get("permissions", "") == permissions]
    
    def find_strings_containing(self, substring: str, case_sensitive: bool = True) -> List[str]:
        """Find strings containing specific substring"""
        if not self.loader:
            return []
        
        strings = self.loader.get_strings()
        
        if not case_sensitive:
            substring = substring.lower()
            return [s for s in strings if substring in s.lower()]
        else:
            return [s for s in strings if substring in s]
    
    def get_analysis_summary(self) -> Dict[str, Any]:
        """Get a summary of analysis results"""
        if not self.loader:
            return {}
        
        binary_info = self.loader.info
        
        return {
            "file": {
                "name": self.file_path.name,
                "size": binary_info.size,
                "type": binary_info.file_type.value,
                "architecture": binary_info.architecture,
                "bits": binary_info.bits,
            },
            "structure": {
                "sections_count": len(binary_info.sections),
                "imports_count": len(binary_info.imports),
                "exports_count": len(binary_info.exports),
                "entry_point": hex(binary_info.entry_point),
            },
            "hashes": {
                "md5": binary_info.md5,
                "sha1": binary_info.sha1,
                "sha256": binary_info.sha256,
            }
        }
