"""
Unit tests for data flow analyzer
"""

import pytest
import networkx as nx

from reversibleai.core.static_analyzer.data_flow import DataFlowAnalyzer


class TestDataFlowAnalyzer:
    """Test data flow analyzer functionality"""
    
    def test_analyzer_initialization(self) -> None:
        """Test analyzer initialization"""
        analyzer = DataFlowAnalyzer()
        assert analyzer is not None
    
    def test_analyze_empty(self) -> None:
        """Test analysis with empty input"""
        analyzer = DataFlowAnalyzer()
        cfg = nx.DiGraph()
        result = analyzer.analyze([], cfg)
        
        assert isinstance(result, dict)
    
    def test_track_variables(self) -> None:
        """Test variable tracking"""
        analyzer = DataFlowAnalyzer()
        
        instructions = [
            {"address": 0x1000, "mnemonic": "mov", "operands": "eax, 0x10"},
            {"address": 0x1005, "mnemonic": "mov", "operands": "ebx, eax"}
        ]
        
        variables = analyzer.track_variables(instructions)
        assert isinstance(variables, dict)
    
    def test_find_dependencies(self) -> None:
        """Test dependency finding"""
        analyzer = DataFlowAnalyzer()
        
        instructions = [
            {"address": 0x1000, "mnemonic": "mov", "operands": "eax, 0x10"},
            {"address": 0x1005, "mnemonic": "add", "operands": "eax, ebx"}
        ]
        
        deps = analyzer.find_dependencies(instructions)
        assert isinstance(deps, list)
