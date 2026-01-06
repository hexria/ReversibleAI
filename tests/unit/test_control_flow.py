"""
Unit tests for control flow analyzer
"""

import pytest
import networkx as nx

from reversibleai.core.static_analyzer.control_flow import ControlFlowAnalyzer


class TestControlFlowAnalyzer:
    """Test control flow analyzer functionality"""
    
    def test_analyzer_initialization(self) -> None:
        """Test analyzer initialization"""
        analyzer = ControlFlowAnalyzer()
        assert analyzer is not None
    
    def test_build_cfg_empty(self) -> None:
        """Test building CFG with empty function list"""
        analyzer = ControlFlowAnalyzer()
        cfg = analyzer.build_cfg([])
        
        assert isinstance(cfg, nx.DiGraph)
        assert cfg.number_of_nodes() == 0
        assert cfg.number_of_edges() == 0
    
    def test_build_cfg_simple(self) -> None:
        """Test building CFG with simple functions"""
        analyzer = ControlFlowAnalyzer()
        
        functions = [
            {
                "start_address": 0x1000,
                "end_address": 0x1050,
                "instructions": [
                    {"address": 0x1000, "mnemonic": "call", "operands": "0x2000"},
                    {"address": 0x1005, "mnemonic": "ret", "operands": ""}
                ]
            }
        ]
        
        cfg = analyzer.build_cfg(functions)
        
        assert isinstance(cfg, nx.DiGraph)
        assert cfg.number_of_nodes() > 0
    
    def test_analyze_basic_blocks(self) -> None:
        """Test basic block analysis"""
        analyzer = ControlFlowAnalyzer()
        
        functions = [
            {
                "start_address": 0x1000,
                "end_address": 0x1050,
                "instructions": [
                    {"address": 0x1000, "mnemonic": "push", "operands": "ebp"},
                    {"address": 0x1001, "mnemonic": "mov", "operands": "ebp, esp"},
                    {"address": 0x1003, "mnemonic": "ret", "operands": ""}
                ]
            }
        ]
        
        blocks = analyzer.analyze_basic_blocks(functions[0])
        assert isinstance(blocks, list)
        assert len(blocks) > 0
    
    def test_find_loops(self) -> None:
        """Test loop detection"""
        analyzer = ControlFlowAnalyzer()
        
        # Create a simple loop structure
        cfg = nx.DiGraph()
        cfg.add_edge(0x1000, 0x1010)
        cfg.add_edge(0x1010, 0x1000)  # Loop back
        
        loops = analyzer.find_loops(cfg)
        assert isinstance(loops, list)
