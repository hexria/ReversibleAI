"""
Control flow analysis using NetworkX
"""

from typing import List, Dict, Any, Optional, Set, Tuple
import networkx as nx
from loguru import logger


class ControlFlowAnalyzer:
    """Analyzer for building and analyzing control flow graphs"""
    
    def __init__(self) -> None:
        self.cfg: nx.DiGraph = nx.DiGraph()
        self.function_graphs: Dict[str, nx.DiGraph] = {}
    
    def build_cfg(self, functions: List[Dict[str, Any]]) -> nx.DiGraph:
        """
        Build control flow graph from functions
        
        Args:
            functions: List of function information dictionaries
            
        Returns:
            NetworkX directed graph representing the CFG
        """
        logger.info("Building control flow graph")
        
        # Create main CFG
        self.cfg = nx.DiGraph()
        
        # Process each function
        for func in functions:
            func_name = func.get("name", f"func_{func['start_address']}")
            func_graph = self._build_function_cfg(func)
            self.function_graphs[func_name] = func_graph
            
            # Add function node to main CFG
            self.cfg.add_node(
                func_name,
                type="function",
                address=func.get("start_address", 0),
                size=func.get("size", 0),
                instruction_count=func.get("instruction_count", 0),
                basic_block_count=func.get("basic_block_count", 0)
            )
        
        # Add inter-procedural edges (function calls)
        self._add_call_edges(functions)
        
        logger.info(f"Built CFG with {self.cfg.number_of_nodes()} nodes, {self.cfg.number_of_edges()} edges")
        return self.cfg
    
    def _build_function_cfg(self, func: Dict[str, Any]) -> nx.DiGraph:
        """Build CFG for a single function"""
        func_graph = nx.DiGraph()
        basic_blocks = func.get("basic_blocks", [])
        
        if not basic_blocks:
            return func_graph
        
        # Add nodes for basic blocks
        for i, bb in enumerate(basic_blocks):
            bb_name = f"{func.get('name', 'unknown')}_bb_{i}"
            func_graph.add_node(
                bb_name,
                type="basic_block",
                start_address=bb["start_address"],
                end_address=bb["end_address"],
                size=bb["size"],
                instructions=bb["instructions"]
            )
        
        # Add edges based on control flow
        for i, bb in enumerate(basic_blocks):
            bb_name = f"{func.get('name', 'unknown')}_bb_{i}"
            
            if not bb["instructions"]:
                continue
            
            # Get the last instruction in the basic block
            last_insn = bb["instructions"][-1]
            mnemonic = last_insn["mnemonic"].lower()
            
            # Determine successors
            if mnemonic in ["jmp", "je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle", "ja", "jae", "jb", "jbe"]:
                # Unconditional or conditional jump
                target = self._extract_jump_target(last_insn)
                if target:
                    target_bb = self._find_basic_block_by_address(basic_blocks, target)
                    if target_bb:
                        target_name = f"{func.get('name', 'unknown')}_bb_{target_bb}"
                        func_graph.add_edge(bb_name, target_name, type="jump")
                
                # For conditional jumps, also add fall-through edge
                if mnemonic != "jmp" and i + 1 < len(basic_blocks):
                    next_bb_name = f"{func.get('name', 'unknown')}_bb_{i + 1}"
                    func_graph.add_edge(bb_name, next_bb_name, type="fallthrough")
            
            elif mnemonic in ["call", "bl", "blx", "jal"]:
                # Function call - add fall-through edge
                if i + 1 < len(basic_blocks):
                    next_bb_name = f"{func.get('name', 'unknown')}_bb_{i + 1}"
                    func_graph.add_edge(bb_name, next_bb_name, type="call_return")
            
            elif mnemonic in ["ret", "retf", "bx lr", "eret", "jr ra"]:
                # Return - no outgoing edges
                pass
            
            else:
                # Fall-through to next basic block
                if i + 1 < len(basic_blocks):
                    next_bb_name = f"{func.get('name', 'unknown')}_bb_{i + 1}"
                    func_graph.add_edge(bb_name, next_bb_name, type="fallthrough")
        
        return func_graph
    
    def _extract_jump_target(self, instruction: Dict[str, Any]) -> Optional[int]:
        """Extract jump target from instruction"""
        operands = instruction.get("operands", "")
        
        if not operands:
            return None
        
        # Handle different operand formats
        if operands.startswith("0x"):
            try:
                return int(operands, 16)
            except ValueError:
                pass
        
        # Handle memory references like [eax + 0x1234]
        if "[" in operands and "]" in operands:
            # Extract immediate offset if present
            import re
            match = re.search(r'0x[0-9a-fA-F]+', operands)
            if match:
                try:
                    return int(match.group(0), 16)
                except ValueError:
                    pass
        
        return None
    
    def _find_basic_block_by_address(self, basic_blocks: List[Dict[str, Any]], address: int) -> Optional[int]:
        """Find basic block index by address"""
        for i, bb in enumerate(basic_blocks):
            start_addr = int(bb["start_address"], 16)
            end_addr = int(bb["end_address"], 16)
            
            if start_addr <= address < end_addr:
                return i
        
        return None
    
    def _add_call_edges(self, functions: List[Dict[str, Any]]) -> None:
        """Add inter-procedural call edges to the main CFG"""
        for func in functions:
            func_name = func.get("name", f"func_{func['start_address']}")
            calls = func.get("calls", [])
            
            for call_addr in calls:
                # Find the called function
                called_func = self._find_function_by_address(functions, call_addr)
                if called_func:
                    called_name = called_func.get("name", f"func_{called_func['start_address']}")
                    self.cfg.add_edge(func_name, called_name, type="call")
    
    def _find_function_by_address(self, functions: List[Dict[str, Any]], address: int) -> Optional[Dict[str, Any]]:
        """Find function by address"""
        for func in functions:
            if func["start_address"] == address:
                return func
        return None
    
    def get_function_cfg(self, function_name: str) -> Optional[nx.DiGraph]:
        """Get CFG for a specific function"""
        return self.function_graphs.get(function_name)
    
    def get_complexity_metrics(self, function_name: str) -> Dict[str, int]:
        """Calculate complexity metrics for a function"""
        func_graph = self.function_graphs.get(function_name)
        if not func_graph:
            return {}
        
        metrics = {
            "cyclomatic_complexity": self._calculate_cyclomatic_complexity(func_graph),
            "nodes": func_graph.number_of_nodes(),
            "edges": func_graph.number_of_edges(),
            "basic_blocks": func_graph.number_of_nodes(),
        }
        
        return metrics
    
    def _calculate_cyclomatic_complexity(self, graph: nx.DiGraph) -> int:
        """Calculate cyclomatic complexity"""
        if graph.number_of_nodes() == 0:
            return 0
        
        # CC = E - N + 2P
        # where E = edges, N = nodes, P = connected components
        return graph.number_of_edges() - graph.number_of_nodes() + 2 * nx.number_weakly_connected_components(graph)
    
    def find_loops(self, function_name: str) -> List[List[str]]:
        """Find loops in a function CFG"""
        func_graph = self.function_graphs.get(function_name)
        if not func_graph:
            return []
        
        # Find simple cycles (loops)
        try:
            cycles = list(nx.simple_cycles(func_graph))
            return cycles
        except nx.NetworkXError:
            return []
    
    def find_dominators(self, function_name: str) -> Dict[str, Set[str]]:
        """Find dominators for each basic block in a function"""
        func_graph = self.function_graphs.get(function_name)
        if not func_graph:
            return {}
        
        try:
            # Find entry node (first basic block)
            entry_nodes = [n for n, d in func_graph.in_degree() if d == 0]
            if not entry_nodes:
                return {}
            
            entry_node = entry_nodes[0]
            dominators = nx.immediate_dominators(func_graph, entry_node)
            
            # Convert to full dominator sets
            full_dominators = {}
            for node in func_graph.nodes():
                if node == entry_node:
                    full_dominators[node] = {entry_node}
                else:
                    full_dominators[node] = {node, entry_node}
            
            # Iteratively refine dominator sets
            changed = True
            while changed:
                changed = False
                for node in func_graph.nodes():
                    if node == entry_node:
                        continue
                    
                    # Get intersection of predecessors' dominators
                    preds = list(func_graph.predecessors(node))
                    if preds:
                        intersection = set(full_dominators[preds[0]])
                        for pred in preds[1:]:
                            intersection &= set(full_dominators[pred])
                        
                        intersection.add(node)
                        
                        if full_dominators[node] != intersection:
                            full_dominators[node] = intersection
                            changed = True
            
            return full_dominators
            
        except Exception as e:
            logger.warning(f"Failed to compute dominators for {function_name}: {e}")
            return {}
    
    def get_path_analysis(self, function_name: str, start: str, end: str) -> List[List[str]]:
        """Find all paths from start to end in a function CFG"""
        func_graph = self.function_graphs.get(function_name)
        if not func_graph:
            return []
        
        try:
            # Find all simple paths
            paths = list(nx.all_simple_paths(func_graph, start, end))
            return paths
        except nx.NetworkXNoPath:
            return []
        except Exception as e:
            logger.warning(f"Path analysis failed for {function_name}: {e}")
            return []
    
    def export_to_dot(self, function_name: str, output_file: str) -> bool:
        """Export function CFG to DOT format"""
        func_graph = self.function_graphs.get(function_name)
        if not func_graph:
            return False
        
        try:
            nx.drawing.nx_pydot.write_dot(func_graph, output_file)
            return True
        except ImportError:
            logger.warning("pydot not available for DOT export")
            return False
        except Exception as e:
            logger.error(f"Failed to export CFG to DOT: {e}")
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get overall CFG statistics"""
        stats = {
            "total_functions": len(self.function_graphs),
            "total_nodes": self.cfg.number_of_nodes(),
            "total_edges": self.cfg.number_of_edges(),
            "functions": {}
        }
        
        for func_name, func_graph in self.function_graphs.items():
            stats["functions"][func_name] = {
                "basic_blocks": func_graph.number_of_nodes(),
                "edges": func_graph.number_of_edges(),
                "complexity": self._calculate_cyclomatic_complexity(func_graph),
                "loops": len(self.find_loops(func_name)),
            }
        
        return stats
