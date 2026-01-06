"""
Data flow analysis for tracking variable usage and dependencies
"""

from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass
import re

from loguru import logger


@dataclass
class Variable:
    """Represents a variable or register in data flow analysis"""
    name: str
    type: str  # "register", "stack", "memory"
    size: int
    definition_address: int
    use_addresses: List[int]
    is_parameter: bool = False
    is_local: bool = False


@dataclass
class DataDependency:
    """Represents a data dependency between variables"""
    source: str
    destination: str
    instruction_address: int
    dependency_type: str  # "def-use", "use-def", "output", "anti"


class DataFlowAnalyzer:
    """Analyzer for data flow and variable tracking"""
    
    def __init__(self) -> None:
        self.variables: Dict[str, Variable] = {}
        self.dependencies: List[DataDependency] = []
        self.def_use_chains: Dict[int, List[str]] = {}  # Address -> variables defined
        self.use_def_chains: Dict[int, List[str]] = {}  # Address -> variables used
    
    def analyze(self, functions: List[Dict[str, Any]], cfg) -> Dict[str, Any]:
        """
        Perform data flow analysis on functions
        
        Args:
            functions: List of function information dictionaries
            cfg: Control flow graph
            
        Returns:
            Dictionary containing data flow analysis results
        """
        logger.info("Starting data flow analysis")
        
        # Analyze each function
        for func in functions:
            func_name = func.get("name", f"func_{func['start_address']}")
            self._analyze_function_data_flow(func)
        
        results = {
            "variables": {name: var.__dict__ for name, var in self.variables.items()},
            "dependencies": [dep.__dict__ for dep in self.dependencies],
            "def_use_chains": self.def_use_chains,
            "use_def_chains": self.use_def_chains,
            "statistics": self._get_statistics(),
        }
        
        logger.info(f"Data flow analysis completed: {len(self.variables)} variables, {len(self.dependencies)} dependencies")
        return results
    
    def _analyze_function_data_flow(self, func: Dict[str, Any]) -> None:
        """Analyze data flow for a single function"""
        basic_blocks = func.get("basic_blocks", [])
        
        if not basic_blocks:
            return
        
        # Track variables across basic blocks
        for bb in basic_blocks:
            self._analyze_basic_block_data_flow(bb, func)
        
        # Analyze function parameters
        self._analyze_function_parameters(func)
        
        # Analyze stack variables
        self._analyze_stack_variables(func)
    
    def _analyze_basic_block_data_flow(self, bb: Dict[str, Any], func: Dict[str, Any]) -> None:
        """Analyze data flow within a basic block"""
        instructions = bb.get("instructions", [])
        
        for insn in instructions:
            address = int(insn["address"], 16)
            mnemonic = insn["mnemonic"]
            operands = insn.get("operands", "")
            
            # Analyze instruction for data flow
            defined_vars = self._get_defined_variables(mnemonic, operands, address)
            used_vars = self._get_used_variables(mnemonic, operands, address)
            
            # Update def-use chains
            if defined_vars:
                self.def_use_chains[address] = defined_vars
            
            if used_vars:
                self.use_def_chains[address] = used_vars
            
            # Create dependencies
            for defined_var in defined_vars:
                for used_var in used_vars:
                    dependency = DataDependency(
                        source=used_var,
                        destination=defined_var,
                        instruction_address=address,
                        dependency_type="def-use"
                    )
                    self.dependencies.append(dependency)
            
            # Update variable information
            for var_name in defined_vars:
                if var_name not in self.variables:
                    self.variables[var_name] = Variable(
                        name=var_name,
                        type=self._classify_variable(var_name),
                        size=self._get_variable_size(var_name, func),
                        definition_address=address,
                        use_addresses=[],
                        is_local=self._is_local_variable(var_name, func),
                        is_parameter=self._is_parameter_variable(var_name, func)
                    )
                else:
                    # Variable redefined
                    self.variables[var_name].definition_address = address
            
            # Update use information
            for var_name in used_vars:
                if var_name in self.variables:
                    if address not in self.variables[var_name].use_addresses:
                        self.variables[var_name].use_addresses.append(address)
    
    def _get_defined_variables(self, mnemonic: str, operands: str, address: int) -> List[str]:
        """Get variables defined by an instruction"""
        defined = []
        mnemonic_lower = mnemonic.lower()
        
        # Instructions that define destination operands
        if mnemonic_lower in ["mov", "lea", "add", "sub", "mul", "div", "and", "or", "xor", "not", "neg"]:
            # First operand is destination
            if operands:
                dest = operands.split(",")[0].strip()
                defined.extend(self._extract_variables_from_operand(dest))
        
        elif mnemonic_lower in ["pop", "inc", "dec"]:
            # Single operand is destination
            if operands:
                defined.extend(self._extract_variables_from_operand(operands))
        
        elif mnemonic_lower in ["push"]:
            # Push doesn't define variables in the traditional sense
            # but it modifies the stack
            pass
        
        elif mnemonic_lower in ["call"]:
            # Call can modify registers according to calling convention
            # For simplicity, we'll track this separately
            pass
        
        return defined
    
    def _get_used_variables(self, mnemonic: str, operands: str, address: int) -> List[str]:
        """Get variables used by an instruction"""
        used = []
        mnemonic_lower = mnemonic.lower()
        
        if operands:
            # Split operands
            op_list = [op.strip() for op in operands.split(",")]
            
            if mnemonic_lower in ["mov", "lea"]:
                # Second operand is source
                if len(op_list) > 1:
                    used.extend(self._extract_variables_from_operand(op_list[1]))
            
            elif mnemonic_lower in ["add", "sub", "mul", "div", "and", "or", "xor"]:
                # Both operands are used (destination is also used)
                for op in op_list:
                    used.extend(self._extract_variables_from_operand(op))
            
            elif mnemonic_lower in ["cmp", "test"]:
                # Both operands are used
                for op in op_list:
                    used.extend(self._extract_variables_from_operand(op))
            
            elif mnemonic_lower in ["push", "pop", "inc", "dec", "not", "neg"]:
                # Single operand is used
                used.extend(self._extract_variables_from_operand(operands))
            
            elif mnemonic_lower in ["jmp", "je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle"]:
                # Jump target might use registers
                used.extend(self._extract_variables_from_operand(operands))
            
            elif mnemonic_lower == "call":
                # Call uses the target and potentially registers for parameters
                used.extend(self._extract_variables_from_operand(operands))
                
                # Add common calling convention registers (simplified)
                used.extend(["eax", "ecx", "edx", "esp", "ebp"])  # x86
                used.extend(["rdi", "rsi", "rdx", "rcx", "r8", "r9"])  # x86_64
        
        return used
    
    def _extract_variables_from_operand(self, operand: str) -> List[str]:
        """Extract variable names from an operand"""
        variables = []
        
        # Register patterns
        register_patterns = [
            r'\b(eax|ebx|ecx|edx|esi|edi|esp|ebp)\b',  # x86
            r'\b(rax|rbx|rcx|rdx|rsi|rdi|rsp|rbp)\b',  # x86_64
            r'\b(r8|r9|r10|r11|r12|r13|r14|r15)\b',    # x86_64 extended
            r'\b(ax|bx|cx|dx|si|di|sp|bp)\b',          # x86 16-bit
            r'\b(ah|al|bh|bl|ch|cl|dh|dl)\b',          # x86 8-bit
            r'\b(r0|r1|r2|r3|r4|r5|r6|r7|r8|r9|r10|r11|r12|r13|r14|r15)\b',  # ARM
        ]
        
        for pattern in register_patterns:
            matches = re.findall(pattern, operand, re.IGNORECASE)
            variables.extend(matches)
        
        # Memory references
        memory_pattern = r'\[([^\]]+)\]'
        memory_matches = re.findall(memory_pattern, operand)
        for match in memory_matches:
            # Extract registers from memory operands
            variables.extend(self._extract_variables_from_operand(match))
        
        # Stack variables (simplified)
        if "ebp" in operand or "rbp" in operand:
            if "-" in operand:
                # [ebp - 0x10] -> stack variable
                variables.append(f"stack_{operand}")
        
        return list(set(variables))  # Remove duplicates
    
    def _classify_variable(self, var_name: str) -> str:
        """Classify variable type"""
        if var_name.startswith("stack_"):
            return "stack"
        elif re.match(r'^(e|r)?[abcd]x$|^[er]s[pi]$|^[er]b[pi]$', var_name):
            return "register"
        elif re.match(r'^r\d+$', var_name):
            return "register"
        else:
            return "memory"
    
    def _get_variable_size(self, var_name: str, func: Dict[str, Any]) -> int:
        """Get variable size in bytes"""
        # This is a simplified implementation
        # In practice, you'd need to track the size based on the architecture and context
        
        if var_name.startswith("stack_"):
            return 4  # Assume 4 bytes for stack variables
        
        # Register sizes
        if var_name in ["eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp"]:
            return 4
        elif var_name in ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp"]:
            return 8
        elif var_name in ["ax", "bx", "cx", "dx", "si", "di", "sp", "bp"]:
            return 2
        elif var_name in ["ah", "al", "bh", "bl", "ch", "cl", "dh", "dl"]:
            return 1
        elif var_name.startswith("r") and var_name[1:].isdigit():
            return 8
        
        return 4  # Default size
    
    def _is_local_variable(self, var_name: str, func: Dict[str, Any]) -> bool:
        """Check if variable is a local variable"""
        return var_name.startswith("stack_")
    
    def _is_parameter_variable(self, var_name: str, func: Dict[str, Any]) -> bool:
        """Check if variable is a function parameter"""
        # This is simplified - in practice, you'd analyze the function prologue
        # and calling convention to determine parameters
        
        # Common parameter registers for different calling conventions
        param_registers = {
            "cdecl": ["eax", "edx", "ecx"],
            "stdcall": ["eax", "edx", "ecx"],
            "fastcall": ["ecx", "edx", "eax"],
            "x86_64": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
            "arm": ["r0", "r1", "r2", "r3"],
        }
        
        for convention, regs in param_registers.items():
            if var_name in regs:
                return True
        
        return False
    
    def _analyze_function_parameters(self, func: Dict[str, Any]) -> None:
        """Analyze function parameters"""
        # This is a simplified implementation
        # In practice, you'd analyze the function prologue and calling convention
        
        func_name = func.get("name", f"func_{func['start_address']}")
        
        # Look for common parameter access patterns
        for var_name, var in self.variables.items():
            if self._is_parameter_variable(var_name, func):
                var.is_parameter = True
    
    def _analyze_stack_variables(self, func: Dict[str, Any]) -> None:
        """Analyze stack variables"""
        # This is simplified - in practice, you'd analyze stack frame layout
        
        for var_name, var in self.variables.items():
            if var.type == "stack":
                var.is_local = True
    
    def _get_statistics(self) -> Dict[str, Any]:
        """Get data flow analysis statistics"""
        stats = {
            "total_variables": len(self.variables),
            "register_variables": len([v for v in self.variables.values() if v.type == "register"]),
            "stack_variables": len([v for v in self.variables.values() if v.type == "stack"]),
            "memory_variables": len([v for v in self.variables.values() if v.type == "memory"]),
            "parameter_variables": len([v for v in self.variables.values() if v.is_parameter]),
            "local_variables": len([v for v in self.variables.values() if v.is_local]),
            "total_dependencies": len(self.dependencies),
            "def_use_chains": len(self.def_use_chains),
            "use_def_chains": len(self.use_def_chains),
        }
        
        return stats
    
    def get_variable_uses(self, variable_name: str) -> List[int]:
        """Get all addresses where a variable is used"""
        if variable_name in self.variables:
            return self.variables[variable_name].use_addresses
        return []
    
    def get_variable_definition(self, variable_name: str) -> Optional[int]:
        """Get the definition address of a variable"""
        if variable_name in self.variables:
            return self.variables[variable_name].definition_address
        return None
    
    def get_variables_defined_at(self, address: int) -> List[str]:
        """Get variables defined at a specific address"""
        return self.def_use_chains.get(address, [])
    
    def get_variables_used_at(self, address: int) -> List[str]:
        """Get variables used at a specific address"""
        return self.use_def_chains.get(address, [])
    
    def find_reaching_definitions(self, variable_name: str, address: int) -> List[int]:
        """Find all reaching definitions for a variable at an address"""
        # This is a simplified implementation
        # In practice, you'd need to perform proper reaching definitions analysis
        
        if variable_name in self.variables:
            return [self.variables[variable_name].definition_address]
        
        return []
    
    def get_data_dependencies_for_instruction(self, address: int) -> List[DataDependency]:
        """Get all data dependencies for an instruction"""
        return [dep for dep in self.dependencies if dep.instruction_address == address]
