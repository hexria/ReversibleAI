"""
Function analyzer for identifying and analyzing functions
"""

from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass
import re

from loguru import logger

from ..loader.base import BaseLoader
from ..constants import FUNCTION_PROLOGUES
from .disassembler import Disassembler, Instruction


@dataclass
class Function:
    """Represents a function in the binary"""
    start_address: int
    end_address: int
    name: Optional[str]
    size: int
    instructions: List[Instruction]
    basic_blocks: List[Dict[str, Any]]
    calling_convention: Optional[str]
    stack_frame_size: int
    local_variables: List[Dict[str, Any]]
    parameters: List[Dict[str, Any]]
    calls: List[int]  # Addresses of functions this function calls
    callers: List[int]  # Addresses of functions that call this function
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            "start_address": hex(self.start_address),
            "end_address": hex(self.end_address),
            "name": self.name,
            "size": self.size,
            "instruction_count": len(self.instructions),
            "basic_block_count": len(self.basic_blocks),
            "calling_convention": self.calling_convention,
            "stack_frame_size": self.stack_frame_size,
            "local_variables": self.local_variables,
            "parameters": self.parameters,
            "calls": [hex(addr) for addr in self.calls],
            "callers": [hex(addr) for addr in self.callers],
        }


class FunctionAnalyzer:
    """Analyzer for identifying and analyzing functions"""
    
    def __init__(self, loader: BaseLoader) -> None:
        self.loader = loader
        self.binary_info = loader.info
        self.disassembler = Disassembler(
            architecture=self.binary_info.architecture,
            bits=self.binary_info.bits,
            endianness=self.binary_info.endianness
        )
        self.functions: List[Function] = []
        self._function_map: Dict[int, Function] = {}  # Address to function mapping
        
    def analyze_functions(self) -> List[Dict[str, Any]]:
        """
        Analyze all functions in the binary
        
        Returns:
            List of function information dictionaries
        """
        logger.info("Starting function analysis")
        
        # Identify functions using different methods
        self._identify_functions_from_symbols()
        self._identify_functions_from_entry_points()
        self._identify_functions_from_code_patterns()
        
        # Analyze each function
        for func in self.functions:
            self._analyze_function_details(func)
        
        # Build call graph
        self._build_call_graph()
        
        logger.info(f"Analyzed {len(self.functions)} functions")
        return [func.to_dict() for func in self.functions]
    
    def _identify_functions_from_symbols(self) -> None:
        """Identify functions from symbol information"""
        # Get exported functions
        for export in self.binary_info.exports:
            if export.get("address", 0) > 0:
                self._create_function(export["address"], export.get("name"))
        
        # Get imported functions (these are external, but we track them)
        for imp in self.binary_info.imports:
            if imp.get("address", 0) > 0:
                self._create_function(imp["address"], imp.get("function"), is_external=True)
    
    def _identify_functions_from_entry_points(self) -> None:
        """Identify functions from entry points"""
        # Main entry point
        if self.binary_info.entry_point > 0:
            self._create_function(self.binary_info.entry_point, "_start")
        
        # Additional entry points can be detected here:
        # - TLS callbacks (PE: IMAGE_DIRECTORY_ENTRY_TLS)
        # - Exception handlers (structured exception handling)
        # - DllMain (for DLLs)
        # - Constructors/Destructors (C++ global objects)
    
    def _identify_functions_from_code_patterns(self) -> None:
        """Identify functions by analyzing code patterns"""
        # This is a simplified implementation
        # In practice, you'd use more sophisticated techniques
        
        # Look for function prologues
        prologue_patterns = self._get_function_prologue_patterns()
        
        # For now, just add some common patterns
        # Function detection using recursive disassembly:
        # 1. Start from known entry points
        # 2. Follow call instructions
        # 3. Identify function prologues/epilogues
        # 4. Build function boundaries
        # This is a simplified implementation - full recursive disassembly
        # would require more sophisticated control flow analysis
        
        pass
    
    def _get_function_prologue_patterns(self) -> List[bytes]:
        """Get common function prologue patterns for the current architecture"""
        arch = self.binary_info.architecture.lower()
        return FUNCTION_PROLOGUES.get(arch, [])
    
    def _create_function(self, address: int, name: Optional[str] = None, is_external: bool = False) -> Optional[Function]:
        """Create a function at the given address"""
        if address in self._function_map:
            return self._function_map[address]
        
        if is_external:
            # External functions don't have code in this binary
            func = Function(
                start_address=address,
                end_address=address,
                name=name,
                size=0,
                instructions=[],
                basic_blocks=[],
                calling_convention=None,
                stack_frame_size=0,
                local_variables=[],
                parameters=[],
                calls=[],
                callers=[]
            )
        else:
            # Try to disassemble the function
            try:
                # Read code at the function address
                code = self._read_code_at_address(address, max_size=0x1000)  # Max 4KB
                
                if code:
                    instructions = self.disassembler.disassemble_function(code, address)
                    
                    if instructions:
                        end_address = instructions[-1].address + instructions[-1].size
                        
                        func = Function(
                            start_address=address,
                            end_address=end_address,
                            name=name,
                            size=end_address - address,
                            instructions=instructions,
                            basic_blocks=[],
                            calling_convention=None,
                            stack_frame_size=0,
                            local_variables=[],
                            parameters=[],
                            calls=[],
                            callers=[]
                        )
                    else:
                        return None
                else:
                    return None
                    
            except Exception as e:
                logger.warning(f"Failed to create function at {hex(address)}: {e}")
                return None
        
        self.functions.append(func)
        self._function_map[address] = func
        
        return func
    
    def _read_code_at_address(self, address: int, max_size: int = 0x1000) -> Optional[bytes]:
        """Read code at the given address from the binary"""
        # This is a simplified implementation
        # In practice, you'd need to map virtual addresses to file offsets
        
        try:
            with open(self.binary_info.path, "rb") as f:
                # For now, just read from the file
                # Virtual address to file offset mapping:
                # For PE: Use section headers to map RVA to file offset
                # For ELF: Use program headers for virtual address mapping
                # For Mach-O: Use segment commands for address mapping
                f.seek(0)
                return f.read(max_size)
        except Exception:
            return None
    
    def _analyze_function_details(self, func: Function) -> None:
        """Analyze detailed information about a function"""
        if not func.instructions:
            return
        
        # Analyze calling convention
        func.calling_convention = self._detect_calling_convention(func)
        
        # Analyze stack frame
        self._analyze_stack_frame(func)
        
        # Find calls made by this function
        func.calls = self._find_function_calls(func)
        
        # Analyze basic blocks
        func.basic_blocks = self._identify_basic_blocks(func)
    
    def _detect_calling_convention(self, func: Function) -> Optional[str]:
        """Detect the calling convention of a function"""
        # This is a very simplified implementation
        # In practice, you'd analyze the prologue/epilogue patterns
        
        if not func.instructions:
            return None
        
        # Look for common patterns
        first_insn = func.instructions[0]
        
        if self.binary_info.architecture == "x86":
            if first_insn.mnemonic == "push" and "ebp" in first_insn.op_str:
                return "cdecl"
            elif first_insn.mnemonic == "mov" and "ebp, esp" in first_insn.op_str:
                return "stdcall"
        elif self.binary_info.architecture == "x86_64":
            if first_insn.mnemonic == "push" and "rbp" in first_insn.op_str:
                return "SystemV AMD64 ABI"
        
        return None
    
    def _analyze_stack_frame(self, func: Function) -> None:
        """Analyze the stack frame of a function"""
        # This is a simplified implementation
        # In practice, you'd track stack pointer changes throughout the function
        
        if not func.instructions:
            return
        
        stack_offset = 0
        
        for insn in func.instructions:
            if insn.mnemonic == "push":
                stack_offset -= self.binary_info.bits // 8
            elif insn.mnemonic == "pop":
                stack_offset += self.binary_info.bits // 8
            elif insn.mnemonic == "sub" and "esp" in insn.op_str:
                # sub esp, imm
                try:
                    imm = int(insn.op_str.split(",")[1].strip(), 0)
                    stack_offset -= imm
                except:
                    pass
            elif insn.mnemonic == "add" and "esp" in insn.op_str:
                # add esp, imm
                try:
                    imm = int(insn.op_str.split(",")[1].strip(), 0)
                    stack_offset += imm
                except:
                    pass
        
        func.stack_frame_size = abs(stack_offset)
    
    def _find_function_calls(self, func: Function) -> List[int]:
        """Find functions called by this function"""
        calls = []
        
        for insn in func.instructions:
            if insn.mnemonic.lower() in ["call", "bl", "blx", "jal"]:
                # Extract target address
                if insn.op_str and insn.op_str.startswith("0x"):
                    try:
                        target = int(insn.op_str, 0)
                        calls.append(target)
                    except ValueError:
                        pass
        
        return calls
    
    def _identify_basic_blocks(self, func: Function) -> List[Dict[str, Any]]:
        """Identify basic blocks in the function"""
        if not func.instructions:
            return []
        
        basic_blocks = []
        current_block = []
        leaders = set()
        
        # Identify leaders (start of basic blocks)
        leaders.add(func.instructions[0].address)  # Function start
        
        for i, insn in enumerate(func.instructions):
            # Jump targets are leaders
            if insn.mnemonic.lower() in ["jmp", "je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle"]:
                if insn.op_str and insn.op_str.startswith("0x"):
                    try:
                        target = int(insn.op_str, 0)
                        leaders.add(target)
                    except ValueError:
                        pass
                
                # Instruction after jump is a leader
                if i + 1 < len(func.instructions):
                    leaders.add(func.instructions[i + 1].address)
            
            # Call targets (for analysis purposes)
            elif insn.mnemonic.lower() in ["call", "bl"]:
                if i + 1 < len(func.instructions):
                    leaders.add(func.instructions[i + 1].address)
        
        # Create basic blocks
        current_block_instructions = []
        
        for insn in func.instructions:
            if insn.address in leaders and current_block_instructions:
                # End current block and start new one
                basic_blocks.append({
                    "start_address": hex(current_block_instructions[0].address),
                    "end_address": hex(current_block_instructions[-1].address + current_block_instructions[-1].size),
                    "instructions": [inst.to_dict() for inst in current_block_instructions],
                    "size": len(current_block_instructions),
                })
                current_block_instructions = []
            
            current_block_instructions.append(insn)
        
        # Add the last block
        if current_block_instructions:
            basic_blocks.append({
                "start_address": hex(current_block_instructions[0].address),
                "end_address": hex(current_block_instructions[-1].address + current_block_instructions[-1].size),
                "instructions": [inst.to_dict() for inst in current_block_instructions],
                "size": len(current_block_instructions),
            })
        
        return basic_blocks
    
    def _build_call_graph(self) -> None:
        """Build the call graph relationships"""
        # Update callers for each function
        for func in self.functions:
            for call_addr in func.calls:
                if call_addr in self._function_map:
                    called_func = self._function_map[call_addr]
                    if func.start_address not in called_func.callers:
                        called_func.callers.append(func.start_address)
    
    def get_function_at_address(self, address: int) -> Optional[Dict[str, Any]]:
        """
        Get function information at specific address
        
        Args:
            address: Function address
            
        Returns:
            Function dictionary or None if not found
        """
        """Get function at specific address"""
        for func in self.functions:
            if func.start_address <= address < func.end_address:
                return func.to_dict()
        return None
    
    def get_functions_by_name(self, name: str) -> List[Dict[str, Any]]:
        """
        Get functions by exact name match
        
        Args:
            name: Function name to search for
            
        Returns:
            List of matching function dictionaries
        """
        """Get functions by exact name match"""
        return [func.to_dict() for func in self.functions if func.name == name]
    
    def search_functions(self, pattern: str) -> List[Dict[str, Any]]:
        """
        Search functions by name pattern
        
        Args:
            pattern: Search pattern (supports wildcards)
            
        Returns:
            List of matching function dictionaries
        """
        """Search functions by name pattern"""
        regex = re.compile(pattern, re.IGNORECASE)
        return [func.to_dict() for func in self.functions if func.name and regex.search(func.name)]
