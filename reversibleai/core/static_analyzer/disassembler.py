"""
Disassembler component using Capstone
"""

from typing import List, Dict, Any, Optional, Tuple
import capstone
from loguru import logger


class Instruction:
    """Represents a single disassembled instruction"""
    
    def __init__(self, cs_insn) -> None:
        self.address = cs_insn.address
        self.mnemonic = cs_insn.mnemonic
        self.op_str = cs_insn.op_str
        self.size = cs_insn.size
        self.bytes = bytes(cs_insn.bytes)
        self.groups = list(cs_insn.groups)
        self.regs_read = list(cs_insn.regs_read)
        self.regs_write = list(cs_insn.regs_write)
        
    @property
    def full_text(self) -> str:
        """Get full instruction text"""
        if self.op_str:
            return f"{self.mnemonic} {self.op_str}"
        return self.mnemonic
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            "address": hex(self.address),
            "mnemonic": self.mnemonic,
            "operands": self.op_str,
            "size": self.size,
            "bytes": self.bytes.hex(),
            "groups": self.groups,
            "regs_read": self.regs_read,
            "regs_write": self.regs_write,
        }


class Disassembler:
    """Disassembler class using Capstone engine"""
    
    def __init__(self, architecture: str, bits: int, endianness: str = "little") -> None:
        self.architecture = architecture.lower()
        self.bits = bits
        self.endianness = endianness.lower()
        self.cs: Optional[capstone.Cs] = None
        
        self._initialize_capstone()
    
    def _initialize_capstone(self) -> None:
        """Initialize Capstone disassembler"""
        try:
            # Map architecture names to Capstone constants
            arch_map = {
                "x86": capstone.x86.X86_ARCH,
                "x86_64": capstone.x86.X86_ARCH,
                "arm": capstone.arm.ARM_ARCH,
                "aarch64": capstone.arm64.ARM64_ARCH,
                "mips": capstone.mips.MIPS_ARCH,
                "ppc": capstone.ppc.PPC_ARCH,
                "riscv": capstone.riscv.RISCV_ARCH,
            }
            
            if self.architecture not in arch_map:
                raise ValueError(f"Unsupported architecture: {self.architecture}")
            
            # Determine mode
            if self.architecture in ["x86", "x86_64"]:
                mode = capstone.x86.X86_MODE_64 if self.bits == 64 else capstone.x86.X86_MODE_32
            elif self.architecture == "arm":
                mode = capstone.arm.ARM_MODE_ARM
            elif self.architecture == "aarch64":
                mode = capstone.arm64.ARM64_MODE_ARM
            elif self.architecture == "mips":
                mode = capstone.mips.MIPS_MODE_32 if self.bits == 32 else capstone.mips.MIPS_MODE_64
            elif self.architecture == "ppc":
                mode = capstone.ppc.PPC_MODE_32 if self.bits == 32 else capstone.ppc.PPC_MODE_64
            elif self.architecture == "riscv":
                mode = capstone.riscv.RISCV_MODE_32 if self.bits == 32 else capstone.riscv.RISCV_MODE_64
            else:
                raise ValueError(f"Unsupported mode for architecture: {self.architecture}")
            
            # Set endianness
            if self.endianness == "big":
                if self.architecture in ["x86", "x86_64"]:
                    logger.warning("x86/x86_64 doesn't support big endian, using little endian")
                else:
                    mode |= capstone.CS_MODE_BIG_ENDIAN
            
            # Create Capstone instance
            self.cs = capstone.Cs(arch_map[self.architecture], mode)
            
            # Set detail mode for more information
            self.cs.detail = True
            
            # Skip data mode for architectures that support it
            if hasattr(capstone, 'CS_OPT_SKIPDATA'):
                self.cs.skipdata = True
            
            logger.debug(f"Initialized Capstone for {self.architecture} {self.bits}-bit {self.endianness}")
            
        except Exception as e:
            logger.error(f"Failed to initialize Capstone: {e}")
            raise
    
    def disassemble(self, code: bytes, base_address: int = 0) -> List[Instruction]:
        """
        Disassemble code bytes
        
        Args:
            code: Code bytes to disassemble
            base_address: Base address for the code
            
        Returns:
            List of Instruction objects
        """
        if not self.cs:
            raise RuntimeError("Disassembler not initialized")
        
        instructions = []
        
        try:
            for cs_insn in self.cs.disasm(code, base_address):
                instructions.append(Instruction(cs_insn))
            
            logger.debug(f"Disassembled {len(instructions)} instructions")
            return instructions
            
        except Exception as e:
            logger.error(f"Disassembly failed: {e}")
            raise
    
    def disassemble_range(self, code: bytes, start_addr: int, end_addr: int) -> List[Instruction]:
        """
        Disassemble code in a specific address range
        
        Args:
            code: Code bytes to disassemble
            start_addr: Start address
            end_addr: End address
            
        Returns:
            List of Instruction objects
        """
        if start_addr >= end_addr:
            raise ValueError("Start address must be less than end address")
        
        # Calculate the bytes needed for the range
        code_size = min(len(code), end_addr - start_addr)
        relevant_code = code[:code_size]
        
        return self.disassemble(relevant_code, start_addr)
    
    def disassemble_function(self, code: bytes, function_start: int, function_end: Optional[int] = None) -> List[Instruction]:
        """
        Disassemble a function
        
        Args:
            code: Code bytes containing the function
            function_start: Start address of the function
            function_end: End address of the function (optional)
            
        Returns:
            List of Instruction objects
        """
        if function_end is None:
            # Try to find function end by looking for RET instructions
            instructions = self.disassemble(code, function_start)
            
            # Find the first RET instruction
            for i, insn in enumerate(instructions):
                if self._is_return_instruction(insn):
                    return instructions[:i+1]
            
            # If no RET found, return all instructions
            return instructions
        else:
            return self.disassemble_range(code, function_start, function_end)
    
    def get_instruction_at(self, code: bytes, address: int) -> Optional[Instruction]:
        """
        Get instruction at specific address
        
        Args:
            code: Code bytes
            address: Address of the instruction
            
        Returns:
            Instruction object or None if not found
        """
        # Disassemble a small range around the address
        start_addr = max(0, address - 15)  # Look back up to 15 bytes
        end_addr = address + 15  # Look forward up to 15 bytes
        
        try:
            instructions = self.disassemble_range(code, start_addr, end_addr)
            
            for insn in instructions:
                if insn.address == address:
                    return insn
            
            return None
            
        except Exception:
            return None
    
    def find_instructions_by_mnemonic(self, code: bytes, mnemonic: str, base_address: int = 0) -> List[Instruction]:
        """
        Find all instructions with specific mnemonic
        
        Args:
            code: Code bytes to search
            mnemonic: Mnemonic to search for
            base_address: Base address for the code
            
        Returns:
            List of matching Instruction objects
        """
        instructions = self.disassemble(code, base_address)
        
        return [insn for insn in instructions if insn.mnemonic.lower() == mnemonic.lower()]
    
    def find_call_instructions(self, code: bytes, base_address: int = 0) -> List[Instruction]:
        """
        Find all call instructions
        
        Args:
            code: Code bytes to search
            base_address: Base address for the code
            
        Returns:
            List of call Instruction objects
        """
        call_mnemonics = ["call", "bl", "blx", "jal", "jalr"]
        
        instructions = self.disassemble(code, base_address)
        
        return [insn for insn in instructions if insn.mnemonic.lower() in call_mnemonics]
    
    def find_jump_instructions(self, code: bytes, base_address: int = 0) -> List[Instruction]:
        """
        Find all jump instructions
        
        Args:
            code: Code bytes to search
            base_address: Base address for the code
            
        Returns:
            List of jump Instruction objects
        """
        jump_mnemonics = [
            "jmp", "je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle", "ja", "jae", "jb", "jbe",
            "b", "beq", "bne", "bgt", "bge", "blt", "ble",
            "j", "beqz", "bnez"
        ]
        
        instructions = self.disassemble(code, base_address)
        
        return [insn for insn in instructions if insn.mnemonic.lower() in jump_mnemonics]
    
    def _is_return_instruction(self, instruction: Instruction) -> bool:
        """Check if instruction is a return instruction"""
        return_mnemonics = ["ret", "retf", "bx lr", "eret", "jr ra"]
        
        return instruction.mnemonic.lower() in return_mnemonics
    
    def get_supported_architectures(self) -> List[str]:
        """Get list of supported architectures"""
        return ["x86", "x86_64", "arm", "aarch64", "mips", "ppc", "riscv"]
    
    def is_architecture_supported(self, arch: str) -> bool:
        """Check if architecture is supported"""
        return arch.lower() in self.get_supported_architectures()
