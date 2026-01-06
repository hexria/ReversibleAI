"""
Unit tests for disassembler
"""

import pytest

from reversibleai.core.static_analyzer.disassembler import Disassembler
from reversibleai.core.exceptions import AnalysisError


class TestDisassembler:
    """Test disassembler functionality"""
    
    def test_disassembler_initialization(self) -> None:
        """Test disassembler initialization"""
        disassembler = Disassembler(architecture="x86", bits=32, endianness="little")
        assert disassembler.architecture == "x86"
        assert disassembler.bits == 32
        assert disassembler.endianness == "little"
    
    def test_disassemble_bytes(self) -> None:
        """Test disassembling bytes"""
        disassembler = Disassembler(architecture="x86", bits=32, endianness="little")
        
        # x86 code: push ebp; mov ebp, esp
        code = b"\x55\x8b\xec"
        instructions = disassembler.disassemble(code, address=0x1000)
        
        assert len(instructions) > 0
        assert instructions[0]["address"] == 0x1000
    
    def test_disassemble_empty(self) -> None:
        """Test disassembling empty bytes"""
        disassembler = Disassembler(architecture="x86", bits=32, endianness="little")
        instructions = disassembler.disassemble(b"", address=0x1000)
        
        assert len(instructions) == 0
    
    def test_unsupported_architecture(self) -> None:
        """Test unsupported architecture"""
        with pytest.raises(AnalysisError):
            Disassembler(architecture="invalid", bits=32, endianness="little")
    
    def test_get_instruction_info(self) -> None:
        """Test getting instruction information"""
        disassembler = Disassembler(architecture="x86", bits=32, endianness="little")
        code = b"\x55"  # push ebp
        instructions = disassembler.disassemble(code, address=0x1000)
        
        if len(instructions) > 0:
            info = disassembler.get_instruction_info(instructions[0])
            assert "mnemonic" in info
            assert "operands" in info
