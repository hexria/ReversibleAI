"""
Stack string extraction and analysis
"""

from typing import List, Dict, Any, Optional, Tuple
import re
from dataclasses import dataclass

from loguru import logger

from ..static_analyzer.disassembler import Disassembler, Instruction


@dataclass
class StackString:
    """Represents a stack string"""
    value: str
    address: int
    construction_instructions: List[Instruction]
    length: int
    encoding: str
    is_obfuscated: bool
    deobfuscation_method: Optional[str] = None


class StackStringExtractor:
    """Extracts and decodes stack-based strings"""
    
    def __init__(self, disassembler: Disassembler) -> None:
        self.disassembler = disassembler
        self.stack_strings: List[StackString] = []
    
    def extract_stack_strings(self, instructions: List[Instruction]) -> List[StackString]:
        """
        Extract stack strings from a list of instructions
        
        Args:
            instructions: List of instructions to analyze
            
        Returns:
            List of StackString objects
        """
        logger.info("Extracting stack strings")
        
        # Look for stack string construction patterns
        construction_patterns = self._identify_construction_patterns(instructions)
        
        for pattern in construction_patterns:
            stack_string = self._decode_stack_string(pattern)
            if stack_string:
                self.stack_strings.append(stack_string)
        
        logger.info(f"Extracted {len(self.stack_strings)} stack strings")
        return self.stack_strings
    
    def _identify_construction_patterns(self, instructions: List[Instruction]) -> List[List[Instruction]]:
        """Identify stack string construction patterns"""
        patterns = []
        current_pattern = []
        
        for i, insn in enumerate(instructions):
            # Look for stack pointer manipulation
            if self._is_stack_construction_instruction(insn):
                if not current_pattern:
                    current_pattern = [insn]
                else:
                    # Check if this continues the pattern
                    if self._continues_stack_pattern(insn, current_pattern[-1]):
                        current_pattern.append(insn)
                    else:
                        # Pattern ended, start new one
                        if len(current_pattern) >= 2:  # Minimum pattern length
                            patterns.append(current_pattern)
                        current_pattern = [insn]
            else:
                # Pattern ended
                if len(current_pattern) >= 2:
                    patterns.append(current_pattern)
                current_pattern = []
        
        # Add the last pattern if it exists
        if len(current_pattern) >= 2:
            patterns.append(current_pattern)
        
        return patterns
    
    def _is_stack_construction_instruction(self, insn: Instruction) -> bool:
        """Check if instruction is part of stack string construction"""
        mnemonic = insn.mnemonic.lower()
        
        # Common stack string construction instructions
        if mnemonic in ["mov", "add", "sub"]:
            operands = insn.op_str.lower()
            
            # Check for stack reference
            if "esp" in operands or "ebp" in operands or "rsp" in operands or "rbp" in operands:
                return True
            
            # Check for immediate values being moved to stack
            if "byte ptr" in operands or "word ptr" in operands or "dword ptr" in operands:
                return True
        
        elif mnemonic in ["push", "pop"]:
            return True
        
        elif mnemonic in ["lea"]:
            # Load effective address with stack reference
            if "esp" in insn.op_str.lower() or "ebp" in insn.op_str.lower():
                return True
        
        return False
    
    def _continues_stack_pattern(self, current_insn: Instruction, previous_insn: Instruction) -> bool:
        """Check if current instruction continues the stack pattern"""
        # Check if addresses are close (sequential stack operations)
        address_diff = abs(current_insn.address - previous_insn.address)
        
        # If instructions are far apart, probably different patterns
        if address_diff > 0x100:  # 256 bytes threshold
            return False
        
        # Check if both operate on stack
        return (self._is_stack_construction_instruction(current_insn) and 
                self._is_stack_construction_instruction(previous_insn))
    
    def _decode_stack_string(self, pattern: List[Instruction]) -> Optional[StackString]:
        """Decode a stack string construction pattern"""
        try:
            # Extract bytes from the pattern
            string_bytes = []
            stack_offset = 0
            
            for insn in pattern:
                extracted_bytes = self._extract_bytes_from_instruction(insn)
                if extracted_bytes:
                    string_bytes.extend(extracted_bytes)
            
            if not string_bytes:
                return None
            
            # Try different encodings
            for encoding in ['ascii', 'utf-8', 'utf-16le']:
                try:
                    decoded = bytes(string_bytes).decode(encoding, errors='ignore')
                    
                    # Check if it looks like a valid string
                    if self._is_valid_string(decoded):
                        return StackString(
                            value=decoded,
                            address=pattern[0].address,
                            construction_instructions=pattern,
                            length=len(decoded),
                            encoding=encoding,
                            is_obfuscated=self._is_obfuscated(decoded),
                            deobfuscation_method=None
                        )
                except UnicodeDecodeError:
                    continue
            
            # Try XOR deobfuscation
            xor_decoded = self._try_xor_deobfuscation(string_bytes)
            if xor_decoded:
                return StackString(
                    value=xor_decoded,
                    address=pattern[0].address,
                    construction_instructions=pattern,
                    length=len(xor_decoded),
                    encoding='ascii',
                    is_obfuscated=True,
                    deobfuscation_method='xor'
                )
            
            return None
            
        except Exception as e:
            logger.warning(f"Failed to decode stack string: {e}")
            return None
    
    def _extract_bytes_from_instruction(self, insn: Instruction) -> List[int]:
        """Extract byte values from an instruction"""
        mnemonic = insn.mnemonic.lower()
        operands = insn.op_str
        
        if mnemonic == "mov":
            # mov [ebp-4], 0x41
            if "byte ptr" in operands.lower():
                # Extract immediate value
                match = re.search(r',\s*(0x[0-9a-fA-F]+|\d+)', operands)
                if match:
                    value = int(match.group(1), 0)
                    return [value & 0xFF]  # Take only low byte
            
            # mov [ebp-4], 'A'
            match = re.search(r",\s*['\"](.)['\"]", operands)
            if match:
                return [ord(match.group(1))]
        
        elif mnemonic == "push":
            # push 0x41414141
            match = re.search(r'push\s+(0x[0-9a-fA-F]+|\d+)', operands)
            if match:
                value = int(match.group(1), 0)
                # Break down into bytes (little-endian)
                return [(value >> (8 * i)) & 0xFF for i in range(4)]
        
        return []
    
    def _is_valid_string(self, string_value: str) -> bool:
        """Check if a decoded value looks like a valid string"""
        if len(string_value) < 4:
            return False
        
        # Check printable character ratio
        printable_count = sum(1 for c in string_value if 32 <= ord(c) <= 126)
        printable_ratio = printable_count / len(string_value)
        
        # At least 80% printable characters
        if printable_ratio < 0.8:
            return False
        
        # Check for common string patterns
        if re.search(r'[a-zA-Z]{3,}', string_value):  # At least 3 consecutive letters
            return True
        
        if re.search(r'\d{3,}', string_value):  # At least 3 consecutive digits
            return True
        
        return False
    
    def _is_obfuscated(self, string_value: str) -> bool:
        """Check if string appears to be obfuscated"""
        # High entropy suggests obfuscation
        entropy = self._calculate_entropy(string_value)
        if entropy > 4.0:
            return True
        
        # Random-looking character patterns
        if re.search(r'[^a-zA-Z0-9\s\.\-_@:/\\]', string_value):
            return True
        
        return False
    
    def _calculate_entropy(self, string_value: str) -> float:
        """Calculate Shannon entropy of string"""
        if not string_value:
            return 0.0
        
        from collections import defaultdict
        import math
        
        # Count character frequencies
        char_counts = defaultdict(int)
        for char in string_value:
            char_counts[char] += 1
        
        # Calculate entropy
        entropy = 0.0
        string_length = len(string_value)
        
        for count in char_counts.values():
            probability = count / string_length
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _try_xor_deobfuscation(self, byte_array: List[int]) -> Optional[str]:
        """Try XOR deobfuscation with common keys"""
        common_keys = [0x00, 0xFF, 0xAA, 0x55, 0x01, 0x02, 0x04, 0x08]
        
        for key in common_keys:
            try:
                # XOR with key
                xored = bytes(b ^ key for b in byte_array)
                
                # Try to decode as ASCII
                decoded = xored.decode('ascii', errors='ignore')
                
                if self._is_valid_string(decoded):
                    return decoded
                    
            except Exception:
                continue
        
        return None
    
    def get_stack_strings_by_length(self, min_length: int, max_length: Optional[int] = None) -> List[StackString]:
        """Get stack strings within specified length range"""
        filtered = []
        
        for stack_string in self.stack_strings:
            if stack_string.length >= min_length:
                if max_length is None or stack_string.length <= max_length:
                    filtered.append(stack_string)
        
        return filtered
    
    def get_obfuscated_stack_strings(self) -> List[StackString]:
        """Get obfuscated stack strings"""
        return [s for s in self.stack_strings if s.is_obfuscated]
    
    def search_stack_strings(self, pattern: str, case_sensitive: bool = False) -> List[StackString]:
        """Search stack strings by pattern"""
        if case_sensitive:
            return [s for s in self.stack_strings if pattern in s.value]
        else:
            pattern_lower = pattern.lower()
            return [s for s in self.stack_strings if pattern_lower in s.value.lower()]
    
    def get_construction_patterns(self) -> Dict[str, List[List[Instruction]]]:
        """Analyze construction patterns used"""
        patterns = {
            "mov_byte": [],
            "push_immediate": [],
            "mixed": []
        }
        
        for stack_string in self.stack_strings:
            insn_types = []
            
            for insn in stack_string.construction_instructions:
                if insn.mnemonic.lower() == "mov" and "byte ptr" in insn.op_str.lower():
                    insn_types.append("mov_byte")
                elif insn.mnemonic.lower() == "push":
                    insn_types.append("push_immediate")
                else:
                    insn_types.append("other")
            
            # Categorize pattern
            if all(t == "mov_byte" for t in insn_types):
                patterns["mov_byte"].append(stack_string.construction_instructions)
            elif all(t == "push_immediate" for t in insn_types):
                patterns["push_immediate"].append(stack_string.construction_instructions)
            else:
                patterns["mixed"].append(stack_string.construction_instructions)
        
        return patterns
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get stack string extraction statistics"""
        if not self.stack_strings:
            return {}
        
        stats = {
            "total_stack_strings": len(self.stack_strings),
            "obfuscated_count": len([s for s in self.stack_strings if s.is_obfuscated]),
            "encodings": {},
            "average_length": 0,
            "max_length": 0,
            "min_length": float('inf'),
            "construction_patterns": self.get_construction_patterns()
        }
        
        total_length = 0
        
        for stack_string in self.stack_strings:
            # Encoding distribution
            encoding = stack_string.encoding
            stats["encodings"][encoding] = stats["encodings"].get(encoding, 0) + 1
            
            # Length stats
            total_length += stack_string.length
            stats["max_length"] = max(stats["max_length"], stack_string.length)
            stats["min_length"] = min(stats["min_length"], stack_string.length)
        
        if self.stack_strings:
            stats["average_length"] = total_length / len(self.stack_strings)
        
        if stats["min_length"] == float('inf'):
            stats["min_length"] = 0
        
        return stats
