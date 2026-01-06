"""
String decoding and deobfuscation utilities
"""

from typing import List, Dict, Any, Optional, Tuple, Union
import base64
import struct
from dataclasses import dataclass

from loguru import logger


@dataclass
class DecodingResult:
    """Result of string decoding attempt"""
    original_value: str
    decoded_value: str
    method: str
    confidence: float  # 0.0 to 1.0
    parameters: Dict[str, Any]


class StringDecoder:
    """Advanced string decoder with multiple algorithms"""
    
    def __init__(self) -> None:
        self.decoding_methods = {
            'base64': self._decode_base64,
            'hex': self._decode_hex,
            'url': self._decode_url,
            'xor': self._decode_xor,
            'rot13': self._decode_rot13,
            'caesar': self._decode_caesar,
            'reverse': self._decode_reverse,
            'unicode_escape': self._decode_unicode_escape,
            'html_entity': self._decode_html_entity,
        }
    
    def decode_string(self, 
                     input_string: str,
                     methods: Optional[List[str]] = None,
                     auto_detect: bool = True) -> List[DecodingResult]:
        """
        Attempt to decode a string using various methods
        
        Args:
            input_string: String to decode
            methods: Specific methods to try (None for all)
            auto_detect: Whether to auto-detect the best method
            
        Returns:
            List of DecodingResult objects
        """
        results = []
        
        if methods is None:
            methods = list(self.decoding_methods.keys())
        
        for method in methods:
            if method in self.decoding_methods:
                try:
                    result = self.decoding_methods[method](input_string)
                    if result:
                        results.append(result)
                except Exception as e:
                    logger.debug(f"Decoding method {method} failed: {e}")
        
        # Sort by confidence
        results.sort(key=lambda x: x.confidence, reverse=True)
        
        return results
    
    def _decode_base64(self, input_string: str) -> Optional[DecodingResult]:
        """Decode Base64 encoded string"""
        try:
            # Clean up the string
            clean_string = input_string.strip()
            
            # Try standard Base64
            decoded = base64.b64decode(clean_string).decode('utf-8', errors='ignore')
            
            if self._is_meaningful_string(decoded):
                return DecodingResult(
                    original_value=input_string,
                    decoded_value=decoded,
                    method="base64",
                    confidence=0.9,
                    parameters={"variant": "standard"}
                )
            
            # Try URL-safe Base64
            decoded = base64.urlsafe_b64decode(clean_string).decode('utf-8', errors='ignore')
            
            if self._is_meaningful_string(decoded):
                return DecodingResult(
                    original_value=input_string,
                    decoded_value=decoded,
                    method="base64",
                    confidence=0.9,
                    parameters={"variant": "urlsafe"}
                )
                
        except Exception:
            pass
        
        return None
    
    def _decode_hex(self, input_string: str) -> Optional[DecodingResult]:
        """Decode hex encoded string"""
        try:
            # Remove common hex prefixes
            clean_string = input_string.strip()
            if clean_string.startswith('0x') or clean_string.startswith('\\x'):
                clean_string = clean_string[2:]
            
            # Remove spaces and other separators
            clean_string = ''.join(c for c in clean_string if c in '0123456789abcdefABCDEF')
            
            # Must have even length
            if len(clean_string) % 2 != 0:
                return None
            
            # Decode
            decoded_bytes = bytes.fromhex(clean_string)
            
            # Try different encodings
            for encoding in ['ascii', 'utf-8', 'utf-16le', 'latin1']:
                try:
                    decoded = decoded_bytes.decode(encoding, errors='ignore')
                    
                    if self._is_meaningful_string(decoded):
                        return DecodingResult(
                            original_value=input_string,
                            decoded_value=decoded,
                            method="hex",
                            confidence=0.8,
                            parameters={"encoding": encoding}
                        )
                except Exception:
                    continue
                    
        except Exception:
            pass
        
        return None
    
    def _decode_url(self, input_string: str) -> Optional[DecodingResult]:
        """Decode URL encoded string"""
        try:
            import urllib.parse
            
            decoded = urllib.parse.unquote(input_string)
            
            if decoded != input_string and self._is_meaningful_string(decoded):
                return DecodingResult(
                    original_value=input_string,
                    decoded_value=decoded,
                    method="url",
                    confidence=0.7,
                    parameters={}
                )
                
        except Exception:
            pass
        
        return None
    
    def _decode_xor(self, input_string: str) -> Optional[DecodingResult]:
        """Decode XOR encoded string with common keys"""
        common_keys = [0x00, 0xFF, 0xAA, 0x55, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20]
        
        for key in common_keys:
            try:
                # XOR with key
                xored = ''.join(chr(ord(c) ^ key) for c in input_string)
                
                if self._is_meaningful_string(xored):
                    return DecodingResult(
                        original_value=input_string,
                        decoded_value=xored,
                        method="xor",
                        confidence=0.6,
                        parameters={"key": key}
                    )
                    
            except Exception:
                continue
        
        return None
    
    def _decode_rot13(self, input_string: str) -> Optional[DecodingResult]:
        """Decode ROT13 encoded string"""
        try:
            decoded = input_string.translate(str.maketrans(
                'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
            ))
            
            if decoded != input_string and self._is_meaningful_string(decoded):
                return DecodingResult(
                    original_value=input_string,
                    decoded_value=decoded,
                    method="rot13",
                    confidence=0.5,
                    parameters={}
                )
                
        except Exception:
            pass
        
        return None
    
    def _decode_caesar(self, input_string: str) -> Optional[DecodingResult]:
        """Decode Caesar cipher with various shifts"""
        for shift in range(1, 26):
            try:
                decoded = ""
                
                for char in input_string:
                    if 'a' <= char <= 'z':
                        decoded += chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
                    elif 'A' <= char <= 'Z':
                        decoded += chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
                    else:
                        decoded += char
                
                if self._is_meaningful_string(decoded):
                    return DecodingResult(
                        original_value=input_string,
                        decoded_value=decoded,
                        method="caesar",
                        confidence=0.4,
                        parameters={"shift": shift}
                    )
                    
            except Exception:
                continue
        
        return None
    
    def _decode_reverse(self, input_string: str) -> Optional[DecodingResult]:
        """Decode reversed string"""
        try:
            decoded = input_string[::-1]
            
            if self._is_meaningful_string(decoded):
                return DecodingResult(
                    original_value=input_string,
                    decoded_value=decoded,
                    method="reverse",
                    confidence=0.3,
                    parameters={}
                )
                
        except Exception:
            pass
        
        return None
    
    def _decode_unicode_escape(self, input_string: str) -> Optional[DecodingResult]:
        """Decode Unicode escape sequences"""
        try:
            decoded = input_string.encode().decode('unicode_escape')
            
            if decoded != input_string and self._is_meaningful_string(decoded):
                return DecodingResult(
                    original_value=input_string,
                    decoded_value=decoded,
                    method="unicode_escape",
                    confidence=0.6,
                    parameters={}
                )
                
        except Exception:
            pass
        
        return None
    
    def _decode_html_entity(self, input_string: str) -> Optional[DecodingResult]:
        """Decode HTML entities"""
        try:
            import html
            
            decoded = html.unescape(input_string)
            
            if decoded != input_string and self._is_meaningful_string(decoded):
                return DecodingResult(
                    original_value=input_string,
                    decoded_value=decoded,
                    method="html_entity",
                    confidence=0.5,
                    parameters={}
                )
                
        except Exception:
            pass
        
        return None
    
    def _is_meaningful_string(self, string_value: str) -> bool:
        """Check if a decoded string looks meaningful"""
        if len(string_value) < 3:
            return False
        
        # Check printable character ratio
        printable_count = sum(1 for c in string_value if 32 <= ord(c) <= 126)
        if len(string_value) > 0:
            printable_ratio = printable_count / len(string_value)
        else:
            printable_ratio = 0
        
        # At least 70% printable characters
        if printable_ratio < 0.7:
            return False
        
        # Check for common patterns
        import re
        
        # Contains letters
        if re.search(r'[a-zA-Z]{2,}', string_value):
            return True
        
        # Contains digits
        if re.search(r'\d{2,}', string_value):
            return True
        
        # Common characters
        if any(c in string_value for c in '._-/@:\\'):
            return True
        
        return False
    
    def auto_decode(self, input_string: str) -> Optional[DecodingResult]:
        """Automatically detect and decode string"""
        results = self.decode_string(input_string, auto_detect=True)
        
        if results:
            return results[0]  # Return the highest confidence result
        
        return None
    
    def batch_decode(self, strings: List[str]) -> Dict[str, List[DecodingResult]]:
        """Decode multiple strings"""
        results = {}
        
        for string_value in strings:
            decoded_results = self.decode_string(string_value)
            if decoded_results:
                results[string_value] = decoded_results
        
        return results
    
    def get_decoding_statistics(self, results: List[DecodingResult]) -> Dict[str, Any]:
        """Get statistics about decoding results"""
        if not results:
            return {}
        
        stats = {
            "total_decodings": len(results),
            "methods": {},
            "average_confidence": 0,
            "high_confidence_count": 0,  # confidence > 0.7
        }
        
        total_confidence = 0
        
        for result in results:
            # Method distribution
            method = result.method
            stats["methods"][method] = stats["methods"].get(method, 0) + 1
            
            # Confidence stats
            total_confidence += result.confidence
            if result.confidence > 0.7:
                stats["high_confidence_count"] += 1
        
        if results:
            stats["average_confidence"] = total_confidence / len(results)
        
        return stats
