"""
Advanced string extraction with decoding support
"""

from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple
import re
import struct
from dataclasses import dataclass
from collections import defaultdict

from loguru import logger
from ..utils.cache import cache_string
from ..constants import SUSPICIOUS_KEYWORDS, DEFAULT_MIN_STRING_LENGTH


@dataclass
class StringInfo:
    """Information about an extracted string"""
    value: str
    address: Optional[int]
    section: Optional[str]
    encoding: str
    length: int
    entropy: float
    is_decoded: bool = False
    decoding_method: Optional[str] = None
    context: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            "value": self.value,
            "address": hex(self.address) if self.address else None,
            "section": self.section,
            "encoding": self.encoding,
            "length": self.length,
            "entropy": self.entropy,
            "is_decoded": self.is_decoded,
            "decoding_method": self.decoding_method,
            "context": self.context,
        }


class StringExtractor:
    """Advanced string extractor with multiple encoding support"""
    
    def __init__(self, file_path: Path) -> None:
        self.file_path = Path(file_path)
        self.strings: List[StringInfo] = []
        self._file_data: Optional[bytes] = None
        
    def extract_strings(self, 
                       min_length: int = DEFAULT_MIN_STRING_LENGTH,
                       encodings: Optional[List[str]] = None,
                       include_unicode: bool = True,
                       calculate_entropy: bool = True) -> List[StringInfo]:
        """
        Extract strings from the binary file
        
        Args:
            min_length: Minimum string length
            encodings: List of encodings to try (default: common ones)
            include_unicode: Whether to include Unicode strings
            calculate_entropy: Whether to calculate string entropy
            
        Returns:
            List of StringInfo objects
        """
        logger.info(f"Extracting strings from {self.file_path}")
        
        if encodings is None:
            encodings = ['ascii', 'utf-8', 'utf-16le', 'utf-16be', 'latin1']
        
        # Read file data
        self._file_data = self._read_file_data()
        if not self._file_data:
            return []
        
        # Extract ASCII strings first (fastest)
        ascii_strings = self._extract_ascii_strings(min_length)
        self.strings.extend(ascii_strings)
        
        # Extract Unicode strings if requested
        if include_unicode:
            unicode_strings = self._extract_unicode_strings(min_length)
            self.strings.extend(unicode_strings)
        
        # Extract strings with other encodings
        for encoding in encodings:
            if encoding not in ['ascii', 'utf-8', 'utf-16le', 'utf-16be']:
                encoded_strings = self._extract_encoded_strings(min_length, encoding)
                self.strings.extend(encoded_strings)
        
        # Calculate entropy if requested
        if calculate_entropy:
            for string_info in self.strings:
                string_info.entropy = StringExtractor._calculate_string_entropy(string_info.value)
        
        # Remove duplicates
        self.strings = self._remove_duplicates(self.strings)
        
        logger.info(f"Extracted {len(self.strings)} strings")
        return self.strings
    
    def _read_file_data(self) -> Optional[bytes]:
        """Read file data"""
        try:
            if not self.file_path.exists():
                from ..exceptions import LoaderError
                raise LoaderError(f"File not found: {self.file_path}", file_path=str(self.file_path))
            with open(self.file_path, 'rb') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Failed to read file {self.file_path}: {e}")
            from ..exceptions import LoaderError
            if isinstance(e, (FileNotFoundError, OSError)):
                raise LoaderError(f"File not found: {self.file_path}", file_path=str(self.file_path)) from e
            return None
    
    def _extract_ascii_strings(self, min_length: int) -> List[StringInfo]:
        """Extract ASCII strings"""
        strings = []
        
        # Regular expression for ASCII strings
        pattern = rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}'
        
        for match in re.finditer(pattern, self._file_data):
            string_value = match.group().decode('ascii', errors='ignore')
            address = match.start()
            
            string_info = StringInfo(
                value=string_value,
                address=address,
                section=None,  # Would need binary analysis to determine
                encoding='ascii',
                length=len(string_value),
                entropy=0.0,  # Will be calculated later
                is_decoded=False
            )
            strings.append(string_info)
        
        return strings
    
    def _extract_unicode_strings(self, min_length: int) -> List[StringInfo]:
        """Extract Unicode strings (UTF-16LE)"""
        strings = []
        
        # UTF-16LE pattern (every other byte is printable)
        pattern = rb'(?:[\x20-\x7E]\x00){' + str(min_length).encode() + rb',}'
        
        for match in re.finditer(pattern, self._file_data):
            try:
                string_value = match.group().decode('utf-16le', errors='ignore')
                # Remove null characters
                string_value = string_value.replace('\x00', '')
                
                if len(string_value) >= min_length:
                    address = match.start()
                    
                    string_info = StringInfo(
                        value=string_value,
                        address=address,
                        section=None,
                        encoding='utf-16le',
                        length=len(string_value),
                        entropy=0.0,
                        is_decoded=False
                    )
                    strings.append(string_info)
                    
            except UnicodeDecodeError:
                continue
        
        return strings
    
    def _extract_encoded_strings(self, min_length: int, encoding: str) -> List[StringInfo]:
        """Extract strings with specific encoding"""
        strings = []
        
        # Try to decode at different offsets
        for offset in range(0, len(self._file_data), 1):
            try:
                # Try to decode a chunk
                chunk_size = min(1024, len(self._file_data) - offset)
                chunk = self._file_data[offset:offset + chunk_size]
                
                decoded = chunk.decode(encoding, errors='ignore')
                
                # Look for printable strings in the decoded chunk
                printable_pattern = r'[\x20-\x7E]{' + str(min_length) + r',}'
                for match in re.finditer(printable_pattern, decoded):
                    string_value = match.group()
                    
                    if len(string_value) >= min_length:
                        # Calculate original address
                        original_offset = offset + match.start() * len(chunk) // len(decoded)
                        
                        string_info = StringInfo(
                            value=string_value,
                            address=original_offset,
                            section=None,
                            encoding=encoding,
                            length=len(string_value),
                            entropy=0.0,
                            is_decoded=True,
                            decoding_method=f"encoding_{encoding}"
                        )
                        strings.append(string_info)
                        
            except Exception:
                continue
        
        return strings
    
    @staticmethod
    def _calculate_string_entropy(string_value: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not string_value:
            return 0.0
        
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
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _remove_duplicates(self, strings: List[StringInfo]) -> List[StringInfo]:
        """Remove duplicate strings, keeping the one with lowest address"""
        seen = {}
        unique_strings = []
        
        for string_info in strings:
            key = (string_info.value, string_info.encoding)
            if key not in seen or string_info.address < seen[key]:
                seen[key] = string_info
        
        for string_info in seen.values():
            unique_strings.append(string_info)
        
        return unique_strings
    
    def find_suspicious_strings(self, 
                              entropy_threshold: float = 4.0,
                              suspicious_keywords: Optional[List[str]] = None) -> List[StringInfo]:
        """
        Find potentially suspicious strings based on entropy and keywords
        
        Args:
            entropy_threshold: Minimum entropy to consider suspicious
            suspicious_keywords: List of suspicious keywords
            
        Returns:
            List of suspicious StringInfo objects
        """
        if suspicious_keywords is None:
            suspicious_keywords = SUSPICIOUS_KEYWORDS
        
        suspicious = []
        
        for string_info in self.strings:
            # Check entropy
            if string_info.entropy > entropy_threshold:
                suspicious.append(string_info)
                continue
            
            # Check keywords
            string_lower = string_info.value.lower()
            for keyword in suspicious_keywords:
                if keyword in string_lower:
                    suspicious.append(string_info)
                    break
        
        return suspicious
    
    def find_urls(self) -> List[StringInfo]:
        """Extract URLs from strings"""
        url_pattern = re.compile(
            r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?',
            re.IGNORECASE
        )
        
        urls = []
        for string_info in self.strings:
            if url_pattern.search(string_info.value):
                urls.append(string_info)
        
        return urls
    
    def find_ip_addresses(self) -> List[StringInfo]:
        """Extract IP addresses from strings"""
        ip_pattern = re.compile(
            r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        )
        
        ips = []
        for string_info in self.strings:
            if ip_pattern.search(string_info.value):
                ips.append(string_info)
        
        return ips
    
    def find_registry_keys(self) -> List[StringInfo]:
        """Extract Windows registry keys from strings"""
        registry_patterns = [
            r'HKEY_[A-Z_]+\\[^\\]+(?:\\[^\\]+)*',
            r'\\Registry\\[^\\]+(?:\\[^\\]+)*',
            r'Software\\[^\\]+(?:\\[^\\]+)*',
        ]
        
        registry_keys = []
        for string_info in self.strings:
            for pattern in registry_patterns:
                if re.search(pattern, string_info.value, re.IGNORECASE):
                    registry_keys.append(string_info)
                    break
        
        return registry_keys
    
    def find_file_paths(self) -> List[StringInfo]:
        """Extract file paths from strings"""
        path_patterns = [
            r'[A-Za-z]:\\[^\\/:*?"<>|]+(?:\\[^\\/:*?"<>|]+)*',
            r'\\[^\\/:*?"<>|]+(?:\\[^\\/:*?"<>|]+)*',
            r'/[^/\0]+(?:/[^/\0]+)*',
        ]
        
        paths = []
        for string_info in self.strings:
            for pattern in path_patterns:
                if re.search(pattern, string_info.value):
                    paths.append(string_info)
                    break
        
        return paths
    
    def get_strings_by_length(self, min_length: int, max_length: Optional[int] = None) -> List[StringInfo]:
        """Get strings within specified length range"""
        filtered = []
        
        for string_info in self.strings:
            if string_info.length >= min_length:
                if max_length is None or string_info.length <= max_length:
                    filtered.append(string_info)
        
        return filtered
    
    def get_strings_by_encoding(self, encoding: str) -> List[StringInfo]:
        """Get strings with specific encoding"""
        return [s for s in self.strings if s.encoding == encoding]
    
    def search_strings(self, pattern: str, case_sensitive: bool = False) -> List[StringInfo]:
        """Search strings by pattern"""
        if case_sensitive:
            return [s for s in self.strings if pattern in s.value]
        else:
            pattern_lower = pattern.lower()
            return [s for s in self.strings if pattern_lower in s.value.lower()]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get string extraction statistics"""
        if not self.strings:
            return {}
        
        stats = {
            "total_strings": len(self.strings),
            "encodings": defaultdict(int),
            "length_distribution": defaultdict(int),
            "average_length": 0,
            "max_length": 0,
            "min_length": float('inf'),
            "average_entropy": 0,
            "high_entropy_strings": 0,  # entropy > 4.0
        }
        
        total_length = 0
        total_entropy = 0
        
        for string_info in self.strings:
            # Encoding distribution
            stats["encodings"][string_info.encoding] += 1
            
            # Length distribution
            stats["length_distribution"][string_info.length] += 1
            
            # Length stats
            total_length += string_info.length
            stats["max_length"] = max(stats["max_length"], string_info.length)
            stats["min_length"] = min(stats["min_length"], string_info.length)
            
            # Entropy stats
            total_entropy += string_info.entropy
            if string_info.entropy > 4.0:
                stats["high_entropy_strings"] += 1
        
        if self.strings:
            stats["average_length"] = total_length / len(self.strings)
            stats["average_entropy"] = total_entropy / len(self.strings)
        
        if stats["min_length"] == float('inf'):
            stats["min_length"] = 0
        
        return dict(stats)
