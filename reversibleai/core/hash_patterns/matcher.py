"""
Hash pattern matching for malware detection and classification
"""

from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple
import hashlib
import re
from dataclasses import dataclass
from collections import defaultdict

from loguru import logger


@dataclass
class HashMatch:
    """Represents a hash pattern match"""
    pattern_name: str
    pattern_type: str
    hash_value: str
    hash_algorithm: str
    confidence: float
    description: str
    references: List[str]
    tags: List[str]


@dataclass
class HashPattern:
    """Represents a hash pattern"""
    name: str
    pattern_type: str  # "file", "function", "string", "import"
    hash_algorithm: str  # "md5", "sha1", "sha256", "imphash", "fuzzy"
    hash_value: str
    description: str
    confidence: float
    references: List[str]
    tags: List[str]
    context: Dict[str, Any]


class HashPatternMatcher:
    """Advanced hash pattern matching system"""
    
    def __init__(self, signature_db_path: Optional[Path] = None) -> None:
        self.signature_db_path = signature_db_path
        self.patterns: Dict[str, List[HashPattern]] = defaultdict(list)
        self.matches: List[HashMatch] = []
        
        # Initialize with built-in patterns
        self._load_builtin_patterns()
        
        # Load external patterns if provided
        if signature_db_path and signature_db_path.exists():
            self._load_external_patterns(signature_db_path)
    
    def _load_builtin_patterns(self) -> None:
        """Load built-in hash patterns"""
        # Common malware hashes (examples)
        builtin_patterns = [
            # File hashes
            HashPattern(
                name="Emotet_Dropper",
                pattern_type="file",
                hash_algorithm="sha256",
                hash_value="b5a7d5f5e5a5d5b5e5a5d5f5e5a5d5b5e5a5d5f5e5a5d5b5e5a5d5f5e5a5d5b5",
                description="Emotet malware dropper variant",
                confidence=0.95,
                references=["https://www.malware-traffic-analysis.net/2021/08/02/index.html"],
                tags=["emotet", "trojan", "banking"],
                context={"family": "Emotet", "variant": "Dropper"}
            ),
            
            # Import hashes
            HashPattern(
                name="Common_Backdoor_Imports",
                pattern_type="import",
                hash_algorithm="imphash",
                hash_value="d41d8cd98f00b204e9800998ecf8427e",  # Example
                description="Common backdoor import pattern",
                confidence=0.8,
                references=["https://www.fireeye.com/blog/threat-research/2019/04/"],
                tags=["backdoor", "remote-access"],
                context={"category": "backdoor"}
            ),
            
            # Function hashes
            HashPattern(
                name="Obfuscated_Entry_Point",
                pattern_type="function",
                hash_algorithm="md5",
                hash_value="5d41402abc4b2a76b9719d911017c592",  # Example
                description="Common obfuscated function entry point pattern",
                confidence=0.7,
                references=["https://research.checkpoint.com/2020/"],
                tags=["obfuscation", "anti-analysis"],
                context={"technique": "obfuscation"}
            ),
        ]
        
        for pattern in builtin_patterns:
            key = f"{pattern.pattern_type}_{pattern.hash_algorithm}"
            self.patterns[key].append(pattern)
    
    def _load_external_patterns(self, db_path: Path) -> None:
        """Load patterns from external database"""
        try:
            # This would load from various formats (JSON, YAML, etc.)
            # For now, just log that we would load
            logger.info(f"Loading external patterns from {db_path}")
            
        except Exception as e:
            logger.error(f"Failed to load external patterns: {e}")
    
    def match_file_hashes(self, file_path: Path) -> List[HashMatch]:
        """Match file hashes against pattern database"""
        matches = []
        
        # Calculate file hashes
        file_hashes = self._calculate_file_hashes(file_path)
        
        # Match against patterns
        for hash_type, hash_value in file_hashes.items():
            key = f"file_{hash_type}"
            if key in self.patterns:
                for pattern in self.patterns[key]:
                    if self._compare_hashes(hash_value, pattern.hash_value, hash_type):
                        match = HashMatch(
                            pattern_name=pattern.name,
                            pattern_type=pattern.pattern_type,
                            hash_value=hash_value,
                            hash_algorithm=hash_type,
                            confidence=pattern.confidence,
                            description=pattern.description,
                            references=pattern.references,
                            tags=pattern.tags
                        )
                        matches.append(match)
        
        return matches
    
    def match_function_hashes(self, functions: List[Dict[str, Any]]) -> List[HashMatch]:
        """Match function hashes against pattern database"""
        matches = []
        
        for func in functions:
            # Calculate function hash
            func_hash = self._calculate_function_hash(func)
            
            # Match against patterns
            key = "function_md5"
            if key in self.patterns:
                for pattern in self.patterns[key]:
                    if self._compare_hashes(func_hash, pattern.hash_value, "md5"):
                        match = HashMatch(
                            pattern_name=pattern.name,
                            pattern_type=pattern.pattern_type,
                            hash_value=func_hash,
                            hash_algorithm="md5",
                            confidence=pattern.confidence,
                            description=pattern.description,
                            references=pattern.references,
                            tags=pattern.tags
                        )
                        matches.append(match)
        
        return matches
    
    def match_string_hashes(self, strings: List[str]) -> List[HashMatch]:
        """Match string hashes against pattern database"""
        matches = []
        
        for string_value in strings:
            # Calculate string hash
            string_hash = hashlib.md5(string_value.encode()).hexdigest()
            
            # Match against patterns
            key = "string_md5"
            if key in self.patterns:
                for pattern in self.patterns[key]:
                    if self._compare_hashes(string_hash, pattern.hash_value, "md5"):
                        match = HashMatch(
                            pattern_name=pattern.name,
                            pattern_type=pattern.pattern_type,
                            hash_value=string_hash,
                            hash_algorithm="md5",
                            confidence=pattern.confidence,
                            description=pattern.description,
                            references=pattern.references,
                            tags=pattern.tags
                        )
                        matches.append(match)
        
        return matches
    
    def match_import_hashes(self, imports: List[Dict[str, Any]]) -> List[HashMatch]:
        """Match import hashes against pattern database"""
        matches = []
        
        # Calculate import hash (imphash-like)
        import_hash = self._calculate_import_hash(imports)
        
        # Match against patterns
        key = "import_imphash"
        if key in self.patterns:
            for pattern in self.patterns[key]:
                if self._compare_hashes(import_hash, pattern.hash_value, "imphash"):
                    match = HashMatch(
                        pattern_name=pattern.name,
                        pattern_type=pattern.pattern_type,
                        hash_value=import_hash,
                        hash_algorithm="imphash",
                        confidence=pattern.confidence,
                        description=pattern.description,
                        references=pattern.references,
                        tags=pattern.tags
                    )
                    matches.append(match)
        
        return matches
    
    def _calculate_file_hashes(self, file_path: Path) -> Dict[str, str]:
        """Calculate various file hashes"""
        hashes = {}
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            hashes['md5'] = hashlib.md5(data).hexdigest()
            hashes['sha1'] = hashlib.sha1(data).hexdigest()
            hashes['sha256'] = hashlib.sha256(data).hexdigest()
            
        except Exception as e:
            logger.error(f"Failed to calculate file hashes: {e}")
        
        return hashes
    
    def _calculate_function_hash(self, function: Dict[str, Any]) -> str:
        """Calculate function hash based on instructions"""
        instructions = function.get('instructions', [])
        
        # Create normalized instruction sequence
        normalized = []
        for insn in instructions:
            mnemonic = insn.get('mnemonic', '').lower()
            operands = insn.get('operands', '').lower()
            
            # Normalize operands (remove immediate values, etc.)
            normalized_operands = self._normalize_operands(operands)
            normalized.append(f"{mnemonic} {normalized_operands}")
        
        # Calculate hash
        function_text = '\n'.join(normalized)
        return hashlib.md5(function_text.encode()).hexdigest()
    
    def _normalize_operands(self, operands: str) -> str:
        """Normalize operands for hashing"""
        # Replace immediate values with placeholder
        normalized = re.sub(r'0x[0-9a-fA-F]+', 'IMM', operands)
        normalized = re.sub(r'\d+', 'NUM', normalized)
        
        # Replace register variations
        normalized = re.sub(r'e[abcd]x', 'REG', normalized)
        normalized = re.sub(r'r[abcd]x', 'REG', normalized)
        
        return normalized.strip()
    
    def _calculate_import_hash(self, imports: List[Dict[str, Any]]) -> str:
        """Calculate import hash similar to imphash"""
        # Sort imports by library and function
        sorted_imports = sorted(imports, key=lambda x: (x.get('library', ''), x.get('function', '')))
        
        # Create import string
        import_parts = []
        for imp in sorted_imports:
            library = imp.get('library', '').lower().replace('.dll', '')
            function = imp.get('function', '').lower()
            import_parts.append(f"{library}.{function}")
        
        import_text = ','.join(import_parts)
        return hashlib.md5(import_text.encode()).hexdigest()
    
    def _compare_hashes(self, hash1: str, hash2: str, hash_type: str) -> bool:
        """Compare two hashes with appropriate method"""
        if hash_type in ["md5", "sha1", "sha256", "imphash"]:
            return hash1.lower() == hash2.lower()
        elif hash_type == "fuzzy":
            return self._fuzzy_hash_compare(hash1, hash2)
        else:
            return hash1 == hash2
    
    def _fuzzy_hash_compare(self, hash1: str, hash2: str, threshold: float = 0.8) -> bool:
        """Compare fuzzy hashes with similarity threshold"""
        # Simple implementation - in practice, use ssdeep or similar
        if len(hash1) != len(hash2):
            return False
        
        matches = sum(1 for a, b in zip(hash1, hash2) if a == b)
        similarity = matches / len(hash1)
        
        return similarity >= threshold
    
    def add_pattern(self, pattern: HashPattern) -> None:
        """Add a new pattern to the database"""
        key = f"{pattern.pattern_type}_{pattern.hash_algorithm}"
        self.patterns[key].append(pattern)
        logger.info(f"Added pattern: {pattern.name}")
    
    def remove_pattern(self, pattern_name: str) -> bool:
        """Remove a pattern by name"""
        for key, pattern_list in self.patterns.items():
            for i, pattern in enumerate(pattern_list):
                if pattern.name == pattern_name:
                    del pattern_list[i]
                    logger.info(f"Removed pattern: {pattern_name}")
                    return True
        return False
    
    def search_patterns(self, query: str) -> List[HashPattern]:
        """Search patterns by name, description, or tags"""
        results = []
        query_lower = query.lower()
        
        for pattern_list in self.patterns.values():
            for pattern in pattern_list:
                if (query_lower in pattern.name.lower() or
                    query_lower in pattern.description.lower() or
                    any(query_lower in tag.lower() for tag in pattern.tags)):
                    results.append(pattern)
        
        return results
    
    def get_patterns_by_tag(self, tag: str) -> List[HashPattern]:
        """Get all patterns with a specific tag"""
        results = []
        tag_lower = tag.lower()
        
        for pattern_list in self.patterns.values():
            for pattern in pattern_list:
                if any(tag_lower == t.lower() for t in pattern.tags):
                    results.append(pattern)
        
        return results
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get pattern database statistics"""
        stats = {
            "total_patterns": 0,
            "pattern_types": defaultdict(int),
            "hash_algorithms": defaultdict(int),
            "tags": defaultdict(int),
        }
        
        for pattern_list in self.patterns.values():
            for pattern in pattern_list:
                stats["total_patterns"] += 1
                stats["pattern_types"][pattern.pattern_type] += 1
                stats["hash_algorithms"][pattern.hash_algorithm] += 1
                
                for tag in pattern.tags:
                    stats["tags"][tag] += 1
        
        return dict(stats)
    
    def export_patterns(self, output_path: Path, format: str = "json") -> bool:
        """Export patterns to file"""
        try:
            all_patterns = []
            for pattern_list in self.patterns.values():
                all_patterns.extend(pattern_list)
            
            if format.lower() == "json":
                import json
                data = [pattern.__dict__ for pattern in all_patterns]
                with open(output_path, 'w') as f:
                    json.dump(data, f, indent=2)
            
            logger.info(f"Exported {len(all_patterns)} patterns to {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export patterns: {e}")
            return False
