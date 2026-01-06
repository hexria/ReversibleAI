"""
YARA rule engine integration
"""

from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import re
from dataclasses import dataclass

from loguru import logger


@dataclass
class YaraMatch:
    """Represents a YARA rule match"""
    rule_name: str
    namespace: str
    tags: List[str]
    meta: Dict[str, Any]
    strings: List[Dict[str, Any]]
    matches: List[Dict[str, Any]]


class YaraEngine:
    """YARA rule engine for malware detection"""
    
    def __init__(self, rules_path: Optional[Path] = None) -> None:
        self.rules_path = rules_path
        self.rules: Dict[str, str] = {}
        self.compiled_rules = None
        
        # Try to import yara-python
        try:
            import yara
            self.yara = yara
            self.yara_available = True
        except ImportError:
            logger.warning("YARA Python module not available. YARA functionality will be limited.")
            self.yara = None
            self.yara_available = False
        
        # Load rules if path provided
        if rules_path and rules_path.exists():
            self.load_rules(rules_path)
        
        # Load built-in rules
        self._load_builtin_rules()
    
    def load_rules(self, rules_path: Path) -> bool:
        """Load YARA rules from file or directory"""
        if not self.yara_available:
            logger.warning("YARA not available, cannot load rules")
            return False
        
        try:
            if rules_path.is_file():
                # Load single file
                with open(rules_path, 'r') as f:
                    rule_content = f.read()
                
                # Compile rules
                self.compiled_rules = self.yara.compile(source=rule_content)
                self.rules[rules_path.name] = rule_content
                
            elif rules_path.is_dir():
                # Load all .yar and .yara files
                rule_files = list(rules_path.glob('*.yar')) + list(rules_path.glob('*.yara'))
                
                if rule_files:
                    self.compiled_rules = self.yara.compile(filepaths=str(rules_path))
                    
                    for rule_file in rule_files:
                        with open(rule_file, 'r') as f:
                            self.rules[rule_file.name] = f.read()
            
            logger.info(f"Loaded YARA rules from {rules_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load YARA rules: {e}")
            return False
    
    def _load_builtin_rules(self) -> None:
        """Load built-in YARA rules"""
        builtin_rules = {
            "pe_features": '''
rule PE_Features {
    meta:
        description = "Detects common PE file features"
        author = "ReversibleAI"
    condition:
        uint16(0) == 0x5A4D and // MZ header
        uint32(uint32(0x3C)) == 0x00004550 // PE header
}
            ''',
            
            "suspicious_strings": '''
rule Suspicious_Strings {
    meta:
        description = "Detects suspicious strings in binaries"
        author = "ReversibleAI"
    strings:
        $s1 = "CreateProcess" nocase
        $s2 = "VirtualAlloc" nocase
        $s3 = "WriteProcessMemory" nocase
        $s4 = "CreateRemoteThread" nocase
        $s5 = "SetWindowsHookEx" nocase
    condition:
        any of them
}
            ''',
            
            "obfuscation_patterns": '''
rule Obfuscation_Patterns {
    meta:
        description = "Detects common obfuscation patterns"
        author = "ReversibleAI"
    strings:
        $xor1 = { 33 ?? ?? ?? ?? } // XOR EAX, imm32
        $xor2 = { 80 ?? ?? } // XOR [mem], imm8
        $pushad = { 60 } // PUSHAD
        $popad = { 61 } // POPAD
    condition:
        any of them
}
            ''',
            
            "network_indicators": '''
rule Network_Indicators {
    meta:
        description = "Detects network-related indicators"
        author = "ReversibleAI"
    strings:
        $http = "http://" nocase
        $https = "https://" nocase
        $ftp = "ftp://" nocase
        $tcp = "tcp://" nocase
        $udp = "udp://" nocase
        $ip_pattern = /\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b/
    condition:
        any of them
}
            '''
        }
        
        if self.yara_available:
            try:
                # Compile built-in rules
                combined_rules = '\n'.join(builtin_rules.values())
                builtin_compiled = self.yara.compile(source=combined_rules)
                
                # Merge with existing rules
                if self.compiled_rules:
                    # This is simplified - in practice, you'd need proper rule merging
                    pass
                else:
                    self.compiled_rules = builtin_compiled
                
                # Add to rules dict
                self.rules.update(builtin_rules)
                
                logger.info("Loaded built-in YARA rules")
                
            except Exception as e:
                logger.error(f"Failed to compile built-in YARA rules: {e}")
        else:
            # Store rules for reference even if YARA is not available
            self.rules.update(builtin_rules)
    
    def scan_file(self, file_path: Path) -> List[YaraMatch]:
        """Scan a file with YARA rules"""
        if not self.yara_available or not self.compiled_rules:
            logger.warning("YARA not available or no rules loaded")
            return []
        
        try:
            matches = self.compiled_rules.match(str(file_path))
            return self._process_yara_matches(matches)
            
        except Exception as e:
            logger.error(f"Failed to scan file {file_path}: {e}")
            return []
    
    def scan_data(self, data: bytes) -> List[YaraMatch]:
        """Scan binary data with YARA rules"""
        if not self.yara_available or not self.compiled_rules:
            logger.warning("YARA not available or no rules loaded")
            return []
        
        try:
            matches = self.compiled_rules.match(data=data)
            return self._process_yara_matches(matches)
            
        except Exception as e:
            logger.error(f"Failed to scan data: {e}")
            return []
    
    def scan_process(self, pid: int) -> List[YaraMatch]:
        """Scan process memory with YARA rules"""
        if not self.yara_available or not self.compiled_rules:
            logger.warning("YARA not available or no rules loaded")
            return []
        
        try:
            matches = self.compiled_rules.match(pid=pid)
            return self._process_yara_matches(matches)
            
        except Exception as e:
            logger.error(f"Failed to scan process {pid}: {e}")
            return []
    
    def _process_yara_matches(self, matches) -> List[YaraMatch]:
        """Process raw YARA matches into our format"""
        processed_matches = []
        
        for match in matches:
            # Extract strings
            strings = []
            if hasattr(match, 'strings'):
                for string_match in match.strings:
                    strings.append({
                        'identifier': string_match[1],
                        'data': string_match[2].hex() if isinstance(string_match[2], bytes) else str(string_match[2]),
                        'offset': string_match[0]
                    })
            
            # Extract meta information
            meta = {}
            if hasattr(match, 'meta'):
                meta = dict(match.meta)
            
            processed_match = YaraMatch(
                rule_name=match.rule,
                namespace=getattr(match, 'namespace', ''),
                tags=list(getattr(match, 'tags', [])),
                meta=meta,
                strings=strings,
                matches=[]
            )
            
            processed_matches.append(processed_match)
        
        return processed_matches
    
    def add_rule(self, rule_name: str, rule_content: str) -> bool:
        """Add a new YARA rule"""
        if not self.yara_available:
            logger.warning("YARA not available")
            return False
        
        try:
            # Validate rule syntax
            self.yara.compile(source=rule_content)
            
            # Add to rules
            self.rules[rule_name] = rule_content
            
            # Recompile all rules
            combined_rules = '\n'.join(self.rules.values())
            self.compiled_rules = self.yara.compile(source=combined_rules)
            
            logger.info(f"Added YARA rule: {rule_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add YARA rule {rule_name}: {e}")
            return False
    
    def remove_rule(self, rule_name: str) -> bool:
        """Remove a YARA rule"""
        if rule_name not in self.rules:
            logger.warning(f"Rule {rule_name} not found")
            return False
        
        try:
            del self.rules[rule_name]
            
            # Recompile remaining rules
            if self.rules and self.yara_available:
                combined_rules = '\n'.join(self.rules.values())
                self.compiled_rules = self.yara.compile(source=combined_rules)
            else:
                self.compiled_rules = None
            
            logger.info(f"Removed YARA rule: {rule_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to remove YARA rule {rule_name}: {e}")
            return False
    
    def get_rules(self) -> Dict[str, str]:
        """Get all loaded rules"""
        return self.rules.copy()
    
    def get_rule_names(self) -> List[str]:
        """Get list of rule names"""
        return list(self.rules.keys())
    
    def validate_rule(self, rule_content: str) -> Tuple[bool, str]:
        """Validate YARA rule syntax"""
        if not self.yara_available:
            return False, "YARA not available"
        
        try:
            self.yara.compile(source=rule_content)
            return True, "Rule syntax is valid"
        except Exception as e:
            return False, f"Syntax error: {str(e)}"
    
    def search_rules(self, pattern: str) -> List[str]:
        """Search rules by pattern"""
        matching_rules = []
        pattern_lower = pattern.lower()
        
        for rule_name, rule_content in self.rules.items():
            if (pattern_lower in rule_name.lower() or
                pattern_lower in rule_content.lower()):
                matching_rules.append(rule_name)
        
        return matching_rules
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get YARA engine statistics"""
        stats = {
            "yara_available": self.yara_available,
            "total_rules": len(self.rules),
            "rules_compiled": self.compiled_rules is not None,
            "rule_names": list(self.rules.keys()),
        }
        
        if self.rules:
            # Analyze rule content
            total_strings = 0
            total_conditions = 0
            
            for rule_content in self.rules.values():
                # Count strings
                total_strings += len(re.findall(r'\$[a-zA-Z_][a-zA-Z0-9_]*', rule_content))
                
                # Count conditions
                total_conditions += len(re.findall(r'condition:', rule_content, re.IGNORECASE))
            
            stats.update({
                "total_strings": total_strings,
                "total_conditions": total_conditions,
                "avg_strings_per_rule": total_strings / len(self.rules) if self.rules else 0,
            })
        
        return stats
    
    def export_rules(self, output_path: Path) -> bool:
        """Export all rules to file"""
        try:
            with open(output_path, 'w') as f:
                for rule_name, rule_content in self.rules.items():
                    f.write(f"// Rule: {rule_name}\n")
                    f.write(rule_content)
                    f.write("\n\n")
            
            logger.info(f"Exported {len(self.rules)} rules to {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export rules: {e}")
            return False
    
    def import_rules(self, import_path: Path) -> int:
        """Import rules from file"""
        if not import_path.exists():
            logger.error(f"Import file not found: {import_path}")
            return 0
        
        try:
            with open(import_path, 'r') as f:
                content = f.read()
            
            # Split by rule (simplified)
            rule_pattern = r'rule\s+(\w+)\s*\{'
            matches = list(re.finditer(rule_pattern, content, re.IGNORECASE))
            
            imported_count = 0
            
            for i, match in enumerate(matches):
                rule_name = match.group(1)
                
                # Find rule boundaries
                start_pos = match.start()
                if i + 1 < len(matches):
                    end_pos = matches[i + 1].start()
                else:
                    end_pos = len(content)
                
                rule_content = content[start_pos:end_pos].strip()
                
                # Add rule
                if self.add_rule(rule_name, rule_content):
                    imported_count += 1
            
            logger.info(f"Imported {imported_count} rules from {import_path}")
            return imported_count
            
        except Exception as e:
            logger.error(f"Failed to import rules: {e}")
            return 0
