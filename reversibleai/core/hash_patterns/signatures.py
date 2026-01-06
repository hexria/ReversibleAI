"""
Signature database management
"""

from pathlib import Path
from typing import List, Dict, Any, Optional
import json
import yaml
from dataclasses import dataclass, asdict
from datetime import datetime

from loguru import logger


@dataclass
class Signature:
    """Represents a malware signature"""
    id: str
    name: str
    description: str
    author: str
    created: datetime
    modified: datetime
    family: str
    category: str
    severity: str  # "low", "medium", "high", "critical"
    confidence: float
    rules: List[Dict[str, Any]]
    references: List[str]
    tags: List[str]


class SignatureDatabase:
    """Manages malware signature database"""
    
    def __init__(self, db_path: Optional[Path] = None) -> None:
        self.db_path = db_path or Path("signatures.db")
        self.signatures: Dict[str, Signature] = {}
        
        # Load existing signatures
        if self.db_path.exists():
            self.load_signatures()
    
    def load_signatures(self) -> None:
        """Load signatures from database"""
        try:
            if self.db_path.suffix.lower() == '.json':
                self._load_json_signatures()
            elif self.db_path.suffix.lower() in ['.yml', '.yaml']:
                self._load_yaml_signatures()
            else:
                logger.warning(f"Unsupported signature database format: {self.db_path.suffix}")
                
            logger.info(f"Loaded {len(self.signatures)} signatures")
            
        except Exception as e:
            logger.error(f"Failed to load signatures: {e}")
    
    def _load_json_signatures(self) -> None:
        """Load signatures from JSON file"""
        with open(self.db_path, 'r') as f:
            data = json.load(f)
        
        for sig_data in data.get('signatures', []):
            signature = self._dict_to_signature(sig_data)
            self.signatures[signature.id] = signature
    
    def _load_yaml_signatures(self) -> None:
        """Load signatures from YAML file"""
        with open(self.db_path, 'r') as f:
            data = yaml.safe_load(f)
        
        for sig_data in data.get('signatures', []):
            signature = self._dict_to_signature(sig_data)
            self.signatures[signature.id] = signature
    
    def save_signatures(self) -> None:
        """Save signatures to database"""
        try:
            signatures_data = []
            for signature in self.signatures.values():
                sig_dict = asdict(signature)
                # Convert datetime objects to strings
                sig_dict['created'] = signature.created.isoformat()
                sig_dict['modified'] = signature.modified.isoformat()
                signatures_data.append(sig_dict)
            
            data = {
                'version': '1.0',
                'created': datetime.now().isoformat(),
                'signatures': signatures_data
            }
            
            if self.db_path.suffix.lower() == '.json':
                with open(self.db_path, 'w') as f:
                    json.dump(data, f, indent=2)
            elif self.db_path.suffix.lower() in ['.yml', '.yaml']:
                with open(self.db_path, 'w') as f:
                    yaml.dump(data, f, default_flow_style=False)
            
            logger.info(f"Saved {len(self.signatures)} signatures to {self.db_path}")
            
        except Exception as e:
            logger.error(f"Failed to save signatures: {e}")
    
    def _dict_to_signature(self, sig_data: Dict[str, Any]) -> Signature:
        """Convert dictionary to Signature object"""
        created = datetime.fromisoformat(sig_data['created']) if isinstance(sig_data['created'], str) else sig_data['created']
        modified = datetime.fromisoformat(sig_data['modified']) if isinstance(sig_data['modified'], str) else sig_data['modified']
        
        return Signature(
            id=sig_data['id'],
            name=sig_data['name'],
            description=sig_data['description'],
            author=sig_data['author'],
            created=created,
            modified=modified,
            family=sig_data['family'],
            category=sig_data['category'],
            severity=sig_data['severity'],
            confidence=sig_data['confidence'],
            rules=sig_data['rules'],
            references=sig_data['references'],
            tags=sig_data['tags']
        )
    
    def add_signature(self, signature: Signature) -> bool:
        """Add a new signature"""
        if signature.id in self.signatures:
            logger.warning(f"Signature {signature.id} already exists")
            return False
        
        self.signatures[signature.id] = signature
        logger.info(f"Added signature: {signature.name}")
        return True
    
    def update_signature(self, signature: Signature) -> bool:
        """Update an existing signature"""
        if signature.id not in self.signatures:
            logger.warning(f"Signature {signature.id} not found")
            return False
        
        signature.modified = datetime.now()
        self.signatures[signature.id] = signature
        logger.info(f"Updated signature: {signature.name}")
        return True
    
    def remove_signature(self, signature_id: str) -> bool:
        """Remove a signature"""
        if signature_id not in self.signatures:
            logger.warning(f"Signature {signature_id} not found")
            return False
        
        signature = self.signatures[signature_id]
        del self.signatures[signature_id]
        logger.info(f"Removed signature: {signature.name}")
        return True
    
    def get_signature(self, signature_id: str) -> Optional[Signature]:
        """Get signature by ID"""
        return self.signatures.get(signature_id)
    
    def search_signatures(self, 
                         name: Optional[str] = None,
                         family: Optional[str] = None,
                         category: Optional[str] = None,
                         severity: Optional[str] = None,
                         tags: Optional[List[str]] = None) -> List[Signature]:
        """Search signatures by various criteria"""
        results = []
        
        for signature in self.signatures.values():
            # Check name
            if name and name.lower() not in signature.name.lower():
                continue
            
            # Check family
            if family and family.lower() != signature.family.lower():
                continue
            
            # Check category
            if category and category.lower() != signature.category.lower():
                continue
            
            # Check severity
            if severity and severity.lower() != signature.severity.lower():
                continue
            
            # Check tags
            if tags:
                if not any(tag.lower() in [t.lower() for t in signature.tags] for tag in tags):
                    continue
            
            results.append(signature)
        
        return results
    
    def get_signatures_by_family(self, family: str) -> List[Signature]:
        """Get all signatures for a specific malware family"""
        return self.search_signatures(family=family)
    
    def get_signatures_by_severity(self, severity: str) -> List[Signature]:
        """Get all signatures with a specific severity level"""
        return self.search_signatures(severity=severity)
    
    def get_families(self) -> List[str]:
        """Get list of all malware families"""
        families = set()
        for signature in self.signatures.values():
            families.add(signature.family)
        return sorted(list(families))
    
    def get_categories(self) -> List[str]:
        """Get list of all categories"""
        categories = set()
        for signature in self.signatures.values():
            categories.add(signature.category)
        return sorted(list(categories))
    
    def get_tags(self) -> List[str]:
        """Get list of all tags"""
        tags = set()
        for signature in self.signatures.values():
            tags.update(signature.tags)
        return sorted(list(tags))
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics"""
        stats = {
            "total_signatures": len(self.signatures),
            "families": {},
            "categories": {},
            "severities": {},
            "top_authors": {},
        }
        
        for signature in self.signatures.values():
            # Family distribution
            stats["families"][signature.family] = stats["families"].get(signature.family, 0) + 1
            
            # Category distribution
            stats["categories"][signature.category] = stats["categories"].get(signature.category, 0) + 1
            
            # Severity distribution
            stats["severities"][signature.severity] = stats["severities"].get(signature.severity, 0) + 1
            
            # Author distribution
            stats["top_authors"][signature.author] = stats["top_authors"].get(signature.author, 0) + 1
        
        return stats
    
    def validate_signature(self, signature: Signature) -> List[str]:
        """Validate signature format and content"""
        errors = []
        
        # Check required fields
        if not signature.id:
            errors.append("Missing signature ID")
        
        if not signature.name:
            errors.append("Missing signature name")
        
        if not signature.description:
            errors.append("Missing signature description")
        
        if not signature.family:
            errors.append("Missing malware family")
        
        if not signature.category:
            errors.append("Missing category")
        
        if signature.severity not in ["low", "medium", "high", "critical"]:
            errors.append(f"Invalid severity: {signature.severity}")
        
        if not (0.0 <= signature.confidence <= 1.0):
            errors.append(f"Invalid confidence: {signature.confidence}")
        
        if not signature.rules:
            errors.append("No rules defined")
        
        # Validate rules
        for i, rule in enumerate(signature.rules):
            if not rule.get('type'):
                errors.append(f"Rule {i}: Missing rule type")
            
            if rule.get('type') == 'hash' and not rule.get('value'):
                errors.append(f"Rule {i}: Missing hash value")
            
            if rule.get('type') == 'yara' and not rule.get('rule'):
                errors.append(f"Rule {i}: Missing YARA rule")
        
        return errors
    
    def import_signatures(self, import_path: Path) -> int:
        """Import signatures from another file"""
        try:
            imported_count = 0
            
            if import_path.suffix.lower() == '.json':
                with open(import_path, 'r') as f:
                    data = json.load(f)
            elif import_path.suffix.lower() in ['.yml', '.yaml']:
                with open(import_path, 'r') as f:
                    data = yaml.safe_load(f)
            else:
                logger.error(f"Unsupported import format: {import_path.suffix}")
                return 0
            
            for sig_data in data.get('signatures', []):
                signature = self._dict_to_signature(sig_data)
                
                # Validate signature
                errors = self.validate_signature(signature)
                if errors:
                    logger.warning(f"Skipping invalid signature {signature.id}: {errors}")
                    continue
                
                # Add or update signature
                if signature.id in self.signatures:
                    self.update_signature(signature)
                else:
                    self.add_signature(signature)
                
                imported_count += 1
            
            logger.info(f"Imported {imported_count} signatures from {import_path}")
            return imported_count
            
        except Exception as e:
            logger.error(f"Failed to import signatures: {e}")
            return 0
    
    def export_signatures(self, export_path: Path, 
                         family: Optional[str] = None,
                         severity: Optional[str] = None) -> int:
        """Export signatures to file"""
        try:
            # Filter signatures
            signatures_to_export = self.search_signatures(family=family, severity=severity)
            
            if not signatures_to_export:
                logger.warning("No signatures to export")
                return 0
            
            # Prepare export data
            signatures_data = []
            for signature in signatures_to_export:
                sig_dict = asdict(signature)
                sig_dict['created'] = signature.created.isoformat()
                sig_dict['modified'] = signature.modified.isoformat()
                signatures_data.append(sig_dict)
            
            data = {
                'version': '1.0',
                'exported': datetime.now().isoformat(),
                'signatures': signatures_data
            }
            
            # Export to file
            if export_path.suffix.lower() == '.json':
                with open(export_path, 'w') as f:
                    json.dump(data, f, indent=2)
            elif export_path.suffix.lower() in ['.yml', '.yaml']:
                with open(export_path, 'w') as f:
                    yaml.dump(data, f, default_flow_style=False)
            
            logger.info(f"Exported {len(signatures_to_export)} signatures to {export_path}")
            return len(signatures_to_export)
            
        except Exception as e:
            logger.error(f"Failed to export signatures: {e}")
            return 0
