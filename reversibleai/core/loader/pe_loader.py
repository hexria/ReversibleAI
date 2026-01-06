"""
PE (Portable Executable) loader implementation
"""

from pathlib import Path
from typing import Dict, List, Any, Optional

import lief
from loguru import logger

from .base import BaseLoader, BinaryInfo, BinaryType


class PELoader(BaseLoader):
    """PE file loader using LIEF"""
    
    def __init__(self, file_path: Path) -> None:
        super().__init__(file_path)
        self.pe: Optional[lief.PE.Binary] = None
    
    def load(self) -> BinaryInfo:
        """Load PE file and extract information"""
        if not self.validate_file():
            raise FileNotFoundError(f"File not found: {self.file_path}")
        
        try:
            self.binary = lief.parse(str(self.file_path))
            if not isinstance(self.binary, lief.PE.Binary):
                raise ValueError("Not a valid PE file")
            
            self.pe = self.binary
            
            # Calculate hashes
            hashes = self.get_file_hash()
            
            # Extract information
            sections = self.get_sections()
            imports = self.get_imports()
            exports = self.get_exports()
            
            # Determine architecture
            architecture = self._get_architecture()
            bits = self._get_bits()
            endianness = "little"  # PE is always little-endian
            
            return BinaryInfo(
                path=self.file_path,
                file_type=BinaryType.PE,
                architecture=architecture,
                bits=bits,
                endianness=endianness,
                entry_point=self.get_entry_point(),
                image_base=self.get_image_base(),
                size=self.file_path.stat().st_size,
                md5=hashes["md5"],
                sha1=hashes["sha1"],
                sha256=hashes["sha256"],
                sections=sections,
                imports=imports,
                exports=exports,
                metadata=self._get_metadata()
            )
            
        except Exception as e:
            logger.error(f"Failed to load PE file {self.file_path}: {e}")
            raise
    
    def get_sections(self) -> List[Dict[str, Any]]:
        """Get PE sections information"""
        if not self.pe:
            return []
        
        sections = []
        for section in self.pe.sections:
            sections.append({
                "name": section.name,
                "virtual_address": section.virtual_address,
                "virtual_size": section.virtual_size,
                "raw_address": section.offset,
                "raw_size": section.size,
                "characteristics": section.characteristics,
                "entropy": section.entropy,
                "permissions": self._get_section_permissions(section),
            })
        
        return sections
    
    def get_imports(self) -> List[Dict[str, Any]]:
        """Get PE imports information"""
        if not self.pe:
            return []
        
        imports = []
        for import_entry in self.pe.imports:
            for function in import_entry.entries:
                imports.append({
                    "library": import_entry.name,
                    "function": function.name,
                    "address": function.iat_address,
                    "ordinal": function.ordinal,
                    "is_ordinal": function.is_ordinal,
                })
        
        return imports
    
    def get_exports(self) -> List[Dict[str, Any]]:
        """Get PE exports information"""
        if not self.pe:
            return []
        
        exports = []
        if self.pe.has_exports:
            for export in self.pe.exported_functions:
                exports.append({
                    "name": export.name,
                    "address": export.address,
                    "ordinal": export.ordinal,
                })
        
        return exports
    
    def get_strings(self, min_length: int = 4) -> List[str]:
        """Extract strings from PE file"""
        if not self.pe:
            return []
        
        strings = []
        for s in self.pe.strings:
            if len(s) >= min_length:
                strings.append(s)
        
        return strings
    
    def get_entry_point(self) -> int:
        """Get PE entry point"""
        if not self.pe:
            return 0
        return self.pe.entrypoint
    
    def get_image_base(self) -> int:
        """Get PE image base"""
        if not self.pe:
            return 0
        return self.pe.imagebase
    
    def _get_architecture(self) -> str:
        """Get PE architecture"""
        if not self.pe:
            return "unknown"
        
        if self.pe.header.machine == lief.PE.MACHINE_TYPES.I386:
            return "x86"
        elif self.pe.header.machine == lief.PE.MACHINE_TYPES.AMD64:
            return "x86_64"
        elif self.pe.header.machine == lief.PE.MACHINE_TYPES.ARM:
            return "arm"
        elif self.pe.header.machine == lief.PE.MACHINE_TYPES.ARM64:
            return "aarch64"
        else:
            return "unknown"
    
    def _get_bits(self) -> int:
        """Get PE bitness"""
        if not self.pe:
            return 0
        
        if self.pe.header.is_64:
            return 64
        else:
            return 32
    
    def _get_section_permissions(self, section) -> str:
        """Get section permissions string"""
        perms = []
        if section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE):
            perms.append("X")
        if section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_READ):
            perms.append("R")
        if section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE):
            perms.append("W")
        
        return "".join(perms) if perms else "---"
    
    def _get_metadata(self) -> Dict[str, Any]:
        """Get additional PE metadata"""
        if not self.pe:
            return {}
        
        metadata = {
            "compile_time": self.pe.header.time_date_stamps,
            "subsystem": str(self.pe.header.subsystem),
            "dll_characteristics": self.pe.header.dll_characteristics_list,
            "machine": str(self.pe.header.machine),
        }
        
        # Add version information if available
        if self.pe.has_resources:
            resources = self.pe.resources
            if hasattr(resources, 'version'):
                version_info = resources.version
                if version_info:
                    metadata["version_info"] = {
                        "company_name": version_info.company_name,
                        "file_description": version_info.file_description,
                        "file_version": version_info.file_version,
                        "product_name": version_info.product_name,
                        "product_version": version_info.product_version,
                    }
        
        return metadata
