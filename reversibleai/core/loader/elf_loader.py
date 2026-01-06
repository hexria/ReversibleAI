"""
ELF (Executable and Linkable Format) loader implementation
"""

from pathlib import Path
from typing import Dict, List, Any, Optional

import lief
from loguru import logger

from .base import BaseLoader, BinaryInfo, BinaryType


class ELFLoader(BaseLoader):
    """ELF file loader using LIEF"""
    
    def __init__(self, file_path: Path) -> None:
        super().__init__(file_path)
        self.elf: Optional[lief.ELF.Binary] = None
    
    def load(self) -> BinaryInfo:
        """Load ELF file and extract information"""
        if not self.validate_file():
            raise FileNotFoundError(f"File not found: {self.file_path}")
        
        try:
            self.binary = lief.parse(str(self.file_path))
            if not isinstance(self.binary, lief.ELF.Binary):
                raise ValueError("Not a valid ELF file")
            
            self.elf = self.binary
            
            # Calculate hashes
            hashes = self.get_file_hash()
            
            # Extract information
            sections = self.get_sections()
            imports = self.get_imports()
            exports = self.get_exports()
            
            # Determine architecture
            architecture = self._get_architecture()
            bits = self._get_bits()
            endianness = "little" if self.elf.header.identity_data == lief.ELF.ELF_DATA.LSB else "big"
            
            return BinaryInfo(
                path=self.file_path,
                file_type=BinaryType.ELF,
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
            logger.error(f"Failed to load ELF file {self.file_path}: {e}")
            raise
    
    def get_sections(self) -> List[Dict[str, Any]]:
        """Get ELF sections information"""
        if not self.elf:
            return []
        
        sections = []
        for section in self.elf.sections:
            sections.append({
                "name": section.name,
                "virtual_address": section.virtual_address,
                "virtual_size": section.size,
                "raw_address": section.file_offset,
                "raw_size": section.size,
                "flags": section.flags,
                "type": str(section.type),
                "entropy": section.entropy,
                "permissions": self._get_section_permissions(section),
            })
        
        return sections
    
    def get_imports(self) -> List[Dict[str, Any]]:
        """Get ELF imports (dynamic symbols) information"""
        if not self.elf:
            return []
        
        imports = []
        if self.elf.has_dynamic_symbols:
            for symbol in self.elf.dynamic_symbols:
                if symbol.imported:
                    imports.append({
                        "name": symbol.name,
                        "library": symbol.library,
                        "address": symbol.value,
                        "binding": str(symbol.binding),
                        "type": str(symbol.type),
                        "visibility": str(symbol.visibility),
                    })
        
        return imports
    
    def get_exports(self) -> List[Dict[str, Any]]:
        """Get ELF exports information"""
        if not self.elf:
            return []
        
        exports = []
        if self.elf.has_dynamic_symbols:
            for symbol in self.elf.dynamic_symbols:
                if symbol.exported:
                    exports.append({
                        "name": symbol.name,
                        "address": symbol.value,
                        "binding": str(symbol.binding),
                        "type": str(symbol.type),
                        "visibility": str(symbol.visibility),
                    })
        
        return exports
    
    def get_strings(self, min_length: int = 4) -> List[str]:
        """Extract strings from ELF file"""
        if not self.elf:
            return []
        
        strings = []
        for s in self.elf.strings:
            if len(s) >= min_length:
                strings.append(s)
        
        return strings
    
    def get_entry_point(self) -> int:
        """Get ELF entry point"""
        if not self.elf:
            return 0
        return self.elf.entrypoint
    
    def get_image_base(self) -> int:
        """Get ELF image base (for PIE binaries, this might be 0)"""
        if not self.elf:
            return 0
        
        # For PIE binaries, the base is typically 0x400000 for 32-bit and 0x100000000 for 64-bit
        # But the actual base is determined at runtime
        if self.elf.header.file_type == lief.ELF.ELF_CLASS.EXEC:
            # Try to find the lowest loadable segment
            min_addr = float('inf')
            for segment in self.elf.segments:
                if segment.type == lief.ELF.SEGMENT_TYPES.LOAD:
                    if segment.virtual_address < min_addr:
                        min_addr = segment.virtual_address
            return min_addr if min_addr != float('inf') else 0
        
        return 0
    
    def _get_architecture(self) -> str:
        """Get ELF architecture"""
        if not self.elf:
            return "unknown"
        
        arch_map = {
            lief.ELF.ARCH.i386: "x86",
            lief.ELF.ARCH.x86_64: "x86_64",
            lief.ELF.ARCH.ARM: "arm",
            lief.ELF.ARCH.AARCH64: "aarch64",
            lief.ELF.ARCH.MIPS: "mips",
            lief.ELF.ARCH.PPC: "ppc",
            lief.ELF.ARCH.PPC64: "ppc64",
            lief.ELF.ARCH.RISCV: "riscv",
        }
        
        return arch_map.get(self.elf.header.machine_type, "unknown")
    
    def _get_bits(self) -> int:
        """Get ELF bitness"""
        if not self.elf:
            return 0
        
        if self.elf.header.identity_class == lief.ELF.ELF_CLASS.CLASS64:
            return 64
        else:
            return 32
    
    def _get_section_permissions(self, section) -> str:
        """Get section permissions string"""
        perms = []
        if section.has(lief.ELF.SECTION_FLAGS.ALLOC):
            if section.has(lief.ELF.SECTION_FLAGS.EXECINSTR):
                perms.append("X")
            if section.has(lief.ELF.SECTION_FLAGS.WRITE):
                perms.append("W")
            if section.has(lief.ELF.SECTION_FLAGS.READ) or not perms:
                perms.append("R")
        
        return "".join(perms) if perms else "---"
    
    def _get_metadata(self) -> Dict[str, Any]:
        """Get additional ELF metadata"""
        if not self.elf:
            return {}
        
        metadata = {
            "file_type": str(self.elf.header.file_type),
            "machine_type": str(self.elf.header.machine_type),
            "object_file_version": str(self.elf.header.object_file_version),
            "os_abi": str(self.elf.header.os_abi),
            "abi_version": self.elf.header.abi_version,
            "program_headers_count": self.elf.header.numberof_segments,
            "section_headers_count": self.elf.header.numberof_sections,
        }
        
        # Add interpreter information if available
        if self.elf.has_interpreter:
            metadata["interpreter"] = self.elf.interpreter
        
        # Add dynamic entries if available
        if self.elf.has_dynamic_entries:
            dynamic_entries = []
            for entry in self.elf.dynamic_entries:
                dynamic_entries.append({
                    "tag": str(entry.tag),
                    "value": entry.value,
                })
            metadata["dynamic_entries"] = dynamic_entries
        
        return metadata
