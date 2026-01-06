"""
Mach-O (Mach Object) loader implementation
"""

from pathlib import Path
from typing import Dict, List, Any, Optional

import lief
from loguru import logger

from .base import BaseLoader, BinaryInfo, BinaryType


class MachOLoader(BaseLoader):
    """Mach-O file loader using LIEF"""
    
    def __init__(self, file_path: Path) -> None:
        super().__init__(file_path)
        self.macho: Optional[lief.MachO.Binary] = None
    
    def load(self) -> BinaryInfo:
        """Load Mach-O file and extract information"""
        if not self.validate_file():
            raise FileNotFoundError(f"File not found: {self.file_path}")
        
        try:
            self.binary = lief.parse(str(self.file_path))
            if not isinstance(self.binary, lief.MachO.Binary):
                raise ValueError("Not a valid Mach-O file")
            
            self.macho = self.binary
            
            # Calculate hashes
            hashes = self.get_file_hash()
            
            # Extract information
            sections = self.get_sections()
            imports = self.get_imports()
            exports = self.get_exports()
            
            # Determine architecture
            architecture = self._get_architecture()
            bits = self._get_bits()
            endianness = "little" if self.macho.header.cpu_type.endianness == lief.ENDIANNESS.LITTLE else "big"
            
            return BinaryInfo(
                path=self.file_path,
                file_type=BinaryType.MACHO,
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
            logger.error(f"Failed to load Mach-O file {self.file_path}: {e}")
            raise
    
    def get_sections(self) -> List[Dict[str, Any]]:
        """Get Mach-O sections information"""
        if not self.macho:
            return []
        
        sections = []
        for command in self.macho.commands:
            if isinstance(command, lief.MachO.SegmentCommand):
                for section in command.sections:
                    sections.append({
                        "name": section.name,
                        "segment": section.segment,
                        "virtual_address": section.virtual_address,
                        "virtual_size": section.size,
                        "raw_address": section.offset,
                        "raw_size": section.size,
                        "flags": section.flags,
                        "alignment": section.alignment,
                        "permissions": self._get_section_permissions(section),
                    })
        
        return sections
    
    def get_imports(self) -> List[Dict[str, Any]]:
        """Get Mach-O imports information"""
        if not self.macho:
            return []
        
        imports = []
        
        # Get imports from LC_LOAD_DYLIB commands
        for command in self.macho.commands:
            if isinstance(command, lief.MachO.DylibCommand):
                imports.append({
                    "library": command.name,
                    "timestamp": command.timestamp,
                    "current_version": command.current_version,
                    "compatibility_version": command.compatibility_version,
                    "type": "dylib",
                })
        
        # Get imported symbols from LC_DYSYMTAB
        if self.macho.has_dynamic_symbol_command:
            for symbol in self.macho.symbols:
                if symbol.has_binding_info and symbol.binding_info.library:
                    imports.append({
                        "symbol": symbol.name,
                        "library": symbol.binding_info.library,
                        "address": symbol.value,
                        "type": "symbol",
                    })
        
        return imports
    
    def get_exports(self) -> List[Dict[str, Any]]:
        """Get Mach-O exports information"""
        if not self.macho:
            return []
        
        exports = []
        
        # Get exported symbols
        for symbol in self.macho.symbols:
            if symbol.has_export_info:
                exports.append({
                    "name": symbol.name,
                    "address": symbol.value,
                    "flags": symbol.export_info.flags,
                    "type": "symbol",
                })
        
        return exports
    
    def get_strings(self, min_length: int = 4) -> List[str]:
        """Extract strings from Mach-O file"""
        if not self.macho:
            return []
        
        strings = []
        for s in self.macho.strings:
            if len(s) >= min_length:
                strings.append(s)
        
        return strings
    
    def get_entry_point(self) -> int:
        """Get Mach-O entry point"""
        if not self.macho:
            return 0
        
        # Try to get entry point from LC_MAIN command
        for command in self.macho.commands:
            if isinstance(command, lief.MachO.MainCommand):
                return command.entrypoint
        
        # Fallback to LC_UNIXTHREAD
        for command in self.macho.commands:
            if isinstance(command, lief.MachO.ThreadCommand):
                if command.pc:
                    return command.pc
        
        return 0
    
    def get_image_base(self) -> int:
        """Get Mach-O image base"""
        if not self.macho:
            return 0
        
        # Find the lowest segment address
        min_addr = float('inf')
        for command in self.macho.commands:
            if isinstance(command, lief.MachO.SegmentCommand):
                if command.virtual_address < min_addr:
                    min_addr = command.virtual_address
        
        return min_addr if min_addr != float('inf') else 0
    
    def _get_architecture(self) -> str:
        """Get Mach-O architecture"""
        if not self.macho:
            return "unknown"
        
        arch_map = {
            lief.MachO.CPU_TYPE.x86: "x86",
            lief.MachO.CPU_TYPE.x86_64: "x86_64",
            lief.MachO.CPU_TYPE.ARM: "arm",
            lief.MachO.CPU_TYPE.ARM64: "aarch64",
            lief.MachO.CPU_TYPE.PPC: "ppc",
            lief.MachO.CPU_TYPE.PPC64: "ppc64",
        }
        
        return arch_map.get(self.macho.header.cpu_type, "unknown")
    
    def _get_bits(self) -> int:
        """Get Mach-O bitness"""
        if not self.macho:
            return 0
        
        return 64 if self.macho.header.is_64 else 32
    
    def _get_section_permissions(self, section) -> str:
        """Get section permissions string"""
        perms = []
        
        if section.flags & 0x4:  # S_ATTR_SOME_INSTRUCTIONS
            perms.append("X")
        if section.flags & 0x2:  # S_ATTR_PURE_INSTRUCTIONS
            perms.append("X")
        if section.flags & 0x1:  # S_ATTR_LOC_RELOC
            perms.append("R")
        if section.flags & 0x8:  # S_ATTR_EXT_RELOC
            perms.append("W")
        
        # Check segment permissions as well
        if hasattr(section, 'segment') and section.segment:
            segment_perms = self._get_segment_permissions(section.segment)
            for perm in segment_perms:
                if perm not in perms:
                    perms.append(perm)
        
        return "".join(perms) if perms else "---"
    
    def _get_segment_permissions(self, segment) -> str:
        """Get segment permissions string"""
        perms = []
        
        if segment.init_prot & 0x4:  # VM_PROT_EXECUTE
            perms.append("X")
        if segment.init_prot & 0x2:  # VM_PROT_WRITE
            perms.append("W")
        if segment.init_prot & 0x1:  # VM_PROT_READ
            perms.append("R")
        
        return "".join(perms) if perms else "---"
    
    def _get_metadata(self) -> Dict[str, Any]:
        """Get additional Mach-O metadata"""
        if not self.macho:
            return {}
        
        metadata = {
            "file_type": str(self.macho.header.file_type),
            "cpu_type": str(self.macho.header.cpu_type),
            "cpu_subtype": self.macho.header.cpu_subtype,
            "flags": self.macho.header.flags_list,
            "number_of_commands": self.macho.header.nb_cmds,
            "size_of_commands": self.macho.header.sizeof_cmds,
        }
        
        # Add UUID if available
        if self.macho.has_uuid:
            metadata["uuid"] = str(self.macho.uuid)
        
        # Add version information if available
        if self.macho.has_version_min:
            metadata["version_min"] = {
                "version": self.macho.version_min.version,
                "sdk": self.macho.version_min.sdk,
            }
        
        # Add source version if available
        if self.macho.has_source_version:
            metadata["source_version"] = str(self.macho.source_version)
        
        # Add code signature information if available
        if self.macho.has_code_signature:
            metadata["code_signature"] = {
                "data_size": self.macho.code_signature.data_size,
                "data_offset": self.macho.code_signature.data_offset,
            }
        
        return metadata
