"""
Base loader class for binary files
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from enum import Enum

import lief


class BinaryType(Enum):
    """Supported binary types"""
    PE = "PE"
    ELF = "ELF"
    MACHO = "MACHO"
    UNKNOWN = "UNKNOWN"


@dataclass
class BinaryInfo:
    """Basic information about a binary file"""
    path: Path
    file_type: BinaryType
    architecture: str
    bits: int
    endianness: str
    entry_point: int
    image_base: int
    size: int
    md5: str
    sha1: str
    sha256: str
    sections: List[Dict[str, Any]]
    imports: List[Dict[str, Any]]
    exports: List[Dict[str, Any]]
    metadata: Dict[str, Any]


class BaseLoader(ABC):
    """Abstract base class for binary loaders"""
    
    def __init__(self, file_path: Union[str, Path]) -> None:
        self.file_path = Path(file_path)
        self.binary: Optional[lief.Binary] = None
        self._info: Optional[BinaryInfo] = None
        
    @abstractmethod
    def load(self) -> BinaryInfo:
        """Load the binary file and return basic information"""
        pass
    
    @abstractmethod
    def get_sections(self) -> List[Dict[str, Any]]:
        """Get information about binary sections"""
        pass
    
    @abstractmethod
    def get_imports(self) -> List[Dict[str, Any]]:
        """Get imported functions and libraries"""
        pass
    
    @abstractmethod
    def get_exports(self) -> List[Dict[str, Any]]:
        """Get exported functions and symbols"""
        pass
    
    @abstractmethod
    def get_strings(self, min_length: int = 4) -> List[str]:
        """Extract strings from the binary"""
        pass
    
    @abstractmethod
    def get_entry_point(self) -> int:
        """Get the entry point address"""
        pass
    
    @abstractmethod
    def get_image_base(self) -> int:
        """Get the image base address"""
        pass
    
    def validate_file(self) -> bool:
        """Validate if the file exists and is readable"""
        return self.file_path.exists() and self.file_path.is_file()
    
    def get_file_hash(self) -> Dict[str, str]:
        """Calculate file hashes"""
        import hashlib
        
        hashes = {"md5": "", "sha1": "", "sha256": ""}
        
        try:
            with open(self.file_path, "rb") as f:
                data = f.read()
                
            hashes["md5"] = hashlib.md5(data).hexdigest()
            hashes["sha1"] = hashlib.sha1(data).hexdigest()
            hashes["sha256"] = hashlib.sha256(data).hexdigest()
            
        except Exception as e:
            raise RuntimeError(f"Failed to calculate hashes: {e}")
            
        return hashes
    
    @property
    def info(self) -> BinaryInfo:
        """Get binary information, loading if necessary"""
        if self._info is None:
            self._info = self.load()
        return self._info
