"""
Factory for creating appropriate loaders based on file type
"""

from pathlib import Path
from typing import Optional, Union

import lief
from loguru import logger

from ..utils.cache import cache_file_hash
from ..validation import validate_path
from ..exceptions import LoaderError
from ..constants import MAGIC_BYTES
from .base import BaseLoader, BinaryType
from .pe_loader import PELoader
from .elf_loader import ELFLoader
from .macho_loader import MachOLoader


class LoaderFactory:
    """Factory class for creating appropriate binary loaders"""
    
    @staticmethod
    def create_loader(file_path: Union[str, Path]) -> BaseLoader:
        """
        Create appropriate loader based on file type
        
        Args:
            file_path: Path to the binary file
            
        Returns:
            Appropriate loader instance
            
        Raises:
            ValueError: If file type is not supported
            FileNotFoundError: If file doesn't exist
        """
        # Validate path
        try:
            path = validate_path(file_path)
        except Exception as e:
            raise LoaderError(f"Invalid file path: {file_path}", file_path=str(file_path)) from e
        
        if not path.exists():
            raise LoaderError(f"File not found: {path}", file_path=str(path))
        
        # Use LIEF to detect file type
        try:
            binary = lief.parse(str(path))
            if binary is None:
                raise LoaderError(f"Cannot parse binary file: {path}", file_path=str(path), file_type="unknown")
            
            if isinstance(binary, lief.PE.Binary):
                logger.debug(f"Detected PE file: {path}")
                return PELoader(path)
            elif isinstance(binary, lief.ELF.Binary):
                logger.debug(f"Detected ELF file: {path}")
                return ELFLoader(path)
            elif isinstance(binary, lief.MachO.Binary):
                logger.debug(f"Detected Mach-O file: {path}")
                return MachOLoader(path)
            else:
                raise LoaderError(f"Unsupported binary format: {path}", file_path=str(path), file_type="unknown")
                
        except LoaderError:
            raise
        except Exception as e:
            logger.error(f"Failed to create loader for {path}: {e}")
            raise LoaderError(f"Failed to create loader: {e}", file_path=str(path)) from e
    
    @staticmethod
    @cache_file_hash
    def detect_binary_type(file_path: Union[str, Path]) -> BinaryType:
        """
        Detect binary type without creating a full loader
        
        Args:
            file_path: Path to the binary file
            
        Returns:
            Binary type enum
        """
        path = Path(file_path)
        
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")
        
        try:
            binary = lief.parse(str(path))
            if binary is None:
                return BinaryType.UNKNOWN
            
            if isinstance(binary, lief.PE.Binary):
                return BinaryType.PE
            elif isinstance(binary, lief.ELF.Binary):
                return BinaryType.ELF
            elif isinstance(binary, lief.MachO.Binary):
                return BinaryType.MACHO
            else:
                return BinaryType.UNKNOWN
                
        except Exception as e:
            logger.warning(f"Failed to detect binary type for {path}: {e}")
            return BinaryType.UNKNOWN
    
    @staticmethod
    def get_supported_extensions() -> list[str]:
        """Get list of supported file extensions"""
        return [
            ".exe", ".dll", ".sys", ".drv",  # PE
            ".elf", ".so", ".o", ".a",       # ELF
            ".dylib", ".bundle",             # Mach-O
        ]
    
    @staticmethod
    @cache_file_hash
    def is_supported_file(file_path: Union[str, Path]) -> bool:
        """
        Check if file is supported by checking extension and magic bytes
        
        Args:
            file_path: Path to the file
            
        Returns:
            True if file is supported, False otherwise
        """
        path = Path(file_path)
        
        # Check extension
        if path.suffix.lower() in LoaderFactory.get_supported_extensions():
            return True
        
        # Check magic bytes
        try:
            with open(path, "rb") as f:
                magic = f.read(4)
            
            # Check magic bytes
            if magic.startswith(MAGIC_BYTES['PE']):
                return True
            
            if magic.startswith(MAGIC_BYTES['ELF']):
                return True
            
            # Mach-O magic bytes
            macho_magics = [
                MAGIC_BYTES['MACHO_32BE'],
                MAGIC_BYTES['MACHO_64BE'],
                MAGIC_BYTES['MACHO_32LE'],
                MAGIC_BYTES['MACHO_64LE']
            ]
            if magic in macho_magics:
                return True
            
        except Exception:
            pass
        
        return False
