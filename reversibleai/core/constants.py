"""
Constants for ReversibleAI framework
"""

from enum import Enum


class AnalysisLevel(Enum):
    """Analysis depth levels"""
    BASIC = "basic"
    STANDARD = "standard"
    DEEP = "deep"
    COMPREHENSIVE = "comprehensive"


class StringEncoding(Enum):
    """Supported string encodings"""
    ASCII = "ascii"
    UTF8 = "utf-8"
    UTF16LE = "utf-16le"
    UTF16BE = "utf-16be"
    LATIN1 = "latin1"


class ReportFormat(Enum):
    """Supported report formats"""
    JSON = "json"
    HTML = "html"
    PDF = "pdf"
    XML = "xml"
    TEXT = "text"


class Architecture(Enum):
    """Supported architectures"""
    X86 = "x86"
    X86_64 = "x86_64"
    ARM = "arm"
    ARM64 = "aarch64"
    MIPS = "mips"
    MIPS64 = "mips64"
    PPC = "ppc"
    PPC64 = "ppc64"
    RISCV = "riscv"
    RISCV64 = "riscv64"
    SPARC = "sparc"
    SPARC64 = "sparc64"


# Default values
DEFAULT_MIN_STRING_LENGTH = 4
DEFAULT_MAX_STRING_LENGTH = 10000
DEFAULT_ANALYSIS_TIMEOUT = 300
DEFAULT_MAX_MEMORY_MB = 2048

# Cache settings
CACHE_MAX_SIZE = 1024
CACHE_TTL_SECONDS = 3600

# File size limits
MAX_FILE_SIZE_MB = 1000  # 1GB
MAX_STRING_LENGTH = 100000

# Suspicious string keywords
SUSPICIOUS_KEYWORDS = [
    'password', 'passwd', 'secret', 'key', 'crypto', 'encrypt',
    'decrypt', 'shell', 'cmd', 'powershell', 'admin', 'root', 'hack',
    'http://', 'https://', 'ftp://', 'tcp://', 'udp://',
    'createprocess', 'virtualalloc', 'writeprocessmemory',
    'createremotethread', 'setwindowshookex', 'regsetvalueex',
    'socket', 'connect', 'bind', 'listen', 'accept'
]

# Function prologue patterns (architecture-specific)
FUNCTION_PROLOGUES = {
    'x86': [
        b'\x55',  # push ebp
        b'\x89\xe5',  # mov ebp, esp
        b'\x55\x8b\xec',  # push ebp; mov ebp, esp
    ],
    'x86_64': [
        b'\x55',  # push rbp
        b'\x48\x89\xe5',  # mov rbp, rsp
        b'\x40\x55',  # push rbp
        b'\x48\x83\xec',  # sub rsp, imm
    ],
    'arm': [
        b'\x2d\xe9',  # push {fp, lr}
        b'\x10\xb5',  # push {r4, lr}
    ],
    'aarch64': [
        b'\xfd\x7b',  # stp x29, x30, [sp, #-imm]!
        b'\xff\x83',  # stp x29, x30, [sp, #-imm]!
    ],
}

# Magic bytes for binary formats
MAGIC_BYTES = {
    'PE': b'MZ',
    'ELF': b'\x7fELF',
    'MACHO_32BE': b'\xfe\xed\xfa\xce',
    'MACHO_64BE': b'\xfe\xed\xfa\xcf',
    'MACHO_32LE': b'\xce\xfa\xed\xfe',
    'MACHO_64LE': b'\xcf\xfa\xed\xfe',
}
