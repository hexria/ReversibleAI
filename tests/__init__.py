"""
Test suite for ReversibleAI framework
"""

import sys
from pathlib import Path

# Add project root to Python path for testing
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from .unit import *
from .integration import *

__all__ = [
    "TestLoader",
    "TestStaticAnalyzer", 
    "TestStringExtractor",
    "TestHashPatternMatcher",
    "TestRuntimeEmulator",
    "TestPlugins",
    "TestCLI",
    "sample_pe_file",
    "sample_elf_file",
    "sample_macho_file",
    "temp_directory"
]
