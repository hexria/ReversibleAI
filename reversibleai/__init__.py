"""
ReversibleAI - Advanced Static & Dynamic Analysis Framework

A modular Python framework for malware analysis and reverse engineering
with support for IDA, Ghidra, and Radare2.
"""

__version__ = "0.1.0"
__author__ = "ReversibleAI Team"
__email__ = "info@reversibleai.com"

from .core import *
from .plugins import *
from .cli import main

__all__ = [
    "__version__",
    "__author__", 
    "__email__",
    "main"
]
