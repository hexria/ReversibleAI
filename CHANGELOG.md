# Changelog

All notable changes to ReversibleAI will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-01-06

### Added
- Initial release of ReversibleAI framework
- Multi-format binary loading (PE, ELF, Mach-O)
- Static analysis capabilities:
  - Function detection and analysis
  - Control flow graph construction
  - Data flow analysis
  - String extraction with multiple encodings
  - Disassembly with Capstone engine
- Dynamic analysis:
  - Runtime emulation with Unicorn engine
  - Custom hooking system
  - Memory analysis
- Hash pattern matching and signature database
- Report generation (HTML, JSON, PDF, XML)
- Plugin system for IDA Pro, Ghidra, and Radare2
- Command-line interface with Rich UI
- Interactive shell mode
- Configuration management (YAML config files, environment variables)
- Comprehensive test suite
- Security features (path traversal protection, input validation)
- Performance optimizations (caching, parallel processing)
- Plugin discovery and management system

### Features
- Support for x86, x86_64, ARM, ARM64, MIPS, PowerPC, RISC-V, SPARC architectures
- Advanced string extraction with entropy calculation
- Suspicious string detection
- Function call graph analysis
- Basic block identification
- API annotation system
- Persistent annotation database

### Security
- Input validation and sanitization
- Path traversal protection
- File permission validation
- Secure file handling

### Performance
- LRU caching for frequently accessed data
- Parallel processing utilities
- Optimized binary parsing

### Documentation
- Comprehensive README
- API documentation
- Usage examples
