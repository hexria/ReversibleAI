# ReversibleAI

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python versions](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Development Status](https://img.shields.io/badge/status-alpha-orange.svg)](https://github.com/reversibleai/reversibleai)

**ReversibleAI** - Advanced Static & Dynamic Analysis Framework for Malware Analysis and Reverse Engineering

A modern, modular Python framework for binary analysis that bridges the gap between traditional reverse engineering tools and contemporary analysis techniques.

> **⚠️ Development Status**: This project is currently in **Alpha** stage. Some features may be incomplete or experimental. We recommend installing from source for the latest updates.

## Installation

### Prerequisites

- Python 3.11 or higher
- pip and setuptools

### Install from Source

Since ReversibleAI is currently in active development, installation from source is recommended:

```bash
# Clone the repository
git clone https://github.com/reversibleai/reversibleai.git
cd reversibleai

# Install in development mode
pip install -e .

# Or install with all optional dependencies
pip install -e ".[dev]"
```

### Optional Dependencies

For specific features, you can install optional dependencies:

```bash
# For IDA Pro integration
pip install -e ".[ida]"

# For Ghidra integration
pip install -e ".[ghidra]"

# For Radare2 integration
pip install -e ".[radare2]"

# For development tools
pip install -e ".[dev]"
```

## Quick Start

### Command Line Usage

**Analyze a binary file:**
```bash
reversibleai analyze malware.exe --output report.html
```

**Extract strings:**
```bash
reversibleai strings malware.exe --min-length 8 --suspicious
```

**Get binary information:**
```bash
reversibleai info malware.exe
```

**Scan with hash patterns:**
```bash
reversibleai hash-scan malware.exe --signatures signatures.db
```

**Interactive mode:**
```bash
reversibleai interactive
```

### Python API

**Basic Analysis:**
```python
from reversibleai.core.static_analyzer.analyzer import StaticAnalyzer
from pathlib import Path

# Initialize analyzer
analyzer = StaticAnalyzer(Path("malware.exe"))

# Perform analysis
result = analyzer.analyze()

print(f"Found {len(result.functions)} functions")
print(f"Found {len(result.strings)} strings")
print(f"Found {len(result.imports)} imports")
```

**String Extraction:**
```python
from reversibleai.core.string_extractor.extractor import StringExtractor
from pathlib import Path

extractor = StringExtractor(Path("malware.exe"))
strings = extractor.extract_strings(min_length=8)

for string_info in strings:
    print(f"{string_info.value} @ {hex(string_info.address)}")
```

**Generate Report:**
```python
from reversibleai.core.static_analyzer.analyzer import StaticAnalyzer
from reversibleai.core.reports.generator import ReportGenerator
from pathlib import Path

analyzer = StaticAnalyzer(Path("malware.exe"))
result = analyzer.analyze()

report_gen = ReportGenerator()
report_gen.generate_analysis_report(
    analysis_result=result.__dict__,
    output_path=Path("report.html"),
    format="html"
)
```

**Binary Information:**
```python
from reversibleai.core.loader.factory import LoaderFactory
from pathlib import Path

loader = LoaderFactory.create_loader(Path("malware.exe"))
binary_info = loader.info

print(f"File type: {binary_info.file_type.value}")
print(f"Architecture: {binary_info.architecture} {binary_info.bits}-bit")
print(f"Entry point: {hex(binary_info.entry_point)}")
print(f"SHA256: {binary_info.sha256}")
```

## Features

### Core Capabilities

- **Multi-format Support**: PE, ELF, Mach-O binary loading and parsing
- **Static Analysis**: 
  - Function detection and analysis
  - Control flow graph (CFG) construction
  - Data flow analysis
  - String extraction with multiple encodings (ASCII, UTF-8, UTF-16)
  - Disassembly with Capstone engine
- **String Analysis**:
  - Entropy calculation
  - Suspicious string detection
  - URL, IP address, registry key, and file path extraction
- **Hash Pattern Matching**: File, function, string, and import hash matching
- **Report Generation**: HTML, JSON, XML formats (PDF support is experimental)
- **Runtime Emulation**: Basic emulation support with Unicorn engine (experimental)

### Plugin System

- Plugin architecture for extending functionality
- Integration support for IDA Pro, Ghidra, and Radare2 (requires optional dependencies)

### Supported Architectures

- x86, x86_64
- ARM, ARM64
- MIPS, MIPS64
- PowerPC, PowerPC64
- RISC-V, RISC-V64
- SPARC, SPARC64

## Requirements

- Python 3.11 or higher
- Core dependencies (automatically installed):
  - LIEF (binary parsing)
  - Capstone (disassembly)
  - NetworkX (graph analysis)
  - Rich (terminal UI)
  - Loguru (logging)
  - And more (see `requirements.txt`)

## Known Limitations

- **PDF Report Generation**: Currently experimental/placeholder implementation
- **YARA Integration**: Hash-based pattern matching is implemented, full YARA integration is planned
- **Dynamic Analysis**: Emulation features are in early development
- **Plugin Integrations**: IDA, Ghidra, and Radare2 plugins require the respective tools to be installed

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](LICENSE) file for details

## Support

- **Issues**: [GitHub Issues](https://github.com/reversibleai/reversibleai/issues)
- **Email**: info@reversibleai.com

## Development Status

This project is in **Alpha** stage (v0.1.0). The core functionality is implemented and tested, but some advanced features may be incomplete or experimental. We're actively working on improving stability and adding new features.

For the latest updates and bug fixes, please install from source and check the [CHANGELOG.md](CHANGELOG.md).
