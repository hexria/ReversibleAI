# ReversibleAI

**ReversibleAI** - Advanced Static & Dynamic Analysis Framework for Malware Analysis and Reverse Engineering

A modern, modular Python framework for binary analysis that bridges the gap between traditional reverse engineering tools and contemporary analysis techniques.

## Installation

### Quick Install

```bash
pip install reversibleai
```

### From Source

```bash
git clone https://github.com/reversibleai/reversibleai.git
cd reversibleai
pip install -e .
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

### Python API

**Basic Analysis:**
```python
from reversibleai import StaticAnalyzer

# Initialize analyzer
analyzer = StaticAnalyzer("malware.exe")

# Perform analysis
result = analyzer.analyze()

print(f"Found {len(result.functions)} functions")
print(f"Found {len(result.strings)} strings")
```

**String Extraction:**
```python
from reversibleai import StringExtractor

extractor = StringExtractor("malware.exe")
strings = extractor.extract_strings(min_length=8)

for string_info in strings:
    print(f"{string_info.value} @ {hex(string_info.address)}")
```

**Generate Report:**
```python
from reversibleai import StaticAnalyzer, ReportGenerator

analyzer = StaticAnalyzer("malware.exe")
result = analyzer.analyze()

report_gen = ReportGenerator()
report_gen.generate_analysis_report(
    analysis_result=result.__dict__,
    output_path="report.html",
    format="html"
)
```

## Features

- **Multi-format Support**: PE, ELF, Mach-O binaries
- **Static Analysis**: Function detection, CFG construction, string extraction
- **Dynamic Analysis**: Runtime emulation with Unicorn engine
- **Pattern Matching**: Hash-based signature matching with YARA integration
- **Report Generation**: HTML, JSON, PDF, XML formats
- **Plugin System**: Integration with IDA Pro, Ghidra, and Radare2

## Requirements

- Python 3.11 or higher
- See `requirements.txt` for dependencies

## Documentation

For detailed documentation, visit: https://reversibleai.readthedocs.io

## License

MIT License - see LICENSE file for details

## Contributing

Contributions are welcome! Please see CONTRIBUTING.md for guidelines.

## Support

- **Issues**: https://github.com/reversibleai/reversibleai/issues
- **Email**: info@reversibleai.com
