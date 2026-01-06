# ReversibleAI

[![codecov](https://codecov.io/gh/reversibleai/reversibleai/branch/main/graph/badge.svg)](https://codecov.io/gh/reversibleai/reversibleai)
[![PyPI version](https://badge.fury.io/py/reversibleai.svg)](https://badge.fury.io/py/reversibleai)
[![Python versions](https://img.shields.io/pypi/pyversions/reversibleai.svg)](https://pypi.org/project/reversibleai/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**ReversibleAI** - Advanced Static & Dynamic Analysis Framework for Malware Analysis and Reverse Engineering

A modern, modular Python framework for binary analysis that bridges the gap between traditional reverse engineering tools and contemporary analysis techniques. Built for security researchers, malware analysts, and reverse engineers.

## ✨ Features

### 🔍 Static Analysis
- **Multi-format Binary Loading**: Support for PE, ELF, Mach-O binaries
- **Advanced Disassembly**: Capstone-based disassembly with multiple architectures
- **Function Analysis**: Automatic function detection, CFG construction, and complexity analysis
- **String Extraction**: Advanced string extraction with decoding and obfuscation detection
- **Pattern Matching**: Hash-based signature matching with YARA integration
- **Data Flow Analysis**: Comprehensive data flow and dependency tracking

### 🚀 Dynamic Analysis
- **Runtime Emulation**: Unicorn-based emulation with hooking support
- **Memory Analysis**: Memory inspection and manipulation during emulation
- **Execution Tracing**: Detailed execution trace and performance metrics
- **Custom Hooks**: Extensible hooking system for custom analysis

### 🔌 Tool Integration
- **IDA Pro**: Full integration with IDA Pro databases and analysis
- **Ghidra**: Native Ghidra plugin support with decompiler integration
- **Radare2**: Complete r2pipe integration for command-line workflows

### 📊 Reporting & Visualization
- **Multiple Formats**: HTML, JSON, PDF, XML report generation
- **Interactive Reports**: Rich HTML reports with graphs and visualizations
- **Export Capabilities**: Export analysis data to various formats
- **Annotation Support**: Persistent annotations and comments

## 🛠️ Installation

### From PyPI (Recommended)
```bash
pip install reversibleai
```

### From Source
```bash
git clone https://github.com/reversibleai/reversibleai.git
cd reversibleai
pip install -e .
```

### Development Installation
```bash
git clone https://github.com/reversibleai/reversibleai.git
cd reversibleai
pip install -e .[dev]
pre-commit install
```

## 🚀 Quick Start

### Command Line Interface

```bash
# Analyze a binary file
reversibleai analyze /path/to/binary.exe --output report.html

# Extract strings
reversibleai strings /path/to/binary.exe --min-length 8 --suspicious

# Get binary information
reversibleai info /path/to/binary.exe

# Scan with hash patterns
reversibleai hash-scan /path/to/binary.exe --signatures signatures.db
```

### Python API

```python
from reversibleai import StaticAnalyzer, ReportGenerator

# Initialize analyzer
analyzer = StaticAnalyzer("/path/to/binary.exe")

# Perform comprehensive analysis
result = analyzer.analyze(
    analyze_functions=True,
    analyze_strings=True,
    analyze_control_flow=True,
    analyze_data_flow=True
)

# Generate report
report_gen = ReportGenerator()
report_gen.generate_analysis_report(result, "report.html", "html")
```

### Plugin Integration

```python
from reversibleai.plugins import IDAPlugin

# Initialize IDA plugin
plugin = IDAPlugin()
plugin.initialize(ida_api_instance)

# Perform analysis
result = plugin.analyze(current_database)
```

## 📋 Supported Architectures

- **x86** (32-bit and 64-bit)
- **ARM** (32-bit and 64-bit)
- **MIPS** (32-bit and 64-bit)
- **PowerPC** (32-bit and 64-bit)
- **RISC-V** (32-bit and 64-bit)
- **SPARC** (32-bit and 64-bit)

## 📚 Documentation

### Core Modules

- **[Binary Loader](docs/loader.md)**: Multi-format binary loading and parsing
- **[Static Analyzer](docs/static_analyzer.md)**: Comprehensive static analysis capabilities
- **[String Extractor](docs/string_extractor.md)**: Advanced string extraction and decoding
- **[Hash Patterns](docs/hash_patterns.md)**: Signature matching and pattern detection
- **[Runtime Emulator](docs/runtime_emulator.md)**: Dynamic analysis and emulation
- **[Annotations](docs/annotations.md)**: Function and code annotation system
- **[Reports](docs/reports.md)**: Report generation and export

### Plugin Development

- **[Plugin Architecture](docs/plugins.md)**: Plugin development guide
- **[IDA Integration](docs/plugins/ida.md)**: IDA Pro plugin development
- **[Ghidra Integration](docs/plugins/ghidra.md)**: Ghidra plugin development
- **[Radare2 Integration](docs/plugins/radare2.md)**: Radare2 plugin development

### API Reference

- **[CLI Reference](docs/cli.md)**: Complete command-line interface reference
- **[Python API](docs/api.md)**: Python API documentation
- **[Configuration](docs/configuration.md)**: Configuration options and settings

## 🔧 Configuration

### Environment Variables

```bash
export REVERSIBLEAI_LOG_LEVEL=INFO
export REVERSIBLEAI_CONFIG_PATH=/path/to/config.yaml
export REVERSIBLEAI_PLUGIN_PATH=/path/to/plugins
```

### Configuration File

```yaml
# ~/.reversibleai/config.yaml
logging:
  level: INFO
  file: ~/.reversibleai/logs/reversibleai.log
  format: json

analysis:
  default_timeout: 300
  max_memory: 2048
  enable_emulation: true

plugins:
  auto_load: true
  search_paths:
    - ~/.reversibleai/plugins
    - /usr/local/lib/reversibleai/plugins
```

## 🧪 Testing

### Run Tests

```bash
# Run all tests
pytest

# Run specific test categories
pytest tests/unit/
pytest tests/integration/

# Run with coverage
pytest --cov=reversibleai --cov-report=html

# Run performance tests
pytest tests/performance/ -m slow
```

### Test Coverage

```bash
# Generate coverage report
pytest --cov=reversibleai --cov-report=html

# View coverage in browser
open htmlcov/index.html
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass (`pytest`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

### Code Style

We use several tools to maintain code quality:

- **Black**: Code formatting
- **isort**: Import sorting
- **flake8**: Linting
- **mypy**: Type checking
- **pre-commit**: Git hooks

These are automatically enforced via CI/CD pipeline.

## 📊 Examples

### Basic Analysis

```python
from reversibleai import StaticAnalyzer

# Analyze a PE file
analyzer = StaticAnalyzer("malware.exe")
result = analyzer.analyze()

print(f"Found {len(result.functions)} functions")
print(f"Found {len(result.strings)} strings")
print(f"Risk level: {result.metadata['risk_level']}")
```

### Custom Analysis Pipeline

```python
from reversibleai import StaticAnalyzer, HashPatternMatcher, ReportGenerator

# Initialize components
analyzer = StaticAnalyzer("sample.exe")
hash_matcher = HashPatternMatcher("signatures.db")
report_gen = ReportGenerator()

# Perform analysis
result = analyzer.analyze()

# Match against signatures
matches = hash_matcher.match_file_hashes("sample.exe")
result.hash_matches = matches

# Generate detailed report
report_gen.generate_analysis_report(result, "analysis_report.html")
```

### Plugin Development

```python
from reversibleai.plugins import AnalysisPlugin, PluginInfo

class CustomPlugin(AnalysisPlugin):
    @property
    def info(self):
        return PluginInfo(
            name="custom_analyzer",
            version="1.0.0",
            description="Custom analysis plugin",
            author="Your Name",
            supported_tools=["ida", "ghidra"],
            supported_architectures=["x86", "x86_64"],
            capabilities=["static_analysis"]
        )
    
    def analyze(self, target, options=None):
        # Custom analysis logic
        return {"custom_result": "analysis_complete"}
```

## 🔌 Plugin Ecosystem

### Available Plugins

- **[reversibleai-ml](https://github.com/reversibleai/reversibleai-ml)**: Machine learning based analysis
- **[reversibleai-network](https://github.com/reversibleai/reversibleai-network)**: Network analysis plugins
- **[reversibleai-yara](https://github.com/reversibleai/reversibleai-yara)**: Advanced YARA integration
- **[reversibleai-ida](https://github.com/reversibleai/reversibleai-ida)**: Enhanced IDA Pro integration

### Installing Plugins

```bash
# Install from PyPI
pip install reversibleai-ml

# Install from source
pip install git+https://github.com/reversibleai/reversibleai-ml.git
```

## 📈 Performance

### Benchmarks

| Binary Type | Size | Analysis Time | Memory Usage |
|--------------|-------|---------------|--------------|
| PE (32-bit) | 1MB   | 2.3s         | 45MB         |
| ELF (64-bit) | 2MB   | 3.1s         | 67MB         |
| Mach-O (64-bit) | 5MB   | 4.7s         | 89MB         |

### Optimization Tips

- Use `--no-functions` for string-only analysis
- Limit string length with `--min-string-length`
- Disable emulation for large files
- Use appropriate analysis level

## 🛡️ Security

### Security Features

- **Sandboxed Execution**: Emulation runs in isolated environment
- **Memory Limits**: Configurable memory usage limits
- **Timeout Protection**: Automatic timeout for long-running operations
- **Input Validation**: Comprehensive input validation and sanitization

### Security Scanning

```bash
# Security scan of the framework itself
bandit -r reversibleai/
safety check

# Scan dependencies
pip-audit
```

## 🐛 Troubleshooting

### Common Issues

**Import Error: No module named 'lief'**
```bash
pip install lief
```

**Emulation Failed: Unsupported Architecture**
```bash
# Check supported architectures
reversibleai --help
```

**Plugin Loading Failed**
```bash
# Check plugin compatibility
reversibleai plugin list
```

### Debug Mode

```bash
# Enable debug logging
export REVERSIBLEAI_LOG_LEVEL=DEBUG
reversibleai analyze sample.exe --verbose
```

### Getting Help

- **Documentation**: [https://reversibleai.readthedocs.io](https://reversibleai.readthedocs.io)
- **Issues**: [GitHub Issues](https://github.com/reversibleai/reversibleai/issues)
- **Discussions**: [GitHub Discussions](https://github.com/reversibleai/reversibleai/discussions)
- **Discord**: [ReversibleAI Discord](https://discord.gg/reversibleai)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [LIEF](https://lief.quarkslab.com/) - Binary parsing library
- [Capstone](https://www.capstone-engine.org/) - Disassembly framework
- [Unicorn](https://www.unicorn-engine.org/) - CPU emulation framework
- [YARA](https://virustotal.github.io/yara/) - Pattern matching
- [Loguru](https://github.com/Delgan/loguru) - Logging library

## 📞 Contact

- **Website**: [https://reversibleai.com](https://reversibleai.com)
- **Email**: info@reversibleai.com
- **Twitter**: [@ReversibleAI](https://twitter.com/ReversibleAI)
- **Mastodon**: [@reversibleai@infosec.exchange](https://infosec.exchange/@reversibleai)

---

**ReversibleAI** - Empowering reverse engineers with modern analysis tools. 🚀
