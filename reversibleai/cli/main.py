"""
Main CLI entry point for ReversibleAI
"""

import argparse
import sys
from pathlib import Path
from typing import Optional
import time

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.theme import Theme

try:
    from loguru import logger
except ImportError:
    import logging as logger
    print("Warning: loguru not available, using standard logging")

from ..core.static_analyzer.analyzer import StaticAnalyzer
from ..core.string_extractor.extractor import StringExtractor
from ..core.hash_patterns.matcher import HashPatternMatcher
from ..core.reports.generator import ReportGenerator
from ..core.exceptions import (
    ReversibleAIError,
    AnalysisError,
    LoaderError,
    ReportError,
    ValidationError
)
from ..core.validation import validate_path
from .plugin_commands import (
    cmd_plugin_list,
    cmd_plugin_info,
    cmd_plugin_enable,
    cmd_plugin_disable,
    cmd_plugin_load,
    cmd_plugin_unload
)
from .interactive import run_interactive

# Rich theme for better colors
custom_theme = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "success": "bold green",
    "header": "bold blue",
    "command": "bold white",
    "option": "italic cyan"
})

# Global console instance
console = Console(theme=custom_theme)


def setup_logging(verbose: bool = False, quiet: bool = False, log_file: Optional[Path] = None) -> None:
    """Setup logging configuration"""
    # Remove default logger
    logger.remove()
    
    # Console logging with Rich integration
    if quiet:
        # No console output
        pass
    elif verbose:
        # Verbose logging with Rich colors
        logger.add(sys.stderr, level="DEBUG", format="<level>{level: <8}</level> | <level>{message}</level>")
    else:
        # Normal logging with Rich colors
        logger.add(sys.stderr, level="INFO", format="<level>{level: <8}</level> | <level>{message}</level>")
    
    # File logging
    if log_file:
        logger.add(log_file, level="DEBUG", format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {message}", rotation="10 MB", retention="5 days")


def create_parser() -> argparse.ArgumentParser:
    """Create command line argument parser with Rich styling"""
    parser = argparse.ArgumentParser(
        prog="reversibleai",
        description=Text("🔍 ReversibleAI - Advanced Static & Dynamic Analysis Framework", style="bold blue"),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s analyze /path/to/binary.exe --output report.html
  %(prog)s analyze /path/to/binary.exe --format json --verbose
  %(prog)s strings /path/to/binary.exe --min-length 8
  %(prog)s hash-scan /path/to/binary.exe --signatures /path/to/signatures.db
        """
    )
    
    # Global options with better help text
    parser.add_argument("-v", "--verbose", action="store_true", 
                       help="Enable verbose output with detailed information")
    parser.add_argument("-q", "--quiet", action="store_true", 
                       help="Suppress console output (silent mode)")
    parser.add_argument("--log-file", type=Path, 
                       help="Log to specified file")
    parser.add_argument("--version", action="version", version="ReversibleAI 0.1.0")
    
    # Subcommands
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Interactive mode
    interactive_parser = subparsers.add_parser("interactive", help="🖥️ Start interactive shell")
    interactive_parser.add_argument("--no-intro", action="store_true", help="Skip intro message")
    
    # Analyze command
    analyze_parser = subparsers.add_parser("analyze", help="🔬 Analyze binary file")
    analyze_parser.add_argument("file", type=Path, help="Binary file to analyze")
    analyze_parser.add_argument("-o", "--output", type=Path, required=True, 
                           help="📄 Output report file")
    analyze_parser.add_argument("-f", "--format", choices=["json", "html", "pdf", "xml"], 
                           default="html", help="📊 Report format")
    analyze_parser.add_argument("--no-functions", action="store_true", 
                           help="⏭️ Skip function analysis")
    analyze_parser.add_argument("--no-strings", action="store_true", 
                           help="📝 Skip string extraction")
    analyze_parser.add_argument("--no-control-flow", action="store_true", 
                           help="🔀 Skip control flow analysis")
    analyze_parser.add_argument("--no-data-flow", action="store_true", 
                           help="💾 Skip data flow analysis")
    analyze_parser.add_argument("--min-string-length", type=int, default=4, 
                           help="📏 Minimum string length")
    analyze_parser.add_argument("--signatures", type=Path, 
                           help="🔍 Signature database file")
    
    # Strings command
    strings_parser = subparsers.add_parser("strings", help="📝 Extract strings from binary")
    strings_parser.add_argument("file", type=Path, help="Binary file to analyze")
    strings_parser.add_argument("-o", "--output", type=Path, 
                           help="📄 Output file (default: stdout)")
    strings_parser.add_argument("-f", "--format", choices=["text", "json", "csv"], 
                           default="text", help="📊 Output format")
    strings_parser.add_argument("--min-length", type=int, default=4,  # Will use config default 
                           help="📏 Minimum string length")
    strings_parser.add_argument("--encoding", choices=["ascii", "utf8", "utf16", "all"], 
                           default="all", help="🔤 String encoding")
    strings_parser.add_argument("--suspicious", action="store_true", 
                           help="⚠️ Only show suspicious strings")
    
    # Hash scan command
    hash_parser = subparsers.add_parser("hash-scan", help="🔍 Scan with hash patterns")
    hash_parser.add_argument("file", type=Path, help="Binary file to scan")
    hash_parser.add_argument("-s", "--signatures", type=Path, required=True, 
                         help="🗂️ Signature database file")
    hash_parser.add_argument("-o", "--output", type=Path, 
                         help="📄 Output file (default: stdout)")
    hash_parser.add_argument("-f", "--format", choices=["text", "json"], 
                         default="text", help="📊 Output format")
    
    # Info command
    info_parser = subparsers.add_parser("info", help="ℹ️ Show binary information")
    info_parser.add_argument("file", type=Path, help="Binary file to analyze")
    info_parser.add_argument("-f", "--format", choices=["text", "json"], 
                        default="text", help="📊 Output format")
    
    # Plugin commands
    plugin_parser = subparsers.add_parser("plugin", help="🔌 Plugin management")
    plugin_subparsers = plugin_parser.add_subparsers(dest="plugin_command", help="Plugin commands")
    
    # Plugin list
    plugin_list_parser = plugin_subparsers.add_parser("list", help="📋 List available plugins")
    plugin_list_parser.add_argument("-f", "--format", choices=["text", "json"], 
                                   default="text", help="📊 Output format")
    
    # Plugin info
    plugin_info_parser = plugin_subparsers.add_parser("info", help="ℹ️ Show plugin information")
    plugin_info_parser.add_argument("plugin_name", help="Plugin name")
    plugin_info_parser.add_argument("-f", "--format", choices=["text", "json"], 
                                   default="text", help="📊 Output format")
    
    # Plugin enable
    plugin_enable_parser = plugin_subparsers.add_parser("enable", help="✅ Enable a plugin")
    plugin_enable_parser.add_argument("plugin_name", help="Plugin name")
    
    # Plugin disable
    plugin_disable_parser = plugin_subparsers.add_parser("disable", help="❌ Disable a plugin")
    plugin_disable_parser.add_argument("plugin_name", help="Plugin name")
    
    # Plugin load
    plugin_load_parser = plugin_subparsers.add_parser("load", help="📥 Load a plugin")
    plugin_load_parser.add_argument("plugin_name", help="Plugin name")
    plugin_load_parser.add_argument("-c", "--config", type=Path, help="Plugin configuration file")
    
    # Plugin unload
    plugin_unload_parser = plugin_subparsers.add_parser("unload", help="📤 Unload a plugin")
    plugin_unload_parser.add_argument("plugin_name", help="Plugin name")
    
    return parser


def cmd_analyze(args) -> int:
    """Handle analyze command with Rich progress and styling"""
    try:
        # Validate file path
        try:
            file_path = validate_path(args.file)
        except (ValidationError, LoaderError) as e:
            console.print(f"[error]❌ {e}[/error]")
            return 1
        
        if not file_path.exists():
            console.print(f"[error]❌ File not found: {file_path}[/error]")
            return 1
        
        # Show header
        console.print(Panel(
            f"[bold blue]🔬 ReversibleAI Analysis[/bold blue]\n"
            f"Analyzing: [cyan]{file_path}[/cyan]",
            title="Analysis Started",
            border_style="blue"
        ))
        
        # Initialize analyzer with progress
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Initializing analyzer...", total=None)
            
            analyzer = StaticAnalyzer(file_path)
            progress.update(task, description="Analyzer initialized")
            
            # Perform analysis with progress
            progress.update(task, description="Starting analysis...")
            start_time = time.time()
            
            result = analyzer.analyze(
                analyze_functions=not args.no_functions,
                analyze_strings=not args.no_strings,
                analyze_control_flow=not args.no_control_flow,
                analyze_data_flow=not args.no_data_flow,
                min_string_length=args.min_string_length
            )
            
            end_time = time.time()
            progress.update(task, description="Analysis completed!")
            
            # Show results summary
            console.print("\n")
            console.print("[bold green]✅ Analysis Complete![/bold green]")
            console.print(f"[info]⏱️ Time taken: {end_time - start_time:.2f} seconds[/info]")
            console.print(f"[info]🔍 Functions found: {len(result.functions)}[/info]")
            console.print(f"[info]📝 Strings found: {len(result.strings)}[/info]")
            console.print(f"[info]🔀 Imports: {len(result.imports)}[/info]")
            console.print(f"[info]📤 Exports: {len(result.exports)}[/info]")
        
        # Add hash pattern matching if signatures provided
        if args.signatures:
            console.print(f"\n[info]🔍 Performing hash pattern matching...[/info]")
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Loading signatures...", total=None)
                
                hash_matcher = HashPatternMatcher(args.signatures)
                progress.update(task, description="Signatures loaded")
                
                # Match file hashes
                progress.update(task, description="Matching file hashes...")
                file_matches = hash_matcher.match_file_hashes(file_path)
                
                # Match function hashes
                progress.update(task, description="Matching function hashes...")
                function_matches = hash_matcher.match_function_hashes(result.functions)
                
                # Match string hashes
                progress.update(task, description="Matching string hashes...")
                string_matches = hash_matcher.match_string_hashes(result.strings)
                
                progress.update(task, description="Hash matching completed!")
                
                # Add hash matches to result
                result.hash_matches = {
                    'file_matches': [match.__dict__ for match in file_matches],
                    'function_matches': [match.__dict__ for match in function_matches],
                    'string_matches': [match.__dict__ for match in string_matches]
                }
                
                # Show hash match summary
                total_matches = len(file_matches) + len(function_matches) + len(string_matches)
                if total_matches > 0:
                    console.print(f"[warning]⚠️ Hash matches found: {total_matches}[/warning]")
                else:
                    console.print(f"[success]✅ No hash matches found[/success]")
        
        # Generate report with progress
        console.print(f"\n[info]📄 Generating report: {args.output}[/info]")
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Generating report...", total=None)
            
            report_generator = ReportGenerator()
            report_generator.set_metadata('file_path', str(file_path))
            report_generator.set_metadata('analysis_options', {
                'functions': not args.no_functions,
                'strings': not args.no_strings,
                'control_flow': not args.no_control_flow,
                'data_flow': not args.no_data_flow,
                'min_string_length': args.min_string_length
            })
            
            success = report_generator.generate_analysis_report(
                analysis_result=result.__dict__,
                output_path=args.output,
                format=args.format
            )
            
            progress.update(task, description="Report generated!")
        
        if success:
            console.print(f"\n[bold green]✅ Analysis complete! Report saved to: {args.output}[/bold green]")
            return 0
        else:
            console.print(f"\n[error]❌ Failed to generate report[/error]")
            return 1
            
    except LoaderError as e:
        console.print(f"[error]❌ Loader error: {e}[/error]")
        return 1
    except AnalysisError as e:
        console.print(f"[error]❌ Analysis error: {e}[/error]")
        return 1
    except ReportError as e:
        console.print(f"[error]❌ Report generation error: {e}[/error]")
        return 1
    except ValidationError as e:
        console.print(f"[error]❌ Validation error: {e}[/error]")
        return 1
    except ReversibleAIError as e:
        console.print(f"[error]❌ Error: {e}[/error]")
        return 1
    except Exception as e:
        console.print(f"[error]❌ Unexpected error: {e}[/error]")
        logger.exception("Unexpected error in analyze command")
        return 1
    finally:
        pass


def cmd_strings(args) -> int:
    """Handle strings command with Rich styling"""
    try:
        # Validate file path
        try:
            file_path = validate_path(args.file)
        except (ValidationError, LoaderError) as e:
            console.print(f"[error]❌ {e}[/error]")
            return 1
        
        if not file_path.exists():
            console.print(f"[error]❌ File not found: {file_path}[/error]")
            return 1
        
        # Show header
        console.print(Panel(
            f"[bold blue]📝 String Extraction[/bold blue]\n"
            f"Extracting from: [cyan]{file_path}[/cyan]",
            title="String Extraction Started",
            border_style="blue"
        ))
        
        # Initialize string extractor with progress
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Initializing extractor...", total=None)
            
            extractor = StringExtractor(file_path)
            progress.update(task, description="Extractor initialized")
            
            # Determine encodings
            encodings = None
            if args.encoding != "all":
                encodings = [args.encoding]
            
            # Extract strings with progress
            progress.update(task, description="Extracting strings...")
            strings = extractor.extract_strings(
                min_length=args.min_length,
                encodings=encodings,
                include_unicode=True
            )
            
            progress.update(task, description="String extraction completed!")
            
            # Filter suspicious strings if requested
            if args.suspicious:
                progress.update(task, description="Filtering suspicious strings...")
                strings = extractor.find_suspicious_strings()
                progress.update(task, description="Filtering completed!")
            
            # Show results summary
            console.print("\n")
            console.print("[bold green]✅ String extraction complete![/bold green]")
            console.print(f"[info]📝 Total strings: {len(strings)}[/info]")
            
            if args.suspicious:
                console.print(f"[warning]⚠️ Suspicious strings: {len(strings)}[/warning]")
        
        # Output results
        if args.output:
            console.print(f"\n[info]📄 Saving to: {args.output}[/info]")
            with open(args.output, 'w', encoding='utf-8') as f:
                if args.format == "json":
                    import json
                    json.dump([s.__dict__ for s in strings], f, indent=2)
                elif args.format == "csv":
                    import csv
                    writer = csv.writer(f)
                    writer.writerow(['value', 'address', 'encoding', 'length', 'entropy'])
                    for s in strings:
                        writer.writerow([s.value, s.address, s.encoding, s.length, s.entropy])
                else:
                    for s in strings:
                        f.write(f"{s.value}\n")
        else:
            if args.format == "json":
                import json
                console.print(json.dumps([s.__dict__ for s in strings], indent=2))
            elif args.format == "csv":
                import csv
                from rich.console import Console
                from rich.table import Table
                
                table = Table(title="Extracted Strings")
                table.add_column("Value", style="cyan")
                table.add_column("Address", style="magenta")
                table.add_column("Encoding", style="green")
                table.add_column("Length", style="blue")
                table.add_column("Entropy", style="yellow")
                
                for s in strings:
                    table.add_row(s.value, s.address, s.encoding, s.length, f"{s.entropy:.2f}")
                
                console.print(table)
            else:
                for s in strings:
                    console.print(f"[info]{s.value}[/info]")
        
        console.print(f"\n[success]✅ String extraction completed![/success]")
        return 0
        
    except LoaderError as e:
        console.print(f"[error]❌ Loader error: {e}[/error]")
        return 1
    except ValidationError as e:
        console.print(f"[error]❌ Validation error: {e}[/error]")
        return 1
    except ReversibleAIError as e:
        console.print(f"[error]❌ Error: {e}[/error]")
        return 1
    except Exception as e:
        console.print(f"[error]❌ Unexpected error: {e}[/error]")
        logger.exception("Unexpected error in strings command")
        return 1


def cmd_hash_scan(args) -> int:
    """Handle hash-scan command"""
    try:
        if not args.file.exists():
            logger.error(f"File not found: {args.file}")
            return 1
        
        if not args.signatures.exists():
            logger.error(f"Signature database not found: {args.signatures}")
            return 1
        
        logger.info(f"Scanning {args.file} with signatures from {args.signatures}")
        
        # Initialize hash pattern matcher
        matcher = HashPatternMatcher(args.signatures)
        
        # Load binary for analysis
        from ..core.loader.factory import LoaderFactory
        loader = LoaderFactory.create_loader(args.file)
        binary_info = loader.info
        
        # Perform various matches
        matches = {}
        
        # File hash matches
        file_matches = matcher.match_file_hashes(args.file)
        if file_matches:
            matches['file'] = [match.__dict__ for match in file_matches]
        
        # String hash matches
        strings = loader.get_strings()
        if strings:
            string_matches = matcher.match_string_hashes(strings)
            if string_matches:
                matches['strings'] = [match.__dict__ for match in string_matches]
        
        # Import hash matches
        import_matches = matcher.match_import_hashes(binary_info.imports)
        if import_matches:
            matches['imports'] = [match.__dict__ for match in import_matches]
        
        # Output results
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                if args.format == "json":
                    import json
                    json.dump(matches, f, indent=2)
                else:
                    for category, category_matches in matches.items():
                        f.write(f"{category.upper()} MATCHES:\n")
                        for match in category_matches:
                            f.write(f"  {match['pattern_name']}: {match['description']}\n")
                        f.write("\n")
        else:
            if args.format == "json":
                import json
                print(json.dumps(matches, indent=2))
            else:
                for category, category_matches in matches.items():
                    print(f"{category.upper()} MATCHES:")
                    for match in category_matches:
                        print(f"  {match['pattern_name']}: {match['description']}")
                    print()
        
        total_matches = sum(len(matches.get(cat, [])) for cat in matches)
        logger.info(f"Scan complete. Found {total_matches} matches")
        return 0
        
    except LoaderError as e:
        logger.error(f"Loader error: {e}")
        return 1
    except ValidationError as e:
        logger.error(f"Validation error: {e}")
        return 1
    except ReversibleAIError as e:
        logger.error(f"Error: {e}")
        return 1
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        logger.exception("Unexpected error in hash-scan command")
        return 1


def cmd_info(args) -> int:
    """Handle info command"""
    try:
        if not args.file.exists():
            logger.error(f"File not found: {args.file}")
            return 1
        
        # Load binary information
        from ..core.loader.factory import LoaderFactory
        loader = LoaderFactory.create_loader(args.file)
        binary_info = loader.info
        
        # Output results
        if args.format == "json":
            import json
            print(json.dumps(binary_info.__dict__, indent=2, default=str))
        else:
            print(f"File: {binary_info.path}")
            print(f"Type: {binary_info.file_type.value}")
            print(f"Architecture: {binary_info.architecture} {binary_info.bits}-bit")
            print(f"Endianness: {binary_info.endianness}")
            print(f"Size: {binary_info.size} bytes")
            print(f"Entry Point: {hex(binary_info.entry_point)}")
            print(f"Image Base: {hex(binary_info.image_base)}")
            print(f"MD5: {binary_info.md5}")
            print(f"SHA1: {binary_info.sha1}")
            print(f"SHA256: {binary_info.sha256}")
            print(f"Sections: {len(binary_info.sections)}")
            print(f"Imports: {len(binary_info.imports)}")
            print(f"Exports: {len(binary_info.exports)}")
        
        return 0
        
    except LoaderError as e:
        logger.error(f"Loader error: {e}")
        return 1
    except ValidationError as e:
        logger.error(f"Validation error: {e}")
        return 1
    except ReversibleAIError as e:
        logger.error(f"Error: {e}")
        return 1
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        logger.exception("Unexpected error in info command")
        return 1


def main() -> int:
    """Main entry point with Rich styling"""
    parser = create_parser()
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose, args.quiet, args.log_file)
    
    # Handle commands with Rich styling
    if args.command == "analyze":
        return cmd_analyze(args)
    elif args.command == "strings":
        return cmd_strings(args)
    elif args.command == "hash-scan":
        return cmd_hash_scan(args)
    elif args.command == "info":
        return cmd_info(args)
    elif args.command == "plugin":
        if args.plugin_command == "list":
            return cmd_plugin_list(args)
        elif args.plugin_command == "info":
            return cmd_plugin_info(args)
        elif args.plugin_command == "enable":
            return cmd_plugin_enable(args)
        elif args.plugin_command == "disable":
            return cmd_plugin_disable(args)
        elif args.plugin_command == "load":
            return cmd_plugin_load(args)
        elif args.plugin_command == "unload":
            return cmd_plugin_unload(args)
        else:
            plugin_parser.print_help()
            return 1
    elif args.command == "interactive":
        return run_interactive()
    else:
        # Show help with Rich styling
        console.print(Panel(
            "[bold blue]🔍 ReversibleAI - Advanced Static & Dynamic Analysis Framework[/bold blue]\n\n"
            "[command]Available commands:[/command]\n"
            "  [info]analyze[/info]     - Analyze binary file\n"
            "  [info]strings[/info]     - Extract strings from binary\n"
            "  [info]hash-scan[/info]  - Scan with hash patterns\n"
            "  [info]info[/info]        - Show binary information\n\n"
            "[dim]Use --help for more information about a command.[/dim]",
            title="ReversibleAI",
            border_style="blue"
        ))
        return 1


if __name__ == "__main__":
    sys.exit(main())
