"""
Main CLI entry point for ReversibleAI
"""

import argparse
import sys
from pathlib import Path
from typing import Optional

from loguru import logger

from ..core.static_analyzer.analyzer import StaticAnalyzer
from ..core.string_extractor.extractor import StringExtractor
from ..core.hash_patterns.matcher import HashPatternMatcher
from ..core.reports.generator import ReportGenerator


def setup_logging(verbose: bool = False, quiet: bool = False, log_file: Optional[Path] = None) -> None:
    """Setup logging configuration"""
    # Remove default logger
    logger.remove()
    
    # Console logging
    if quiet:
        # No console output
        pass
    elif verbose:
        # Verbose logging
        logger.add(sys.stderr, level="DEBUG", format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>")
    else:
        # Normal logging
        logger.add(sys.stderr, level="INFO", format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>")
    
    # File logging
    if log_file:
        logger.add(log_file, level="DEBUG", format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}", rotation="10 MB", retention="5 days")


def create_parser() -> argparse.ArgumentParser:
    """Create command line argument parser"""
    parser = argparse.ArgumentParser(
        prog="reversibleai",
        description="ReversibleAI - Advanced Static & Dynamic Analysis Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s analyze /path/to/binary.exe --output report.html
  %(prog)s analyze /path/to/binary.exe --format json --verbose
  %(prog)s strings /path/to/binary.exe --min-length 8
  %(prog)s hash-scan /path/to/binary.exe --signatures /path/to/signatures.db
        """
    )
    
    # Global options
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress console output")
    parser.add_argument("--log-file", type=Path, help="Log to specified file")
    parser.add_argument("--version", action="version", version="ReversibleAI 0.1.0")
    
    # Subcommands
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze binary file")
    analyze_parser.add_argument("file", type=Path, help="Binary file to analyze")
    analyze_parser.add_argument("-o", "--output", type=Path, required=True, help="Output report file")
    analyze_parser.add_argument("-f", "--format", choices=["json", "html", "pdf", "xml"], default="html", help="Report format")
    analyze_parser.add_argument("--no-functions", action="store_true", help="Skip function analysis")
    analyze_parser.add_argument("--no-strings", action="store_true", help="Skip string extraction")
    analyze_parser.add_argument("--no-control-flow", action="store_true", help="Skip control flow analysis")
    analyze_parser.add_argument("--no-data-flow", action="store_true", help="Skip data flow analysis")
    analyze_parser.add_argument("--min-string-length", type=int, default=4, help="Minimum string length")
    analyze_parser.add_argument("--signatures", type=Path, help="Signature database file")
    
    # Strings command
    strings_parser = subparsers.add_parser("strings", help="Extract strings from binary")
    strings_parser.add_argument("file", type=Path, help="Binary file to analyze")
    strings_parser.add_argument("-o", "--output", type=Path, help="Output file (default: stdout)")
    strings_parser.add_argument("-f", "--format", choices=["text", "json", "csv"], default="text", help="Output format")
    strings_parser.add_argument("--min-length", type=int, default=4, help="Minimum string length")
    strings_parser.add_argument("--encoding", choices=["ascii", "utf8", "utf16", "all"], default="all", help="String encoding")
    strings_parser.add_argument("--suspicious", action="store_true", help="Only show suspicious strings")
    
    # Hash scan command
    hash_parser = subparsers.add_parser("hash-scan", help="Scan with hash patterns")
    hash_parser.add_argument("file", type=Path, help="Binary file to scan")
    hash_parser.add_argument("-s", "--signatures", type=Path, required=True, help="Signature database file")
    hash_parser.add_argument("-o", "--output", type=Path, help="Output file (default: stdout)")
    hash_parser.add_argument("-f", "--format", choices=["text", "json"], default="text", help="Output format")
    
    # Info command
    info_parser = subparsers.add_parser("info", help="Show binary information")
    info_parser.add_argument("file", type=Path, help="Binary file to analyze")
    info_parser.add_argument("-f", "--format", choices=["text", "json"], default="text", help="Output format")
    
    return parser


def cmd_analyze(args) -> int:
    """Handle analyze command"""
    try:
        if not args.file.exists():
            logger.error(f"File not found: {args.file}")
            return 1
        
        logger.info(f"Starting analysis of {args.file}")
        
        # Initialize analyzer
        analyzer = StaticAnalyzer(args.file)
        
        # Perform analysis
        result = analyzer.analyze(
            analyze_functions=not args.no_functions,
            analyze_strings=not args.no_strings,
            analyze_control_flow=not args.no_control_flow,
            analyze_data_flow=not args.no_data_flow,
            min_string_length=args.min_string_length
        )
        
        # Add hash pattern matching if signatures provided
        if args.signatures:
            logger.info("Performing hash pattern matching")
            hash_matcher = HashPatternMatcher(args.signatures)
            
            # Match file hashes
            file_matches = hash_matcher.match_file_hashes(args.file)
            
            # Match function hashes
            function_matches = hash_matcher.match_function_hashes(result.functions)
            
            # Match string hashes
            string_matches = hash_matcher.match_string_hashes(result.strings)
            
            # Add hash matches to result
            result.hash_matches = {
                'file_matches': [match.__dict__ for match in file_matches],
                'function_matches': [match.__dict__ for match in function_matches],
                'string_matches': [match.__dict__ for match in string_matches]
            }
        
        # Generate report
        report_generator = ReportGenerator()
        report_generator.set_metadata('file_path', str(args.file))
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
        
        if success:
            logger.info(f"Analysis complete. Report saved to {args.output}")
            return 0
        else:
            logger.error("Failed to generate report")
            return 1
            
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        return 1


def cmd_strings(args) -> int:
    """Handle strings command"""
    try:
        if not args.file.exists():
            logger.error(f"File not found: {args.file}")
            return 1
        
        logger.info(f"Extracting strings from {args.file}")
        
        # Initialize string extractor
        extractor = StringExtractor(args.file)
        
        # Determine encodings
        encodings = None
        if args.encoding != "all":
            encodings = [args.encoding]
        
        # Extract strings
        strings = extractor.extract_strings(
            min_length=args.min_length,
            encodings=encodings,
            include_unicode=True
        )
        
        # Filter suspicious strings if requested
        if args.suspicious:
            strings = extractor.find_suspicious_strings()
        
        # Output results
        if args.output:
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
                print(json.dumps([s.__dict__ for s in strings], indent=2))
            elif args.format == "csv":
                import csv
                writer = csv.writer(sys.stdout)
                writer.writerow(['value', 'address', 'encoding', 'length', 'entropy'])
                for s in strings:
                    writer.writerow([s.value, s.address, s.encoding, s.length, s.entropy])
            else:
                for s in strings:
                    print(s.value)
        
        logger.info(f"Extracted {len(strings)} strings")
        return 0
        
    except Exception as e:
        logger.error(f"String extraction failed: {e}")
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
        
    except Exception as e:
        logger.error(f"Hash scan failed: {e}")
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
        
    except Exception as e:
        logger.error(f"Info command failed: {e}")
        return 1


def main() -> int:
    """Main entry point"""
    parser = create_parser()
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose, args.quiet, args.log_file)
    
    # Handle commands
    if args.command == "analyze":
        return cmd_analyze(args)
    elif args.command == "strings":
        return cmd_strings(args)
    elif args.command == "hash-scan":
        return cmd_hash_scan(args)
    elif args.command == "info":
        return cmd_info(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
