"""
CLI command implementations
"""

from pathlib import Path
from typing import Dict, Any, List
import json
import csv
import sys

from loguru import logger


class CommandError(Exception):
    """Command execution error"""
    pass


class BaseCommand:
    """Base class for CLI commands"""
    
    def __init__(self):
        self.name = self.__class__.__name__.lower().replace('command', '')
    
    def execute(self, args) -> int:
        """Execute the command"""
        raise NotImplementedError
    
    def validate_args(self, args) -> bool:
        """Validate command arguments"""
        return True


class AnalyzeCommand(BaseCommand):
    """Analyze binary file command"""
    
    def execute(self, args) -> int:
        try:
            from ..core.static_analyzer.analyzer import StaticAnalyzer
            from ..core.reports.generator import ReportGenerator
            
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
            
            # Generate report
            report_generator = ReportGenerator()
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


class StringsCommand(BaseCommand):
    """Extract strings command"""
    
    def execute(self, args) -> int:
        try:
            from ..core.string_extractor.extractor import StringExtractor
            
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
            self._output_strings(strings, args)
            
            logger.info(f"Extracted {len(strings)} strings")
            return 0
            
        except Exception as e:
            logger.error(f"String extraction failed: {e}")
            return 1
    
    def _output_strings(self, strings: List, args) -> None:
        """Output strings in specified format"""
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                self._write_strings(strings, f, args.format)
        else:
            self._write_strings(strings, sys.stdout, args.format)
    
    def _write_strings(self, strings: List, output, format: str) -> None:
        """Write strings to output in specified format"""
        if format == "json":
            json.dump([s.__dict__ for s in strings], output, indent=2)
        elif format == "csv":
            writer = csv.writer(output)
            writer.writerow(['value', 'address', 'encoding', 'length', 'entropy'])
            for s in strings:
                writer.writerow([s.value, s.address, s.encoding, s.length, s.entropy])
        else:
            for s in strings:
                output.write(f"{s.value}\n")


class HashScanCommand(BaseCommand):
    """Hash pattern scanning command"""
    
    def execute(self, args) -> int:
        try:
            from ..core.hash_patterns.matcher import HashPatternMatcher
            from ..core.loader.factory import LoaderFactory
            
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
            loader = LoaderFactory.create_loader(args.file)
            binary_info = loader.info
            
            # Perform various matches
            matches = self._perform_hash_matching(matcher, args.file, binary_info)
            
            # Output results
            self._output_hash_matches(matches, args)
            
            total_matches = sum(len(matches.get(cat, [])) for cat in matches)
            logger.info(f"Scan complete. Found {total_matches} matches")
            return 0
            
        except Exception as e:
            logger.error(f"Hash scan failed: {e}")
            return 1
    
    def _perform_hash_matching(self, matcher, file_path: Path, binary_info) -> Dict[str, Any]:
        """Perform hash pattern matching"""
        matches = {}
        
        # File hash matches
        file_matches = matcher.match_file_hashes(file_path)
        if file_matches:
            matches['file'] = [match.__dict__ for match in file_matches]
        
        # String hash matches
        strings = binary_info.strings
        if strings:
            string_matches = matcher.match_string_hashes(strings)
            if string_matches:
                matches['strings'] = [match.__dict__ for match in string_matches]
        
        # Import hash matches
        import_matches = matcher.match_import_hashes(binary_info.imports)
        if import_matches:
            matches['imports'] = [match.__dict__ for match in import_matches]
        
        return matches
    
    def _output_hash_matches(self, matches: Dict[str, Any], args) -> None:
        """Output hash matches in specified format"""
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                self._write_hash_matches(matches, f, args.format)
        else:
            self._write_hash_matches(matches, sys.stdout, args.format)
    
    def _write_hash_matches(self, matches: Dict[str, Any], output, format: str) -> None:
        """Write hash matches to output in specified format"""
        if format == "json":
            json.dump(matches, output, indent=2)
        else:
            for category, category_matches in matches.items():
                output.write(f"{category.upper()} MATCHES:\n")
                for match in category_matches:
                    output.write(f"  {match['pattern_name']}: {match['description']}\n")
                output.write("\n")


class InfoCommand(BaseCommand):
    """Show binary information command"""
    
    def execute(self, args) -> int:
        try:
            from ..core.loader.factory import LoaderFactory
            
            if not args.file.exists():
                logger.error(f"File not found: {args.file}")
                return 1
            
            # Load binary information
            loader = LoaderFactory.create_loader(args.file)
            binary_info = loader.info
            
            # Output results
            self._output_binary_info(binary_info, args)
            
            return 0
            
        except Exception as e:
            logger.error(f"Info command failed: {e}")
            return 1
    
    def _output_binary_info(self, binary_info, args) -> None:
        """Output binary information in specified format"""
        if args.format == "json":
            json.dump(binary_info.__dict__, sys.stdout, indent=2, default=str)
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


# Command registry
COMMANDS = {
    'analyze': AnalyzeCommand,
    'strings': StringsCommand,
    'hash-scan': HashScanCommand,
    'info': InfoCommand,
}


def get_command(name: str) -> BaseCommand:
    """Get command by name"""
    if name not in COMMANDS:
        raise CommandError(f"Unknown command: {name}")
    
    return COMMANDS[name]()


def list_commands() -> List[str]:
    """List available commands"""
    return list(COMMANDS.keys())
