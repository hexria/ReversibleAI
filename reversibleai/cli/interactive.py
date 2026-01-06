"""
Interactive shell mode for ReversibleAI
"""

import sys
from pathlib import Path
from typing import Optional, List
import cmd
import shlex

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm

from ..core.static_analyzer.analyzer import StaticAnalyzer
from ..core.string_extractor.extractor import StringExtractor
from ..core.hash_patterns.matcher import HashPatternMatcher
from ..core.reports.generator import ReportGenerator
from ..core.exceptions import ReversibleAIError
from ..core.validation import validate_path

console = Console()


class ReversibleAIShell(cmd.Cmd):
    """Interactive shell for ReversibleAI"""
    
    intro = Panel(
        "[bold blue]🔍 ReversibleAI Interactive Shell[/bold blue]\n"
        "Type 'help' for available commands or 'exit' to quit.",
        title="Welcome",
        border_style="blue"
    )
    prompt = "[reversibleai] > "
    
    def __init__(self) -> None:
        super().__init__()
        self.current_file: Optional[Path] = None
        self.analyzer: Optional[StaticAnalyzer] = None
        self.analysis_result = None
    
    def do_load(self, arg: str) -> None:
        """Load a binary file: load <file_path>"""
        if not arg:
            console.print("[error]Usage: load <file_path>[/error]")
            return
        
        try:
            file_path = validate_path(arg.strip())
            if not file_path.exists():
                console.print(f"[error]File not found: {file_path}[/error]")
                return
            
            self.current_file = file_path
            self.analyzer = StaticAnalyzer(file_path)
            console.print(f"[success]✅ Loaded: {file_path}[/success]")
        except Exception as e:
            console.print(f"[error]Failed to load file: {e}[/error]")
    
    def do_analyze(self, arg: str) -> None:
        """Analyze loaded binary: analyze [options]"""
        if self.analyzer is None:
            console.print("[error]No file loaded. Use 'load <file>' first.[/error]")
            return
        
        try:
            # Parse options
            options = {}
            if arg:
                parts = shlex.split(arg)
                for part in parts:
                    if part.startswith("--"):
                        key = part[2:].replace("-", "_")
                        options[key] = True
            
            self.analysis_result = self.analyzer.analyze(**options)
            console.print(f"[success]✅ Analysis complete[/success]")
            console.print(f"[info]Functions: {len(self.analysis_result.functions)}[/info]")
            console.print(f"[info]Strings: {len(self.analysis_result.strings)}[/info]")
        except Exception as e:
            console.print(f"[error]Analysis failed: {e}[/error]")
    
    def do_strings(self, arg: str) -> None:
        """Extract strings: strings [--min-length N] [--suspicious]"""
        if self.current_file is None:
            console.print("[error]No file loaded. Use 'load <file>' first.[/error]")
            return
        
        try:
            extractor = StringExtractor(self.current_file)
            options = {}
            
            if arg:
                parts = shlex.split(arg)
                for i, part in enumerate(parts):
                    if part == "--min-length" and i + 1 < len(parts):
                        options["min_length"] = int(parts[i + 1])
                    elif part == "--suspicious":
                        options["suspicious"] = True
            
            strings = extractor.extract_strings(**options)
            console.print(f"[success]✅ Extracted {len(strings)} strings[/success]")
            
            # Show first 10 strings
            for s in strings[:10]:
                console.print(f"[info]{s.value}[/info]")
        except Exception as e:
            console.print(f"[error]String extraction failed: {e}[/error]")
    
    def do_info(self, arg: str) -> None:
        """Show binary information"""
        if self.analyzer is None:
            console.print("[error]No file loaded. Use 'load <file>' first.[/error]")
            return
        
        try:
            summary = self.analyzer.get_analysis_summary()
            console.print(Panel(
                f"[cyan]File:[/cyan] {summary['file']['name']}\n"
                f"[cyan]Type:[/cyan] {summary['file']['type']}\n"
                f"[cyan]Architecture:[/cyan] {summary['file']['architecture']}\n"
                f"[cyan]Size:[/cyan] {summary['file']['size']} bytes",
                title="Binary Information",
                border_style="cyan"
            ))
        except Exception as e:
            console.print(f"[error]Failed to get info: {e}[/error]")
    
    def do_report(self, arg: str) -> None:
        """Generate report: report <output_file> [--format html|json|pdf|xml]"""
        if self.analysis_result is None:
            console.print("[error]No analysis results. Run 'analyze' first.[/error]")
            return
        
        if not arg:
            console.print("[error]Usage: report <output_file> [--format html|json|pdf|xml][/error]")
            return
        
        try:
            parts = shlex.split(arg)
            output_path = Path(parts[0])
            format_type = "html"
            
            if "--format" in parts:
                idx = parts.index("--format")
                if idx + 1 < len(parts):
                    format_type = parts[idx + 1]
            
            generator = ReportGenerator()
            success = generator.generate_analysis_report(
                analysis_result=self.analysis_result.__dict__,
                output_path=output_path,
                format=format_type
            )
            
            if success:
                console.print(f"[success]✅ Report saved to {output_path}[/success]")
            else:
                console.print("[error]Failed to generate report[/error]")
        except Exception as e:
            console.print(f"[error]Report generation failed: {e}[/error]")
    
    def do_clear(self, arg: str) -> None:
        """Clear current file and analysis"""
        self.current_file = None
        self.analyzer = None
        self.analysis_result = None
        console.print("[success]✅ Cleared[/success]")
    
    def do_exit(self, arg: str) -> bool:
        """Exit the shell"""
        return True
    
    def do_quit(self, arg: str) -> bool:
        """Exit the shell"""
        return True
    
    def do_EOF(self, arg: str) -> bool:
        """Exit on EOF"""
        console.print()
        return True
    
    def default(self, line: str) -> None:
        """Handle unknown commands"""
        console.print(f"[error]Unknown command: {line.split()[0]}[/error]")
        console.print("[info]Type 'help' for available commands[/info]")


def run_interactive() -> int:
    """Run interactive shell"""
    try:
        shell = ReversibleAIShell()
        shell.cmdloop()
        return 0
    except KeyboardInterrupt:
        console.print("\n[info]Exiting...[/info]")
        return 0
    except Exception as e:
        console.print(f"[error]Shell error: {e}[/error]")
        return 1
