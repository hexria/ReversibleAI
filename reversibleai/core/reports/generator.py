"""
Main report generator for analysis results
"""

from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from datetime import datetime
from dataclasses import dataclass

from loguru import logger

from .formatters import JSONFormatter, HTMLFormatter, PDFFormatter, XMLFormatter


@dataclass
class ReportSection:
    """Represents a section in the report"""
    title: str
    content: Any
    order: int
    metadata: Dict[str, Any]


class ReportGenerator:
    """Main report generator class"""
    
    def __init__(self) -> None:
        self.formatters = {
            'json': JSONFormatter(),
            'html': HTMLFormatter(),
            'pdf': PDFFormatter(),
            'xml': XMLFormatter()
        }
        self.sections: List[ReportSection] = []
        self.metadata: Dict[str, Any] = {}
    
    def add_section(self, title: str, content: Any, order: int = 0, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Add a section to the report"""
        section = ReportSection(
            title=title,
            content=content,
            order=order,
            metadata=metadata or {}
        )
        self.sections.append(section)
        logger.debug(f"Added report section: {title}")
    
    def set_metadata(self, key: str, value: Any) -> None:
        """Set report metadata"""
        self.metadata[key] = value
    
    def generate_report(self, 
                       output_path: Path,
                       format: str = 'json',
                       template: Optional[str] = None) -> bool:
        """
        Generate a report in the specified format
        
        Args:
            output_path: Path to save the report
            format: Report format ('json', 'html', 'pdf', 'xml')
            template: Optional template name
            
        Returns:
            True if successful, False otherwise
        """
        if format not in self.formatters:
            logger.error(f"Unsupported report format: {format}")
            return False
        
        try:
            # Sort sections by order
            sorted_sections = sorted(self.sections, key=lambda x: x.order)
            
            # Prepare report data
            report_data = {
                'metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'generator': 'ReversibleAI',
                    'version': '0.1.0',
                    **self.metadata
                },
                'sections': [
                    {
                        'title': section.title,
                        'content': section.content,
                        'metadata': section.metadata
                    }
                    for section in sorted_sections
                ]
            }
            
            # Generate report using appropriate formatter
            formatter = self.formatters[format]
            success = formatter.format_report(report_data, output_path, template)
            
            if success:
                logger.info(f"Generated {format.upper()} report: {output_path}")
            else:
                logger.error(f"Failed to generate {format.upper()} report")
            
            return success
            
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            return False
    
    def generate_analysis_report(self, 
                               analysis_result: Dict[str, Any],
                               output_path: Path,
                               format: str = 'html') -> bool:
        """
        Generate a comprehensive analysis report
        
        Args:
            analysis_result: Results from static analysis
            output_path: Path to save the report
            format: Report format
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Clear existing sections
            self.sections.clear()
            self.metadata.clear()
            
            # Set metadata
            self.set_metadata('report_type', 'analysis')
            self.set_metadata('file_path', str(analysis_result.get('file_path', 'Unknown')))
            
            # Add executive summary
            self.add_section(
                title='Executive Summary',
                content=self._create_executive_summary(analysis_result),
                order=1
            )
            
            # Add file information
            self.add_section(
                title='File Information',
                content=analysis_result.get('file_info', {}),
                order=2
            )
            
            # Add functions analysis
            if 'functions' in analysis_result:
                self.add_section(
                    title='Functions Analysis',
                    content={
                        'total_functions': len(analysis_result['functions']),
                        'functions': analysis_result['functions'][:20],  # Limit to first 20
                        'summary': self._summarize_functions(analysis_result['functions'])
                    },
                    order=3
                )
            
            # Add strings analysis
            if 'strings' in analysis_result:
                self.add_section(
                    title='Strings Analysis',
                    content={
                        'total_strings': len(analysis_result['strings']),
                        'suspicious_strings': self._find_suspicious_strings(analysis_result['strings']),
                        'urls': self._extract_urls(analysis_result['strings']),
                        'sample_strings': analysis_result['strings'][:50]  # Limit to first 50
                    },
                    order=4
                )
            
            # Add imports/exports
            if 'imports' in analysis_result or 'exports' in analysis_result:
                self.add_section(
                    title='Imports and Exports',
                    content={
                        'imports': analysis_result.get('imports', []),
                        'exports': analysis_result.get('exports', []),
                        'summary': self._summarize_imports_exports(
                            analysis_result.get('imports', []),
                            analysis_result.get('exports', [])
                        )
                    },
                    order=5
                )
            
            # Add control flow analysis
            if 'control_flow' in analysis_result:
                self.add_section(
                    title='Control Flow Analysis',
                    content=analysis_result['control_flow'],
                    order=6
                )
            
            # Add data flow analysis
            if 'data_flow' in analysis_result:
                self.add_section(
                    title='Data Flow Analysis',
                    content=analysis_result['data_flow'],
                    order=7
                )
            
            # Add security findings
            security_findings = self._generate_security_findings(analysis_result)
            if security_findings:
                self.add_section(
                    title='Security Findings',
                    content=security_findings,
                    order=8
                )
            
            # Generate the report
            return self.generate_report(output_path, format)
            
        except Exception as e:
            logger.error(f"Failed to generate analysis report: {e}")
            return False
    
    def _create_executive_summary(self, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """Create executive summary of analysis"""
        file_info = analysis_result.get('file_info', {})
        functions = analysis_result.get('functions', [])
        strings = analysis_result.get('strings', [])
        imports = analysis_result.get('imports', [])
        
        return {
            'file_name': Path(file_info.get('path', '')).name,
            'file_type': file_info.get('file_type', 'Unknown'),
            'architecture': file_info.get('architecture', 'Unknown'),
            'file_size': file_info.get('size', 0),
            'functions_count': len(functions),
            'strings_count': len(strings),
            'imports_count': len(imports),
            'complexity_score': self._calculate_complexity_score(functions),
            'risk_level': self._assess_risk_level(analysis_result),
            'analysis_time': datetime.now().isoformat()
        }
    
    def _summarize_functions(self, functions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Summarize functions analysis"""
        if not functions:
            return {}
        
        # Calculate statistics
        sizes = [f.get('size', 0) for f in functions]
        instruction_counts = [f.get('instruction_count', 0) for f in functions]
        
        return {
            'total_functions': len(functions),
            'average_size': sum(sizes) / len(sizes) if sizes else 0,
            'max_size': max(sizes) if sizes else 0,
            'average_instructions': sum(instruction_counts) / len(instruction_counts) if instruction_counts else 0,
            'complex_functions': len([f for f in functions if f.get('basic_block_count', 0) > 10]),
            'named_functions': len([f for f in functions if f.get('name') and not f['name'].startswith('sub_')])
        }
    
    def _find_suspicious_strings(self, strings: List[str]) -> List[Dict[str, Any]]:
        """Find suspicious strings"""
        suspicious_keywords = [
            'password', 'passwd', 'secret', 'key', 'crypto', 'encrypt', 'decrypt',
            'shell', 'cmd', 'powershell', 'admin', 'root', 'hack', 'crack',
            'malware', 'virus', 'trojan', 'backdoor', 'rootkit'
        ]
        
        suspicious = []
        for string_value in strings[:100]:  # Limit to first 100 strings
            string_lower = string_value.lower()
            for keyword in suspicious_keywords:
                if keyword in string_lower:
                    suspicious.append({
                        'string': string_value,
                        'keyword': keyword,
                        'reason': f"Contains suspicious keyword: {keyword}"
                    })
                    break
        
        return suspicious[:20]  # Limit to top 20
    
    def _extract_urls(self, strings: List[str]) -> List[str]:
        """Extract URLs from strings"""
        import re
        
        url_pattern = re.compile(
            r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?',
            re.IGNORECASE
        )
        
        urls = []
        for string_value in strings:
            if url_pattern.search(string_value):
                urls.append(string_value)
        
        return urls[:10]  # Limit to first 10 URLs
    
    def _summarize_imports_exports(self, imports: List[Dict[str, Any]], exports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Summarize imports and exports"""
        # Group imports by library
        import_libraries = {}
        for imp in imports:
            library = imp.get('library', 'Unknown')
            import_libraries[library] = import_libraries.get(library, 0) + 1
        
        # Find suspicious imports
        suspicious_imports = [
            imp for imp in imports
            if any(keyword in imp.get('function', '').lower() 
                   for keyword in ['createprocess', 'virtualalloc', 'writeprocessmemory'])
        ]
        
        return {
            'total_imports': len(imports),
            'total_exports': len(exports),
            'unique_libraries': len(import_libraries),
            'top_libraries': sorted(import_libraries.items(), key=lambda x: x[1], reverse=True)[:5],
            'suspicious_imports_count': len(suspicious_imports),
            'suspicious_imports': suspicious_imports[:10]
        }
    
    def _calculate_complexity_score(self, functions: List[Dict[str, Any]]) -> float:
        """Calculate complexity score based on functions"""
        if not functions:
            return 0.0
        
        score = 0.0
        
        for func in functions:
            # Add points for function size
            score += func.get('size', 0) / 1000.0
            
            # Add points for basic blocks
            score += func.get('basic_block_count', 0) * 0.1
            
            # Add points for instruction count
            score += func.get('instruction_count', 0) * 0.01
        
        # Normalize to 0-100 scale
        return min(100.0, score / len(functions))
    
    def _assess_risk_level(self, analysis_result: Dict[str, Any]) -> str:
        """Assess risk level based on analysis results"""
        risk_score = 0
        
        # Check suspicious strings
        strings = analysis_result.get('strings', [])
        suspicious_count = len(self._find_suspicious_strings(strings))
        risk_score += suspicious_count * 2
        
        # Check suspicious imports
        imports = analysis_result.get('imports', [])
        suspicious_imports = [
            imp for imp in imports
            if any(keyword in imp.get('function', '').lower() 
                   for keyword in ['createprocess', 'virtualalloc', 'writeprocessmemory'])
        ]
        risk_score += len(suspicious_imports) * 3
        
        # Check complexity
        functions = analysis_result.get('functions', [])
        complexity = self._calculate_complexity_score(functions)
        if complexity > 50:
            risk_score += 10
        
        # Determine risk level
        if risk_score >= 20:
            return "High"
        elif risk_score >= 10:
            return "Medium"
        elif risk_score >= 5:
            return "Low"
        else:
            return "Minimal"
    
    def _generate_security_findings(self, analysis_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate security findings"""
        findings = []
        
        # Check for suspicious imports
        imports = analysis_result.get('imports', [])
        suspicious_imports = [
            imp for imp in imports
            if any(keyword in imp.get('function', '').lower() 
                   for keyword in ['createprocess', 'virtualalloc', 'writeprocessmemory'])
        ]
        
        if suspicious_imports:
            findings.append({
                'type': 'Suspicious Imports',
                'severity': 'Medium',
                'description': f"Found {len(suspicious_imports)} suspicious API imports",
                'details': suspicious_imports[:5]
            })
        
        # Check for suspicious strings
        strings = analysis_result.get('strings', [])
        suspicious_strings = self._find_suspicious_strings(strings)
        
        if suspicious_strings:
            findings.append({
                'type': 'Suspicious Strings',
                'severity': 'Low',
                'description': f"Found {len(suspicious_strings)} suspicious strings",
                'details': suspicious_strings[:5]
            })
        
        # Check for obfuscation indicators
        functions = analysis_result.get('functions', [])
        obfuscated_functions = [
            f for f in functions
            if f.get('name', '').startswith('sub_') and f.get('size', 0) > 1000
        ]
        
        if len(obfuscated_functions) > len(functions) * 0.5:
            findings.append({
                'type': 'Potential Obfuscation',
                'severity': 'High',
                'description': "High percentage of unnamed functions, possible obfuscation",
                'details': {'unnamed_functions': len(obfuscated_functions), 'total_functions': len(functions)}
            })
        
        return findings
    
    def clear_sections(self) -> None:
        """Clear all sections"""
        self.sections.clear()
    
    def clear_metadata(self) -> None:
        """Clear all metadata"""
        self.metadata.clear()
    
    def get_available_formats(self) -> List[str]:
        """Get list of available report formats"""
        return list(self.formatters.keys())
    
    def add_custom_formatter(self, name: str, formatter) -> None:
        """Add a custom formatter"""
        self.formatters[name] = formatter
        logger.info(f"Added custom formatter: {name}")
