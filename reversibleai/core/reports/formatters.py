"""
Report formatters for different output formats
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Any, Optional
import json
import xml.etree.ElementTree as ET
from datetime import datetime

from loguru import logger


class BaseFormatter(ABC):
    """Abstract base class for report formatters"""
    
    @abstractmethod
    def format_report(self, report_data: Dict[str, Any], output_path: Path, template: Optional[str] = None) -> bool:
        """Format and save report"""
        pass


class JSONFormatter(BaseFormatter):
    """JSON report formatter"""
    
    def format_report(self, report_data: Dict[str, Any], output_path: Path, template: Optional[str] = None) -> bool:
        """Format report as JSON"""
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)
            
            logger.debug(f"JSON report saved to {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save JSON report: {e}")
            return False


class HTMLFormatter(BaseFormatter):
    """HTML report formatter"""
    
    def format_report(self, report_data: Dict[str, Any], output_path: Path, template: Optional[str] = None) -> bool:
        """Format report as HTML"""
        try:
            html_content = self._generate_html(report_data)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.debug(f"HTML report saved to {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save HTML report: {e}")
            return False
    
    def _generate_html(self, report_data: Dict[str, Any]) -> str:
        """Generate HTML content"""
        metadata = report_data.get('metadata', {})
        sections = report_data.get('sections', [])
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ReversibleAI Analysis Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .header {{
            border-bottom: 2px solid #007acc;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            color: #007acc;
            margin: 0;
            font-size: 2.5em;
        }}
        .metadata {{
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        .metadata dt {{
            font-weight: bold;
            color: #495057;
        }}
        .metadata dd {{
            margin-left: 20px;
            margin-bottom: 10px;
        }}
        .section {{
            margin-bottom: 40px;
        }}
        .section h2 {{
            color: #007acc;
            border-bottom: 1px solid #dee2e6;
            padding-bottom: 10px;
        }}
        .section h3 {{
            color: #495057;
            margin-top: 25px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            border: 1px solid #dee2e6;
            padding: 12px;
            text-align: left;
        }}
        th {{
            background-color: #007acc;
            color: white;
            font-weight: bold;
        }}
        tr:nth-child(even) {{
            background-color: #f8f9fa;
        }}
        .code {{
            background-color: #f1f3f4;
            padding: 10px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            overflow-x: auto;
        }}
        .alert {{
            padding: 15px;
            margin: 20px 0;
            border-radius: 4px;
        }}
        .alert-high {{
            background-color: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
        }}
        .alert-medium {{
            background-color: #fff3cd;
            border: 1px solid #ffeaa7;
            color: #856404;
        }}
        .alert-low {{
            background-color: #d1ecf1;
            border: 1px solid #bee5eb;
            color: #0c5460;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .stat-card {{
            background-color: #f8f9fa;
            padding: 20px;
            border-radius: 5px;
            text-align: center;
            border-left: 4px solid #007acc;
        }}
        .stat-number {{
            font-size: 2em;
            font-weight: bold;
            color: #007acc;
        }}
        .stat-label {{
            color: #6c757d;
            margin-top: 5px;
        }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #dee2e6;
            text-align: center;
            color: #6c757d;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>ReversibleAI Analysis Report</h1>
            <p>Generated on {metadata.get('generated_at', 'Unknown')}</p>
        </div>
        
        <div class="metadata">
            <h3>Report Information</h3>
            <dl>
                <dt>Generator</dt>
                <dd>{metadata.get('generator', 'Unknown')}</dd>
                <dt>Version</dt>
                <dd>{metadata.get('version', 'Unknown')}</dd>
                <dt>Report Type</dt>
                <dd>{metadata.get('report_type', 'Unknown')}</dd>
                <dt>File Path</dt>
                <dd>{metadata.get('file_path', 'Unknown')}</dd>
            </dl>
        </div>
        
        {self._format_sections_html(sections)}
        
        <div class="footer">
            <p>Report generated by ReversibleAI - Advanced Static & Dynamic Analysis Framework</p>
        </div>
    </div>
</body>
</html>
        """
        
        return html
    
    def _format_sections_html(self, sections: list) -> str:
        """Format sections as HTML"""
        html = ""
        
        for section in sections:
            title = section.get('title', 'Untitled Section')
            content = section.get('content', {})
            
            html += f'<div class="section">\n'
            html += f'<h2>{title}</h2>\n'
            
            # Format content based on its type
            if isinstance(content, dict):
                html += self._format_dict_html(content)
            elif isinstance(content, list):
                html += self._format_list_html(content)
            else:
                html += f'<p>{content}</p>\n'
            
            html += '</div>\n'
        
        return html
    
    def _format_dict_html(self, data: dict) -> str:
        """Format dictionary as HTML"""
        html = ""
        
        for key, value in data.items():
            if isinstance(value, dict):
                html += f'<h3>{key.replace("_", " ").title()}</h3>\n'
                html += self._format_dict_html(value)
            elif isinstance(value, list):
                html += f'<h3>{key.replace("_", " ").title()}</h3>\n'
                html += self._format_list_html(value)
            else:
                html += f'<p><strong>{key.replace("_", " ").title()}:</strong> {value}</p>\n'
        
        return html
    
    def _format_list_html(self, data: list) -> str:
        """Format list as HTML"""
        if not data:
            return '<p>No data available</p>'
        
        # Check if this is a list of dictionaries (for table format)
        if data and isinstance(data[0], dict):
            return self._format_table_html(data)
        
        # Regular list
        html = '<ul>\n'
        for item in data:
            html += f'<li>{item}</li>\n'
        html += '</ul>\n'
        
        return html
    
    def _format_table_html(self, data: list) -> str:
        """Format list of dictionaries as HTML table"""
        if not data:
            return '<p>No data available</p>'
        
        # Get all possible keys from all items
        all_keys = set()
        for item in data:
            all_keys.update(item.keys())
        
        # Sort keys for consistent column order
        keys = sorted(all_keys)
        
        html = '<table>\n'
        html += '<thead><tr>\n'
        for key in keys:
            html += f'<th>{key.replace("_", " ").title()}</th>\n'
        html += '</tr></thead>\n'
        html += '<tbody>\n'
        
        for item in data:
            html += '<tr>\n'
            for key in keys:
                value = item.get(key, '')
                if isinstance(value, (list, dict)):
                    value = str(value)[:100] + '...' if len(str(value)) > 100 else str(value)
                html += f'<td>{value}</td>\n'
            html += '</tr>\n'
        
        html += '</tbody>\n'
        html += '</table>\n'
        
        return html


class XMLFormatter(BaseFormatter):
    """XML report formatter"""
    
    def format_report(self, report_data: Dict[str, Any], output_path: Path, template: Optional[str] = None) -> bool:
        """Format report as XML"""
        try:
            root = ET.Element("report")
            
            # Add metadata
            metadata = report_data.get('metadata', {})
            metadata_elem = ET.SubElement(root, "metadata")
            for key, value in metadata.items():
                elem = ET.SubElement(metadata_elem, key)
                elem.text = str(value)
            
            # Add sections
            sections = report_data.get('sections', [])
            sections_elem = ET.SubElement(root, "sections")
            
            for section in sections:
                section_elem = ET.SubElement(sections_elem, "section")
                section_elem.set("title", section.get('title', ''))
                
                content = section.get('content', {})
                self._add_xml_content(section_elem, content)
            
            # Write to file
            tree = ET.ElementTree(root)
            tree.write(output_path, encoding='utf-8', xml_declaration=True)
            
            logger.debug(f"XML report saved to {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save XML report: {e}")
            return False
    
    def _add_xml_content(self, parent: ET.Element, content: Any) -> None:
        """Add content to XML element"""
        if isinstance(content, dict):
            for key, value in content.items():
                elem = ET.SubElement(parent, key)
                if isinstance(value, (dict, list)):
                    self._add_xml_content(elem, value)
                else:
                    elem.text = str(value)
        elif isinstance(content, list):
            for i, item in enumerate(content):
                elem = ET.SubElement(parent, f"item_{i}")
                if isinstance(item, (dict, list)):
                    self._add_xml_content(elem, item)
                else:
                    elem.text = str(item)
        else:
            parent.text = str(content)


class PDFFormatter(BaseFormatter):
    """PDF report formatter (placeholder implementation)"""
    
    def format_report(self, report_data: Dict[str, Any], output_path: Path, template: Optional[str] = None) -> bool:
        """Format report as PDF"""
        try:
            # This is a placeholder implementation
            # In practice, you would use a library like reportlab or weasyprint
            
            # For now, create a simple text-based PDF-like file
            pdf_content = self._generate_pdf_like_content(report_data)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(pdf_content)
            
            logger.debug(f"PDF-like report saved to {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save PDF report: {e}")
            return False
    
    def _generate_pdf_like_content(self, report_data: Dict[str, Any]) -> str:
        """Generate PDF-like content (placeholder)"""
        metadata = report_data.get('metadata', {})
        sections = report_data.get('sections', [])
        
        content = f"""
ReversibleAI Analysis Report
{'=' * 50}

Generated: {metadata.get('generated_at', 'Unknown')}
Generator: {metadata.get('generator', 'Unknown')} v{metadata.get('version', 'Unknown')}
Report Type: {metadata.get('report_type', 'Unknown')}
File Path: {metadata.get('file_path', 'Unknown')}

{'=' * 50}

"""
        
        for section in sections:
            title = section.get('title', 'Untitled Section')
            content = section.get('content', {})
            
            content += f"\n{title}\n{'-' * len(title)}\n\n"
            
            if isinstance(content, dict):
                content += self._format_dict_text(content)
            elif isinstance(content, list):
                content += self._format_list_text(content)
            else:
                content += f"{content}\n"
            
            content += "\n"
        
        content += f"\n{'=' * 50}\n"
        content += "End of Report\n"
        
        return content
    
    def _format_dict_text(self, data: dict) -> str:
        """Format dictionary as text"""
        text = ""
        
        for key, value in data.items():
            if isinstance(value, dict):
                text += f"{key.replace('_', ' ').title()}:\n"
                text += self._format_dict_text(value)
            elif isinstance(value, list):
                text += f"{key.replace('_', ' ').title()}:\n"
                text += self._format_list_text(value)
            else:
                text += f"  {key.replace('_', ' ').title()}: {value}\n"
        
        return text
    
    def _format_list_text(self, data: list) -> str:
        """Format list as text"""
        if not data:
            return "  No data available\n"
        
        text = ""
        for i, item in enumerate(data):
            if isinstance(item, dict):
                text += f"  Item {i + 1}:\n"
                text += self._format_dict_text(item)
            else:
                text += f"  - {item}\n"
        
        return text
