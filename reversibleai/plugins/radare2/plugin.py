"""
Radare2 plugin implementation
"""

from typing import Dict, List, Any, Optional
import json

from loguru import logger

from ..base import BasePlugin, PluginInfo, AnalysisPlugin, AnnotationPlugin


class Radare2Plugin(AnalysisPlugin, AnnotationPlugin):
    """Radare2 integration plugin"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.r2_instance = None
        self.r2_available = False
        
        # Try to import r2pipe
        try:
            import r2pipe
            self.r2pipe = r2pipe
            self.r2_available = True
            logger.info("r2pipe loaded successfully")
        except ImportError:
            logger.warning("r2pipe not available. Running in standalone mode.")
    
    @property
    def info(self) -> PluginInfo:
        """Get plugin information"""
        return PluginInfo(
            name="radare2",
            version="0.1.0",
            description="Radare2 integration plugin for ReversibleAI",
            author="ReversibleAI Team",
            supported_tools=["radare2"],
            supported_architectures=["x86", "x86_64", "arm", "aarch64", "mips", "ppc", "sparc"],
            capabilities=["static_analysis", "annotations", "export", "debugging"],
            dependencies=["r2pipe"],
            config_schema={
                "type": "object",
                "properties": {
                    "auto_analyze": {
                        "type": "bool",
                        "default": True,
                        "description": "Automatically analyze when r2 opens a file"
                    },
                    "analysis_level": {
                        "type": "string",
                        "enum": ["aaa", "aaaa", "aaaaa"],
                        "default": "aaaa",
                        "description": "Analysis level (aaa=quick, aaaa=medium, aaaaa=deep)"
                    },
                    "enable_esil": {
                        "type": "bool",
                        "default": True,
                        "description": "Enable ESIL emulation"
                    }
                },
                "required": []
            }
        )
    
    def initialize(self, tool_instance: Any) -> bool:
        """Initialize plugin with Radare2 instance"""
        if not self.r2_available:
            logger.error("r2pipe not available")
            return False
        
        try:
            self.r2_instance = tool_instance
            
            # Setup r2 analysis if enabled
            if self.get_config("auto_analyze", True):
                self._setup_r2_analysis()
            
            logger.info("Radare2 plugin initialized")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize Radare2 plugin: {e}")
            return False
    
    def cleanup(self) -> None:
        """Cleanup plugin resources"""
        if self.r2_available and self.r2_instance:
            try:
                # Close r2 session
                self.r2_instance.quit()
                logger.info("Radare2 plugin cleaned up")
            except Exception as e:
                logger.error(f"Failed to cleanup Radare2 plugin: {e}")
    
    def analyze(self, target: Any, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Analyze current Radare2 session"""
        if not self.r2_available:
            return {"error": "r2pipe not available"}
        
        try:
            analysis_result = {
                "binary_info": self._get_binary_info(),
                "functions": self._get_functions(),
                "imports": self._get_imports(),
                "exports": self._get_exports(),
                "strings": self._get_strings(),
                "sections": self._get_sections(),
                "xrefs": self._get_xrefs(),
                "symbols": self._get_symbols()
            }
            
            # Add ESIL analysis if enabled
            if self.get_config("enable_esil", True):
                analysis_result["esil_analysis"] = self._get_esil_analysis()
            
            logger.info(f"Radare2 analysis completed: {len(analysis_result['functions'])} functions")
            return analysis_result
            
        except Exception as e:
            logger.error(f"Radare2 analysis failed: {e}")
            return {"error": str(e)}
    
    def annotate(self, target: Any, annotations: Dict[str, Any]) -> bool:
        """Apply annotations to Radare2 session"""
        if not self.r2_available:
            return False
        
        try:
            # Apply function annotations
            if "functions" in annotations:
                for func_ann in annotations["functions"]:
                    self._annotate_function(func_ann)
            
            # Apply comments
            if "comments" in annotations:
                for comment in annotations["comments"]:
                    self._add_comment(comment)
            
            # Apply flags
            if "flags" in annotations:
                for flag in annotations["flags"]:
                    self._add_flag(flag)
            
            logger.info("Applied annotations to Radare2 session")
            return True
            
        except Exception as e:
            logger.error(f"Failed to apply annotations: {e}")
            return False
    
    def extract_annotations(self, target: Any) -> Dict[str, Any]:
        """Extract annotations from Radare2 session"""
        if not self.r2_available:
            return {}
        
        try:
            annotations = {
                "functions": self._extract_function_annotations(),
                "comments": self._extract_comments(),
                "flags": self._extract_flags(),
                "metadata": self._extract_metadata()
            }
            
            logger.info("Extracted annotations from Radare2 session")
            return annotations
            
        except Exception as e:
            logger.error(f"Failed to extract annotations: {e}")
            return {}
    
    def get_supported_file_types(self) -> List[str]:
        """Get supported file types"""
        return [
            "Portable Executable (PE)",
            "Executable and Linkable Format (ELF)",
            "Mach-O Binary",
            "Raw Binary",
            "Intel HEX",
            "Motorola S-Record",
            "COFF",
            "OAT",
            "DEX"
        ]
    
    def _setup_r2_analysis(self) -> None:
        """Setup r2 analysis"""
        if not self.r2_available:
            return
        
        try:
            analysis_level = self.get_config("analysis_level", "aaaa")
            self.r2_instance.cmd(f"{analysis_level}")
            
            logger.info(f"Performed r2 analysis level: {analysis_level}")
            
        except Exception as e:
            logger.error(f"Failed to setup r2 analysis: {e}")
    
    def _get_binary_info(self) -> Dict[str, Any]:
        """Get binary information from r2"""
        if not self.r2_available:
            return {}
        
        try:
            info = self.r2_instance.cmdj("ij")
            
            return {
                "file": info.get("file", {}),
                "bin": info.get("bin", {}),
                "core": info.get("core", {}),
                "io": info.get("io", {}),
                "anal": info.get("anal", {}),
                "dbg": info.get("dbg", {})
            }
            
        except Exception as e:
            logger.error(f"Failed to get binary info: {e}")
            return {}
    
    def _get_functions(self) -> List[Dict[str, Any]]:
        """Get function information from r2"""
        if not self.r2_available:
            return []
        
        functions = []
        
        try:
            functions_data = self.r2_instance.cmdj("aflj")
            
            for func in functions_data:
                func_info = {
                    "name": func.get("name", ""),
                    "offset": hex(func.get("offset", 0)),
                    "size": func.get("size", 0),
                    "cc": func.get("cc", "unknown"),
                    "nbbs": func.get("nbbs", 0),
                    "edges": func.get("edges", 0),
                    "ebbs": func.get("ebbs", 0),
                    "calltype": func.get("calltype", "unknown"),
                    "type": func.get("type", "unknown")
                }
                
                # Get function details
                try:
                    details = self.r2_instance.cmdj(f"pdfj @ {func.get('offset', 0)}")
                    if details:
                        func_info["disassembly"] = details.get("ops", [])
                        func_info["graph"] = details.get("blocks", [])
                except:
                    pass
                
                functions.append(func_info)
                
        except Exception as e:
            logger.error(f"Failed to get functions: {e}")
        
        return functions
    
    def _get_imports(self) -> List[Dict[str, Any]]:
        """Get import information from r2"""
        if not self.r2_available:
            return []
        
        imports = []
        
        try:
            imports_data = self.r2_instance.cmdj("iij")
            
            for imp in imports_data:
                imp_info = {
                    "name": imp.get("name", ""),
                    "plt": hex(imp.get("plt", 0)) if imp.get("plt") else None,
                    "ordinal": imp.get("ordinal"),
                    "bind": imp.get("bind", "unknown"),
                    "type": imp.get("type", "unknown")
                }
                
                imports.append(imp_info)
                
        except Exception as e:
            logger.error(f"Failed to get imports: {e}")
        
        return imports
    
    def _get_exports(self) -> List[Dict[str, Any]]:
        """Get export information from r2"""
        if not self.r2_available:
            return []
        
        exports = []
        
        try:
            exports_data = self.r2_instance.cmdj("iEj")
            
            for exp in exports_data:
                exp_info = {
                    "name": exp.get("name", ""),
                    "offset": hex(exp.get("offset", 0)),
                    "size": exp.get("size", 0),
                    "type": exp.get("type", "unknown")
                }
                
                exports.append(exp_info)
                
        except Exception as e:
            logger.error(f"Failed to get exports: {e}")
        
        return exports
    
    def _get_strings(self) -> List[Dict[str, Any]]:
        """Get string information from r2"""
        if not self.r2_available:
            return []
        
        strings = []
        
        try:
            strings_data = self.r2_instance.cmdj("izj")
            
            for string in strings_data:
                str_info = {
                    "value": string.get("string", ""),
                    "offset": hex(string.get("vaddr", 0)),
                    "length": string.get("length", 0),
                    "type": string.get("type", "ascii")
                }
                
                strings.append(str_info)
                
        except Exception as e:
            logger.error(f"Failed to get strings: {e}")
        
        return strings
    
    def _get_sections(self) -> List[Dict[str, Any]]:
        """Get section information from r2"""
        if not self.r2_available:
            return []
        
        sections = []
        
        try:
            sections_data = self.r2_instance.cmdj("iSj")
            
            for section in sections_data:
                sec_info = {
                    "name": section.get("name", ""),
                    "vaddr": hex(section.get("vaddr", 0)),
                    "vsize": section.get("vsize", 0),
                    "perm": section.get("perm", ""),
                    "arch": section.get("arch", ""),
                    "bits": section.get("bits", 0),
                    "size": section.get("size", 0)
                }
                
                sections.append(sec_info)
                
        except Exception as e:
            logger.error(f"Failed to get sections: {e}")
        
        return sections
    
    def _get_xrefs(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get cross-reference information from r2"""
        if not self.r2_available:
            return {}
        
        xrefs = {"code_refs": [], "data_refs": []}
        
        try:
            # Get all xrefs
            xrefs_data = self.r2_instance.cmdj("axfj")
            
            for xref in xrefs_data:
                xref_info = {
                    "from": hex(xref.get("from", 0)),
                    "to": hex(xref.get("to", 0)),
                    "type": xref.get("type", "unknown")
                }
                
                if xref.get("type") in ["call", "jump"]:
                    xrefs["code_refs"].append(xref_info)
                else:
                    xrefs["data_refs"].append(xref_info)
                    
        except Exception as e:
            logger.error(f"Failed to get xrefs: {e}")
        
        return xrefs
    
    def _get_symbols(self) -> List[Dict[str, Any]]:
        """Get symbol information from r2"""
        if not self.r2_available:
            return []
        
        symbols = []
        
        try:
            symbols_data = self.r2_instance.cmdj("isj")
            
            for symbol in symbols_data:
                sym_info = {
                    "name": symbol.get("name", ""),
                    "vaddr": hex(symbol.get("vaddr", 0)),
                    "bind": symbol.get("bind", "unknown"),
                    "type": symbol.get("type", "unknown"),
                    "size": symbol.get("size", 0)
                }
                
                symbols.append(sym_info)
                
        except Exception as e:
            logger.error(f"Failed to get symbols: {e}")
        
        return symbols
    
    def _get_esil_analysis(self) -> Dict[str, Any]:
        """Get ESIL analysis from r2"""
        if not self.r2_available:
            return {}
        
        try:
            # Get ESIL registers
            registers = self.r2_instance.cmdj("aerj")
            
            # Get ESIL memory info
            memory_info = self.r2_instance.cmdj("aemj")
            
            return {
                "registers": registers,
                "memory_info": memory_info
            }
            
        except Exception as e:
            logger.error(f"Failed to get ESIL analysis: {e}")
            return {}
    
    def _annotate_function(self, func_ann: Dict[str, Any]) -> None:
        """Annotate a function in r2"""
        if not self.r2_available:
            return
        
        try:
            offset = func_ann.get("offset")
            if not offset:
                return
            
            # Set function name
            if "name" in func_ann:
                self.r2_instance.cmd(f"afn {func_ann['name']} @ {offset}")
            
            # Set function comment
            if "comment" in func_ann:
                self.r2_instance.cmd(f"CCu {func_ann['comment']} @ {offset}")
                
        except Exception as e:
            logger.error(f"Failed to annotate function: {e}")
    
    def _add_comment(self, comment: Dict[str, Any]) -> None:
        """Add comment in r2"""
        if not self.r2_available:
            return
        
        try:
            offset = comment.get("offset")
            text = comment.get("text")
            
            if offset and text:
                self.r2_instance.cmd(f"CCu {text} @ {offset}")
                
        except Exception as e:
            logger.error(f"Failed to add comment: {e}")
    
    def _add_flag(self, flag: Dict[str, Any]) -> None:
        """Add flag in r2"""
        if not self.r2_available:
            return
        
        try:
            offset = flag.get("offset")
            name = flag.get("name")
            size = flag.get("size", 1)
            
            if offset and name:
                self.r2_instance.cmd(f"f {name} {size} @ {offset}")
                
        except Exception as e:
            logger.error(f"Failed to add flag: {e}")
    
    def _extract_function_annotations(self) -> List[Dict[str, Any]]:
        """Extract function annotations from r2"""
        annotations = []
        
        try:
            functions_data = self.r2_instance.cmdj("aflj")
            
            for func in functions_data:
                ann = {
                    "offset": hex(func.get("offset", 0)),
                    "name": func.get("name", ""),
                    "comment": func.get("comment", "")
                }
                annotations.append(ann)
                
        except Exception as e:
            logger.error(f"Failed to extract function annotations: {e}")
        
        return annotations
    
    def _extract_comments(self) -> List[Dict[str, Any]]:
        """Extract comments from r2"""
        comments = []
        
        try:
            comments_data = self.r2_instance.cmdj("CCj")
            
            for comment in comments_data:
                comm_info = {
                    "offset": hex(comment.get("offset", 0)),
                    "text": comment.get("text", ""),
                    "type": comment.get("type", "unknown")
                }
                comments.append(comm_info)
                
        except Exception as e:
            logger.error(f"Failed to extract comments: {e}")
        
        return comments
    
    def _extract_flags(self) -> List[Dict[str, Any]]:
        """Extract flags from r2"""
        flags = []
        
        try:
            flags_data = self.r2_instance.cmdj("fj")
            
            for flag in flags_data:
                flag_info = {
                    "name": flag.get("name", ""),
                    "offset": hex(flag.get("offset", 0)),
                    "size": flag.get("size", 0),
                    "type": flag.get("type", "unknown")
                }
                flags.append(flag_info)
                
        except Exception as e:
            logger.error(f"Failed to extract flags: {e}")
        
        return flags
    
    def _extract_metadata(self) -> Dict[str, Any]:
        """Extract metadata from r2"""
        metadata = {}
        
        try:
            # Get project info
            project_info = self.r2_instance.cmdj("Pj")
            if project_info:
                metadata["project"] = project_info
            
            # Get analysis info
            analysis_info = self.r2_instance.cmdj("afij")
            if analysis_info:
                metadata["analysis"] = analysis_info
                
        except Exception as e:
            logger.error(f"Failed to extract metadata: {e}")
        
        return metadata
