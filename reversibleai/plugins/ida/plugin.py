"""
IDA Pro plugin implementation
"""

from typing import Dict, List, Any, Optional
import json

from loguru import logger

from ..base import BasePlugin, PluginInfo, AnalysisPlugin, AnnotationPlugin


class IDAPlugin(AnalysisPlugin, AnnotationPlugin):
    """IDA Pro integration plugin"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.ida_instance = None
        self.ida_available = False
        
        # Try to import IDA modules
        try:
            import idc
            import idaapi
            import idautils
            self.idc = idc
            self.idaapi = idaapi
            self.idautils = idautils
            self.ida_available = True
            logger.info("IDA Pro modules loaded successfully")
        except ImportError:
            logger.warning("IDA Pro modules not available. Running in standalone mode.")
    
    @property
    def info(self) -> PluginInfo:
        """Get plugin information"""
        return PluginInfo(
            name="ida_pro",
            version="0.1.0",
            description="IDA Pro integration plugin for ReversibleAI",
            author="ReversibleAI Team",
            supported_tools=["ida"],
            supported_architectures=["x86", "x86_64", "arm", "aarch64"],
            capabilities=["static_analysis", "annotations", "export"],
            dependencies=["idapython"],
            config_schema={
                "type": "object",
                "properties": {
                    "auto_analyze": {
                        "type": "bool",
                        "default": True,
                        "description": "Automatically analyze when IDA opens a file"
                    },
                    "export_functions": {
                        "type": "bool", 
                        "default": True,
                        "description": "Export function information"
                    },
                    "export_strings": {
                        "type": "bool",
                        "default": True,
                        "description": "Export string information"
                    }
                },
                "required": []
            }
        )
    
    def initialize(self, tool_instance: Any) -> bool:
        """Initialize plugin with IDA instance"""
        if not self.ida_available:
            logger.error("IDA Pro not available")
            return False
        
        try:
            self.ida_instance = tool_instance
            
            # Setup IDA hooks if auto-analyze is enabled
            if self.get_config("auto_analyze", True):
                self._setup_ida_hooks()
            
            # Add menu items
            self._setup_ida_menu()
            
            logger.info("IDA Pro plugin initialized")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize IDA plugin: {e}")
            return False
    
    def cleanup(self) -> None:
        """Cleanup plugin resources"""
        if self.ida_available and self.ida_instance:
            try:
                # Remove hooks
                self._remove_ida_hooks()
                
                # Remove menu items
                self._remove_ida_menu()
                
                logger.info("IDA Pro plugin cleaned up")
            except Exception as e:
                logger.error(f"Failed to cleanup IDA plugin: {e}")
    
    def analyze(self, target: Any, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Analyze current IDA database"""
        if not self.ida_available:
            return {"error": "IDA Pro not available"}
        
        try:
            analysis_result = {
                "file_info": self._get_file_info(),
                "functions": self._get_functions(),
                "segments": self._get_segments(),
                "imports": self._get_imports(),
                "exports": self._get_exports(),
                "strings": self._get_strings(),
                "xrefs": self._get_xrefs()
            }
            
            logger.info(f"IDA analysis completed: {len(analysis_result['functions'])} functions")
            return analysis_result
            
        except Exception as e:
            logger.error(f"IDA analysis failed: {e}")
            return {"error": str(e)}
    
    def annotate(self, target: Any, annotations: Dict[str, Any]) -> bool:
        """Apply annotations to IDA database"""
        if not self.ida_available:
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
            
            # Apply color coding
            if "colors" in annotations:
                for color_info in annotations["colors"]:
                    self._set_color(color_info)
            
            logger.info("Applied annotations to IDA database")
            return True
            
        except Exception as e:
            logger.error(f"Failed to apply annotations: {e}")
            return False
    
    def extract_annotations(self, target: Any) -> Dict[str, Any]:
        """Extract annotations from IDA database"""
        if not self.ida_available:
            return {}
        
        try:
            annotations = {
                "functions": self._extract_function_annotations(),
                "comments": self._extract_comments(),
                "colors": self._extract_colors(),
                "names": self._extract_names()
            }
            
            logger.info("Extracted annotations from IDA database")
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
            "Raw Binary"
        ]
    
    def _setup_ida_hooks(self) -> None:
        """Setup IDA event hooks"""
        if not self.ida_available:
            return
        
        # Define hook class
        class IDAHooks(self.idaapi.UI_Hooks):
            def ready(self):
                """Called when IDA is ready"""
                logger.info("IDA is ready, triggering auto-analysis")
                # Trigger analysis
                plugin_instance = IDAPlugin()
                result = plugin_instance.analyze(None)
                # Save or process result as needed
                return 0
        
        # Install hooks
        self.ida_hooks = IDAHooks()
        self.ida_hooks.hook()
    
    def _remove_ida_hooks(self) -> None:
        """Remove IDA hooks"""
        if hasattr(self, 'ida_hooks'):
            self.ida_hooks.unhook()
    
    def _setup_ida_menu(self) -> None:
        """Setup IDA menu items"""
        if not self.ida_available:
            return
        
        # Add menu items
        menu_items = [
            ("ReversibleAI/", "Analyze with ReversibleAI", self._menu_analyze),
            ("ReversibleAI/", "Export Analysis", self._menu_export),
            ("ReversibleAI/", "Import Annotations", self._menu_import),
            ("ReversibleAI/", "Settings", self._menu_settings)
        ]
        
        for menu_path, text, callback in menu_items:
            self.idaapi.add_menu_item(menu_path, text, callback)
    
    def _remove_ida_menu(self) -> None:
        """Remove IDA menu items"""
        if not self.ida_available:
            return
        
        # Remove menu items
        self.idaapi.del_menu_item("ReversibleAI/")
    
    def _menu_analyze(self) -> None:
        """Menu callback for analysis"""
        result = self.analyze(None)
        # Show results or save to file
        self._show_analysis_result(result)
    
    def _menu_export(self) -> None:
        """Menu callback for export"""
        # Show file dialog and export
        pass
    
    def _menu_import(self) -> None:
        """Menu callback for import"""
        # Show file dialog and import
        pass
    
    def _menu_settings(self) -> None:
        """Menu callback for settings"""
        # Show settings dialog
        pass
    
    def _get_file_info(self) -> Dict[str, Any]:
        """Get file information from IDA"""
        if not self.ida_available:
            return {}
        
        try:
            return {
                "filename": self.idc.get_input_file_path(),
                "size": self.idc.get_input_file_size(),
                "format": self.idc.get_file_type_name(),
                "architecture": self.idc.get_inf_attr(self.idc.INF_PROCNAME),
                "bits": 64 if self.idc.get_inf_attr(self.idc.INF_64BIT) else 32,
                "entry_point": hex(self.idc.get_inf_attr(self.idc.INF_START_IP)),
                "image_base": hex(self.idc.get_inf_attr(self.idc.INF_BASEADDR))
            }
        except Exception as e:
            logger.error(f"Failed to get file info: {e}")
            return {}
    
    def _get_functions(self) -> List[Dict[str, Any]]:
        """Get function information from IDA"""
        if not self.ida_available:
            return []
        
        functions = []
        
        try:
            for func in self.idautils.Functions():
                func_info = {
                    "start_address": hex(func.start_ea),
                    "end_address": hex(func.end_ea),
                    "name": func.name,
                    "size": func.size(),
                    "flags": func.flags,
                    "chunks": []
                }
                
                # Get function chunks
                for chunk in func.chunks:
                    func_info["chunks"].append({
                        "start": hex(chunk[0]),
                        "end": hex(chunk[1])
                    })
                
                functions.append(func_info)
            
        except Exception as e:
            logger.error(f"Failed to get functions: {e}")
        
        return functions
    
    def _get_segments(self) -> List[Dict[str, Any]]:
        """Get segment information from IDA"""
        if not self.ida_available:
            return []
        
        segments = []
        
        try:
            for seg in self.idautils.Segments():
                seg_info = {
                    "start_address": hex(seg.start_ea),
                    "end_address": hex(seg.end_ea),
                    "name": seg.name,
                    "size": seg.size(),
                    "permissions": seg.perm,
                    "class": seg.sel,
                    "type": seg.type
                }
                segments.append(seg_info)
                
        except Exception as e:
            logger.error(f"Failed to get segments: {e}")
        
        return segments
    
    def _get_imports(self) -> List[Dict[str, Any]]:
        """Get import information from IDA"""
        if not self.ida_available:
            return []
        
        imports = []
        
        try:
            for imp in self.idautils.Imports():
                imp_info = {
                    "address": hex(imp.ea),
                    "name": imp.name,
                    "library": imp.dll if hasattr(imp, 'dll') else "Unknown"
                }
                imports.append(imp_info)
                
        except Exception as e:
            logger.error(f"Failed to get imports: {e}")
        
        return imports
    
    def _get_exports(self) -> List[Dict[str, Any]]:
        """Get export information from IDA"""
        if not self.ida_available:
            return []
        
        exports = []
        
        try:
            for exp in self.idautils.Entries():
                if exp.is_export():
                    exp_info = {
                        "address": hex(exp.ea),
                        "name": exp.name,
                        "ordinal": exp.ordinal if hasattr(exp, 'ordinal') else None
                    }
                    exports.append(exp_info)
                    
        except Exception as e:
            logger.error(f"Failed to get exports: {e}")
        
        return exports
    
    def _get_strings(self) -> List[Dict[str, Any]]:
        """Get string information from IDA"""
        if not self.ida_available:
            return []
        
        strings = []
        
        try:
            for string in self.idautils.Strings():
                str_info = {
                    "address": hex(string.ea),
                    "value": str(string),
                    "length": string.length,
                    "type": string.type
                }
                strings.append(str_info)
                
        except Exception as e:
            logger.error(f"Failed to get strings: {e}")
        
        return strings
    
    def _get_xrefs(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get cross-reference information from IDA"""
        if not self.ida_available:
            return {}
        
        xrefs = {"code_refs": [], "data_refs": []}
        
        try:
            # Get code references
            for ref in self.idautils.Xrefs():
                ref_info = {
                    "from_address": hex(ref.frm),
                    "to_address": hex(ref.to),
                    "type": ref.type
                }
                
                if ref.iscode:
                    xrefs["code_refs"].append(ref_info)
                else:
                    xrefs["data_refs"].append(ref_info)
                    
        except Exception as e:
            logger.error(f"Failed to get xrefs: {e}")
        
        return xrefs
    
    def _annotate_function(self, func_ann: Dict[str, Any]) -> None:
        """Annotate a function in IDA"""
        if not self.ida_available:
            return
        
        try:
            address = int(func_ann["address"], 16)
            
            # Set function name
            if "name" in func_ann:
                self.idc.set_name(address, func_ann["name"])
            
            # Set function comment
            if "comment" in func_ann:
                self.idc.set_func_cmt(address, func_ann["comment"], 0)
            
            # Set repeatable comment
            if "repeatable_comment" in func_ann:
                self.idc.set_func_cmt(address, func_ann["repeatable_comment"], 1)
                
        except Exception as e:
            logger.error(f"Failed to annotate function: {e}")
    
    def _add_comment(self, comment: Dict[str, Any]) -> None:
        """Add comment in IDA"""
        if not self.ida_available:
            return
        
        try:
            address = int(comment["address"], 16)
            text = comment["text"]
            repeatable = comment.get("repeatable", False)
            
            if repeatable:
                self.idc.set_cmt(address, text, 1)
            else:
                self.idc.set_cmt(address, text, 0)
                
        except Exception as e:
            logger.error(f"Failed to add comment: {e}")
    
    def _set_color(self, color_info: Dict[str, Any]) -> None:
        """Set color in IDA"""
        if not self.ida_available:
            return
        
        try:
            address = int(color_info["address"], 16)
            color = color_info["color"]
            
            self.idc.set_color(address, self.idc.CIC_ITEM, color)
            
        except Exception as e:
            logger.error(f"Failed to set color: {e}")
    
    def _extract_function_annotations(self) -> List[Dict[str, Any]]:
        """Extract function annotations from IDA"""
        annotations = []
        
        try:
            for func in self.idautils.Functions():
                ann = {
                    "address": hex(func.start_ea),
                    "name": func.name,
                    "comment": self.idc.get_func_cmt(func.start_ea, 0),
                    "repeatable_comment": self.idc.get_func_cmt(func.start_ea, 1)
                }
                annotations.append(ann)
                
        except Exception as e:
            logger.error(f"Failed to extract function annotations: {e}")
        
        return annotations
    
    def _extract_comments(self) -> List[Dict[str, Any]]:
        """Extract comments from IDA"""
        comments = []
        
        try:
            # This is simplified - in practice you'd iterate through all addresses
            # and collect comments
            pass
            
        except Exception as e:
            logger.error(f"Failed to extract comments: {e}")
        
        return comments
    
    def _extract_colors(self) -> List[Dict[str, Any]]:
        """Extract color information from IDA"""
        colors = []
        
        try:
            # This is simplified - in practice you'd iterate through addresses
            # and collect color information
            pass
            
        except Exception as e:
            logger.error(f"Failed to extract colors: {e}")
        
        return colors
    
    def _extract_names(self) -> List[Dict[str, Any]]:
        """Extract name information from IDA"""
        names = []
        
        try:
            # This is simplified - in practice you'd iterate through addresses
            # and collect name information
            pass
            
        except Exception as e:
            logger.error(f"Failed to extract names: {e}")
        
        return names
    
    def _show_analysis_result(self, result: Dict[str, Any]) -> None:
        """Show analysis result in IDA"""
        if not self.ida_available:
            return
        
        try:
            # Create a custom view or show in output window
            result_text = json.dumps(result, indent=2)
            self.idc.msg(f"ReversibleAI Analysis Result:\n{result_text}\n")
            
        except Exception as e:
            logger.error(f"Failed to show analysis result: {e}")
