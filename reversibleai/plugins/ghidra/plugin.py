"""
Ghidra plugin implementation
"""

from typing import Dict, List, Any, Optional
import json

from loguru import logger

from ..base import BasePlugin, PluginInfo, AnalysisPlugin, AnnotationPlugin


class GhidraPlugin(AnalysisPlugin, AnnotationPlugin):
    """Ghidra integration plugin"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.ghidra_instance = None
        self.ghidra_available = False
        
        # Try to import Ghidra modules
        try:
            from ghidra.app.decompiler import DecompInterface
            from ghidra.program.model.address import Address
            from ghidra.program.model.listing import ProgramFragment
            from ghidra.program.model.symbol import SymbolTable
            from ghidra.util.task import TaskMonitor
            
            self.DecompInterface = DecompInterface
            self.Address = Address
            self.ProgramFragment = ProgramFragment
            self.SymbolTable = SymbolTable
            self.TaskMonitor = TaskMonitor
            
            self.ghidra_available = True
            logger.info("Ghidra modules loaded successfully")
        except ImportError:
            logger.warning("Ghidra modules not available. Running in standalone mode.")
    
    @property
    def info(self) -> PluginInfo:
        """Get plugin information"""
        return PluginInfo(
            name="ghidra",
            version="0.1.0",
            description="Ghidra integration plugin for ReversibleAI",
            author="ReversibleAI Team",
            supported_tools=["ghidra"],
            supported_architectures=["x86", "x86_64", "arm", "aarch64", "mips", "ppc"],
            capabilities=["static_analysis", "annotations", "decompilation", "export"],
            dependencies=["ghidra"],
            config_schema={
                "type": "object",
                "properties": {
                    "auto_analyze": {
                        "type": "bool",
                        "default": True,
                        "description": "Automatically analyze when Ghidra opens a file"
                    },
                    "decompile_functions": {
                        "type": "bool",
                        "default": True,
                        "description": "Decompile functions during analysis"
                    },
                    "export_pcode": {
                        "type": "bool",
                        "default": False,
                        "description": "Export P-Code during analysis"
                    }
                },
                "required": []
            }
        )
    
    def initialize(self, tool_instance: Any) -> bool:
        """Initialize plugin with Ghidra instance"""
        if not self.ghidra_available:
            logger.error("Ghidra not available")
            return False
        
        try:
            self.ghidra_instance = tool_instance
            
            # Setup Ghidra event listeners
            if self.get_config("auto_analyze", True):
                self._setup_ghidra_listeners()
            
            # Add script actions
            self._setup_ghidra_actions()
            
            logger.info("Ghidra plugin initialized")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize Ghidra plugin: {e}")
            return False
    
    def cleanup(self) -> None:
        """Cleanup plugin resources"""
        if self.ghidra_available and self.ghidra_instance:
            try:
                # Remove listeners
                self._remove_ghidra_listeners()
                
                # Remove actions
                self._remove_ghidra_actions()
                
                logger.info("Ghidra plugin cleaned up")
            except Exception as e:
                logger.error(f"Failed to cleanup Ghidra plugin: {e}")
    
    def analyze(self, target: Any, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Analyze current Ghidra program"""
        if not self.ghidra_available:
            return {"error": "Ghidra not available"}
        
        try:
            current_program = self._get_current_program()
            if not current_program:
                return {"error": "No program loaded in Ghidra"}
            
            analysis_result = {
                "program_info": self._get_program_info(current_program),
                "functions": self._get_functions(current_program),
                "data_types": self._get_data_types(current_program),
                "symbols": self._get_symbols(current_program),
                "memory_blocks": self._get_memory_blocks(current_program),
                "imports": self._get_imports(current_program),
                "exports": self._get_exports(current_program)
            }
            
            # Add decompilation if enabled
            if self.get_config("decompile_functions", True):
                analysis_result["decompiled_functions"] = self._decompile_functions(current_program)
            
            logger.info(f"Ghidra analysis completed: {len(analysis_result['functions'])} functions")
            return analysis_result
            
        except Exception as e:
            logger.error(f"Ghidra analysis failed: {e}")
            return {"error": str(e)}
    
    def annotate(self, target: Any, annotations: Dict[str, Any]) -> bool:
        """Apply annotations to Ghidra program"""
        if not self.ghidra_available:
            return False
        
        try:
            current_program = self._get_current_program()
            if not current_program:
                return False
            
            # Apply function annotations
            if "functions" in annotations:
                for func_ann in annotations["functions"]:
                    self._annotate_function(current_program, func_ann)
            
            # Apply comments
            if "comments" in annotations:
                for comment in annotations["comments"]:
                    self._add_comment(current_program, comment)
            
            # Apply data type annotations
            if "data_types" in annotations:
                for dt_ann in annotations["data_types"]:
                    self._apply_data_type(current_program, dt_ann)
            
            logger.info("Applied annotations to Ghidra program")
            return True
            
        except Exception as e:
            logger.error(f"Failed to apply annotations: {e}")
            return False
    
    def extract_annotations(self, target: Any) -> Dict[str, Any]:
        """Extract annotations from Ghidra program"""
        if not self.ghidra_available:
            return {}
        
        try:
            current_program = self._get_current_program()
            if not current_program:
                return {}
            
            annotations = {
                "functions": self._extract_function_annotations(current_program),
                "comments": self._extract_comments(current_program),
                "data_types": self._extract_data_type_annotations(current_program),
                "bookmarks": self._extract_bookmarks(current_program)
            }
            
            logger.info("Extracted annotations from Ghidra program")
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
            "Binary containers (ZIP, TAR, etc.)"
        ]
    
    def _get_current_program(self):
        """Get current Ghidra program"""
        if not self.ghidra_available:
            return None
        
        try:
            from ghidra.framework.plugintool import PluginTool
            tool = PluginTool.getTool()
            if tool:
                return tool.getProgram()
            return None
        except Exception as e:
            logger.error(f"Failed to get current program: {e}")
            return None
    
    def _setup_ghidra_listeners(self) -> None:
        """Setup Ghidra event listeners"""
        if not self.ghidra_available:
            return
        
        # This would setup Ghidra-specific event listeners
        # Implementation depends on Ghidra version and API
        pass
    
    def _remove_ghidra_listeners(self) -> None:
        """Remove Ghidra listeners"""
        # Remove previously installed listeners
        pass
    
    def _setup_ghidra_actions(self) -> None:
        """Setup Ghidra script actions"""
        if not self.ghidra_available:
            return
        
        # This would setup Ghidra script actions
        # Implementation depends on Ghidra version and API
        pass
    
    def _remove_ghidra_actions(self) -> None:
        """Remove Ghidra actions"""
        # Remove previously installed actions
        pass
    
    def _get_program_info(self, program) -> Dict[str, Any]:
        """Get program information from Ghidra"""
        if not program:
            return {}
        
        try:
            image_base = program.getImageBase()
            language = program.getLanguage()
            compiler = program.getCompiler()
            
            return {
                "name": program.getName(),
                "executable_format": program.getExecutableFormat(),
                "executable_path": program.getExecutablePath(),
                "image_base": str(image_base),
                "language": str(language) if language else "Unknown",
                "compiler": str(compiler) if compiler else "Unknown",
                "address_size": program.getAddressFactory().getDefaultAddressSize() * 8,
                "creation_date": str(program.getCreationDate()) if program.getCreationDate() else None,
                "modification_date": str(program.getModificationDate()) if program.getModificationDate() else None
            }
        except Exception as e:
            logger.error(f"Failed to get program info: {e}")
            return {}
    
    def _get_functions(self, program) -> List[Dict[str, Any]]:
        """Get function information from Ghidra"""
        if not program:
            return []
        
        functions = []
        
        try:
            function_manager = program.getFunctionManager()
            func_iter = function_manager.getFunctions(True)
            
            for func in func_iter:
                func_info = {
                    "name": func.getName(),
                    "entry_point": str(func.getEntryPoint()),
                    "body": str(func.getBody()),
                    "size": func.getBody().getNumAddresses(),
                    "calling_convention": str(func.getCallingConvention()) if func.getCallingConvention() else "Unknown",
                    "return_type": str(func.getReturnType()) if func.getReturnType() else "Unknown",
                    "parameters": [],
                    "local_variables": [],
                    "is_thunk": func.isThunk(),
                    "is_external": func.isExternal(),
                    "signature": func.getPrototypeString(False, False)
                }
                
                # Get parameters
                for param in func.getParameters():
                    param_info = {
                        "name": param.getName(),
                        "type": str(param.getDataType()),
                        "ordinal": param.getOrdinal(),
                        "size": param.getLength()
                    }
                    func_info["parameters"].append(param_info)
                
                # Get local variables
                for var in func.getLocalVariables():
                    var_info = {
                        "name": var.getName(),
                        "type": str(var.getDataType()),
                        "size": var.getLength(),
                        "storage": str(var.getStorage())
                    }
                    func_info["local_variables"].append(var_info)
                
                functions.append(func_info)
                
        except Exception as e:
            logger.error(f"Failed to get functions: {e}")
        
        return functions
    
    def _get_data_types(self, program) -> List[Dict[str, Any]]:
        """Get data type information from Ghidra"""
        if not program:
            return []
        
        data_types = []
        
        try:
            data_type_manager = program.getDataTypeManager()
            
            # Get all data types
            dt_iter = data_type_manager.getAllDataTypes()
            
            for dt in dt_iter:
                dt_info = {
                    "name": dt.getName(),
                    "path": dt.getPath().getPath(),
                    "category": dt.getCategoryPath().getPath(),
                    "size": dt.getLength(),
                    "is_pointer": dt.isPointer(),
                    "is_array": dt.isArray(),
                    "is_struct": dt.isStructure(),
                    "is_union": dt.isUnion(),
                    "is_enum": dt.isEnum(),
                    "description": dt.getDescription() if dt.getDescription() else ""
                }
                
                data_types.append(dt_info)
                
        except Exception as e:
            logger.error(f"Failed to get data types: {e}")
        
        return data_types
    
    def _get_symbols(self, program) -> List[Dict[str, Any]]:
        """Get symbol information from Ghidra"""
        if not program:
            return []
        
        symbols = []
        
        try:
            symbol_table = program.getSymbolTable()
            
            # Get all symbols
            sym_iter = symbol_table.getAllSymbols(True)
            
            for symbol in sym_iter:
                sym_info = {
                    "name": symbol.getName(),
                    "address": str(symbol.getAddress()),
                    "symbol_type": str(symbol.getSymbolType()),
                    "source": str(symbol.getSource()),
                    "reference_count": symbol.getReferenceCount(),
                    "is_global": symbol.isGlobal(),
                    "is_external": symbol.isExternal(),
                    "is_primary": symbol.isPrimary()
                }
                
                symbols.append(sym_info)
                
        except Exception as e:
            logger.error(f"Failed to get symbols: {e}")
        
        return symbols
    
    def _get_memory_blocks(self, program) -> List[Dict[str, Any]]:
        """Get memory block information from Ghidra"""
        if not program:
            return []
        
        memory_blocks = []
        
        try:
            memory = program.getMemory()
            
            # Get all memory blocks
            block_iter = memory.getBlocks()
            
            for block in block_iter:
                block_info = {
                    "name": block.getName(),
                    "start_address": str(block.getStart()),
                    "end_address": str(block.getEnd()),
                    "size": block.getSize(),
                    "permissions": self._get_block_permissions(block),
                    "is_initialized": block.isInitialized(),
                    "is_loaded": block.isLoaded(),
                    "comment": block.getComment() if block.getComment() else ""
                }
                
                memory_blocks.append(block_info)
                
        except Exception as e:
            logger.error(f"Failed to get memory blocks: {e}")
        
        return memory_blocks
    
    def _get_block_permissions(self, block) -> str:
        """Get memory block permissions string"""
        permissions = ""
        
        if block.isRead():
            permissions += "R"
        if block.isWrite():
            permissions += "W"
        if block.isExecute():
            permissions += "X"
        
        return permissions or "---"
    
    def _get_imports(self, program) -> List[Dict[str, Any]]:
        """Get import information from Ghidra"""
        if not program:
            return []
        
        imports = []
        
        try:
            symbol_table = program.getSymbolTable()
            
            # Get external symbols (imports)
            ext_iter = symbol_table.getExternalSymbols()
            
            for symbol in ext_iter:
                import_info = {
                    "name": symbol.getName(),
                    "address": str(symbol.getAddress()),
                    "library": symbol.getParentNamespace() if symbol.getParentNamespace() else "Unknown",
                    "ordinal": symbol.getOrdinal() if hasattr(symbol, 'getOrdinal') else None
                }
                
                imports.append(import_info)
                
        except Exception as e:
            logger.error(f"Failed to get imports: {e}")
        
        return imports
    
    def _get_exports(self, program) -> List[Dict[str, Any]]:
        """Get export information from Ghidra"""
        if not program:
            return []
        
        exports = []
        
        try:
            symbol_table = program.getSymbolTable()
            
            # Get global symbols (exports)
            global_iter = symbol_table.getGlobalSymbols()
            
            for symbol in global_iter:
                if symbol.isExternal() == False:  # Not external means it's defined in this program
                    export_info = {
                        "name": symbol.getName(),
                        "address": str(symbol.getAddress()),
                        "ordinal": symbol.getOrdinal() if hasattr(symbol, 'getOrdinal') else None
                    }
                    
                    exports.append(export_info)
                    
        except Exception as e:
            logger.error(f"Failed to get exports: {e}")
        
        return exports
    
    def _decompile_functions(self, program) -> List[Dict[str, Any]]:
        """Decompile functions using Ghidra's decompiler"""
        if not program:
            return []
        
        decompiled_functions = []
        
        try:
            function_manager = program.getFunctionManager()
            func_iter = function_manager.getFunctions(True)
            
            # Setup decompiler interface
            decompiler = self.DecompInterface()
            
            for func in func_iter:
                try:
                    # Decompile function
                    decompiled_code = decompiler.decompileFunction(func, 30, self.TaskMonitor.DUMMY)
                    
                    if decompiled_code:
                        func_info = {
                            "name": func.getName(),
                            "entry_point": str(func.getEntryPoint()),
                            "decompiled_code": decompiled_code.getC(),
                            "decompilation_status": "success"
                        }
                    else:
                        func_info = {
                            "name": func.getName(),
                            "entry_point": str(func.getEntryPoint()),
                            "decompiled_code": "",
                            "decompilation_status": "failed"
                        }
                    
                    decompiled_functions.append(func_info)
                    
                except Exception as e:
                    logger.warning(f"Failed to decompile function {func.getName()}: {e}")
                    
                    func_info = {
                        "name": func.getName(),
                        "entry_point": str(func.getEntryPoint()),
                        "decompiled_code": "",
                        "decompilation_status": f"error: {str(e)}"
                    }
                    
                    decompiled_functions.append(func_info)
                
        except Exception as e:
            logger.error(f"Failed to setup decompiler: {e}")
        
        return decompiled_functions
    
    def _annotate_function(self, program, func_ann: Dict[str, Any]) -> None:
        """Annotate a function in Ghidra"""
        if not program:
            return
        
        try:
            # Get function by address
            address = program.getAddressFactory().getAddress(func_ann["address"])
            if not address:
                return
            
            function_manager = program.getFunctionManager()
            func = function_manager.getFunctionAt(address)
            
            if not func:
                return
            
            # Set function name
            if "name" in func_ann:
                func.setName(func_ann["name"])
            
            # Set function comment
            if "comment" in func_ann:
                func.setComment(func_ann["comment"])
                
        except Exception as e:
            logger.error(f"Failed to annotate function: {e}")
    
    def _add_comment(self, program, comment: Dict[str, Any]) -> None:
        """Add comment in Ghidra"""
        if not program:
            return
        
        try:
            address = program.getAddressFactory().getAddress(comment["address"])
            if not address:
                return
            
            # Set comment at address
            code_unit = program.getListing().getCodeUnitAt(address)
            if code_unit:
                code_unit.setComment(comment["text"])
                
        except Exception as e:
            logger.error(f"Failed to add comment: {e}")
    
    def _apply_data_type(self, program, dt_ann: Dict[str, Any]) -> None:
        """Apply data type in Ghidra"""
        if not program:
            return
        
        try:
            address = program.getAddressFactory().getAddress(dt_ann["address"])
            if not address:
                return
            
            data_type_manager = program.getDataTypeManager()
            data_type = data_type_manager.getDataType(dt_ann["type_name"])
            
            if data_type:
                # Apply data type at address
                program.getListing().createData(address, data_type)
                
        except Exception as e:
            logger.error(f"Failed to apply data type: {e}")
    
    def _extract_function_annotations(self, program) -> List[Dict[str, Any]]:
        """Extract function annotations from Ghidra"""
        annotations = []
        
        try:
            function_manager = program.getFunctionManager()
            func_iter = function_manager.getFunctions(True)
            
            for func in func_iter:
                ann = {
                    "address": str(func.getEntryPoint()),
                    "name": func.getName(),
                    "comment": func.getComment() if func.getComment() else ""
                }
                annotations.append(ann)
                
        except Exception as e:
            logger.error(f"Failed to extract function annotations: {e}")
        
        return annotations
    
    def _extract_comments(self, program) -> List[Dict[str, Any]]:
        """Extract comments from Ghidra"""
        comments = []
        
        try:
            # This is simplified - in practice you'd iterate through code units
            # and collect comments
            pass
            
        except Exception as e:
            logger.error(f"Failed to extract comments: {e}")
        
        return comments
    
    def _extract_data_type_annotations(self, program) -> List[Dict[str, Any]]:
        """Extract data type annotations from Ghidra"""
        annotations = []
        
        try:
            # This is simplified - in practice you'd iterate through data items
            # and collect type information
            pass
            
        except Exception as e:
            logger.error(f"Failed to extract data type annotations: {e}")
        
        return annotations
    
    def _extract_bookmarks(self, program) -> List[Dict[str, Any]]:
        """Extract bookmarks from Ghidra"""
        bookmarks = []
        
        try:
            # This is simplified - in practice you'd use Ghidra's bookmark manager
            pass
            
        except Exception as e:
            logger.error(f"Failed to extract bookmarks: {e}")
        
        return bookmarks
