"""
API information database for function annotations
"""

from typing import Dict, List, Any, Optional
import json
from pathlib import Path

from loguru import logger


class APIInfo:
    """API information database for common Windows and Linux APIs"""
    
    def __init__(self) -> None:
        self.api_database: Dict[str, Dict[str, Any]] = {}
        self._load_builtin_api_info()
    
    def _load_builtin_api_info(self) -> None:
        """Load built-in API information"""
        # Windows API information
        windows_apis = {
            # File operations
            "CreateFileA": {
                "description": "Creates or opens a file, directory, or I/O device",
                "parameters": [
                    {"name": "lpFileName", "type": "LPCSTR", "description": "File name"},
                    {"name": "dwDesiredAccess", "type": "DWORD", "description": "Access mode"},
                    {"name": "dwShareMode", "type": "DWORD", "description": "Share mode"},
                    {"name": "lpSecurityAttributes", "type": "LPSECURITY_ATTRIBUTES", "description": "Security attributes"},
                    {"name": "dwCreationDisposition", "type": "DWORD", "description": "Creation disposition"},
                    {"name": "dwFlagsAndAttributes", "type": "DWORD", "description": "File attributes"},
                    {"name": "hTemplateFile", "type": "HANDLE", "description": "Template file handle"}
                ],
                "return_value": {"type": "HANDLE", "description": "File handle or INVALID_HANDLE_VALUE"},
                "calling_convention": "stdcall",
                "tags": ["file", "io", "windows"],
                "confidence": 0.9,
                "source": "windows_api"
            },
            "CreateFileW": {
                "description": "Creates or opens a file, directory, or I/O device (Unicode)",
                "parameters": [
                    {"name": "lpFileName", "type": "LPCWSTR", "description": "File name"},
                    {"name": "dwDesiredAccess", "type": "DWORD", "description": "Access mode"},
                    {"name": "dwShareMode", "type": "DWORD", "description": "Share mode"},
                    {"name": "lpSecurityAttributes", "type": "LPSECURITY_ATTRIBUTES", "description": "Security attributes"},
                    {"name": "dwCreationDisposition", "type": "DWORD", "description": "Creation disposition"},
                    {"name": "dwFlagsAndAttributes", "type": "DWORD", "description": "File attributes"},
                    {"name": "hTemplateFile", "type": "HANDLE", "description": "Template file handle"}
                ],
                "return_value": {"type": "HANDLE", "description": "File handle or INVALID_HANDLE_VALUE"},
                "calling_convention": "stdcall",
                "tags": ["file", "io", "windows"],
                "confidence": 0.9,
                "source": "windows_api"
            },
            "ReadFile": {
                "description": "Reads data from a file",
                "parameters": [
                    {"name": "hFile", "type": "HANDLE", "description": "File handle"},
                    {"name": "lpBuffer", "type": "LPVOID", "description": "Buffer to read data into"},
                    {"name": "nNumberOfBytesToRead", "type": "DWORD", "description": "Number of bytes to read"},
                    {"name": "lpNumberOfBytesRead", "type": "LPDWORD", "description": "Number of bytes read"},
                    {"name": "lpOverlapped", "type": "LPOVERLAPPED", "description": "Overlapped structure"}
                ],
                "return_value": {"type": "BOOL", "description": "Success status"},
                "calling_convention": "stdcall",
                "tags": ["file", "io", "windows"],
                "confidence": 0.9,
                "source": "windows_api"
            },
            "WriteFile": {
                "description": "Writes data to a file",
                "parameters": [
                    {"name": "hFile", "type": "HANDLE", "description": "File handle"},
                    {"name": "lpBuffer", "type": "LPCVOID", "description": "Buffer to write from"},
                    {"name": "nNumberOfBytesToWrite", "type": "DWORD", "description": "Number of bytes to write"},
                    {"name": "lpNumberOfBytesWritten", "type": "LPDWORD", "description": "Number of bytes written"},
                    {"name": "lpOverlapped", "type": "LPOVERLAPPED", "description": "Overlapped structure"}
                ],
                "return_value": {"type": "BOOL", "description": "Success status"},
                "calling_convention": "stdcall",
                "tags": ["file", "io", "windows"],
                "confidence": 0.9,
                "source": "windows_api"
            },
            
            # Process operations
            "CreateProcessA": {
                "description": "Creates a new process and its primary thread",
                "parameters": [
                    {"name": "lpApplicationName", "type": "LPCSTR", "description": "Application name"},
                    {"name": "lpCommandLine", "type": "LPSTR", "description": "Command line"},
                    {"name": "lpProcessAttributes", "type": "LPSECURITY_ATTRIBUTES", "description": "Process security"},
                    {"name": "lpThreadAttributes", "type": "LPSECURITY_ATTRIBUTES", "description": "Thread security"},
                    {"name": "bInheritHandles", "type": "BOOL", "description": "Handle inheritance"},
                    {"name": "dwCreationFlags", "type": "DWORD", "description": "Creation flags"},
                    {"name": "lpEnvironment", "type": "LPVOID", "description": "Environment block"},
                    {"name": "lpCurrentDirectory", "type": "LPCSTR", "description": "Current directory"},
                    {"name": "lpStartupInfo", "type": "LPSTARTUPINFOA", "description": "Startup info"},
                    {"name": "lpProcessInformation", "type": "LPPROCESS_INFORMATION", "description": "Process info"}
                ],
                "return_value": {"type": "BOOL", "description": "Success status"},
                "calling_convention": "stdcall",
                "tags": ["process", "windows", "malware"],
                "confidence": 0.9,
                "source": "windows_api"
            },
            "CreateProcessW": {
                "description": "Creates a new process and its primary thread (Unicode)",
                "parameters": [
                    {"name": "lpApplicationName", "type": "LPCWSTR", "description": "Application name"},
                    {"name": "lpCommandLine", "type": "LPWSTR", "description": "Command line"},
                    {"name": "lpProcessAttributes", "type": "LPSECURITY_ATTRIBUTES", "description": "Process security"},
                    {"name": "lpThreadAttributes", "type": "LPSECURITY_ATTRIBUTES", "description": "Thread security"},
                    {"name": "bInheritHandles", "type": "BOOL", "description": "Handle inheritance"},
                    {"name": "dwCreationFlags", "type": "DWORD", "description": "Creation flags"},
                    {"name": "lpEnvironment", "type": "LPVOID", "description": "Environment block"},
                    {"name": "lpCurrentDirectory", "type": "LPCWSTR", "description": "Current directory"},
                    {"name": "lpStartupInfo", "type": "LPSTARTUPINFOW", "description": "Startup info"},
                    {"name": "lpProcessInformation", "type": "LPPROCESS_INFORMATION", "description": "Process info"}
                ],
                "return_value": {"type": "BOOL", "description": "Success status"},
                "calling_convention": "stdcall",
                "tags": ["process", "windows", "malware"],
                "confidence": 0.9,
                "source": "windows_api"
            },
            "VirtualAlloc": {
                "description": "Reserves or commits a region of memory",
                "parameters": [
                    {"name": "lpAddress", "type": "LPVOID", "description": "Starting address"},
                    {"name": "dwSize", "type": "SIZE_T", "description": "Size of region"},
                    {"name": "flAllocationType", "type": "DWORD", "description": "Allocation type"},
                    {"name": "flProtect", "type": "DWORD", "description": "Memory protection"}
                ],
                "return_value": {"type": "LPVOID", "description": "Base address of allocated region"},
                "calling_convention": "stdcall",
                "tags": ["memory", "windows", "malware"],
                "confidence": 0.9,
                "source": "windows_api"
            },
            "VirtualFree": {
                "description": "Releases or decommits a region of memory",
                "parameters": [
                    {"name": "lpAddress", "type": "LPVOID", "description": "Base address"},
                    {"name": "dwSize", "type": "SIZE_T", "description": "Size of region"},
                    {"name": "dwFreeType", "type": "DWORD", "description": "Free type"}
                ],
                "return_value": {"type": "BOOL", "description": "Success status"},
                "calling_convention": "stdcall",
                "tags": ["memory", "windows"],
                "confidence": 0.9,
                "source": "windows_api"
            },
            
            # Network operations
            "WSAStartup": {
                "description": "Initiates Winsock usage",
                "parameters": [
                    {"name": "wVersionRequested", "type": "WORD", "description": "Winsock version"},
                    {"name": "lpWSAData", "type": "LPWSADATA", "description": "WSADATA structure"}
                ],
                "return_value": {"type": "int", "description": "Error code"},
                "calling_convention": "stdcall",
                "tags": ["network", "windows", "winsock"],
                "confidence": 0.9,
                "source": "windows_api"
            },
            "socket": {
                "description": "Creates a socket",
                "parameters": [
                    {"name": "af", "type": "int", "description": "Address family"},
                    {"name": "type", "type": "int", "description": "Socket type"},
                    {"name": "protocol", "type": "int", "description": "Protocol"}
                ],
                "return_value": {"type": "SOCKET", "description": "Socket descriptor"},
                "calling_convention": "stdcall",
                "tags": ["network", "windows", "socket"],
                "confidence": 0.9,
                "source": "windows_api"
            },
            "connect": {
                "description": "Establishes a connection to a specified socket",
                "parameters": [
                    {"name": "s", "type": "SOCKET", "description": "Socket descriptor"},
                    {"name": "name", "type": "const struct sockaddr*", "description": "Socket address"},
                    {"name": "namelen", "type": "int", "description": "Address length"}
                ],
                "return_value": {"type": "int", "description": "Error code"},
                "calling_convention": "stdcall",
                "tags": ["network", "windows", "socket"],
                "confidence": 0.9,
                "source": "windows_api"
            },
            
            # Registry operations
            "RegOpenKeyExA": {
                "description": "Opens a specified registry key",
                "parameters": [
                    {"name": "hKey", "type": "HKEY", "description": "Handle to open key"},
                    {"name": "lpSubKey", "type": "LPCSTR", "description": "Name of subkey to open"},
                    {"name": "ulOptions", "type": "DWORD", "description": "Reserved"},
                    {"name": "samDesired", "type": "REGSAM", "description": "Access mask"},
                    {"name": "phkResult", "type": "PHKEY", "description": "Handle to opened key"}
                ],
                "return_value": {"type": "LSTATUS", "description": "Error code"},
                "calling_convention": "stdcall",
                "tags": ["registry", "windows"],
                "confidence": 0.9,
                "source": "windows_api"
            },
            "RegSetValueExA": {
                "description": "Sets the data and type of a specified value under a registry key",
                "parameters": [
                    {"name": "hKey", "type": "HKEY", "description": "Handle to open key"},
                    {"name": "lpValueName", "type": "LPCSTR", "description": "Name of value to set"},
                    {"name": "Reserved", "type": "DWORD", "description": "Reserved"},
                    {"name": "dwType", "type": "DWORD", "description": "Type of value"},
                    {"name": "lpData", "type": "const BYTE*", "description": "Value data"},
                    {"name": "cbData", "type": "DWORD", "description": "Size of value data"}
                ],
                "return_value": {"type": "LSTATUS", "description": "Error code"},
                "calling_convention": "stdcall",
                "tags": ["registry", "windows"],
                "confidence": 0.9,
                "source": "windows_api"
            },
            
            # Synchronization
            "CreateMutexA": {
                "description": "Creates or opens a named or unnamed mutex object",
                "parameters": [
                    {"name": "lpMutexAttributes", "type": "LPSECURITY_ATTRIBUTES", "description": "Security attributes"},
                    {"name": "bInitialOwner", "type": "BOOL", "description": "Initial ownership"},
                    {"name": "lpName", "type": "LPCSTR", "description": "Mutex name"}
                ],
                "return_value": {"type": "HANDLE", "description": "Mutex handle"},
                "calling_convention": "stdcall",
                "tags": ["synchronization", "windows"],
                "confidence": 0.9,
                "source": "windows_api"
            },
            "WaitForSingleObject": {
                "description": "Waits until the specified object is in the signaled state",
                "parameters": [
                    {"name": "hHandle", "type": "HANDLE", "description": "Object handle"},
                    {"name": "dwMilliseconds", "type": "DWORD", "description": "Timeout interval"}
                ],
                "return_value": {"type": "DWORD", "description": "Wait result"},
                "calling_convention": "stdcall",
                "tags": ["synchronization", "windows"],
                "confidence": 0.9,
                "source": "windows_api"
            }
        }
        
        # Linux/POSIX API information
        linux_apis = {
            "open": {
                "description": "Opens a file or device",
                "parameters": [
                    {"name": "pathname", "type": "const char*", "description": "File path"},
                    {"name": "flags", "type": "int", "description": "Access flags"},
                    {"name": "mode", "type": "mode_t", "description": "File mode"}
                ],
                "return_value": {"type": "int", "description": "File descriptor or -1 on error"},
                "calling_convention": "cdecl",
                "tags": ["file", "io", "linux", "posix"],
                "confidence": 0.9,
                "source": "posix"
            },
            "read": {
                "description": "Reads from a file descriptor",
                "parameters": [
                    {"name": "fd", "type": "int", "description": "File descriptor"},
                    {"name": "buf", "type": "void*", "description": "Buffer"},
                    {"name": "count", "type": "size_t", "description": "Number of bytes to read"}
                ],
                "return_value": {"type": "ssize_t", "description": "Number of bytes read or -1 on error"},
                "calling_convention": "cdecl",
                "tags": ["file", "io", "linux", "posix"],
                "confidence": 0.9,
                "source": "posix"
            },
            "write": {
                "description": "Writes to a file descriptor",
                "parameters": [
                    {"name": "fd", "type": "int", "description": "File descriptor"},
                    {"name": "buf", "type": "const void*", "description": "Buffer"},
                    {"name": "count", "type": "size_t", "description": "Number of bytes to write"}
                ],
                "return_value": {"type": "ssize_t", "description": "Number of bytes written or -1 on error"},
                "calling_convention": "cdecl",
                "tags": ["file", "io", "linux", "posix"],
                "confidence": 0.9,
                "source": "posix"
            },
            "fork": {
                "description": "Creates a new process",
                "parameters": [],
                "return_value": {"type": "pid_t", "description": "Child process ID in parent, 0 in child, -1 on error"},
                "calling_convention": "cdecl",
                "tags": ["process", "linux", "posix"],
                "confidence": 0.9,
                "source": "posix"
            },
            "execve": {
                "description": "Executes a program",
                "parameters": [
                    {"name": "pathname", "type": "const char*", "description": "Program path"},
                    {"name": "argv", "type": "char* const*", "description": "Program arguments"},
                    {"name": "envp", "type": "char* const*", "description": "Environment variables"}
                ],
                "return_value": {"type": "int", "description": "-1 on error (doesn't return on success)"},
                "calling_convention": "cdecl",
                "tags": ["process", "linux", "posix"],
                "confidence": 0.9,
                "source": "posix"
            },
            "malloc": {
                "description": "Allocates memory",
                "parameters": [
                    {"name": "size", "type": "size_t", "description": "Size to allocate"}
                ],
                "return_value": {"type": "void*", "description": "Pointer to allocated memory or NULL"},
                "calling_convention": "cdecl",
                "tags": ["memory", "linux", "posix", "c_standard"],
                "confidence": 0.9,
                "source": "libc"
            },
            "free": {
                "description": "Frees allocated memory",
                "parameters": [
                    {"name": "ptr", "type": "void*", "description": "Pointer to free"}
                ],
                "return_value": {"type": "void", "description": "No return value"},
                "calling_convention": "cdecl",
                "tags": ["memory", "linux", "posix", "c_standard"],
                "confidence": 0.9,
                "source": "libc"
            },
            "socket": {
                "description": "Creates a socket",
                "parameters": [
                    {"name": "domain", "type": "int", "description": "Communication domain"},
                    {"name": "type", "type": "int", "description": "Socket type"},
                    {"name": "protocol", "type": "int", "description": "Protocol"}
                ],
                "return_value": {"type": "int", "description": "Socket descriptor or -1 on error"},
                "calling_convention": "cdecl",
                "tags": ["network", "linux", "posix"],
                "confidence": 0.9,
                "source": "posix"
            },
            "connect": {
                "description": "Connects a socket to an address",
                "parameters": [
                    {"name": "sockfd", "type": "int", "description": "Socket descriptor"},
                    {"name": "addr", "type": "const struct sockaddr*", "description": "Socket address"},
                    {"name": "addrlen", "type": "socklen_t", "description": "Address length"}
                ],
                "return_value": {"type": "int", "description": "0 on success, -1 on error"},
                "calling_convention": "cdecl",
                "tags": ["network", "linux", "posix"],
                "confidence": 0.9,
                "source": "posix"
            }
        }
        
        # Common C library functions
        libc_functions = {
            "printf": {
                "description": "Prints formatted output to stdout",
                "parameters": [
                    {"name": "format", "type": "const char*", "description": "Format string"},
                    {"name": "...", "type": "...", "description": "Additional arguments"}
                ],
                "return_value": {"type": "int", "description": "Number of characters printed"},
                "calling_convention": "cdecl",
                "tags": ["io", "c_standard", "format_string"],
                "confidence": 0.9,
                "source": "libc"
            },
            "sprintf": {
                "description": "Writes formatted output to a string",
                "parameters": [
                    {"name": "str", "type": "char*", "description": "Destination buffer"},
                    {"name": "format", "type": "const char*", "description": "Format string"},
                    {"name": "...", "type": "...", "description": "Additional arguments"}
                ],
                "return_value": {"type": "int", "description": "Number of characters written"},
                "calling_convention": "cdecl",
                "tags": ["io", "c_standard", "format_string", "buffer_overflow"],
                "confidence": 0.9,
                "source": "libc"
            },
            "strcpy": {
                "description": "Copies a string",
                "parameters": [
                    {"name": "dest", "type": "char*", "description": "Destination buffer"},
                    {"name": "src", "type": "const char*", "description": "Source string"}
                ],
                "return_value": {"type": "char*", "description": "Destination buffer"},
                "calling_convention": "cdecl",
                "tags": ["c_standard", "string", "buffer_overflow"],
                "confidence": 0.9,
                "source": "libc"
            },
            "strcat": {
                "description": "Concatenates two strings",
                "parameters": [
                    {"name": "dest", "type": "char*", "description": "Destination buffer"},
                    {"name": "src", "type": "const char*", "description": "Source string"}
                ],
                "return_value": {"type": "char*", "description": "Destination buffer"},
                "calling_convention": "cdecl",
                "tags": ["c_standard", "string", "buffer_overflow"],
                "confidence": 0.9,
                "source": "libc"
            },
            "strlen": {
                "description": "Calculates the length of a string",
                "parameters": [
                    {"name": "str", "type": "const char*", "description": "String to measure"}
                ],
                "return_value": {"type": "size_t", "description": "String length"},
                "calling_convention": "cdecl",
                "tags": ["c_standard", "string"],
                "confidence": 0.9,
                "source": "libc"
            },
            "memcpy": {
                "description": "Copies memory area",
                "parameters": [
                    {"name": "dest", "type": "void*", "description": "Destination buffer"},
                    {"name": "src", "type": "const void*", "description": "Source buffer"},
                    {"name": "n", "type": "size_t", "description": "Number of bytes to copy"}
                ],
                "return_value": {"type": "void*", "description": "Destination buffer"},
                "calling_convention": "cdecl",
                "tags": ["c_standard", "memory"],
                "confidence": 0.9,
                "source": "libc"
            },
            "memset": {
                "description": "Fills memory with a constant byte",
                "parameters": [
                    {"name": "s", "type": "void*", "description": "Memory area"},
                    {"name": "c", "type": "int", "description": "Byte value"},
                    {"name": "n", "type": "size_t", "description": "Number of bytes"}
                ],
                "return_value": {"type": "void*", "description": "Memory area"},
                "calling_convention": "cdecl",
                "tags": ["c_standard", "memory"],
                "confidence": 0.9,
                "source": "libc"
            }
        }
        
        # Combine all APIs
        self.api_database.update(windows_apis)
        self.api_database.update(linux_apis)
        self.api_database.update(libc_functions)
        
        logger.debug(f"Loaded {len(self.api_database)} API definitions")
    
    def get_function_info(self, function_name: str) -> Optional[Dict[str, Any]]:
        """Get information about a function"""
        # Try exact match first
        if function_name in self.api_database:
            return self.api_database[function_name]
        
        # Try case-insensitive match
        function_lower = function_name.lower()
        for api_name, api_info in self.api_database.items():
            if api_name.lower() == function_lower:
                return api_info
        
        # Try partial match
        for api_name, api_info in self.api_database.items():
            if function_lower in api_name.lower() or api_name.lower() in function_lower:
                return api_info
        
        return None
    
    def search_functions(self, query: str) -> List[Dict[str, Any]]:
        """Search for functions by name, description, or tags"""
        query_lower = query.lower()
        results = []
        
        for api_name, api_info in self.api_database.items():
            if (query_lower in api_name.lower() or
                query_lower in api_info.get('description', '').lower() or
                any(query_lower in tag.lower() for tag in api_info.get('tags', []))):
                results.append({
                    'name': api_name,
                    **api_info
                })
        
        return results
    
    def get_functions_by_tag(self, tag: str) -> List[Dict[str, Any]]:
        """Get all functions with a specific tag"""
        tag_lower = tag.lower()
        results = []
        
        for api_name, api_info in self.api_database.items():
            if any(tag_lower == t.lower() for t in api_info.get('tags', [])):
                results.append({
                    'name': api_name,
                    **api_info
                })
        
        return results
    
    def get_functions_by_source(self, source: str) -> List[Dict[str, Any]]:
        """Get all functions from a specific source"""
        results = []
        
        for api_name, api_info in self.api_database.items():
            if api_info.get('source') == source:
                results.append({
                    'name': api_name,
                    **api_info
                })
        
        return results
    
    def get_malware_relevant_apis(self) -> List[Dict[str, Any]]:
        """Get APIs commonly used in malware"""
        malware_tags = ['malware', 'buffer_overflow', 'format_string']
        results = []
        
        for api_name, api_info in self.api_database.items():
            if any(tag in api_info.get('tags', []) for tag in malware_tags):
                results.append({
                    'name': api_name,
                    **api_info
                })
        
        return results
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get API database statistics"""
        stats = {
            'total_apis': len(self.api_database),
            'sources': {},
            'tags': {},
            'calling_conventions': {},
        }
        
        for api_info in self.api_database.values():
            # Source distribution
            source = api_info.get('source', 'unknown')
            stats['sources'][source] = stats['sources'].get(source, 0) + 1
            
            # Tag distribution
            for tag in api_info.get('tags', []):
                stats['tags'][tag] = stats['tags'].get(tag, 0) + 1
            
            # Calling convention distribution
            cc = api_info.get('calling_convention', 'unknown')
            stats['calling_conventions'][cc] = stats['calling_conventions'].get(cc, 0) + 1
        
        return stats
    
    def add_custom_api(self, name: str, info: Dict[str, Any]) -> bool:
        """Add a custom API definition"""
        try:
            # Validate required fields
            required_fields = ['description', 'parameters', 'return_value']
            for field in required_fields:
                if field not in info:
                    logger.error(f"Missing required field: {field}")
                    return False
            
            # Set default values
            info.setdefault('calling_convention', 'cdecl')
            info.setdefault('tags', [])
            info.setdefault('confidence', 0.7)
            info.setdefault('source', 'custom')
            
            self.api_database[name] = info
            logger.info(f"Added custom API: {name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add custom API: {e}")
            return False
    
    def remove_api(self, name: str) -> bool:
        """Remove an API definition"""
        if name in self.api_database:
            del self.api_database[name]
            logger.info(f"Removed API: {name}")
            return True
        return False
    
    def export_api_database(self, output_path: Path) -> bool:
        """Export API database to file"""
        try:
            with open(output_path, 'w') as f:
                json.dump(self.api_database, f, indent=2)
            
            logger.info(f"Exported API database to {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export API database: {e}")
            return False
    
    def import_api_database(self, input_path: Path) -> int:
        """Import API database from file"""
        try:
            with open(input_path, 'r') as f:
                imported_apis = json.load(f)
            
            count = 0
            for name, info in imported_apis.items():
                self.api_database[name] = info
                count += 1
            
            logger.info(f"Imported {count} APIs from {input_path}")
            return count
            
        except Exception as e:
            logger.error(f"Failed to import API database: {e}")
            return 0
