"""
Unicorn engine wrapper for emulation
"""

from typing import Dict, Any, Optional, List, Callable
from pathlib import Path
import time
import struct

from loguru import logger

try:
    import unicorn
    from unicorn import Uc, UC_ARCH, UC_MODE
    from unicorn.x86_const import UC_X86_REG_EIP, UC_X86_REG_ESP, UC_X86_REG_EBP
    from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_SP
    from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_SP
    UNICORN_AVAILABLE = True
except ImportError:
    logger.warning("Unicorn engine not available. Runtime emulation will be limited.")
    UNICORN_AVAILABLE = False

from .hooks import EmulationHooks


class UnicornEmulator:
    """Unicorn engine wrapper for CPU emulation"""
    
    def __init__(self, architecture: str, bits: int) -> None:
        if not UNICORN_AVAILABLE:
            raise ImportError("Unicorn engine is not available")
        
        self.architecture = architecture.lower()
        self.bits = bits
        self.uc: Optional[Uc] = None
        self.hooks: Dict[int, Dict[str, Any]] = {}
        self.next_hook_id = 1
        
        # Architecture-specific constants
        self._setup_architecture_constants()
        
        # Initialize emulator
        self._initialize_emulator()
    
    def _setup_architecture_constants(self) -> None:
        """Setup architecture-specific constants"""
        if self.architecture == "x86":
            self.arch = UC_ARCH.X86
            self.mode = UC_MODE.MODE_32
            self.pc_reg = UC_X86_REG_EIP
            self.sp_reg = UC_X86_REG_ESP
            self.bp_reg = UC_X86_REG_EBP
        elif self.architecture == "x86_64":
            self.arch = UC_ARCH.X86
            self.mode = UC_MODE.MODE_64
            self.pc_reg = None  # Will be set based on Unicorn constants
            self.sp_reg = None
            self.bp_reg = None
        elif self.architecture == "arm":
            self.arch = UC_ARCH.ARM
            self.mode = UC_MODE.MODE_ARM
            self.pc_reg = UC_ARM_REG_PC
            self.sp_reg = UC_ARM_REG_SP
            self.bp_reg = None
        elif self.architecture == "aarch64":
            self.arch = UC_ARCH.ARM64
            self.mode = UC_MODE.MODE_ARM
            self.pc_reg = UC_ARM64_REG_PC
            self.sp_reg = UC_ARM64_REG_SP
            self.bp_reg = None
        else:
            raise ValueError(f"Unsupported architecture: {self.architecture}")
    
    def _initialize_emulator(self) -> None:
        """Initialize Unicorn emulator"""
        try:
            self.uc = Uc(self.arch, self.mode)
            logger.debug(f"Initialized Unicorn for {self.architecture} {self.bits}-bit")
        except Exception as e:
            logger.error(f"Failed to initialize Unicorn: {e}")
            raise
    
    def load_code(self, code: bytes, base_address: int) -> None:
        """Load code into emulator memory"""
        if not self.uc:
            raise RuntimeError("Emulator not initialized")
        
        # Map memory for code
        self.uc.mem_map(base_address, len(code) + 0x1000)  # Add extra space
        
        # Write code to memory
        self.uc.mem_write(base_address, code)
        
        # Set instruction pointer
        self._set_pc(base_address)
    
    def load_binary(self, file_path: Path, base_address: Optional[int] = None) -> bool:
        """Load binary file into emulator"""
        if not self.uc:
            raise RuntimeError("Emulator not initialized")
        
        try:
            with open(file_path, 'rb') as f:
                binary_data = f.read()
            
            if base_address is None:
                base_address = 0x10000000  # Default base address
            
            # Map memory for binary
            self.uc.mem_map(base_address, len(binary_data) + 0x10000)
            
            # Write binary to memory
            self.uc.mem_write(base_address, binary_data)
            
            # Set instruction pointer to entry point
            self._set_pc(base_address)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to load binary: {e}")
            return False
    
    def setup_stack(self, stack_base: int, stack_size: int) -> None:
        """Setup stack memory"""
        if not self.uc:
            raise RuntimeError("Emulator not initialized")
        
        # Map stack memory
        self.uc.mem_map(stack_base - stack_size, stack_size)
        
        # Set stack pointer
        self._set_sp(stack_base)
    
    def emulate(self, 
                start_address: int,
                end_address: Optional[int] = None,
                timeout: float = 10.0,
                max_instructions: int = 10000) -> Dict[str, Any]:
        """Run emulation"""
        if not self.uc:
            raise RuntimeError("Emulator not initialized")
        
        start_time = time.time()
        instructions_executed = 0
        
        try:
            # Set start address
            self._set_pc(start_address)
            
            # Emulate
            if end_address:
                self.uc.emu_start(start_address, end_address, timeout=int(timeout * 1000000))
            else:
                # Emulate until timeout or max instructions
                self.uc.emu_start(start_address, 0xFFFFFFFF, timeout=int(timeout * 1000000))
            
            execution_time = time.time() - start_time
            
            # Get final state
            final_state = self.get_registers()
            
            return {
                'status': 'completed',
                'end_address': self._get_pc(),
                'instructions_executed': instructions_executed,
                'execution_time': execution_time,
                'final_state': final_state,
                'memory_dump': {},  # Would need to implement memory dumping
                'register_states': [final_state],  # Simplified
                'error_message': None
            }
            
        except unicorn.UcError as e:
            execution_time = time.time() - start_time
            
            error_message = str(e)
            if "UC_ERR_TIMEOUT" in error_message:
                status = 'timeout'
            else:
                status = 'error'
            
            return {
                'status': status,
                'end_address': self._get_pc(),
                'instructions_executed': instructions_executed,
                'execution_time': execution_time,
                'final_state': self.get_registers(),
                'memory_dump': {},
                'register_states': [self.get_registers()],
                'error_message': error_message
            }
    
    def setup_code_hooks(self, hooks_manager: EmulationHooks) -> None:
        """Setup code execution hooks"""
        if not self.uc:
            return
        
        def code_hook(uc, address, size, user_data):
            hooks_manager.trigger_code_hook(address, size)
        
        self.uc.hook_add(unicorn.UC_HOOK_CODE, code_hook)
    
    def setup_memory_hooks(self, hooks_manager: EmulationHooks) -> None:
        """Setup memory access hooks"""
        if not self.uc:
            return
        
        def mem_hook(uc, access, address, size, value, user_data):
            hooks_manager.trigger_memory_hook(access, address, size, value)
        
        self.uc.hook_add(unicorn.UC_HOOK_MEM_READ | unicorn.UC_HOOK_MEM_WRITE, mem_hook)
    
    def setup_interrupt_hooks(self, hooks_manager: EmulationHooks) -> None:
        """Setup interrupt hooks"""
        if not self.uc:
            return
        
        def intr_hook(uc, intno, user_data):
            hooks_manager.trigger_interrupt_hook(intno)
        
        self.uc.hook_add(unicorn.UC_HOOK_INTR, intr_hook)
    
    def add_hook(self, hook_type: str, callback, address: Optional[int] = None, **kwargs) -> int:
        """Add a custom hook"""
        if not self.uc:
            raise RuntimeError("Emulator not initialized")
        
        hook_id = self.next_hook_id
        self.next_hook_id += 1
        
        try:
            if hook_type == "code":
                if address:
                    hook = self.uc.hook_add(unicorn.UC_HOOK_CODE, callback, address, address)
                else:
                    hook = self.uc.hook_add(unicorn.UC_HOOK_CODE, callback)
            elif hook_type == "mem_read":
                hook = self.uc.hook_add(unicorn.UC_HOOK_MEM_READ, callback)
            elif hook_type == "mem_write":
                hook = self.uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, callback)
            elif hook_type == "interrupt":
                hook = self.uc.hook_add(unicorn.UC_HOOK_INTR, callback)
            else:
                raise ValueError(f"Unsupported hook type: {hook_type}")
            
            self.hooks[hook_id] = {
                'type': hook_type,
                'address': address,
                'callback': callback,
                'unicorn_hook': hook
            }
            
            return hook_id
            
        except Exception as e:
            logger.error(f"Failed to add hook: {e}")
            raise
    
    def remove_hook(self, hook_id: int) -> bool:
        """Remove a hook"""
        if hook_id not in self.hooks:
            return False
        
        try:
            hook_info = self.hooks[hook_id]
            self.uc.hook_del(hook_info['unicorn_hook'])
            del self.hooks[hook_id]
            return True
        except Exception as e:
            logger.error(f"Failed to remove hook: {e}")
            return False
    
    def get_registers(self) -> Dict[str, int]:
        """Get current register values"""
        if not self.uc:
            return {}
        
        registers = {}
        
        try:
            if self.architecture == "x86":
                # x86 registers
                registers['eax'] = self.uc.reg_read(unicorn.x86_const.UC_X86_REG_EAX)
                registers['ebx'] = self.uc.reg_read(unicorn.x86_const.UC_X86_REG_EBX)
                registers['ecx'] = self.uc.reg_read(unicorn.x86_const.UC_X86_REG_ECX)
                registers['edx'] = self.uc.reg_read(unicorn.x86_const.UC_X86_REG_EDX)
                registers['esi'] = self.uc.reg_read(unicorn.x86_const.UC_X86_REG_ESI)
                registers['edi'] = self.uc.reg_read(unicorn.x86_const.UC_X86_REG_EDI)
                registers['ebp'] = self.uc.reg_read(unicorn.x86_const.UC_X86_REG_EBP)
                registers['esp'] = self.uc.reg_read(unicorn.x86_const.UC_X86_REG_ESP)
                registers['eip'] = self.uc.reg_read(unicorn.x86_const.UC_X86_REG_EIP)
            
            elif self.architecture == "arm":
                # ARM registers
                for i in range(13):
                    registers[f'r{i}'] = self.uc.reg_read(getattr(unicorn.arm_const, f'UC_ARM_REG_R{i}'))
                registers['sp'] = self.uc.reg_read(unicorn.arm_const.UC_ARM_REG_SP)
                registers['lr'] = self.uc.reg_read(unicorn.arm_const.UC_ARM_REG_LR)
                registers['pc'] = self.uc.reg_read(unicorn.arm_const.UC_ARM_REG_PC)
            
        except Exception as e:
            logger.error(f"Failed to read registers: {e}")
        
        return registers
    
    def set_register(self, register: str, value: int) -> None:
        """Set register value"""
        if not self.uc:
            raise RuntimeError("Emulator not initialized")
        
        try:
            if self.architecture == "x86":
                reg_map = {
                    'eax': unicorn.x86_const.UC_X86_REG_EAX,
                    'ebx': unicorn.x86_const.UC_X86_REG_EBX,
                    'ecx': unicorn.x86_const.UC_X86_REG_ECX,
                    'edx': unicorn.x86_const.UC_X86_REG_EDX,
                    'esi': unicorn.x86_const.UC_X86_REG_ESI,
                    'edi': unicorn.x86_const.UC_X86_REG_EDI,
                    'ebp': unicorn.x86_const.UC_X86_REG_EBP,
                    'esp': unicorn.x86_const.UC_X86_REG_ESP,
                    'eip': unicorn.x86_const.UC_X86_REG_EIP,
                }
                
                if register.lower() in reg_map:
                    self.uc.reg_write(reg_map[register.lower()], value)
                else:
                    raise ValueError(f"Unknown register: {register}")
            
            elif self.architecture == "arm":
                reg_map = {}
                for i in range(13):
                    reg_map[f'r{i}'] = getattr(unicorn.arm_const, f'UC_ARM_REG_R{i}')
                reg_map['sp'] = unicorn.arm_const.UC_ARM_REG_SP
                reg_map['lr'] = unicorn.arm_const.UC_ARM_REG_LR
                reg_map['pc'] = unicorn.arm_const.UC_ARM_REG_PC
                
                if register.lower() in reg_map:
                    self.uc.reg_write(reg_map[register.lower()], value)
                else:
                    raise ValueError(f"Unknown register: {register}")
            
        except Exception as e:
            logger.error(f"Failed to set register: {e}")
            raise
    
    def read_memory(self, address: int, size: int) -> bytes:
        """Read memory from emulator"""
        if not self.uc:
            raise RuntimeError("Emulator not initialized")
        
        return self.uc.mem_read(address, size)
    
    def write_memory(self, address: int, data: bytes) -> None:
        """Write memory to emulator"""
        if not self.uc:
            raise RuntimeError("Emulator not initialized")
        
        self.uc.mem_write(address, data)
    
    def pause(self) -> None:
        """Pause emulation"""
        if not self.uc:
            return
        
        self.uc.emu_stop()
    
    def resume(self) -> None:
        """Resume emulation"""
        # Unicorn doesn't have a direct resume function
        # This would need to be implemented with state management
        pass
    
    def stop(self) -> None:
        """Stop emulation"""
        if not self.uc:
            return
        
        self.uc.emu_stop()
    
    def reset(self) -> None:
        """Reset emulator"""
        if not self.uc:
            return
        
        # Close current instance and create new one
        self.uc.close()
        self._initialize_emulator()
        self.hooks.clear()
        self.next_hook_id = 1
    
    def get_memory_map(self) -> Dict[int, Dict[str, Any]]:
        """Get memory map"""
        # Unicorn doesn't provide direct memory map access
        # This would need to be implemented by tracking memory mappings
        return {}
    
    def _set_pc(self, address: int) -> None:
        """Set program counter"""
        if self.pc_reg:
            self.uc.reg_write(self.pc_reg, address)
    
    def _get_pc(self) -> int:
        """Get program counter"""
        if self.pc_reg:
            return self.uc.reg_read(self.pc_reg)
        return 0
    
    def _set_sp(self, address: int) -> None:
        """Set stack pointer"""
        if self.sp_reg:
            self.uc.reg_write(self.sp_reg, address)
    
    def _get_sp(self) -> int:
        """Get stack pointer"""
        if self.sp_reg:
            return self.uc.reg_read(self.sp_reg)
        return 0
