"""
Main runtime emulator interface
"""

from typing import List, Dict, Any, Optional, Tuple, Union
from pathlib import Path
from dataclasses import dataclass
from enum import Enum

from loguru import logger

from .unicorn_engine import UnicornEmulator
from .hooks import EmulationHooks


class EmulationStatus(Enum):
    """Emulation status enumeration"""
    NOT_STARTED = "not_started"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    ERROR = "error"
    TIMEOUT = "timeout"


@dataclass
class EmulationResult:
    """Results of emulation session"""
    status: EmulationStatus
    start_address: int
    end_address: int
    instructions_executed: int
    execution_time: float
    final_state: Dict[str, Any]
    memory_dump: Dict[int, bytes]
    register_states: List[Dict[str, Any]]
    hooks_triggered: List[Dict[str, Any]]
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            "status": self.status.value,
            "start_address": hex(self.start_address),
            "end_address": hex(self.end_address),
            "instructions_executed": self.instructions_executed,
            "execution_time": self.execution_time,
            "final_state": self.final_state,
            "memory_dump": {hex(addr): data.hex() for addr, data in self.memory_dump.items()},
            "register_states": self.register_states,
            "hooks_triggered": self.hooks_triggered,
            "error_message": self.error_message,
        }


class RuntimeEmulator:
    """Main runtime emulator class"""
    
    def __init__(self, architecture: str, bits: int = 32) -> None:
        self.architecture = architecture.lower()
        self.bits = bits
        self.unicorn_emulator: Optional[UnicornEmulator] = None
        self.hooks: EmulationHooks = EmulationHooks()
        self.status = EmulationStatus.NOT_STARTED
        
        # Initialize emulator
        self._initialize_emulator()
    
    def _initialize_emulator(self) -> None:
        """Initialize the Unicorn emulator"""
        try:
            self.unicorn_emulator = UnicornEmulator(self.architecture, self.bits)
            logger.info(f"Initialized emulator for {self.architecture} {self.bits}-bit")
        except Exception as e:
            logger.error(f"Failed to initialize emulator: {e}")
            raise
    
    def load_code(self, code: bytes, base_address: int = 0x10000000) -> bool:
        """
        Load code into emulator memory
        
        Args:
            code: Code bytes to load
            base_address: Base address for the code
            
        Returns:
            True if successful, False otherwise
        """
        if not self.unicorn_emulator:
            logger.error("Emulator not initialized")
            return False
        
        try:
            self.unicorn_emulator.load_code(code, base_address)
            logger.info(f"Loaded {len(code)} bytes at {hex(base_address)}")
            return True
        except Exception as e:
            logger.error(f"Failed to load code: {e}")
            return False
    
    def load_binary(self, file_path: Path, base_address: Optional[int] = None) -> bool:
        """
        Load binary file into emulator
        
        Args:
            file_path: Path to binary file
            base_address: Base address (auto-detected if None)
            
        Returns:
            True if successful, False otherwise
        """
        if not self.unicorn_emulator:
            logger.error("Emulator not initialized")
            return False
        
        try:
            success = self.unicorn_emulator.load_binary(file_path, base_address)
            if success:
                logger.info(f"Loaded binary {file_path}")
            return success
        except Exception as e:
            logger.error(f"Failed to load binary: {e}")
            return False
    
    def setup_stack(self, stack_base: int = 0x7ffff000, stack_size: int = 0x10000) -> bool:
        """
        Setup stack memory
        
        Args:
            stack_base: Base address of stack
            stack_size: Size of stack
            
        Returns:
            True if successful, False otherwise
        """
        if not self.unicorn_emulator:
            logger.error("Emulator not initialized")
            return False
        
        try:
            self.unicorn_emulator.setup_stack(stack_base, stack_size)
            logger.info(f"Setup stack: base={hex(stack_base)}, size={hex(stack_size)}")
            return True
        except Exception as e:
            logger.error(f"Failed to setup stack: {e}")
            return False
    
    def emulate(self, 
                start_address: int,
                end_address: Optional[int] = None,
                timeout: float = 10.0,
                max_instructions: int = 10000) -> EmulationResult:
        """
        Start emulation
        
        Args:
            start_address: Address to start emulation
            end_address: Address to stop emulation (optional)
            timeout: Maximum execution time in seconds
            max_instructions: Maximum number of instructions to execute
            
        Returns:
            EmulationResult object with execution details
        """
        if not self.unicorn_emulator:
            logger.error("Emulator not initialized")
            return EmulationResult(
                status=EmulationStatus.ERROR,
                start_address=start_address,
                end_address=end_address or 0,
                instructions_executed=0,
                execution_time=0.0,
                final_state={},
                memory_dump={},
                register_states=[],
                hooks_triggered=[],
                error_message="Emulator not initialized"
            )
        
        self.status = EmulationStatus.RUNNING
        
        try:
            logger.info(f"Starting emulation at {hex(start_address)}")
            
            # Setup hooks
            self._setup_hooks()
            
            # Start emulation
            result = self.unicorn_emulator.emulate(
                start_address=start_address,
                end_address=end_address,
                timeout=timeout,
                max_instructions=max_instructions
            )
            
            self.status = EmulationStatus.COMPLETED
            
            # Create result object
            emulation_result = EmulationResult(
                status=result.get('status', EmulationStatus.COMPLETED),
                start_address=start_address,
                end_address=result.get('end_address', end_address or 0),
                instructions_executed=result.get('instructions_executed', 0),
                execution_time=result.get('execution_time', 0.0),
                final_state=result.get('final_state', {}),
                memory_dump=result.get('memory_dump', {}),
                register_states=result.get('register_states', []),
                hooks_triggered=self.hooks.get_triggered_hooks(),
                error_message=result.get('error_message')
            )
            
            logger.info(f"Emulation completed: {emulation_result.instructions_executed} instructions in {emulation_result.execution_time:.4f}s")
            return emulation_result
            
        except Exception as e:
            self.status = EmulationStatus.ERROR
            logger.error(f"Emulation failed: {e}")
            
            return EmulationResult(
                status=EmulationStatus.ERROR,
                start_address=start_address,
                end_address=end_address or 0,
                instructions_executed=0,
                execution_time=0.0,
                final_state={},
                memory_dump={},
                register_states=[],
                hooks_triggered=self.hooks.get_triggered_hooks(),
                error_message=str(e)
            )
    
    def _setup_hooks(self) -> None:
        """Setup emulation hooks"""
        if not self.unicorn_emulator:
            return
        
        # Setup code hooks
        self.unicorn_emulator.setup_code_hooks(self.hooks)
        
        # Setup memory hooks
        self.unicorn_emulator.setup_memory_hooks(self.hooks)
        
        # Setup interrupt hooks
        self.unicorn_emulator.setup_interrupt_hooks(self.hooks)
    
    def add_hook(self, hook_type: str, callback, address: Optional[int] = None, **kwargs) -> bool:
        """
        Add a custom hook
        
        Args:
            hook_type: Type of hook (code, memory, interrupt)
            callback: Callback function
            address: Address for hook (optional)
            **kwargs: Additional hook parameters
            
        Returns:
            True if successful, False otherwise
        """
        if not self.unicorn_emulator:
            logger.error("Emulator not initialized")
            return False
        
        try:
            hook_id = self.unicorn_emulator.add_hook(hook_type, callback, address, **kwargs)
            self.hooks.add_hook(hook_id, hook_type, address, callback)
            logger.info(f"Added {hook_type} hook at {hex(address) if address else 'all addresses'}")
            return True
        except Exception as e:
            logger.error(f"Failed to add hook: {e}")
            return False
    
    def remove_hook(self, hook_id: int) -> bool:
        """
        Remove a hook
        
        Args:
            hook_id: Hook ID to remove
            
        Returns:
            True if successful, False otherwise
        """
        if not self.unicorn_emulator:
            logger.error("Emulator not initialized")
            return False
        
        try:
            success = self.unicorn_emulator.remove_hook(hook_id)
            if success:
                self.hooks.remove_hook(hook_id)
                logger.info(f"Removed hook {hook_id}")
            return success
        except Exception as e:
            logger.error(f"Failed to remove hook: {e}")
            return False
    
    def get_registers(self) -> Dict[str, int]:
        """Get current register values"""
        if not self.unicorn_emulator:
            return {}
        
        return self.unicorn_emulator.get_registers()
    
    def set_register(self, register: str, value: int) -> bool:
        """
        Set register value
        
        Args:
            register: Register name
            value: Register value
            
        Returns:
            True if successful, False otherwise
        """
        if not self.unicorn_emulator:
            logger.error("Emulator not initialized")
            return False
        
        try:
            self.unicorn_emulator.set_register(register, value)
            logger.debug(f"Set {register} = {hex(value)}")
            return True
        except Exception as e:
            logger.error(f"Failed to set register: {e}")
            return False
    
    def read_memory(self, address: int, size: int) -> Optional[bytes]:
        """
        Read memory from emulator
        
        Args:
            address: Memory address
            size: Number of bytes to read
            
        Returns:
            Memory data or None if failed
        """
        if not self.unicorn_emulator:
            logger.error("Emulator not initialized")
            return None
        
        try:
            data = self.unicorn_emulator.read_memory(address, size)
            logger.debug(f"Read {size} bytes from {hex(address)}")
            return data
        except Exception as e:
            logger.error(f"Failed to read memory: {e}")
            return None
    
    def write_memory(self, address: int, data: bytes) -> bool:
        """
        Write memory to emulator
        
        Args:
            address: Memory address
            data: Data to write
            
        Returns:
            True if successful, False otherwise
        """
        if not self.unicorn_emulator:
            logger.error("Emulator not initialized")
            return False
        
        try:
            self.unicorn_emulator.write_memory(address, data)
            logger.debug(f"Wrote {len(data)} bytes to {hex(address)}")
            return True
        except Exception as e:
            logger.error(f"Failed to write memory: {e}")
            return False
    
    def pause(self) -> bool:
        """Pause emulation"""
        if not self.unicorn_emulator:
            return False
        
        try:
            self.unicorn_emulator.pause()
            self.status = EmulationStatus.PAUSED
            logger.info("Emulation paused")
            return True
        except Exception as e:
            logger.error(f"Failed to pause emulation: {e}")
            return False
    
    def resume(self) -> bool:
        """Resume emulation"""
        if not self.unicorn_emulator:
            return False
        
        try:
            self.unicorn_emulator.resume()
            self.status = EmulationStatus.RUNNING
            logger.info("Emulation resumed")
            return True
        except Exception as e:
            logger.error(f"Failed to resume emulation: {e}")
            return False
    
    def stop(self) -> bool:
        """Stop emulation"""
        if not self.unicorn_emulator:
            return False
        
        try:
            self.unicorn_emulator.stop()
            self.status = EmulationStatus.COMPLETED
            logger.info("Emulation stopped")
            return True
        except Exception as e:
            logger.error(f"Failed to stop emulation: {e}")
            return False
    
    def reset(self) -> bool:
        """Reset emulator state"""
        if not self.unicorn_emulator:
            return False
        
        try:
            self.unicorn_emulator.reset()
            self.status = EmulationStatus.NOT_STARTED
            self.hooks.reset()
            logger.info("Emulator reset")
            return True
        except Exception as e:
            logger.error(f"Failed to reset emulator: {e}")
            return False
    
    def get_memory_map(self) -> Dict[int, Dict[str, Any]]:
        """Get memory map"""
        if not self.unicorn_emulator:
            return {}
        
        return self.unicorn_emulator.get_memory_map()
    
    def get_emulation_statistics(self) -> Dict[str, Any]:
        """Get emulation statistics"""
        if not self.unicorn_emulator:
            return {}
        
        return {
            "status": self.status.value,
            "architecture": self.architecture,
            "bits": self.bits,
            "hooks_count": len(self.hooks.get_all_hooks()),
            "memory_regions": len(self.get_memory_map()),
            "current_registers": self.get_registers(),
        }
