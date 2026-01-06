"""
Emulation hooks management
"""

from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass
from datetime import datetime


@dataclass
class HookEvent:
    """Represents a hook event"""
    hook_id: int
    hook_type: str
    address: Optional[int]
    timestamp: datetime
    data: Dict[str, Any]


class EmulationHooks:
    """Manages emulation hooks and events"""
    
    def __init__(self) -> None:
        self.hooks: Dict[int, Dict[str, Any]] = {}
        self.events: List[HookEvent] = []
        self.next_hook_id = 1
        self.enabled_hooks = {
            'code': True,
            'memory_read': True,
            'memory_write': True,
            'interrupt': True,
            'syscall': True,
        }
    
    def add_hook(self, hook_id: int, hook_type: str, address: Optional[int], callback: Callable) -> None:
        """Add a hook to the registry"""
        self.hooks[hook_id] = {
            'id': hook_id,
            'type': hook_type,
            'address': address,
            'callback': callback,
            'created': datetime.now(),
            'trigger_count': 0,
        }
    
    def remove_hook(self, hook_id: int) -> None:
        """Remove a hook from the registry"""
        if hook_id in self.hooks:
            del self.hooks[hook_id]
    
    def trigger_code_hook(self, address: int, size: int) -> None:
        """Trigger a code execution hook"""
        if not self.enabled_hooks['code']:
            return
        
        event = HookEvent(
            hook_id=0,  # General code hook
            hook_type='code',
            address=address,
            timestamp=datetime.now(),
            data={
                'size': size,
                'instruction_bytes': None,  # Would be populated by emulator
            }
        )
        
        self.events.append(event)
        
        # Update trigger counts for matching hooks
        for hook_info in self.hooks.values():
            if hook_info['type'] == 'code':
                if hook_info['address'] is None or hook_info['address'] == address:
                    hook_info['trigger_count'] += 1
                    
                    # Call callback if provided
                    if hook_info['callback']:
                        try:
                            hook_info['callback'](address, size)
                        except Exception as e:
                            print(f"Hook callback error: {e}")
    
    def trigger_memory_hook(self, access: int, address: int, size: int, value: int) -> None:
        """Trigger a memory access hook"""
        # Determine access type
        if access & 1:  # UC_MEM_READ
            hook_type = 'memory_read'
            if not self.enabled_hooks['memory_read']:
                return
        elif access & 2:  # UC_MEM_WRITE
            hook_type = 'memory_write'
            if not self.enabled_hooks['memory_write']:
                return
        else:
            return
        
        event = HookEvent(
            hook_id=0,
            hook_type=hook_type,
            address=address,
            timestamp=datetime.now(),
            data={
                'size': size,
                'value': value,
                'access_type': access,
            }
        )
        
        self.events.append(event)
        
        # Update trigger counts for matching hooks
        for hook_info in self.hooks.values():
            if hook_info['type'] == hook_type:
                if hook_info['address'] is None or hook_info['address'] == address:
                    hook_info['trigger_count'] += 1
                    
                    # Call callback if provided
                    if hook_info['callback']:
                        try:
                            hook_info['callback'](access, address, size, value)
                        except Exception as e:
                            print(f"Hook callback error: {e}")
    
    def trigger_interrupt_hook(self, interrupt_number: int) -> None:
        """Trigger an interrupt hook"""
        if not self.enabled_hooks['interrupt']:
            return
        
        event = HookEvent(
            hook_id=0,
            hook_type='interrupt',
            address=None,
            timestamp=datetime.now(),
            data={
                'interrupt_number': interrupt_number,
            }
        )
        
        self.events.append(event)
        
        # Update trigger counts for matching hooks
        for hook_info in self.hooks.values():
            if hook_info['type'] == 'interrupt':
                hook_info['trigger_count'] += 1
                
                # Call callback if provided
                if hook_info['callback']:
                    try:
                        hook_info['callback'](interrupt_number)
                    except Exception as e:
                        print(f"Hook callback error: {e}")
    
    def trigger_syscall_hook(self, syscall_number: int, args: List[int]) -> None:
        """Trigger a system call hook"""
        if not self.enabled_hooks['syscall']:
            return
        
        event = HookEvent(
            hook_id=0,
            hook_type='syscall',
            address=None,
            timestamp=datetime.now(),
            data={
                'syscall_number': syscall_number,
                'args': args,
            }
        )
        
        self.events.append(event)
        
        # Update trigger counts for matching hooks
        for hook_info in self.hooks.values():
            if hook_info['type'] == 'syscall':
                hook_info['trigger_count'] += 1
                
                # Call callback if provided
                if hook_info['callback']:
                    try:
                        hook_info['callback'](syscall_number, args)
                    except Exception as e:
                        print(f"Hook callback error: {e}")
    
    def get_triggered_hooks(self) -> List[Dict[str, Any]]:
        """Get all triggered hook events"""
        return [
            {
                'hook_id': event.hook_id,
                'hook_type': event.hook_type,
                'address': hex(event.address) if event.address else None,
                'timestamp': event.timestamp.isoformat(),
                'data': event.data,
            }
            for event in self.events
        ]
    
    def get_all_hooks(self) -> Dict[int, Dict[str, Any]]:
        """Get all registered hooks"""
        return self.hooks.copy()
    
    def get_hooks_by_type(self, hook_type: str) -> List[Dict[str, Any]]:
        """Get hooks by type"""
        return [hook for hook in self.hooks.values() if hook['type'] == hook_type]
    
    def get_events_by_type(self, event_type: str) -> List[HookEvent]:
        """Get events by type"""
        return [event for event in self.events if event.hook_type == event_type]
    
    def get_events_by_address(self, address: int) -> List[HookEvent]:
        """Get events by address"""
        return [event for event in self.events if event.address == address]
    
    def get_hook_statistics(self) -> Dict[str, Any]:
        """Get hook statistics"""
        stats = {
            'total_hooks': len(self.hooks),
            'total_events': len(self.events),
            'hooks_by_type': {},
            'events_by_type': {},
            'most_triggered_hooks': [],
        }
        
        # Hook type distribution
        for hook in self.hooks.values():
            hook_type = hook['type']
            stats['hooks_by_type'][hook_type] = stats['hooks_by_type'].get(hook_type, 0) + 1
        
        # Event type distribution
        for event in self.events:
            event_type = event.hook_type
            stats['events_by_type'][event_type] = stats['events_by_type'].get(event_type, 0) + 1
        
        # Most triggered hooks
        triggered_hooks = [
            (hook['id'], hook['trigger_count'])
            for hook in self.hooks.values()
            if hook['trigger_count'] > 0
        ]
        triggered_hooks.sort(key=lambda x: x[1], reverse=True)
        stats['most_triggered_hooks'] = triggered_hooks[:10]
        
        return stats
    
    def enable_hook_type(self, hook_type: str) -> None:
        """Enable a specific hook type"""
        if hook_type in self.enabled_hooks:
            self.enabled_hooks[hook_type] = True
    
    def disable_hook_type(self, hook_type: str) -> None:
        """Disable a specific hook type"""
        if hook_type in self.enabled_hooks:
            self.enabled_hooks[hook_type] = False
    
    def clear_events(self) -> None:
        """Clear all events"""
        self.events.clear()
    
    def reset(self) -> None:
        """Reset hooks manager"""
        self.hooks.clear()
        self.events.clear()
        self.next_hook_id = 1
        
        # Reset enabled hooks to default
        self.enabled_hooks = {
            'code': True,
            'memory_read': True,
            'memory_write': True,
            'interrupt': True,
            'syscall': True,
        }
    
    def export_events(self, format: str = 'json') -> str:
        """Export events to string format"""
        if format.lower() == 'json':
            import json
            return json.dumps([event.__dict__ for event in self.events], indent=2, default=str)
        elif format.lower() == 'csv':
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write header
            writer.writerow(['hook_id', 'hook_type', 'address', 'timestamp', 'data'])
            
            # Write events
            for event in self.events:
                writer.writerow([
                    event.hook_id,
                    event.hook_type,
                    hex(event.address) if event.address else '',
                    event.timestamp.isoformat(),
                    str(event.data)
                ])
            
            return output.getvalue()
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def filter_events(self, 
                     hook_type: Optional[str] = None,
                     address: Optional[int] = None,
                     start_time: Optional[datetime] = None,
                     end_time: Optional[datetime] = None) -> List[HookEvent]:
        """Filter events by criteria"""
        filtered = self.events
        
        if hook_type:
            filtered = [e for e in filtered if e.hook_type == hook_type]
        
        if address is not None:
            filtered = [e for e in filtered if e.address == address]
        
        if start_time:
            filtered = [e for e in filtered if e.timestamp >= start_time]
        
        if end_time:
            filtered = [e for e in filtered if e.timestamp <= end_time]
        
        return filtered
