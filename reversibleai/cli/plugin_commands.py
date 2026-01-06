"""
CLI commands for plugin management
"""

from pathlib import Path
from typing import Optional, Dict, Any
import json

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from reversibleai.plugins.registry import get_plugin_registry, list_plugins, load_plugin
from reversibleai.core.exceptions import PluginError

console = Console()


def cmd_plugin_list(args) -> int:
    """List all available plugins"""
    try:
        registry = get_plugin_registry()
        plugins = registry.list_plugins()
        loaded_plugins = registry.list_loaded_plugins()
        loaded_names = {p.name for p in loaded_plugins}
        
        if args.format == "json":
            output = {
                "plugins": [
                    {
                        **p.__dict__,
                        "loaded": p.name in loaded_names
                    }
                    for p in plugins
                ]
            }
            print(json.dumps(output, indent=2, default=str))
        else:
            table = Table(title="Available Plugins")
            table.add_column("Name", style="cyan")
            table.add_column("Version", style="green")
            table.add_column("Description", style="white")
            table.add_column("Status", style="yellow")
            
            for plugin_info in plugins:
                status = "Loaded" if plugin_info.name in loaded_names else "Available"
                table.add_row(
                    plugin_info.name,
                    plugin_info.version,
                    plugin_info.description[:50] + "..." if len(plugin_info.description) > 50 else plugin_info.description,
                    status
                )
            
            console.print(table)
        
        return 0
    except Exception as e:
        console.print(f"[error]❌ Failed to list plugins: {e}[/error]")
        return 1


def cmd_plugin_info(args) -> int:
    """Show detailed information about a plugin"""
    try:
        registry = get_plugin_registry()
        plugin = registry.get_plugin(args.plugin_name)
        
        if plugin is None:
            # Try to load it
            try:
                plugin = registry.load_plugin(args.plugin_name)
            except PluginError:
                console.print(f"[error]❌ Plugin not found: {args.plugin_name}[/error]")
                return 1
        
        plugin_info = plugin.info
        
        if args.format == "json":
            print(json.dumps(plugin_info.__dict__, indent=2, default=str))
        else:
            console.print(Panel(
                f"[bold blue]{plugin_info.name}[/bold blue] v{plugin_info.version}\n\n"
                f"[cyan]Description:[/cyan] {plugin_info.description}\n"
                f"[cyan]Author:[/cyan] {plugin_info.author}\n"
                f"[cyan]Supported Tools:[/cyan] {', '.join(plugin_info.supported_tools)}\n"
                f"[cyan]Supported Architectures:[/cyan] {', '.join(plugin_info.supported_architectures)}\n"
                f"[cyan]Capabilities:[/cyan] {', '.join(plugin_info.capabilities)}\n"
                f"[cyan]Status:[/cyan] {'Loaded' if plugin else 'Available'}",
                title="Plugin Information",
                border_style="blue"
            ))
        
        return 0
    except Exception as e:
        console.print(f"[error]❌ Failed to get plugin info: {e}[/error]")
        return 1


def cmd_plugin_enable(args) -> int:
    """Enable a plugin"""
    try:
        registry = get_plugin_registry()
        plugin = registry.load_plugin(args.plugin_name)
        plugin.enable()
        
        console.print(f"[success]✅ Plugin {args.plugin_name} enabled[/success]")
        return 0
    except PluginError as e:
        console.print(f"[error]❌ {e}[/error]")
        return 1
    except Exception as e:
        console.print(f"[error]❌ Failed to enable plugin: {e}[/error]")
        return 1


def cmd_plugin_disable(args) -> int:
    """Disable a plugin"""
    try:
        registry = get_plugin_registry()
        plugin = registry.get_plugin(args.plugin_name)
        
        if plugin is None:
            console.print(f"[error]❌ Plugin not loaded: {args.plugin_name}[/error]")
            return 1
        
        plugin.disable()
        console.print(f"[success]✅ Plugin {args.plugin_name} disabled[/success]")
        return 0
    except Exception as e:
        console.print(f"[error]❌ Failed to disable plugin: {e}[/error]")
        return 1


def cmd_plugin_load(args) -> int:
    """Load a plugin"""
    try:
        registry = get_plugin_registry()
        config = None
        
        if args.config:
            import yaml
            with open(args.config) as f:
                config = yaml.safe_load(f)
        
        plugin = registry.load_plugin(args.plugin_name, config)
        console.print(f"[success]✅ Plugin {args.plugin_name} loaded[/success]")
        return 0
    except PluginError as e:
        console.print(f"[error]❌ {e}[/error]")
        return 1
    except Exception as e:
        console.print(f"[error]❌ Failed to load plugin: {e}[/error]")
        return 1


def cmd_plugin_unload(args) -> int:
    """Unload a plugin"""
    try:
        registry = get_plugin_registry()
        success = registry.unload_plugin(args.plugin_name)
        
        if success:
            console.print(f"[success]✅ Plugin {args.plugin_name} unloaded[/success]")
            return 0
        else:
            console.print(f"[error]❌ Plugin not loaded: {args.plugin_name}[/error]")
            return 1
    except Exception as e:
        console.print(f"[error]❌ Failed to unload plugin: {e}[/error]")
        return 1
