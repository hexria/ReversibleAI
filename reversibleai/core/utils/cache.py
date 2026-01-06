"""
Caching utilities for ReversibleAI
"""

import functools
import hashlib
import json
from typing import Any, Callable, Dict, Optional
from pathlib import Path
from collections import OrderedDict
import time

from loguru import logger


class LRUCache:
    """LRU Cache implementation with size limit and TTL support"""
    
    def __init__(self, maxsize: int = 128, ttl: Optional[float] = None):
        """
        Initialize LRU cache
        
        Args:
            maxsize: Maximum number of items in cache
            ttl: Time to live in seconds (None for no expiration)
        """
        self.maxsize = maxsize
        self.ttl = ttl
        self.cache: OrderedDict[str, tuple[Any, float]] = OrderedDict()
        self.hits = 0
        self.misses = 0
    
    def get(self, key: str) -> Optional[Any]:
        """Get item from cache"""
        if key not in self.cache:
            self.misses += 1
            return None
        
        value, timestamp = self.cache[key]
        
        # Check TTL
        if self.ttl is not None:
            if time.time() - timestamp > self.ttl:
                del self.cache[key]
                self.misses += 1
                return None
        
        # Move to end (most recently used)
        self.cache.move_to_end(key)
        self.hits += 1
        return value
    
    def set(self, key: str, value: Any) -> None:
        """Set item in cache"""
        if key in self.cache:
            self.cache.move_to_end(key)
        elif len(self.cache) >= self.maxsize:
            # Remove oldest item
            self.cache.popitem(last=False)
        
        self.cache[key] = (value, time.time())
    
    def clear(self) -> None:
        """Clear all items from cache"""
        self.cache.clear()
        self.hits = 0
        self.misses = 0
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total = self.hits + self.misses
        hit_rate = self.hits / total if total > 0 else 0.0
        
        return {
            "size": len(self.cache),
            "maxsize": self.maxsize,
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": hit_rate,
            "ttl": self.ttl
        }


# Global cache instances
_file_hash_cache = LRUCache(maxsize=256, ttl=3600)  # 1 hour TTL
_function_cache = LRUCache(maxsize=512, ttl=1800)   # 30 minutes TTL
_string_cache = LRUCache(maxsize=1024, ttl=1800)    # 30 minutes TTL


def _make_key(*args: Any, **kwargs: Any) -> str:
    """Create cache key from arguments"""
    # Convert args and kwargs to a hashable string
    key_parts = []
    
    for arg in args:
        if isinstance(arg, (str, int, float, bool, type(None))):
            key_parts.append(str(arg))
        elif isinstance(arg, Path):
            key_parts.append(str(arg))
        elif isinstance(arg, bytes):
            # Hash bytes to avoid storing large data
            key_parts.append(hashlib.sha256(arg).hexdigest())
        else:
            # For complex objects, use JSON serialization
            try:
                key_parts.append(json.dumps(arg, sort_keys=True, default=str))
            except (TypeError, ValueError):
                # Fallback to string representation
                key_parts.append(str(arg))
    
    # Add kwargs
    if kwargs:
        sorted_kwargs = sorted(kwargs.items())
        key_parts.append(json.dumps(sorted_kwargs, sort_keys=True))
    
    # Create hash of combined key parts
    key_string = "|".join(key_parts)
    return hashlib.sha256(key_string.encode()).hexdigest()


def cache_result(cache_instance: Optional[LRUCache] = None, 
                 key_func: Optional[Callable] = None,
                 ttl: Optional[float] = None) -> Callable:
    """
    Decorator to cache function results
    
    Args:
        cache_instance: LRUCache instance to use (default: creates new one)
        key_func: Custom function to generate cache key
        ttl: Time to live in seconds
    
    Returns:
        Decorated function with caching
    """
    def decorator(func: Callable) -> Callable:
        cache = cache_instance or LRUCache(maxsize=128, ttl=ttl)
        
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                cache_key = f"{func.__module__}.{func.__name__}:{_make_key(*args, **kwargs)}"
            
            # Check cache
            result = cache.get(cache_key)
            if result is not None:
                logger.debug(f"Cache hit for {func.__name__}")
                return result
            
            # Compute result
            logger.debug(f"Cache miss for {func.__name__}")
            result = func(*args, **kwargs)
            
            # Store in cache
            cache.set(cache_key, result)
            
            return result
        
        wrapper.cache = cache
        wrapper.clear_cache = lambda: cache.clear()
        wrapper.get_cache_stats = lambda: cache.get_stats()
        
        return wrapper
    
    return decorator


def clear_cache(cache_name: Optional[str] = None) -> None:
    """
    Clear cache(s)
    
    Args:
        cache_name: Name of cache to clear (None for all)
    """
    if cache_name == "file_hash" or cache_name is None:
        _file_hash_cache.clear()
    if cache_name == "function" or cache_name is None:
        _function_cache.clear()
    if cache_name == "string" or cache_name is None:
        _string_cache.clear()
    
    logger.info(f"Cleared cache: {cache_name or 'all'}")


def get_cache_stats() -> Dict[str, Dict[str, Any]]:
    """Get statistics for all caches"""
    return {
        "file_hash": _file_hash_cache.get_stats(),
        "function": _function_cache.get_stats(),
        "string": _string_cache.get_stats()
    }


# Convenience decorators for common use cases
def cache_file_hash(func: Callable) -> Callable:
    """Cache decorator for file hash operations"""
    return cache_result(cache_instance=_file_hash_cache)(func)


def cache_function(func: Callable) -> Callable:
    """Cache decorator for function analysis"""
    return cache_result(cache_instance=_function_cache)(func)


def cache_string(func: Callable) -> Callable:
    """Cache decorator for string operations"""
    return cache_result(cache_instance=_string_cache)(func)
