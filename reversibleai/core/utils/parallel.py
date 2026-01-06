"""
Parallel processing utilities for ReversibleAI
"""

import multiprocessing
from typing import Callable, Iterable, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
import functools

from loguru import logger


def parallel_map(func: Callable,
                 iterable: Iterable[Any],
                 max_workers: Optional[int] = None,
                 use_processes: bool = False,
                 chunk_size: Optional[int] = None) -> List[Any]:
    """
    Apply function to items in parallel
    
    Args:
        func: Function to apply
        iterable: Items to process
        max_workers: Maximum number of workers (None for CPU count)
        use_processes: Use processes instead of threads
        chunk_size: Chunk size for batching (None for auto)
    
    Returns:
        List of results in same order as input
    """
    if max_workers is None:
        max_workers = multiprocessing.cpu_count()
    
    items = list(iterable)
    
    if len(items) == 0:
        return []
    
    # Use single worker for small inputs
    if len(items) == 1 or max_workers == 1:
        return [func(item) for item in items]
    
    executor_class = ProcessPoolExecutor if use_processes else ThreadPoolExecutor
    
    with executor_class(max_workers=max_workers) as executor:
        if chunk_size:
            # Process in chunks
            futures = []
            for i in range(0, len(items), chunk_size):
                chunk = items[i:i + chunk_size]
                future = executor.submit(_process_chunk, func, chunk)
                futures.append(future)
            
            results = []
            for future in futures:
                results.extend(future.result())
        else:
            # Submit all at once
            futures = {executor.submit(func, item): i for i, item in enumerate(items)}
            results = [None] * len(items)
            
            for future in as_completed(futures):
                index = futures[future]
                try:
                    results[index] = future.result()
                except Exception as e:
                    logger.error(f"Error processing item {index}: {e}")
                    results[index] = None
        
        return results


def _process_chunk(func: Callable, chunk: List[Any]) -> List[Any]:
    """Process a chunk of items"""
    return [func(item) for item in chunk]


def parallel_process(func: Callable,
                     items: List[Any],
                     max_workers: Optional[int] = None) -> List[Any]:
    """
    Process items using multiple processes
    
    Args:
        func: Function to apply
        items: Items to process
        max_workers: Maximum number of processes
    
    Returns:
        List of results
    """
    return parallel_map(func, items, max_workers=max_workers, use_processes=True)


def parallel_string_extraction(strings_data: List[bytes],
                               extract_func: Callable,
                               max_workers: Optional[int] = None) -> List[Any]:
    """
    Extract strings in parallel
    
    Args:
        strings_data: List of byte sequences to extract strings from
        extract_func: Function to extract strings from bytes
        max_workers: Maximum number of workers
    
    Returns:
        List of extracted strings
    """
    return parallel_map(extract_func, strings_data, max_workers=max_workers)


def parallel_disassembly(instructions_data: List[bytes],
                         disassemble_func: Callable,
                         max_workers: Optional[int] = None) -> List[Any]:
    """
    Disassemble instructions in parallel
    
    Args:
        instructions_data: List of byte sequences to disassemble
        disassemble_func: Function to disassemble bytes
        max_workers: Maximum number of workers
    
    Returns:
        List of disassembled instructions
    """
    return parallel_map(disassemble_func, instructions_data, max_workers=max_workers)
