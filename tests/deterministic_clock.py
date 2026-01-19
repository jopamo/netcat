"""
Deterministic clock for testing timeout and retry logic.

This module provides a clock that can be controlled deterministically
for testing timeout, backoff, and retry behavior.
"""

import time
from typing import Optional, Callable

class DeterministicClock:
    """A deterministic clock for testing."""
    
    def __init__(self, start_time: float = 0.0):
        """
        Initialize deterministic clock.
        
        Args:
            start_time: Initial clock time in seconds
        """
        self._current_time = start_time
        self._real_start = time.monotonic()
        self._time_scale = 1.0  # Real time scaling factor
        
    def time(self) -> float:
        """Get current deterministic time in seconds."""
        return self._current_time
    
    def monotonic(self) -> float:
        """Get current deterministic monotonic time in seconds."""
        return self._current_time
    
    def sleep(self, seconds: float) -> None:
        """Advance deterministic time by seconds."""
        if seconds < 0:
            raise ValueError("sleep length must be non-negative")
        self._current_time += seconds
        
    def advance(self, seconds: float) -> None:
        """Alias for sleep."""
        self.sleep(seconds)
        
    def set_time(self, new_time: float) -> None:
        """Set deterministic time to new_time."""
        if new_time < self._current_time:
            raise ValueError("Cannot set time backwards")
        self._current_time = new_time
        
    def real_time_elapsed(self) -> float:
        """Get real time elapsed since clock creation."""
        return time.monotonic() - self._real_start
    
    def sync_to_real_time(self) -> None:
        """
        Sync deterministic time to match real elapsed time.
        
        Useful for tests that mix deterministic and real time.
        """
        self._current_time = self.real_time_elapsed()


class TimeoutSimulator:
    """Simulate timeout behavior deterministically."""
    
    def __init__(self, clock: DeterministicClock):
        """
        Initialize timeout simulator.
        
        Args:
            clock: DeterministicClock instance
        """
        self.clock = clock
        self._should_timeout = False
        self._timeout_delay = 0.0
        self._timeout_count = 0
        
    def set_should_timeout(self, should_timeout: bool, delay: float = 0.0) -> None:
        """
        Configure whether next operation should timeout.
        
        Args:
            should_timeout: If True, next operation will timeout
            delay: How long to wait before timing out (default: 0)
        """
        self._should_timeout = should_timeout
        self._timeout_delay = delay
        self._timeout_count = 0
        
    def with_timeout(self, operation: Callable, timeout: float, 
                     poll_interval: float = 0.1) -> bool:
        """
        Execute operation with timeout simulation.
        
        Args:
            operation: Callable that returns True if successful, False if should retry
            timeout: Maximum time to wait in seconds
            poll_interval: How often to retry operation
            
        Returns:
            True if operation succeeded, False if timed out
        """
        deadline = self.clock.time() + timeout
        attempts = 0
        
        while self.clock.time() < deadline:
            attempts += 1
            
            # Try the operation first
            if operation():
                return True
                
            # Check if we should timeout after failed operation
            if self._should_timeout and attempts > self._timeout_count:
                self.clock.advance(self._timeout_delay)
                self._timeout_count = attempts
                return False
                
            # Wait before retrying
            wait_time = min(poll_interval, deadline - self.clock.time())
            if wait_time > 0:
                self.clock.advance(wait_time)
                
        return False
    
    def connect_with_timeout(self, connect_fn: Callable, timeout: float) -> bool:
        """
        Simulate connect with timeout.
        
        Args:
            connect_fn: Function that attempts connection, returns True on success
            timeout: Connection timeout in seconds
            
        Returns:
            True if connected, False if timed out
        """
        return self.with_timeout(connect_fn, timeout)
    
    def poll_with_timeout(self, poll_fn: Callable, timeout: float) -> bool:
        """
        Simulate poll with timeout.
        
        Args:
            poll_fn: Function that checks poll status, returns True if ready
            timeout: Poll timeout in seconds
            
        Returns:
            True if ready, False if timed out
        """
        return self.with_timeout(poll_fn, timeout)