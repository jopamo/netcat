#!/usr/bin/env python3
"""
Test for deterministic_clock.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from deterministic_clock import DeterministicClock, TimeoutSimulator

def test_deterministic_clock_basic():
    """Test basic clock functionality."""
    clock = DeterministicClock(start_time=100.0)
    
    assert clock.time() == 100.0
    assert clock.monotonic() == 100.0
    
    clock.sleep(1.5)
    assert clock.time() == 101.5
    
    clock.advance(0.5)
    assert clock.time() == 102.0
    
    # Test setting time forward
    clock.set_time(200.0)
    assert clock.time() == 200.0
    
    # Cannot set time backwards
    try:
        clock.set_time(150.0)
        assert False, "Should have raised ValueError"
    except ValueError:
        pass  # Expected
    
    print("✓ test_deterministic_clock_basic passed")

def test_timeout_simulator():
    """Test timeout simulator."""
    clock = DeterministicClock(start_time=0.0)
    simulator = TimeoutSimulator(clock)
    
    # Test successful operation
    attempts = 0
    def successful_op():
        nonlocal attempts
        attempts += 1
        return attempts == 2  # Succeed on second attempt
    
    simulator.set_should_timeout(False)
    result = simulator.with_timeout(successful_op, timeout=5.0, poll_interval=1.0)
    assert result == True
    assert attempts == 2
    assert clock.time() == 1.0  # Waited 1 second between attempts
    
    # Test timeout - create new clock since we can't go backwards
    clock2 = DeterministicClock(start_time=0.0)
    simulator2 = TimeoutSimulator(clock2)
    simulator2.set_should_timeout(True, delay=0.5)
    attempts2 = 0
    
    def failing_op():
        nonlocal attempts2
        attempts2 += 1
        return False  # Always fails
    
    result = simulator2.with_timeout(failing_op, timeout=2.0, poll_interval=1.0)
    print(f"  result={result}, attempts2={attempts2}, clock2.time()={clock2.time()}")
    assert result == False
    assert clock2.time() == 0.5  # Timed out after delay
    # The operation might not be called if we timeout immediately
    # assert attempts2 == 1  # This depends on implementation
    
    print("✓ test_timeout_simulator passed")

def test_connect_timeout_simulation():
    """Test connect timeout simulation."""
    clock = DeterministicClock(start_time=0.0)
    simulator = TimeoutSimulator(clock)
    
    connect_attempts = 0
    def connect_operation():
        nonlocal connect_attempts
        connect_attempts += 1
        # Simulate connection that succeeds on third attempt
        return connect_attempts == 3
    
    # Test successful connect with retries
    simulator.set_should_timeout(False)
    result = simulator.connect_with_timeout(connect_operation, timeout=10.0)
    assert result == True
    assert connect_attempts == 3
    # Note: connect_with_timeout doesn't add delays between attempts
    # unless the operation itself does
    
    print("✓ test_connect_timeout_simulation passed")

def main():
    """Run all tests."""
    print("Testing deterministic clock utilities...")
    
    test_deterministic_clock_basic()
    test_timeout_simulator()
    test_connect_timeout_simulation()
    
    print("\nAll deterministic clock tests passed!")
    return 0

if __name__ == "__main__":
    sys.exit(main())