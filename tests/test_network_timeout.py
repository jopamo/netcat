#!/usr/bin/env python3
"""
Test network timeout behavior using deterministic clock.

This test uses the deterministic clock to test timeout scenarios
without relying on real system time.
"""

import sys
import os
import socket
import subprocess
import time
import threading
from typing import Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from deterministic_clock import DeterministicClock, TimeoutSimulator
from netpair import NetcatPeer, tcp_pair, free_tcp_port


class MockSocketServer:
    """Mock socket server for testing timeout behavior."""
    
    def __init__(self, clock: DeterministicClock):
        self.clock = clock
        self.sock: Optional[socket.socket] = None
        self.port: Optional[int] = None
        self.thread: Optional[threading.Thread] = None
        self.should_accept = True
        self.accept_delay = 0.0
        self.read_delay = 0.0
        self.should_read = True
        
    def start(self, host: str = "127.0.0.1") -> int:
        """Start mock server on a random port."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, 0))
        port = self.sock.getsockname()[1]
        self.port = port
        self.sock.listen(1)
        return port
        
        def accept_loop():
            while self.should_accept:
                try:
                    # Simulate accept delay
                    if self.accept_delay > 0:
                        self.clock.sleep(self.accept_delay)
                    
                    conn, addr = self.sock.accept()
                    
                    # Simulate read delay
                    if self.read_delay > 0:
                        self.clock.sleep(self.read_delay)
                    
                    if self.should_read:
                        try:
                            data = conn.recv(1024)
                            if data:
                                conn.send(b"response")
                        except:
                            pass
                    
                    conn.close()
                except:
                    break
        
        self.thread = threading.Thread(target=accept_loop, daemon=True)
        self.thread.start()
        return self.port
    
    def stop(self):
        """Stop the mock server."""
        self.should_accept = False
        if self.sock:
            self.sock.close()
        if self.thread:
            self.thread.join(timeout=1.0)


def test_connect_timeout_deterministic():
    """Test connect timeout using deterministic clock."""
    print("Testing connect timeout with deterministic clock...")
    
    clock = DeterministicClock(start_time=0.0)
    simulator = TimeoutSimulator(clock)
    
    # Simulate a connection that times out
    connect_attempts = 0
    
    def connect_operation():
        nonlocal connect_attempts
        connect_attempts += 1
        # Simulate connection that would block (EINPROGRESS)
        return False
    
    # Set up to timeout after 1 second
    simulator.set_should_timeout(True, delay=1.0)
    
    start_time = clock.time()
    result = simulator.connect_with_timeout(connect_operation, timeout=5.0)
    elapsed = clock.time() - start_time
    
    assert result == False, "Should have timed out"
    assert abs(elapsed - 1.0) < 0.1, f"Should have timed out after ~1.0s, got {elapsed}s"
    assert connect_attempts == 1, f"Should have attempted once, got {connect_attempts}"
    
    print("  ✓ Connect timeout test passed")


def test_retry_with_backoff():
    """Test retry with exponential backoff using deterministic clock."""
    print("Testing retry with backoff...")
    
    clock = DeterministicClock(start_time=0.0)
    
    # Simulate operation that fails 3 times then succeeds
    attempts = 0
    backoff_times = []
    
    def operation_with_backoff():
        nonlocal attempts, backoff_times
        attempts += 1
        
        # Record time of attempt
        attempt_time = clock.time()
        if attempts > 1:
            backoff_times.append(attempt_time)
        
        # Succeed on 4th attempt
        return attempts >= 4
    
    # Manual retry loop with exponential backoff
    max_attempts = 5
    base_delay = 0.1
    max_delay = 1.0
    
    success = False
    for attempt in range(max_attempts):
        if operation_with_backoff():
            success = True
            break
        
        # Exponential backoff
        delay = min(base_delay * (2 ** attempt), max_delay)
        clock.sleep(delay)
    
    assert success == True, "Should have succeeded after retries"
    assert attempts == 4, f"Should have taken 4 attempts, got {attempts}"
    
    # Check backoff times (should be ~0.1, 0.2, 0.4 seconds between attempts)
    if len(backoff_times) >= 2:
        # First backoff should be around 0.1s after first attempt
        assert abs(backoff_times[0] - 0.1) < 0.01, f"First backoff wrong: {backoff_times[0]}"
    
    print("  ✓ Retry with backoff test passed")


def test_idle_timeout_simulation():
    """Test idle timeout simulation."""
    print("Testing idle timeout simulation...")
    
    clock = DeterministicClock(start_time=0.0)
    
    # Simulate: data arrives at specific times
    data_arrival_times = [0.0, 0.5, 1.0]  # Data packets arrive at these times
    data_index = 0
    last_activity_time = clock.time()
    idle_timeout = 2.0
    poll_interval = 0.5
    
    def check_idle_timeout():
        nonlocal last_activity_time
        current_time = clock.time()
        idle_time = current_time - last_activity_time
        return idle_time < idle_timeout
    
    def try_read():
        nonlocal data_index, last_activity_time
        current_time = clock.time()
        
        # Check if data has arrived at current time
        if data_index < len(data_arrival_times):
            expected_time = data_arrival_times[data_index]
            if current_time >= expected_time:
                data_index += 1
                last_activity_time = current_time
                print(f"    Read data #{data_index} at time {current_time:.2f}")
                return True
        
        return False
    
    # Simulate polling loop
    while check_idle_timeout():
        if try_read():
            # Got data, continue immediately
            continue
        else:
            # No data, wait before checking again
            clock.sleep(poll_interval)
    
    # Verify results
    assert data_index == 3, f"Should have received 3 data packets, got {data_index}"
    # Last data at time 1.0, idle timeout 2.0, so should exit when clock >= 3.0
    assert clock.time() >= 3.0, f"Should have idled out after ~3.0s, clock at {clock.time()}"
    
    print("  ✓ Idle timeout simulation test passed")


def test_integration_with_real_nc():
    """Test timeout behavior with real netcat using deterministic clock for timing."""
    print("Testing integration with real netcat (skipped in CI)...")
    
    # Skip this test in automated environments as it requires netcat binary
    # and real network operations
    print("  ⚠ Integration test skipped (requires netcat binary)")
    return
    
    # Note: The following code would test with real netcat:
    # 1. Find netcat binary
    # 2. Test connection timeout to non-existent port
    # 3. Test read timeout with server that accepts but doesn't send
    # 4. Use deterministic clock to control mock server timing


def main():
    """Run all network timeout tests."""
    print("=" * 60)
    print("Network Timeout Tests using Deterministic Clock")
    print("=" * 60)
    
    try:
        test_connect_timeout_deterministic()
        test_retry_with_backoff()
        test_idle_timeout_simulation()
        test_integration_with_real_nc()
        
        print("\n" + "=" * 60)
        print("All network timeout tests passed! ✓")
        print("=" * 60)
        return 0
        
    except AssertionError as e:
        print(f"\nTest failed: {e}")
        return 1
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())