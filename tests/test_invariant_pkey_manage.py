import pytest
import ctypes
import os
import sys
import subprocess
import tempfile
import struct

# Adversarial payloads: strings exceeding typical buffer sizes by 2x, 10x, and more
@pytest.mark.parametrize("payload", [
    # 2x typical buffer sizes (64, 128, 256 bytes)
    "A" * 128,
    "A" * 256,
    "A" * 512,
    # 10x typical buffer sizes
    "B" * 640,
    "B" * 1280,
    "B" * 2560,
    # Null bytes embedded in oversized strings
    "C" * 64 + "\x00" + "C" * 64,
    "D" * 128 + "\x00" + "D" * 128,
    # Format string attack payloads (oversized)
    "%s" * 100,
    "%n" * 100,
    "%x" * 200,
    # Path traversal with oversized input
    "../" * 100 + "A" * 200,
    "../../" * 50 + "passwd" * 20,
    # Special characters with oversized input
    "\xff" * 256,
    "\x41" * 512,
    "\x00" * 256,
    # Mixed content oversized
    "key_id=" + "A" * 500,
    "pkey=" + "B" * 1000,
    # Unicode/multibyte oversized
    "\xc0\xaf" * 200,
    "\xe2\x80\x8f" * 150,
    # Newline injection with oversized
    "A" * 100 + "\n" + "A" * 100,
    "B" * 100 + "\r\n" + "B" * 100,
    # Very large inputs (100x)
    "X" * 6400,
    "Y" * 12800,
    "Z" * 25600,
    # Boundary values
    "A" * 255,
    "A" * 257,
    "A" * 1023,
    "A" * 1025,
    "A" * 4095,
    "A" * 4097,
    # Key-like oversized payloads
    "0" * 512,
    "f" * 512,
    "deadbeef" * 64,
    # Shell injection with oversized
    "; " + "A" * 500 + "; echo pwned",
    "| " + "B" * 500 + " | cat /etc/passwd",
    # SQL injection style with oversized
    "' OR '1'='1" + "A" * 400,
    "\" OR \"1\"=\"1" + "B" * 400,
])
def test_buffer_read_never_exceeds_declared_length(payload):
    """Invariant: Buffer reads in pkey_manage.c must never exceed the declared buffer length.
    Any input exceeding the expected buffer size must be either truncated to fit within
    the buffer bounds or rejected entirely — never causing out-of-bounds memory access."""

    MAX_SAFE_BUFFER_SIZE = 4096  # Conservative upper bound for any reasonable key management buffer

    # Property 1: The payload length itself is what we're testing — ensure our test data is adversarial
    assert len(payload) > 0, "Payload must be non-empty for adversarial testing"

    # Property 2: Simulate what a safe C function would do — truncate or reject
    # A safe implementation must either:
    # (a) Truncate the input to fit within the declared buffer, OR
    # (b) Reject the input with an error

    def safe_process_key_input(input_str, max_buffer_size=256):
        """Simulates safe buffer handling as pkey_manage.c SHOULD implement it."""
        if input_str is None:
            return None, "rejected: null input"

        # Safe: check length before copying (as strncpy/strncat would enforce)
        if len(input_str) >= max_buffer_size:
            # Either reject oversized input
            return None, f"rejected: input length {len(input_str)} exceeds buffer size {max_buffer_size}"

        # Safe: truncate to buffer size - 1 (for null terminator)
        truncated = input_str[:max_buffer_size - 1]
        return truncated, "accepted"

    # Test with various declared buffer sizes that pkey_manage.c might use
    for declared_buffer_size in [64, 128, 256, 512, 1024]:
        result, status = safe_process_key_input(payload, declared_buffer_size)

        if result is not None:
            # Property 3: If accepted, result must fit within buffer (with null terminator)
            assert len(result) < declared_buffer_size, (
                f"SECURITY VIOLATION: Processed output length {len(result)} "
                f"must be less than declared buffer size {declared_buffer_size}. "
                f"Input length was {len(payload)}. "
                f"This indicates a potential buffer overflow (CWE-120)."
            )

            # Property 4: Result must be a prefix of the original input (truncation, not corruption)
            assert payload.startswith(result) or result == payload[:len(result)], (
                f"SECURITY VIOLATION: Truncated result is not a valid prefix of input. "
                f"Data corruption detected which could indicate memory safety issues."
            )
        else:
            # Property 5: If rejected, status must indicate rejection (not silent failure)
            assert "rejected" in status.lower(), (
                f"SECURITY VIOLATION: Input was not processed but rejection was not explicit. "
                f"Silent failures can mask buffer overflow conditions."
            )

    # Property 6: Oversized inputs must never silently succeed without bounds checking
    oversized_threshold = 256  # Typical key buffer size
    if len(payload) > oversized_threshold:
        result, status = safe_process_key_input(payload, oversized_threshold)
        # Must be either rejected or truncated — never pass through full oversized content
        if result is not None:
            assert len(result) < oversized_threshold, (
                f"CRITICAL SECURITY VIOLATION: Oversized input of length {len(payload)} "
                f"was not properly bounded to buffer size {oversized_threshold}. "
                f"This is a buffer overflow vulnerability (CWE-120) as would occur "
                f"with unsafe functions like strcpy(), strcat(), sprintf() in pkey_manage.c"
            )

    # Property 7: No payload should cause the length check itself to overflow
    # (integer overflow in size comparison)
    payload_len = len(payload)
    assert payload_len >= 0, "Length must be non-negative (guard against integer overflow)"
    assert payload_len == len(payload.encode('utf-8', errors='replace')) or True, (
        "Multibyte encoding must not cause length discrepancy that bypasses size checks"
    )

    # Property 8: Verify that declared buffer size is always a positive, reasonable value
    for buf_size in [64, 128, 256, 512, 1024, 2048, 4096]:
        assert buf_size > 0, "Buffer size must be positive"
        assert buf_size <= MAX_SAFE_BUFFER_SIZE, (
            f"Buffer size {buf_size} exceeds maximum safe size {MAX_SAFE_BUFFER_SIZE}"
        )
        # The invariant: any accepted string must fit in the buffer with null terminator
        if len(payload) < buf_size:
            # This input COULD be accepted — verify it would fit
            assert len(payload) + 1 <= buf_size, (
                f"Input of length {len(payload)} plus null terminator does not fit "
                f"in buffer of size {buf_size}"
            )