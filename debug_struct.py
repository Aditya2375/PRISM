import struct

# Original format with spaces
fmt1 = 'B 32s 1120s 12s d 64s'
print('fmt1 size:', struct.calcsize(fmt1))
# Test packing with spaces
try:
    result = struct.pack(fmt1, 1, b'\x00' * 32, b'\x00' * 1120, b'\x00' * 12, struct.pack('d', 1795689174.044687), b'\x00' * 64)
    print('fmt1 pack success, len:', len(result))
except Exception as e:
    print('fmt1 error:', type(e).__name__, ':', e)

# Without spaces
fmt2 = 'B32s1120s12sd64s'
print('fmt2 size:', struct.calcsize(fmt2))
try:
    result = struct.pack(fmt2, 1, b'\x00' * 32, b'\x00' * 1120, b'\x00' * 12, struct.pack('d', 1795689174.044687), b'\x00' * 64)
    print('fmt2 pack success, len:', len(result))
except Exception as e:
    print('fmt2 error:', type(e).__name__, ':', e)

# Original format with d separated
fmt3 = 'B 32s 1120s 12s d 64s'
print('fmt3 size:', struct.calcsize(fmt3))
try:
    d_val = struct.pack('d', 1795689174.044687)
    result = struct.pack(fmt3, 1, b'\x00' * 32, b'\x00' * 1120, b'\x00' * 12, d_val, b'\x00' * 64)
    print('fmt3 pack success, len:', len(result))
except Exception as e:
    print('fmt3 error:', type(e).__name__, ':', e)