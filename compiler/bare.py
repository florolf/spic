def pack_uint(val: int) -> bytes:
    assert val >= 0

    out = bytearray()
    while True:
        new_val = val >> 7

        if new_val == 0:
            out.append(val & 0x7f)
            return bytes(out)
        else:
            out.append(0x80 | (val & 0x7f))
            val = new_val

def unpack_uint(buf: bytearray) -> int:
    val = 0
    shift = 0

    while True:
        c = buf.pop(0)

        val = val | ((c & 0x7f) << shift)
        if c & 0x80 == 0:
            break

        shift += 7

    return val

def unpack_fixed(buf: bytearray, length: int) -> bytes:
    out = bytes(buf[:length])
    del buf[:length]

    return out

def unpack_data(buf: bytearray) -> bytes:
    length = unpack_uint(buf)

    return unpack_fixed(buf, length)
