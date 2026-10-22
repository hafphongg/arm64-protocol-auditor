"""
tlv_codec.py - Generic Binary TLV (Type-Length-Value) Serializer and Deserializer.
Part of the open-source ARM64 Protocol Security Auditing Framework.
Licensed under MIT License.
"""

import struct
from typing import List, Tuple, Dict, Any, Optional

class TLVCodec:
    """
    High-performance binary codec for parsing and synthesizing 
    custom TLV structures commonly found in mobile ARM64 application runtimes.
    """

    @staticmethod
    def pack(tag: int, value: bytes) -> bytes:
        """Packs a single TLV element with a 4-byte big-endian tag and 4-byte length."""
        return struct.pack(">II", tag, len(value)) + value

    @staticmethod
    def unpack(stream: bytes) -> List[Tuple[int, bytes]]:
        """Unpacks a raw byte stream into a list of (tag, value_bytes) tuples."""
        results = []
        offset = 0
        total_len = len(stream)
        while offset + 8 <= total_len:
            tag, length = struct.unpack_from(">II", stream, offset)
            offset += 8
            if offset + length > total_len:
                break
            val = stream[offset:offset+length]
            results.append((tag, val))
            offset += length
        return results

    @staticmethod
    def pack_nested(tag: int, sub_items: List[Tuple[int, bytes]]) -> bytes:
        """Packs nested TLV elements inside a parent container."""
        inner_stream = b"".join(TLVCodec.pack(t, v) for t, v in sub_items)
        return TLVCodec.pack(tag, inner_stream)
