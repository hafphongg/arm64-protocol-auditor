"""
crypto_auditor.py - Automated detection of weak cryptographic stream ciphers and key derivation flaws.
Part of the open-source ARM64 Protocol Security Auditing Framework.
Licensed under MIT License.
"""

import hashlib
from typing import Optional, Tuple

class StreamCipherAuditor:
    """
    Audits proprietary application network streams for weak XOR/Stream cipher implementations,
    specifically detecting derivation seams from unauthenticated packet headers (CWE-327 / CWE-321).
    """

    @staticmethod
    def derive_xor_keystream(master_key: bytes, header_metadata: bytes, target_length: int) -> bytes:
        """
        Simulates iterative key derivation using static master keys mixed with packet frame fields.
        """
        seed = hashlib.md5(master_key + header_metadata).digest()
        keystream = bytearray()
        while len(keystream) < target_length:
            keystream.extend(seed)
        return bytes(keystream[:target_length])

    @staticmethod
    def decrypt_stream(ciphertext: bytes, keystream: bytes) -> bytes:
        """Performs XOR stream cipher decryption using a recovered keystream."""
        return bytes([c ^ k for c, k in zip(ciphertext, keystream)])

    @staticmethod
    def audit_key_entropy(sample_bytes: bytes) -> float:
        """Calculates Shannon entropy to detect whether a payload is cleartext, compressed, or encrypted."""
        import math
        if not sample_bytes:
            return 0.0
        entropy = 0.0
        for x in range(256):
            p_x = float(sample_bytes.count(x)) / len(sample_bytes)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy
