"""
main.py - Entry point for the ARM64 Protocol Security Auditor Framework.
Licensed under MIT License.
"""

import sys
import argparse
from core.tlv_codec import TLVCodec
from core.crypto_auditor import StreamCipherAuditor

def main():
    parser = argparse.ArgumentParser(
        description="ARM64 Binary Protocol Security Auditor (ProtocolRecon-AI)",
        epilog="Empirical benchmark tool for testing proprietary binary protocols."
    )
    parser.add_argument("--audit-entropy", type=str, help="Hex-encoded stream sample to evaluate entropy")
    parser.add_argument("--demo", action="store_true", help="Run self-test demonstrations of TLV and Stream Cipher auditing")

    args = parser.parse_args()

    print("==================================================================")
    print("ARM64 Binary Protocol Security Auditor (ProtocolRecon-AI v1.0.0)")
    print("Open-source security research tool for binary network streams.")
    print("==================================================================")

    if args.demo or len(sys.argv) == 1:
        print("\n[*] Running Framework Self-Test...")
        
        # Test 1: TLV Packing & Unpacking
        test_payload = TLVCodec.pack(0x01, b"AuthenticationHeader") + TLVCodec.pack(0x02, b"\x00\x01\x02\x03")
        unpacked = TLVCodec.unpack(test_payload)
        print(f"[+] TLV Serializer Test: Successfully parsed {len(unpacked)} tags.")

        # Test 2: Shannon Entropy
        entropy = StreamCipherAuditor.audit_key_entropy(b"A" * 100)
        print(f"[+] Entropy Analysis Test: Monotonous stream entropy = {entropy:.2f} (Expected ~0.0)")
        print("\n[+] Framework is operational and ready for research.")

if __name__ == "__main__":
    main()
