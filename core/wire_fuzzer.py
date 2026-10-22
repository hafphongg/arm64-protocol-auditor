"""
wire_fuzzer.py - Pure network-level packet synthesizer and state-machine fuzzer.
Part of the open-source ARM64 Protocol Security Auditing Framework.
Licensed under MIT License.
"""

import socket
import struct
import time
from typing import Dict, Any, Optional

class WireFuzzer:
    """
    Synthesizes custom L4 socket packets without relying on application GUI or local client dependencies.
    """

    def __init__(self, target_host: str, target_port: int, timeout: float = 5.0):
        self.host = target_host
        self.port = target_port
        self.timeout = timeout

    def build_frame(self, cmd: int, sub_cmd: int, payload: bytes, seq: int = 1) -> bytes:
        """
        Builds a standard 16-byte proprietary network header:
        FrameSize (4B), Command (2B), SubCommand (2B), MsgType (2B), Sequence (4B), Flags (2B)
        """
        frame_size = 16 + len(payload)
        header = struct.pack(">IHHHIH", frame_size, cmd, sub_cmd, 1, seq, 1)
        return header + payload

    def send_and_receive(self, packet: bytes) -> Optional[bytes]:
        """Transmits a synthesized binary frame and receives the server response."""
        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as s:
                s.sendall(packet)
                resp_header = s.recv(16)
                if len(resp_header) < 16:
                    return None
                frame_len = struct.unpack(">I", resp_header[:4])[0]
                remaining = frame_len - 16
                body = b""
                while len(body) < remaining:
                    chunk = s.recv(min(4096, remaining - len(body)))
                    if not chunk:
                        break
                    body += chunk
                return resp_header + body
        except Exception as e:
            return None
