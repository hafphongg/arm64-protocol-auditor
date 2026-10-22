# ARM64 Binary Protocol Recon & Automated Security Auditing Framework (ProtocolRecon-AI)

An open-source, AI-driven framework designed to automate the reconstruction, semantic decoding, and vulnerability discovery of proprietary binary network protocols (TLV/custom wire framing) on ARM64 platforms.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)

---

## 1. Research Background & Real-World Impact
Mobile applications frequently employ proprietary binary transport protocols over TCP port 443 instead of standard HTTPS to optimize throughput and obscure network semantics. However, custom cryptographic schemes often introduce critical vulnerabilities (such as static XOR keystream derivation, missing rate limits, and unauthenticated metadata broadcasting).

This open-source framework provides modular tools to:
1. Reverse-engineer proprietary binary packet layouts (Type-Length-Value / TLV).
2. Measure payload entropy and identify broken stream ciphers (CWE-327 / CWE-321).
3. Synthesize pure Layer-4 TCP socket harnesses without dependencies on client mobile GUI.

### Verified Benchmark Case Study:
- **Target Architecture:** Proprietary L4 TCP Socket Protocol & Binary Storage Engine
- **Vulnerability Tracking:** MITRE CVE Candidate `CAN-2026-2040492`
- **Severity Rating:** CVSS v4.0: 9.3 CRITICAL / CVSS v3.1: 9.1 CRITICAL
- **Responsible Disclosure:** Conducted under ISO/IEC 29147 (90-day embargo).

---

## 2. Architecture & Modules

```
arm64-protocol-auditor/
├── core/
│   ├── tlv_codec.py          # High-performance binary TLV serializer/deserializer
│   ├── crypto_auditor.py     # Stream cipher keystream recovery & Shannon entropy analyzer
│   └── wire_fuzzer.py        # Standalone L4 TCP frame synthesizer and state fuzzer
├── main.py                   # CLI entrypoint
└── README.md
```

---

## 3. Quickstart

```bash
# Clone the repository
git clone https://github.com/hafphongg/arm64-protocol-auditor.git
cd arm64-protocol-auditor

# Run self-test demo
python main.py --demo
```

---

## 4. OpenAI Codex Integration Roadmap
We are integrating OpenAI's advanced reasoning models (Codex / GPT-4o / O-series) into this framework to:
- Automatically translate decompiled ARM64 disassembly (from IDA Pro / Ghidra) into reproducible Python network harnesses.
- Infer complex binary wire structures from raw hex capture traces.
- Synthesize automated security regression test suites for open-source protocol research.

---

## 5. License
This project is open-source under the [MIT License](LICENSE).

<!-- verified by hafphongg -->
