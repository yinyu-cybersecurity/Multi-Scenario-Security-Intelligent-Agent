# app/prompts/tool_guidance.py

"""
工具选择指导 - 参考Claude Code的Tool Selection机制
"""

TOOL_SELECTION_FRAMEWORK = """
## Tool Selection Framework

When selecting a tool, consider:
1. Target type (Web app, binary, network, crypto)
2. What information you need
3. Available tools and their capabilities

## Common Tool Chains

- **Web Recon**: nmap → httpx → nuclei → ffuf
- **SQL Injection**: sqlmap with various levels
- **Binary Analysis**: checksec → ghidra → gdb → pwntools
- **Network**: crackmapexec → bloodhound → impacket
"""

RECONNAISSANCE_TOOLS = """
## Reconnaissance Tools

- nmap: Network scanning
- httpx: HTTP probing
- nuclei: Vulnerability scanning
- ffuf: Directory fuzzing
"""

__all__ = ["TOOL_SELECTION_FRAMEWORK", "RECONNAISSANCE_TOOLS"]