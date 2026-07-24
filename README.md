# WAF-Bypasser: LLM-Driven Iterative Evasion Fuzzer

`WAF-Bypasser` is a professional, modular Python library and CLI tool designed for black-box differential fuzzing, token-filtering analysis, and generative syntax adaptation to bypass Web Application Firewalls (WAFs). 

It dynamically determines WAF regex blocking rules, builds a target-specific character blockmap, and uses rule-based heuristics as well as LLM-driven generative adaptation (feedback loops) to bypass firewalls for payloads like SQL Injection, SSRF, Path Traversal, and XSS.

## Core Features

- **Differential Token Filtering**: Maps target blocking rules using single-character and multi-character probes to identify permitted/blocked symbols, functions, and keywords.
- **Rule-Based Heuristic Mutators**: Mutates exploit payloads using predefined obfuscation techniques:
  - **SQL Mutators**: SQL comments, alternative white-space characters, alternative concatenation/string representations, alternative functions (e.g., `CONCAT` vs `||`).
  - **SSRF Mutators**: Host schema bypasses (decimal IP representation, octal, hex, IPv6 shorthand, DNS rebinding-ready inputs).
  - **XSS/Common Mutators**: Double/triple URL encoding, unicode obfuscation, HTML entity encoding.
- **Generative Evasion Feedback Loop (LLM integration)**: When heuristic mutations fail, the tool engages an LLM (Gemini, Claude, OpenAI, etc.) in a feedback loop. The LLM receives the payload, the target's blockmap, and the raw WAF response, dynamically reasoning to propose new syntactically valid bypass candidates.
- **MCP Server Support**: Exposes the tool's capabilities as a Model Context Protocol (MCP) server. Any agent (like Claude Desktop, Jetski, or other LLM-based assistants) can directly interact with the fuzzer as a tool.
- **Robust HTTP Session Client**: Includes support for custom headers, custom cookies, custom User-Agents, rate-limiting, proxies, and automatic session persistence.

## Project Structure

```text
waf-bypasser/
├── README.md
├── pyproject.toml
├── requirements.txt
├── waf_bypasser/
│   ├── __init__.py
│   ├── client.py         # HTTP client wrapper (proxy, headers, cookies, rate-limiting)
│   ├── prober.py         # Token filtering & blocked character mapper
│   ├── mutators/
│   │   ├── __init__.py
│   │   ├── base.py
│   │   ├── sql.py        # SQLi obfuscations
│   │   ├── ssrf.py       # SSRF schema bypasses
│   │   └── encoder.py    # Common encoders (hex, unicode, URL encoding)
│   ├── core.py           # Orchestrates probing, heuristics, and LLM feedback loop
│   ├── llm.py            # Generic LLM API wrapper (Gemini, OpenAI, Anthropic)
│   └── mcp_server.py     # MCP Server entrypoint
├── tests/
│   ├── test_prober.py
│   ├── test_mutators.py
│   └── test_core.py
└── examples/
    ├── basic_cli.py
    └── llm_integration.py
```

## Setup & Installation

### Prerequisites
- Python 3.10+
- LLM API Keys (optional, for LLM-driven feedback loop)

### Installation
Clone the repository and install dependencies:
```bash
git clone https://github.com/your-username/waf-bypasser.git
cd waf-bypasser
pip install -r requirements.txt
```

To run as an MCP server:
```json
{
  "mcpServers": {
    "waf-bypasser": {
      "command": "python",
      "args": ["-m", "waf_bypasser.mcp_server"]
    }
  }
}
```

## Usage

### CLI
Run a basic probe on a target URL:
```bash
python -m waf_bypasser.cli --url "http://example.com/search?q=" --payload "1' UNION SELECT 1,2,3--"
```

### Library
```python
from waf_bypasser import WafBypasser

bypasser = WafBypasser(
    target_url="http://example.com/search?q=",
    base_payload="1' UNION SELECT 1,2,3--",
    use_llm=True,
    provider="gemini"
)

result = bypasser.run()
if result.success:
    print(f"Bypass succeeded! Payload: {result.payload}")
else:
    print("Failed to bypass WAF.")
```
