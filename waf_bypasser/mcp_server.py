import json
import logging
from typing import Optional, List, Dict, Any
from mcp.server.fastmcp import FastMCP

from .core import WafBypasser
from .client import WafClient
from .prober import WafProber, BlockMap
from .mutators.encoder import EncoderMutator
from .mutators.sql import SqlMutator
from .mutators.ssrf import SsrfMutator

# Setup basic logging to stderr so it doesn't pollute stdout (MCP uses stdin/stdout for communications)
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger("waf_bypasser.mcp_server")

# Create a FastMCP server
mcp = FastMCP("WAF-Bypasser")

@mcp.tool()
def probe_waf(
    target_url: str,
    param_name: Optional[str] = None,
    method: str = "GET",
    proxy: Optional[str] = None,
) -> str:
    """
    Run differential token probing on the target URL to check which characters
    and keywords are blocked or allowed by the target WAF.

    Args:
        target_url: The base target URL to test.
        param_name: The parameter name to inject probe characters into.
        method: HTTP method (GET or POST).
        proxy: Optional HTTP proxy to route requests through.

    Returns:
        A JSON string containing the block map (allowed/blocked lists).
    """
    try:
        client = WafClient(
            base_url=target_url,
            method=method,
            proxy=proxy,
        )
        prober = WafProber(client=client, param_name=param_name)
        block_map = prober.probe_all()
        return json.dumps(block_map.to_dict(), indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})

@mcp.tool()
def generate_heuristic_mutations(
    base_payload: str,
    block_map_json: str,
    vuln_type: str = "sql",
) -> List[str]:
    """
    Generate mutated bypass candidate payloads using rule-based heuristic mutators
    based on the provided block map of blocked/allowed characters.

    Args:
        base_payload: The standard exploit payload (e.g. "1' UNION SELECT 1,2,3--").
        block_map_json: The WAF block map JSON string (obtained from probe_waf).
        vuln_type: The type of vulnerability ("sql", "ssrf", "xss", "generic").

    Returns:
        A list of mutated payload strings.
    """
    try:
        block_data = json.loads(block_map_json)
        block_map = BlockMap()
        block_map.allowed = set(block_data.get("allowed", []))
        block_map.blocked = set(block_data.get("blocked", []))

        mutators = [EncoderMutator()]
        vtype = vuln_type.lower()
        if vtype == "sql":
            mutators.append(SqlMutator())
        elif vtype == "ssrf":
            mutators.append(SsrfMutator())

        candidates = []
        for mutator in mutators:
            candidates.extend(mutator.mutate(base_payload, block_map))

        return list(set(candidates))
    except Exception as e:
        return [f"Error: {e}"]

@mcp.tool()
def bypass_waf(
    target_url: str,
    base_payload: str,
    param_name: Optional[str] = None,
    method: str = "GET",
    vuln_type: str = "sql",
    use_llm: bool = False,
    llm_provider: str = "gemini",
    proxy: Optional[str] = None,
) -> str:
    """
    Orchestrate the entire WAF evasion workflow: run differential probing to compile
    the WAF blocked character map, test heuristic mutations, and optionally use an LLM
    feedback loop for advanced evasion.

    Args:
        target_url: The base target URL to test.
        base_payload: The starting exploit payload.
        param_name: The parameter name to inject the payload into.
        method: HTTP method (GET or POST).
        vuln_type: The type of vulnerability ("sql", "ssrf", "xss", "generic").
        use_llm: If true, use LLM feedback loop if heuristics fail.
        llm_provider: The LLM model/api provider ("gemini", "openai", "claude").
        proxy: Optional HTTP proxy to route requests through.

    Returns:
        A JSON string containing the BypassResult.
    """
    try:
        bypasser = WafBypasser(
            target_url=target_url,
            base_payload=base_payload,
            param_name=param_name,
            method=method,
            vuln_type=vuln_type,
            use_llm=use_llm,
            llm_provider=llm_provider,
            proxy=proxy,
        )
        result = bypasser.run()
        return json.dumps(result.model_dump(), indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})

def main():
    # Runs the FastMCP server over standard I/O (stdin/stdout)
    mcp.run()

if __name__ == "__main__":
    main()
