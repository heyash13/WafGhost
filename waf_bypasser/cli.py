import argparse
import sys
import logging
import json
from .core import WafBypasser

def setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)]
    )

def main():
    parser = argparse.ArgumentParser(
        description="WAF-Bypasser: LLM-Driven Iterative Evasion Fuzzer"
    )
    parser.add_argument(
        "--url",
        required=True,
        help="Target base URL to send requests to (can contain {payload} placeholder)"
    )
    parser.add_argument(
        "--payload",
        required=True,
        help="Base exploit payload to bypass WAF for"
    )
    parser.add_argument(
        "--param",
        help="Target parameter name in query or POST body where payload is injected"
    )
    parser.add_argument(
        "--method",
        default="GET",
        choices=["GET", "POST"],
        help="HTTP request method (default: GET)"
    )
    parser.add_argument(
        "--vuln-type",
        default="sql",
        choices=["sql", "ssrf", "xss", "generic"],
        help="Vulnerability type for selecting specific mutators (default: sql)"
    )
    parser.add_argument(
        "--use-llm",
        action="store_true",
        help="Enable fallback LLM generative feedback loop"
    )
    parser.add_argument(
        "--llm-provider",
        default="gemini",
        choices=["gemini", "openai", "claude"],
        help="LLM provider to use (default: gemini)"
    )
    parser.add_argument(
        "--llm-key",
        help="API key for the selected LLM provider"
    )
    parser.add_argument(
        "--proxy",
        help="Proxy URL (e.g. http://127.0.0.1:8080)"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging output"
    )
    parser.add_argument(
        "--output",
        help="Save results JSON to this filepath"
    )

    args = parser.parse_args()

    setup_logging(args.verbose)

    # Run the bypasser
    bypasser = WafBypasser(
        target_url=args.url,
        base_payload=args.payload,
        param_name=args.param,
        method=args.method,
        proxy=args.proxy,
        vuln_type=args.vuln_type,
        use_llm=args.use_llm,
        llm_provider=args.llm_provider,
        llm_api_key=args.llm_key,
    )

    print("\n" + "="*50)
    print("WAF-Bypasser Evasion Run Initiated")
    print(f"Target: {args.url}")
    print(f"Base Payload: {args.payload}")
    print(f"Vulnerability Type: {args.vuln_type}")
    print(f"LLM Evasion Enabled: {args.use_llm}")
    print("="*50 + "\n")

    result = bypasser.run()

    print("\n" + "="*50)
    print("Run Complete!")
    print(f"Success: {result.success}")
    if result.success:
        print(f"Bypassed Payload: {result.payload}")
    else:
        print("Bypass Failed.")
    print(f"Total Attempts: {result.attempts}")
    print("="*50 + "\n")

    if args.output:
        try:
            with open(args.output, "w") as f:
                json.dump(result.model_dump(), f, indent=2)
            print(f"Saved results to {args.output}")
        except Exception as e:
            print(f"Failed to save output to {args.output}: {e}")

    if not result.success:
        sys.exit(1)

if __name__ == "__main__":
    main()
