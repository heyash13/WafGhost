import argparse
import sys
import logging
import json

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.live import Live
from rich.align import Align

from .core import WafBypasser

# Initialize Rich Console
console = Console()

def setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stderr)] # output logs to stderr to avoid rich pollution
    )

def render_banner():
    banner = """
 _    _            ___  _               _   
| |  | |          / __|| |             | |  
| |  | | __ _  _  | |  | |__   ___  ___| |_ 
| |/\| |/ _` || | | |  | '_ \ / _ \/ __| __|
\  /\  / (_| || | | |__| | | | (_) \__ \ |_ 
 \/  \/ \__,_||_| \___/|_| |_|\___/|___/\__|
    [bold cyan]LLM-Driven Iterative Evasion Fuzzer[/bold cyan] v0.1.0
    """
    console.print(Align.center(banner))

def display_summary(result):
    console.print("\n")
    if result.success:
        success_text = Text.assemble(
            ("BYPASS SUCCESSFUL!\n\n", "bold green"),
            ("Payload: ", "bold yellow"),
            (result.payload, "bold white underline"),
            (f"\nAttempts: {result.attempts}", "cyan")
        )
        panel = Panel(
            success_text,
            title="[bold green]Success[/bold green]",
            border_style="green",
            expand=False
        )
    else:
        fail_text = Text.assemble(
            ("BYPASS FAILED\n\n", "bold red"),
            ("All generated and LLM-proposed evasion candidates were blocked by the target WAF.\n", "white"),
            (f"Attempts: {result.attempts}", "cyan")
        )
        panel = Panel(
            fail_text,
            title="[bold red]Failure[/bold red]",
            border_style="red",
            expand=False
        )
    console.print(Align.center(panel))

def display_block_map(block_map_dict):
    table = Table(title="[bold cyan]Differential Token Map[/bold cyan]", border_style="blue")
    table.add_column("Status", justify="center", style="bold")
    table.add_column("Tokens / Characters", justify="left")

    allowed_chars = [repr(c) for c in block_map_dict.get("allowed", [])]
    blocked_chars = [repr(c) for c in block_map_dict.get("blocked", [])]

    table.add_row("[green]ALLOWED[/green]", ", ".join(allowed_chars) if allowed_chars else "None")
    table.add_row("[red]BLOCKED[/red]", ", ".join(blocked_chars) if blocked_chars else "None")
    
    console.print(table)
    console.print("\n")

def main():
    parser = argparse.ArgumentParser(
        description="WafGhost: LLM-Driven Iterative Evasion Fuzzer"
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
        default="auto",
        choices=["auto", "sql", "ssrf", "xss", "generic"],
        help="Vulnerability type (default: auto-detect)"
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
        "--max-llm-iterations",
        type=int,
        default=4,
        help="Maximum LLM generative mutation iterations (set to -1 or 0 for unlimited loop)"
    )
    parser.add_argument(
        "--output",
        help="Save results JSON to this filepath"
    )

    args = parser.parse_args()

    setup_logging(args.verbose)
    render_banner()

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
        max_llm_iterations=args.max_llm_iterations,
    )

    # Initial status panel
    target_info = Text.assemble(
        ("Target URL:    ", "cyan"), (f"{args.url}\n", "white"),
        ("Base Payload:  ", "cyan"), (f"{repr(args.payload)}\n", "white"),
        ("Detected Vuln: ", "cyan"), (f"{bypasser.vuln_type.upper()}\n", "bold magenta"),
        ("LLM Feedback:  ", "cyan"), (f"{'ENABLED (' + args.llm_provider + ')' if args.use_llm else 'DISABLED'}\n", "green" if args.use_llm else "red")
    )
    console.print(Panel(target_info, title="[bold]Configuration[/bold]", border_style="cyan"))

    console.print("[yellow]Running initial WAF fingerprinting & token probing...[/yellow]")
    
    # Run the fuzzer
    result = bypasser.run()

    # If WAF detected, print it out
    if result.detected_waf:
        console.print(Panel(f"[bold red]Target Protected by: {result.detected_waf}[/bold red]", border_style="red"))
    else:
        console.print("[yellow]No specific WAF brand signature detected.[/yellow]")

    # Print Block Map
    display_block_map(result.block_map)

    # Print attempt log table
    log_table = Table(title="[bold cyan]Fuzzing Attempts Log[/bold cyan]", border_style="blue")
    log_table.add_column("Attempt", justify="center")
    log_table.add_column("Source", justify="center")
    log_table.add_column("Payload Candidate", justify="left")
    log_table.add_column("Status Code", justify="center")
    log_table.add_column("Blocked", justify="center")

    for idx, entry in enumerate(result.log):
        blocked_str = "[bold red]YES[/bold red]" if entry["is_blocked"] else "[bold green]NO[/bold green]"
        log_table.add_row(
            str(idx + 1),
            entry["source"],
            repr(entry["payload"]),
            str(entry["status_code"]),
            blocked_str
        )

    console.print(log_table)

    # Show final summary
    display_summary(result)

    if args.output:
        try:
            with open(args.output, "w") as f:
                json.dump(result.model_dump(), f, indent=2)
            console.print(f"[green]Saved detailed JSON log to {args.output}[/green]")
        except Exception as e:
            console.print(f"[red]Failed to save output file: {e}[/red]")

    if not result.success:
        sys.exit(1)

if __name__ == "__main__":
    main()
