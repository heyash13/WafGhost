import logging
from typing import Dict, List, Any, Optional
from pydantic import BaseModel

from .client import WafClient
from .prober import WafProber, BlockMap
from .mutators.encoder import EncoderMutator
from .mutators.sql import SqlMutator
from .mutators.ssrf import SsrfMutator
from .llm import LlmClient
from .fingerprinter import WafFingerprinter

# Configure logger
logger = logging.getLogger("waf_bypasser.core")

class BypassResult(BaseModel):
    success: bool
    payload: Optional[str] = None
    block_map: Dict[str, List[str]]
    detected_waf: Optional[str] = None
    vuln_type: str
    attempts: int
    log: List[Dict[str, Any]]

class WafBypasser:
    """
    Advanced orchestrator that runs auto-vuln detection, token probing,
    WAF fingerprinting, multi-stage chained heuristic mutations,
    and LLM feedback loop.
    """

    def __init__(
        self,
        target_url: str,
        base_payload: str,
        param_name: Optional[str] = None,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None,
        vuln_type: str = "auto",  # "auto", "sql", "ssrf", "xss", "generic"
        use_llm: bool = False,
        llm_provider: str = "gemini",
        llm_api_key: Optional[str] = None,
        max_llm_iterations: int = 4,
        rate_limit_delay: float = 0.1,
    ):
        self.target_url = target_url
        self.base_payload = base_payload
        self.param_name = param_name
        self.use_llm = use_llm
        self.max_llm_iterations = max_llm_iterations

        # 1. Auto-detect vulnerability type if needed
        self.vuln_type = self._detect_vuln_type(base_payload) if vuln_type == "auto" else vuln_type.lower()

        # Initialize WafClient
        self.client = WafClient(
            base_url=target_url,
            method=method,
            headers=headers,
            cookies=cookies,
            proxy=proxy,
            rate_limit_delay=rate_limit_delay
        )

        # Initialize LLM client
        self.llm_client = None
        if self.use_llm:
            self.llm_client = LlmClient(provider=llm_provider, api_key=llm_api_key)

        self.history: List[Dict[str, Any]] = []
        self.tested_payloads = set()
        self.detected_waf = None

    def _detect_vuln_type(self, payload: str) -> str:
        """Heuristically determines the vulnerability type based on payload contents."""
        payload_lower = payload.lower()
        
        # SSRF checks
        if any(scheme in payload_lower for scheme in ["http://", "https://", "ftp://", "gopher://", "dict://", "file://"]) or payload_lower in ["localhost", "127.0.0.1", "[::1]"]:
            return "ssrf"
            
        # XSS checks
        if any(tag in payload_lower for tag in ["<script", "javascript:", "onerror", "onload", "alert(", "confirm(", "prompt(", "<svg", "<iframe"]):
            return "xss"
            
        # SQL Injection checks
        if any(sql in payload_lower for sql in ["select", "union", "insert", "delete", "where", "--", "/*", "*/", "sys.user_tables"]):
            return "sql"
            
        return "generic"

    def run(self) -> BypassResult:
        """
        Runs the advanced WAF bypass pipeline.
        """
        logger.info(f"Starting advanced run. Detected vulnerability type: {self.vuln_type.upper()}")
        
        # 1. Run WAF Fingerprinting on baseline block trigger
        logger.info("Performing baseline WAF fingerprinting request...")
        fingerprint_res = self.client.send_payload(self.base_payload, param_name=self.param_name)
        self.detected_waf = WafFingerprinter.identify(
            status_code=fingerprint_res["status_code"],
            headers=fingerprint_res["headers"],
            body=fingerprint_res["text"]
        )
        if self.detected_waf:
            logger.info(f"Target Firewall Fingerprint: [bold red]{self.detected_waf}[/bold red]")
        else:
            logger.info("No distinct WAF signatures matched. Treating as standard security filter.")

        # 2. Probe target and build BlockMap
        prober = WafProber(client=self.client, param_name=self.param_name)
        block_map = prober.probe_all()

        # 3. Generate chained/nested candidates using pipeline
        candidates = self._generate_chained_candidates(self.base_payload, block_map)
        logger.info(f"Generated {len(candidates)} multi-stage nested bypass candidates.")

        # 4. Test chained candidates
        for idx, candidate in enumerate(candidates):
            if candidate in self.tested_payloads:
                continue
            self.tested_payloads.add(candidate)

            logger.debug(f"Testing candidate payload: {repr(candidate)}")
            res = self.client.send_payload(candidate, param_name=self.param_name)
            
            # Log attempt
            attempt_log = {
                "source": "heuristic_chained",
                "payload": candidate,
                "is_blocked": res["is_blocked"],
                "status_code": res["status_code"],
                "length": res["length"],
            }
            self.history.append(attempt_log)

            if res["success"]:
                logger.info(f"Bypass SUCCESS with chained payload: {repr(candidate)}")
                return BypassResult(
                    success=True,
                    payload=candidate,
                    block_map=block_map.to_dict(),
                    detected_waf=self.detected_waf,
                    vuln_type=self.vuln_type,
                    attempts=len(self.tested_payloads),
                    log=self.history
                )

        # 5. Fallback to LLM generative loop if rule-based pipeline fails
        if self.use_llm and self.llm_client:
            logger.info("Heuristic mutation pipeline exhausted. Initiating LLM generative feedback loop...")
            
            last_resp = self.history[-1] if self.history else {"status_code": 403, "length": 0, "text": "Access Denied"}

            iteration = 0
            while True:
                if self.max_llm_iterations > 0 and iteration >= self.max_llm_iterations:
                    logger.info("Reached maximum configured LLM iterations limit. Stopping.")
                    break
                
                if self.max_llm_iterations <= 0 and iteration > 0 and iteration % 20 == 0:
                    logger.warning(f"Fuzzer has run {iteration} LLM iterations without a bypass. Still searching since unlimited mode is enabled...")

                iter_label = f"unlimited_{iteration+1}" if self.max_llm_iterations <= 0 else f"{iteration+1}/{self.max_llm_iterations}"
                logger.info(f"LLM Loop iteration {iter_label}...")

                # Feed LLM with target blocks, last failure, and history of tested payloads to avoid duplicates
                context_summary = last_resp.copy()
                context_summary["previously_tested_failed_payloads"] = list(self.tested_payloads)[-15:] # send last 15 attempts to keep token size low
                context_summary["detected_waf"] = self.detected_waf

                llm_candidates = self.llm_client.generate_mutations(
                    base_payload=self.base_payload,
                    block_map=block_map.to_dict(),
                    waf_response_summary=context_summary,
                    vuln_type=self.vuln_type
                )

                if not llm_candidates:
                    logger.warning("LLM generated no new mutations.")
                    break

                for candidate in llm_candidates:
                    if candidate in self.tested_payloads:
                        continue
                    self.tested_payloads.add(candidate)

                    logger.info(f"Testing LLM-proposed payload: {repr(candidate)}")
                    res = self.client.send_payload(candidate, param_name=self.param_name)
                    
                    attempt_log = {
                        "source": f"llm_iter_{iteration+1}",
                        "payload": candidate,
                        "is_blocked": res["is_blocked"],
                        "status_code": res["status_code"],
                        "length": res["length"],
                    }
                    self.history.append(attempt_log)

                    if res["success"]:
                        logger.info(f"Bypass SUCCESS with LLM payload: {repr(candidate)}")
                        return BypassResult(
                            success=True,
                            payload=candidate,
                            block_map=block_map.to_dict(),
                            detected_waf=self.detected_waf,
                            vuln_type=self.vuln_type,
                            attempts=len(self.tested_payloads),
                            log=self.history
                        )
                    
                    last_resp = attempt_log
                iteration += 1

        # If everything fails
        logger.warning("Failed to bypass WAF. All candidates blocked.")
        return BypassResult(
            success=False,
            payload=None,
            block_map=block_map.to_dict(),
            detected_waf=self.detected_waf,
            vuln_type=self.vuln_type,
            attempts=len(self.tested_payloads),
            log=self.history
        )

    def _generate_chained_candidates(self, base_payload: str, block_map: BlockMap) -> List[str]:
        """
        Runs a multi-stage mutation pipeline chaining SQL/SSRF transformations
        together with encoding mutators to create advanced nested bypass payloads.
        """
        # Set up specific mutator layers
        vuln_mutator = None
        if self.vuln_type == "sql":
            vuln_mutator = SqlMutator()
        elif self.vuln_type == "ssrf":
            vuln_mutator = SsrfMutator()

        encoder = EncoderMutator()

        # Step 1: Base candidates (vuln specific)
        level_1 = [base_payload]
        if vuln_mutator:
            level_1.extend(vuln_mutator.mutate(base_payload, block_map))
        level_1 = list(set(level_1))

        # Step 2: Apply encoders to all level 1 candidates (combining casing/obfuscation + encodings)
        level_2 = []
        for l1_candidate in level_1:
            level_2.extend(encoder.mutate(l1_candidate, block_map))
        
        # Combine all candidates together
        final_candidates = list(set(level_1 + level_2))
        return final_candidates
