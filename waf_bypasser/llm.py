import os
import json
import logging
from typing import Dict, List, Any, Optional

# Configure logger
logger = logging.getLogger("waf_bypasser.llm")

class LlmClient:
    """
    Interface client to invoke various LLMs (Gemini, OpenAI, Claude)
    for generative payload mutation.
    """

    def __init__(self, provider: str = "gemini", api_key: Optional[str] = None):
        self.provider = provider.lower()
        self.api_key = api_key or self._get_api_key_from_env()

        if not self.api_key:
            logger.warning(
                f"No API key found in environment for provider '{self.provider}'. "
                "Generative LLM mutations will be disabled."
            )

        self._initialize_sdk()

    def _get_api_key_from_env(self) -> Optional[str]:
        if self.provider == "gemini":
            return os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        elif self.provider == "openai":
            return os.getenv("OPENAI_API_KEY")
        elif self.provider == "anthropic" or self.provider == "claude":
            return os.getenv("ANTHROPIC_API_KEY")
        return None

    def _initialize_sdk(self):
        if not self.api_key:
            return

        if self.provider == "gemini":
            import google.generativeai as genai
            genai.configure(api_key=self.api_key)
        elif self.provider == "openai":
            from openai import OpenAI
            self.openai_client = OpenAI(api_key=self.api_key)
        elif self.provider in ["anthropic", "claude"]:
            from anthropic import Anthropic
            self.anthropic_client = Anthropic(api_key=self.api_key)

    def generate_mutations(
        self,
        base_payload: str,
        block_map: Dict[str, List[str]],
        waf_response_summary: Dict[str, Any],
        vuln_type: str = "sql",
        max_candidates: int = 5,
    ) -> List[str]:
        """
        Queries the LLM with context about the target blocks and asks for new mutation ideas.
        Returns a list of candidate payloads.
        """
        if not self.api_key:
            logger.debug("Skipping LLM mutation: LLM Client is not configured.")
            return []

        prompt = self._build_prompt(base_payload, block_map, waf_response_summary, vuln_type, max_candidates)
        system_instruction = (
            "You are a WAF Evasion Fuzzing Assistant. Your goal is to bypass a Web Application Firewall "
            "by mutating a base exploit payload. You are given a map of blocked/allowed characters/keywords "
            "and details of the WAF response. Respond ONLY with a valid JSON block containing an array of "
            "mutated payload strings. Do not include markdown code block formatting (like ```json) in your actual response text, "
            "just return raw JSON."
        )

        try:
            if self.provider == "gemini":
                import google.generativeai as genai
                model = genai.GenerativeModel(
                    model_name="gemini-1.5-flash",
                    generation_config={"response_mime_type": "application/json"}
                )
                response = model.generate_content(
                    contents=f"{system_instruction}\n\n{prompt}"
                )
                return self._parse_json_response(response.text)

            elif self.provider == "openai":
                response = self.openai_client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[
                        {"role": "system", "content": system_instruction},
                        {"role": "user", "content": prompt}
                    ],
                    response_format={"type": "json_object"}
                )
                content = response.choices[0].message.content
                return self._parse_json_response(content)

            elif self.provider in ["anthropic", "claude"]:
                response = self.anthropic_client.messages.create(
                    model="claude-3-5-sonnet-20240620",
                    max_tokens=1020,
                    system=system_instruction,
                    messages=[
                        {"role": "user", "content": prompt}
                    ]
                )
                content = response.content[0].text
                return self._parse_json_response(content)

        except Exception as e:
            logger.error(f"Error querying LLM provider '{self.provider}': {e}", exc_info=True)

        return []

    def _build_prompt(
        self,
        base_payload: str,
        block_map: Dict[str, List[str]],
        waf_response_summary: Dict[str, Any],
        vuln_type: str,
        max_candidates: int,
    ) -> str:
        return f"""
We are testing a web application parameter for {vuln_type.upper()} vulnerabilities.
The base payload we want to run is: {repr(base_payload)}

From token probing, we know the WAF filters/blocks characters and keywords as follows:
- Blocked characters/keywords: {block_map.get('blocked', [])}
- Allowed characters/keywords: {block_map.get('allowed', [])}

When we send our payload (or probes), the WAF responds with:
- HTTP Status Code: {waf_response_summary.get('status_code')}
- Response Content length: {waf_response_summary.get('length')} bytes
- Short Response snippet: {repr(waf_response_summary.get('text', '')[:400])}

Task:
Analyze the target's blockmap and response pattern. Generate up to {max_candidates} alternative, syntactically valid variations of the base payload that avoid all blocked characters/keywords.
For example, if spaces are blocked, you can use comment blocks `/**/` or URL-encoded equivalents. If single quotes are blocked, use hexadecimal representation.

Your response MUST be a JSON object matching this schema:
{{
  "candidates": [
     "candidate_payload_1",
     "candidate_payload_2"
  ],
  "evasion_reasoning": "A short 1-2 sentence explanation of your bypass strategy."
}}
"""

    def _parse_json_response(self, text: str) -> List[str]:
        try:
            # Clean text if the LLM output contains markdown wrapper
            text_cleaned = text.strip()
            if text_cleaned.startswith("```json"):
                text_cleaned = text_cleaned[7:]
            if text_cleaned.endswith("```"):
                text_cleaned = text_cleaned[:-3]
            text_cleaned = text_cleaned.strip()
            
            data = json.loads(text_cleaned)
            candidates = data.get("candidates", [])
            logger.debug(f"LLM proposed candidates: {candidates}")
            if "evasion_reasoning" in data:
                logger.info(f"LLM Strategy reasoning: {data['evasion_reasoning']}")
            return [str(c) for c in candidates]
        except Exception as e:
            logger.warning(f"Failed to parse JSON response from LLM: {e}. Raw response: {text}")
            return []
