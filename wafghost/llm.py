import os
import json
import logging
from typing import Dict, List, Any, Optional

# Configure logger
logger = logging.getLogger("wafghost.llm")

class LlmEvasionSession:
    """
    Maintains conversation history and model context for stateful,
    multi-turn real-time WAF evasion.
    """
    def __init__(self, provider: str, client: Any, base_payload: str, block_map: Dict[str, List[str]], vuln_type: str):
        self.provider = provider
        self.client = client
        self.base_payload = base_payload
        self.block_map = block_map
        self.vuln_type = vuln_type
        
        # Message list for OpenAI & Claude
        self.messages: List[Dict[str, str]] = []
        
        # Chat session for Gemini
        self.gemini_chat = None
        
        self.system_instruction = (
            "You are an expert WAF Evasion Fuzzing Assistant. Your goal is to bypass a Web Application Firewall "
            "by mutating a base exploit payload. You must reason in real-time about why previous attempts failed "
            "based on the response status code, headers, and body snippets, and propose a new bypass candidate.\n\n"
            "Evasion Strategies to consider:\n"
            "- SQLi: mixed casing, nested comments (e.g. un/**/ion), MySQL versioned comments (/*!50000union*/), "
            "hexadecimal representation of strings, unicode compatibility homoglyphs (like fullwidth characters or escaping "
            "such as \\U0027 or permissive escape blocks), alternative functions (CONCAT, group_concat, CHAR).\n"
            "- SSRF: IP encodings (decimal, octal, hex representations), IPv6 bracket shorthand, credentials/userinfo obfuscation, "
            "wildcard DNS resolvers (nip.io, local.gd).\n"
            "- XSS: alternate tags (<svg>, <iframe, <details>), event handlers (onerror, onload), unicode escapes.\n\n"
            "You must return ONLY a valid JSON object matching this schema. Do not include markdown code block formatting (like ```json), just return raw JSON:\n"
            "{\n"
            "  \"candidate\": \"proposed_bypass_payload\",\n"
            "  \"evasion_reasoning\": \"A short 1-2 sentence explanation of your bypass strategy and why the previous attempt failed.\"\n"
            "}"
        )


class LlmClient:
    """
    Interface client to invoke various LLMs (Gemini, OpenAI, Claude)
    for stateful generative WAF evasion.
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
        elif self.provider in ["anthropic", "claude"]:
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

    def create_evasion_session(
        self,
        base_payload: str,
        block_map: Dict[str, List[str]],
        vuln_type: str = "sql"
    ) -> LlmEvasionSession:
        """
        Creates and initializes a stateful evasion chat session.
        """
        session = LlmEvasionSession(
            provider=self.provider,
            client=self,
            base_payload=base_payload,
            block_map=block_map,
            vuln_type=vuln_type
        )

        if not self.api_key:
            return session

        if self.provider == "gemini":
            import google.generativeai as genai
            model = genai.GenerativeModel(
                model_name="gemini-1.5-flash",
                system_instruction=session.system_instruction,
                generation_config={"response_mime_type": "application/json"}
            )
            session.gemini_chat = model.start_chat(history=[])
            
        elif self.provider == "openai":
            session.messages = [
                {"role": "system", "content": session.system_instruction}
            ]
            
        elif self.provider in ["anthropic", "claude"]:
            session.messages = []

        return session

    def propose_next_candidate(
        self,
        session: LlmEvasionSession,
        last_attempt: Optional[Dict[str, Any]] = None
    ) -> tuple[Optional[str], str]:
        """
        Queries the LLM with the latest attempt details (or baseline info)
        and retrieves the next proposed mutation payload + evasion reasoning.
        """
        if not self.api_key:
            return None, "LLM Client not configured."

        # Construct prompt
        if last_attempt is None:
            # First turn: establish baseline
            prompt = f"""
We are starting a WAF evasion session.
- Vulnerability Type: {session.vuln_type.upper()}
- Base Exploit Payload to run: {repr(session.base_payload)}
- Target WAF Blocked Tokens: {session.block_map.get('blocked', [])}
- Target WAF Allowed Tokens: {session.block_map.get('allowed', [])}

Propose the first candidate payload that attempts to bypass the WAF.
"""
        else:
            # Subsequent turns: reactive reasoning
            prompt = f"""
We tried sending this payload: {repr(last_attempt.get('payload'))}
The WAF BLOCKED it.
- HTTP Status Code: {last_attempt.get('status_code')}
- Response Content length: {last_attempt.get('length')} bytes
- Response body snippet: {repr(last_attempt.get('text', '')[:500])}

Analyze why the WAF blocked this payload. Propose the next mutated payload candidate.
"""

        try:
            if self.provider == "gemini":
                response = session.gemini_chat.send_message(prompt)
                return self._parse_json_response(response.text)

            elif self.provider == "openai":
                session.messages.append({"role": "user", "content": prompt})
                response = self.openai_client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=session.messages,
                    response_format={"type": "json_object"}
                )
                content = response.choices[0].message.content
                session.messages.append({"role": "assistant", "content": content})
                return self._parse_json_response(content)

            elif self.provider in ["anthropic", "claude"]:
                session.messages.append({"role": "user", "content": prompt})
                response = self.anthropic_client.messages.create(
                    model="claude-3-5-sonnet-20240620",
                    max_tokens=1020,
                    system=session.system_instruction,
                    messages=session.messages
                )
                content = response.content[0].text
                session.messages.append({"role": "assistant", "content": content})
                return self._parse_json_response(content)

        except Exception as e:
            logger.error(f"Error querying stateful chat for provider '{self.provider}': {e}", exc_info=True)

        return None, f"LLM error: {e}"

    def _parse_json_response(self, text: str) -> tuple[Optional[str], str]:
        try:
            text_cleaned = text.strip()
            if text_cleaned.startswith("```json"):
                text_cleaned = text_cleaned[7:]
            if text_cleaned.endswith("```"):
                text_cleaned = text_cleaned[:-3]
            text_cleaned = text_cleaned.strip()
            
            data = json.loads(text_cleaned)
            candidate = data.get("candidate")
            reasoning = data.get("evasion_reasoning", "No reasoning provided.")
            return candidate, reasoning
        except Exception as e:
            logger.warning(f"Failed to parse JSON response: {e}. Raw: {text}")
            return None, f"Parsing error: {e}"
