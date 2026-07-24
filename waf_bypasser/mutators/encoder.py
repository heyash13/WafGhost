import urllib.parse
from typing import List
from .base import BaseMutator
from ..prober import BlockMap

class EncoderMutator(BaseMutator):
    """
    Applies encoding techniques (URL, double-URL, hex, Unicode) to bypass WAF filters.
    """

    def mutate(self, payload: str, block_map: BlockMap) -> List[str]:
        candidates = []

        # 1. URL Encoding
        candidates.append(urllib.parse.quote(payload))

        # 2. Double URL Encoding
        candidates.append(urllib.parse.quote(urllib.parse.quote(payload)))

        # 3. Hex Encoding (if WAF struggles with hex notation, e.g. for SQL/XSS contexts)
        # e.g., 'abc' -> 0x616263 (sometimes used for SQL strings)
        try:
            hex_payload = "0x" + payload.encode("utf-8").hex()
            candidates.append(hex_payload)
        except Exception:
            pass

        # 4. Unicode escape obfuscation (useful if payload is executed in a JS / JSON context)
        unicode_payload = ""
        for char in payload:
            if char.isalnum():
                unicode_payload += char
            else:
                unicode_payload += f"\\u{ord(char):04x}"
        candidates.append(unicode_payload)

        # 5. Mixed URL Encoding (only encode characters that are blocked by WAF)
        mixed_payload = ""
        for char in payload:
            if block_map.is_blocked(char):
                mixed_payload += urllib.parse.quote(char)
            else:
                mixed_payload += char
        if mixed_payload != payload:
            candidates.append(mixed_payload)

        # 6. Double encode only blocked characters
        double_mixed_payload = ""
        for char in payload:
            if block_map.is_blocked(char):
                double_mixed_payload += urllib.parse.quote(urllib.parse.quote(char))
            else:
                double_mixed_payload += char
        if double_mixed_payload != payload and double_mixed_payload != mixed_payload:
            candidates.append(double_mixed_payload)

        return list(set(candidates))
