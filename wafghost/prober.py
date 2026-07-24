import logging
from typing import Dict, List, Set, Optional, Any
from .client import WafClient

# Configure logger
logger = logging.getLogger("wafghost.prober")

class BlockMap:
    """
    Data structure containing allowed and blocked characters/keywords.
    """
    def __init__(self):
        self.allowed: Set[str] = set()
        self.blocked: Set[str] = set()
        self.probing_results: Dict[str, Dict[str, Any]] = {}

    def add_result(self, token: str, success: bool, response_meta: Dict[str, Any]):
        self.probing_results[token] = response_meta
        if success:
            self.allowed.add(token)
        else:
            self.blocked.add(token)

    def is_blocked(self, token: str) -> bool:
        return token in self.blocked

    def is_allowed(self, token: str) -> bool:
        return token in self.allowed

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": sorted(list(self.allowed)),
            "blocked": sorted(list(self.blocked)),
        }


class WafProber:
    """
    Differential prober that sends single-character and token probes to build
    a map of what characters are filtered or blocked by the WAF.
    """
    
    DEFAULT_SYMBOLS = [
        "'", "\"", "`", ";", ",", "+", "-", "/", "*", "=", 
        "<", ">", "(", ")", "{", "}", "[", "]", "!", "@", 
        "#", "$", "%", "^", "&", "|", "\\", "?", ".", ":", 
        " ", "\t", "\n", "\r"
    ]
    
    DEFAULT_KEYWORDS = [
        "union", "select", "insert", "update", "delete", "drop", "alter", 
        "script", "javascript", "onerror", "onload", "eval", "alert", 
        "http", "https", "file", "gopher", "dict", "ftp", "ldap",
        "127.0.0.1", "localhost", "[::1]", "etc", "passwd"
    ]

    def __init__(
        self,
        client: WafClient,
        param_name: Optional[str] = None,
        custom_symbols: Optional[List[str]] = None,
        custom_keywords: Optional[List[str]] = None,
    ):
        self.client = client
        self.param_name = param_name
        self.symbols = custom_symbols if custom_symbols is not None else self.DEFAULT_SYMBOLS
        self.keywords = custom_keywords if custom_keywords is not None else self.DEFAULT_KEYWORDS

    def probe_all(self) -> BlockMap:
        """
        Probes the target with all symbols and keywords to construct a BlockMap.
        """
        block_map = BlockMap()
        
        logger.info("Starting differential token probing...")
        
        # Probe single characters/symbols
        for symbol in self.symbols:
            logger.debug(f"Probing symbol: {repr(symbol)}")
            res = self.client.send_payload(symbol, param_name=self.param_name)
            # If request didn't fail due to structural client errors, record it
            block_map.add_result(symbol, res["success"], res)
            
        # Probe keywords
        for keyword in self.keywords:
            logger.debug(f"Probing keyword: {keyword}")
            res = self.client.send_payload(keyword, param_name=self.param_name)
            block_map.add_result(keyword, res["success"], res)
            
        logger.info(f"Probing complete. Blocked count: {len(block_map.blocked)}, Allowed count: {len(block_map.allowed)}")
        return block_map
