"""
WafGhost: LLM-Driven Iterative WAF Evasion Fuzzer
"""

from .client import WafClient
from .prober import WafProber, BlockMap
from .core import WafBypasser, BypassResult

__version__ = "0.1.0"
__all__ = ["WafClient", "WafProber", "BlockMap", "WafBypasser", "BypassResult"]
