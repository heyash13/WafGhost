from unittest.mock import MagicMock
from wafghost.client import WafClient
from wafghost.prober import WafProber

def test_waf_prober():
    # Mock WafClient
    mock_client = MagicMock(spec=WafClient)
    
    # We want to mock client.send_payload(symbol)
    # Let's say it blocks "'" and "union", but allows everything else
    def send_payload_side_effect(payload, param_name=None):
        if payload in ["'", "union"]:
            return {
                "success": False,
                "is_blocked": True,
                "status_code": 403,
                "headers": {},
                "text": "Blocked by WAF",
                "length": 14
            }
        else:
            return {
                "success": True,
                "is_blocked": False,
                "status_code": 200,
                "headers": {},
                "text": "Allowed",
                "length": 7
            }

    mock_client.send_payload.side_effect = send_payload_side_effect

    # Initialize prober with custom small list to keep it fast
    prober = WafProber(
        client=mock_client,
        custom_symbols=["'", '"', " "],
        custom_keywords=["union", "select"]
    )
    
    block_map = prober.probe_all()

    # Verify blocked and allowed sets
    assert block_map.is_blocked("'")
    assert block_map.is_blocked("union")
    assert block_map.is_allowed('"')
    assert block_map.is_allowed(" ")
    assert block_map.is_allowed("select")
