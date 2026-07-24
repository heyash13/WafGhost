from unittest.mock import MagicMock, patch
from wafghost.core import WafBypasser
from wafghost.client import WafClient

@patch('wafghost.core.WafClient')
def test_waf_bypasser_heuristic_success(mock_client_class):
    # Setup mock client instance
    mock_client = MagicMock(spec=WafClient)
    mock_client_class.return_value = mock_client
    
    def send_payload_side_effect(payload, param_name=None):
        if "'" in payload or " " in payload:
            if "/**/" in payload and "'" not in payload and " " not in payload:
                return {"success": True, "is_blocked": False, "status_code": 200, "headers": {}, "text": "OK", "length": 2}
            return {"success": False, "is_blocked": True, "status_code": 403, "headers": {}, "text": "Blocked", "length": 7}
        return {"success": True, "is_blocked": False, "status_code": 200, "headers": {}, "text": "OK", "length": 2}

    mock_client.send_payload.side_effect = send_payload_side_effect

    # Initialize orchestrator
    bypasser = WafBypasser(
        target_url="http://example.com/search?q=",
        base_payload="1 UNION SELECT 1,2,3--",
        vuln_type="sql",
        use_llm=False
    )
    # Inject mock client manually to bypass internal instantiating
    bypasser.client = mock_client

    result = bypasser.run()
    
    assert result.success is True
    assert result.payload is not None
    # Verify the successful payload has space substituted or encoded
    assert " " not in result.payload
    assert result.attempts > 0
