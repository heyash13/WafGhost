from typing import Dict, Any, Optional

class WafFingerprinter:
    """
    Analyzes HTTP response headers and body content to identify
    the active Web Application Firewall (WAF) brand.
    """

    SIGNATURES = {
        "Cloudflare": {
            "headers": ["cf-ray", "cf-cache-status", "__cfduid"],
            "server": ["cloudflare"],
            "body": ["cloudflare-nginx", "cloudflare.com/5xx-error-landing"],
        },
        "AWS WAF": {
            "headers": ["x-amz-apigw-id", "x-amzn-requestid", "x-amzn-trace-id"],
            "server": ["awselb/2.0"],
            "body": ["aws-waf", "aws waf", "security.chkp"],
        },
        "Imperva Incapsula": {
            "headers": ["x-iinfo", "x-cdn", "visid_incap", "incap_ses"],
            "server": ["incapsula"],
            "body": ["incapsula", "imperva", "incident_id"],
        },
        "Akamai": {
            "headers": ["x-akamai-transformed", "x-akamai-request-id"],
            "server": ["akamaighost", "akamai-edge"],
            "body": ["akamai", "akamai technologies"],
        },
        "Sucuri": {
            "headers": ["x-sucuri-id", "x-sucuri-cache"],
            "server": ["sucuri/nginx"],
            "body": ["sucuri website firewall", "sucuri.net"],
        },
        "ModSecurity": {
            "headers": ["x-absolute-redirectpub"],
            "server": ["mod_security", "modsecurity"],
            "body": ["modsecurity", "mod_security", "was blocked by modsecurity"],
        },
        "F5 BIG-IP ASM": {
            "headers": ["x-f5-http-pass-through"],
            "server": ["big-ip", "f5"],
            "body": ["the requested url was rejected. please consult with your administrator"],
        },
        "FortiWeb": {
            "headers": [],
            "server": ["fortiweb"],
            "body": ["fortiweb", "fortigate"],
        }
    }

    @classmethod
    def identify(cls, status_code: int, headers: Dict[str, str], body: str) -> Optional[str]:
        """
        Identify active WAF from response details.
        """
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        server_val = headers_lower.get("server", "")

        for waf_name, sigs in cls.SIGNATURES.items():
            # Check Server header
            for s in sigs.get("server", []):
                if s in server_val:
                    return waf_name

            # Check other headers existence or values
            for h in sigs.get("headers", []):
                if h in headers_lower:
                    return waf_name

            # Check response body keywords
            body_lower = body.lower()
            for b in sigs.get("body", []):
                if b in body_lower:
                    return waf_name

        # Fallback to generic blocked detection
        if status_code in [403, 406, 429, 501] or any(k in body for k in ["Access Denied", "blocked by", "WAF"]):
            return "Generic WAF / Security Filter"

        return None
