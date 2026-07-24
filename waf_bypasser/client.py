import time
import urllib.parse
from typing import Dict, Any, Optional, Union
import requests

class WafClient:
    """
    Robust HTTP client for testing targets protected by Web Application Firewalls.
    Supports proxying, custom headers/cookies, rate limiting, and block detection.
    """

    def __init__(
        self,
        base_url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None,
        block_status_codes: Optional[list[int]] = None,
        block_keywords: Optional[list[str]] = None,
        timeout: float = 10.0,
        rate_limit_delay: float = 0.1,  # Seconds between requests
    ):
        self.base_url = base_url
        self.method = method.upper()
        self.session = requests.Session()
        self.timeout = timeout
        self.rate_limit_delay = rate_limit_delay
        self.last_request_time = 0.0

        # Set default headers if not provided
        self.headers = headers or {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
        self.session.headers.update(self.headers)

        if cookies:
            self.session.cookies.update(cookies)

        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

        # WAF detection configuration
        self.block_status_codes = block_status_codes or [403, 406, 429, 418, 501]
        self.block_keywords = block_keywords or [
            "Access Denied",
            "WAF",
            "Web Application Firewall",
            "Cloudflare",
            "ModSecurity",
            "sucuri",
            "Incapsula",
            "AkamaiGhost",
            "blocked by",
            "security challenge",
            "captcha",
        ]

    def _sleep_if_needed(self):
        """Enforces a basic rate limit delay to avoid overloading targets or triggering IP bans."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - elapsed)
        self.last_request_time = time.time()

    def send_payload(
        self,
        payload: str,
        param_name: Optional[str] = None,
        place_in_headers: bool = False,
    ) -> Dict[str, Any]:
        """
        Sends the payload to the target. 
        If param_name is provided, it replaces/adds it to query parameters or JSON/form body.
        If param_name is not provided, it inserts the payload directly into the URL where a placeholder '{payload}' is found.
        If place_in_headers is True, payload can be passed in a specific header.
        """
        self._sleep_if_needed()

        url = self.base_url
        data = None
        json_data = None
        headers = self.session.headers.copy()

        # Build request parameters
        if place_in_headers and param_name:
            headers[param_name] = payload
        elif param_name:
            parsed_url = urllib.parse.urlparse(self.base_url)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            # Update param in query or create query if empty
            query_params[param_name] = [payload]
            new_query = urllib.parse.urlencode(query_params, doseq=True)
            
            # Reconstruct URL without query, then add new query
            url = urllib.parse.urlunparse(
                (
                    parsed_url.scheme,
                    parsed_url.netloc,
                    parsed_url.path,
                    parsed_url.params,
                    new_query,
                    parsed_url.fragment,
                )
            )
        else:
            # Replace placeholder {payload} if present in URL
            if "{payload}" in url:
                url = url.replace("{payload}", urllib.parse.quote(payload))
            else:
                # If no placeholder and no param name, append to URL
                parsed_url = urllib.parse.urlparse(url)
                if parsed_url.query:
                    url += f"&{urllib.parse.quote(payload)}"
                else:
                    url += f"?{urllib.parse.quote(payload)}"

        # Perform request
        try:
            if self.method == "POST":
                # Detect if target is JSON
                if "application/json" in headers.get("Content-Type", "").lower():
                    json_data = {param_name: payload} if param_name else payload
                else:
                    data = {param_name: payload} if param_name else payload
                
                response = self.session.post(
                    url,
                    data=data,
                    json=json_data,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=False,
                )
            else:
                response = self.session.get(
                    url,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=False,
                )

            # Analyze response to check if blocked
            is_blocked = self.is_blocked(response)
            
            return {
                "success": not is_blocked,
                "is_blocked": is_blocked,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "text": response.text,
                "length": len(response.content),
                "url": response.url,
            }

        except requests.exceptions.RequestException as e:
            return {
                "success": False,
                "is_blocked": True,
                "status_code": 0,
                "headers": {},
                "text": str(e),
                "length": 0,
                "url": url,
                "error": str(e),
            }

    def is_blocked(self, response: requests.Response) -> bool:
        """
        Heuristically check if the response was blocked by WAF.
        """
        # Status code checking
        if response.status_code in self.block_status_codes:
            return True

        # Check headers for common WAF indicators
        headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
        for waf_header in ["x-waf-blocked", "x-cdn", "server"]:
            val = headers_lower.get(waf_header, "")
            if any(k.lower() in val for k in self.block_keywords):
                return True

        # Body text keyword search
        body_content = response.text
        for kw in self.block_keywords:
            if kw.lower() in body_content.lower():
                return True

        return False
