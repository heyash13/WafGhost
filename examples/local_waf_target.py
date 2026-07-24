import re
import time
import urllib.parse
import html
from http.server import HTTPServer, BaseHTTPRequestHandler

# Simulates IP request tracking for WAF Rate Limiting
rate_limit_db = {}

class LocalWafHandler(BaseHTTPRequestHandler):
    """
    Ultra-strict Mock WAF mimicking OWASP ModSecurity CRS Paranoia Level 3 & 4.
    Performs recursive URL & HTML entity decoding, strict regex blocks on SQL keywords,
    blocks SQL comments, detects common system variables/functions, and applies IP rate-limiting.
    """

    def recursive_decode(self, text: str, depth: int = 3) -> str:
        """Decodes URL encoding and HTML entities recursively."""
        decoded = text
        for _ in range(depth):
            # 1. URL Decode
            temp = urllib.parse.unquote(decoded)
            # 2. HTML Entity Decode (e.g. &#x27; -> ')
            temp = html.unescape(temp)
            if temp == decoded:
                break
            decoded = temp
        return decoded

    def normalize_payload(self, raw_payload: str) -> str:
        """
        Normalizes input payload:
        1. Recursively decodes URL & HTML entities.
        2. Identifies and replaces hex strings (0x...) with decoded text.
        3. Normalizes unicode characters.
        """
        # Recursive decode
        payload = self.recursive_decode(raw_payload)

        # Hex representations (0x...) decoding
        hex_literals = re.findall(r'0x([0-9a-fA-F]+)', payload)
        for hex_str in hex_literals:
            try:
                decoded_hex = bytes.fromhex(hex_str).decode('utf-8', errors='ignore')
                payload = payload.replace(f"0x{hex_str}", decoded_hex)
            except Exception:
                pass

        # Unicode escapes normalization
        try:
            payload = payload.encode('utf-8').decode('unicode-escape')
        except Exception:
            pass

        return payload

    def check_rate_limit(self, client_ip: str) -> bool:
        """
        Simulates WAF Rate Limiting.
        Limits clients to maximum 8 requests within a sliding 2-second window.
        """
        now = time.time()
        # Clean old timestamps
        if client_ip in rate_limit_db:
            rate_limit_db[client_ip] = [t for t in rate_limit_db[client_ip] if now - t < 2.0]
        else:
            rate_limit_db[client_ip] = []

        # Check threshold
        if len(rate_limit_db[client_ip]) >= 8:
            return True # Rate limit triggered

        rate_limit_db[client_ip].append(now)
        return False

    def check_owasp_crs_rules_strict(self, payload: str) -> tuple[bool, str]:
        """
        Implements ultra-strict OWASP CRS PL3/PL4 WAF rules.
        """
        # Rule 1: Quotation characters breakout attempt
        if "'" in payload or '"' in payload or "`" in payload:
            return True, "OWASP Rule 942100: Detects SQL breakout characters (quotes)"

        # Rule 2: Complete block of SQL comment syntax (PL3/PL4 style)
        # Blocks standard comments --, #, /*, */, or versioned comments /*!
        if "--" in payload or "#" in payload or "/*" in payload or "*/" in payload:
            return True, "OWASP Rule 942430: SQL Comment Delimiter Injection Blocked (e.g. --, #, /*, */)"

        # Rule 3: Detect SQL keywords union/select (even without comments, since comments are blocked)
        # Case-insensitive standalone keywords match
        if re.search(r'(?i)\b(?:union|select|insert|delete|update|drop|alter|declare|exec)\b', payload):
            return True, "OWASP Rule 942100: Strict SQL keyword block triggered"

        # Rule 4: Classic SQL Injection Tautology (e.g. or 1=1, or like, and true, etc.)
        if re.search(r'(?i)\b(or|and|xor|not)\b\s+.*?(=|<|>|like|regexp|in|between|is)\b', payload):
            return True, "OWASP Rule 942110: Detects SQL Injection Tautology (boolean comparison)"

        # Rule 5: Detect SQL system functions
        if re.search(r'(?i)\b(?:char|concat|ascii|bin|hex|substr|substring|mid|length|len|count|sleep|benchmark|user|database|version)\b\s*\(', payload):
            return True, "OWASP Rule 942260: SQL System Function Execution Blocked"

        # Rule 6: SQL system variables / tables
        if "@@" in payload or "information_schema" in payload.lower() or "sys.user_tables" in payload.lower():
            return True, "OWASP Rule 942120: SQL System Schema/Variable Query Blocked"

        # Rule 7: Hex characters query filter (PL4 checks for raw hex matching SQL symbols)
        if re.search(r'(?i)(?:char|ascii|hex)\b', payload):
            return True, "OWASP Rule 942100: Hex or Character encoding function keywords blocked"

        return False, ""

    def do_GET(self):
        client_ip = self.client_address[0]

        # 1. Rate Limiting Check
        if self.check_rate_limit(client_ip):
            self.send_response(429)
            self.send_header("Content-Type", "text/html")
            self.send_header("Retry-After", "2")
            self.end_headers()
            self.wfile.write(b"<h1>429 Too Many Requests</h1><p>Rate Limit Exceeded. Triggered by WAF Anti-DDoS.</p>")
            return

        parsed_url = urllib.parse.urlparse(self.path)
        
        if parsed_url.path != "/search":
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")
            return

        query_params = urllib.parse.parse_qs(parsed_url.query)
        raw_q = query_params.get("q", [""])[0]

        # Normalize the payload to defeat encoding/hex obfuscations
        normalized_q = self.normalize_payload(raw_q)
        
        # Run ultra-strict rules
        is_blocked, rule_reason = self.check_owasp_crs_rules_strict(normalized_q)

        if is_blocked:
            self.send_response(403)
            self.send_header("Content-Type", "text/html")
            self.send_header("Server", "AdvancedWAF/2.4 (CRS/3.3-PL4)")
            self.end_headers()
            response_html = f"""
            <html>
            <head><title>403 Forbidden</title></head>
            <body style="font-family:sans-serif; margin:10% auto; width:60%;">
            <h1 style="color:red; border-bottom:1px solid #ccc; padding-bottom:10px;">403 Forbidden - Security Action</h1>
            <p>Your request was intercepted by the Web Application Firewall.</p>
            <p><b>Triggered Signature:</b> <code>{rule_reason}</code></p>
            <p><b>Normalized Payload Evaluated:</b> <code>{repr(normalized_q)}</code></p>
            <hr style="border:0; border-top:1px solid #eee;" />
            <small>Server: AdvancedWAF (CRS/3.3-PL4)</small>
            </body>
            </html>
            """
            self.wfile.write(response_html.encode("utf-8"))
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            success_html = f"""
            <html>
            <head><title>Search Results</title></head>
            <body style="font-family:sans-serif; margin:10% auto; width:60%;">
            <h1 style="color:green;">Search Results</h1>
            <p>Your search returned successfully.</p>
            <p><b>Query received:</b> <code>{raw_q}</code></p>
            <p style='color:green;'><b>Bypass Success! The WAF was not triggered.</b></p>
            </body>
            </html>
            """
            self.wfile.write(success_html.encode("utf-8"))

def run(port=5050):
    server_address = ('127.0.0.1', port)
    httpd = HTTPServer(server_address, LocalWafHandler)
    print(f"Advanced PL4 OWASP-CRS WAF Target Server running on http://127.0.0.1:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
        httpd.server_close()

if __name__ == '__main__':
    run()
