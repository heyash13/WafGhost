import re
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler

class LocalWafHandler(BaseHTTPRequestHandler):
    """
    An advanced mock WAF mimicking real-world OWASP ModSecurity CRS rules.
    Performs recursive decoding, hex decoding normalization, and strict regex checks.
    """

    def recursive_url_decode(self, text: str, depth: int = 3) -> str:
        """Decodes URL encoding recursively to defeat double/triple encoding bypasses."""
        decoded = text
        for _ in range(depth):
            temp = urllib.parse.unquote(decoded)
            if temp == decoded:
                break
            decoded = temp
        return decoded

    def normalize_payload(self, raw_payload: str) -> str:
        """
        Normalizes the input payload:
        1. Recursively URL decodes it.
        2. Normalizes unicode characters.
        3. Identifies hex strings (0x...) and converts them to raw text for content scanning.
        """
        # Decode URL encoding
        payload = self.recursive_url_decode(raw_payload)

        # Find 0x... hex literals and decode them to plain text
        hex_literals = re.findall(r'0x([0-9a-fA-F]+)', payload)
        for hex_str in hex_literals:
            try:
                decoded_hex = bytes.fromhex(hex_str).decode('utf-8', errors='ignore')
                payload = payload.replace(f"0x{hex_str}", decoded_hex)
            except Exception:
                pass

        # Normalize unicode escape sequences (\u0027)
        try:
            # Replaces things like \u0027 with their actual character
            payload = payload.encode('utf-8').decode('unicode-escape')
        except Exception:
            pass

        return payload

    def check_owasp_crs_rules(self, payload: str) -> tuple[bool, str]:
        """
        Simulates standard OWASP Core Rule Set PL1 & PL2 SQL Injection rules.
        """
        # Rule 1: Detect SQL keyword combination pattern: union + select
        # E.g. union select, union/**/select, un/**/ion/**/sel/**/ect, /*!50000union*/select
        # Sanitized payload strip comments to see if keyword is still formed
        stripped_comments = re.sub(r'/\*.*?\*/', '', payload)
        # remove versioned comment markers as well
        stripped_comments = re.sub(r'/\*\!\d{5}', '', stripped_comments)
        
        # Matches union ... select, union join, etc.
        if re.search(r'(?i)\bunion\b.*?\bselect\b', stripped_comments):
            return True, "OWASP Rule 942100: Detects basic SQL injection keywords combination (union select)"

        # Rule 2: Classic SQLi Tautology e.g. or 1=1, or 'a'='a', or like, or regexp
        # Matches operators like =, !=, LIKE, REGEXP
        if re.search(r'(?i)\b(or|and)\b.*?(?:=|<|>|like|regexp)\b', stripped_comments):
            return True, "OWASP Rule 942110: Detects SQL Injection Tautology (or 1=1)"

        # Rule 3: Versioned comment injection detection (/*!50000union */)
        if re.search(r'(?i)/\*!\d{5}', payload):
            return True, "OWASP Rule 942200: Detects MySQL versioned comment execution syntax"

        # Rule 4: SQL string generation functions like CHAR() or CONCAT()
        if re.search(r'(?i)\b(?:char|concat|ascii|bin|hex)\b\s*\(', stripped_comments):
            return True, "OWASP Rule 942260: Detects SQL injection string generation functions (CHAR, CONCAT)"

        # Rule 5: Detect inline comments inside keywords e.g. un/**/ion
        # (detects comment block inside letters)
        if re.search(r'(?i)[a-z]+/\*.*?\*/[a-z]+', payload):
            return True, "OWASP Rule 942440: Detects comment injection inside keywords (obfuscated SQL keywords)"

        # Rule 6: Check for quotation characters that trigger syntax breakout
        if "'" in payload or '"' in payload or "`" in payload:
            return True, "OWASP Rule 942100: Detects SQL character breakout attempt (quotes)"

        # Rule 7: Detect space characters combined with keywords
        # If the input contains spaces alongside select/union/from/where
        if re.search(r'(?i)\b(?:select|union|from|where|insert|delete|update)\b\s+', payload):
            return True, "OWASP Rule 942100: Detects SQL keyword followed by whitespace/tabs"

        return False, ""

    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        
        if parsed_url.path != "/search":
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")
            return

        query_params = urllib.parse.parse_qs(parsed_url.query)
        raw_q = query_params.get("q", [""])[0]

        # Normalize the payload to defeat simple bypass attempts
        normalized_q = self.normalize_payload(raw_q)
        
        # Run WAF rule validations
        is_blocked, rule_reason = self.check_owasp_crs_rules(normalized_q)

        if is_blocked:
            self.send_response(403)
            self.send_header("Content-Type", "text/html")
            self.send_header("Server", "AdvancedWAF/2.4 (CRS/3.3)")
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
            <small>Server: AdvancedWAF (CRS/3.3)</small>
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
    print(f"Advanced OWASP-CRS WAF Target Server running on http://127.0.0.1:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
        httpd.server_close()

if __name__ == '__main__':
    run()
