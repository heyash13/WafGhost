import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler

class LocalWafHandler(BaseHTTPRequestHandler):
    """
    A simple local HTTP server simulating a Web Application Firewall (WAF)
    that blocks simple SQLi attempts but allows successfully mutated payloads.
    """

    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        
        # We only serve /search
        if parsed_url.path != "/search":
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")
            return

        # Parse query params
        query_params = urllib.parse.parse_qs(parsed_url.query)
        q = query_params.get("q", [""])[0]

        # WAF rules:
        # 1. Block if it contains single quote (') or double quote (")
        # 2. Block if it contains spaces ( )
        # 3. Block if it contains the word "union" or "select" (case-insensitive)
        # Exception: Allow if keywords are commented (e.g. un/**/ion) or hex encoded.
        
        is_blocked = False
        block_reason = ""

        if "'" in q or '"' in q:
            is_blocked = True
            block_reason = "Quote character detected"
        elif " " in q:
            is_blocked = True
            block_reason = "Space character detected"
        elif "union" in q.lower() or "select" in q.lower():
            is_blocked = True
            block_reason = "SQL Keyword detected"

        if is_blocked:
            # Simulate a 403 Forbidden WAF Block response
            self.send_response(403)
            self.send_header("Content-Type", "text/html")
            self.send_header("Server", "LocalMockWAF/1.0")
            self.end_headers()
            response_html = f"""
            <html>
            <head><title>403 Forbidden</title></head>
            <body>
            <h1>Access Denied (WAF Blocked)</h1>
            <p>Reason: {block_reason}</p>
            <p>Your request has been flagged by the Web Application Firewall.</p>
            </body>
            </html>
            """
            self.wfile.write(response_html.encode("utf-8"))
        else:
            # Bypass succeeded!
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            success_html = f"""
            <html>
            <head><title>Search Results</title></head>
            <body>
            <h1>Search Results</h1>
            <p>Query received: <code>{q}</code></p>
            <p style='color:green;'><b>Bypass Success! The WAF was not triggered.</b></p>
            </body>
            </html>
            """
            self.wfile.write(success_html.encode("utf-8"))

def run(port=5000):
    server_address = ('127.0.0.1', port)
    httpd = HTTPServer(server_address, LocalWafHandler)
    print(f"Mock WAF Target Server running on http://127.0.0.1:{port}")
    print("Use this as a target for testing WAF-Bypasser safely.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
        httpd.server_close()

if __name__ == '__main__':
    run()
