"""A DPoP nonce gate in front of Keycloak's token and userinfo endpoints (lab only).

Keycloak only hands out DPoP nonces on its verifiable-credentials endpoint, so nothing in
the lab ever asked os-sso for one and its retry path (RFC 9449 section 8) went untested.
Caddy routes the two endpoints through here: a request that carries a DPoP proof without
the current nonce gets the standard challenge -- 400 use_dpop_nonce at the token endpoint,
401 with WWW-Authenticate at userinfo, the nonce in a DPoP-Nonce header -- and everything
else, including every request without DPoP, goes to Keycloak untouched.
"""
import base64
import http.client
import http.server
import json
import secrets
import socketserver

UPSTREAM = ("keycloak", 8080)
NONCE = secrets.token_urlsafe(16)
HOP = {"connection", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade"}


def proof_nonce(proof):
    try:
        payload = proof.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))).get("nonce")
    except (IndexError, ValueError):
        return None


class Gate(http.server.BaseHTTPRequestHandler):
    def handle_any(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        proof = self.headers.get("DPoP")
        if proof is not None and proof_nonce(proof) != NONCE:
            userinfo = self.path.split("?")[0].endswith("/userinfo")
            self.send_response(401 if userinfo else 400)
            self.send_header("DPoP-Nonce", NONCE)
            self.send_header("Cache-Control", "no-store")
            if userinfo:
                self.send_header("WWW-Authenticate", 'DPoP error="use_dpop_nonce", error_description="nonce required"')
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                out = json.dumps({"error": "use_dpop_nonce", "error_description": "nonce required"}).encode()
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)
            print(f"challenged {self.command} {self.path.split('?')[0]}", flush=True)
            return
        conn = http.client.HTTPConnection(*UPSTREAM, timeout=30)
        headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP}
        conn.request(self.command, self.path, body=body or None, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        self.send_response(resp.status)
        for k, v in resp.getheaders():
            if k.lower() not in HOP and k.lower() != "content-length":
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        if proof is not None:
            print(f"passed {self.command} {self.path.split('?')[0]} with the nonce -> {resp.status}", flush=True)

    do_GET = do_POST = handle_any

    def log_message(self, *args):
        pass


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


if __name__ == "__main__":
    Server(("0.0.0.0", 8000), Gate).serve_forever()
