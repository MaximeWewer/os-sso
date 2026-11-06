"""Sign out at Keycloak as the browser would, and load the front-channel iframes it renders.

usage: kc_frontchannel.py <cookie jar> <realm base>

The logout is started from another client of the same Keycloak session (the realm's own
account-console), the way a user signing out of some other application would: Keycloak
then has to tell every other client of that session -- the firewall among them.
"""
import base64
import hashlib
import http.cookiejar
import re
import secrets
import sys
from urllib.parse import parse_qs, urlparse

import requests
import urllib3

urllib3.disable_warnings()
jar_path, realm = sys.argv[1], sys.argv[2].rstrip("/")
jar = http.cookiejar.MozillaCookieJar(jar_path)
jar.load(ignore_discard=True, ignore_expires=True)
# The jar writes session cookies with expires=0, which cookiejar reads as long expired.
for c in jar:
    if c.expires == 0:
        c.expires = None
s = requests.Session()
s.cookies = jar
s.verify = False

client, redirect = "account-console", realm + "/account/"
verifier = secrets.token_urlsafe(48)
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
r = s.get(realm + "/protocol/openid-connect/auth", allow_redirects=False, params={
    "client_id": client, "redirect_uri": redirect, "response_type": "code", "scope": "openid",
    "prompt": "none", "code_challenge": challenge, "code_challenge_method": "S256",
})
code = parse_qs(urlparse(r.headers.get("Location", "")).query).get("code", [""])[0]
if not code:
    sys.exit("no silent code from Keycloak (no SSO session?): " + r.headers.get("Location", str(r.status_code)))
tokens = s.post(realm + "/protocol/openid-connect/token", data={
    "grant_type": "authorization_code", "client_id": client, "code": code,
    "redirect_uri": redirect, "code_verifier": verifier,
}).json()

r = s.get(realm + "/protocol/openid-connect/logout",
          params={"id_token_hint": tokens["id_token"], "client_id": client})
frames = [u.replace("&amp;", "&") for u in re.findall(r'<iframe[^>]+src="([^"]+)"', r.text)]
print("keycloak logout page:", r.status_code, "iframes:", len(frames))
for url in frames:
    f = s.get(url, headers={"Referer": realm + "/"})
    print("iframe", url)
    print("  ->", f.status_code, "| CSP:", f.headers.get("Content-Security-Policy", "-"),
          "| X-Frame-Options:", f.headers.get("X-Frame-Options", "-"))
