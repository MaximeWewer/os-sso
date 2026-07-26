#!/usr/bin/env python3
"""Drive a full SSO browser ceremony against the lab IdPs.

The shell suites used to scrape Keycloak's login form with curl. That works for
Keycloak and not at all for Authentik, whose login page is a single-page app talking
to a flow-executor API -- there is no form to scrape. Rather than keep two dialects of
"log in" in shell, the whole ceremony lives here: start at the os-sso login endpoint,
authenticate at whichever IdP answers, and come back to the callback/ACS.

Cookies for BOTH hosts (the firewall and the IdP) live in one jar, which is also
written out in Netscape format so the calling shell can keep using the session with
`curl -b`.

Exit status is 0 when the firewall accepted the login. The final HTTP status of the
callback/ACS step is printed on stdout so the suites can assert on it.
"""

import argparse
import html
import http.cookiejar
import re
import sys
import urllib.parse

import requests

requests.packages.urllib3.disable_warnings()


class CeremonyError(RuntimeError):
    pass


def start(session, gui, protocol, provider, start_url=None):
    """Ask os-sso to begin, and follow it to wherever the IdP wants the user.

    `start_url` overrides the endpoint, for the flows whose login URL carries extra
    parameters: the OpenVPN one-time session id, or a captive-portal zone.
    """
    url = start_url or (
        f"{gui}/api/sso/{protocol}/login?provider={urllib.parse.quote(provider)}"
    )
    first = session.get(url, allow_redirects=False)
    if first.status_code != 302:
        raise CeremonyError(
            f"login endpoint returned {first.status_code}, not a redirect to the IdP"
        )
    return session.get(first.headers["location"], allow_redirects=True)


def keycloak_authenticate(session, page, user, password):
    """Keycloak renders a plain login form; post it."""
    match = re.search(r'action="([^"]+)"', page.text)
    if not match:
        raise CeremonyError("no login form on the Keycloak page")
    action = html.unescape(match.group(1))
    return session.post(
        action,
        data={"username": user, "password": password, "credentialId": ""},
        allow_redirects=False,
    )


def authentik_run_flow(session, page, user, password):
    """Execute the Authentik flow displayed on `page`, one stage at a time.

    Each POST answers the current stage and the next GET reveals the following one,
    until the flow hands back a redirect. Anything else means the flow asked for
    something this lab does not script (MFA, explicit consent, a captcha).
    """
    landed = urllib.parse.urlparse(page.url)
    flow = landed.path.strip("/").split("/")[-1]
    executor = (
        f"{landed.scheme}://{landed.netloc}/api/v3/flows/executor/{flow}/"
        f"?query={urllib.parse.quote(landed.query, safe='')}"
    )
    answers = {
        "ak-stage-identification": {"uid_field": user},
        "ak-stage-password": {"password": password},
        "ak-stage-user-login": {},
    }

    seen = []
    for _ in range(10):
        stage = session.get(executor, headers={"Accept": "application/json"})
        if stage.status_code != 200:
            raise CeremonyError(f"flow executor returned {stage.status_code}")
        data = stage.json()
        component = data.get("component", "")
        seen.append(component)
        if component == "xak-flow-redirect":
            return session.get(
                urllib.parse.urljoin(executor, data["to"]), allow_redirects=False
            )
        if component == "ak-stage-autosubmit":
            # How Authentik delivers a SAML response: a form the browser posts to the
            # ACS. It is not a question to answer, it is the answer -- post it.
            return deliver(session, data["url"], data.get("attrs", {}))
        if component not in answers:
            raise CeremonyError(f"unscripted Authentik stage '{component}'")
        csrf = session.cookies.get("authentik_csrf", domain=landed.hostname)
        posted = session.post(
            executor,
            json=answers[component],
            headers={"X-authentik-CSRF": csrf or "", "Referer": page.url},
            allow_redirects=False,
        )
        if posted.status_code not in (200, 302):
            raise CeremonyError(
                f"stage '{component}' rejected the answer ({posted.status_code})"
            )
    raise CeremonyError(
        "the Authentik flow did not finish in 10 stages: " + " -> ".join(seen)
    )


def authentik_resume(session, response, user, password):
    """Authentik chains flows: authentication, then provider authorization.

    The second one lands the browser on another /if/flow/ page, which is a dead end
    for a plain redirect follower -- it has to be executed like the first. Returns
    None when the page is not a flow, so the caller can report being stuck.
    """
    if "/if/flow/" not in response.url:
        return None
    return authentik_run_flow(session, response, user, password)

def follow_to_firewall(session, response, gui, resume=None):
    """Walk the redirect chain until the firewall answers; return that response.

    SAML comes back as an auto-submitting POST form instead of a redirect, so that
    form is submitted here -- it is what a browser would do. `resume` gets a chance to
    unstick the walk when the IdP parks the browser on a page of its own.
    """
    for _ in range(12):
        if response.status_code in (301, 302, 303, 307, 308):
            target = urllib.parse.urljoin(response.url, response.headers["location"])
            if target.startswith(gui):
                return session.get(target, allow_redirects=False)
            response = session.get(target, allow_redirects=False)
            continue

        form = re.search(r'action="([^"]+)"[^>]*>(.*?)</form>', response.text, re.S)
        if form and gui in html.unescape(form.group(1)):
            fields = {
                name: html.unescape(value)
                for name, value in re.findall(
                    r'name="([^"]+)"[^>]*value="([^"]*)"', form.group(2)
                )
            }
            return deliver(session, html.unescape(form.group(1)), fields)
        resumed = resume(session, response) if resume else None
        if resumed is not None:
            response = resumed
            continue

        raise CeremonyError(
            f"stuck at {response.url} ({response.status_code}), no way back to {gui}"
        )
    raise CeremonyError("too many redirects on the way back")


# Set when --capture is in play: the SAMLResponse is written here and never posted.
CAPTURE_PATH = None


class Captured(Exception):
    """Raised once the SAML response has been captured, to unwind the ceremony."""


def deliver(session, url, fields):
    """Post the IdP's form back to the firewall -- or capture it and stop."""
    if CAPTURE_PATH and "SAMLResponse" in fields:
        with open(CAPTURE_PATH, "w") as handle:
            handle.write(fields["SAMLResponse"])
        raise Captured()
    return session.post(url, data=fields, allow_redirects=False)


def save_cookies(session, path):
    """Hand the session on to the shell suites in the format curl reads.

    requests keeps its own jar type, so the cookies are copied into a Netscape file
    rather than saved directly. The WebGUI session cookie has no expiry, so both
    "discard" and "expires" have to be ignored or it would not be written at all.
    """
    jar = http.cookiejar.MozillaCookieJar(path)
    for cookie in session.cookies:
        if cookie.expires is None:
            cookie.expires = 0
            cookie.discard = False
        # Python appends ".local" to a dotless host ("localhost" -> "localhost.local",
        # RFC 2965). curl does not, so it would never match the cookie back to the
        # firewall and the shell suites would see an anonymous session.
        if cookie.domain.endswith(".local"):
            cookie.domain = cookie.domain[: -len(".local")]
        jar.set_cookie(cookie)
    jar.save(ignore_discard=True, ignore_expires=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--gui", required=True)
    parser.add_argument("--provider", required=True)
    parser.add_argument("--protocol", choices=["oidc", "saml"], default="oidc")
    parser.add_argument("--idp", choices=["keycloak", "authentik"], default="keycloak")
    parser.add_argument("--user", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--jar", required=True, help="Netscape cookie file to write")
    parser.add_argument(
        "--body", help="write the final page here (the VPN / portal confirmation)"
    )
    parser.add_argument(
        "--start-url",
        help="begin here instead of the plain login endpoint (carries &vpn= / &cp=)",
    )
    parser.add_argument(
        "--capture",
        help="SAML only: write the SAMLResponse here instead of posting it to the ACS, "
        "so a suite can replay it or post it by hand",
    )
    args = parser.parse_args()

    session = requests.Session()
    session.verify = False

    global CAPTURE_PATH
    CAPTURE_PATH = args.capture

    try:
        page = start(
            session, args.gui, args.protocol, args.provider, args.start_url
        )
        if args.idp == "keycloak":
            authenticated = keycloak_authenticate(session, page, args.user, args.password)
            resume = None
        else:
            authenticated = authentik_run_flow(session, page, args.user, args.password)
            resume = lambda s, r: authentik_resume(s, r, args.user, args.password)
        final = follow_to_firewall(session, authenticated, args.gui, resume)
    except Captured:
        save_cookies(session, args.jar)
        print("captured")
        return 0
    except CeremonyError as exc:
        print(f"000 {exc}", file=sys.stderr)
        print("000")
        return 1
    except requests.RequestException as exc:
        print(f"000 {exc}", file=sys.stderr)
        print("000")
        return 1

    save_cookies(session, args.jar)
    print(final.status_code)
    # 302 is the WebGUI login; the VPN and captive-portal flows end on a page (200)
    # instead of a redirect, and both mean the firewall accepted the identity.
    if final.status_code == 200 and args.body:
        with open(args.body, "w") as handle:
            handle.write(final.text)
    return 0 if final.status_code in (200, 302) else 1


if __name__ == "__main__":
    sys.exit(main())
