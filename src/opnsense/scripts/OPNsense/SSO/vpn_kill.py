#!/usr/local/bin/python3
"""
    Copyright (C) 2026 Maxime Wewer
    SPDX-License-Identifier: BSD-2-Clause

    Disconnect every OpenVPN tunnel belonging to a common name.

        vpn_kill.py <common_name>

    A tunnel that came up through SSO web-auth outlives the thing that authorized it:
    the IdP session can end, the account can be deactivated over SCIM, and the tunnel
    stays up until its own renegotiation or the client leaves. This is what os-sso calls
    to close that gap, so a revocation reaches the VPN and not only the WebGUI.

    Every management socket is tried rather than asking the operator which OpenVPN
    instance a profile belongs to: killing a common name that is not connected there is
    a no-op, and the alternative is an internal instance id in the configuration that
    nobody can be expected to know.
"""
import glob
import json
import os
import re
import socket
import sys

SOCKET_GLOB = '/var/etc/openvpn/*.sock'
TIMEOUT = 3


def kill_on(socket_path, common_name):
    """Ask one instance to drop the common name. Returns how many it dropped."""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(TIMEOUT)
            sock.connect(socket_path)
            sock.recv(4096)  # greeting
            sock.send(('kill %s\n' % common_name).encode())
            answer = sock.recv(4096).decode(errors='replace')
    except (OSError, socket.timeout):
        return 0
    # "SUCCESS: common name 'x' found, 1 client(s) killed"
    if 'SUCCESS' not in answer:
        return 0
    numbers = [int(word) for word in re.findall(r'\d+', answer)]
    return numbers[0] if numbers else 1


if __name__ == '__main__':
    name = sys.argv[1] if len(sys.argv) > 1 else ''
    # The name crosses into a management-interface command, one line at a time: anything
    # that could carry a second command, or an argument to one, is not a common name.
    if not name or not re.match(r'^[A-Za-z0-9._@ -]{1,64}$', name):
        print(json.dumps({'status': 'invalid common name', 'killed': 0}))
        sys.exit(1)

    killed = 0
    sockets = sorted(glob.glob(SOCKET_GLOB))
    for path in sockets:
        if os.path.exists(path):
            killed += kill_on(path, name)
    print(json.dumps({'status': 'ok', 'killed': killed, 'instances': len(sockets)}))
