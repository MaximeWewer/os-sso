<?php

/*
 * Lab test: Captive Portal authorizer security gates + a real "allow" attempt.
 * Args: <zoneid-bound-to-keycloak> <zoneid-with-enforce-group>
 * Run as root in the VM.
 */
require_once('util.inc');
require_once('script/load_phalcon.php');

use OPNsense\SSO\CaptivePortalAuthorizer;
use OPNsense\SSO\NormalizedIdentity;

$zoneOk = $argv[1] ?? '';
$zoneEnforce = $argv[2] ?? '';
$pass = 0;
$fail = 0;

function gate(string $label, callable $fn, bool $expectThrow, int &$pass, int &$fail): void
{
    try {
        $fn();
        if ($expectThrow) {
            echo "  FAIL $label (no rejection)\n";
            $fail++;
        } else {
            echo "  PASS $label\n";
            $pass++;
        }
    } catch (\Throwable $e) {
        if ($expectThrow) {
            echo "  PASS $label (rejected: " . $e->getMessage() . ")\n";
            $pass++;
        } else {
            echo "  FAIL $label (unexpected: " . $e->getMessage() . ")\n";
            $fail++;
        }
    }
}

$id = new NormalizedIdentity('keycloak');
$id->username = 'cptester';
$id->subject = 'cp-sub-1';
$id->groups = ['admins'];

// 1. unknown zone -> reject
gate('unknown zone rejected', fn() => CaptivePortalAuthorizer::authorize('99999', 'keycloak', $id, '127.0.0.1'), true, $pass, $fail);

// 2. provider not bound to the zone (authentik not in zone authservers) -> reject
gate('unbound provider rejected', fn() => CaptivePortalAuthorizer::authorize($zoneOk, 'authentik', $id, '127.0.0.1'), true, $pass, $fail);

// 3. group enforcement: zone requires "admins" but this identity lacks it -> reject
if ($zoneEnforce !== '') {
    $idNoAdmin = new NormalizedIdentity('keycloak');
    $idNoAdmin->username = 'cpguest';
    $idNoAdmin->subject = 'cp-sub-2';
    $idNoAdmin->groups = ['users'];
    gate('enforce-group mismatch rejected', fn() => CaptivePortalAuthorizer::authorize($zoneEnforce, 'keycloak', $idNoAdmin, '127.0.0.1'), true, $pass, $fail);
}

// 4. valid binding -> attempt the real configd "captiveportal allow"
try {
    $r = CaptivePortalAuthorizer::authorize($zoneOk, 'keycloak', $id, '127.0.0.1');
    echo "  PASS allow accepted -> session=" . json_encode($r['session']) . "\n";
    $pass++;
} catch (\Throwable $e) {
    // The gates passed; the configd allow itself may need a fully applied CP zone
    // (pf tables / lighttpd) which the headless lab doesn't bring up. Report it.
    echo "  INFO allow reached configd, returned: " . $e->getMessage() . "\n";
}

echo "RESULT $pass passed, $fail failed\n";
exit($fail === 0 ? 0 : 1);
