#!/usr/bin/env python3

"""Regression tests for the OpenVPN guard manifest parser."""

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "src/opnsense/scripts/OPNsense/SSO/vpn_guard.py"
SPEC = importlib.util.spec_from_file_location("vpn_guard", SOURCE)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {SOURCE}")
VPN_GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VPN_GUARD)


class LoadManifestTest(unittest.TestCase):
    """Exercise current and legacy representations of the instance map."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.original_manifest = VPN_GUARD.MANIFEST
        VPN_GUARD.MANIFEST = Path(self.temporary.name) / "openvpn-instances.json"

    def tearDown(self) -> None:
        VPN_GUARD.MANIFEST = self.original_manifest
        self.temporary.cleanup()

    def write_manifest(self, instances: object) -> None:
        VPN_GUARD.MANIFEST.write_text(
            json.dumps({"version": 1, "instances": instances}),
            encoding="utf-8",
        )

    def test_empty_instance_map(self) -> None:
        self.write_manifest({})
        self.assertEqual({}, VPN_GUARD.load_manifest())

    def test_legacy_empty_instance_list(self) -> None:
        self.write_manifest([])
        self.assertEqual({}, VPN_GUARD.load_manifest())

    @mock.patch.object(VPN_GUARD, "log")
    def test_non_empty_instance_list_is_rejected(self, log: mock.Mock) -> None:
        self.write_manifest([{"profile": "invalid"}])
        self.assertIsNone(VPN_GUARD.load_manifest())
        log.assert_called_once_with(
            "integration manifest has no instance map",
            VPN_GUARD.syslog.LOG_ERR,
        )


class SavedFlagsTest(unittest.TestCase):
    """The local config parser is bounded and never accepts XML entities."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.original_config = VPN_GUARD.CONFIG_XML
        self.original_limit = VPN_GUARD.CONFIG_XML_MAX_BYTES
        VPN_GUARD.CONFIG_XML = Path(self.temporary.name) / "config.xml"

    def tearDown(self) -> None:
        VPN_GUARD.CONFIG_XML = self.original_config
        VPN_GUARD.CONFIG_XML_MAX_BYTES = self.original_limit
        self.temporary.cleanup()

    def write_config(self, document: str) -> None:
        VPN_GUARD.CONFIG_XML.write_text(document, encoding="utf-8")

    def test_reads_managed_instance_flags(self) -> None:
        self.write_config(
            """<opnsense><OPNsense><OpenVPN><Instances>
            <Instance uuid="12345678-1234-1234-1234-123456789abc">
              <authmode></authmode>
              <various_flags>auth-user-pass-optional,verb 3</various_flags>
            </Instance>
            </Instances></OpenVPN></OPNsense></opnsense>"""
        )
        self.assertEqual(
            {
                "12345678-1234-1234-1234-123456789abc": (
                    ["auth-user-pass-optional", "verb 3"],
                    "",
                )
            },
            VPN_GUARD.saved_flags(),
        )

    @mock.patch.object(VPN_GUARD, "log")
    def test_rejects_dtd_and_entity_declarations(self, log: mock.Mock) -> None:
        self.write_config(
            "<!DOCTYPE opnsense [<!ENTITY x 'expanded'>]><opnsense>&x;</opnsense>"
        )
        self.assertIsNone(VPN_GUARD.saved_flags())
        self.assertIn("DTD and entity declarations", log.call_args.args[0])

    @mock.patch.object(VPN_GUARD, "log")
    def test_rejects_oversized_config_before_parsing(self, log: mock.Mock) -> None:
        VPN_GUARD.CONFIG_XML_MAX_BYTES = 32
        self.write_config("<opnsense>" + ("x" * 64) + "</opnsense>")
        self.assertIsNone(VPN_GUARD.saved_flags())
        self.assertIn("document exceeds 32 bytes", log.call_args.args[0])


class RuntimeGuardTest(unittest.TestCase):
    """Inspect the loaded runtime file even after config.xml has been repaired."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.uuid = "11111111-1111-4111-8111-111111111111"
        self.settings = {
            "profile": "staff",
            "auth_directive": 'auth-user-pass-verify "/usr/local/opnsense/scripts/OPNsense/SSO/auth-user-pass-verify.sh staff" via-file',
            "optional_directive": "auth-user-pass-optional",
            "config_file": str(Path(self.temporary.name) / "runtime.conf"),
            "pid_file": str(Path(self.temporary.name) / "runtime.pid"),
        }
        self.valid_flags = [self.settings["auth_directive"], self.settings["optional_directive"]]
        self.manifest = {self.uuid: self.settings}
        self.instances = {self.uuid: (self.valid_flags, "")}

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_repaired_saved_config_does_not_hide_unsafe_runtime(self) -> None:
        Path(self.settings["config_file"]).write_text("dev tun\n", encoding="utf-8")
        self.assertTrue(VPN_GUARD.saved_config_valid(self.uuid, self.settings, self.instances))
        self.assertFalse(VPN_GUARD.generated_config_valid(self.settings))
        with mock.patch.object(VPN_GUARD, "load_manifest", return_value=self.manifest), \
             mock.patch.object(VPN_GUARD, "process_running", return_value=True), \
             mock.patch.object(VPN_GUARD, "saved_config_valid", return_value=True), \
             mock.patch.object(VPN_GUARD, "repair") as repair, \
             mock.patch.object(VPN_GUARD, "log"), \
             mock.patch.object(VPN_GUARD.time, "sleep", side_effect=RuntimeError("one iteration")):
            with self.assertRaisesRegex(RuntimeError, "one iteration"):
                VPN_GUARD.main()
            repair.assert_called_once_with([self.uuid])

    def test_second_password_verifier_is_not_safe(self) -> None:
        flags = self.valid_flags + ['auth-user-pass-verify "/other/verifier" via-env']
        self.assertFalse(VPN_GUARD.saved_config_valid(self.uuid, self.settings, {self.uuid: (flags, "")}))
        Path(self.settings["config_file"]).write_text("\n".join(flags), encoding="utf-8")
        self.assertFalse(VPN_GUARD.generated_config_valid(self.settings))

    def test_conflicting_selection_stays_blocked(self) -> None:
        self.assertFalse(VPN_GUARD.saved_config_valid(self.uuid, self.settings | {"blocked": "1"}, self.instances))

    def test_partial_sync_restarts_only_validated_instance(self) -> None:
        other = "22222222-2222-4222-8222-222222222222"
        blocked = self.settings | {"blocked": "1"}
        manifest = self.manifest | {other: blocked}
        instances = self.instances | {other: (self.valid_flags, "")}
        result = subprocess.CompletedProcess([], 0, "PARTIAL: changed=1 managed=1; invalid other profile", "")
        with mock.patch.object(VPN_GUARD, "configctl", return_value=result) as control, \
             mock.patch.object(VPN_GUARD, "load_manifest", return_value=manifest), \
             mock.patch.object(VPN_GUARD, "saved_flags", return_value=instances), \
             mock.patch.object(VPN_GUARD, "generated_config_valid", return_value=True), \
             mock.patch.object(VPN_GUARD, "log"):
            VPN_GUARD.repair([self.uuid, other])
        self.assertEqual([
            mock.call("openvpn", "stop", self.uuid),
            mock.call("openvpn", "stop", other),
            mock.call("sso", "sync_openvpn"),
            mock.call("openvpn", "restart", self.uuid),
        ], control.call_args_list)

    def test_failed_reconciliation_never_restarts(self) -> None:
        result = subprocess.CompletedProcess([], 1, "", "cannot save config")
        with mock.patch.object(VPN_GUARD, "configctl", return_value=result) as control, \
             mock.patch.object(VPN_GUARD, "log"):
            VPN_GUARD.repair([self.uuid])
        self.assertEqual([mock.call("openvpn", "stop", self.uuid), mock.call("sso", "sync_openvpn")], control.call_args_list)

    def test_failed_runtime_verification_stops_instance_again(self) -> None:
        result = subprocess.CompletedProcess([], 0, "OK: changed=1 managed=1", "")
        with mock.patch.object(VPN_GUARD, "configctl", return_value=result) as control, \
             mock.patch.object(VPN_GUARD, "load_manifest", return_value=self.manifest), \
             mock.patch.object(VPN_GUARD, "saved_flags", return_value=self.instances), \
             mock.patch.object(VPN_GUARD, "generated_config_valid", return_value=False), \
             mock.patch.object(VPN_GUARD, "log"):
            VPN_GUARD.repair([self.uuid])
        self.assertEqual(mock.call("openvpn", "stop", self.uuid), control.call_args_list[-1])


if __name__ == "__main__":
    unittest.main()
