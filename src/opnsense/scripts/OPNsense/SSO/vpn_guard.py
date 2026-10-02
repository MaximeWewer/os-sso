#!/usr/local/bin/python3

"""Fail closed when a managed OpenVPN instance loses the os-sso auth hook."""

import json
import os
import re
import subprocess
import syslog
import time
import xml.etree.ElementTree as ET
from pathlib import Path


MANIFEST = Path("/usr/local/etc/sso/openvpn-instances.json")
CONFIG_XML = Path("/conf/config.xml")
UUID = re.compile(r"^[0-9a-f-]{36}$")
CHECK_INTERVAL = 1.0
REPAIR_BACKOFF = 30.0


def log(message: str, priority: int = syslog.LOG_NOTICE) -> None:
    syslog.syslog(priority, message.replace("\n", " ").replace("\r", " "))


def load_manifest() -> dict[str, dict[str, str]] | None:
    try:
        payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exception:
        log(f"cannot read integration manifest: {exception}", syslog.LOG_ERR)
        return None

    instances = payload.get("instances", {})
    if not isinstance(instances, dict):
        log("integration manifest has no instance map", syslog.LOG_ERR)
        return None

    result: dict[str, dict[str, str]] = {}
    for uuid, settings in instances.items():
        if not isinstance(uuid, str) or UUID.fullmatch(uuid) is None or not isinstance(settings, dict):
            log("integration manifest contains an invalid instance", syslog.LOG_ERR)
            continue
        required = {"profile", "auth_directive", "optional_directive", "config_file", "pid_file"}
        if not required.issubset(settings) or not all(isinstance(settings[key], str) for key in required):
            log(f"integration manifest for {uuid} is incomplete", syslog.LOG_ERR)
            continue
        result[uuid] = settings
    return result


def saved_flags() -> dict[str, tuple[list[str], str]] | None:
    try:
        root = ET.parse(CONFIG_XML).getroot()
    except (OSError, ET.ParseError) as exception:
        log(f"cannot inspect config.xml: {exception}", syslog.LOG_ERR)
        return None

    result: dict[str, tuple[list[str], str]] = {}
    for instance in root.findall("./OPNsense/OpenVPN/Instances/Instance"):
        uuid = instance.attrib.get("uuid", "")
        flags = [flag.strip() for flag in (instance.findtext("various_flags") or "").split(",") if flag.strip()]
        result[uuid] = (flags, (instance.findtext("authmode") or "").strip())
    return result


def process_running(pid_file: str) -> bool:
    try:
        pid = int(Path(pid_file).read_text(encoding="ascii").strip())
        os.kill(pid, 0)
        return True
    except (FileNotFoundError, OSError, ValueError):
        return False


def generated_config_valid(settings: dict[str, str]) -> bool:
    try:
        lines = [line.strip() for line in Path(settings["config_file"]).read_text(encoding="utf-8").splitlines()]
    except OSError:
        return False

    auth_lines = [line for line in lines if line.startswith("auth-user-pass-verify ")]
    return auth_lines == [settings["auth_directive"]] and settings["optional_directive"] in lines


def saved_config_valid(
    uuid: str,
    settings: dict[str, str],
    instances: dict[str, tuple[list[str], str]] | None,
) -> bool:
    if instances is None or uuid not in instances:
        return False
    flags, authmode = instances[uuid]
    return authmode == "" and settings["auth_directive"] in flags and settings["optional_directive"] in flags


def configctl(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["/usr/local/sbin/configctl", *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )


def repair(uuids: list[str]) -> None:
    for uuid in uuids:
        result = configctl("openvpn", "stop", uuid)
        if result.returncode != 0:
            log(f"could not stop unsafe OpenVPN instance {uuid}: {result.stderr.strip()}", syslog.LOG_ERR)

    sync = configctl("sso", "sync_openvpn")
    if sync.returncode != 0 or not sync.stdout.lstrip().startswith("OK:"):
        detail = (sync.stderr or sync.stdout).strip()
        log(f"OpenVPN integration repair failed; managed instances remain stopped: {detail}", syslog.LOG_ERR)
        return

    configure = configctl("openvpn", "configure")
    if configure.returncode != 0:
        log(f"OpenVPN reconfiguration failed: {configure.stderr.strip()}", syslog.LOG_ERR)
        return
    log(f"repaired and reconfigured managed OpenVPN instance(s): {', '.join(uuids)}")


def main() -> None:
    syslog.openlog("os-sso-vpn-guard", facility=syslog.LOG_AUTH)
    last_repair = 0.0
    last_problem: tuple[str, ...] = ()
    last_manifest: dict[str, dict[str, str]] = {}
    config_stamp: tuple[int, int] | None = None
    config_instances: dict[str, tuple[list[str], str]] | None = {}

    while True:
        manifest = load_manifest()
        if manifest is None:
            # Recover a deleted/corrupt manifest from config.xml. Until that
            # succeeds, retain the last valid one instead of silently forgetting
            # which running instances are supposed to be protected.
            configctl("sso", "sync_openvpn")
            manifest = load_manifest()
            if manifest is None:
                manifest = last_manifest
        last_manifest = manifest
        if manifest:
            try:
                stat = CONFIG_XML.stat()
                current_stamp = (stat.st_mtime_ns, stat.st_size)
            except OSError:
                current_stamp = None
            if current_stamp != config_stamp:
                config_instances = saved_flags()
                config_stamp = current_stamp
        else:
            config_instances = {}
            config_stamp = None
        unsafe = []
        for uuid, settings in manifest.items():
            if not process_running(settings["pid_file"]):
                continue
            if not saved_config_valid(uuid, settings, config_instances) or not generated_config_valid(settings):
                unsafe.append(uuid)

        problem = tuple(sorted(unsafe))
        now = time.monotonic()
        if problem and (problem != last_problem or now - last_repair >= REPAIR_BACKOFF):
            log(
                f"stopping OpenVPN instance(s) without enforced os-sso authentication: {', '.join(problem)}",
                syslog.LOG_WARNING,
            )
            repair(list(problem))
            last_repair = now
        last_problem = problem
        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()
