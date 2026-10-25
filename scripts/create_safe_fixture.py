"""Create non-installable, controlled static-analysis fixtures for local demos/tests.

These fixtures intentionally contain textual manifests and DEX-shaped byte streams.
They are not real applications and must never be represented as malware or production APKs.
Adheres to Section 24 and Appendix II of the SHADOWPATH engineering contract.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from pathlib import Path


BASE_DIR = Path("fixtures")
SAFE_APPS_DIR = BASE_DIR / "safe-android-apps"
EXPECTED_DIR = BASE_DIR / "expected"


def make_manifest(pkg: str, label: str, permissions: list[str] | None = None, exported_activity: str | None = None) -> bytes:
    perms_xml = "".join(f'  <uses-permission android:name="{p}" />\n' for p in (permissions or []))
    activity_xml = f'    <activity android:name="{exported_activity}" android:exported="true" />\n' if exported_activity else ""
    return f'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{pkg}">
{perms_xml}  <application android:label="{label}">
{activity_xml}  </application>
</manifest>'''.encode("utf-8")


def build_fixture_apk(
    dest_path: Path,
    manifest_bytes: bytes,
    dex_bytes: bytes,
    native_so: bytes | None = None,
    cert_bytes: bytes | None = None,
    guard_manifest: dict | None = None,
) -> str:
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(dest_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", manifest_bytes)
        archive.writestr("classes.dex", dex_bytes)
        if cert_bytes:
            archive.writestr("META-INF/CERT.RSA", cert_bytes)
        if native_so:
            archive.writestr("lib/armeabi-v7a/libsample.so", native_so)
        if guard_manifest:
            archive.writestr("assets/guard_manifest.json", json.dumps(guard_manifest, indent=2).encode("utf-8"))
    sha = hashlib.sha256(dest_path.read_bytes()).hexdigest()
    return sha


def generate_all_fixtures() -> None:
    SAFE_APPS_DIR.mkdir(parents=True, exist_ok=True)
    EXPECTED_DIR.mkdir(parents=True, exist_ok=True)

    fixtures = [
        {
            "name": "hello_world",
            "manifest": make_manifest("org.shadowpath.hello", "Hello World"),
            "dex": b"dex\n035\x00Hello world benign sample",
            "cert": b"SHADOWPATH-HELLO-WORLD-CERT",
            "expected": {
                "fixture": "hello_world",
                "synthetic": True,
                "expected": {
                    "manifest_parsed": True,
                    "findings_count": 0,
                    "runtime_maliciousness_claim": False,
                },
                "notes": "Benign hello world app with no sensitive declarations.",
            },
        },
        {
            "name": "time_guarded_sink",
            "manifest": make_manifest("org.shadowpath.timeguard", "Time Guarded Test", ["android.permission.SEND_SMS"]),
            "dex": (
                b"dex\n035\x00"
                b"time_guarded elapsed_minutes Landroid/telephony/SmsManager;->sendTextMessage "
                b"https://telemetry.control.test/report"
            ),
            "cert": b"SHADOWPATH-TIMEGUARD-CERT",
            "guard_manifest": {
                "target_method": "Landroid/telephony/SmsManager;->sendTextMessage",
                "ast": {
                    "kind": "and",
                    "terms": [
                        {"kind": "compare", "left": {"var": "elapsed_minutes", "type": "int"}, "op": "ge", "right": {"literal": 10}}
                    ],
                    "source": {"dex": "classes.dex", "method": "Lorg/shadowpath/Guard;->shouldTrigger()Z", "block": "bb_01"},
                },
                "assumptions": ["Device elapsed time is measured in whole minutes"],
            },
            "expected": {
                "fixture": "time_guarded_sink",
                "synthetic": True,
                "expected": {
                    "guard_class": "simple_time_comparison",
                    "solver_status": "sat",
                    "sensitive_operation": "android.permission.SEND_SMS",
                    "evidence_status": "conditionally_reachable",
                },
                "notes": "Controlled fixture with time guard resolved via Z3 solver.",
            },
        },
        {
            "name": "device_guarded_sink",
            "manifest": make_manifest("org.shadowpath.deviceguard", "Device Guarded Test", ["android.permission.READ_CONTACTS"]),
            "dex": (
                b"dex\n035\x00"
                b"device_guarded mock_device_state Landroid/provider/ContactsContract;->openInputStream "
                b"https://exfil.control.test/contacts"
            ),
            "cert": b"SHADOWPATH-DEVICEGUARD-CERT",
            "guard_manifest": {
                "target_method": "Landroid/provider/ContactsContract;->openInputStream",
                "ast": {
                    "kind": "and",
                    "terms": [
                        {"kind": "compare", "left": {"var": "mock_device_state", "type": "string"}, "op": "eq", "right": {"literal": "ready"}}
                    ],
                    "source": {"dex": "classes.dex", "method": "Lorg/shadowpath/Guard;->checkDevice()Z", "block": "bb_02"},
                },
                "assumptions": ["Device state matches 'ready'"],
            },
            "expected": {
                "fixture": "device_guarded_sink",
                "synthetic": True,
                "expected": {
                    "guard_class": "device_state_comparison",
                    "solver_status": "sat",
                    "sensitive_operation": "android.permission.READ_CONTACTS",
                    "evidence_status": "conditionally_reachable",
                },
                "notes": "Controlled fixture with device-state guard resolved via Z3.",
            },
        },
        {
            "name": "dead_branch",
            "manifest": make_manifest("org.shadowpath.deadbranch", "Dead Branch Test"),
            "dex": (
                b"dex\n035\x00"
                b"dead_branch branch_flag Ldalvik/system/DexClassLoader;->loadClass"
            ),
            "cert": b"SHADOWPATH-DEADBRANCH-CERT",
            "guard_manifest": {
                "target_method": "Ldalvik/system/DexClassLoader;->loadClass",
                "ast": {
                    "kind": "and",
                    "terms": [
                        {"kind": "compare", "left": {"var": "branch_flag", "type": "int"}, "op": "gt", "right": {"literal": 10}},
                        {"kind": "compare", "left": {"var": "branch_flag", "type": "int"}, "op": "lt", "right": {"literal": 5}},
                    ],
                    "source": {"dex": "classes.dex", "method": "Lorg/shadowpath/Guard;->unreachableBranch()Z", "block": "bb_dead"},
                },
                "assumptions": ["Mutually exclusive integer bounds"],
            },
            "expected": {
                "fixture": "dead_branch",
                "synthetic": True,
                "expected": {
                    "guard_class": "contradictory_bounds",
                    "solver_status": "unsat",
                    "evidence_status": "observed",
                },
                "notes": "Unsatisfiable dead code branch proven UNSAT by Z3.",
            },
        },
        {
            "name": "manifest_misconfig",
            "manifest": make_manifest(
                "org.shadowpath.misconfig",
                "Misconfiguration Test",
                ["android.permission.SEND_SMS"],
                ".ExportedUnprotectedActivity",
            ),
            "dex": b"dex\n035\x00misconfig test code",
            "cert": b"SHADOWPATH-MISCONFIG-CERT",
            "expected": {
                "fixture": "manifest_misconfig",
                "synthetic": True,
                "expected": {
                    "exported_components": 1,
                    "sensitive_permissions": ["android.permission.SEND_SMS"],
                    "rules": ["SP-APK-001", "SP-APK-002"],
                },
                "notes": "Deliberately exported component without protection.",
            },
        },
        {
            "name": "reflection_unknown",
            "manifest": make_manifest("org.shadowpath.reflection", "Reflection Test"),
            "dex": b"dex\n035\x00DexClassLoader PathClassLoader Class.forName java/lang/reflect",
            "cert": b"SHADOWPATH-REFLECTION-CERT",
            "expected": {
                "fixture": "reflection_unknown",
                "synthetic": True,
                "expected": {
                    "blindspots": ["DYNAMIC_CODE_LOADING_UNRESOLVED", "REFLECTION_TARGET_UNRESOLVED"],
                },
                "notes": "Reflection-related strings producing explicit blindspot ledger entries.",
            },
        },
    ]

    for item in fixtures:
        apk_file = SAFE_APPS_DIR / f"{item['name']}.apk"
        sha = build_fixture_apk(
            apk_file,
            item["manifest"],
            item["dex"],
            cert_bytes=item.get("cert"),
            guard_manifest=item.get("guard_manifest"),
        )
        expected_meta = dict(item["expected"])
        expected_meta["apk_sha256"] = sha
        expected_path = EXPECTED_DIR / f"{item['name']}.expected.json"
        expected_path.write_text(json.dumps(expected_meta, indent=2), encoding="utf-8")
        print(f"Created {apk_file} (SHA: {sha[:12]}...) with ground truth {expected_path.name}")

    # Also build the default controlled_static_fixture.apk
    default_manifest = make_manifest("org.shadowpath.fixture", "Controlled Static Fixture", ["android.permission.SEND_SMS"], ".ExportedTestActivity")
    default_dex = (
        b"dex\n035\x00"
        b"time_guarded elapsed_minutes "
        b"https://controlled.example.test/diagnostic "
        b"DexClassLoader Class.forName controlled fixture only"
    )
    default_apk = BASE_DIR / "controlled_static_fixture.apk"
    sha = build_fixture_apk(
        default_apk,
        default_manifest,
        default_dex,
        native_so=b"CONTROLLED-NATIVE-PLACEHOLDER",
        cert_bytes=b"SHADOWPATH-CONTROLLED-TEST-CERTIFICATE",
    )
    print(f"Created {default_apk} (SHA: {sha[:12]}...)")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--matrix", action="store_true", default=True, help="Generate entire safe fixture matrix")
    args = parser.parse_args()
    generate_all_fixtures()


if __name__ == "__main__":
    main()
