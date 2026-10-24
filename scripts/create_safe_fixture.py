"""Create a non-installable, controlled static-analysis fixture for local demos/tests.

It intentionally contains only a textual manifest and a DEX-shaped byte stream. It is
not a real application and must never be represented as malware or a production APK.
"""

from __future__ import annotations

import argparse
import zipfile
from pathlib import Path


MANIFEST = b'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.shadowpath.fixture">
  <uses-permission android:name="android.permission.SEND_SMS" />
  <application android:label="Controlled Static Fixture">
    <activity android:name=".ExportedTestActivity" android:exported="true" />
  </application>
</manifest>'''
DEX_SHAPED_TEXT = (
    b"dex\n035\x00"
    b"https://controlled.example.test/diagnostic "
    b"DexClassLoader Class.forName controlled fixture only"
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("fixtures/controlled_static_fixture.apk"))
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(args.output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", MANIFEST)
        archive.writestr("classes.dex", DEX_SHAPED_TEXT)
        archive.writestr("META-INF/CERT.RSA", b"SHADOWPATH-CONTROLLED-TEST-CERTIFICATE")
        archive.writestr("lib/armeabi-v7a/libcontrolled.so", b"CONTROLLED-NATIVE-PLACEHOLDER")
    print(f"Created {args.output} (controlled, non-installable static fixture).")


if __name__ == "__main__":
    main()
