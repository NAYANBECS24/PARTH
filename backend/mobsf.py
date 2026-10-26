from __future__ import annotations

import hashlib
import json
import mimetypes
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


class MobSFError(RuntimeError):
    """An isolated MobSF request did not produce a usable static report."""


@dataclass(frozen=True)
class MobSFStaticReport:
    scan_hash: str
    scan_type: str
    summary: dict[str, Any]
    report_sha256: str


class MobSFClient:
    """Small allowlisted client for MobSF's static-analysis REST API.

    The client deliberately exposes only upload + static scan. Dynamic MobSF
    operations are not available from this application because they require a
    separately quarantined Android runtime and explicit analyst approval.
    """

    def __init__(self, base_url: str, api_key: str, timeout_seconds: float) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds

    def _request(self, path: str, data: bytes, content_type: str) -> dict[str, Any]:
        request = Request(
            f"{self.base_url}{path}",
            data=data,
            method="POST",
            headers={
                "Authorization": self.api_key,
                "X-Mobsf-Api-Key": self.api_key,
                "Content-Type": content_type,
                "Accept": "application/json",
            },
        )
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:  # noqa: S310 - endpoint is explicit analyst configuration
                body = response.read()
        except HTTPError as error:
            message = error.read().decode("utf-8", errors="replace")[:500]
            raise MobSFError(f"MobSF returned HTTP {error.code}: {message}") from error
        except URLError as error:
            raise MobSFError(f"MobSF connection failed: {error.reason}") from error
        except TimeoutError as error:
            raise MobSFError("MobSF request timed out") from error

        try:
            payload = json.loads(body)
        except json.JSONDecodeError as error:
            raise MobSFError("MobSF returned a non-JSON response") from error
        if not isinstance(payload, dict):
            raise MobSFError("MobSF returned an unexpected response shape")
        if payload.get("error"):
            raise MobSFError(f"MobSF error: {str(payload['error'])[:500]}")
        return payload

    @staticmethod
    def _multipart(apk_path: Path) -> tuple[bytes, str]:
        boundary = f"----shadowpath-{secrets.token_hex(16)}"
        filename = apk_path.name.replace('"', "")
        content_type = mimetypes.guess_type(filename)[0] or "application/vnd.android.package-archive"
        body = b"".join(
            (
                f"--{boundary}\r\n".encode(),
                f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode(),
                f"Content-Type: {content_type}\r\n\r\n".encode(),
                apk_path.read_bytes(),
                f"\r\n--{boundary}--\r\n".encode(),
            )
        )
        return body, f"multipart/form-data; boundary={boundary}"

    @staticmethod
    def _summary(report: dict[str, Any], scan_hash: str, scan_type: str) -> dict[str, Any]:
        permissions = report.get("permissions")
        permissions_count = len(permissions) if isinstance(permissions, (dict, list)) else None
        return {
            "provider": "mobsf",
            "scan_hash": scan_hash,
            "scan_type": scan_type,
            "app_name": report.get("app_name") or report.get("file_name"),
            "package_name": report.get("package_name") or report.get("package"),
            "version_name": report.get("version_name"),
            "security_score": report.get("security_score"),
            "permissions_count": permissions_count,
        }

    def scan_apk(self, apk_path: Path) -> MobSFStaticReport:
        upload_body, content_type = self._multipart(apk_path)
        upload = self._request("/api/v1/upload", upload_body, content_type)
        scan_hash = upload.get("hash")
        scan_type = upload.get("scan_type")
        if not isinstance(scan_hash, str) or not isinstance(scan_type, str):
            raise MobSFError("MobSF upload did not return a scan hash and type")
        scan = self._request(
            "/api/v1/scan",
            urlencode({"hash": scan_hash, "scan_type": scan_type, "re_scan": "0"}).encode(),
            "application/x-www-form-urlencoded",
        )
        canonical = json.dumps(scan, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        return MobSFStaticReport(
            scan_hash=scan_hash,
            scan_type=scan_type,
            summary=self._summary(scan, scan_hash, scan_type),
            report_sha256=hashlib.sha256(canonical).hexdigest(),
        )
