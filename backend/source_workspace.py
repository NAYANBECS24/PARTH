from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

from backend.adapters import ReverseEngineeringToolchain
from backend.config import settings


SHA256 = re.compile(r"^[a-f0-9]{64}$")
SOURCE_EXTENSIONS = {".java": "java", ".kt": "kotlin", ".xml": "xml", ".smali": "smali", ".properties": "text", ".txt": "text"}


class SourceWorkspaceError(RuntimeError):
    """Expected source-workspace failure that is safe to show to an analyst."""


class JadxSourceWorkspace:
    """Bounded, on-demand JADX output used only for static source review.

    APK code is never launched. JADX receives the uploaded archive as parser input,
    and output is kept below the application's data directory with an allowlisted
    text-file viewer. The workspace does not become a source of automatic findings.
    """

    @staticmethod
    def _workspace_dir(sample_sha256: str) -> Path:
        if not SHA256.fullmatch(sample_sha256):
            raise SourceWorkspaceError("Invalid sample hash for source workspace")
        root = settings.source_workspace_dir.resolve()
        target = (root / sample_sha256).resolve()
        if root not in target.parents:
            raise SourceWorkspaceError("Source workspace path escaped its controlled storage root")
        return target

    @classmethod
    def _source_root(cls, sample_sha256: str) -> Path:
        return cls._workspace_dir(sample_sha256) / "sources"

    @staticmethod
    def _jadx_environment() -> dict[str, str]:
        environment = os.environ.copy()
        bundled_java_home = settings.toolchain_dir / "jadx" / "jre"
        if not environment.get("JAVA_HOME") and (bundled_java_home / "bin" / "java.exe").is_file():
            environment["JAVA_HOME"] = str(bundled_java_home)
        return environment

    @classmethod
    def _files(cls, sample_sha256: str, query: str = "", limit: int | None = None) -> list[dict[str, Any]]:
        root = cls._source_root(sample_sha256).resolve()
        if not root.is_dir():
            return []
        normalized_query = query.strip().casefold()
        maximum = min(limit or settings.source_workspace_max_files, settings.source_workspace_max_files)
        records: list[dict[str, Any]] = []
        for path in sorted(root.rglob("*")):
            if len(records) >= maximum:
                break
            if not path.is_file() or path.suffix.lower() not in SOURCE_EXTENSIONS:
                continue
            resolved = path.resolve()
            if root not in resolved.parents:
                continue
            relative = resolved.relative_to(root).as_posix()
            if normalized_query and normalized_query not in relative.casefold():
                continue
            size = resolved.stat().st_size
            records.append(
                {
                    "path": relative,
                    "language": SOURCE_EXTENSIONS[resolved.suffix.lower()],
                    "byte_size": size,
                    "viewable": size <= settings.source_workspace_max_file_bytes,
                }
            )
        return records

    @classmethod
    def status(cls, sample_sha256: str, query: str = "", limit: int | None = None) -> dict[str, Any]:
        tool = ReverseEngineeringToolchain.detect_jadx()
        workspace_dir = cls._workspace_dir(sample_sha256)
        source_root = workspace_dir / "sources"
        generated = source_root.is_dir()
        return {
            "state": "ready" if generated else "not_generated" if tool.status == "available" else "unavailable",
            "tool": {"status": tool.status, "version": tool.version, "details": tool.details, "remediation": tool.remediation},
            "generated": generated,
            "files": cls._files(sample_sha256, query, limit) if generated else [],
            "limits": {
                "max_files": settings.source_workspace_max_files,
                "max_viewable_file_bytes": settings.source_workspace_max_file_bytes,
            },
        }

    @classmethod
    def generate(cls, sample_sha256: str, apk_path: Path) -> dict[str, Any]:
        tool = ReverseEngineeringToolchain.detect_jadx()
        if tool.status != "available" or not tool.path:
            raise SourceWorkspaceError(tool.remediation or "JADX is not available in this environment")
        if not apk_path.is_file():
            raise SourceWorkspaceError("The persisted APK file is unavailable")

        output_dir = cls._workspace_dir(sample_sha256)
        if (output_dir / "sources").is_dir():
            return cls.status(sample_sha256)

        root = settings.source_workspace_dir.resolve()
        root.mkdir(parents=True, exist_ok=True)
        temporary_dir = Path(tempfile.mkdtemp(prefix=f"{sample_sha256[:12]}-", dir=root)).resolve()
        if root not in temporary_dir.parents:
            raise SourceWorkspaceError("Temporary decompiler directory escaped controlled storage")
        try:
            process = subprocess.run(
                [tool.path, "--no-res", "--threads-count", "2", "--output-dir", str(temporary_dir), str(apk_path)],
                capture_output=True,
                text=True,
                timeout=settings.source_workspace_timeout_seconds,
                env=cls._jadx_environment(),
            )
            source_root = temporary_dir / "sources"
            if process.returncode != 0 or not source_root.is_dir():
                diagnostic = (process.stderr or process.stdout or "JADX did not produce source output").strip().replace("\n", " ")[:500]
                raise SourceWorkspaceError(f"JADX source recovery did not complete: {diagnostic}")
            temporary_dir.replace(output_dir)
        except subprocess.TimeoutExpired as error:
            raise SourceWorkspaceError("JADX source recovery exceeded the configured safety timeout") from error
        finally:
            if temporary_dir.exists():
                # This path is created above underneath the controlled workspace root.
                shutil.rmtree(temporary_dir, ignore_errors=True)
        return cls.status(sample_sha256)

    @classmethod
    def read(cls, sample_sha256: str, requested_path: str) -> dict[str, Any]:
        if not requested_path or len(requested_path) > 500:
            raise SourceWorkspaceError("A valid source file path is required")
        posix_path = PurePosixPath(requested_path)
        if posix_path.is_absolute() or ".." in posix_path.parts:
            raise SourceWorkspaceError("Source path is not allowed")
        root = cls._source_root(sample_sha256).resolve()
        target = (root / Path(*posix_path.parts)).resolve()
        if root not in target.parents or not target.is_file() or target.suffix.lower() not in SOURCE_EXTENSIONS:
            raise SourceWorkspaceError("Source file was not found")
        size = target.stat().st_size
        if size > settings.source_workspace_max_file_bytes:
            raise SourceWorkspaceError("Source file exceeds the safe viewer size limit")
        return {
            "path": target.relative_to(root).as_posix(),
            "language": SOURCE_EXTENSIONS[target.suffix.lower()],
            "byte_size": size,
            "content": target.read_text(encoding="utf-8", errors="replace"),
        }
