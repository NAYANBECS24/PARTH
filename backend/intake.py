from __future__ import annotations

import hashlib
import shutil
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path

from fastapi import HTTPException, UploadFile

from backend.config import Settings, settings


@dataclass(frozen=True)
class StoredUpload:
    sha256: str
    byte_size: int
    original_filename: str
    storage_path: Path
    archive_entry_count: int


def _reject(detail: str, status_code: int = 422) -> None:
    raise HTTPException(status_code=status_code, detail={"code": "invalid_apk", "message": detail})


def validate_archive(path: Path, app_settings: Settings = settings) -> int:
    try:
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            if not members:
                _reject("The APK archive is empty.")
            if len(members) > app_settings.max_archive_entries:
                _reject(f"Archive has more than {app_settings.max_archive_entries} entries.")

            total_uncompressed = 0
            for member in members:
                name = member.filename.replace("\\", "/")
                if name.startswith("/") or ".." in Path(name).parts:
                    _reject("Archive contains a traversal or absolute entry path.")
                total_uncompressed += member.file_size
                if total_uncompressed > app_settings.max_uncompressed_bytes:
                    _reject("Archive exceeds the safe uncompressed-size limit.")
                if member.compress_size == 0 and member.file_size > 0:
                    _reject("Archive contains an invalid zero-sized compressed member.")
                if member.compress_size > 0 and member.file_size / member.compress_size > app_settings.max_compression_ratio:
                    _reject("Archive exceeds the allowed compression ratio.")
            return len(members)
    except zipfile.BadZipFile as error:
        _reject(f"File is not a valid ZIP/APK archive: {error}")
    raise AssertionError("unreachable")


async def store_upload(upload: UploadFile, app_settings: Settings = settings) -> StoredUpload:
    original_filename = Path(upload.filename or "upload.apk").name
    if not original_filename.lower().endswith(".apk"):
        _reject("Only .apk files are accepted.")

    temporary_path = app_settings.upload_dir / f".intake-{uuid.uuid4().hex}.part"
    digest = hashlib.sha256()
    byte_size = 0
    try:
        with temporary_path.open("xb") as target:
            while chunk := await upload.read(1024 * 1024):
                byte_size += len(chunk)
                if byte_size > app_settings.max_upload_bytes:
                    _reject(f"Upload exceeds the {app_settings.max_upload_bytes}-byte safety limit.", 413)
                digest.update(chunk)
                target.write(chunk)

        if byte_size < 4:
            _reject("The uploaded file is too small to be an APK.")
        with temporary_path.open("rb") as source:
            if source.read(4) != b"PK\x03\x04":
                _reject("APK files must begin with a standard ZIP local-file header.")

        entry_count = validate_archive(temporary_path, app_settings)
        sha256 = digest.hexdigest()
        stored_path = app_settings.upload_dir / f"{sha256}.apk"
        if stored_path.exists():
            temporary_path.unlink(missing_ok=True)
        else:
            shutil.move(str(temporary_path), str(stored_path))
        return StoredUpload(sha256, byte_size, original_filename, stored_path, entry_count)
    finally:
        temporary_path.unlink(missing_ok=True)
        await upload.close()
