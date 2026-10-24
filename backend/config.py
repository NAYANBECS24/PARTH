from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")


def _path_setting(name: str, default: str) -> Path:
    value = Path(os.getenv(name, default))
    return value if value.is_absolute() else (ROOT / value).resolve()


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    database_path: Path
    max_upload_bytes: int
    max_archive_entries: int
    max_uncompressed_bytes: int
    max_compression_ratio: int
    analysis_poll_seconds: float
    enable_nvidia: bool
    allow_fixtures: bool
    cors_origins: tuple[str, ...]

    @property
    def upload_dir(self) -> Path:
        return self.data_dir / "uploads"

    @property
    def report_dir(self) -> Path:
        return self.data_dir / "reports"

    @property
    def capsule_dir(self) -> Path:
        return self.data_dir / "capsules"

    def ensure_directories(self) -> None:
        for directory in (self.data_dir, self.upload_dir, self.report_dir, self.capsule_dir):
            directory.mkdir(parents=True, exist_ok=True)


def get_settings() -> Settings:
    data_dir = _path_setting("SHADOWPATH_DATA_DIR", "data")
    database_path = _path_setting("SHADOWPATH_DATABASE_URL", "data/shadowpath.db")
    settings = Settings(
        data_dir=data_dir,
        database_path=database_path,
        max_upload_bytes=int(os.getenv("SHADOWPATH_MAX_UPLOAD_BYTES", "104857600")),
        max_archive_entries=int(os.getenv("SHADOWPATH_MAX_ARCHIVE_ENTRIES", "12000")),
        max_uncompressed_bytes=int(os.getenv("SHADOWPATH_MAX_UNCOMPRESSED_BYTES", "536870912")),
        max_compression_ratio=int(os.getenv("SHADOWPATH_MAX_COMPRESSION_RATIO", "120")),
        analysis_poll_seconds=float(os.getenv("SHADOWPATH_ANALYSIS_POLL_SECONDS", "1")),
        enable_nvidia=os.getenv("SHADOWPATH_ENABLE_NVIDIA", "false").lower() == "true",
        allow_fixtures=os.getenv("SHADOWPATH_ALLOW_FIXTURES", "false").lower() == "true",
        cors_origins=tuple(
            origin.strip()
            for origin in os.getenv("SHADOWPATH_CORS_ORIGINS", "http://127.0.0.1:5173,http://localhost:5173").split(",")
            if origin.strip()
        ),
    )
    settings.ensure_directories()
    return settings


settings = get_settings()
