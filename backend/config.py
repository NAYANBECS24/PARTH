from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")
# Created only by scripts/configure-mobsf.ps1 and intentionally ignored by Git.
# A complete explicit shell/.env configuration retains precedence. Otherwise the
# generated local pair replaces empty placeholder values from .env.example.
if not (os.getenv("MOBSF_API_URL") and os.getenv("MOBSF_API_KEY")):
    load_dotenv(ROOT / ".mobsf.env", override=True)


def _is_serverless_environment() -> bool:
    """Detect serverless runtimes even when optional Vercel variables are hidden."""
    return bool(
        os.getenv("VERCEL")
        or os.getenv("VERCEL_ENV")
        or os.getenv("VERCEL_REGION")
        or os.getenv("AWS_LAMBDA_FUNCTION_NAME")
        or Path("/var/task").is_dir()
    )


def _path_setting(name: str, default: str) -> Path:
    value = Path(os.getenv(name, default))
    return value if value.is_absolute() else (ROOT / value).resolve()


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    database_path: Path
    toolchain_dir: Path
    mobsf_api_url: str | None
    mobsf_api_key: str | None
    mobsf_timeout_seconds: float
    max_upload_bytes: int
    max_archive_entries: int
    max_uncompressed_bytes: int
    max_compression_ratio: int
    analysis_poll_seconds: float
    auth_disabled: bool
    enable_nvidia: bool
    nvidia_api_key: str | None
    nvidia_base_url: str
    nvidia_model: str
    nvidia_max_tokens: int
    nvidia_timeout_seconds: float
    nvidia_daily_call_budget: int
    allow_fixtures: bool
    cors_origins: tuple[str, ...]

    @property
    def nvidia_configured(self) -> bool:
        return self.enable_nvidia and bool(self.nvidia_api_key) and bool(self.nvidia_model)

    @property
    def mobsf_configured(self) -> bool:
        return bool(self.mobsf_api_url and self.mobsf_api_key)

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
    is_serverless = _is_serverless_environment()
    if is_serverless:
        data_dir = Path("/tmp/shadowpath_data")
        database_path = Path("/tmp/shadowpath_data/shadowpath.db")
        data_dir.mkdir(parents=True, exist_ok=True)
        seed_db = ROOT / "data" / "shadowpath.db"
        if not database_path.exists() and seed_db.exists():
            import shutil
            try:
                shutil.copy2(seed_db, database_path)
                for sub in ("reports", "capsules", "uploads"):
                    src_sub = ROOT / "data" / sub
                    dest_sub = data_dir / sub
                    if src_sub.exists() and not dest_sub.exists():
                        shutil.copytree(src_sub, dest_sub)
            except Exception:
                pass
    else:
        data_dir = _path_setting("SHADOWPATH_DATA_DIR", "data")
        database_path = _path_setting("SHADOWPATH_DATABASE_URL", "data/shadowpath.db")

    default_auth_disabled = "true" if is_serverless else "false"
    auth_disabled = os.getenv("SHADOWPATH_AUTH_DISABLED", default_auth_disabled).lower() == "true"

    mobsf_disabled = os.getenv("SHADOWPATH_DISABLE_MOBSF", "false").lower() == "true"
    mobsf_api_url = None if mobsf_disabled else (os.getenv("MOBSF_API_URL", "").strip().rstrip("/") or None)
    mobsf_api_key = None if mobsf_disabled else (os.getenv("MOBSF_API_KEY", "").strip() or None)

    settings = Settings(
        data_dir=data_dir,
        database_path=database_path,
        toolchain_dir=_path_setting("SHADOWPATH_TOOLCHAIN_DIR", ".toolcache"),
        mobsf_api_url=mobsf_api_url,
        mobsf_api_key=mobsf_api_key,
        mobsf_timeout_seconds=max(10.0, min(float(os.getenv("MOBSF_TIMEOUT_SECONDS", "180")), 600.0)),
        max_upload_bytes=int(os.getenv("SHADOWPATH_MAX_UPLOAD_BYTES", "104857600")),
        max_archive_entries=int(os.getenv("SHADOWPATH_MAX_ARCHIVE_ENTRIES", "12000")),
        max_uncompressed_bytes=int(os.getenv("SHADOWPATH_MAX_UNCOMPRESSED_BYTES", "536870912")),
        max_compression_ratio=int(os.getenv("SHADOWPATH_MAX_COMPRESSION_RATIO", "120")),
        analysis_poll_seconds=float(os.getenv("SHADOWPATH_ANALYSIS_POLL_SECONDS", "1")),
        auth_disabled=auth_disabled,
        enable_nvidia=os.getenv("SHADOWPATH_ENABLE_NVIDIA", "false").lower() == "true",
        nvidia_api_key=os.getenv("NVIDIA_API_KEY") or None,
        nvidia_base_url=os.getenv("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1").rstrip("/"),
        nvidia_model=os.getenv("NVIDIA_MODEL", "nvidia/nemotron-3-ultra-550b-a55b"),
        nvidia_max_tokens=max(256, min(int(os.getenv("NVIDIA_MAX_TOKENS", "1200")), 4096)),
        nvidia_timeout_seconds=max(5.0, min(float(os.getenv("NVIDIA_TIMEOUT_SECONDS", "45")), 120.0)),
        nvidia_daily_call_budget=max(1, min(int(os.getenv("NVIDIA_DAILY_CALL_BUDGET", "25")), 500)),
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
