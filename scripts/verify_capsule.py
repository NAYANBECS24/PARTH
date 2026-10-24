from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.reports import verify_capsule  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify every file hash recorded in a SHADOWPATH evidence capsule")
    parser.add_argument("capsule", type=Path, help="Path to the exported capsule ZIP")
    args = parser.parse_args()
    result = verify_capsule(args.capsule)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
