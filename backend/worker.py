from __future__ import annotations

import argparse
import time

from backend.analyzer import next_queued_job, run_analysis
from backend.config import settings
from backend.database import initialise_database, transaction, utcnow
from backend.repository import log_event


def reconcile_interrupted_jobs() -> int:
    """Do not silently continue a possibly interrupted analysis with partial evidence."""
    with transaction() as connection:
        rows = connection.execute("SELECT id FROM jobs WHERE status = 'running'").fetchall()
        for row in rows:
            connection.execute(
                """UPDATE jobs SET status = 'failed', error_code = 'WORKER_INTERRUPTED',
                   error_detail = 'Worker stopped before a terminal state; retry as a new job.', finished_at = ?, updated_at = ? WHERE id = ?""",
                (utcnow(), utcnow(), row["id"]),
            )
    for row in rows:
        log_event(row["id"], "error", "Worker restart marked an interrupted run failed; partial data was not promoted.")
    return len(rows)


def serve(once: bool = False) -> None:
    initialise_database()
    recovered = reconcile_interrupted_jobs()
    if recovered:
        print(f"Recovered {recovered} interrupted job(s) as failed.")
    print("SHADOWPATH worker started; APK code is never executed.")
    while True:
        job_id = next_queued_job()
        if job_id:
            print(f"Processing {job_id}")
            run_analysis(job_id)
            if once:
                return
            continue
        if once:
            return
        time.sleep(settings.analysis_poll_seconds)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SHADOWPATH static-analysis worker")
    parser.add_argument("--once", action="store_true", help="Process at most one queued job then exit")
    args = parser.parse_args()
    serve(once=args.once)
