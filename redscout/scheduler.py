"""
Scheduler - cron-like scheduling for recurring scans (authorized targets only).
"""
import time
import datetime
import yaml
from pathlib import Path
from apscheduler.schedulers.background import BackgroundScheduler


class ScanScheduler:
    def __init__(self, jobs_file: str = "schedules.yaml"):
        self.jobs_file = Path(jobs_file)
        self.scheduler = BackgroundScheduler()

    def _run_job(self, job: dict):
        from .main import run_scan
        print(f"[{datetime.datetime.now()}] Running scheduled scan: {job['name']}")
        run_scan(
            scope=job["scope"],
            target=job["target"],
            workflow=job.get("workflow"),
            report=job.get("report", "report.pdf"),
        )

    def load_jobs(self):
        if not self.jobs_file.exists():
            return []
        return yaml.safe_load(self.jobs_file.read_text()).get("jobs", [])

    def start(self):
        for job in self.load_jobs():
            cron = job.get("cron", "0 2 * * *")
            minute, hour, day, month, dow = cron.split()
            self.scheduler.add_job(
                self._run_job,
                "cron",
                args=[job],
                minute=minute, hour=hour, day=day, month=month, day_of_week=dow,
                id=job["name"],
                replace_existing=True,
            )
        self.scheduler.start()
        print("Scheduler started. Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(60)
        except KeyboardInterrupt:
            self.scheduler.shutdown()