"""
Scheduler
=========
Manages periodic background jobs for the monitoring engine.

Jobs:
    - ``network_scan``   : ARP-based network discovery every 30 seconds
    - ``log_cleanup``    : purge old network_logs every hour
    - ``stats_refresh``  : recompute statistics cache every minute
    - ``report_generation`` : daily compliance / summary report
    - ``health_check``   : periodic health verification every 5 minutes

Uses APScheduler as a background scheduler without blocking the API server.

If APScheduler is not installed, the scheduler falls back to a simple
daemon-thread loop as a graceful degradation.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from utils.logger import get_logger

logger = get_logger()

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.interval import IntervalTrigger
    APSCHEDULER_AVAILABLE = True
except ImportError:  # pragma: no cover
    APSCHEDULER_AVAILABLE = False


class Scheduler:
    """Periodic job scheduler for ShadowPulse.

    Usage::

        sch = Scheduler()
        sch.add_job("my_job", my_callback, interval_seconds=30)
        sch.start()
        # ...
        sch.stop()
    """

    def __init__(self):
        self._apscheduler: Optional[BackgroundScheduler] = None
        self._fallback_jobs: List[Dict[str, Any]] = []  # job_id -> callback+interval
        self._fallback_threads: List[threading.Thread] = []
        self._fallback_stop = threading.Event()
        self._use_apscheduler = APSCHEDULER_AVAILABLE
        self._started = False

        if self._use_apscheduler:
            self._apscheduler = BackgroundScheduler(daemon=True)
            logger.info("Scheduler: using APScheduler")
        else:
            logger.info("Scheduler: APScheduler not available; using fallback thread loop")

    # ------------------------------------------------------------------
    # Job registration
    # ------------------------------------------------------------------
    def remove_job(self, job_id: str) -> None:
        """Remove a previously registered job (restart-safe)."""
        if self._use_apscheduler and self._apscheduler is not None:
            try:
                self._apscheduler.remove_job(job_id)
            except Exception:
                pass
        else:
            self._fallback_jobs = [
                j for j in self._fallback_jobs if j["job_id"] != job_id
            ]
            # Also drop any live thread for this job.
            self._fallback_threads = [
                t for t in self._fallback_threads
                if t.name != f"job-{job_id}" or not t.is_alive()
            ]
            if hasattr(self, f"_thr_{job_id}"):
                delattr(self, f"_thr_{job_id}")

    def add_job(
        self,
        job_id: str,
        callback: Callable,
        interval_seconds: int = 60,
        args: Optional[List[Any]] = None,
        kwargs: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Register a periodic job.

        ``callback`` will be called every ``interval_seconds`` seconds.
        Exceptions raised by the callback are logged but never propagated.
        """
        safe_cb = self._safe_wrapper(job_id, callback, args or [], kwargs or {})

        if self._use_apscheduler and self._apscheduler is not None:
            self._apscheduler.add_job(
                safe_cb,
                trigger=IntervalTrigger(seconds=interval_seconds),
                id=job_id,
                name=job_id,
                replace_existing=True,
            )
            logger.info(
                f"Scheduler: registered job '{job_id}' every {interval_seconds}s (APScheduler)"
            )
        else:
            # Remove any prior registration with the same job_id (restart-safe).
            self.remove_job(job_id)
            # Persist the job spec so threads can be (re)created on start().
            self._fallback_jobs.append({
                "job_id": job_id,
                "callback": safe_cb,
                "interval": interval_seconds,
            })
            logger.info(
                f"Scheduler: registered job '{job_id}' every {interval_seconds}s (fallback)"
            )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def start(self) -> None:
        """Start all registered jobs."""
        if self._started:
            return
        self._started = True

        if self._use_apscheduler and self._apscheduler is not None:
            self._apscheduler.start()
            logger.info("Scheduler: APScheduler started")
        else:
            self._fallback_stop.clear()
            # Recreate any threads that were previously stopped so restart works.
            alive_threads = [t for t in self._fallback_threads if t.is_alive()]
            self._fallback_threads = alive_threads
            # If all threads were joined on stop(), rebuild them from stored jobs.
            if len(self._fallback_threads) < len(self._fallback_jobs):
                self._rebuild_fallback_threads()
            logger.info("Scheduler: fallback threads started")

    def stop(self) -> None:
        """Stop all jobs gracefully."""
        if not self._started:
            return
        self._started = False

        if self._use_apscheduler and self._apscheduler is not None:
            self._apscheduler.shutdown(wait=False)
            logger.info("Scheduler: APScheduler stopped")
        else:
            self._fallback_stop.set()
            for t in self._fallback_threads:
                if t.is_alive():
                    t.join(timeout=2)
            logger.info("Scheduler: fallback threads stopped")

    @property
    def is_running(self) -> bool:
        if self._use_apscheduler and self._apscheduler is not None:
            return self._apscheduler.running
        return self._started

    def job_count(self) -> int:
        if self._use_apscheduler and self._apscheduler is not None:
            return len(self._apscheduler.get_jobs())
        return len(self._fallback_threads)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    @staticmethod
    def _safe_wrapper(job_id: str, cb: Callable, args: list, kwargs: dict) -> Callable:
        """Wrap callback so exceptions never propagate into the scheduler."""

        def wrapper() -> None:
            try:
                cb(*args, **kwargs)
            except Exception as exc:
                logger.error(f"Scheduler: job '{job_id}' failed: {exc}")

        return wrapper

    def _fallback_loop(self, job_id: str, cb: Callable, interval: int) -> None:
        """Simple while-loop fallback when APScheduler is absent."""
        while not self._fallback_stop.is_set():
            cb()
            self._fallback_stop.wait(timeout=interval)

    def _job_specs_count(self) -> int:
        """Number of registered fallback job specs (threads we intend to run)."""
        return len(self._fallback_jobs)

    def _rebuild_fallback_threads(self) -> None:
        """Recreate fallback threads after a stop() joined them."""
        existing_names = {t.name for t in self._fallback_threads if t.is_alive()}
        rebuilt = []
        for job in self._fallback_jobs:
            thread_name = f"job-{job['job_id']}"
            if thread_name in existing_names:
                continue
            thread = threading.Thread(
                target=self._fallback_loop,
                args=(job["job_id"], job["callback"], job["interval"]),
                daemon=True,
                name=thread_name,
            )
            setattr(self, f"_thr_{job['job_id']}", thread)
            self._fallback_threads.append(thread)
            thread.start()
            rebuilt.append(job["job_id"])
        if rebuilt:
            logger.info(f"Scheduler: rebuilt fallback threads for {rebuilt}")

    def status_dict(self) -> dict:
        """Snapshot for /api/status."""
        return {
            "engine": "apscheduler" if self._use_apscheduler else "fallback_thread",
            "running": self.is_running,
            "job_count": self.job_count(),
            "jobs": self._list_jobs(),
        }

    def _list_jobs(self) -> list:
        if self._use_apscheduler and self._apscheduler is not None:
            return [
                {"id": j.id, "next_run": str(j.next_run_time) if j.next_run_time else None}
                for j in self._apscheduler.get_jobs()
            ]
        return [{"id": t.name.replace("job-", ""), "next_run": None} for t in self._fallback_threads]
