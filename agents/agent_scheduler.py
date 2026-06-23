"""
Agent Scheduler: runs all Hermes pipeline agents on a 24/7 schedule.
Manages state, activity logs, and per-agent enable/disable controls.
Designed to run as daemon threads inside the Flask process.
"""
import sys
import threading
import subprocess
import json
import logging
import schedule as schedule_lib
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).parent.parent
WORKSPACE = Path(__file__).parent / "workspace"
STATE_FILE = WORKSPACE / "agent_state.json"
MAX_LOG = 1000  # Max activity log entries kept in memory
AGENT_TIMEOUT_S = 600  # Kill any agent that runs longer than 10 minutes

LOG_FILE  = WORKSPACE / "activity_log.jsonl"   # Persisted log — shared with Flask
PID_FILE  = WORKSPACE / "scheduler.pid"         # Written by standalone run_scheduler.py

AGENT_DEFS = {
    "ticket_handler": {
        "display_name": "Ticket Handler",
        "description": "Monitors support inbox and DB; uses Hermes to categorize tickets and draft replies.",
        "script": "ticket_handler.py",
        "interval_minutes": 30,
        "icon": "bi-envelope-fill",
        "color": "#0ea5e9",
        "enabled_default": True,
    },
    "business_analyst": {
        "display_name": "Business Analyst",
        "description": "Scans the codebase, git history, and error logs to find improvement opportunities.",
        "script": "business_analyst.py",
        "interval_minutes": 1440,  # 24h
        "icon": "bi-graph-up-arrow",
        "color": "#8b5cf6",
        "enabled_default": True,
    },
    "bug_scanner": {
        "display_name": "Bug Scanner",
        "description": "Scans core source files for bugs and security vulnerabilities.",
        "script": "bug_fixer.py",
        "interval_minutes": 360,  # 6h
        "icon": "bi-bug-fill",
        "color": "#ef4444",
        "enabled_default": True,
    },
    "code_reviewer": {
        "display_name": "Code Reviewer",
        "description": "Reviews the latest git diff for quality, security, and regressions.",
        "script": "code_reviewer.py",
        "interval_minutes": 120,  # 2h
        "icon": "bi-search",
        "color": "#10b981",
        "enabled_default": True,
    },
    "pipeline": {
        "display_name": "Improvement Pipeline",
        "description": "Full autonomous cycle: analyst → implement → tests → business manager → approval email.",
        "script": None,  # orchestrated by run_agent.py pipeline command
        "interval_minutes": 2880,  # 48h
        "icon": "bi-rocket-fill",
        "color": "#f59e0b",
        "enabled_default": False,  # Disabled by default — consequential changes
    },
}


class AgentScheduler:
    """Singleton scheduler that manages all Hermes agents."""

    def __init__(self):
        self._lock = threading.Lock()
        self._scheduler = schedule_lib.Scheduler()
        self._scheduler_thread: Optional[threading.Thread] = None
        self._scheduler_running = False
        self._running_agents: dict[str, threading.Thread] = {}
        self._procs: dict[str, subprocess.Popen] = {}   # live subprocess refs for kill
        self._activity: list[dict] = []
        self._started_at: Optional[datetime] = None
        self._task_count = 0

        # Per-agent state
        self._state: dict[str, dict] = {}
        for name, cfg in AGENT_DEFS.items():
            self._state[name] = {
                "enabled": cfg["enabled_default"],
                "status": "idle",         # idle | running | error | paused
                "last_run": None,
                "last_run_duration_s": None,
                "last_result": None,      # "success" | "error" | "skipped"
                "last_error": None,
                "next_run": None,
                "run_count": 0,
                "runs_today": 0,
                "today_date": datetime.utcnow().date().isoformat(),
            }

        self._load_persisted_state()

    # ─── Lifecycle ────────────────────────────────────────────────────────

    def start(self):
        if self._scheduler_running:
            return
        WORKSPACE.mkdir(parents=True, exist_ok=True)
        self._scheduler_running = True
        self._started_at = datetime.utcnow()
        self._register_all_jobs()
        self._scheduler_thread = threading.Thread(
            target=self._scheduler_loop, daemon=True, name="agent-scheduler"
        )
        self._scheduler_thread.start()
        self._log("scheduler", "Agent scheduler started (24/7 mode)", level="info")
        logger.info("Agent scheduler started")

    def stop(self):
        self._scheduler_running = False
        self._scheduler.clear()
        self._log("scheduler", "Agent scheduler stopped", level="warning")

    # ─── Control ─────────────────────────────────────────────────────────

    def trigger(self, name: str) -> bool:
        """Run an agent immediately in a background thread."""
        if name not in AGENT_DEFS:
            return False
        with self._lock:
            if self._state[name]["status"] == "running":
                self._log(name, "Already running — trigger ignored")
                return False
        thread = threading.Thread(
            target=self._run_agent, args=(name,), daemon=True, name=f"agent-{name}"
        )
        thread.start()
        with self._lock:
            self._running_agents[name] = thread
        return True

    def enable(self, name: str):
        if name not in self._state:
            return
        with self._lock:
            self._state[name]["enabled"] = True
        self._reschedule(name)
        self._log(name, "Enabled — will run on schedule", level="info")
        self._persist_state()

    def disable(self, name: str):
        if name not in self._state:
            return
        with self._lock:
            self._state[name]["enabled"] = False
        tag = f"agent-{name}"
        self._scheduler.clear(tag)
        self._log(name, "Disabled — removed from schedule", level="warning")
        self._persist_state()

    def kill(self, name: str) -> bool:
        """Forcefully terminate a running agent subprocess and reset its state."""
        if name not in AGENT_DEFS:
            return False
        proc = self._procs.get(name)
        if proc:
            try:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
            except Exception:
                pass
            with self._lock:
                self._procs.pop(name, None)
        with self._lock:
            if name in self._state:
                self._state[name]["status"] = "idle"
                self._state[name]["last_result"] = "error"
                self._state[name]["last_error"] = "Terminated by admin"
        self._log(name, "Agent forcefully terminated by admin", level="warning")
        self._persist_state()
        return True

    # ─── Status / Logs ────────────────────────────────────────────────────

    def get_status(self) -> dict:
        # If this process owns the scheduler, use in-memory running flag.
        # Otherwise check whether the standalone scheduler PID is alive.
        daemon_running = self._scheduler_running
        if not daemon_running:
            daemon_running = self._is_external_scheduler_running()

        with self._lock:
            agents = {}
            for name, cfg in AGENT_DEFS.items():
                s = dict(self._state[name])
                s.update({
                    "name": name,
                    "display_name": cfg["display_name"],
                    "description": cfg["description"],
                    "icon": cfg["icon"],
                    "color": cfg["color"],
                    "interval_minutes": cfg["interval_minutes"],
                })
                agents[name] = s

            return {
                "daemon_running": daemon_running,
                "started_at": self._started_at.isoformat() if self._started_at else None,
                "uptime_s": (datetime.utcnow() - self._started_at).total_seconds()
                            if self._started_at else 0,
                "task_count": self._task_count,
                "agents": agents,
            }

    def get_logs(self, limit: int = 200, since: Optional[str] = None) -> list[dict]:
        # Prefer in-memory log (this process ran agents); fall back to persisted file.
        with self._lock:
            logs = list(self._activity)

        if not logs and LOG_FILE.exists():
            try:
                lines = LOG_FILE.read_text(encoding="utf-8").splitlines()
                logs = [json.loads(l) for l in lines if l.strip()]
            except Exception:
                pass

        if since:
            try:
                cutoff = datetime.fromisoformat(since)
                logs = [l for l in logs if datetime.fromisoformat(l["ts"]) > cutoff]
            except ValueError:
                pass

        return logs[-limit:]

    @staticmethod
    def _is_external_scheduler_running() -> bool:
        """Check if a standalone run_scheduler.py process is alive via PID file."""
        try:
            if not PID_FILE.exists():
                return False
            pid = int(PID_FILE.read_text().strip())
            import psutil
            return psutil.pid_exists(pid)
        except Exception:
            return False

    # ─── Internals ────────────────────────────────────────────────────────

    def _register_all_jobs(self):
        self._scheduler.clear()
        for name, cfg in AGENT_DEFS.items():
            if self._state[name]["enabled"]:
                self._schedule_job(name, cfg["interval_minutes"])

    def _reschedule(self, name: str):
        tag = f"agent-{name}"
        self._scheduler.clear(tag)
        if self._state[name]["enabled"]:
            self._schedule_job(name, AGENT_DEFS[name]["interval_minutes"])

    def _schedule_job(self, name: str, interval_minutes: int):
        tag = f"agent-{name}"
        job = self._scheduler.every(interval_minutes).minutes.do(
            self._run_agent_from_scheduler, name
        ).tag(tag)
        next_run = datetime.utcnow() + timedelta(minutes=interval_minutes)
        with self._lock:
            self._state[name]["next_run"] = next_run.isoformat()
        logger.info(f"Scheduled {name} every {interval_minutes}m (next: {next_run.strftime('%H:%M')})")

    def _run_agent_from_scheduler(self, name: str):
        """Called by the schedule loop — runs agent in a thread."""
        with self._lock:
            if not self._state[name]["enabled"]:
                return
            if self._state[name]["status"] == "running":
                self._log(name, "Skipped — previous run still in progress")
                return

        self._run_agent(name)

        # Update next_run time
        interval = AGENT_DEFS[name]["interval_minutes"]
        next_run = datetime.utcnow() + timedelta(minutes=interval)
        with self._lock:
            self._state[name]["next_run"] = next_run.isoformat()

    def _run_agent(self, name: str):
        cfg = AGENT_DEFS[name]
        started = datetime.utcnow()

        with self._lock:
            self._state[name]["status"] = "running"
            self._state[name]["last_run"] = started.isoformat()
            # Reset daily counter if date changed
            today = started.date().isoformat()
            if self._state[name]["today_date"] != today:
                self._state[name]["runs_today"] = 0
                self._state[name]["today_date"] = today
            self._task_count += 1

        self._log(name, f"Starting {cfg['display_name']}...", level="info")

        try:
            if name == "pipeline":
                cmd = [sys.executable, str(Path(__file__).parent / "run_agent.py"), "pipeline"]
            else:
                # Pass default bug targets for bug_scanner
                cmd = [sys.executable, str(Path(__file__).parent / "run_agent.py"), self._cmd_for(name)]
                if name == "bug_scanner":
                    core_files = [
                        "app.py", "link_verifier.py", "domain_scanner.py",
                        "database.py", "auth.py",
                    ]
                    cmd += [f for f in core_files if (PROJECT_ROOT / f).exists()]

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,  # never block on stdin
                text=True,
                cwd=str(PROJECT_ROOT),
            )

            with self._lock:
                self._procs[name] = proc

            # Watchdog: kill the process if it exceeds the timeout
            def _watchdog():
                if proc.poll() is None:
                    self._log(name, f"Timeout ({AGENT_TIMEOUT_S//60}m) exceeded — killing agent", level="warning")
                    proc.kill()

            watchdog = threading.Timer(AGENT_TIMEOUT_S, _watchdog)
            watchdog.start()

            try:
                for line in proc.stdout:
                    line = line.rstrip()
                    if line:
                        self._log(name, line)
                proc.wait()
            finally:
                watchdog.cancel()
                with self._lock:
                    self._procs.pop(name, None)

            rc = proc.returncode
            duration = (datetime.utcnow() - started).total_seconds()

            with self._lock:
                # Don't overwrite "idle" if kill() already reset the state
                if self._state[name]["status"] == "running":
                    self._state[name]["status"] = "idle"
                    self._state[name]["last_result"] = "success" if rc == 0 else "error"
                    self._state[name]["last_run_duration_s"] = round(duration, 1)
                    self._state[name]["run_count"] += 1
                    self._state[name]["runs_today"] += 1
                    if rc != 0:
                        self._state[name]["last_error"] = f"Exit code {rc}"

            level = "info" if rc == 0 else "error"
            self._log(name, f"Completed in {duration:.0f}s (exit {rc})", level=level)

        except Exception as e:
            duration = (datetime.utcnow() - started).total_seconds()
            with self._lock:
                self._state[name]["status"] = "error"
                self._state[name]["last_result"] = "error"
                self._state[name]["last_error"] = str(e)
                self._state[name]["last_run_duration_s"] = round(duration, 1)
                self._procs.pop(name, None)
            self._log(name, f"Error: {e}", level="error")
            logger.exception(f"Agent {name} raised exception")

        self._persist_state()

    def _cmd_for(self, name: str) -> str:
        MAP = {
            "ticket_handler": "tickets",
            "business_analyst": "analyze",
            "bug_scanner": "fix-bugs",
            "code_reviewer": "review",
        }
        return MAP.get(name, name)

    def _scheduler_loop(self):
        while self._scheduler_running:
            self._scheduler.run_pending()
            time.sleep(10)

    def _log(self, agent: str, message: str, level: str = "info"):
        entry = {
            "ts": datetime.utcnow().isoformat(),
            "agent": agent,
            "message": message,
            "level": level,
        }
        with self._lock:
            self._activity.append(entry)
            if len(self._activity) > MAX_LOG:
                self._activity = self._activity[-MAX_LOG:]
        # Persist to file so Flask process can read it
        try:
            WORKSPACE.mkdir(parents=True, exist_ok=True)
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
            # Trim file to last MAX_LOG lines
            self._trim_log_file()
        except Exception:
            pass

    def _trim_log_file(self):
        try:
            if not LOG_FILE.exists():
                return
            lines = LOG_FILE.read_text(encoding="utf-8").splitlines(keepends=True)
            if len(lines) > MAX_LOG:
                LOG_FILE.write_text("".join(lines[-MAX_LOG:]), encoding="utf-8")
        except Exception:
            pass

    def _persist_state(self):
        try:
            WORKSPACE.mkdir(parents=True, exist_ok=True)
            with self._lock:
                data = {k: dict(v) for k, v in self._state.items()}
            STATE_FILE.write_text(json.dumps(data, indent=2))
        except Exception:
            pass

    def _load_persisted_state(self):
        try:
            if STATE_FILE.exists():
                saved = json.loads(STATE_FILE.read_text())
                for name, s in saved.items():
                    if name in self._state:
                        self._state[name]["enabled"]             = s.get("enabled", self._state[name]["enabled"])
                        self._state[name]["run_count"]           = s.get("run_count", 0)
                        self._state[name]["runs_today"]          = s.get("runs_today", 0)
                        self._state[name]["today_date"]          = s.get("today_date", self._state[name]["today_date"])
                        self._state[name]["last_run"]            = s.get("last_run")
                        self._state[name]["last_result"]         = s.get("last_result")
                        self._state[name]["last_run_duration_s"] = s.get("last_run_duration_s")
                        self._state[name]["last_error"]          = s.get("last_error")
                        self._state[name]["next_run"]            = s.get("next_run")
                        self._state[name]["status"]              = "idle"  # always reset on load
        except Exception:
            pass


# Module-level singleton — imported by agent_routes.py and app.py
_scheduler: Optional[AgentScheduler] = None


def get_agent_scheduler() -> AgentScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = AgentScheduler()
    return _scheduler
