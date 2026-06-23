"""
Standalone 24/7 agent scheduler — runs independently of Flask.

Usage:
  python agents/run_scheduler.py            # start scheduler (foreground)
  python agents/run_scheduler.py status     # show what's scheduled
  python agents/run_scheduler.py run <name> # trigger one agent immediately

To run in the background on Windows (survives terminal close):
  pythonw agents/run_scheduler.py

Logs: agents/workspace/scheduler.log
"""
import sys
import os
import signal
import logging
import time
from pathlib import Path
from datetime import datetime

# Ensure project root is on path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(Path(__file__).parent))

LOG_FILE = Path(__file__).parent / "workspace" / "scheduler.log"
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

# Log to both file and stdout
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(str(LOG_FILE), encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger(__name__)


def cmd_status():
    from agents.agent_scheduler import get_agent_scheduler, AGENT_DEFS
    sched = get_agent_scheduler()
    status = sched.get_status()
    print(f"\nScheduler running: {status['daemon_running']}")
    print(f"Uptime:            {status['uptime_s']:.0f}s")
    print(f"Tasks completed:   {status['task_count']}\n")
    for name, a in status["agents"].items():
        enabled = "ON " if a["enabled"] else "OFF"
        interval = AGENT_DEFS[name]["interval_minutes"]
        print(f"  [{enabled}] {a['display_name']:<22} every {interval}m  "
              f"status={a['status']:<8} runs={a['run_count']}  "
              f"last={a.get('last_run','never')[:19] if a.get('last_run') else 'never'}")
    print()


def cmd_run(name: str):
    from agents.agent_scheduler import get_agent_scheduler, AGENT_DEFS
    if name not in AGENT_DEFS:
        print(f"Unknown agent: {name}")
        print(f"Available: {', '.join(AGENT_DEFS.keys())}")
        sys.exit(1)
    sched = get_agent_scheduler()
    sched.start()
    print(f"Triggering {name}...")
    sched.trigger(name)
    # Wait for it to finish
    import time
    while True:
        s = sched.get_status()
        if s["agents"][name]["status"] != "running":
            break
        time.sleep(2)
    print(f"Done. Result: {sched.get_status()['agents'][name].get('last_result')}")


def main():
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == "status":
            cmd_status()
            return
        if cmd == "run" and len(sys.argv) > 2:
            cmd_run(sys.argv[2])
            return
        print(__doc__)
        sys.exit(1)

    # ── Start the scheduler daemon ──────────────────────────────────────────
    logger.info("=" * 60)
    logger.info("SecureLink Agent Scheduler starting")
    logger.info(f"Project root: {PROJECT_ROOT}")
    logger.info(f"Log file:     {LOG_FILE}")
    logger.info("=" * 60)

    # Verify Ollama is reachable before committing to run
    from agents.hermes_client import is_available
    if not is_available():
        logger.error("Ollama is not running or hermes3 is not pulled.")
        logger.error("  Start Ollama:  ollama serve")
        logger.error("  Pull model:    ollama pull hermes3")
        logger.error("Scheduler will start anyway and retry when agents fire.")

    from agents.agent_scheduler import get_agent_scheduler, PID_FILE
    sched = get_agent_scheduler()
    sched.start()

    # Write PID file so Flask admin dashboard can detect us
    try:
        PID_FILE.parent.mkdir(parents=True, exist_ok=True)
        PID_FILE.write_text(str(os.getpid()))
        logger.info(f"PID file written: {PID_FILE} (pid={os.getpid()})")
    except Exception as e:
        logger.warning(f"Could not write PID file: {e}")

    logger.info("Scheduler started. Press Ctrl+C to stop.")
    logger.info("Agents and their schedules:")
    from agents.agent_scheduler import AGENT_DEFS
    for name, cfg in AGENT_DEFS.items():
        state = sched.get_status()["agents"][name]
        enabled = "enabled" if state["enabled"] else "DISABLED"
        logger.info(f"  {cfg['display_name']:<22} every {cfg['interval_minutes']}m  [{enabled}]")

    # Graceful shutdown on Ctrl+C or SIGTERM
    def _shutdown(sig, frame):
        logger.info("Shutdown signal received — stopping scheduler...")
        sched.stop()
        try:
            PID_FILE.unlink(missing_ok=True)
        except Exception:
            pass
        logger.info("Scheduler stopped.")
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # Keep the process alive — the scheduler runs in daemon threads
    while True:
        time.sleep(60)
        # Heartbeat log every hour
        uptime = sched.get_status()["uptime_s"]
        if uptime % 3600 < 60:
            logger.info(f"Heartbeat — uptime {uptime/3600:.1f}h, "
                        f"tasks completed: {sched.get_status()['task_count']}")


if __name__ == "__main__":
    main()
