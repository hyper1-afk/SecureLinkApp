"""
Flask blueprint: /admin/agents page + /admin/api/agents/* API.
Follows the same auth pattern as the rest of the admin panel
(Bearer token via admin_manager, validated on every API call).
"""
import json
import logging
import subprocess
import sys
from functools import wraps
from datetime import datetime
from pathlib import Path

from flask import Blueprint, render_template, jsonify, request

logger = logging.getLogger(__name__)

agent_bp = Blueprint("agents", __name__)

PENDING_DIR = Path(__file__).parent / "agents" / "workspace" / "pending_changes"

# ── Lazy-init (set by init_agent_routes called from app.py) ──────────────────
_admin_manager = None


def init_agent_routes(admin_manager):
    global _admin_manager
    _admin_manager = admin_manager


def _get_token():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return None


def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = _get_token()
        if not token:
            return jsonify({"error": "Authentication required"}), 401
        if _admin_manager is None:
            return jsonify({"error": "Admin manager not initialized"}), 500
        result = _admin_manager.validate_employee_token(token)
        if not result:
            return jsonify({"error": "Invalid or expired token"}), 401
        request.current_employee = result["employee"]
        return f(*args, **kwargs)
    return decorated


def _scheduler():
    from agents.agent_scheduler import get_agent_scheduler
    return get_agent_scheduler()


# ── Page route (no auth decorator — same as all other admin pages) ────────────

@agent_bp.route("/admin/agents")
def agents_dashboard():
    return render_template("admin/agents.html")


# ── Status / logs ─────────────────────────────────────────────────────────────

@agent_bp.route("/admin/api/agents/status")
@require_admin
def agents_status():
    status = _scheduler().get_status()

    pending = []
    if PENDING_DIR.exists():
        for f in sorted(PENDING_DIR.glob("*.json"), reverse=True)[:10]:
            try:
                d = json.loads(f.read_text())
                pending.append({
                    "token":       d.get("token", "")[:16] + "…",
                    "full_token":  d.get("token", ""),
                    "status":      d.get("status", "?"),
                    "title":       d.get("recommendation", {}).get("title", "?"),
                    "branch":      d.get("branch", ""),
                    "test_passed": d.get("test_passed"),
                    "created_at":  d.get("created_at", ""),
                })
            except Exception:
                pass

    status["pending_changes"] = pending
    status["server_time"] = datetime.utcnow().isoformat()
    return jsonify(status)


@agent_bp.route("/admin/api/agents/logs")
@require_admin
def agents_logs():
    since = request.args.get("since")
    limit = min(int(request.args.get("limit", 200)), 500)
    logs = _scheduler().get_logs(limit=limit, since=since)
    return jsonify({"logs": logs, "count": len(logs)})


# ── Agent controls ────────────────────────────────────────────────────────────

@agent_bp.route("/admin/api/agents/<name>/kill", methods=["POST"])
@require_admin
def kill_agent(name):
    ok = _scheduler().kill(name)
    if not ok:
        return jsonify({"error": "Agent not found"}), 404
    logger.warning(f"Admin {request.current_employee.get('username')} force-killed: {name}")
    return jsonify({"success": True, "message": f"Agent '{name}' terminated"})


@agent_bp.route("/admin/api/agents/<name>/trigger", methods=["POST"])
@require_admin
def trigger_agent(name):
    ok = _scheduler().trigger(name)
    if not ok:
        return jsonify({"error": "Agent not found or already running"}), 400
    logger.info(f"Admin {request.current_employee.get('username')} triggered: {name}")
    return jsonify({"success": True, "message": f"Agent '{name}' started"})


@agent_bp.route("/admin/api/agents/<name>/enable", methods=["POST"])
@require_admin
def enable_agent(name):
    _scheduler().enable(name)
    return jsonify({"success": True})


@agent_bp.route("/admin/api/agents/<name>/disable", methods=["POST"])
@require_admin
def disable_agent(name):
    _scheduler().disable(name)
    return jsonify({"success": True})


# ── Daemon controls ───────────────────────────────────────────────────────────

@agent_bp.route("/admin/api/agents/daemon/stop", methods=["POST"])
@require_admin
def daemon_stop():
    _scheduler().stop()
    logger.warning(f"Admin {request.current_employee.get('username')} stopped agent scheduler")
    return jsonify({"success": True, "message": "Scheduler stopped"})


@agent_bp.route("/admin/api/agents/daemon/start", methods=["POST"])
@require_admin
def daemon_start():
    _scheduler().start()
    return jsonify({"success": True, "message": "Scheduler started"})


# ── Pipeline approval ─────────────────────────────────────────────────────────

@agent_bp.route("/admin/api/agents/pipeline/<token>/approve", methods=["POST"])
@require_admin
def approve_change(token):
    deploy_script = Path(__file__).parent / "agents" / "deploy_agent.py"
    result = subprocess.run(
        [sys.executable, str(deploy_script), "approve", token],
        capture_output=True, text=True
    )
    ok = result.returncode == 0
    logger.info(f"Admin {request.current_employee.get('username')} approved pipeline token {token[:16]}")
    return jsonify({"success": ok, "message": result.stdout or result.stderr})


@agent_bp.route("/admin/api/agents/pipeline/<token>/deny", methods=["POST"])
@require_admin
def deny_change(token):
    deploy_script = Path(__file__).parent / "agents" / "deploy_agent.py"
    result = subprocess.run(
        [sys.executable, str(deploy_script), "deny", token],
        capture_output=True, text=True
    )
    ok = result.returncode == 0
    return jsonify({"success": ok, "message": result.stdout or result.stderr})


# ── Memory ────────────────────────────────────────────────────────────────────

@agent_bp.route("/admin/api/agents/memory")
@require_admin
def agents_memory():
    from agents.agent_memory import all_summaries
    return jsonify({"summaries": all_summaries()})


@agent_bp.route("/admin/api/agents/<name>/memory")
@require_admin
def agent_memory_detail(name):
    from agents.agent_memory import _load
    return jsonify({"agent": name, "learnings": _load(name)[-50:]})


@agent_bp.route("/admin/api/agents/<name>/teach", methods=["POST"])
@require_admin
def teach_agent(name):
    from agents.agent_memory import record
    data = request.get_json() or {}
    lesson = data.get("lesson", "").strip()
    if not lesson:
        return jsonify({"error": "lesson is required"}), 400
    record(name, lesson=lesson,
           lesson_type=data.get("type", "correction"),
           trigger=data.get("trigger", "Manual admin correction"),
           confidence=float(data.get("confidence", 0.9)))
    logger.info(f"Admin taught {name}: {lesson[:80]}")
    return jsonify({"success": True})


@agent_bp.route("/admin/api/agents/<name>/dismiss", methods=["POST"])
@require_admin
def dismiss_finding(name):
    from agents.agent_memory import dismiss
    data = request.get_json() or {}
    pattern = data.get("pattern", "").strip()
    if not pattern:
        return jsonify({"error": "pattern is required"}), 400
    dismiss(name, pattern)
    return jsonify({"success": True})
