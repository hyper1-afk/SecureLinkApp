"""
Agent memory: lets each Hermes agent learn from its own mistakes and successes.

After every run an agent "reflects" — Hermes reads its own output and the outcome
and writes a concise lesson. Before the next run those lessons are injected into the
system prompt so the same mistake won't happen twice.

Memory is stored in agents/workspace/memory/<agent_name>.json
Each file holds up to MAX_LEARNINGS entries (oldest are pruned first).
"""
import sys
import os
import json
import threading
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from hermes_client import chat, is_available

MEMORY_DIR = Path(__file__).parent / "workspace" / "memory"
MAX_LEARNINGS = 80   # cap per agent — keeps context size sane
RECALL_LIMIT  = 10   # max lessons injected per run

REFLECT_PROMPT = """\
You just completed an automated task. Review your output and the outcome, then extract \
a concise, actionable lesson for your future self.

Output ONLY valid JSON — no markdown fences:
{
  "type": "mistake|success|correction|warning",
  "lesson": "<one or two sentences: what to do or avoid next time, starting with a verb>",
  "trigger": "<brief description of the situation that prompted this lesson>",
  "confidence": <0.0-1.0>
}

Rules:
- type=mistake    → something went wrong; lesson describes how to prevent it
- type=success    → something worked well; lesson says to repeat it
- type=correction → output was wrong but fixable; lesson says how to correct it
- type=warning    → potential issue noticed; lesson says what to watch for
- confidence < 0.5 → uncertain; these are recalled less often
- Lessons must be specific and actionable, not generic advice
- If the run was entirely routine with no notable lesson, output: {"skip": true}"""


_lock = threading.Lock()


# ─── Public API ──────────────────────────────────────────────────────────────


def recall(agent_name: str) -> str:
    """
    Return a block of remembered lessons to inject into a system prompt.
    Returns empty string if no memory exists yet.
    """
    learnings = _load(agent_name)
    if not learnings:
        return ""

    # Sort by confidence desc, recency desc; take top RECALL_LIMIT
    sorted_l = sorted(
        learnings,
        key=lambda l: (l.get("confidence", 0.5), l.get("ts", "")),
        reverse=True,
    )
    top = sorted_l[:RECALL_LIMIT]

    lines = ["--- Lessons from past runs (apply these) ---"]
    for l in top:
        icon = {"mistake": "AVOID", "success": "DO", "correction": "FIX", "warning": "WATCH"}.get(l.get("type", ""), "NOTE")
        lines.append(f"[{icon}] {l.get('lesson', '')}")
    lines.append("--- End of lessons ---")
    return "\n".join(lines)


def reflect(agent_name: str, run_output: str, outcome: str = "unknown"):
    """
    Call Hermes to extract a lesson from a completed run, then store it.
    outcome: "success" | "error" | "skipped"
    This is intentionally non-blocking — runs in a background thread.
    """
    if not is_available():
        return  # Silently skip if Ollama is down

    thread = threading.Thread(
        target=_reflect_worker,
        args=(agent_name, run_output, outcome),
        daemon=True,
        name=f"reflect-{agent_name}",
    )
    thread.start()


def record(agent_name: str, lesson: str, lesson_type: str = "correction",
           trigger: str = "", confidence: float = 0.8):
    """
    Manually record a lesson (e.g. when an admin corrects a ticket draft).
    """
    entry = {
        "ts": datetime.utcnow().isoformat(),
        "type": lesson_type,
        "lesson": lesson,
        "trigger": trigger,
        "confidence": confidence,
        "source": "manual",
    }
    _append(agent_name, entry)


def dismiss(agent_name: str, pattern: str):
    """
    Record that a certain finding/pattern is a false positive to ignore.
    Used when an admin dismisses a bug report or ticket category.
    """
    record(
        agent_name,
        lesson=f"Ignore or deprioritize findings matching: {pattern}",
        lesson_type="correction",
        trigger="Admin dismissed this finding as a false positive",
        confidence=0.9,
    )


def summarize(agent_name: str) -> dict:
    """Return stats about this agent's memory."""
    learnings = _load(agent_name)
    types = {}
    for l in learnings:
        t = l.get("type", "unknown")
        types[t] = types.get(t, 0) + 1
    return {
        "agent": agent_name,
        "total_learnings": len(learnings),
        "by_type": types,
        "oldest": learnings[0].get("ts") if learnings else None,
        "newest": learnings[-1].get("ts") if learnings else None,
    }


def all_summaries() -> list[dict]:
    MEMORY_DIR.mkdir(parents=True, exist_ok=True)
    return [summarize(f.stem) for f in sorted(MEMORY_DIR.glob("*.json"))]


# ─── Internals ────────────────────────────────────────────────────────────────


def _reflect_worker(agent_name: str, run_output: str, outcome: str):
    try:
        # Trim output to fit in context
        trimmed = run_output[-4000:] if len(run_output) > 4000 else run_output
        context = f"Agent: {agent_name}\nOutcome: {outcome}\n\nRun output:\n{trimmed}"

        raw = chat([
            {"role": "system", "content": REFLECT_PROMPT},
            {"role": "user",   "content": context},
        ], timeout=60)

        cleaned = raw.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
        data = json.loads(cleaned)

        if data.get("skip"):
            return  # Routine run, nothing to learn

        entry = {
            "ts":         datetime.utcnow().isoformat(),
            "type":       data.get("type", "warning"),
            "lesson":     data.get("lesson", "").strip(),
            "trigger":    data.get("trigger", "").strip(),
            "confidence": float(data.get("confidence", 0.5)),
            "outcome":    outcome,
            "source":     "reflection",
        }

        if entry["lesson"]:
            _append(agent_name, entry)

    except (json.JSONDecodeError, Exception):
        pass  # Reflection is best-effort; never block the main run


def _load(agent_name: str) -> list:
    f = MEMORY_DIR / f"{agent_name}.json"
    if not f.exists():
        return []
    try:
        with _lock:
            return json.loads(f.read_text())
    except Exception:
        return []


def _append(agent_name: str, entry: dict):
    MEMORY_DIR.mkdir(parents=True, exist_ok=True)
    f = MEMORY_DIR / f"{agent_name}.json"
    with _lock:
        learnings = []
        if f.exists():
            try:
                learnings = json.loads(f.read_text())
            except Exception:
                learnings = []
        learnings.append(entry)
        # Prune oldest low-confidence entries when over cap
        if len(learnings) > MAX_LEARNINGS:
            learnings.sort(key=lambda l: (l.get("confidence", 0.5), l.get("ts", "")))
            learnings = learnings[-(MAX_LEARNINGS):]
        f.write_text(json.dumps(learnings, indent=2))
