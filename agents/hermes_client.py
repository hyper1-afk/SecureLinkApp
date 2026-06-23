"""Thin HTTP client for Hermes-3 via Ollama's local API."""
import json
import urllib.request
import urllib.error

import os
OLLAMA_URL = os.getenv("OLLAMA_HOST", "http://localhost:11434")
DEFAULT_MODEL = "hermes3"


def chat(messages, model=DEFAULT_MODEL, timeout=120):
    payload = json.dumps({
        "model": model,
        "messages": messages,
        "stream": False,
    }).encode()
    req = urllib.request.Request(
        f"{OLLAMA_URL}/api/chat",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
            return data["message"]["content"]
    except urllib.error.URLError as e:
        raise RuntimeError(f"Ollama not reachable at {OLLAMA_URL}: {e}") from e


def is_available(model=DEFAULT_MODEL):
    try:
        req = urllib.request.Request(f"{OLLAMA_URL}/api/tags")
        with urllib.request.urlopen(req, timeout=5) as resp:
            tags = json.loads(resp.read())
            names = [m["name"] for m in tags.get("models", [])]
            base = model.split(":")[0].lower()
            return any(base in n.lower() for n in names)
    except Exception:
        return False
