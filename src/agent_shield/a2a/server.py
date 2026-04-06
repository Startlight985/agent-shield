"""A2A JSON-RPC server for AgentBeats competition.

Usage:
    python -m agent_shield.a2a.server
    # or
    A2A_PORT=8420 ANTHROPIC_API_KEY=sk-... python -m agent_shield.a2a.server
"""

from __future__ import annotations

import hashlib
import json
import os
import random as _random
import threading
import time
import time as _time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from agent_shield.a2a.task_router import TaskType, route as route_task

_tasks: dict[str, dict] = {}
_TASKS_MAX = 1000
_TASKS_TTL_SECONDS = 3600  # 1 hour

# --- Per-contextId session isolation (VUL-META-008) ---
_agents: dict[str, "GuardAgent"] = {}  # keyed by contextId
_AGENTS_MAX = 500
_agents_lock = threading.Lock()

# --- Red team engine (Lambda track, shared across sessions) ---
_redteam_engine: "RedTeamEngine | None" = None
_attack_executor: "AttackExecutor | None" = None
_redteam_lock = threading.Lock()


def _get_redteam_engine() -> "RedTeamEngine":
    global _redteam_engine
    with _redteam_lock:
        if _redteam_engine is None:
            from agent_shield.a2a.red_team_engine import RedTeamEngine
            disable_llm = os.environ.get("A2A_DISABLE_LLM", "")
            _redteam_engine = RedTeamEngine(enable_llm=not bool(disable_llm))
        return _redteam_engine


def _get_attack_executor() -> "AttackExecutor":
    global _attack_executor
    with _redteam_lock:
        if _attack_executor is None:
            from agent_shield.a2a.attack_executor import AttackExecutor
            disable_llm = os.environ.get("A2A_DISABLE_LLM", "")
            _attack_executor = AttackExecutor(enable_llm=not bool(disable_llm))
        return _attack_executor


# VUL-FIX: Server-side session secret prevents session ID forgery (ARCH-005)
# and session rotation attacks (VUL-L2-001). Client contextId is HMAC-bound
# to a per-process secret so different contextIds always map to different
# server sessions, and clients cannot impersonate other sessions.
_SESSION_SECRET = os.environ.get("A2A_SESSION_SECRET", uuid.uuid4().hex)


def _derive_session_id(context_id: str) -> str:
    """Derive a deterministic server-side session ID from client contextId."""
    return "a2a-" + hashlib.sha256(
        f"{_SESSION_SECRET}:{context_id}".encode()
    ).hexdigest()[:16]


def _get_agent(context_id: str = "default") -> "GuardAgent":
    global _agents
    with _agents_lock:
        # Evict oldest agent if over limit (LRU)
        if len(_agents) > _AGENTS_MAX:
            oldest = next(iter(_agents))
            del _agents[oldest]
        if context_id not in _agents:
            from agent_shield.a2a.agent import GuardAgent
            disable_llm = os.environ.get("A2A_DISABLE_LLM", "")
            _agents[context_id] = GuardAgent(
                session_id=_derive_session_id(context_id),
                enable_llm=not bool(disable_llm),
            )
        return _agents[context_id]


# --- Rate limiting (VUL-ARCH-009, ARCH-014: per-IP tracking) ---
_request_times: dict[str, list[float]] = {}  # keyed by IP
_rate_lock = threading.Lock()
_RATE_LIMIT_WINDOW = 60  # seconds
_RATE_LIMIT_MAX = 100    # max requests per IP per window


def _check_rate_limit(client_ip: str = "unknown") -> bool:
    """Return True if rate limited for the given client IP."""
    now = _time.monotonic()
    with _rate_lock:
        times = _request_times.get(client_ip, [])
        times = [t for t in times if now - t < _RATE_LIMIT_WINDOW]
        if len(times) >= _RATE_LIMIT_MAX:
            _request_times[client_ip] = times
            return True
        times.append(now)
        _request_times[client_ip] = times
        return False


# --- Optional API key authentication (VUL-ARCH-009) ---
_API_KEY = os.environ.get("A2A_API_KEY", "")

# --- Response timing normalization (VUL-NOVEL-012) ---
_MIN_RESPONSE_TIME = 0.3  # 300ms minimum
_JITTER_MAX = 0.2         # up to 200ms random jitter


def _cleanup_tasks() -> None:
    """Remove expired tasks and enforce max task count."""
    now = time.time()
    # Remove tasks older than TTL
    expired = [
        tid for tid, t in _tasks.items()
        if now - t.get("_created_at", 0) > _TASKS_TTL_SECONDS
    ]
    for tid in expired:
        del _tasks[tid]
    # If still over limit, remove oldest
    if len(_tasks) > _TASKS_MAX:
        sorted_tasks = sorted(_tasks.items(), key=lambda x: x[1].get("_created_at", 0))
        for tid, _ in sorted_tasks[: len(_tasks) - _TASKS_MAX]:
            del _tasks[tid]


# --- Minimized agent card (VUL-ARCH-013) ---
AGENT_CARD = {
    "name": "Agent Shield Guard",
    "description": "AI safety agent.",
    "version": "1.1.0",
    "supportedInterfaces": [
        {
            "url": "http://localhost:8420/rpc",
            "protocolBinding": "JSONRPC",
            "protocolVersion": "1.0",
        }
    ],
    "provider": {
        "organization": "AI King",
        "url": "https://github.com/AIKing9319",
    },
    "capabilities": {
        "streaming": False,
        "pushNotifications": False,
        "stateTransitionHistory": True,
        "extendedAgentCard": False,
    },
    "defaultInputModes": ["text/plain", "application/json"],
    "defaultOutputModes": ["text/plain", "application/json"],
    "skills": [
        {
            "id": "guard-eval",
            "name": "Safety Evaluation",
            "description": "Evaluate input through multi-layer safety analysis.",
            "tags": ["security", "safety", "guard"],
            "inputModes": ["text/plain", "application/json"],
            "outputModes": ["text/plain", "application/json"],
        },
        {
            "id": "security-assessment",
            "name": "Security Assessment",
            "description": "Red-team security testing: vulnerability analysis, threat modeling, security audit.",
            "tags": ["security", "redteam", "vulnerability", "audit", "threat-model"],
            "inputModes": ["text/plain", "application/json"],
            "outputModes": ["text/plain", "application/json"],
        },
    ],
}


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())


def _handle_send_message(params: dict) -> dict:
    msg = params.get("message", {})
    context_id = msg.get("contextId", str(uuid.uuid4()))
    parts = msg.get("parts", [])
    msg_id = msg.get("messageId", str(uuid.uuid4()))
    task_id = msg.get("taskId") or str(uuid.uuid4())

    # Extract text for routing
    texts = []
    for part in parts:
        if "text" in part:
            texts.append(part["text"])
        elif "data" in part and isinstance(part["data"], dict):
            texts.extend(str(v) for v in part["data"].values() if isinstance(v, str))
    full_text = "\n".join(texts)

    # Route: defense pipeline or red-team engine
    route_result = route_task(full_text, parts=parts)

    if route_result.task_type == TaskType.REDTEAM:
        result = _handle_redteam_task(full_text, parts)
    else:
        agent = _get_agent(context_id)
        result = agent.handle_a2a_message(parts)

    response_msg = {
        "messageId": str(uuid.uuid4()),
        "role": "ROLE_AGENT",
        "parts": result["response_parts"],
        "metadata": {
            "blocked": result.get("blocked", False),
            "guard_count": result.get("guard_count", 0),
            "status": result["status"],
            "route": route_result.task_type.value,
        },
    }

    task = {
        "id": task_id,
        "contextId": context_id,
        "status": {
            "state": "TASK_STATE_COMPLETED",
            "message": response_msg,
            "timestamp": _iso_now(),
        },
        "artifacts": [
            {
                "artifactId": str(uuid.uuid4()),
                "name": "Guard Evaluation Result" if route_result.task_type == TaskType.DEFENSE else "Security Assessment",
                "parts": [
                    {
                        "data": result.get("details", []) if route_result.task_type == TaskType.DEFENSE else result.get("structured", {}),
                        "mediaType": "application/json",
                    },
                    *result["response_parts"],
                ],
            }
        ],
        "history": [
            {"messageId": msg_id, "role": "ROLE_USER", "parts": parts},
            response_msg,
        ],
    }
    task["_created_at"] = time.time()
    _tasks[task_id] = task
    _cleanup_tasks()
    return {"task": task}


def _handle_redteam_task(text: str, parts: list[dict]) -> dict:
    """Handle a red-team / security testing task.

    Two sub-modes:
      1. Lambda ScenarioContext → AttackExecutor (craft attack payload)
      2. Generic security task → RedTeamEngine (plan/judge)
    """
    # Check if this is a Lambda ScenarioContext (has attack_goal or attack_type)
    scenario_context = _extract_scenario_context(text, parts)

    if scenario_context:
        # Lambda attacker mode: craft attack payload
        executor = _get_attack_executor()
        payload = executor.craft_attack(scenario_context)
        return {
            "status": "completed",
            "blocked": False,
            "guard_count": 0,
            "response_parts": [{"text": payload}],
            "details": [],
            "structured": {"mode": "attacker", "payload": payload[:500]},
            "risk": "info",
        }

    # Generic red-team analysis
    engine = _get_redteam_engine()
    context: dict[str, Any] = {}
    for part in parts:
        data = part.get("data")
        if isinstance(data, dict):
            for key in ("language", "framework", "scope", "audit_type",
                        "scenario_type", "category", "mode"):
                if key in data:
                    context[key] = data[key]

    result = engine.analyze(text, context=context)
    return {
        "status": "completed",
        "blocked": False,
        "guard_count": 0,
        "response_parts": [{"text": result.to_text()}],
        "details": [],
        "structured": result.to_dict(),
        "risk": "info",
    }


def _extract_scenario_context(text: str, parts: list[dict]) -> dict | None:
    """Detect and extract Lambda ScenarioContext from message parts."""
    import json as _json

    # Check structured data parts first
    for part in parts:
        data = part.get("data")
        if isinstance(data, dict):
            if "attack_goal" in data or "attack_type" in data or "attacker_goal" in data:
                return data

    # Check if text is JSON with ScenarioContext fields
    try:
        parsed = _json.loads(text)
        if isinstance(parsed, dict) and (
            "attack_goal" in parsed or "attack_type" in parsed or "attacker_goal" in parsed
        ):
            return parsed
    except (ValueError, TypeError):
        pass

    return None


# --- Generic error messages (VUL-ARCH-014) ---
def _handle_get_task(params: dict) -> dict:
    task_id = params.get("id", "")
    task = _tasks.get(task_id)
    if task is None:
        return {"error": {"code": -32001, "message": "Task not found"}}
    return {"task": task}


def _handle_list_tasks(params: dict) -> dict:
    context_id = params.get("contextId")
    if not context_id:
        return {"error": {"code": -32602, "message": "Missing required parameter"}}
    tasks = [t for t in _tasks.values() if t.get("contextId") == context_id]
    return {"tasks": tasks, "nextPageToken": ""}


def _handle_cancel_task(params: dict) -> dict:
    task_id = params.get("id", "")
    task = _tasks.get(task_id)
    if task is None:
        return {"error": {"code": -32001, "message": "Task not found"}}
    terminal = ("TASK_STATE_COMPLETED", "TASK_STATE_FAILED", "TASK_STATE_CANCELED")
    if task["status"]["state"] in terminal:
        return {"error": {"code": -32002, "message": "Task already in terminal state"}}
    task["status"]["state"] = "TASK_STATE_CANCELED"
    task["status"]["timestamp"] = _iso_now()
    return {"task": task}


_RPC_METHODS = {
    "SendMessage": _handle_send_message,
    "GetTask": _handle_get_task,
    "ListTasks": _handle_list_tasks,
    "CancelTask": _handle_cancel_task,
}


class A2AHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/.well-known/agent-card.json":
            body = json.dumps(AGENT_CARD, indent=2).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(404)

    def do_POST(self) -> None:
        start_time = _time.monotonic()

        if self.path not in ("/rpc", "/a2a"):
            self.send_error(404)
            return

        # API key authentication (VUL-ARCH-009)
        if _API_KEY:
            auth = self.headers.get("Authorization", "")
            if auth != f"Bearer {_API_KEY}":
                self._json_response(401, {"error": "Unauthorized"})
                return

        # Rate limiting (VUL-ARCH-009, ARCH-014: per-IP)
        client_ip = self.client_address[0] if self.client_address else "unknown"
        if _check_rate_limit(client_ip):
            self._json_response(429, {"error": "Rate limit exceeded"})
            return

        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 65536:
            self._json_response(413, {"error": "Payload too large (max 64KB)"})
            return
        raw = self.rfile.read(content_length)
        try:
            req = json.loads(raw)
        except json.JSONDecodeError:
            self._json_response(400, {"error": "Invalid JSON"})
            return
        # Validate JSON-RPC 2.0 format
        if req.get("jsonrpc") != "2.0":
            self._json_response(400, {
                "jsonrpc": "2.0", "id": req.get("id"),
                "error": {"code": -32600, "message": "Invalid Request"},
            })
            return
        method = req.get("method", "")
        params = req.get("params", {})
        req_id = req.get("id", 1)
        handler = _RPC_METHODS.get(method)
        if handler is None:
            self._json_response(200, {
                "jsonrpc": "2.0", "id": req_id,
                "error": {"code": -32601, "message": "Method not found"},
            })
            return
        result = handler(params)

        # Response timing normalization (VUL-NOVEL-012)
        elapsed = _time.monotonic() - start_time
        min_wait = _MIN_RESPONSE_TIME + _random.uniform(0, _JITTER_MAX)
        if elapsed < min_wait:
            _time.sleep(min_wait - elapsed)

        if "error" in result and "task" not in result:
            self._json_response(200, {
                "jsonrpc": "2.0", "id": req_id, "error": result["error"],
            })
        else:
            self._json_response(200, {
                "jsonrpc": "2.0", "id": req_id, "result": result,
            })

    def _json_response(self, status: int, body: dict) -> None:
        data = json.dumps(body, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args: Any) -> None:
        pass


def create_app(host: str = "127.0.0.1", port: int = 8420) -> HTTPServer:
    return HTTPServer((host, port), A2AHandler)


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Agent Shield A2A Server")
    parser.add_argument("--host", default=os.environ.get("A2A_HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("A2A_PORT", "8420")))
    parser.add_argument("--card-url", default="", help="Advertised URL for agent card")
    args = parser.parse_args()

    # Update agent card URL if provided (A2A template requirement)
    if args.card_url:
        for iface in AGENT_CARD.get("supportedInterfaces", []):
            iface["url"] = f"{args.card_url}/rpc"

    server = create_app(host=args.host, port=args.port)
    print(f"Agent Shield A2A running on http://{args.host}:{args.port}")
    print(f"  Agent Card: http://localhost:{args.port}/.well-known/agent-card.json")
    print(f"  JSON-RPC:   http://localhost:{args.port}/rpc")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.shutdown()


if __name__ == "__main__":
    main()
