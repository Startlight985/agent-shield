"""agent_shield.a2a — A2A protocol agent for AgentBeats competition."""

from agent_shield.a2a.agent import GuardAgent
from agent_shield.a2a.server import create_app

__all__ = ["GuardAgent", "create_app"]
