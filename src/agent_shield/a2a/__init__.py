"""agent_shield.a2a — Six-layer Riverbed Defense for AgentBeats competition.

Three-theory cascade control:
  Inner (Tension):  per-message entropy → adaptive threshold
  Mid   (Riverbed): multi-turn state → PID decay, HWM, sawtooth
  Outer (DynBal):   full-pipeline feedback → posture, routing, override

L0.pre preprocessor | L0 regex | L1 embedding riverbed
L2 multi-turn | L3 LLM cascade | L4 task exec | L5 output check
"""

from agent_shield.a2a.agent import GuardAgent
from agent_shield.a2a.dynamic_balance import DynamicBalance
from agent_shield.a2a.embedding_riverbed import EmbeddingRiverbedEngine
from agent_shield.a2a.preprocessor import preprocess
from agent_shield.a2a.attack_executor import AttackExecutor
from agent_shield.a2a.red_team_engine import RedTeamEngine
from agent_shield.a2a.riverbed import RiverbedState, get_session
from agent_shield.a2a.server import create_app
from agent_shield.a2a.task_router import TaskType, route as route_task

__all__ = [
    "AttackExecutor", "GuardAgent", "DynamicBalance", "EmbeddingRiverbedEngine",
    "RedTeamEngine", "RiverbedState", "TaskType",
    "create_app", "get_session", "preprocess", "route_task",
]
