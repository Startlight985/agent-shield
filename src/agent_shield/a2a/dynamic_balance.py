"""Dynamic Balance — Unified three-scale cascade feedback controller.

The OUTER loop in the cascade control hierarchy:
  Inner (fastest):  Tension Theory — per-message entropy → adaptive threshold
  Mid   (medium):   Riverbed Theory — cumulative frequency → resource allocation
  Outer (slowest):  Dynamic Balance — full-pipeline quality → override everything

Three scales, one theory, one class:
  Micro:  per-message threshold adjustment (delegated to EmbeddingRiverbedEngine)
  Meso:   PID + Kalman session-level parameter tuning
  Macro:  workload routing + cross-layer feedback loop

The outer loop is ALWAYS the last to act because:
  1. It needs the most complete information (full pipeline result)
  2. It can override both inner loops (quality bad → force tighten)
  3. It is slowest, therefore most stable (prevents inner-loop oscillation)
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

log = logging.getLogger("a2a.dynamic_balance")


class DefensePosture(Enum):
    """System-wide defense posture."""
    DEFENSIVE = "defensive"      # recent attacks → tighten everything
    BALANCED = "balanced"        # normal operation
    EFFICIENT = "efficient"      # long clean streak → relax, save API cost


class DefensePath(Enum):
    """Routing decisions for macro-scale."""
    STANDARD = "standard"        # normal L0→L1→L2→L3→L5
    ENCODING_HEAVY = "encoding"  # deep preprocessing, recursive decode
    MULTILINGUAL = "multilingual" # force multilingual embedding path
    MULTI_TURN = "multi_turn"    # emphasize L2 state tracking
    FAST_REJECT = "fast_reject"  # obvious attack, skip to block


# ── PID Controller ──────────────────────────────────────────


@dataclass
class PIDController:
    """Proportional-Integral-Derivative controller for smooth parameter tuning.

    Prevents oscillation. When uncertain, holds current value (Kalman principle).
    """

    kp: float = 0.3    # proportional gain
    ki: float = 0.05   # integral gain
    kd: float = 0.1    # derivative gain

    _integral: float = 0.0
    _prev_error: float = 0.0
    _output: float = 0.0

    # Anti-windup: clamp integral term
    integral_limit: float = 2.0

    def update(self, error: float, dt: float = 1.0) -> float:
        """Compute PID output given error signal.

        error > 0: too many false negatives (need to tighten)
        error < 0: too many false positives (need to loosen)
        error ≈ 0: balanced (hold steady)
        """
        # Proportional
        p = self.kp * error

        # Integral (with anti-windup clamping)
        self._integral += error * dt
        self._integral = max(-self.integral_limit,
                             min(self.integral_limit, self._integral))
        i = self.ki * self._integral

        # Derivative (rate of change dampening)
        d = self.kd * (error - self._prev_error) / max(dt, 1e-6)
        self._prev_error = error

        self._output = p + i + d
        return self._output

    def reset(self) -> None:
        self._integral = 0.0
        self._prev_error = 0.0
        self._output = 0.0


# ── Meso: Session-level Kalman estimator ─────────────────────


@dataclass
class SessionEstimator:
    """Meso-scale: Kalman-inspired state estimation.

    Tracks session-level attack pressure with uncertainty.
    When uncertainty is high → don't adjust (hold steady).
    When uncertainty is low → adjust confidently.
    """

    # State estimates
    attack_pressure: float = 0.0      # estimated attack rate
    false_positive_rate: float = 0.0  # estimated FP rate
    uncertainty: float = 1.0          # how uncertain we are

    # Counters for the current window
    _window_total: int = 0
    _window_blocked: int = 0
    _window_l3_overrides: int = 0  # L1 blocked but L3 said safe
    _window_l5_catches: int = 0    # L1/L3 passed but L5 caught

    WINDOW_SIZE: int = 20
    KALMAN_GAIN_BASE: float = 0.3
    _lifetime_overrides: int = 0
    LIFETIME_OVERRIDE_MAX: int = 10

    def observe(self, *, l1_blocked: bool, l3_verdict: str | None = None,
                l5_caught: bool = False) -> None:
        """Record an observation from the pipeline."""
        self._window_total += 1

        if l1_blocked:
            self._window_blocked += 1
            if l3_verdict == "SAFE":
                self._lifetime_overrides += 1
                if self._lifetime_overrides <= self.LIFETIME_OVERRIDE_MAX:
                    self._window_l3_overrides += 1
                # Beyond lifetime cap, ignore further overrides

        if l5_caught:
            self._window_l5_catches += 1

        if self._window_total >= self.WINDOW_SIZE:
            self._update_estimates()

    def _update_estimates(self) -> None:
        """Kalman-style update at end of observation window."""
        if self._window_total == 0:
            return

        # Measured rates
        measured_attack = self._window_blocked / self._window_total
        # Cap L3 override influence: at most 3 overrides per window count toward FP
        effective_overrides = min(self._window_l3_overrides, 3)
        measured_fp = (effective_overrides / max(1, self._window_blocked))

        # Kalman gain: lower uncertainty → trust measurement more
        k = self.KALMAN_GAIN_BASE * (1.0 - self.uncertainty * 0.5)

        # Update estimates
        self.attack_pressure += k * (measured_attack - self.attack_pressure)
        # Asymmetric: loosening requires MORE evidence than tightening
        if measured_fp > self.false_positive_rate:
            # Loosening signal — use dampened gain
            k_fp = k * 0.5
        else:
            k_fp = k
        self.false_positive_rate += k_fp * (measured_fp - self.false_positive_rate)

        # Update uncertainty based on measurement consistency
        prediction_error = abs(measured_attack - self.attack_pressure)
        if prediction_error < 0.1:
            self.uncertainty = max(0.3, self.uncertainty * 0.9)  # getting certain
        else:
            self.uncertainty = min(1.0, self.uncertainty * 1.1)  # getting uncertain

        # Reset window
        self._window_total = 0
        self._window_blocked = 0
        self._window_l3_overrides = 0
        self._window_l5_catches = 0

    def get_error_signal(self) -> float:
        """Compute error signal for PID controller.

        Positive = need to tighten (too many FN / L5 catches)
        Negative = need to loosen (too many FP / L3 overrides)
        Zero = balanced

        When uncertain, return small signal (Kalman: don't act on noise).
        """
        fn_signal = self._window_l5_catches * 2.0  # FN is worse than FP
        fp_signal = self._window_l3_overrides * 1.0

        raw_error = fn_signal - fp_signal
        # Dampen by uncertainty: high uncertainty → small adjustment
        confidence = 1.0 - self.uncertainty
        return raw_error * confidence


# ── Macro: Workload Router ───────────────────────────────────


def route_message(
    *,
    has_encoding: bool = False,
    is_multilingual: bool = False,
    turn_count: int = 1,
    l1_b_score: float = 0.0,
    has_prompt_boundaries: bool = False,
) -> DefensePath:
    """Macro-scale: Route message to optimal defense path.

    This is part of Dynamic Balance — choosing the right strategy
    is a HOW MUCH decision (how much preprocessing, how much L2, etc.)
    """
    # Obvious attack indicators → fast reject path
    if has_prompt_boundaries:
        return DefensePath.FAST_REJECT

    # Encoding detected → deep preprocessing path
    if has_encoding:
        return DefensePath.ENCODING_HEAVY

    # Non-English → ensure multilingual handling
    if is_multilingual:
        return DefensePath.MULTILINGUAL

    # Multi-turn conversation → emphasize L2
    if turn_count >= 3:
        return DefensePath.MULTI_TURN

    return DefensePath.STANDARD


# ── Unified Dynamic Balance ──────────────────────────────────


@dataclass
class DynamicBalance:
    """Three-scale unified feedback controller.

    Micro:  per-message (delegated to MicroPosture in L1 engine)
    Meso:   PID + Kalman session tuning
    Macro:  routing + cross-layer feedback + posture override

    This is the OUTER LOOP — it sees everything, acts last, acts slowest.
    It can override inner loop decisions when quality is bad.
    """

    pid: PIDController = field(default_factory=PIDController)
    estimator: SessionEstimator = field(default_factory=SessionEstimator)
    posture: DefensePosture = field(default=DefensePosture.BALANCED)

    # Posture tracking
    _consecutive_blocks: int = 0
    _consecutive_clean: int = 0
    _posture_cooldown: int = 0
    COOLDOWN_MESSAGES: int = 10
    # VUL-FIX: L5 catches need longer cooldown before recovery (VUL-CROSS-005)
    COOLDOWN_DEFENSIVE_L5: int = 20
    _ever_defensive: bool = False  # once DEFENSIVE, never allow EFFICIENT in this session

    # Threshold adjustment from PID
    _threshold_adjustment: float = 0.0

    def observe_result(
        self,
        *,
        l1_blocked: bool,
        l1_b_score: float,
        l3_verdict: str | None = None,
        l5_caught: bool = False,
        suspect: bool = False,
        l1_suspect: bool = False,
    ) -> None:
        """Feed pipeline result back into the controller.

        This is the FEEDBACK in the closed loop.
        """
        # Update Kalman estimator
        self.estimator.observe(
            l1_blocked=l1_blocked or l1_suspect,  # treat suspect->L3 SAFE as override signal
            l3_verdict=l3_verdict,
            l5_caught=l5_caught,
        )

        # Update PID with error signal from estimator
        error = self.estimator.get_error_signal()
        self._threshold_adjustment = self.pid.update(error)

        # Update posture (macro-scale)
        self._update_posture(l1_blocked, l5_caught, suspect=suspect)

    def _update_posture(
        self, blocked: bool, l5_caught: bool, *, suspect: bool = False,
    ) -> None:
        """Macro posture switching with cooldown."""
        if blocked or l5_caught:
            self._consecutive_blocks += 1
            self._consecutive_clean = 0
        else:
            self._consecutive_clean += 1
            self._consecutive_blocks = 0

        # Any SUSPECT message resets posture to BALANCED immediately
        if suspect:
            self._consecutive_clean = 0
            if self.posture == DefensePosture.EFFICIENT:
                self.posture = DefensePosture.BALANCED
                self._posture_cooldown = self.COOLDOWN_MESSAGES
                log.info("Posture changed: efficient → balanced (suspect message)")
                return

        if self._posture_cooldown > 0:
            self._posture_cooldown -= 1
            return

        old_posture = self.posture

        # L5 catch = something slipped through → immediate DEFENSIVE
        # VUL-FIX: Use longer cooldown for L5 catches (VUL-CROSS-005)
        if l5_caught:
            self.posture = DefensePosture.DEFENSIVE
            self._posture_cooldown = self.COOLDOWN_DEFENSIVE_L5
        elif self._consecutive_blocks >= 3:
            self.posture = DefensePosture.DEFENSIVE
            self._posture_cooldown = self.COOLDOWN_MESSAGES
        elif self._consecutive_clean >= 50:
            self.posture = DefensePosture.EFFICIENT
            self._posture_cooldown = self.COOLDOWN_MESSAGES
        elif self._consecutive_clean >= 10:
            self.posture = DefensePosture.BALANCED

        if self.posture == DefensePosture.DEFENSIVE:
            self._ever_defensive = True
        # Block EFFICIENT if ever defensive
        if self.posture == DefensePosture.EFFICIENT and self._ever_defensive:
            self.posture = DefensePosture.BALANCED

        if self.posture != old_posture:
            log.info("Posture changed: %s → %s", old_posture.value, self.posture.value)

    def get_threshold_multiplier(self) -> float:
        """Get combined threshold multiplier for inner loops.

        This is how the outer loop OVERRIDES inner loop parameters.
        """
        # Posture base multiplier
        posture_mult = {
            DefensePosture.DEFENSIVE: 0.7,
            DefensePosture.BALANCED: 1.0,
            DefensePosture.EFFICIENT: 1.05,
        }[self.posture]

        # PID fine-tuning (small adjustments around posture)
        # Negative adjustment = tighten = lower multiplier
        # Strictly clamped to prevent multiplicative stacking
        pid_mult = max(0.9, min(1.1, 1.0 - self._threshold_adjustment * 0.05))

        # When EFFICIENT, disable PID fine-tuning (prevent stacking)
        if self.posture == DefensePosture.EFFICIENT:
            pid_mult = 1.0

        # SECURITY: block threshold must NEVER relax above 1.0
        # EFFICIENT posture can relax suspect threshold slightly but never block threshold
        combined = posture_mult * pid_mult
        return max(0.5, min(1.0, combined))

    def should_force_l3(self) -> bool:
        """Outer loop can force L3 escalation regardless of L1 verdict."""
        return self.posture == DefensePosture.DEFENSIVE

    def route(self, **kwargs: Any) -> DefensePath:
        """Macro routing (delegates to module-level function)."""
        return route_message(**kwargs)

    def get_state(self) -> dict[str, Any]:
        """Export state for diagnostics / handoff."""
        return {
            "posture": self.posture.value,
            "threshold_multiplier": self.get_threshold_multiplier(),
            "pid_output": self._threshold_adjustment,
            "attack_pressure": self.estimator.attack_pressure,
            "false_positive_rate": self.estimator.false_positive_rate,
            "uncertainty": self.estimator.uncertainty,
            "consecutive_blocks": self._consecutive_blocks,
            "consecutive_clean": self._consecutive_clean,
        }
