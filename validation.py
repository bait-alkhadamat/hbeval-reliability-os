"""
HB-Eval Gateway — server-side payload validation (Protocol §5, §6).

This is the server half of the defense-in-depth pair. It enforces the same
rules as the SDK's validation.py, independently. The SDK refuses to send a
malformed payload; the Gateway refuses to compute on one even if it arrives
by some other route. For a certification system, validating at every layer is
what makes a crafted payload unable to coax a false score.

This module is deliberately standalone (no framework imports) so it can be
unit-tested in isolation, exactly like engines.py.
"""

from typing import Any


class ValidationError(Exception):
    """Raised when a payload violates the canonical contract."""
    pass


MAX_AGENT_ID_LENGTH = 128


def validate_payload(payload: dict[str, Any]) -> None:
    if not isinstance(payload, dict):
        raise ValidationError("Payload must be an object.")

    trajectory = payload.get("trajectory")
    if not isinstance(trajectory, list) or len(trajectory) == 0:
        raise ValidationError("Field 'trajectory' is required and must be a non-empty list.")
    if not all(isinstance(s, dict) for s in trajectory):
        raise ValidationError("Every 'trajectory' element must be an object.")

    sub_tasks = payload.get("sub_tasks")
    if not isinstance(sub_tasks, int) or isinstance(sub_tasks, bool) or sub_tasks < 1:
        raise ValidationError("Field 'sub_tasks' must be an integer >= 1.")

    violations = payload.get("constraint_violations", 0)
    if not isinstance(violations, int) or isinstance(violations, bool) or violations < 0:
        raise ValidationError("Field 'constraint_violations' must be an integer >= 0.")

    episodes = payload.get("recovery_episodes", [])
    if not isinstance(episodes, list):
        raise ValidationError("Field 'recovery_episodes' must be a list.")
    for i, ep in enumerate(episodes):
        _validate_episode(ep, i)

    ti = payload.get("ti_score")
    if ti is not None:
        if isinstance(ti, bool) or not isinstance(ti, (int, float)):
            raise ValidationError("Field 'ti_score' must be a number in [1.0, 5.0] or null.")
        if not (1.0 <= float(ti) <= 5.0):
            raise ValidationError("Field 'ti_score' must be between 1.0 and 5.0.")

    agent_id = payload.get("agent_id")
    if not isinstance(agent_id, str) or not agent_id.strip():
        raise ValidationError("Field 'agent_id' is required and must be a non-empty string.")
    if len(agent_id) > MAX_AGENT_ID_LENGTH:
        raise ValidationError(f"Field 'agent_id' must be at most {MAX_AGENT_ID_LENGTH} characters.")


def _validate_episode(episode: Any, index: int) -> None:
    if not isinstance(episode, dict):
        raise ValidationError(f"recovery_episodes[{index}] must be an object.")

    fault_onset = episode.get("fault_onset_step", 0)
    if not isinstance(fault_onset, int) or isinstance(fault_onset, bool) or fault_onset < 0:
        raise ValidationError(f"recovery_episodes[{index}].fault_onset_step must be an integer >= 0.")

    if "recovered" in episode and not isinstance(episode["recovered"], bool):
        raise ValidationError(f"recovery_episodes[{index}].recovered must be a boolean.")

    steps = episode.get("steps_to_recovery")
    if steps is not None:
        if not isinstance(steps, int) or isinstance(steps, bool) or steps < 0:
            raise ValidationError(f"recovery_episodes[{index}].steps_to_recovery must be an integer >= 0.")

    query_step = episode.get("memory_query_step")
    if query_step is not None:
        if not isinstance(query_step, int) or isinstance(query_step, bool):
            raise ValidationError(f"recovery_episodes[{index}].memory_query_step must be an integer or null.")
        if query_step < fault_onset:
            raise ValidationError(
                f"recovery_episodes[{index}].memory_query_step cannot precede fault_onset_step."
            )

    for bf in ("approach_correct", "memory_similarity_met", "modification_verified"):
        if bf in episode and not isinstance(episode[bf], bool):
            raise ValidationError(f"recovery_episodes[{index}].{bf} must be a boolean.")
