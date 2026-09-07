"""Deterministic bounded exhaustive state exploration for Carry2PC."""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, replace
from enum import Enum
from typing import Iterable

from carry2pc.canonical import canonical_data, stable_hash


class Mutant(str, Enum):
    OMIT_OBLIGATION_ON_INSTALL = "omit_obligation_on_install"
    DUAL_ACTIVE_ON_ACTIVATE = "dual_active_on_activate"
    EPOCH_GUARD_CONVERTS_COMMIT_TO_ABORT = "epoch_guard_converts_commit_to_abort"
    REWRITE_INTENT_ON_INSTALL = "rewrite_intent_on_install"
    DUPLICATE_OUTBOX_ENQUEUE = "duplicate_outbox_enqueue"


class Invariant(str, Enum):
    OWNERSHIP_UNIQUENESS = "ownership_uniqueness"
    TRANSFER_LINEAGE = "transfer_lineage"
    OBLIGATION_PERSISTENCE = "obligation_persistence"
    DECISION_CONSISTENCY = "decision_consistency"
    INTENT_FIDELITY = "intent_fidelity"
    DURABLE_ENQUEUE_INTEGRITY = "durable_enqueue_integrity"
    CAPSULE_COMPONENT_INTEGRITY = "capsule_component_integrity"


@dataclass(frozen=True, order=True)
class CommandBinding:
    command_id: str
    twin_id: str
    operation_id: str
    command_index: int
    payload: str


@dataclass(frozen=True)
class ReplicaState:
    mode: str
    pending_transfer_id: str
    has_obligation: bool
    intent_value: str
    command_id: str
    command_payload: str
    tombstone: str
    tombstone_record_digest: str
    value: str
    version: int
    authorization: tuple[str, tuple[str, ...], int, str]
    frontier: tuple[tuple[str, int, str], ...]
    locks: tuple[str, ...]
    outbox: tuple[CommandBinding, ...]


@dataclass(frozen=True)
class BoundedState:
    source_id: str
    target_id: str
    owner: str
    epoch: int
    transfer_stage: str
    terminal_outcome: str
    terminal_delivered_source: bool
    terminal_delivered_target: bool
    certified_root_equal: bool
    yes_emitted: bool
    prepare_epoch: int | None
    decision: str
    decision_deliveries_source: int
    decision_deliveries_target: int
    decision_inbox_source: int
    decision_inbox_target: int
    decision_inbox_digest_source: str
    decision_inbox_digest_target: str
    twin_id: str
    tx_id: str
    expected_intent: str
    expected_command_id: str
    expected_command_index: int
    expected_command_payload: str
    enqueue_events: tuple[CommandBinding, ...]
    source: ReplicaState
    target: ReplicaState

    @classmethod
    def initial(
        cls,
        *,
        source: str,
        target: str,
        initial_value: str,
        intent_value: str,
        twin_id: str,
        tx_id: str,
        command_id: str,
        command_index: int,
        command_payload: str,
    ) -> "BoundedState":
        return cls(
            source_id=source,
            target_id=target,
            owner=source,
            epoch=0,
            transfer_stage="none",
            terminal_outcome="none",
            terminal_delivered_source=False,
            terminal_delivered_target=False,
            certified_root_equal=True,
            yes_emitted=False,
            prepare_epoch=None,
            decision="none",
            decision_deliveries_source=0,
            decision_deliveries_target=0,
            decision_inbox_source=0,
            decision_inbox_target=0,
            decision_inbox_digest_source="none",
            decision_inbox_digest_target="none",
            twin_id=twin_id,
            tx_id=tx_id,
            expected_intent=intent_value,
            expected_command_id=command_id,
            expected_command_index=command_index,
            expected_command_payload=command_payload,
            enqueue_events=(),
            source=ReplicaState(
                mode="active",
                pending_transfer_id="none",
                has_obligation=False,
                intent_value="",
                command_id="",
                command_payload="",
                tombstone="none",
                tombstone_record_digest="none",
                value=initial_value,
                version=0,
                authorization=("controller", ("write",), 0, "credential"),
                frontier=(("sensor-0", 7, "event-7"),),
                locks=(),
                outbox=(),
            ),
            target=ReplicaState(
                mode="absent",
                pending_transfer_id="none",
                has_obligation=False,
                intent_value="",
                command_id="",
                command_payload="",
                tombstone="none",
                tombstone_record_digest="none",
                value=initial_value,
                version=0,
                authorization=("controller", ("write",), 0, "credential"),
                frontier=(("sensor-0", 7, "event-7"),),
                locks=(),
                outbox=(),
            ),
        )


def invariant_violations(state: BoundedState) -> tuple[Invariant, ...]:
    violations: list[Invariant] = []
    active_replicas = [
        (state.source_id, state.source),
        (state.target_id, state.target),
    ]
    active_replicas = [item for item in active_replicas if item[1].mode == "active"]
    if len(active_replicas) > 1:
        violations.append(Invariant.OWNERSHIP_UNIQUENESS)
    if len(active_replicas) == 1 and active_replicas[0][0] != state.owner:
        violations.append(Invariant.OWNERSHIP_UNIQUENESS)

    for replica in (state.source, state.target):
        if replica.mode == "absent":
            continue
        pending_mode = replica.mode in {"frozen", "staging"}
        if pending_mode != (replica.pending_transfer_id != "none") or (
            pending_mode and replica.pending_transfer_id != "current"
        ):
            violations.append(Invariant.TRANSFER_LINEAGE)
            break

    current = state.source if state.owner == state.source_id else state.target
    current_resolved = current.tombstone != "none"
    if state.yes_emitted and not current_resolved:
        if not current.has_obligation:
            violations.append(Invariant.OBLIGATION_PERSISTENCE)

    for replica in (state.source, state.target):
        if replica.tombstone != "none" and (
            replica.tombstone != state.decision
            or replica.tombstone_record_digest != "tds"
        ):
            violations.append(Invariant.DECISION_CONSISTENCY)
            break
    for inbox, digest in (
        (state.decision_inbox_source, state.decision_inbox_digest_source),
        (state.decision_inbox_target, state.decision_inbox_digest_target),
    ):
        if (inbox == 0) != (digest == "none") or (inbox > 0 and digest != "tds"):
            violations.append(Invariant.DECISION_CONSISTENCY)
            break

    authoritative_replicas = [state.source]
    if state.target.mode != "absent":
        authoritative_replicas.append(state.target)
    if any(
        replica.has_obligation
        and (
            replica.intent_value != state.expected_intent
            or replica.command_id != state.expected_command_id
            or replica.command_payload != state.expected_command_payload
        )
        for replica in authoritative_replicas
    ):
        violations.append(Invariant.INTENT_FIDELITY)
    if any(
        replica.tombstone == "commit" and replica.value != state.expected_intent
        for replica in authoritative_replicas
    ):
        violations.append(Invariant.INTENT_FIDELITY)

    expected_binding = CommandBinding(
        command_id=state.expected_command_id,
        twin_id=state.twin_id,
        operation_id=state.tx_id,
        command_index=state.expected_command_index,
        payload=state.expected_command_payload,
    )
    committed = False
    for replica in authoritative_replicas:
        reserved_bindings = tuple(
            binding
            for binding in replica.outbox
            if binding.command_id == state.expected_command_id
        )
        reservation_consumed_early = replica.has_obligation and bool(reserved_bindings)
        duplicate_or_conflicting = len(reserved_bindings) > 1 or any(
            binding != expected_binding for binding in reserved_bindings
        )
        missing_commit_binding = (
            replica.tombstone == "commit" and reserved_bindings != (expected_binding,)
        )
        abort_has_binding = replica.tombstone == "abort" and bool(reserved_bindings)
        committed = committed or replica.tombstone == "commit"
        if (
            reservation_consumed_early
            or duplicate_or_conflicting
            or missing_commit_binding
            or abort_has_binding
        ):
            violations.append(Invariant.DURABLE_ENQUEUE_INTEGRITY)
            break
    expected_events = tuple(
        binding
        for binding in state.enqueue_events
        if binding.command_id == state.expected_command_id
    )
    event_binding_invalid = any(
        binding != expected_binding for binding in expected_events
    )
    event_count_invalid = len(expected_events) != (1 if committed else 0)
    if event_binding_invalid or event_count_invalid:
        violations.append(Invariant.DURABLE_ENQUEUE_INTEGRITY)

    expected_authorization = ("controller", ("write",), 0, "credential")
    expected_frontier = (("sensor-0", 7, "event-7"),)
    for replica in authoritative_replicas:
        expected_version = 1 if replica.tombstone == "commit" else 0
        expected_locks = ("value",) if replica.has_obligation else ()
        if (
            replica.authorization != expected_authorization
            or replica.frontier != expected_frontier
            or replica.version != expected_version
            or replica.locks != expected_locks
        ):
            violations.append(Invariant.CAPSULE_COMPONENT_INTEGRITY)
            break
    if not state.certified_root_equal:
        violations.append(Invariant.CAPSULE_COMPONENT_INTEGRITY)
    return tuple(dict.fromkeys(violations))


def successors(
    state: BoundedState,
    *,
    decision_outcomes: tuple[str, ...],
    allow_resume: bool,
    allow_duplicate_delivery: bool,
    mutant: Mutant | None,
) -> tuple[tuple[str, BoundedState], ...]:
    candidates: list[tuple[str, BoundedState]] = []

    if (
        not state.yes_emitted
        and state.source.mode == "active"
        and state.transfer_stage == "none"
    ):
        prepared_source = replace(
            state.source,
            has_obligation=True,
            intent_value=state.expected_intent,
            command_id=state.expected_command_id,
            command_payload=state.expected_command_payload,
            locks=("value",),
        )
        candidates.append(
            (
                "prepare_yes",
                replace(
                    state,
                    yes_emitted=True,
                    prepare_epoch=state.epoch,
                    source=prepared_source,
                ),
            )
        )

    if state.yes_emitted and state.decision == "none":
        for outcome in decision_outcomes:
            candidates.append((f"decide_{outcome}", replace(state, decision=outcome)))

    if state.decision != "none":
        delivery_limit = 2 if allow_duplicate_delivery else 1
        delivered = state.decision_deliveries_source + state.decision_deliveries_target
        if delivered < delivery_limit:
            candidates.append(
                (
                    "deliver_decision_source",
                    replace(
                        state,
                        decision_deliveries_source=(
                            state.decision_deliveries_source + 1
                        ),
                        decision_inbox_source=state.decision_inbox_source + 1,
                        decision_inbox_digest_source="tds",
                    ),
                )
            )
            if state.target.mode != "absent":
                candidates.append(
                    (
                        "deliver_decision_target",
                        replace(
                            state,
                            decision_deliveries_target=(
                                state.decision_deliveries_target + 1
                            ),
                            decision_inbox_target=state.decision_inbox_target + 1,
                            decision_inbox_digest_target="tds",
                        ),
                    )
                )

    if state.source.mode == "active" and state.transfer_stage == "none":
        candidates.append(
            (
                "freeze",
                replace(
                    state,
                    source=replace(
                        state.source,
                        mode="frozen",
                        pending_transfer_id="current",
                    ),
                    transfer_stage="frozen",
                ),
            )
        )

    if state.transfer_stage == "frozen" and state.terminal_outcome == "none":
        staged = replace(state.source, mode="staging")
        if mutant is Mutant.OMIT_OBLIGATION_ON_INSTALL:
            staged = replace(
                staged,
                has_obligation=False,
                intent_value="",
                command_id="",
                command_payload="",
                locks=(),
            )
        if mutant is Mutant.REWRITE_INTENT_ON_INSTALL and staged.has_obligation:
            staged = replace(
                staged,
                intent_value=f"{staged.intent_value}:mutated",
                command_payload=f"{staged.command_payload}:mutated",
            )
        candidates.append(
            (
                "install",
                replace(
                    state,
                    target=staged,
                    transfer_stage="installed",
                    certified_root_equal=True,
                ),
            )
        )

    if state.transfer_stage == "installed" and state.terminal_outcome == "none":
        source = state.source
        if mutant is Mutant.DUAL_ACTIVE_ON_ACTIVATE:
            source = replace(source, mode="active")
        candidates.append(
            (
                "os_commit_activate",
                replace(
                    state,
                    owner=state.target_id,
                    epoch=state.epoch + 1,
                    source=source,
                    transfer_stage="terminal",
                    terminal_outcome="activate",
                ),
            )
        )

    if (
        allow_resume
        and state.transfer_stage in {"frozen", "installed"}
        and state.terminal_outcome == "none"
    ):
        candidates.append(
            (
                "os_commit_resume",
                replace(
                    state,
                    owner=state.source_id,
                    transfer_stage="terminal",
                    terminal_outcome="resume",
                ),
            )
        )

    if state.terminal_outcome != "none":
        if not state.terminal_delivered_source:
            source_mode = "fenced" if state.terminal_outcome == "activate" else "active"
            candidates.append(
                (
                    f"deliver_{state.terminal_outcome}_source",
                    replace(
                        state,
                        source=replace(
                            state.source,
                            mode=source_mode,
                            pending_transfer_id="none",
                        ),
                        terminal_delivered_source=True,
                    ),
                )
            )
        if not state.terminal_delivered_target:
            target_mode = (
                "active"
                if state.terminal_outcome == "activate"
                else ("discarded" if state.target.mode != "absent" else "absent")
            )
            candidates.append(
                (
                    f"deliver_{state.terminal_outcome}_target",
                    replace(
                        state,
                        target=replace(
                            state.target,
                            mode=target_mode,
                            pending_transfer_id="none",
                        ),
                        terminal_delivered_target=True,
                    ),
                )
            )

    for endpoint in ("source", "target"):
        current = state.source if endpoint == "source" else state.target
        inbox = (
            state.decision_inbox_source
            if endpoint == "source"
            else state.decision_inbox_target
        )
        inbox_digest = (
            state.decision_inbox_digest_source
            if endpoint == "source"
            else state.decision_inbox_digest_target
        )
        if (
            inbox == 0
            or inbox_digest != "tds"
            or current.mode != "active"
            or state.owner
            != (state.source_id if endpoint == "source" else state.target_id)
        ):
            continue
        processed = current
        enqueue_events = state.enqueue_events
        action = f"process_decision_{endpoint}"
        if current.tombstone == "none" and current.has_obligation:
            resolved_decision = state.decision
            epoch_guard_fired = (
                mutant is Mutant.EPOCH_GUARD_CONVERTS_COMMIT_TO_ABORT
                and state.decision == "commit"
                and state.prepare_epoch is not None
                and state.prepare_epoch != state.epoch
            )
            if epoch_guard_fired:
                resolved_decision = "abort"
                action = "epoch_guard_converts_commit_to_abort"
            processed = replace(
                current,
                has_obligation=False,
                tombstone=resolved_decision,
                tombstone_record_digest="tds",
                locks=(),
            )
            if resolved_decision == "commit":
                binding = CommandBinding(
                    command_id=processed.command_id,
                    twin_id=state.twin_id,
                    operation_id=state.tx_id,
                    command_index=state.expected_command_index,
                    payload=processed.command_payload,
                )
                processed = replace(
                    processed,
                    value=processed.intent_value,
                    version=processed.version + 1,
                    outbox=(*processed.outbox, binding),
                )
                enqueue_events = (*enqueue_events, binding)
        elif current.tombstone == state.decision:
            action = f"reprocess_decision_{endpoint}"
            if mutant is Mutant.DUPLICATE_OUTBOX_ENQUEUE and state.decision == "commit":
                binding = CommandBinding(
                    command_id=current.command_id,
                    twin_id=state.twin_id,
                    operation_id=state.tx_id,
                    command_index=state.expected_command_index,
                    payload=current.command_payload,
                )
                processed = replace(
                    current,
                    outbox=(*current.outbox, binding),
                )
                enqueue_events = (*enqueue_events, binding)
        else:
            continue
        changes: dict[str, object] = {
            endpoint: processed,
            "enqueue_events": enqueue_events,
            f"decision_inbox_{endpoint}": inbox - 1,
            f"decision_inbox_digest_{endpoint}": (
                "none" if inbox == 1 else inbox_digest
            ),
        }
        candidates.append((action, replace(state, **changes)))

    return tuple(candidates)


def apply_action(
    state: BoundedState,
    action: str,
    *,
    decision_outcomes: tuple[str, ...] = ("commit", "abort"),
    allow_resume: bool = True,
    allow_duplicate_delivery: bool = True,
) -> BoundedState:
    """Apply one named compliant transition for implementation conformance."""
    matches = tuple(
        candidate
        for candidate_action, candidate in successors(
            state,
            decision_outcomes=decision_outcomes,
            allow_resume=allow_resume,
            allow_duplicate_delivery=allow_duplicate_delivery,
            mutant=None,
        )
        if candidate_action == action
    )
    if len(matches) != 1:
        raise ValueError(
            f"expected one enabled {action!r} transition, found {len(matches)}"
        )
    return matches[0]


def checkpoint_projection(state: BoundedState) -> dict[str, object]:
    """Map checker state to the implementation checkpoint contract."""

    def replica_fields(replica: ReplicaState) -> dict[str, object]:
        if replica.mode == "absent":
            return {"mode": "absent", "pending_transfer_id": "none"}
        return {
            "mode": replica.mode,
            "pending_transfer_id": replica.pending_transfer_id,
            "has_obligation": replica.has_obligation,
            "intent_value": replica.intent_value if replica.has_obligation else "",
            "command_id": replica.command_id if replica.has_obligation else "",
            "command_payload": replica.command_payload
            if replica.has_obligation
            else "",
            "tombstone": replica.tombstone,
            "tombstone_record_digest": replica.tombstone_record_digest,
            "value": replica.value,
            "version": replica.version,
            "authorization": replica.authorization,
            "frontier": replica.frontier,
            "locks": replica.locks,
            "outbox": tuple(
                (
                    binding.command_id,
                    binding.twin_id,
                    binding.operation_id,
                    binding.command_index,
                    binding.payload,
                )
                for binding in replica.outbox
            ),
        }

    event_counts = Counter(state.enqueue_events)
    return {
        "owner": state.owner,
        "epoch": state.epoch,
        "transfer_stage": state.transfer_stage,
        "terminal_outcome": state.terminal_outcome,
        "terminal_delivered_source": state.terminal_delivered_source,
        "terminal_delivered_target": state.terminal_delivered_target,
        "certified_root_equal": state.certified_root_equal,
        "yes_emitted": state.yes_emitted,
        "prepare_epoch": state.prepare_epoch,
        "decision": state.decision,
        "decision_deliveries_source": state.decision_deliveries_source,
        "decision_deliveries_target": state.decision_deliveries_target,
        "decision_inbox_source": state.decision_inbox_source,
        "decision_inbox_target": state.decision_inbox_target,
        "decision_inbox_digest_source": state.decision_inbox_digest_source,
        "decision_inbox_digest_target": state.decision_inbox_digest_target,
        "source": replica_fields(state.source),
        "target": replica_fields(state.target),
        "enqueue_bindings": tuple(
            (
                binding.command_id,
                binding.twin_id,
                binding.operation_id,
                binding.command_index,
                binding.payload,
                count,
            )
            for binding, count in sorted(event_counts.items())
        ),
    }


TRUE_OVERLAP_ACTIONS = (
    "prepare_yes",
    "freeze",
    "install",
    "os_commit_activate",
    "deliver_activate_target",
    "decide_commit",
    "deliver_decision_target",
    "process_decision_target",
)


def _advance_overlap_monitor(progress: int, action: str) -> int:
    if (
        progress < len(TRUE_OVERLAP_ACTIONS)
        and action == TRUE_OVERLAP_ACTIONS[progress]
    ):
        return progress + 1
    return progress


def explore(
    *,
    source: str,
    target: str,
    initial_value: str,
    intent_value: str,
    twin_id: str,
    tx_id: str,
    command_id: str,
    command_index: int,
    command_payload: str,
    max_depth: int,
    max_states: int,
    decision_outcomes: Iterable[str],
    allow_resume: bool,
    allow_duplicate_delivery: bool,
    mutant: Mutant | None = None,
) -> dict[str, object]:
    outcomes = tuple(decision_outcomes)
    if not outcomes or not set(outcomes).issubset({"commit", "abort"}):
        raise ValueError("decision outcomes must contain commit and/or abort")
    initial = BoundedState.initial(
        source=source,
        target=target,
        initial_value=initial_value,
        intent_value=intent_value,
        twin_id=twin_id,
        tx_id=tx_id,
        command_id=command_id,
        command_index=command_index,
        command_payload=command_payload,
    )
    frontier = deque([(initial, 0, tuple(), 0)])
    seen = {(initial, 0)}
    protocol_states = {initial}
    explored = 0
    transitions = 0
    depth_cut_states = 0
    first_witness: dict[str, object] | None = None
    true_overlap: dict[str, object] | None = None
    max_states_reached = False

    while frontier:
        state, depth, path, overlap_progress = frontier.popleft()
        explored += 1
        if depth >= max_depth:
            depth_cut_states += 1
            continue
        for action, candidate in successors(
            state,
            decision_outcomes=outcomes,
            allow_resume=allow_resume,
            allow_duplicate_delivery=allow_duplicate_delivery,
            mutant=mutant,
        ):
            transitions += 1
            candidate_path = (*path, action)
            candidate_progress = _advance_overlap_monitor(overlap_progress, action)
            violations = invariant_violations(candidate)
            if violations:
                if first_witness is None:
                    witness_state = canonical_data(candidate)
                    first_witness = {
                        "depth": depth + 1,
                        "actions": candidate_path,
                        "violated_invariants": tuple(item.value for item in violations),
                        "state": witness_state,
                        "state_sha256": stable_hash(
                            "carry2pc.witness-state.v1", witness_state
                        ),
                    }
                continue
            if true_overlap is None and candidate_progress == len(TRUE_OVERLAP_ACTIONS):
                overlap_state = canonical_data(candidate)
                true_overlap = {
                    "depth": depth + 1,
                    "actions": candidate_path,
                    "state": overlap_state,
                    "state_sha256": stable_hash(
                        "carry2pc.witness-state.v1", overlap_state
                    ),
                }
            product_state = (candidate, candidate_progress)
            if product_state not in seen:
                if len(seen) >= max_states:
                    max_states_reached = True
                    frontier.clear()
                    break
                seen.add(product_state)
                protocol_states.add(candidate)
                frontier.append(
                    (candidate, depth + 1, candidate_path, candidate_progress)
                )
        if max_states_reached:
            break

    return {
        "variant": "compliant" if mutant is None else mutant.value,
        "bounded_complete": not max_states_reached and depth_cut_states == 0,
        "max_states_reached": max_states_reached,
        "depth_bound": max_depth,
        "state_bound": max_states,
        "states_discovered": len(seen),
        "protocol_states_discovered": len(protocol_states),
        "states_explored": explored,
        "transitions_considered": transitions,
        "states_at_depth_cut": depth_cut_states,
        "violation_witness": first_witness,
        "true_overlap_witness": true_overlap,
    }
