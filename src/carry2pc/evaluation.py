"""Deterministic evaluation matrix for the finite Carry2PC model."""

from __future__ import annotations

from collections import deque
from copy import deepcopy
from dataclasses import replace
import hashlib
from itertools import permutations
import json
from pathlib import Path
from typing import Any

from carry2pc.canonical import canonical_data, stable_hash
from carry2pc.certificates import QuorumGroup, QuorumProof, QuorumRegistry
from carry2pc.config import VerificationConfig
from carry2pc.modelcheck import (
    BoundedState,
    Mutant,
    apply_action,
    checkpoint_projection,
    explore,
    successors,
)
from carry2pc.protocol import Carry2PC, ProtocolError
from carry2pc.schemas import (
    AuthorizationContext,
    CommandIntent,
    InputFrontier,
    StateEntry,
    UpdateCommand,
    WriteIntent,
    capsule_from_bytes,
    capsule_to_bytes,
    stable_command_id,
    stable_update_command_id,
)
from carry2pc.types import Decision
from carry2pc.verification import EXPECTED_MUTANT_INVARIANT


ARTIFACT_STATUS = "deterministic_exhaustive_evaluation"
REPRODUCTION_COMMAND = (
    "python3 -m carry2pc evaluate-matrix --config <CONFIG> --output <OUTPUT>"
)
DECISION_PROFILES = (
    ("commit_only", ("commit",)),
    ("abort_only", ("abort",)),
    ("commit_and_abort", ("commit", "abort")),
)


def _quorum_group(group_id: str) -> QuorumGroup:
    members = tuple(f"{group_id}:replica-{index}" for index in range(4))
    return QuorumGroup(group_id, 0, members, 1, members[:3])


def _reference_protocol(case: str) -> tuple[Carry2PC, str, str, str]:
    source, target, twin_id = f"source-{case}", f"target-{case}", f"twin-{case}"
    registry = QuorumRegistry(
        _quorum_group(group_id)
        for group_id in (
            "ownership",
            "decision",
            f"shard:{source}",
            f"shard:{target}",
        )
    )
    protocol = Carry2PC(quorum_registry=registry)
    protocol.initialize_twin(
        twin_id=twin_id,
        owner=source,
        state=(StateEntry("value", "0"),),
        authorization=AuthorizationContext("controller", ("write",), 0, "credential"),
        input_frontier=(InputFrontier("sensor-0", 7, "event-7"),),
    )
    return protocol, source, target, twin_id


def _implementation_checkpoint(
    protocol: Carry2PC,
    *,
    source: str,
    target: str,
    twin_id: str,
    tx_id: str,
) -> dict[str, object]:
    owner = protocol.owners[twin_id]
    source_copy = protocol.copies[(source, twin_id)]
    target_copy = protocol.copies.get((target, twin_id))
    handover = next(iter(protocol.handovers.values()), None)
    if handover is None:
        transfer_stage = "none"
        terminal_outcome = "none"
        terminal_delivered_source = False
        terminal_delivered_target = False
        certified_root_equal = True
    elif handover.terminal:
        transfer_stage = "terminal"
        terminal_outcome = "activate" if handover.activate is not None else "resume"
        terminal_delivered_source = source in handover.terminal_deliveries
        terminal_delivered_target = target in handover.terminal_deliveries
        certified_root_equal = (
            handover.install is None
            or handover.install.capsule_root == handover.freeze.capsule_root
        )
    elif handover.install is not None:
        transfer_stage = "installed"
        terminal_outcome = "none"
        terminal_delivered_source = False
        terminal_delivered_target = False
        certified_root_equal = (
            handover.install.capsule_root == handover.freeze.capsule_root
        )
    else:
        transfer_stage = "frozen"
        terminal_outcome = "none"
        terminal_delivered_source = False
        terminal_delivered_target = False
        certified_root_equal = True
    decision = protocol.decisions.get(tx_id)

    def replica_fields(copy: object | None) -> dict[str, object]:
        if copy is None:
            return {"mode": "absent", "pending_transfer_id": "none"}
        obligation = copy.capsule.obligation(tx_id)
        tombstone = copy.capsule.tombstone(tx_id)
        write_value = ""
        command_id = ""
        command_payload = ""
        if obligation is not None:
            write_value = next(
                (
                    write.value_json
                    for write in obligation.record.writes
                    if write.key == "value"
                ),
                "",
            )
            if obligation.record.commands:
                command_id = obligation.record.commands[0].command_id
                command_payload = obligation.record.commands[0].payload_json
        value = next(
            entry.value_json for entry in copy.capsule.state if entry.key == "value"
        )
        pending_transfer_id = "none"
        if copy.pending_transfer_id is not None:
            pending_transfer_id = (
                "current"
                if handover is not None
                and copy.pending_transfer_id == handover.transfer_id
                else "other"
            )
        tombstone_record_digest = "none"
        if tombstone is not None:
            tombstone_record_digest = (
                "tds"
                if decision is not None
                and tombstone.decision_record_digest == decision.record_digest
                else "other"
            )
        return {
            "mode": copy.mode.value,
            "pending_transfer_id": pending_transfer_id,
            "has_obligation": obligation is not None,
            "intent_value": write_value,
            "command_id": command_id,
            "command_payload": command_payload,
            "tombstone": "none" if tombstone is None else tombstone.decision.value,
            "tombstone_record_digest": tombstone_record_digest,
            "value": value,
            "version": copy.capsule.version,
            "authorization": (
                copy.capsule.authorization.subject,
                copy.capsule.authorization.scopes,
                copy.capsule.authorization.revocation_version,
                copy.capsule.authorization.credential_digest,
            ),
            "frontier": tuple(
                (
                    entry.producer,
                    entry.last_sequence,
                    entry.last_event_hash,
                )
                for entry in copy.capsule.input_frontier
            ),
            "locks": tuple(
                sorted(
                    lock for item in copy.capsule.prepared for lock in item.record.locks
                )
            ),
            "outbox": tuple(
                sorted(
                    (
                        entry.command_id,
                        copy.twin_id,
                        entry.operation_id,
                        entry.command_index,
                        entry.payload_json,
                    )
                    for entry in copy.capsule.outbox
                )
            ),
        }

    def inbox_fields(shard_id: str) -> tuple[int, str]:
        entries = tuple(
            (digest, count)
            for (shard, candidate_twin, candidate_tx, digest), count in (
                protocol.decision_inbox.items()
            )
            if (shard, candidate_twin, candidate_tx) == (shard_id, twin_id, tx_id)
        )
        count = sum(item_count for _, item_count in entries)
        if count == 0:
            return 0, "none"
        if decision is not None and all(
            digest == decision.record_digest for digest, _ in entries
        ):
            return count, "tds"
        return count, "other"

    def delivery_count(shard_id: str) -> int:
        if decision is None:
            return 0
        return protocol.decision_delivery_counts.get(
            (shard_id, twin_id, tx_id, decision.record_digest), 0
        )

    yes = protocol.yes_history.get((tx_id, twin_id))
    source_inbox, source_inbox_digest = inbox_fields(source)
    target_inbox, target_inbox_digest = inbox_fields(target)
    return {
        "owner": owner.owner,
        "epoch": owner.epoch,
        "transfer_stage": transfer_stage,
        "terminal_outcome": terminal_outcome,
        "terminal_delivered_source": terminal_delivered_source,
        "terminal_delivered_target": terminal_delivered_target,
        "certified_root_equal": certified_root_equal,
        "yes_emitted": yes is not None,
        "prepare_epoch": None if yes is None else yes.prepare_epoch,
        "decision": "none" if decision is None else decision.decision.value,
        "decision_deliveries_source": delivery_count(source),
        "decision_deliveries_target": delivery_count(target),
        "decision_inbox_source": source_inbox,
        "decision_inbox_target": target_inbox,
        "decision_inbox_digest_source": source_inbox_digest,
        "decision_inbox_digest_target": target_inbox_digest,
        "source": replica_fields(source_copy),
        "target": replica_fields(target_copy),
        "enqueue_bindings": tuple(
            (
                command_id,
                *protocol.outbox_enqueue_bindings[command_id],
                count,
            )
            for command_id, count in sorted(protocol.outbox_enqueue_counts.items())
        ),
    }


def _checkpoint_check(
    protocol: Carry2PC,
    checker: BoundedState,
    *,
    source: str,
    target: str,
    twin_id: str,
    tx_id: str,
) -> tuple[bool, str]:
    implementation = _implementation_checkpoint(
        protocol,
        source=source,
        target=target,
        twin_id=twin_id,
        tx_id=tx_id,
    )
    expected = checkpoint_projection(checker)
    return implementation == expected, stable_hash(
        "carry2pc.conformance-checkpoint.v1", expected
    )


def _execute_implementation_action(
    protocol: Carry2PC,
    action: str,
    *,
    source: str,
    target: str,
    twin_id: str,
    tx_id: str,
    command_id: str,
    command_payload: str,
) -> None:
    if action == "prepare_yes":
        protocol.prepare(
            tx_id=tx_id,
            twin_id=twin_id,
            participant_set=(twin_id,),
            reads=(),
            writes=(WriteIntent("value", "1"),),
            locks=("value",),
            commands=(CommandIntent(command_id, command_payload),),
        )
        return
    if action == "freeze":
        protocol.freeze(twin_id=twin_id, target=target)
        return
    handover = next(iter(protocol.handovers.values()), None)
    if action == "install":
        if handover is None:
            raise AssertionError("checker enabled install without a handover")
        protocol.install(handover.freeze)
        return
    if action == "os_commit_activate":
        if handover is None or handover.install is None:
            raise AssertionError("checker enabled activation without InstallQC")
        protocol.commit_activate(handover.install)
        return
    if action.startswith("deliver_activate_"):
        if handover is None or handover.activate is None:
            raise AssertionError("checker enabled ActivateQC delivery before OS commit")
        endpoint = source if action.endswith("source") else target
        protocol.deliver_activate(handover.activate, shard_id=endpoint)
        return
    if action == "os_commit_resume":
        if handover is None:
            raise AssertionError("checker enabled resumption without FreezeQC")
        protocol.commit_resume(handover.freeze)
        return
    if action.startswith("deliver_resume_"):
        if handover is None or handover.resume is None:
            raise AssertionError("checker enabled ResumeQC delivery before OS commit")
        endpoint = source if action.endswith("source") else target
        protocol.deliver_resume(handover.resume, shard_id=endpoint)
        return
    if action in {"decide_commit", "decide_abort"}:
        yes = protocol.yes_history[(tx_id, twin_id)]
        protocol.decide(
            tx_id=tx_id,
            decision=(Decision.COMMIT if action.endswith("commit") else Decision.ABORT),
            participant_set=(twin_id,),
            yes_certificates=(yes,),
        )
        return
    if action.startswith("deliver_decision_"):
        endpoint = source if action.endswith("source") else target
        protocol.deliver_decision(
            shard_id=endpoint,
            twin_id=twin_id,
            decision_certificate=protocol.decisions[tx_id],
        )
        return
    if action.startswith(("process_decision_", "reprocess_decision_")):
        endpoint = source if action.endswith("source") else target
        protocol.process_decision(
            shard_id=endpoint,
            twin_id=twin_id,
            decision_certificate=protocol.decisions[tx_id],
        )
        return
    raise AssertionError(f"no implementation action mapping for {action!r}")


def _implementation_trace(case: str, *, outcome: str) -> dict[str, object]:
    protocol, source, target, twin_id = _reference_protocol(case)
    tx_id = f"tx-{case}"
    command_id = stable_command_id(twin_id, tx_id, 0)
    command_payload = '{"command":"apply"}'
    checker = BoundedState.initial(
        source=source,
        target=target,
        initial_value="0",
        intent_value="1",
        twin_id=twin_id,
        tx_id=tx_id,
        command_id=command_id,
        command_index=0,
        command_payload=command_payload,
    )
    matches: list[bool] = []
    checkpoints: list[dict[str, object]] = []
    checkpoint_digest = ""

    def compare(action: str) -> None:
        nonlocal checkpoint_digest
        matched, checkpoint_digest = _checkpoint_check(
            protocol,
            checker,
            source=source,
            target=target,
            twin_id=twin_id,
            tx_id=tx_id,
        )
        matches.append(matched)
        checkpoints.append(
            {
                "action": action,
                "matched": matched,
                "state_sha256": checkpoint_digest,
            }
        )

    def advance(action: str) -> None:
        nonlocal checker
        checker = apply_action(checker, action)
        compare(action)

    compare("initial")

    def execute(action: str) -> None:
        _execute_implementation_action(
            protocol,
            action,
            source=source,
            target=target,
            twin_id=twin_id,
            tx_id=tx_id,
            command_id=command_id,
            command_payload=command_payload,
        )
        advance(action)

    execute("prepare_yes")
    execute("freeze")
    if outcome == "activate":
        execute("install")
        execute("os_commit_activate")
        execute("deliver_activate_target")
        execute("deliver_activate_source")
        decision_outcome = Decision.COMMIT
    else:
        if outcome == "installed_resume":
            execute("install")
        execute("os_commit_resume")
        execute("deliver_resume_target")
        execute("deliver_resume_source")
        decision_outcome = Decision.ABORT
    execute(f"decide_{decision_outcome.value}")
    endpoint = "target" if outcome == "activate" else "source"
    execute(f"deliver_decision_{endpoint}")
    execute(f"process_decision_{endpoint}")
    if outcome == "activate":
        execute("deliver_decision_target")
        execute("reprocess_decision_target")
    protocol.assert_authoritative_invariants(twin_id)
    return {
        "case": case,
        "passed": all(matches),
        "matched_checkpoints": sum(matches),
        "checkpoints": len(matches),
        "checkpoint_results": checkpoints,
        "final_checkpoint_sha256": checkpoint_digest,
    }


def _implementation_conformance() -> dict[str, object]:
    checks = (
        _implementation_trace("activate_commit_redelivery", outcome="activate"),
        _implementation_trace("direct_resume_abort", outcome="direct_resume"),
        _implementation_trace("installed_resume_abort", outcome="installed_resume"),
    )
    return {
        "cases": len(checks),
        "passed": sum(bool(check["passed"]) for check in checks),
        "checks": checks,
    }


def _reachable_transition_conformance() -> dict[str, object]:
    case = "reachable_transition_projection"
    protocol, source, target, twin_id = _reference_protocol(case)
    tx_id = f"tx-{case}"
    command_id = stable_command_id(twin_id, tx_id, 0)
    command_payload = '{"command":"apply"}'
    initial = BoundedState.initial(
        source=source,
        target=target,
        initial_value="0",
        intent_value="1",
        twin_id=twin_id,
        tx_id=tx_id,
        command_id=command_id,
        command_index=0,
        command_payload=command_payload,
    )
    initial_implementation_digest = stable_hash(
        "carry2pc.implementation-state.v1", _protocol_state_snapshot(protocol)
    )
    queue = deque([(initial, protocol)])
    seen = {(initial, initial_implementation_digest)}
    checker_states = {initial}
    checked_transitions = 0
    mismatches: list[dict[str, str]] = []
    while queue:
        checker, implementation = queue.popleft()
        for action, candidate in successors(
            checker,
            decision_outcomes=("commit", "abort"),
            allow_resume=True,
            allow_duplicate_delivery=True,
            mutant=None,
        ):
            candidate_implementation = deepcopy(implementation)
            _execute_implementation_action(
                candidate_implementation,
                action,
                source=source,
                target=target,
                twin_id=twin_id,
                tx_id=tx_id,
                command_id=command_id,
                command_payload=command_payload,
            )
            candidate_implementation.assert_authoritative_invariants(twin_id)
            matched, state_digest = _checkpoint_check(
                candidate_implementation,
                candidate,
                source=source,
                target=target,
                twin_id=twin_id,
                tx_id=tx_id,
            )
            checked_transitions += 1
            if not matched:
                mismatches.append(
                    {"action": action, "expected_state_sha256": state_digest}
                )
            candidate_key = (
                candidate,
                stable_hash(
                    "carry2pc.implementation-state.v1",
                    _protocol_state_snapshot(candidate_implementation),
                ),
            )
            if candidate_key not in seen:
                seen.add(candidate_key)
                checker_states.add(candidate)
                queue.append((candidate, candidate_implementation))
    return {
        "case": case,
        "passed": not mismatches,
        "reachable_states": len(checker_states),
        "reachable_product_states": len(seen),
        "checked_transitions": checked_transitions,
        "mismatches": mismatches,
    }


def _command_namespace_contract() -> dict[str, object]:
    case = "command_namespace_contract"
    protocol, _source, _target, twin_id = _reference_protocol(case)
    tx_id = "transaction-namespace-contract"
    update_id = "update-namespace-contract"
    payload = '{"command":"apply"}'
    tx_command_id = stable_command_id(twin_id, tx_id, 0)
    update_command_id = stable_update_command_id(twin_id, update_id, 0)
    yes = protocol.prepare(
        tx_id=tx_id,
        twin_id=twin_id,
        participant_set=(twin_id,),
        reads=(),
        writes=(WriteIntent("value", "1"),),
        locks=("value",),
        commands=(CommandIntent(tx_command_id, payload),),
    )
    protocol.update(
        update_id=update_id,
        twin_id=twin_id,
        writes=(WriteIntent("aux", "1"),),
        locks=("aux",),
        commands=(UpdateCommand(update_command_id, payload),),
    )
    decision = protocol.decide(
        tx_id=tx_id,
        decision=Decision.COMMIT,
        participant_set=(twin_id,),
        yes_certificates=(yes,),
    )
    protocol.resolve(twin_id=twin_id, decision_certificate=decision)
    protocol.resolve(twin_id=twin_id, decision_certificate=decision)
    protocol.assert_authoritative_invariants(twin_id)
    entries = {
        entry.command_id: (
            twin_id,
            entry.operation_id,
            entry.command_index,
            entry.payload_json,
        )
        for entry in protocol.active_twin(twin_id).capsule.outbox
    }
    expected = {
        tx_command_id: (twin_id, tx_id, 0, payload),
        update_command_id: (twin_id, update_id, 0, payload),
    }
    passed = (
        tx_command_id.startswith("tx:")
        and update_command_id.startswith("update:")
        and tx_command_id != update_command_id
        and entries == expected
        and protocol.outbox_enqueue_bindings == expected
        and protocol.outbox_enqueue_counts == {tx_command_id: 1, update_command_id: 1}
    )
    return {
        "case": case,
        "passed": passed,
        "bindings": len(entries),
        "binding_sha256": stable_hash("carry2pc.command-bindings.v1", entries),
    }


def _capsule_wire_contract() -> dict[str, object]:
    case = "capsule_wire_contract"
    protocol, source, target, twin_id = _reference_protocol(case)
    tx_id = "transaction-wire-contract"
    protocol.prepare(
        tx_id=tx_id,
        twin_id=twin_id,
        participant_set=(twin_id,),
        reads=(),
        writes=(WriteIntent("value", "1"),),
        locks=("value",),
    )
    freeze = protocol.freeze(twin_id=twin_id, target=target)
    source_capsule = protocol.copies[(source, twin_id)].capsule
    wire = capsule_to_bytes(source_capsule)
    reconstructed = capsule_from_bytes(wire)

    rejected_malformed = False
    try:
        protocol.install(freeze, capsule_bytes=wire[:-1])
    except ProtocolError:
        rejected_malformed = True

    changed = wire.replace(b'"value_json":"0"', b'"value_json":"9"', 1)
    rejected_wrong_root = False
    try:
        protocol.install(freeze, capsule_bytes=changed)
    except ProtocolError:
        rejected_wrong_root = True

    install = protocol.install(freeze, capsule_bytes=wire)
    staged_capsule = protocol.copies[(target, twin_id)].capsule
    passed = (
        reconstructed == source_capsule
        and reconstructed is not source_capsule
        and rejected_malformed
        and rejected_wrong_root
        and install.capsule_root == freeze.capsule_root == staged_capsule.root
        and staged_capsule == source_capsule
        and staged_capsule is not source_capsule
    )
    return {
        "case": case,
        "passed": passed,
        "wire_bytes": len(wire),
        "fresh_reconstruction": staged_capsule is not source_capsule,
        "malformed_rejected": rejected_malformed,
        "wrong_root_rejected": rejected_wrong_root,
        "root_equal": install.capsule_root == freeze.capsule_root,
    }


def _service_group_binding_contract() -> dict[str, object]:
    case = "service_group_binding_contract"
    protocol, source, target, twin_id = _reference_protocol(case)
    tx_id = "transaction-group-binding"
    yes = protocol.prepare(
        tx_id=tx_id,
        twin_id=twin_id,
        participant_set=(twin_id,),
        reads=(),
        writes=(WriteIntent("value", "1"),),
        locks=("value",),
    )
    decision = protocol.decide(
        tx_id=tx_id,
        decision=Decision.COMMIT,
        participant_set=(twin_id,),
        yes_certificates=(yes,),
    )
    freeze = protocol.freeze(twin_id=twin_id, target=target)

    wrong_decision = replace(
        decision,
        proof=protocol.registry.attest("ownership", decision.subject_hash),
    )
    decision_rejected = False
    try:
        protocol.deliver_decision(
            shard_id=source,
            twin_id=twin_id,
            decision_certificate=wrong_decision,
        )
    except ProtocolError:
        decision_rejected = True

    wrong_freeze = replace(
        freeze,
        proof=protocol.registry.attest("decision", freeze.subject_hash),
    )
    freeze_rejected = False
    try:
        protocol.install(wrong_freeze)
    except ProtocolError:
        freeze_rejected = True

    passed = decision_rejected and freeze_rejected
    return {
        "case": case,
        "passed": passed,
        "cross_group_decision_rejected": decision_rejected,
        "cross_group_freeze_rejected": freeze_rejected,
    }


def _sequential_composition_contract() -> dict[str, object]:
    shards = ("composition-a", "composition-b", "composition-c")
    registry = QuorumRegistry(
        _quorum_group(group_id)
        for group_id in (
            "ownership",
            "decision",
            *(f"shard:{shard}" for shard in shards),
        )
    )
    protocol = Carry2PC(quorum_registry=registry)
    twin_id = "twin-sequential-composition"
    protocol.initialize_twin(
        twin_id=twin_id,
        owner=shards[0],
        state=(StateEntry("value", "0"),),
        authorization=AuthorizationContext("controller", ("write",), 0, "credential"),
        input_frontier=(InputFrontier("sensor-0", 7, "event-7"),),
    )
    payload = '{"command":"apply"}'
    update_id = "update-composition"
    update_command = stable_update_command_id(twin_id, update_id, 0)
    protocol.update(
        update_id=update_id,
        twin_id=twin_id,
        writes=(WriteIntent("aux", "1"),),
        locks=("aux",),
        commands=(UpdateCommand(update_command, payload),),
    )
    tx_ids = ("tx-composition-1", "tx-composition-2")
    yes_certificates = []
    for index, tx_id in enumerate(tx_ids, start=1):
        command_id = stable_command_id(twin_id, tx_id, 0)
        yes_certificates.append(
            protocol.prepare(
                tx_id=tx_id,
                twin_id=twin_id,
                participant_set=(twin_id,),
                reads=(),
                writes=(WriteIntent(f"value-{index}", str(index)),),
                locks=(f"value-{index}",),
                commands=(CommandIntent(command_id, payload),),
            )
        )
        if index == 1:
            first_freeze = protocol.freeze(twin_id=twin_id, target=shards[1])
            first_install = protocol.install(first_freeze)
            first_activate = protocol.commit_activate(first_install)
            protocol.deliver_activate(first_activate, shard_id=shards[1])
            protocol.deliver_activate(first_activate, shard_id=shards[0])

    second_freeze = protocol.freeze(twin_id=twin_id, target=shards[2])
    second_install = protocol.install(second_freeze)
    obligations_at_second_install = len(
        protocol.copies[(shards[2], twin_id)].capsule.prepared
    )
    second_activate = protocol.commit_activate(second_install)
    protocol.deliver_activate(second_activate, shard_id=shards[1])
    protocol.deliver_activate(second_activate, shard_id=shards[2])

    decisions = (
        protocol.decide(
            tx_id=tx_ids[0],
            decision=Decision.COMMIT,
            participant_set=(twin_id,),
            yes_certificates=(yes_certificates[0],),
        ),
        protocol.decide(
            tx_id=tx_ids[1],
            decision=Decision.ABORT,
            participant_set=(twin_id,),
            yes_certificates=(yes_certificates[1],),
        ),
    )
    for decision in decisions:
        protocol.resolve(twin_id=twin_id, decision_certificate=decision)
        protocol.resolve(twin_id=twin_id, decision_certificate=decision)
    protocol.assert_authoritative_invariants(twin_id)
    active = protocol.active_twin(twin_id)
    outbox_ids = {entry.command_id for entry in active.capsule.outbox}
    expected_outbox = {
        update_command,
        stable_command_id(twin_id, tx_ids[0], 0),
    }
    root_equalities = tuple(
        record.install is not None
        and record.install.capsule_root == record.freeze.capsule_root
        for record in protocol.handovers.values()
    )
    passed = (
        active.owner == shards[2]
        and active.epoch == 2
        and obligations_at_second_install == 2
        and len(active.capsule.prepared) == 0
        and len(active.capsule.decisions) == 2
        and active.capsule.version == 2
        and active.capsule.authorization
        == AuthorizationContext("controller", ("write",), 0, "credential")
        and active.capsule.input_frontier == (InputFrontier("sensor-0", 7, "event-7"),)
        and outbox_ids == expected_outbox
        and all(protocol.outbox_enqueue_counts[item] == 1 for item in expected_outbox)
        and root_equalities == (True, True)
    )
    return {
        "case": "two_obligations_update_two_sequential_handovers",
        "passed": passed,
        "handover_count": len(protocol.handovers),
        "owner_epoch": active.epoch,
        "obligations_at_second_install": obligations_at_second_install,
        "resolved_obligations": len(active.capsule.decisions),
        "outbox_bindings": len(outbox_ids),
        "capsule_version": active.capsule.version,
        "root_equalities": root_equalities,
    }


def _participant_migration_contract() -> dict[str, object]:
    source, target = "participant-source", "participant-target"
    moving_twin, stationary_twin = "participant-moving", "participant-stationary"
    registry = QuorumRegistry(
        _quorum_group(group_id)
        for group_id in (
            "ownership",
            "decision",
            f"shard:{source}",
            f"shard:{target}",
        )
    )
    protocol = Carry2PC(quorum_registry=registry)
    authorization = AuthorizationContext(
        "participant-controller", ("write",), 0, "participant-credential"
    )
    frontier = (InputFrontier("participant-sensor", 11, "participant-event-11"),)
    protocol.initialize_twin(
        twin_id=moving_twin,
        owner=source,
        state=(StateEntry("axis-x", "0"), StateEntry("axis-y", "0")),
        authorization=authorization,
        input_frontier=frontier,
    )
    protocol.initialize_twin(
        twin_id=stationary_twin,
        owner=source,
        state=(StateEntry("status", '"idle"'),),
        authorization=authorization,
        input_frontier=frontier,
    )

    tx_id = "transaction-two-logical-participants"
    participants = tuple(sorted((moving_twin, stationary_twin)))
    moving_yes = protocol.prepare(
        tx_id=tx_id,
        twin_id=moving_twin,
        participant_set=participants,
        reads=(),
        writes=(WriteIntent("axis-x", "7"), WriteIntent("axis-y", "9")),
        locks=("axis-x", "axis-y"),
    )
    stationary_yes = protocol.prepare(
        tx_id=tx_id,
        twin_id=stationary_twin,
        participant_set=participants,
        reads=(),
        writes=(WriteIntent("status", '"committed"'),),
        locks=("status",),
    )

    freeze = protocol.freeze(twin_id=moving_twin, target=target)
    install = protocol.install(freeze)
    activate = protocol.commit_activate(install)
    protocol.deliver_activate(activate, shard_id=target)
    protocol.deliver_activate(activate, shard_id=source)

    conflicting_update_blocked = False
    try:
        protocol.update(
            update_id="partial-moving-resource-update",
            twin_id=moving_twin,
            writes=(WriteIntent("axis-x", "8"),),
            locks=("axis-x",),
        )
    except ProtocolError:
        conflicting_update_blocked = True

    decision = protocol.decide(
        tx_id=tx_id,
        decision=Decision.COMMIT,
        participant_set=participants,
        yes_certificates=(moving_yes, stationary_yes),
    )
    moving_result = protocol.resolve(twin_id=moving_twin, decision_certificate=decision)
    stationary_result = protocol.resolve(
        twin_id=stationary_twin, decision_certificate=decision
    )
    protocol.assert_authoritative_invariants(moving_twin)
    protocol.assert_authoritative_invariants(stationary_twin)

    moving = protocol.active_twin(moving_twin)
    stationary = protocol.active_twin(stationary_twin)
    moving_state = {entry.key: entry.value_json for entry in moving.capsule.state}
    stationary_state = {
        entry.key: entry.value_json for entry in stationary.capsule.state
    }
    moving_tombstone = moving.capsule.tombstone(tx_id)
    stationary_tombstone = stationary.capsule.tombstone(tx_id)
    same_decision = (
        moving_tombstone is not None
        and stationary_tombstone is not None
        and moving_tombstone.decision is Decision.COMMIT
        and stationary_tombstone.decision is Decision.COMMIT
        and moving_tombstone.decision_record_digest
        == stationary_tombstone.decision_record_digest
        == decision.record_digest
    )
    passed = (
        moving.owner == target
        and stationary.owner == source
        and moving_state == {"axis-x": "7", "axis-y": "9"}
        and stationary_state == {"status": '"committed"'}
        and moving_result.applied_now
        and stationary_result.applied_now
        and conflicting_update_blocked
        and same_decision
    )
    return {
        "case": "two_logical_participants_one_migrates",
        "passed": passed,
        "logical_participants": len(participants),
        "migrated_participants": 1,
        "migrated_resource_keys": len(moving_state),
        "conflicting_update_blocked": conflicting_update_blocked,
        "same_decision_record": same_decision,
        "moving_owner_epoch": moving.epoch,
        "stationary_owner_epoch": stationary.epoch,
    }


def _post_activation_update_interleaving_contract() -> dict[str, object]:
    source, target = "update-source", "update-target"
    twin_id, tx_id = "twin-update-interleaving", "tx-update-interleaving"
    registry = QuorumRegistry(
        _quorum_group(group_id)
        for group_id in (
            "ownership",
            "decision",
            f"shard:{source}",
            f"shard:{target}",
        )
    )
    protocol = Carry2PC(quorum_registry=registry)
    protocol.initialize_twin(
        twin_id=twin_id,
        owner=source,
        state=(StateEntry("value", "0"), StateEntry("aux", "0")),
        authorization=AuthorizationContext("controller", ("write",), 0, "credential"),
        input_frontier=(InputFrontier("sensor-0", 7, "event-7"),),
    )
    tx_command = CommandIntent(
        stable_command_id(twin_id, tx_id, 0),
        '{"command":"apply-transaction"}',
    )
    yes = protocol.prepare(
        tx_id=tx_id,
        twin_id=twin_id,
        participant_set=(twin_id,),
        reads=(),
        writes=(WriteIntent("value", "1"),),
        locks=("value",),
        commands=(tx_command,),
    )
    freeze = protocol.freeze(twin_id=twin_id, target=target)
    install = protocol.install(freeze)
    protocol.activate(install)
    decision = protocol.decide(
        tx_id=tx_id,
        decision=Decision.COMMIT,
        participant_set=(twin_id,),
        yes_certificates=(yes,),
    )

    update_id = "update-after-activation"
    update_command = UpdateCommand(
        stable_update_command_id(twin_id, update_id, 0),
        '{"command":"apply-update"}',
    )

    def run(order: tuple[str, ...]) -> tuple[Carry2PC, dict[str, object]]:
        replay = deepcopy(protocol)
        for action in order:
            if action == "update":
                replay.update(
                    update_id=update_id,
                    twin_id=twin_id,
                    writes=(WriteIntent("aux", "9"),),
                    locks=("aux",),
                    commands=(update_command,),
                )
            elif action == "resolve":
                replay.resolve(twin_id=twin_id, decision_certificate=decision)
            else:
                raise AssertionError(f"unknown interleaving action: {action}")
        replay.resolve(twin_id=twin_id, decision_certificate=decision)
        replay.assert_authoritative_invariants(twin_id)
        active = replay.active_twin(twin_id)
        tombstone = active.capsule.tombstone(tx_id)
        projection = {
            "owner": active.owner,
            "epoch": active.epoch,
            "version": active.capsule.version,
            "state": tuple(
                sorted((entry.key, entry.value_json) for entry in active.capsule.state)
            ),
            "outbox": tuple(sorted(entry.command_id for entry in active.capsule.outbox)),
            "resolved": None
            if tombstone is None
            else (
                tombstone.decision,
                tombstone.decision_record_digest,
                tombstone.intent_digest,
            ),
        }
        return replay, projection

    update_first, update_first_projection = run(("update", "resolve"))
    resolve_first, resolve_first_projection = run(("resolve", "update"))
    expected_commands = {tx_command.command_id, update_command.command_id}
    counts_are_once = all(
        replay.outbox_enqueue_counts.get(command_id) == 1
        for replay in (update_first, resolve_first)
        for command_id in expected_commands
    )
    passed = (
        update_first_projection == resolve_first_projection
        and update_first_projection["owner"] == target
        and update_first_projection["epoch"] == 1
        and update_first_projection["version"] == 2
        and update_first_projection["state"] == (("aux", "9"), ("value", "1"))
        and set(update_first_projection["outbox"]) == expected_commands
        and counts_are_once
    )
    return {
        "case": "post_activation_nonconflicting_update_resolve_interleaving",
        "passed": passed,
        "schedules": 2,
        "same_final_projection": update_first_projection == resolve_first_projection,
        "owner_epoch": update_first_projection["epoch"],
        "capsule_version": update_first_projection["version"],
        "outbox_bindings": len(update_first_projection["outbox"]),
        "each_command_enqueued_once": counts_are_once,
    }


def _protocol_state_snapshot(protocol: Carry2PC) -> dict[str, object]:
    return deepcopy(
        {
            "copies": protocol.copies,
            "owners": protocol.owners,
            "owner_history": protocol.owner_history,
            "handovers": protocol.handovers,
            "decisions": protocol.decisions,
            "yes_history": protocol.yes_history,
            "outbox_enqueue_counts": protocol.outbox_enqueue_counts,
            "outbox_enqueue_bindings": protocol.outbox_enqueue_bindings,
            "decision_inbox": protocol.decision_inbox,
            "decision_delivery_counts": protocol.decision_delivery_counts,
            "log_cut": protocol._log_cut,
        }
    )


def _stale_terminal_delivery_schedules(
    checkpoint: Carry2PC,
    deliveries: tuple[tuple[str, Any, str], ...],
) -> tuple[int, bool]:
    checked = 0
    for schedule in permutations(deliveries):
        replay = deepcopy(checkpoint)
        before = _protocol_state_snapshot(replay)
        for terminal_kind, certificate, shard_id in schedule:
            if terminal_kind == "activate":
                replay.deliver_activate(certificate, shard_id=shard_id)
            elif terminal_kind == "resume":
                replay.deliver_resume(certificate, shard_id=shard_id)
            else:
                raise AssertionError(f"unknown terminal kind: {terminal_kind}")
        checked += 1
        if before != _protocol_state_snapshot(replay):
            return checked, False
    return checked, True


def _terminal_lineage_redelivery_contract() -> dict[str, object]:
    source, old_target, successor = "lineage-a", "lineage-b", "lineage-c"
    registry = QuorumRegistry(
        _quorum_group(group_id)
        for group_id in (
            "ownership",
            "decision",
            *(f"shard:{shard}" for shard in (source, old_target, successor)),
        )
    )
    protocol = Carry2PC(quorum_registry=registry)

    resume_twin_id = "twin-resume-lineage"
    protocol.initialize_twin(
        twin_id=resume_twin_id,
        owner=source,
        state=(StateEntry("value", "0"),),
        authorization=AuthorizationContext("controller", ("write",), 0, "credential"),
    )
    resumed_freeze = protocol.freeze(twin_id=resume_twin_id, target=old_target)
    protocol.install(resumed_freeze)
    stale_resume = protocol.commit_resume(resumed_freeze)
    protocol.deliver_resume(stale_resume, shard_id=source)
    protocol.deliver_resume(stale_resume, shard_id=old_target)
    successor_freeze = protocol.freeze(twin_id=resume_twin_id, target=successor)
    successor_install = protocol.install(successor_freeze)
    restored_resume = deepcopy(protocol)
    resume_checkpoint_equal = _protocol_state_snapshot(
        restored_resume
    ) == _protocol_state_snapshot(protocol)
    resume_schedules, stale_resume_stutter = _stale_terminal_delivery_schedules(
        restored_resume,
        (
            ("resume", stale_resume, source),
            ("resume", stale_resume, old_target),
        ),
    )
    successor_activation = restored_resume.commit_activate(successor_install)
    restored_resume.deliver_activate(successor_activation, shard_id=source)
    restored_resume.deliver_activate(successor_activation, shard_id=successor)
    restored_resume.assert_authoritative_invariants(resume_twin_id)
    resume_active = restored_resume.active_twin(resume_twin_id)

    activate_twin_id = "twin-activate-lineage"
    protocol.initialize_twin(
        twin_id=activate_twin_id,
        owner=source,
        state=(StateEntry("value", "0"),),
        authorization=AuthorizationContext("controller", ("write",), 0, "credential"),
    )
    first_freeze = protocol.freeze(twin_id=activate_twin_id, target=old_target)
    first_install = protocol.install(first_freeze)
    stale_activate = protocol.commit_activate(first_install)
    protocol.deliver_activate(stale_activate, shard_id=source)
    protocol.deliver_activate(stale_activate, shard_id=old_target)

    second_freeze = protocol.freeze(twin_id=activate_twin_id, target=successor)
    second_install = protocol.install(second_freeze)
    restored_activate = deepcopy(protocol)
    activate_checkpoint_equal = _protocol_state_snapshot(
        restored_activate
    ) == _protocol_state_snapshot(protocol)
    activate_schedules, stale_activate_stutter = _stale_terminal_delivery_schedules(
        restored_activate,
        (
            ("activate", stale_activate, source),
            ("activate", stale_activate, old_target),
        ),
    )
    second_activate = restored_activate.commit_activate(second_install)
    restored_activate.deliver_activate(second_activate, shard_id=old_target)
    restored_activate.deliver_activate(second_activate, shard_id=successor)

    third_freeze = restored_activate.freeze(twin_id=activate_twin_id, target=old_target)
    third_install = restored_activate.install(third_freeze)
    restored_reuse = deepcopy(restored_activate)
    reuse_schedules, reused_target_stutter = _stale_terminal_delivery_schedules(
        restored_reuse,
        (
            ("activate", stale_activate, old_target),
            ("activate", second_activate, old_target),
            ("activate", second_activate, successor),
        ),
    )
    third_activate = restored_reuse.commit_activate(third_install)
    restored_reuse.deliver_activate(third_activate, shard_id=successor)
    restored_reuse.deliver_activate(third_activate, shard_id=old_target)
    restored_reuse.assert_authoritative_invariants(activate_twin_id)
    activate_active = restored_reuse.active_twin(activate_twin_id)
    terminal_modes = {
        shard: restored_reuse.copies[(shard, activate_twin_id)].mode.value
        for shard in (source, old_target, successor)
    }
    pending_lineages = {
        shard: restored_reuse.copies[(shard, activate_twin_id)].pending_transfer_id
        for shard in (source, old_target, successor)
    }
    evidence = {
        "case": "stale_terminal_qcs_across_restored_interleaved_lineages",
        "resume_checkpoint_equal": resume_checkpoint_equal,
        "stale_resume_delivery_stutter": stale_resume_stutter,
        "resume_active_owner": resume_active.owner,
        "resume_active_epoch": resume_active.epoch,
        "activate_checkpoint_equal": activate_checkpoint_equal,
        "stale_activate_delivery_stutter": stale_activate_stutter,
        "reused_target_delivery_stutter": reused_target_stutter,
        "redelivery_schedules_checked": (
            resume_schedules + activate_schedules + reuse_schedules
        ),
        "active_owner": activate_active.owner,
        "active_epoch": activate_active.epoch,
        "terminal_modes": terminal_modes,
        "all_terminal_pending_lineages_cleared": all(
            lineage is None for lineage in pending_lineages.values()
        ),
        "resume_lineages_distinct": (
            resumed_freeze.transfer_id != successor_freeze.transfer_id
        ),
        "activation_lineages_distinct": len(
            {
                first_freeze.transfer_id,
                second_freeze.transfer_id,
                third_freeze.transfer_id,
            }
        )
        == 3,
    }
    passed = (
        resume_checkpoint_equal
        and stale_resume_stutter
        and resume_active.owner == successor
        and resume_active.epoch == 1
        and activate_checkpoint_equal
        and stale_activate_stutter
        and reused_target_stutter
        and evidence["redelivery_schedules_checked"] == 10
        and activate_active.owner == old_target
        and activate_active.epoch == 3
        and terminal_modes
        == {source: "fenced", old_target: "active", successor: "fenced"}
        and evidence["all_terminal_pending_lineages_cleared"] is True
        and evidence["resume_lineages_distinct"] is True
        and evidence["activation_lineages_distinct"] is True
    )
    return {
        **evidence,
        "passed": passed,
        "evidence_sha256": stable_hash(
            "carry2pc.terminal-lineage-contract.v2", evidence
        ),
    }


def _decision_record_binding_contract() -> dict[str, object]:
    protocol, source, _target, twin_id = _reference_protocol("decision-digest-binding")
    tx_id = "tx-decision-digest-binding"
    yes = protocol.prepare(
        tx_id=tx_id,
        twin_id=twin_id,
        participant_set=(twin_id,),
        reads=(),
        writes=(WriteIntent("value", "1"),),
        locks=("value",),
    )
    commit = protocol.decide(
        tx_id=tx_id,
        decision=Decision.COMMIT,
        participant_set=(twin_id,),
        yes_certificates=(yes,),
    )
    abort_substitute = protocol.issuer.decision(
        group_id=protocol.decision_group,
        tx_id=tx_id,
        decision=Decision.ABORT,
        participant_set=(twin_id,),
        yes_record_digests=(),
    )
    decision_group = protocol.registry.group(protocol.decision_group)
    alternate_proof = QuorumProof(
        group_id=decision_group.group_id,
        configuration=decision_group.configuration,
        signers=(
            decision_group.members[3],
            decision_group.members[2],
            decision_group.members[1],
        ),
        subject_hash=commit.subject_hash,
    )
    alternate_commit = replace(commit, proof=alternate_proof)
    protocol.deliver_decision(
        shard_id=source,
        twin_id=twin_id,
        decision_certificate=alternate_commit,
    )
    before_substitution = _protocol_state_snapshot(protocol)
    rejected = False
    rejection = ""
    try:
        protocol.process_decision(
            shard_id=source,
            twin_id=twin_id,
            decision_certificate=abort_substitute,
        )
    except ProtocolError as exc:
        rejected = True
        rejection = str(exc)
    substitution_stutter = before_substitution == _protocol_state_snapshot(protocol)
    result = protocol.process_decision(
        shard_id=source,
        twin_id=twin_id,
        decision_certificate=alternate_commit,
    )
    protocol.assert_authoritative_invariants(twin_id)
    tombstone = protocol.active_twin(twin_id).capsule.tombstone(tx_id)
    inbox_empty = not any(
        key[:3] == (source, twin_id, tx_id) for key in protocol.decision_inbox
    )
    evidence = {
        "case": "semantic_record_accepts_alternate_qc_and_rejects_abort_record",
        "commit_record_digest": commit.record_digest,
        "alternate_commit_record_digest": alternate_commit.record_digest,
        "commit_proof_digest": commit.proof_digest,
        "alternate_commit_proof_digest": alternate_commit.proof_digest,
        "abort_record_digest": abort_substitute.record_digest,
        "alternate_commit_quorum_valid": alternate_commit.verify(protocol.registry),
        "abort_substitute_quorum_valid": abort_substitute.verify(protocol.registry),
        "substitution_rejected": rejected,
        "substitution_state_unchanged": substitution_stutter,
        "rejection": rejection,
        "correct_commit_applied": result.applied_now,
        "inbox_empty_after_correct_process": inbox_empty,
        "tombstone_decision": None if tombstone is None else tombstone.decision.value,
        "tombstone_record_digest": (
            None if tombstone is None else tombstone.decision_record_digest
        ),
    }
    passed = (
        commit.record_digest == alternate_commit.record_digest
        and commit.proof_digest != alternate_commit.proof_digest
        and commit.digest != alternate_commit.digest
        and commit.record_digest != abort_substitute.record_digest
        and evidence["alternate_commit_quorum_valid"] is True
        and evidence["abort_substitute_quorum_valid"] is True
        and rejected
        and substitution_stutter
        and result.applied_now
        and inbox_empty
        and tombstone is not None
        and tombstone.decision is Decision.COMMIT
        and tombstone.decision_record_digest == commit.record_digest
    )
    return {
        **evidence,
        "passed": passed,
        "evidence_sha256": stable_hash(
            "carry2pc.decision-record-contract.v2", evidence
        ),
    }


def _json_bytes(payload: Any) -> bytes:
    return (
        json.dumps(canonical_data(payload), indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_json_bytes(payload))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _matrix(config: VerificationConfig) -> list[dict[str, object]]:
    cells: list[dict[str, object]] = []
    configured_outcomes = set(config.bounds.decision_outcomes)
    profiles = tuple(
        (profile, outcomes)
        for profile, outcomes in DECISION_PROFILES
        if set(outcomes).issubset(configured_outcomes)
    )
    resume_values = (False, True) if config.bounds.allow_resume else (False,)
    duplicate_values = (
        (False, True) if config.bounds.allow_duplicate_delivery else (False,)
    )
    for profile, outcomes in profiles:
        for allow_resume in resume_values:
            for allow_duplicate_delivery in duplicate_values:
                cells.append(
                    {
                        "cell_id": (
                            f"{profile}__resume_{str(allow_resume).lower()}"
                            f"__duplicate_{str(allow_duplicate_delivery).lower()}"
                        ),
                        "decision_profile": profile,
                        "decision_outcomes": outcomes,
                        "allow_resume": allow_resume,
                        "allow_duplicate_delivery": allow_duplicate_delivery,
                    }
                )
    return cells


def _run_cell(
    config: VerificationConfig,
    cell: dict[str, object],
    mutant: Mutant | None,
) -> dict[str, object]:
    scenario = config.scenario
    bounds = config.bounds
    result = explore(
        source=scenario.source,
        target=scenario.target,
        initial_value=scenario.initial_value_json,
        intent_value=scenario.intent_value_json,
        twin_id=scenario.twin_id,
        tx_id=scenario.tx_id,
        command_id=scenario.command_id,
        command_index=0,
        command_payload=scenario.command_payload_json,
        max_depth=bounds.max_depth,
        max_states=bounds.max_states,
        decision_outcomes=cell["decision_outcomes"],
        allow_resume=bool(cell["allow_resume"]),
        allow_duplicate_delivery=bool(cell["allow_duplicate_delivery"]),
        mutant=mutant,
    )
    witness = result["violation_witness"]
    expected = None if mutant is None else EXPECTED_MUTANT_INVARIANT[mutant].value
    expected_witness_found = (
        isinstance(witness, dict)
        and expected is not None
        and expected in witness["violated_invariants"]
    )
    applicable = _mutant_applicable(cell, mutant)
    return {
        "artifact_status": ARTIFACT_STATUS,
        "cell": cell,
        "variant": result["variant"],
        "expected_invariant": expected,
        "mutant_applicable": applicable,
        "bounded_complete": result["bounded_complete"],
        "max_states_reached": result["max_states_reached"],
        "states_at_depth_cut": result["states_at_depth_cut"],
        "states_discovered": result["states_discovered"],
        "protocol_states_discovered": result["protocol_states_discovered"],
        "states_explored": result["states_explored"],
        "transitions_considered": result["transitions_considered"],
        "expected_witness_found": expected_witness_found,
        "violation_witness": witness,
        "true_overlap_witness": result["true_overlap_witness"],
    }


def _mutant_applicable(
    cell: dict[str, object],
    mutant: Mutant | None,
) -> bool:
    if mutant is None:
        return False
    outcomes = tuple(cell["decision_outcomes"])
    if mutant is Mutant.EPOCH_GUARD_CONVERTS_COMMIT_TO_ABORT:
        return "commit" in outcomes
    if mutant is Mutant.DUPLICATE_OUTBOX_ENQUEUE:
        return "commit" in outcomes and bool(cell["allow_duplicate_delivery"])
    return True


def _aggregate(records: list[dict[str, object]]) -> dict[str, object]:
    variants = ("compliant", *(mutant.value for mutant in Mutant))
    rows: list[dict[str, object]] = []
    for variant in variants:
        selected = [record for record in records if record["variant"] == variant]
        witnesses = [
            record for record in selected if record["expected_witness_found"] is True
        ]
        applicable = [
            record for record in selected if record["mutant_applicable"] is True
        ]
        witness_depths = [
            record["violation_witness"]["depth"]
            for record in witnesses
            if isinstance(record["violation_witness"], dict)
        ]
        rows.append(
            {
                "variant": variant,
                "expected_invariant": selected[0]["expected_invariant"],
                "cells": len(selected),
                "bounded_complete_cells": sum(
                    record["bounded_complete"] is True for record in selected
                ),
                "applicable_cells": len(applicable),
                "witness_cells": len(witnesses),
                "shortest_witness_depth": min(witness_depths)
                if witness_depths
                else None,
                "states_explored_min": min(
                    record["states_explored"] for record in selected
                ),
                "states_explored_max": max(
                    record["states_explored"] for record in selected
                ),
                "transitions_considered_min": min(
                    record["transitions_considered"] for record in selected
                ),
                "transitions_considered_max": max(
                    record["transitions_considered"] for record in selected
                ),
            }
        )

    compliant = [record for record in records if record["variant"] == "compliant"]
    conformance = _implementation_conformance()
    transition_conformance = _reachable_transition_conformance()
    namespace_contract = _command_namespace_contract()
    capsule_wire_contract = _capsule_wire_contract()
    service_group_contract = _service_group_binding_contract()
    composition_contract = _sequential_composition_contract()
    participant_contract = _participant_migration_contract()
    update_interleaving_contract = _post_activation_update_interleaving_contract()
    terminal_lineage_contract = _terminal_lineage_redelivery_contract()
    decision_record_contract = _decision_record_binding_contract()
    all_complete = all(record["bounded_complete"] is True for record in records)
    all_compliant_safe = all(
        record["violation_witness"] is None for record in compliant
    )
    overlap_applicable = [
        record
        for record in compliant
        if "commit" in tuple(record["cell"]["decision_outcomes"])
    ]
    overlap_nonapplicable = [
        record
        for record in compliant
        if "commit" not in tuple(record["cell"]["decision_outcomes"])
    ]
    all_applicable_overlap_witnessed = all(
        record["true_overlap_witness"] is not None for record in overlap_applicable
    )
    all_nonapplicable_overlap_unwitnessed = all(
        record["true_overlap_witness"] is None for record in overlap_nonapplicable
    )
    applicable_mutants = [
        record for record in records if record["mutant_applicable"] is True
    ]
    all_applicable_witnessed = all(
        record["expected_witness_found"] is True for record in applicable_mutants
    )
    all_nonapplicable_unwitnessed = all(
        record["expected_witness_found"] is False
        and record["violation_witness"] is None
        for record in records
        if record["variant"] != "compliant" and record["mutant_applicable"] is False
    )
    passed = (
        all_complete
        and all_compliant_safe
        and all_applicable_overlap_witnessed
        and all_nonapplicable_overlap_unwitnessed
        and all_applicable_witnessed
        and all_nonapplicable_unwitnessed
        and conformance["passed"] == conformance["cases"]
        and transition_conformance["passed"] is True
        and namespace_contract["passed"] is True
        and capsule_wire_contract["passed"] is True
        and service_group_contract["passed"] is True
        and composition_contract["passed"] is True
        and participant_contract["passed"] is True
        and update_interleaving_contract["passed"] is True
        and terminal_lineage_contract["passed"] is True
        and decision_record_contract["passed"] is True
    )
    return {
        "schema_version": "carry2pc/evaluation_metrics/v2",
        "artifact_status": ARTIFACT_STATUS,
        "configuration_cells": len({record["cell"]["cell_id"] for record in records}),
        "variant_count_per_cell": len(variants),
        "total_exhaustive_runs": len(records),
        "passed": passed,
        "all_runs_bounded_complete": all_complete,
        "all_compliant_cells_safe": all_compliant_safe,
        "overlap_applicable_compliant_cells": len(overlap_applicable),
        "all_overlap_applicable_compliant_cells_witnessed": (
            all_applicable_overlap_witnessed
        ),
        "all_overlap_nonapplicable_compliant_cells_unwitnessed": (
            all_nonapplicable_overlap_unwitnessed
        ),
        "applicable_mutant_runs": len(applicable_mutants),
        "all_applicable_mutant_witnesses_found": all_applicable_witnessed,
        "all_nonapplicable_mutants_unwitnessed": all_nonapplicable_unwitnessed,
        "state_cap_hits": sum(
            record["max_states_reached"] is True for record in records
        ),
        "depth_frontier_states": sum(
            int(record["states_at_depth_cut"]) for record in records
        ),
        "total_states_explored": sum(
            int(record["states_explored"]) for record in records
        ),
        "total_transitions_considered": sum(
            int(record["transitions_considered"]) for record in records
        ),
        "compliant_safe_cells": sum(
            record["violation_witness"] is None for record in compliant
        ),
        "compliant_overlap_cells": sum(
            record["true_overlap_witness"] is not None for record in compliant
        ),
        "variant_rows": rows,
        "reference_implementation_conformance": conformance,
        "reachable_transition_conformance": transition_conformance,
        "command_namespace_contract": namespace_contract,
        "capsule_wire_contract": capsule_wire_contract,
        "service_group_binding_contract": service_group_contract,
        "sequential_composition_contract": composition_contract,
        "participant_migration_contract": participant_contract,
        "post_activation_update_interleaving_contract": update_interleaving_contract,
        "terminal_lineage_redelivery_contract": terminal_lineage_contract,
        "decision_record_binding_contract": decision_record_contract,
    }


def run_evaluation_matrix(
    config: VerificationConfig,
    output_dir: str | Path,
    *,
    config_path: str | Path,
) -> dict[str, object]:
    output = Path(output_dir)
    raw_path = output / "raw" / "records.jsonl"
    metrics_path = output / "aggregate_metrics.json"
    manifest_path = output / "manifest.json"

    package_dir = Path(__file__).resolve().parent
    source_root = (
        package_dir.parent.parent
        if package_dir.parent.name == "src"
        else package_dir.parent
    )
    config_file = Path(config_path).resolve()
    config_file_sha256 = _sha256(config_file)
    try:
        config_record = str(config_file.relative_to(source_root))
        config_scope = "source_bundle"
    except ValueError:
        config_record = config_file.name
        config_scope = "external"
    producer_files = {
        str(path.relative_to(source_root)): _sha256(path)
        for path in sorted(package_dir.glob("*.py"))
    }

    records: list[dict[str, object]] = []
    matrix = _matrix(config)
    for cell in matrix:
        records.append(_run_cell(config, cell, None))
        for mutant in config.mutants:
            records.append(_run_cell(config, cell, mutant))

    raw_path.parent.mkdir(parents=True, exist_ok=True)
    raw_path.write_bytes(
        b"".join(
            json.dumps(canonical_data(record), sort_keys=True).encode("utf-8") + b"\n"
            for record in records
        )
    )
    metrics = _aggregate(records)
    _write_json(metrics_path, metrics)

    manifest = {
        "schema_version": "carry2pc/evaluation_manifest/v2",
        "artifact_status": ARTIFACT_STATUS,
        "producer": {
            "command": REPRODUCTION_COMMAND,
            "files_sha256": producer_files,
            "bundle_sha256": stable_hash(
                "carry2pc.evaluation_producer.v1", producer_files
            ),
        },
        "input": {
            "config": config_record,
            "config_scope": config_scope,
            "config_file_sha256": config_file_sha256,
            "config_semantic_digest": config.digest,
            "depth_bound": config.bounds.max_depth,
            "state_bound": config.bounds.max_states,
        },
        "matrix": matrix,
        "outputs": {
            "raw/records.jsonl": {
                "records": len(records),
                "sha256": _sha256(raw_path),
            },
            "aggregate_metrics.json": {"sha256": _sha256(metrics_path)},
        },
    }
    _write_json(manifest_path, manifest)
    return metrics
