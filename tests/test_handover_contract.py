"""Focused regression tests for the Carry2PC handover contract."""

from __future__ import annotations

from dataclasses import replace
import json

import pytest

from carry2pc.certificates import QuorumGroup, QuorumRegistry
from carry2pc.protocol import Carry2PC, ProtocolError
from carry2pc.schemas import (
    AuthorizationContext,
    CommandIntent,
    InputFrontier,
    ReadVersion,
    StateEntry,
    UpdateCommand,
    WriteIntent,
    abort_intent_digest,
    capsule_to_bytes,
    stable_command_id,
    stable_update_command_id,
)
from carry2pc.types import Decision, OwnerMode


def _group(group_id: str) -> QuorumGroup:
    members = tuple(f"{group_id}:replica-{index}" for index in range(4))
    return QuorumGroup(
        group_id=group_id,
        configuration=0,
        members=members,
        max_byzantine=1,
        model_signers=members[:3],
    )


def _protocol() -> tuple[Carry2PC, str, str, str]:
    source, target, twin_id = "shard-a", "shard-b", "twin-0"
    protocol = Carry2PC(
        quorum_registry=QuorumRegistry(
            _group(group_id)
            for group_id in (
                "ownership",
                "decision",
                f"shard:{source}",
                f"shard:{target}",
            )
        )
    )
    protocol.initialize_twin(
        twin_id=twin_id,
        owner=source,
        state=(StateEntry("value", "0"),),
        authorization=AuthorizationContext(
            "controller", ("write",), 0, "credential"
        ),
        input_frontier=(InputFrontier("sensor-0", 7, "event-7"),),
    )
    return protocol, source, target, twin_id


def _staged_handover() -> tuple[Carry2PC, str, str, str, object]:
    protocol, source, target, twin_id = _protocol()
    freeze = protocol.freeze(twin_id=twin_id, target=target)
    install = protocol.install(freeze)
    return protocol, source, target, twin_id, install


def test_activation_preserves_twin_and_advances_owner_epoch_once() -> None:
    protocol, source, target, twin_id, install = _staged_handover()
    source_copy = protocol.copies[(source, twin_id)]
    staged_copy = protocol.copies[(target, twin_id)]

    assert source_copy.epoch == 0
    assert staged_copy.twin_id == twin_id
    assert staged_copy.epoch == source_copy.epoch + 1
    assert staged_copy.capsule.version == source_copy.capsule.version
    assert staged_copy.mode is OwnerMode.STAGING

    activation = protocol.commit_activate(install)
    protocol.deliver_activate(activation, shard_id=source)
    protocol.deliver_activate(activation, shard_id=target)

    active = protocol.active_twin(twin_id)
    assert active.twin_id == twin_id
    assert active.owner == target
    assert active.epoch == 1
    assert active.capsule.version == 0
    protocol.assert_authoritative_invariants(twin_id)


def test_handover_preserves_a_nonzero_capsule_version_and_payload() -> None:
    protocol, source, target, twin_id = _protocol()
    update_id = "update-0"
    command = UpdateCommand(
        stable_update_command_id(twin_id, update_id, 0),
        '{"command":"notify"}',
    )
    enqueued = protocol.update(
        update_id=update_id,
        twin_id=twin_id,
        writes=(WriteIntent("value", "17"),),
        locks=("value",),
        commands=(command,),
    )
    assert enqueued == (command.command_id,)
    expected_capsule = protocol.active_twin(twin_id).capsule
    assert expected_capsule.version == 1

    freeze = protocol.freeze(twin_id=twin_id, target=target)
    install = protocol.install(freeze)
    staged = protocol.copies[(target, twin_id)]

    assert staged.twin_id == twin_id
    assert staged.epoch == protocol.copies[(source, twin_id)].epoch + 1
    assert staged.capsule == expected_capsule
    assert staged.capsule is not expected_capsule
    assert staged.capsule.state == (StateEntry("value", "17"),)
    assert staged.capsule.authorization == expected_capsule.authorization
    assert staged.capsule.input_frontier == expected_capsule.input_frontier
    assert staged.capsule.outbox == expected_capsule.outbox

    activation = protocol.activate(install)
    assert activation.new_epoch == 1
    active = protocol.active_twin(twin_id)
    assert active.twin_id == twin_id
    assert active.epoch == 1
    assert active.capsule == expected_capsule
    protocol.assert_authoritative_invariants(twin_id)


def test_install_rejects_malformed_and_wrong_root_capsule_bytes() -> None:
    protocol, source, target, twin_id = _protocol()
    freeze = protocol.freeze(twin_id=twin_id, target=target)
    wire = capsule_to_bytes(protocol.copies[(source, twin_id)].capsule)

    with pytest.raises(ProtocolError, match="malformed capsule bytes"):
        protocol.install(freeze, capsule_bytes=wire[:-1])
    assert (target, twin_id) not in protocol.copies

    changed = wire.replace(b'"value_json":"0"', b'"value_json":"9"', 1)
    with pytest.raises(ProtocolError, match="do not match FreezeQC root"):
        protocol.install(freeze, capsule_bytes=changed)
    assert (target, twin_id) not in protocol.copies

    protocol.install(freeze, capsule_bytes=wire)
    assert protocol.copies[(target, twin_id)].capsule is not protocol.copies[
        (source, twin_id)
    ].capsule


def test_install_rejects_invalid_nested_versions() -> None:
    protocol, source, target, twin_id = _protocol()
    protocol.prepare(
        tx_id="tx-invalid-wire",
        twin_id=twin_id,
        participant_set=(twin_id,),
        reads=(ReadVersion("value", 0),),
        writes=(WriteIntent("value", "1"),),
        locks=("value",),
    )
    freeze = protocol.freeze(twin_id=twin_id, target=target)
    document = json.loads(capsule_to_bytes(protocol.copies[(source, twin_id)].capsule))
    document["prepared"][0]["record"]["reads"][0]["version"] = -1
    invalid = json.dumps(
        document,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")

    with pytest.raises(ProtocolError, match="malformed capsule bytes"):
        protocol.install(freeze, capsule_bytes=invalid)


def test_install_rejects_freeze_detached_from_current_owner_certificate() -> None:
    protocol, source, target, twin_id = _protocol()
    freeze = protocol.freeze(twin_id=twin_id, target=target)
    protocol.owners[twin_id] = protocol.issuer.owner(
        group_id="ownership",
        twin_id=twin_id,
        epoch=0,
        owner=source,
        previous_certificate_digest="forked-genesis",
    )

    with pytest.raises(ProtocolError, match="current OwnerQC"):
        protocol.install(freeze)


def test_install_rejects_tombstone_detached_from_tds_record() -> None:
    protocol, source, target, twin_id = _protocol()
    yes = protocol.prepare(
        tx_id="tx-corrupt-tombstone",
        twin_id=twin_id,
        participant_set=(twin_id,),
        reads=(ReadVersion("value", 0),),
        writes=(WriteIntent("value", "1"),),
        locks=("value",),
    )
    decision = protocol.decide(
        tx_id="tx-corrupt-tombstone",
        decision=Decision.COMMIT,
        participant_set=(twin_id,),
        yes_certificates=(yes,),
    )
    protocol.resolve(twin_id=twin_id, decision_certificate=decision)
    source_copy = protocol.copies[(source, twin_id)]
    tombstone = source_copy.capsule.decisions[0]
    corrupted_capsule = replace(
        source_copy.capsule,
        decisions=(replace(tombstone, decision_record_digest="forged-record"),),
    )
    protocol.copies[(source, twin_id)] = replace(
        source_copy, capsule=corrupted_capsule
    )
    freeze = protocol.freeze(twin_id=twin_id, target=target)

    with pytest.raises(ProtocolError, match="unique TDS record"):
        protocol.install(freeze)


def test_service_specific_quorums_reject_cross_group_substitution() -> None:
    protocol, _source, _target, twin_id = _protocol()
    yes = protocol.prepare(
        tx_id="tx-group-binding",
        twin_id=twin_id,
        participant_set=(twin_id,),
        reads=(),
        writes=(WriteIntent("value", "3"),),
        locks=("value",),
    )
    decision = protocol.decide(
        tx_id="tx-group-binding",
        decision=Decision.COMMIT,
        participant_set=(twin_id,),
        yes_certificates=(yes,),
    )
    wrong_group_decision = replace(
        decision,
        proof=protocol.registry.attest("ownership", decision.subject_hash),
    )
    with pytest.raises(ProtocolError, match="invalid DecisionQC"):
        protocol.deliver_decision(
            shard_id="shard-a",
            twin_id=twin_id,
            decision_certificate=wrong_group_decision,
        )


def test_install_rejects_yes_certificate_from_a_different_source_shard() -> None:
    protocol, source, target, twin_id = _protocol()
    tx_id = "tx-wrong-yes-source"
    yes = protocol.prepare(
        tx_id=tx_id,
        twin_id=twin_id,
        participant_set=(twin_id,),
        reads=(),
        writes=(WriteIntent("value", "8"),),
        locks=("value",),
    )

    source_copy = protocol.copies[(source, twin_id)]
    obligation = source_copy.capsule.obligation(tx_id)
    assert obligation is not None
    forged_yes = replace(
        yes,
        proof=protocol.registry.attest(
            protocol.shard_group(target), yes.subject_hash
        ),
    )
    forged_obligation = replace(obligation, yes_certificate=forged_yes)
    forged_capsule = replace(
        source_copy.capsule, prepared=(forged_obligation,)
    )
    protocol.copies[(source, twin_id)] = replace(
        source_copy, capsule=forged_capsule
    )
    protocol.yes_history.clear()
    freeze = protocol.freeze(twin_id=twin_id, target=target)

    with pytest.raises(ProtocolError, match="source-shard binding"):
        protocol.install(freeze)


def test_install_accepts_restored_per_obligation_source_binding() -> None:
    protocol, source, target, twin_id = _protocol()
    tx_id = "tx-restored-install-source"
    protocol.prepare(
        tx_id=tx_id,
        twin_id=twin_id,
        participant_set=(twin_id,),
        reads=(),
        writes=(WriteIntent("value", "9"),),
        locks=("value",),
    )
    freeze = protocol.freeze(twin_id=twin_id, target=target)
    protocol.yes_history.clear()

    install = protocol.install(
        freeze,
        expected_source_groups={
            (tx_id, twin_id): protocol.shard_group(source)
        },
    )

    assert install.source == source
    assert protocol.copies[(target, twin_id)].capsule.root == freeze.capsule_root


def test_prepare_rejects_write_without_matching_lock() -> None:
    protocol, _source, _target, twin_id = _protocol()
    with pytest.raises(ProtocolError, match="writes require matching locks"):
        protocol.prepare(
            tx_id="tx-unlocked-write",
            twin_id=twin_id,
            participant_set=(twin_id,),
            reads=(),
            writes=(WriteIntent("value", "4"),),
            locks=(),
        )


def test_activation_delivery_is_idempotent_after_owner_change() -> None:
    protocol, source, target, twin_id, install = _staged_handover()
    activation = protocol.commit_activate(install)

    for shard_id in (source, target, source, target):
        protocol.deliver_activate(activation, shard_id=shard_id)

    assert protocol.owners[twin_id].owner == target
    assert protocol.owners[twin_id].epoch == 1
    assert protocol.copies[(source, twin_id)].mode is OwnerMode.FENCED
    assert protocol.copies[(target, twin_id)].mode is OwnerMode.ACTIVE
    assert len(protocol.owner_history[twin_id]) == 2
    protocol.assert_authoritative_invariants(twin_id)


def test_decision_waits_for_successor_activation() -> None:
    protocol, source, target, twin_id = _protocol()
    yes = protocol.prepare(
        tx_id="tx-0",
        twin_id=twin_id,
        participant_set=(twin_id,),
        reads=(),
        writes=(WriteIntent("value", "21"),),
        locks=("value",),
    )
    decision = protocol.decide(
        tx_id="tx-0",
        decision=Decision.COMMIT,
        participant_set=(twin_id,),
        yes_certificates=(yes,),
    )
    freeze = protocol.freeze(twin_id=twin_id, target=target)
    install = protocol.install(freeze)
    activation = protocol.commit_activate(install)
    protocol.deliver_decision(
        shard_id=target,
        twin_id=twin_id,
        decision_certificate=decision,
    )

    with pytest.raises(ProtocolError, match="current owner is not active"):
        protocol.process_decision(
            shard_id=target,
            twin_id=twin_id,
            decision_certificate=decision,
        )

    protocol.deliver_activate(activation, shard_id=source)
    protocol.deliver_activate(activation, shard_id=target)
    result = protocol.process_decision(
        shard_id=target,
        twin_id=twin_id,
        decision_certificate=decision,
    )

    assert result.applied_now
    assert result.owner == target
    assert result.owner_epoch == 1
    assert protocol.active_twin(twin_id).capsule.version == 1
    protocol.assert_authoritative_invariants(twin_id)


def test_successor_resolves_origin_epoch_once_under_duplicate_delivery() -> None:
    protocol, source, target, twin_id = _protocol()
    tx_id = "tx-carried"
    command = CommandIntent(
        stable_command_id(twin_id, tx_id, 0),
        '{"command":"apply"}',
    )
    yes = protocol.prepare(
        tx_id=tx_id,
        twin_id=twin_id,
        participant_set=(twin_id,),
        reads=(),
        writes=(WriteIntent("value", "29"),),
        locks=("value",),
        commands=(command,),
    )
    assert yes.prepare_epoch == 0

    decision = protocol.decide(
        tx_id=tx_id,
        decision=Decision.COMMIT,
        participant_set=(twin_id,),
        yes_certificates=(yes,),
    )
    freeze = protocol.freeze(twin_id=twin_id, target=target)
    install = protocol.install(freeze)
    protocol.activate(install)
    assert protocol.active_twin(twin_id).epoch == 1

    protocol.deliver_decision(
        shard_id=target,
        twin_id=twin_id,
        decision_certificate=decision,
    )
    protocol.deliver_decision(
        shard_id=target,
        twin_id=twin_id,
        decision_certificate=decision,
    )
    first = protocol.process_decision(
        shard_id=target,
        twin_id=twin_id,
        decision_certificate=decision,
    )
    second = protocol.process_decision(
        shard_id=target,
        twin_id=twin_id,
        decision_certificate=decision,
    )

    active = protocol.active_twin(twin_id)
    assert first.applied_now
    assert first.enqueued_commands == (command.command_id,)
    assert not second.applied_now
    assert second.enqueued_commands == ()
    assert active.capsule.version == 1
    assert active.capsule.state == (StateEntry("value", "29"),)
    assert len(active.capsule.outbox) == 1
    assert protocol.outbox_enqueue_counts[command.command_id] == 1
    protocol.assert_authoritative_invariants(twin_id)


def test_successor_resolves_without_owner_history_lookup() -> None:
    protocol, source, target, twin_id = _protocol()
    yes = protocol.prepare(
        tx_id="tx-history-free",
        twin_id=twin_id,
        participant_set=(twin_id,),
        reads=(ReadVersion("value", 0),),
        writes=(WriteIntent("value", "31"),),
        locks=("value",),
    )
    freeze = protocol.freeze(twin_id=twin_id, target=target)
    install = protocol.install(freeze)
    protocol.activate(install)

    protocol.owner_history[twin_id] = []
    decision = protocol.decide(
        tx_id="tx-history-free",
        decision=Decision.COMMIT,
        participant_set=(twin_id,),
        yes_certificates=(yes,),
    )
    result = protocol.resolve(twin_id=twin_id, decision_certificate=decision)

    assert result.applied_now is True
    assert protocol.active_twin(twin_id).capsule.state == (StateEntry("value", "31"),)
    protocol.assert_authoritative_invariants(twin_id)


def test_sequential_handovers_keep_each_yes_source_shard() -> None:
    protocol, source, target, twin_id = _protocol()
    first_yes = protocol.prepare(
        tx_id="tx-source-a",
        twin_id=twin_id,
        participant_set=(twin_id,),
        reads=(),
        writes=(WriteIntent("value", "35"),),
        locks=("value",),
    )
    first_freeze = protocol.freeze(twin_id=twin_id, target=target)
    first_install = protocol.install(first_freeze)
    protocol.activate(first_install)

    second_yes = protocol.prepare(
        tx_id="tx-source-b",
        twin_id=twin_id,
        participant_set=(twin_id,),
        reads=(),
        writes=(WriteIntent("aux", "36"),),
        locks=("aux",),
    )
    second_freeze = protocol.freeze(twin_id=twin_id, target=source)
    second_install = protocol.install(second_freeze)
    protocol.activate(second_install)

    first_decision = protocol.decide(
        tx_id="tx-source-a",
        decision=Decision.COMMIT,
        participant_set=(twin_id,),
        yes_certificates=(first_yes,),
    )
    second_decision = protocol.decide(
        tx_id="tx-source-b",
        decision=Decision.COMMIT,
        participant_set=(twin_id,),
        yes_certificates=(second_yes,),
    )
    protocol.resolve(twin_id=twin_id, decision_certificate=first_decision)
    protocol.resolve(twin_id=twin_id, decision_certificate=second_decision)

    assert protocol.active_twin(twin_id).capsule.state == (
        StateEntry("aux", "36"),
        StateEntry("value", "35"),
    )
    protocol.assert_authoritative_invariants(twin_id)


def test_successor_restores_tds_and_yes_evidence_before_resolution() -> None:
    protocol, source, target, twin_id = _protocol()
    tx_id = "tx-evidence-restore"
    yes = protocol.prepare(
        tx_id=tx_id,
        twin_id=twin_id,
        participant_set=(twin_id,),
        reads=(),
        writes=(WriteIntent("value", "32"),),
        locks=("value",),
    )
    decision = protocol.decide(
        tx_id=tx_id,
        decision=Decision.COMMIT,
        participant_set=(twin_id,),
        yes_certificates=(yes,),
    )
    freeze = protocol.freeze(twin_id=twin_id, target=target)
    install = protocol.install(freeze)
    protocol.activate(install)

    protocol.decisions.clear()
    protocol.yes_history.clear()
    with pytest.raises(ProtocolError, match="expected source-shard binding"):
        protocol.restore_decision_evidence(decision, (yes,))
    protocol.restore_decision_evidence(
        decision,
        (yes,),
        expected_source_groups={twin_id: protocol.shard_group(source)},
    )
    result = protocol.resolve(twin_id=twin_id, decision_certificate=decision)

    assert result.applied_now is True
    assert protocol.active_twin(twin_id).capsule.state == (StateEntry("value", "32"),)


def test_restore_rejects_yes_certificate_not_bound_by_decision_record() -> None:
    protocol, source, _target, twin_id = _protocol()
    tx_id = "tx-restore-binding"
    yes = protocol.prepare(
        tx_id=tx_id,
        twin_id=twin_id,
        participant_set=(twin_id,),
        reads=(),
        writes=(WriteIntent("value", "33"),),
        locks=("value",),
    )
    decision = protocol.decide(
        tx_id=tx_id,
        decision=Decision.COMMIT,
        participant_set=(twin_id,),
        yes_certificates=(yes,),
    )
    forged_yes = protocol.issuer.yes(
        group_id=protocol.shard_group(source),
        tx_id=tx_id,
        twin_id=twin_id,
        prepare_epoch=yes.prepare_epoch,
        participant_set=yes.participant_set,
        intent_digest="forged-intent",
        lock_digest=yes.lock_digest,
        prepared_record_digest=yes.prepared_record_digest,
    )
    protocol.decisions.clear()
    protocol.yes_history.clear()

    with pytest.raises(ProtocolError, match="does not match DecisionQC"):
        protocol.restore_decision_evidence(decision, (forged_yes,))


def test_restore_rejects_yes_certificate_from_wrong_source_group() -> None:
    protocol, source, target, twin_id = _protocol()
    tx_id = "tx-restore-source"
    yes = protocol.prepare(
        tx_id=tx_id,
        twin_id=twin_id,
        participant_set=(twin_id,),
        reads=(),
        writes=(WriteIntent("value", "34"),),
        locks=("value",),
    )
    decision = protocol.decide(
        tx_id=tx_id,
        decision=Decision.COMMIT,
        participant_set=(twin_id,),
        yes_certificates=(yes,),
    )
    forged_yes = replace(
        yes,
        proof=protocol.registry.attest(
            protocol.shard_group(target), yes.subject_hash
        ),
    )
    protocol.decisions.clear()
    protocol.yes_history.clear()

    with pytest.raises(ProtocolError, match="wrong source-shard binding"):
        protocol.restore_decision_evidence(
            decision,
            (forged_yes,),
            expected_source_groups={twin_id: protocol.shard_group(source)},
        )


def test_abort_without_prepared_obligation_records_a_noop_tombstone() -> None:
    protocol, _source, _target, twin_id = _protocol()
    decision = protocol.decide(
        tx_id="tx-abort-no-prepare",
        decision=Decision.ABORT,
        participant_set=(twin_id,),
    )

    result = protocol.resolve(twin_id=twin_id, decision_certificate=decision)
    active = protocol.active_twin(twin_id)
    tombstone = active.capsule.tombstone("tx-abort-no-prepare")

    assert result.applied_now is True
    assert result.enqueued_commands == ()
    assert active.capsule.version == 0
    assert tombstone is not None
    assert tombstone.decision is Decision.ABORT
    assert tombstone.intent_digest == abort_intent_digest(
        twin_id, "tx-abort-no-prepare"
    )
    protocol.assert_authoritative_invariants(twin_id)


def test_resume_keeps_the_source_epoch_and_discards_staging_copy() -> None:
    protocol, source, target, twin_id, install = _staged_handover()
    freeze = protocol.handovers[install.transfer_id].freeze
    resume = protocol.commit_resume(freeze)

    protocol.deliver_resume(resume, shard_id=target)
    protocol.deliver_resume(resume, shard_id=source)

    active = protocol.active_twin(twin_id)
    assert active.owner == source
    assert active.epoch == 0
    assert protocol.copies[(target, twin_id)].mode is OwnerMode.DISCARDED
    assert len(protocol.owner_history[twin_id]) == 1
    protocol.assert_authoritative_invariants(twin_id)
