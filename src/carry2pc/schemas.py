"""Authoritative mobile digital-twin state schemas."""

from __future__ import annotations

from dataclasses import dataclass, replace
import json
from typing import Iterable

from carry2pc.canonical import canonical_json, stable_hash
from carry2pc.certificates import DecisionCertificate, QuorumProof, YesCertificate
from carry2pc.types import Decision, OutboxStatus, OwnerMode


TRANSACTION_COMMAND_PREFIX = "tx:"
UPDATE_COMMAND_PREFIX = "update:"


def _object(value: object, expected: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f"{label} must contain exactly {sorted(expected)}")
    return value


def _items(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be an array")
    return value


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{label} must be an integer")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    return value


def _require_unique(values: Iterable[str], label: str) -> None:
    collected = tuple(values)
    if len(set(collected)) != len(collected):
        raise ValueError(f"{label} must be unique")


def stable_command_id(twin_id: str, tx_id: str, command_index: int) -> str:
    """Derive the durable command namespace from its transaction position."""
    if command_index < 0:
        raise ValueError("command_index must be non-negative")
    return TRANSACTION_COMMAND_PREFIX + stable_hash(
        "carry2pc.transaction-command-id.v1",
        {"twin_id": twin_id, "tx_id": tx_id, "command_index": command_index},
    )


def stable_update_command_id(twin_id: str, update_id: str, command_index: int) -> str:
    """Derive an identifier in the disjoint nontransactional-update namespace."""
    if command_index < 0:
        raise ValueError("command_index must be non-negative")
    return UPDATE_COMMAND_PREFIX + stable_hash(
        "carry2pc.update-command-id.v1",
        {"twin_id": twin_id, "update_id": update_id, "command_index": command_index},
    )


def abort_intent_digest(twin_id: str, tx_id: str) -> str:
    """Bind an ABORT no-op for a participant that never prepared the tx."""
    return stable_hash(
        "carry2pc.abort-no-intent.v1", {"twin_id": twin_id, "tx_id": tx_id}
    )


@dataclass(frozen=True, order=True)
class StateEntry:
    key: str
    value_json: str

    def __post_init__(self) -> None:
        if not self.key:
            raise ValueError("state key must not be empty")
        if not self.value_json:
            raise ValueError("state value must not be empty")


@dataclass(frozen=True)
class AuthorizationContext:
    subject: str
    scopes: tuple[str, ...]
    revocation_version: int
    credential_digest: str

    def __post_init__(self) -> None:
        if not self.subject:
            raise ValueError("authorization subject must not be empty")
        if not self.credential_digest:
            raise ValueError("credential digest must not be empty")
        if any(not scope for scope in self.scopes):
            raise ValueError("authorization scopes must not be empty")
        _require_unique(self.scopes, "authorization scopes")
        if self.revocation_version < 0:
            raise ValueError("revocation_version must be non-negative")


@dataclass(frozen=True, order=True)
class InputFrontier:
    producer: str
    last_sequence: int
    last_event_hash: str

    def __post_init__(self) -> None:
        if not self.producer:
            raise ValueError("frontier producer must not be empty")
        if not self.last_event_hash:
            raise ValueError("frontier event hash must not be empty")
        if self.last_sequence < 0:
            raise ValueError("input sequence must be non-negative")


@dataclass(frozen=True, order=True)
class ReadVersion:
    key: str
    version: int

    def __post_init__(self) -> None:
        if not self.key:
            raise ValueError("read key must not be empty")
        if self.version < 0:
            raise ValueError("read version must be non-negative")


@dataclass(frozen=True, order=True)
class WriteIntent:
    key: str
    value_json: str

    def __post_init__(self) -> None:
        if not self.key:
            raise ValueError("write key must not be empty")
        if not self.value_json:
            raise ValueError("write body must not be empty")


@dataclass(frozen=True, order=True)
class CommandIntent:
    command_id: str
    payload_json: str

    def __post_init__(self) -> None:
        if not self.command_id.startswith(TRANSACTION_COMMAND_PREFIX):
            raise ValueError("prepared command_id must use the transaction namespace")
        if not self.payload_json:
            raise ValueError("command body must not be empty")

    @property
    def payload_digest(self) -> str:
        return stable_hash("carry2pc.command-payload.v1", self.payload_json)


@dataclass(frozen=True, order=True)
class UpdateCommand:
    command_id: str
    payload_json: str

    def __post_init__(self) -> None:
        if not self.command_id.startswith(UPDATE_COMMAND_PREFIX):
            raise ValueError("update command_id must use the update namespace")
        if not self.payload_json:
            raise ValueError("command body must not be empty")

    @property
    def payload_digest(self) -> str:
        return stable_hash("carry2pc.command-payload.v1", self.payload_json)


@dataclass(frozen=True)
class PreparedRecord:
    tx_id: str
    participant_set: tuple[str, ...]
    reads: tuple[ReadVersion, ...]
    writes: tuple[WriteIntent, ...]
    locks: tuple[str, ...]
    commands: tuple[CommandIntent, ...]
    prepare_epoch: int

    def __post_init__(self) -> None:
        if not self.tx_id:
            raise ValueError("tx_id must not be empty")
        if any(not participant for participant in self.participant_set):
            raise ValueError("participants must not be empty")
        if any(not lock for lock in self.locks):
            raise ValueError("locks must not be empty")
        _require_unique(self.participant_set, "participant_set")
        _require_unique((entry.key for entry in self.reads), "read keys")
        _require_unique((entry.key for entry in self.writes), "write keys")
        _require_unique(self.locks, "locks")
        _require_unique(
            (command.command_id for command in self.commands), "command ids"
        )
        if self.prepare_epoch < 0:
            raise ValueError("prepare_epoch must be non-negative")
        uncovered_writes = {entry.key for entry in self.writes}.difference(self.locks)
        if uncovered_writes:
            raise ValueError(
                f"prepared writes require matching locks: {sorted(uncovered_writes)}"
            )

    @property
    def participant_set_digest(self) -> str:
        return stable_hash("carry2pc.participants.v1", self.participant_set)

    @property
    def intent_digest(self) -> str:
        return stable_hash(
            "carry2pc.intent.v2",
            {"writes": self.writes, "commands": self.commands},
        )

    @property
    def lock_digest(self) -> str:
        return stable_hash("carry2pc.locks.v1", self.locks)

    @property
    def digest(self) -> str:
        return stable_hash("carry2pc.prepared_record.v2", self)


@dataclass(frozen=True)
class PreparedObligation:
    record: PreparedRecord
    yes_certificate: YesCertificate

    def validate(self, twin_id: str) -> None:
        certificate = self.yes_certificate
        if certificate.tx_id != self.record.tx_id or certificate.twin_id != twin_id:
            raise ValueError("YES certificate identity does not match prepared record")
        if certificate.prepare_epoch != self.record.prepare_epoch:
            raise ValueError("YES certificate prepare epoch does not match record")
        if certificate.participant_set != self.record.participant_set:
            raise ValueError("YES certificate participant set does not match record")
        if certificate.intent_digest != self.record.intent_digest:
            raise ValueError("YES certificate does not bind the prepared intent")
        if certificate.lock_digest != self.record.lock_digest:
            raise ValueError("YES certificate does not bind the prepared locks")
        if certificate.prepared_record_digest != self.record.digest:
            raise ValueError("YES certificate does not bind the prepared record")
        for command_index, command in enumerate(self.record.commands):
            if command.command_id != stable_command_id(
                twin_id, self.record.tx_id, command_index
            ):
                raise ValueError(
                    "prepared command_id does not match its reserved position"
                )


@dataclass(frozen=True, order=True)
class DecisionTombstone:
    tx_id: str
    decision: Decision
    decision_record_digest: str
    applied_version: int
    intent_digest: str

    def __post_init__(self) -> None:
        if not self.tx_id:
            raise ValueError("decision tx_id must not be empty")
        if not self.decision_record_digest or not self.intent_digest:
            raise ValueError("decision digests must not be empty")
        if self.applied_version < 0:
            raise ValueError("applied_version must be non-negative")


@dataclass(frozen=True, order=True)
class OutboxEntry:
    command_id: str
    operation_id: str
    command_index: int
    payload_json: str
    status: OutboxStatus = OutboxStatus.PENDING

    def __post_init__(self) -> None:
        if not self.command_id or not self.operation_id:
            raise ValueError("outbox command and operation ids must not be empty")
        if self.command_index < 0:
            raise ValueError("outbox command_index must be non-negative")
        if not self.command_id.startswith(
            (TRANSACTION_COMMAND_PREFIX, UPDATE_COMMAND_PREFIX)
        ):
            raise ValueError("outbox command_id has an unknown namespace")
        if not self.payload_json:
            raise ValueError("outbox command body must not be empty")

    @property
    def payload_digest(self) -> str:
        return stable_hash("carry2pc.command-payload.v1", self.payload_json)

    @property
    def binding(self) -> tuple[str, str, int, str]:
        return (
            self.command_id,
            self.operation_id,
            self.command_index,
            self.payload_json,
        )


@dataclass(frozen=True)
class TwinCapsule:
    twin_id: str
    version: int
    state: tuple[StateEntry, ...]
    authorization: AuthorizationContext
    input_frontier: tuple[InputFrontier, ...]
    prepared: tuple[PreparedObligation, ...]
    decisions: tuple[DecisionTombstone, ...]
    outbox: tuple[OutboxEntry, ...]

    def __post_init__(self) -> None:
        if not self.twin_id:
            raise ValueError("capsule twin_id must not be empty")
        if self.version < 0:
            raise ValueError("capsule version must be non-negative")
        _require_unique((entry.key for entry in self.state), "state keys")
        _require_unique(
            (entry.producer for entry in self.input_frontier), "frontier producers"
        )
        prepared_ids = tuple(item.record.tx_id for item in self.prepared)
        decision_ids = tuple(item.tx_id for item in self.decisions)
        _require_unique(prepared_ids, "prepared tx ids")
        _require_unique(decision_ids, "decision tombstones")
        _require_unique((item.command_id for item in self.outbox), "outbox command ids")
        for item in self.outbox:
            if item.command_id.startswith(TRANSACTION_COMMAND_PREFIX):
                expected_id = stable_command_id(
                    self.twin_id, item.operation_id, item.command_index
                )
            else:
                expected_id = stable_update_command_id(
                    self.twin_id, item.operation_id, item.command_index
                )
            if item.command_id != expected_id:
                raise ValueError(
                    "outbox command_id does not match its reserved position"
                )
        reserved_command_ids = tuple(
            command.command_id
            for obligation in self.prepared
            for command in obligation.record.commands
        )
        _require_unique(reserved_command_ids, "reserved prepared command ids")
        consumed_reservations = set(reserved_command_ids).intersection(
            item.command_id for item in self.outbox
        )
        if consumed_reservations:
            raise ValueError(
                "unresolved prepared commands cannot already exist in the outbox: "
                f"{sorted(consumed_reservations)}"
            )
        overlap = set(prepared_ids).intersection(decision_ids)
        if overlap:
            raise ValueError(
                f"transactions cannot be both prepared and resolved: {sorted(overlap)}"
            )
        for obligation in self.prepared:
            obligation.validate(self.twin_id)

    @property
    def root(self) -> str:
        return stable_hash("carry2pc.authoritative_capsule.v3", self)

    def obligation(self, tx_id: str) -> PreparedObligation | None:
        return next(
            (item for item in self.prepared if item.record.tx_id == tx_id), None
        )

    def tombstone(self, tx_id: str) -> DecisionTombstone | None:
        return next((item for item in self.decisions if item.tx_id == tx_id), None)

    def with_obligation(self, obligation: PreparedObligation) -> "TwinCapsule":
        if self.obligation(obligation.record.tx_id) is not None:
            raise ValueError(f"transaction already prepared: {obligation.record.tx_id}")
        prepared = tuple(
            sorted((*self.prepared, obligation), key=lambda item: item.record.tx_id)
        )
        return replace(self, prepared=prepared)

    def without_obligation(self, tx_id: str) -> "TwinCapsule":
        return replace(
            self,
            prepared=tuple(
                item for item in self.prepared if item.record.tx_id != tx_id
            ),
        )

    def updated(
        self,
        *,
        update_id: str,
        writes: Iterable[StateEntry],
        commands: Iterable[UpdateCommand],
    ) -> tuple["TwinCapsule", tuple[str, ...]]:
        """Apply a prevalidated nontransactional update without touching P or D."""
        if not update_id:
            raise ValueError("update_id must not be empty")
        next_state = {entry.key: entry for entry in self.state}
        for write in writes:
            next_state[write.key] = write
        outbox = {entry.command_id: entry for entry in self.outbox}
        enqueued: list[str] = []
        for command_index, command in enumerate(commands):
            expected_id = stable_update_command_id(
                self.twin_id, update_id, command_index
            )
            if command.command_id != expected_id:
                raise ValueError(
                    "nontransactional command_id must use its reserved update position"
                )
            candidate = OutboxEntry(
                command_id=command.command_id,
                operation_id=update_id,
                command_index=command_index,
                payload_json=command.payload_json,
            )
            existing = outbox.get(command.command_id)
            if existing is not None and existing.binding != candidate.binding:
                raise ValueError(f"outbox command collision: {command.command_id}")
            if existing is None:
                outbox[command.command_id] = candidate
                enqueued.append(command.command_id)
        return (
            replace(
                self,
                version=self.version + 1,
                state=tuple(sorted(next_state.values())),
                outbox=tuple(sorted(outbox.values())),
            ),
            tuple(enqueued),
        )

    def resolved(
        self,
        *,
        obligation: PreparedObligation,
        decision_certificate: DecisionCertificate,
    ) -> tuple["TwinCapsule", tuple[str, ...]]:
        record = obligation.record
        next_state = {entry.key: entry for entry in self.state}
        enqueued: list[str] = []
        outbox = {entry.command_id: entry for entry in self.outbox}
        next_version = self.version
        if decision_certificate.decision is Decision.COMMIT:
            for write in record.writes:
                next_state[write.key] = StateEntry(write.key, write.value_json)
            for command_index, command in enumerate(record.commands):
                existing = outbox.get(command.command_id)
                candidate = OutboxEntry(
                    command_id=command.command_id,
                    operation_id=record.tx_id,
                    command_index=command_index,
                    payload_json=command.payload_json,
                )
                if existing is not None and existing.binding != candidate.binding:
                    raise ValueError(f"outbox command collision: {command.command_id}")
                if existing is None:
                    outbox[command.command_id] = candidate
                    enqueued.append(command.command_id)
            next_version += 1
        tombstone = DecisionTombstone(
            tx_id=record.tx_id,
            decision=decision_certificate.decision,
            decision_record_digest=decision_certificate.record_digest,
            applied_version=next_version,
            intent_digest=record.intent_digest,
        )
        decisions = tuple(
            sorted((*self.decisions, tombstone), key=lambda item: item.tx_id)
        )
        return (
            replace(
                self.without_obligation(record.tx_id),
                version=next_version,
                state=tuple(sorted(next_state.values())),
                decisions=decisions,
                outbox=tuple(sorted(outbox.values())),
            ),
            tuple(enqueued),
        )

    def aborted_without_obligation(
        self,
        *,
        twin_id: str,
        tx_id: str,
        decision_certificate: DecisionCertificate,
    ) -> tuple["TwinCapsule", tuple[str, ...]]:
        """Record an ABORT for a participant that never acquired a YES obligation."""
        if decision_certificate.decision is not Decision.ABORT:
            raise ValueError("only ABORT may resolve without a prepared obligation")
        tombstone = DecisionTombstone(
            tx_id=tx_id,
            decision=Decision.ABORT,
            decision_record_digest=decision_certificate.record_digest,
            applied_version=self.version,
            intent_digest=abort_intent_digest(twin_id, tx_id),
        )
        decisions = tuple(
            sorted((*self.decisions, tombstone), key=lambda item: item.tx_id)
        )
        return replace(self, decisions=decisions), ()


def capsule_to_bytes(capsule: TwinCapsule) -> bytes:
    """Return the canonical wire representation certified during handover."""
    return canonical_json(capsule).encode("utf-8")


def capsule_from_bytes(payload: bytes) -> TwinCapsule:
    """Parse and validate a canonical capsule received from an untrusted peer."""
    if not isinstance(payload, bytes):
        raise ValueError("capsule payload must be bytes")
    try:
        raw = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("capsule payload is not valid UTF-8 JSON") from exc
    root = _object(
        raw,
        {
            "twin_id",
            "version",
            "state",
            "authorization",
            "input_frontier",
            "prepared",
            "decisions",
            "outbox",
        },
        "capsule",
    )

    authorization_raw = _object(
        root["authorization"],
        {"subject", "scopes", "revocation_version", "credential_digest"},
        "authorization",
    )
    authorization = AuthorizationContext(
        subject=_text(authorization_raw["subject"], "authorization.subject"),
        scopes=tuple(
            _text(item, "authorization.scope")
            for item in _items(authorization_raw["scopes"], "authorization.scopes")
        ),
        revocation_version=_integer(
            authorization_raw["revocation_version"],
            "authorization.revocation_version",
        ),
        credential_digest=_text(
            authorization_raw["credential_digest"],
            "authorization.credential_digest",
        ),
    )

    state: list[StateEntry] = []
    for item in _items(root["state"], "state"):
        entry = _object(item, {"key", "value_json"}, "state entry")
        state.append(
            StateEntry(
                _text(entry["key"], "state.key"),
                _text(entry["value_json"], "state.value_json"),
            )
        )

    frontier: list[InputFrontier] = []
    for item in _items(root["input_frontier"], "input_frontier"):
        entry = _object(
            item,
            {"producer", "last_sequence", "last_event_hash"},
            "frontier entry",
        )
        frontier.append(
            InputFrontier(
                producer=_text(entry["producer"], "frontier.producer"),
                last_sequence=_integer(
                    entry["last_sequence"], "frontier.last_sequence"
                ),
                last_event_hash=_text(
                    entry["last_event_hash"], "frontier.last_event_hash"
                ),
            )
        )

    prepared: list[PreparedObligation] = []
    for item in _items(root["prepared"], "prepared"):
        obligation_raw = _object(
            item, {"record", "yes_certificate"}, "prepared obligation"
        )
        record_raw = _object(
            obligation_raw["record"],
            {
                "tx_id",
                "participant_set",
                "reads",
                "writes",
                "locks",
                "commands",
                "prepare_epoch",
            },
            "prepared record",
        )
        reads = []
        for value in _items(record_raw["reads"], "prepared reads"):
            entry = _object(value, {"key", "version"}, "read version")
            reads.append(
                ReadVersion(
                    _text(entry["key"], "read.key"),
                    _integer(entry["version"], "read.version"),
                )
            )
        writes = []
        for value in _items(record_raw["writes"], "prepared writes"):
            entry = _object(value, {"key", "value_json"}, "write intent")
            writes.append(
                WriteIntent(
                    _text(entry["key"], "write.key"),
                    _text(entry["value_json"], "write.value_json"),
                )
            )
        commands = []
        for value in _items(record_raw["commands"], "prepared commands"):
            entry = _object(value, {"command_id", "payload_json"}, "command")
            commands.append(
                CommandIntent(
                    _text(entry["command_id"], "command.command_id"),
                    _text(entry["payload_json"], "command.payload_json"),
                )
            )
        record = PreparedRecord(
            tx_id=_text(record_raw["tx_id"], "record.tx_id"),
            participant_set=tuple(
                _text(value, "record.participant")
                for value in _items(
                    record_raw["participant_set"], "record.participant_set"
                )
            ),
            reads=tuple(reads),
            writes=tuple(writes),
            locks=tuple(
                _text(value, "record.lock")
                for value in _items(record_raw["locks"], "record.locks")
            ),
            commands=tuple(commands),
            prepare_epoch=_integer(
                record_raw["prepare_epoch"], "record.prepare_epoch"
            ),
        )
        yes_raw = _object(
            obligation_raw["yes_certificate"],
            {
                "tx_id",
                "twin_id",
                "prepare_epoch",
                "participant_set",
                "intent_digest",
                "lock_digest",
                "prepared_record_digest",
                "proof",
            },
            "YES certificate",
        )
        proof_raw = _object(
            yes_raw["proof"],
            {"group_id", "configuration", "signers", "subject_hash"},
            "YES proof",
        )
        proof = QuorumProof(
            group_id=_text(proof_raw["group_id"], "proof.group_id"),
            configuration=_integer(
                proof_raw["configuration"], "proof.configuration"
            ),
            signers=tuple(
                _text(value, "proof.signer")
                for value in _items(proof_raw["signers"], "proof.signers")
            ),
            subject_hash=_text(proof_raw["subject_hash"], "proof.subject_hash"),
        )
        prepared.append(
            PreparedObligation(
                record=record,
                yes_certificate=YesCertificate(
                    tx_id=_text(yes_raw["tx_id"], "yes.tx_id"),
                    twin_id=_text(yes_raw["twin_id"], "yes.twin_id"),
                    prepare_epoch=_integer(
                        yes_raw["prepare_epoch"], "yes.prepare_epoch"
                    ),
                    participant_set=tuple(
                        _text(value, "yes.participant")
                        for value in _items(
                            yes_raw["participant_set"], "yes.participant_set"
                        )
                    ),
                    intent_digest=_text(
                        yes_raw["intent_digest"], "yes.intent_digest"
                    ),
                    lock_digest=_text(yes_raw["lock_digest"], "yes.lock_digest"),
                    prepared_record_digest=_text(
                        yes_raw["prepared_record_digest"],
                        "yes.prepared_record_digest",
                    ),
                    proof=proof,
                ),
            )
        )

    decisions: list[DecisionTombstone] = []
    for item in _items(root["decisions"], "decisions"):
        entry = _object(
            item,
            {
                "tx_id",
                "decision",
                "decision_record_digest",
                "applied_version",
                "intent_digest",
            },
            "decision tombstone",
        )
        try:
            decision = Decision(_text(entry["decision"], "decision.decision"))
        except ValueError as exc:
            raise ValueError("decision.decision is invalid") from exc
        decisions.append(
            DecisionTombstone(
                tx_id=_text(entry["tx_id"], "decision.tx_id"),
                decision=decision,
                decision_record_digest=_text(
                    entry["decision_record_digest"],
                    "decision.decision_record_digest",
                ),
                applied_version=_integer(
                    entry["applied_version"], "decision.applied_version"
                ),
                intent_digest=_text(
                    entry["intent_digest"], "decision.intent_digest"
                ),
            )
        )

    outbox: list[OutboxEntry] = []
    for item in _items(root["outbox"], "outbox"):
        entry = _object(
            item,
            {
                "command_id",
                "operation_id",
                "command_index",
                "payload_json",
                "status",
            },
            "outbox entry",
        )
        try:
            status = OutboxStatus(_text(entry["status"], "outbox.status"))
        except ValueError as exc:
            raise ValueError("outbox.status is invalid") from exc
        outbox.append(
            OutboxEntry(
                command_id=_text(entry["command_id"], "outbox.command_id"),
                operation_id=_text(entry["operation_id"], "outbox.operation_id"),
                command_index=_integer(
                    entry["command_index"], "outbox.command_index"
                ),
                payload_json=_text(entry["payload_json"], "outbox.payload_json"),
                status=status,
            )
        )

    capsule = TwinCapsule(
        twin_id=_text(root["twin_id"], "capsule.twin_id"),
        version=_integer(root["version"], "capsule.version"),
        state=tuple(state),
        authorization=authorization,
        input_frontier=tuple(frontier),
        prepared=tuple(prepared),
        decisions=tuple(decisions),
        outbox=tuple(outbox),
    )
    if capsule_to_bytes(capsule) != payload:
        raise ValueError("capsule payload is not canonically encoded")
    return capsule


@dataclass(frozen=True)
class AuthoritativeTwin:
    twin_id: str
    epoch: int
    owner: str
    mode: OwnerMode
    capsule: TwinCapsule
    pending_transfer_id: str | None = None

    def __post_init__(self) -> None:
        if not self.twin_id:
            raise ValueError("authoritative twin_id must not be empty")
        if self.epoch < 0:
            raise ValueError("ownership epoch must be non-negative")
        if self.capsule.twin_id != self.twin_id:
            raise ValueError("capsule twin_id does not match authoritative twin")
        pending_mode = self.mode in {OwnerMode.FROZEN, OwnerMode.STAGING}
        if pending_mode != (self.pending_transfer_id is not None):
            raise ValueError(
                "FROZEN/STAGING twins require one pending transfer lineage and "
                "terminal/serving twins must clear it"
            )
        if self.pending_transfer_id == "":
            raise ValueError("pending transfer lineage must not be empty")

    @property
    def capsule_root(self) -> str:
        return self.capsule.root
