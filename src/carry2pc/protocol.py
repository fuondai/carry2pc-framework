"""Carry2PC state machine for prepared-obligation-preserving handover."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Iterable

from carry2pc.canonical import stable_hash
from carry2pc.certificates import (
    ActivateCertificate,
    CertificateIssuer,
    DecisionCertificate,
    FreezeCertificate,
    InstallCertificate,
    OwnerCertificate,
    QuorumRegistry,
    ResumeCertificate,
    YesCertificate,
)
from carry2pc.schemas import (
    AuthoritativeTwin,
    AuthorizationContext,
    CommandIntent,
    InputFrontier,
    PreparedObligation,
    PreparedRecord,
    ReadVersion,
    StateEntry,
    TwinCapsule,
    UpdateCommand,
    WriteIntent,
    abort_intent_digest,
    capsule_from_bytes,
    capsule_to_bytes,
    stable_command_id,
    stable_update_command_id,
)
from carry2pc.types import Decision, OwnerMode


class ProtocolError(RuntimeError):
    pass


@dataclass
class HandoverRecord:
    transfer_id: str
    freeze: FreezeCertificate
    install: InstallCertificate | None = None
    activate: ActivateCertificate | None = None
    resume: ResumeCertificate | None = None
    successor_owner: OwnerCertificate | None = None
    terminal_deliveries: set[str] = field(default_factory=set)

    @property
    def terminal(self) -> bool:
        return self.activate is not None or self.resume is not None


@dataclass(frozen=True)
class ResolutionResult:
    twin_id: str
    tx_id: str
    decision: Decision
    owner: str
    owner_epoch: int
    applied_now: bool
    enqueued_commands: tuple[str, ...]


class Carry2PC:
    def __init__(
        self,
        *,
        quorum_registry: QuorumRegistry,
        ownership_group: str = "ownership",
        decision_group: str = "decision",
    ) -> None:
        self.registry = quorum_registry
        self.issuer = CertificateIssuer(quorum_registry)
        self.ownership_group = ownership_group
        self.decision_group = decision_group
        self.copies: dict[tuple[str, str], AuthoritativeTwin] = {}
        self.owners: dict[str, OwnerCertificate] = {}
        self.owner_history: dict[str, list[OwnerCertificate]] = {}
        self.handovers: dict[str, HandoverRecord] = {}
        self.decisions: dict[str, DecisionCertificate] = {}
        self.yes_history: dict[tuple[str, str], YesCertificate] = {}
        self.outbox_enqueue_counts: dict[str, int] = {}
        self.outbox_enqueue_bindings: dict[str, tuple[str, str, int, str]] = {}
        self.decision_inbox: dict[tuple[str, str, str, str], int] = {}
        self.decision_delivery_counts: dict[tuple[str, str, str, str], int] = {}
        self._log_cut = 0

    @staticmethod
    def shard_group(shard_id: str) -> str:
        return f"shard:{shard_id}"

    def initialize_twin(
        self,
        *,
        twin_id: str,
        owner: str,
        state: Iterable[StateEntry],
        authorization: AuthorizationContext,
        input_frontier: Iterable[InputFrontier] = (),
    ) -> OwnerCertificate:
        if twin_id in self.owners:
            raise ProtocolError(f"twin already initialized: {twin_id}")
        owner_certificate = self.issuer.owner(
            group_id=self.ownership_group,
            twin_id=twin_id,
            epoch=0,
            owner=owner,
            previous_certificate_digest="",
        )
        capsule = TwinCapsule(
            twin_id=twin_id,
            version=0,
            state=tuple(sorted(state)),
            authorization=authorization,
            input_frontier=tuple(sorted(input_frontier)),
            prepared=(),
            decisions=(),
            outbox=(),
        )
        self.copies[(owner, twin_id)] = AuthoritativeTwin(
            twin_id=twin_id,
            epoch=0,
            owner=owner,
            mode=OwnerMode.ACTIVE,
            capsule=capsule,
        )
        self.owners[twin_id] = owner_certificate
        self.owner_history[twin_id] = [owner_certificate]
        return owner_certificate

    def active_twin(self, twin_id: str) -> AuthoritativeTwin:
        owner_certificate = self._owner_certificate(twin_id)
        twin = self._copy(owner_certificate.owner, twin_id)
        if twin.mode is not OwnerMode.ACTIVE:
            raise ProtocolError(f"current owner is not active for twin {twin_id}")
        if twin.epoch != owner_certificate.epoch:
            raise ProtocolError("owner certificate epoch does not match active twin")
        return twin

    def prepare(
        self,
        *,
        tx_id: str,
        twin_id: str,
        participant_set: Iterable[str],
        reads: Iterable[ReadVersion],
        writes: Iterable[WriteIntent],
        locks: Iterable[str],
        commands: Iterable[CommandIntent] = (),
    ) -> YesCertificate:
        twin = self.active_twin(twin_id)
        participants = tuple(sorted(participant_set))
        if twin_id not in participants:
            raise ProtocolError("participant set must contain the prepared twin")
        if (tx_id, twin_id) in self.yes_history:
            existing = twin.capsule.obligation(tx_id)
            if existing is None:
                raise ProtocolError(
                    "durable YES exists without an unresolved obligation"
                )
            return existing.yes_certificate
        normalized_locks = tuple(sorted(locks))
        normalized_writes = tuple(sorted(writes))
        uncovered_writes = {write.key for write in normalized_writes}.difference(
            normalized_locks
        )
        if uncovered_writes:
            raise ProtocolError(
                f"prepared writes require matching locks: {sorted(uncovered_writes)}"
            )
        held_locks = {
            lock
            for obligation in twin.capsule.prepared
            for lock in obligation.record.locks
        }
        overlap = held_locks.intersection(normalized_locks)
        if overlap:
            raise ProtocolError(f"conflicting locks are held: {sorted(overlap)}")
        normalized_commands = tuple(commands)
        for command_index, command in enumerate(normalized_commands):
            expected_id = stable_command_id(twin_id, tx_id, command_index)
            if command.command_id != expected_id:
                raise ProtocolError(
                    "command_id must be derived from twin_id, tx_id, and command index"
                )
        record = PreparedRecord(
            tx_id=tx_id,
            participant_set=participants,
            reads=tuple(sorted(reads)),
            writes=normalized_writes,
            locks=normalized_locks,
            commands=normalized_commands,
            prepare_epoch=twin.epoch,
        )
        yes_certificate = self.issuer.yes(
            group_id=self.shard_group(twin.owner),
            tx_id=tx_id,
            twin_id=twin_id,
            prepare_epoch=twin.epoch,
            participant_set=participants,
            intent_digest=record.intent_digest,
            lock_digest=record.lock_digest,
            prepared_record_digest=record.digest,
        )
        obligation = PreparedObligation(record=record, yes_certificate=yes_certificate)
        self._validate_obligation(obligation, twin_id, "prepared")
        if not yes_certificate.verify(
            self.registry,
            expected_group_id=self.shard_group(twin.owner),
        ):
            raise ProtocolError("prepared YES certificate failed quorum verification")
        updated = replace(twin, capsule=twin.capsule.with_obligation(obligation))
        self.copies[(twin.owner, twin_id)] = updated
        self.yes_history[(tx_id, twin_id)] = yes_certificate
        return yes_certificate

    def update(
        self,
        *,
        update_id: str,
        twin_id: str,
        writes: Iterable[WriteIntent],
        locks: Iterable[str],
        commands: Iterable[UpdateCommand] = (),
    ) -> tuple[str, ...]:
        """Apply a prevalidated nontransactional operation at the active owner."""
        twin = self.active_twin(twin_id)
        normalized_locks = tuple(sorted(locks))
        held_locks = {
            lock
            for obligation in twin.capsule.prepared
            for lock in obligation.record.locks
        }
        overlap = held_locks.intersection(normalized_locks)
        if overlap:
            raise ProtocolError(f"conflicting locks are held: {sorted(overlap)}")
        normalized_writes = tuple(sorted(writes))
        if not {write.key for write in normalized_writes}.issubset(normalized_locks):
            raise ProtocolError("update locks must cover every written key")
        normalized_commands = tuple(commands)
        for command_index, command in enumerate(normalized_commands):
            expected_id = stable_update_command_id(twin_id, update_id, command_index)
            if command.command_id != expected_id:
                raise ProtocolError(
                    "command_id must be derived from twin_id, update_id, and command index"
                )
        try:
            updated_capsule, enqueued = twin.capsule.updated(
                update_id=update_id,
                writes=(
                    StateEntry(write.key, write.value_json)
                    for write in normalized_writes
                ),
                commands=normalized_commands,
            )
        except ValueError as exc:
            raise ProtocolError(
                "nontransactional update violates capsule integrity"
            ) from exc
        self.copies[(twin.owner, twin_id)] = replace(twin, capsule=updated_capsule)
        self._record_enqueues(updated_capsule, enqueued)
        return enqueued

    def decide(
        self,
        *,
        tx_id: str,
        decision: Decision,
        participant_set: Iterable[str],
        yes_certificates: Iterable[YesCertificate] = (),
    ) -> DecisionCertificate:
        participants = tuple(sorted(participant_set))
        existing = self.decisions.get(tx_id)
        if existing is not None:
            if (
                existing.decision is not decision
                or existing.participant_set != participants
            ):
                raise ProtocolError(
                    f"conflicting global decision for transaction {tx_id}"
                )
            return existing
        certificates = tuple(yes_certificates)
        certificate_by_twin = {
            certificate.twin_id: certificate for certificate in certificates
        }
        if len(certificate_by_twin) != len(certificates):
            raise ProtocolError("duplicate YES certificate for one participant")
        if decision is Decision.COMMIT and set(certificate_by_twin) != set(
            participants
        ):
            raise ProtocolError("COMMIT requires one YES certificate per participant")
        for twin_id, certificate in certificate_by_twin.items():
            if not certificate.verify(
                self.registry,
                expected_group_id=self._yes_group_id(certificate),
            ):
                raise ProtocolError(
                    f"invalid YES certificate for participant {twin_id}"
                )
            if (
                certificate.tx_id != tx_id
                or certificate.participant_set != participants
            ):
                raise ProtocolError(
                    "YES certificate does not match transaction proposal"
                )
            issued = self.yes_history.get((tx_id, twin_id))
            if issued is None or issued.subject_hash != certificate.subject_hash:
                raise ProtocolError(
                    "YES certificate is not backed by a durable participant record"
                )
            self._validate_yes_source_binding(certificate)
        record_digest_pairs = tuple(
            sorted(
                (twin_id, certificate.subject_hash)
                for twin_id, certificate in certificate_by_twin.items()
            )
        )
        decision_certificate = self.issuer.decision(
            group_id=self.decision_group,
            tx_id=tx_id,
            decision=decision,
            participant_set=participants,
            yes_record_digests=record_digest_pairs,
        )
        if not decision_certificate.verify(
            self.registry, expected_group_id=self.decision_group
        ):
            raise ProtocolError(
                "global decision certificate failed quorum verification"
            )
        self.decisions[tx_id] = decision_certificate
        return decision_certificate

    def restore_decision_evidence(
        self,
        decision_certificate: DecisionCertificate,
        yes_certificates: Iterable[YesCertificate] = (),
        *,
        expected_source_groups: dict[str, str] | None = None,
    ) -> None:
        """Restore durable TDS/YES evidence before a successor serves a capsule.

        A deployment recovery layer supplies these records from the TDS and
        shard logs.  They are deliberately restored separately from the
        mobile capsule: the capsule carries the intent needed for resolution,
        while the service records authenticate the decision and its provenance.
        """
        if not decision_certificate.verify(
            self.registry, expected_group_id=self.decision_group
        ):
            raise ProtocolError("invalid DecisionQC during evidence restore")
        existing = self.decisions.get(decision_certificate.tx_id)
        if existing is not None and existing != decision_certificate:
            raise ProtocolError("conflicting durable TDS record during restore")
        certificates = tuple(yes_certificates)
        by_twin = {certificate.twin_id: certificate for certificate in certificates}
        if len(by_twin) != len(certificates):
            raise ProtocolError("duplicate YES certificate during evidence restore")
        participants = set(decision_certificate.participant_set)
        if not set(by_twin).issubset(participants):
            raise ProtocolError("restored YES certificate names a non-participant")
        if (
            decision_certificate.decision is Decision.COMMIT
            and set(by_twin) != participants
        ):
            raise ProtocolError("COMMIT restore requires one YES per participant")
        decision_bindings = dict(decision_certificate.yes_record_digests)
        source_groups = expected_source_groups or {}
        restored: list[tuple[tuple[str, str], YesCertificate]] = []
        for twin_id, certificate in by_twin.items():
            if certificate.tx_id != decision_certificate.tx_id:
                raise ProtocolError(
                    "restored YES certificate has the wrong transaction"
                )
            if certificate.participant_set != decision_certificate.participant_set:
                raise ProtocolError(
                    "restored YES certificate has the wrong participants"
                )
            expected_digest = decision_bindings.get(twin_id)
            if expected_digest is not None and certificate.subject_hash != expected_digest:
                raise ProtocolError(
                    "restored YES certificate does not match DecisionQC"
                )
            expected_group = source_groups.get(twin_id)
            prior = self.yes_history.get((certificate.tx_id, twin_id))
            if prior is None and expected_group is None:
                raise ProtocolError(
                    "expected source-shard binding is required during recovery"
                )
            if expected_group is not None and certificate.proof.group_id != expected_group:
                raise ProtocolError(
                    "restored YES certificate has the wrong source-shard binding"
                )
            if not certificate.verify(
                self.registry,
                expected_group_id=self._yes_group_id(certificate),
            ):
                raise ProtocolError("invalid YES certificate during evidence restore")
            if prior is not None and prior != certificate:
                raise ProtocolError("conflicting durable YES record during restore")
            self._validate_yes_source_binding(
                certificate, expected_group_id=expected_group
            )
            restored.append(((certificate.tx_id, twin_id), certificate))
        for key, certificate in restored:
            self.yes_history[key] = certificate
        self.decisions[decision_certificate.tx_id] = decision_certificate

    def freeze(self, *, twin_id: str, target: str) -> FreezeCertificate:
        source_twin = self.active_twin(twin_id)
        if target == source_twin.owner:
            raise ProtocolError("handover target must differ from source")
        owner_certificate = self._owner_certificate(twin_id)
        self._log_cut += 1
        transfer_id = stable_hash(
            "carry2pc.transfer.v1",
            {
                "twin_id": twin_id,
                "epoch": source_twin.epoch,
                "source": source_twin.owner,
                "target": target,
                "cut": self._log_cut,
            },
        )
        frozen = replace(
            source_twin,
            mode=OwnerMode.FROZEN,
            pending_transfer_id=transfer_id,
        )
        self.copies[(source_twin.owner, twin_id)] = frozen
        certificate = self.issuer.freeze(
            group_id=self.shard_group(source_twin.owner),
            transfer_id=transfer_id,
            twin_id=twin_id,
            epoch=source_twin.epoch,
            source=source_twin.owner,
            target=target,
            cut=self._log_cut,
            capsule_root=frozen.capsule_root,
            owner_certificate_digest=owner_certificate.digest,
        )
        self.handovers[transfer_id] = HandoverRecord(
            transfer_id=transfer_id,
            freeze=certificate,
        )
        return certificate

    def install(
        self,
        freeze: FreezeCertificate,
        *,
        capsule_bytes: bytes | None = None,
        expected_source_groups: dict[tuple[str, str], str] | None = None,
    ) -> InstallCertificate:
        if not freeze.verify(
            self.registry, expected_group_id=self.shard_group(freeze.source)
        ):
            raise ProtocolError("invalid FreezeQC")
        handover = self._handover(freeze.transfer_id)
        if handover.freeze.digest != freeze.digest:
            raise ProtocolError("FreezeQC does not match handover record")
        if handover.terminal:
            raise ProtocolError("cannot install after terminal handover outcome")
        if handover.install is not None:
            return handover.install
        current_owner = self._owner_certificate(freeze.twin_id)
        if not current_owner.verify(
            self.registry, expected_group_id=self.ownership_group
        ):
            raise ProtocolError("current OwnerQC failed quorum verification")
        if (
            current_owner.digest != freeze.owner_certificate_digest
            or current_owner.owner != freeze.source
            or current_owner.epoch != freeze.epoch
        ):
            raise ProtocolError("FreezeQC does not extend the current OwnerQC")
        source = self._copy(freeze.source, freeze.twin_id)
        if (
            source.mode is not OwnerMode.FROZEN
            or source.pending_transfer_id != freeze.transfer_id
            or source.capsule_root != freeze.capsule_root
        ):
            raise ProtocolError("source no longer matches certified freeze cut")
        wire_capsule = (
            capsule_to_bytes(source.capsule)
            if capsule_bytes is None
            else capsule_bytes
        )
        try:
            reconstructed_capsule = capsule_from_bytes(wire_capsule)
        except (TypeError, ValueError) as exc:
            raise ProtocolError("target rejected malformed capsule bytes") from exc
        if reconstructed_capsule.root != freeze.capsule_root:
            raise ProtocolError("target capsule bytes do not match FreezeQC root")
        staged = AuthoritativeTwin(
            twin_id=reconstructed_capsule.twin_id,
            epoch=source.epoch + 1,
            owner=freeze.target,
            mode=OwnerMode.STAGING,
            capsule=reconstructed_capsule,
            pending_transfer_id=freeze.transfer_id,
        )
        self._validate_capsule(
            staged, expected_yes_group_ids=expected_source_groups
        )
        self.copies[(freeze.target, freeze.twin_id)] = staged
        certificate = self.issuer.install(
            group_id=self.shard_group(freeze.target),
            transfer_id=freeze.transfer_id,
            twin_id=freeze.twin_id,
            new_epoch=freeze.epoch + 1,
            source=freeze.source,
            target=freeze.target,
            cut=freeze.cut,
            capsule_root=staged.capsule_root,
            freeze_certificate_digest=freeze.digest,
        )
        handover.install = certificate
        return certificate

    def commit_activate(self, install: InstallCertificate) -> ActivateCertificate:
        """Order the OS activation record without assuming network delivery."""
        if not install.verify(
            self.registry, expected_group_id=self.shard_group(install.target)
        ):
            raise ProtocolError("invalid InstallQC")
        handover = self._handover(install.transfer_id)
        if handover.install is None or handover.install.digest != install.digest:
            raise ProtocolError("InstallQC does not match handover record")
        if handover.resume is not None:
            raise ProtocolError("ResumeQC already finalized this handover")
        if handover.activate is not None:
            return handover.activate
        target = self._copy(install.target, install.twin_id)
        source = self._copy(install.source, install.twin_id)
        if (
            target.mode is not OwnerMode.STAGING
            or target.pending_transfer_id != install.transfer_id
            or target.capsule_root != install.capsule_root
        ):
            raise ProtocolError("target staging state does not match InstallQC")
        if (
            source.mode is not OwnerMode.FROZEN
            or source.pending_transfer_id != install.transfer_id
        ):
            raise ProtocolError("source freeze lineage does not match InstallQC")
        previous_owner = self._owner_certificate(install.twin_id)
        if previous_owner.epoch + 1 != install.new_epoch:
            raise ProtocolError("InstallQC does not extend the current ownership epoch")
        new_owner = self.issuer.owner(
            group_id=self.ownership_group,
            twin_id=install.twin_id,
            epoch=install.new_epoch,
            owner=install.target,
            previous_certificate_digest=previous_owner.digest,
        )
        certificate = self.issuer.activate(
            group_id=self.ownership_group,
            transfer_id=install.transfer_id,
            twin_id=install.twin_id,
            new_epoch=install.new_epoch,
            target=install.target,
            capsule_root=install.capsule_root,
            freeze_certificate_digest=handover.freeze.digest,
            install_certificate_digest=install.digest,
            owner_certificate_digest=new_owner.digest,
        )
        self.owners[install.twin_id] = new_owner
        self.owner_history[install.twin_id].append(new_owner)
        handover.activate = certificate
        handover.successor_owner = new_owner
        return certificate

    def deliver_activate(
        self,
        certificate: ActivateCertificate,
        *,
        shard_id: str,
    ) -> None:
        """Deliver a committed ActivateQC to one endpoint, idempotently."""
        if not certificate.verify(
            self.registry, expected_group_id=self.ownership_group
        ):
            raise ProtocolError("invalid ActivateQC")
        handover = self._handover(certificate.transfer_id)
        if handover.activate is None or handover.activate.digest != certificate.digest:
            raise ProtocolError("ActivateQC is not the OS terminal record")
        install = handover.install
        if install is None:
            raise ProtocolError("activation has no matching InstallQC")
        if shard_id not in {install.source, install.target}:
            raise ProtocolError("ActivateQC endpoint is not part of this handover")
        if shard_id == install.target:
            target = self._copy(install.target, install.twin_id)
            if (
                target.mode is not OwnerMode.STAGING
                or target.pending_transfer_id != certificate.transfer_id
            ):
                return
            self.copies[(install.target, install.twin_id)] = replace(
                target,
                mode=OwnerMode.ACTIVE,
                pending_transfer_id=None,
            )
        else:
            source = self._copy(install.source, install.twin_id)
            if (
                source.mode is not OwnerMode.FROZEN
                or source.pending_transfer_id != certificate.transfer_id
            ):
                return
            self.copies[(install.source, install.twin_id)] = replace(
                source,
                mode=OwnerMode.FENCED,
                pending_transfer_id=None,
            )
        handover.terminal_deliveries.add(shard_id)
        self.assert_authoritative_invariants(install.twin_id)

    def activate(self, install: InstallCertificate) -> ActivateCertificate:
        """Convenience wrapper that commits and delivers ActivateQC to both shards."""
        certificate = self.commit_activate(install)
        self.deliver_activate(certificate, shard_id=install.source)
        self.deliver_activate(certificate, shard_id=install.target)
        return certificate

    def commit_resume(self, freeze: FreezeCertificate) -> ResumeCertificate:
        """Order the OS resumption record without assuming network delivery."""
        if not freeze.verify(
            self.registry, expected_group_id=self.shard_group(freeze.source)
        ):
            raise ProtocolError("invalid FreezeQC")
        handover = self._handover(freeze.transfer_id)
        if handover.freeze.digest != freeze.digest:
            raise ProtocolError("FreezeQC does not match handover record")
        if handover.activate is not None:
            raise ProtocolError("ActivateQC already finalized this handover")
        if handover.resume is not None:
            return handover.resume
        source = self._copy(freeze.source, freeze.twin_id)
        owner_certificate = self._owner_certificate(freeze.twin_id)
        if (
            source.mode is not OwnerMode.FROZEN
            or source.pending_transfer_id != freeze.transfer_id
        ):
            raise ProtocolError("source is not frozen for this transfer lineage")
        if (
            owner_certificate.owner != freeze.source
            or owner_certificate.epoch != freeze.epoch
        ):
            raise ProtocolError("ownership advanced before resume")
        certificate = self.issuer.resume(
            group_id=self.ownership_group,
            transfer_id=freeze.transfer_id,
            twin_id=freeze.twin_id,
            epoch=freeze.epoch,
            source=freeze.source,
            capsule_root=freeze.capsule_root,
            freeze_certificate_digest=freeze.digest,
            owner_certificate_digest=owner_certificate.digest,
        )
        handover.resume = certificate
        return certificate

    def deliver_resume(
        self,
        certificate: ResumeCertificate,
        *,
        shard_id: str,
    ) -> None:
        """Deliver a committed ResumeQC to one endpoint, idempotently."""
        if not certificate.verify(
            self.registry, expected_group_id=self.ownership_group
        ):
            raise ProtocolError("invalid ResumeQC")
        handover = self._handover(certificate.transfer_id)
        if handover.resume is None or handover.resume.digest != certificate.digest:
            raise ProtocolError("ResumeQC is not the OS terminal record")
        freeze = handover.freeze
        if shard_id not in {freeze.source, freeze.target}:
            raise ProtocolError("ResumeQC endpoint is not part of this handover")
        if shard_id == freeze.source:
            source = self._copy(freeze.source, freeze.twin_id)
            if (
                source.mode is not OwnerMode.FROZEN
                or source.pending_transfer_id != certificate.transfer_id
            ):
                return
            self.copies[(freeze.source, freeze.twin_id)] = replace(
                source,
                mode=OwnerMode.ACTIVE,
                pending_transfer_id=None,
            )
        else:
            target_key = (freeze.target, freeze.twin_id)
            if target_key in self.copies:
                target = self.copies[target_key]
                if (
                    target.mode is not OwnerMode.STAGING
                    or target.pending_transfer_id != certificate.transfer_id
                ):
                    return
                self.copies[target_key] = replace(
                    target,
                    mode=OwnerMode.DISCARDED,
                    pending_transfer_id=None,
                )
        handover.terminal_deliveries.add(shard_id)
        self.assert_authoritative_invariants(freeze.twin_id)

    def resume(self, freeze: FreezeCertificate) -> ResumeCertificate:
        """Convenience wrapper that commits and delivers ResumeQC to both shards."""
        certificate = self.commit_resume(freeze)
        self.deliver_resume(certificate, shard_id=freeze.target)
        self.deliver_resume(certificate, shard_id=freeze.source)
        return certificate

    def deliver_decision(
        self,
        *,
        shard_id: str,
        twin_id: str,
        decision_certificate: DecisionCertificate,
    ) -> None:
        """Place one authenticated DecisionQC delivery in a shard inbox."""
        self._validate_tds_decision(decision_certificate)
        self._copy(shard_id, twin_id)
        key = (
            shard_id,
            twin_id,
            decision_certificate.tx_id,
            decision_certificate.record_digest,
        )
        self.decision_inbox[key] = self.decision_inbox.get(key, 0) + 1
        self.decision_delivery_counts[key] = (
            self.decision_delivery_counts.get(key, 0) + 1
        )

    def process_decision(
        self,
        *,
        shard_id: str,
        twin_id: str,
        decision_certificate: DecisionCertificate,
    ) -> ResolutionResult:
        """Consume one delivered DecisionQC at the current active owner."""
        self._validate_tds_decision(decision_certificate)
        key = (
            shard_id,
            twin_id,
            decision_certificate.tx_id,
            decision_certificate.record_digest,
        )
        pending = self.decision_inbox.get(key, 0)
        if pending == 0:
            raise ProtocolError("DecisionQC has not been delivered to this shard")
        twin = self.active_twin(twin_id)
        if twin.owner != shard_id:
            raise ProtocolError("only the current active owner may process DecisionQC")
        result = self._apply_decision(
            twin=twin,
            twin_id=twin_id,
            decision_certificate=decision_certificate,
        )
        if pending == 1:
            self.decision_inbox.pop(key)
        else:
            self.decision_inbox[key] = pending - 1
        return result

    def resolve(
        self,
        *,
        twin_id: str,
        decision_certificate: DecisionCertificate,
    ) -> ResolutionResult:
        twin = self.active_twin(twin_id)
        self.deliver_decision(
            shard_id=twin.owner,
            twin_id=twin_id,
            decision_certificate=decision_certificate,
        )
        return self.process_decision(
            shard_id=twin.owner,
            twin_id=twin_id,
            decision_certificate=decision_certificate,
        )

    def _apply_decision(
        self,
        *,
        twin: AuthoritativeTwin,
        twin_id: str,
        decision_certificate: DecisionCertificate,
    ) -> ResolutionResult:
        existing = twin.capsule.tombstone(decision_certificate.tx_id)
        if existing is not None:
            if (
                existing.decision is not decision_certificate.decision
                or existing.decision_record_digest != decision_certificate.record_digest
            ):
                raise ProtocolError("local tombstone conflicts with global decision")
            return ResolutionResult(
                twin_id=twin_id,
                tx_id=decision_certificate.tx_id,
                decision=existing.decision,
                owner=twin.owner,
                owner_epoch=twin.epoch,
                applied_now=False,
                enqueued_commands=(),
            )
        if twin_id not in decision_certificate.participant_set:
            raise ProtocolError("DecisionQC does not include this participant")
        obligation = twin.capsule.obligation(decision_certificate.tx_id)
        if obligation is None:
            if decision_certificate.decision is Decision.ABORT:
                updated_capsule, enqueued = twin.capsule.aborted_without_obligation(
                    twin_id=twin_id,
                    tx_id=decision_certificate.tx_id,
                    decision_certificate=decision_certificate,
                )
                self.copies[(twin.owner, twin_id)] = replace(
                    twin, capsule=updated_capsule
                )
                return ResolutionResult(
                    twin_id=twin_id,
                    tx_id=decision_certificate.tx_id,
                    decision=Decision.ABORT,
                    owner=twin.owner,
                    owner_epoch=twin.epoch,
                    applied_now=True,
                    enqueued_commands=enqueued,
                )
            raise ProtocolError("current owner lacks the durable prepared obligation")
        self._validate_obligation(obligation, twin_id, "current")
        self._validate_yes_source_binding(obligation.yes_certificate)
        if not obligation.yes_certificate.verify(
            self.registry,
            expected_group_id=self._yes_group_id(obligation.yes_certificate),
        ):
            raise ProtocolError(
                "prepared obligation contains an invalid YES certificate"
            )
        if decision_certificate.participant_set != obligation.record.participant_set:
            raise ProtocolError(
                "DecisionQC participant set does not match prepared record"
            )
        if decision_certificate.decision is Decision.COMMIT:
            decision_yes = dict(decision_certificate.yes_record_digests)
            if decision_yes.get(twin_id) != obligation.yes_certificate.subject_hash:
                raise ProtocolError(
                    "DecisionQC does not reference this prepared intent"
                )
        updated_capsule, enqueued = twin.capsule.resolved(
            obligation=obligation,
            decision_certificate=decision_certificate,
        )
        self.copies[(twin.owner, twin_id)] = replace(twin, capsule=updated_capsule)
        self._record_enqueues(updated_capsule, enqueued)
        return ResolutionResult(
            twin_id=twin_id,
            tx_id=decision_certificate.tx_id,
            decision=decision_certificate.decision,
            owner=twin.owner,
            owner_epoch=twin.epoch,
            applied_now=True,
            enqueued_commands=enqueued,
        )

    def assert_authoritative_invariants(self, twin_id: str) -> None:
        owner_certificate = self._owner_certificate(twin_id)
        if not owner_certificate.verify(
            self.registry, expected_group_id=self.ownership_group
        ):
            raise ProtocolError("current OwnerQC is invalid")
        history = self.owner_history.get(twin_id, [])
        history_complete = bool(history)
        if not history:
            # A successor may retain only the certified ownership head. Historical
            # YESQCs carry their source-shard binding, so resolution remains local.
            history = [owner_certificate]
        for index, certificate in enumerate(history):
            if not certificate.verify(
                self.registry, expected_group_id=self.ownership_group
            ):
                raise ProtocolError("ownership chain contains an invalid OwnerQC")
            if not history_complete:
                continue
            if index == 0:
                if certificate.epoch != 0 or certificate.previous_certificate_digest:
                    raise ProtocolError(
                        "ownership chain has an invalid genesis certificate"
                    )
                continue
            previous = history[index - 1]
            if certificate.epoch != previous.epoch + 1:
                raise ProtocolError("ownership epochs are not consecutive")
            if certificate.previous_certificate_digest != previous.digest:
                raise ProtocolError("ownership certificate chain is broken")
        if history[-1].digest != owner_certificate.digest:
            raise ProtocolError("current OwnerQC is not the ownership-chain head")
        for (_, candidate_id), twin in self.copies.items():
            if candidate_id != twin_id:
                continue
            pending_mode = twin.mode in {OwnerMode.FROZEN, OwnerMode.STAGING}
            if pending_mode != (twin.pending_transfer_id is not None):
                raise ProtocolError("local mode and pending transfer lineage disagree")
            for tombstone in twin.capsule.decisions:
                recorded = self.decisions.get(tombstone.tx_id)
                if (
                    recorded is None
                    or recorded.record_digest != tombstone.decision_record_digest
                    or recorded.decision is not tombstone.decision
                ):
                    raise ProtocolError("local tombstone does not match the TDS record")
                issued = self.yes_history.get((tombstone.tx_id, twin_id))
                if issued is not None and issued.intent_digest == tombstone.intent_digest:
                    continue
                if (
                    tombstone.decision is Decision.ABORT
                    and tombstone.intent_digest
                    == abort_intent_digest(twin_id, tombstone.tx_id)
                ):
                    continue
                raise ProtocolError("local tombstone does not match certified intent")
        active = [
            twin
            for (_, candidate_id), twin in self.copies.items()
            if candidate_id == twin_id and twin.mode is OwnerMode.ACTIVE
        ]
        if len(active) > 1:
            raise ProtocolError(f"more than one active owner for {twin_id}")
        if active and (
            active[0].owner != owner_certificate.owner
            or active[0].epoch != owner_certificate.epoch
        ):
            raise ProtocolError("active state does not match current OwnerQC")
        if not active:

            def explains_current_nonserving(record: HandoverRecord) -> bool:
                freeze = record.freeze
                if freeze.twin_id != twin_id:
                    return False
                if record.activate is not None:
                    activate = record.activate
                    return (
                        owner_certificate.owner == activate.target
                        and owner_certificate.epoch == activate.new_epoch
                        and activate.target not in record.terminal_deliveries
                    )
                if record.resume is not None:
                    resume = record.resume
                    return (
                        owner_certificate.owner == resume.source
                        and owner_certificate.epoch == resume.epoch
                        and resume.source not in record.terminal_deliveries
                    )
                return (
                    owner_certificate.owner == freeze.source
                    and owner_certificate.epoch == freeze.epoch
                    and freeze.source not in record.terminal_deliveries
                )

            handover_nonserving = any(
                explains_current_nonserving(record)
                for record in self.handovers.values()
            )
            if not handover_nonserving:
                raise ProtocolError(
                    "no active owner outside a certified non-serving handover state"
                )
        for command_id, count in self.outbox_enqueue_counts.items():
            if count > 1:
                raise ProtocolError(f"command enqueued more than once: {command_id}")
        if not active:
            return
        active_outbox = {entry.command_id: entry for entry in active[0].capsule.outbox}
        for command_id, binding in self.outbox_enqueue_bindings.items():
            if binding[0] != twin_id:
                continue
            entry = active_outbox.get(command_id)
            if entry is None:
                raise ProtocolError(
                    f"enqueued command missing from active outbox: {command_id}"
                )
            if binding != (
                active[0].twin_id,
                entry.operation_id,
                entry.command_index,
                entry.payload_json,
            ):
                raise ProtocolError(f"enqueued command binding changed: {command_id}")

    def _record_enqueues(
        self,
        capsule: TwinCapsule,
        command_ids: Iterable[str],
    ) -> None:
        outbox = {entry.command_id: entry for entry in capsule.outbox}
        for command_id in command_ids:
            try:
                entry = outbox[command_id]
            except KeyError as exc:
                raise ProtocolError(
                    f"enqueue event has no durable outbox entry: {command_id}"
                ) from exc
            binding = (
                capsule.twin_id,
                entry.operation_id,
                entry.command_index,
                entry.payload_json,
            )
            existing = self.outbox_enqueue_bindings.get(command_id)
            if existing is not None and existing != binding:
                raise ProtocolError(f"enqueue binding changed: {command_id}")
            self.outbox_enqueue_bindings[command_id] = binding
            self.outbox_enqueue_counts[command_id] = (
                self.outbox_enqueue_counts.get(command_id, 0) + 1
            )

    def _validate_tds_decision(self, decision_certificate: DecisionCertificate) -> None:
        if not decision_certificate.verify(
            self.registry, expected_group_id=self.decision_group
        ):
            raise ProtocolError("invalid DecisionQC")
        recorded = self.decisions.get(decision_certificate.tx_id)
        if (
            recorded is None
            or recorded.record_digest != decision_certificate.record_digest
        ):
            raise ProtocolError("DecisionQC does not certify the unique TDS record")

    def _validate_capsule(
        self,
        twin: AuthoritativeTwin,
        *,
        expected_yes_group_ids: dict[tuple[str, str], str] | None = None,
    ) -> None:
        if twin.capsule.twin_id != twin.twin_id:
            raise ProtocolError("transferred capsule belongs to a different twin")
        for obligation in twin.capsule.prepared:
            self._validate_obligation(obligation, twin.twin_id, "transferred")
            key = (obligation.record.tx_id, twin.twin_id)
            expected_group_id = (expected_yes_group_ids or {}).get(key)
            if expected_group_id is None and key not in self.yes_history:
                raise ProtocolError(
                    "YES certificate source-shard binding unavailable during recovery"
                )
            self._validate_yes_source_binding(
                obligation.yes_certificate,
                expected_group_id=expected_group_id,
            )
            if not obligation.yes_certificate.verify(
                self.registry,
                expected_group_id=self._yes_group_id(obligation.yes_certificate),
            ):
                raise ProtocolError(
                    "transferred obligation has an invalid YES certificate"
                )
        for tombstone in twin.capsule.decisions:
            recorded = self.decisions.get(tombstone.tx_id)
            if (
                recorded is None
                or recorded.decision is not tombstone.decision
                or recorded.record_digest != tombstone.decision_record_digest
            ):
                raise ProtocolError(
                    "transferred tombstone does not match the unique TDS record"
                )
            issued = self.yes_history.get((tombstone.tx_id, twin.twin_id))
            if issued is not None and issued.intent_digest == tombstone.intent_digest:
                continue
            if (
                tombstone.decision is Decision.ABORT
                and tombstone.intent_digest
                == abort_intent_digest(twin.twin_id, tombstone.tx_id)
            ):
                continue
            if issued is None or issued.intent_digest != tombstone.intent_digest:
                raise ProtocolError(
                    "transferred tombstone does not match the certified intent"
                )

    @staticmethod
    def _validate_obligation(
        obligation: PreparedObligation,
        twin_id: str,
        location: str,
    ) -> None:
        try:
            obligation.validate(twin_id)
        except ValueError as exc:
            raise ProtocolError(
                f"{location} obligation does not match its certified record"
            ) from exc

    def _validate_yes_source_binding(
        self,
        certificate: YesCertificate,
        *,
        expected_group_id: str | None = None,
    ) -> None:
        """Reject a YES certificate from an unexpected source quorum."""
        if (
            expected_group_id is not None
            and certificate.proof.group_id != expected_group_id
        ):
            raise ProtocolError("YES certificate source-shard binding changed")
        issued = self.yes_history.get((certificate.tx_id, certificate.twin_id))
        if issued is None:
            return
        if (
            issued.proof.group_id != certificate.proof.group_id
            or issued.proof.configuration != certificate.proof.configuration
        ):
            raise ProtocolError("YES certificate source-shard binding changed")

    def _owner_certificate(self, twin_id: str) -> OwnerCertificate:
        try:
            return self.owners[twin_id]
        except KeyError as exc:
            raise ProtocolError(f"unknown twin: {twin_id}") from exc

    @staticmethod
    def _yes_group_id(certificate: YesCertificate) -> str:
        group_id = certificate.proof.group_id
        if not group_id.startswith("shard:"):
            raise ProtocolError("YES certificate is not bound to a shard quorum")
        return group_id

    def _owner_at_epoch(self, twin_id: str, epoch: int) -> str:
        try:
            return next(
                certificate.owner
                for certificate in self.owner_history[twin_id]
                if certificate.epoch == epoch
            )
        except (KeyError, StopIteration) as exc:
            raise ProtocolError(
                f"ownership history has no epoch {epoch} for twin {twin_id}"
            ) from exc

    def _copy(self, shard_id: str, twin_id: str) -> AuthoritativeTwin:
        try:
            return self.copies[(shard_id, twin_id)]
        except KeyError as exc:
            raise ProtocolError(
                f"missing twin copy {twin_id} at shard {shard_id}"
            ) from exc

    def _handover(self, transfer_id: str) -> HandoverRecord:
        try:
            return self.handovers[transfer_id]
        except KeyError as exc:
            raise ProtocolError(f"unknown handover: {transfer_id}") from exc
