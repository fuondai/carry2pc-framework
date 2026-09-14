"""Canonical quorum-certificate schemas.

The verifier instantiates quorum authorization under the configured fault model.
A proof is valid only when its signer set belongs to the configured group and
reaches the declared Byzantine threshold for the exact canonical subject hash.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar, Iterable

from carry2pc.canonical import stable_hash
from carry2pc.types import Decision


@dataclass(frozen=True)
class QuorumGroup:
    group_id: str
    configuration: int
    members: tuple[str, ...]
    max_byzantine: int
    model_signers: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.group_id, str) or not self.group_id:
            raise ValueError("group_id must be a non-empty string")
        if (
            isinstance(self.configuration, bool)
            or not isinstance(self.configuration, int)
            or self.configuration < 0
        ):
            raise ValueError("configuration must be a non-negative integer")
        if (
            isinstance(self.max_byzantine, bool)
            or not isinstance(self.max_byzantine, int)
            or self.max_byzantine < 0
        ):
            raise ValueError("max_byzantine must be a non-negative integer")
        if any(
            not isinstance(member, str) or not member for member in self.members
        ) or (self.members != tuple(sorted(set(self.members)))):
            raise ValueError("quorum members must be non-empty, unique, and canonical")
        if len(self.members) < 3 * self.max_byzantine + 1:
            raise ValueError("BFT group requires at least 3f+1 members")
        if any(
            not isinstance(signer, str) or not signer for signer in self.model_signers
        ) or self.model_signers != tuple(sorted(set(self.model_signers))):
            raise ValueError("model signers must be non-empty, unique, and canonical")
        if not set(self.model_signers).issubset(self.members):
            raise ValueError("model signers must belong to the quorum group")
        if len(self.model_signers) < self.threshold:
            raise ValueError("model signer set does not reach quorum threshold")

    @property
    def threshold(self) -> int:
        return 2 * self.max_byzantine + 1


@dataclass(frozen=True)
class QuorumProof:
    group_id: str
    configuration: int
    signers: tuple[str, ...]
    subject_hash: str

    def __post_init__(self) -> None:
        if not isinstance(self.group_id, str) or not self.group_id:
            raise ValueError("proof group_id must be a non-empty string")
        if (
            isinstance(self.configuration, bool)
            or not isinstance(self.configuration, int)
            or self.configuration < 0
        ):
            raise ValueError("proof configuration must be a non-negative integer")
        if any(not isinstance(signer, str) or not signer for signer in self.signers):
            raise ValueError("proof signers must be non-empty strings")
        if len(set(self.signers)) != len(self.signers):
            raise ValueError("proof signers must be unique")
        if (
            not isinstance(self.subject_hash, str)
            or len(self.subject_hash) != 64
            or self.subject_hash != self.subject_hash.lower()
        ):
            raise ValueError("proof subject_hash must be a lowercase SHA-256 digest")
        try:
            bytes.fromhex(self.subject_hash)
        except ValueError as exc:
            raise ValueError(
                "proof subject_hash must be a lowercase SHA-256 digest"
            ) from exc
        object.__setattr__(self, "signers", tuple(sorted(self.signers)))


class QuorumRegistry:
    def __init__(self, groups: Iterable[QuorumGroup]):
        registered = tuple(groups)
        if not registered:
            raise ValueError("at least one quorum group is required")
        if len({group.group_id for group in registered}) != len(registered):
            raise ValueError("quorum group identifiers must be unique")
        self._groups = {group.group_id: group for group in registered}

    def attest(self, group_id: str, subject_hash: str) -> QuorumProof:
        group = self.group(group_id)
        return QuorumProof(
            group_id=group.group_id,
            configuration=group.configuration,
            signers=tuple(sorted(group.model_signers)),
            subject_hash=subject_hash,
        )

    def verify(self, proof: QuorumProof, subject_hash: str) -> bool:
        group = self._groups.get(proof.group_id)
        if group is None or proof.configuration != group.configuration:
            return False
        if proof.subject_hash != subject_hash:
            return False
        if proof.signers != tuple(sorted(set(proof.signers))):
            return False
        if not set(proof.signers).issubset(group.members):
            return False
        return len(proof.signers) >= group.threshold

    def group(self, group_id: str) -> QuorumGroup:
        try:
            return self._groups[group_id]
        except KeyError as exc:
            raise ValueError(f"unknown quorum group: {group_id}") from exc


class CanonicalCertificate:
    DOMAIN: ClassVar[str]
    proof: QuorumProof

    def payload(self) -> dict[str, Any]:
        raise NotImplementedError

    @property
    def subject_hash(self) -> str:
        return stable_hash(f"{self.DOMAIN}.payload", self.payload())

    @property
    def digest(self) -> str:
        return stable_hash(
            f"{self.DOMAIN}.certificate",
            {"payload": self.payload(), "proof": self.proof},
        )

    @property
    def proof_digest(self) -> str:
        return stable_hash(f"{self.DOMAIN}.proof", self.proof)

    def verify(
        self,
        registry: QuorumRegistry,
        *,
        expected_group_id: str | None = None,
    ) -> bool:
        if expected_group_id is not None and self.proof.group_id != expected_group_id:
            return False
        return registry.verify(self.proof, self.subject_hash)


@dataclass(frozen=True)
class OwnerCertificate(CanonicalCertificate):
    DOMAIN: ClassVar[str] = "carry2pc.owner.v1"
    twin_id: str
    epoch: int
    owner: str
    previous_certificate_digest: str
    proof: QuorumProof

    def payload(self) -> dict[str, Any]:
        return {
            "twin_id": self.twin_id,
            "epoch": self.epoch,
            "owner": self.owner,
            "previous_certificate_digest": self.previous_certificate_digest,
        }


@dataclass(frozen=True)
class YesCertificate(CanonicalCertificate):
    DOMAIN: ClassVar[str] = "carry2pc.prepared_yes.v1"
    tx_id: str
    twin_id: str
    prepare_epoch: int
    participant_set: tuple[str, ...]
    intent_digest: str
    lock_digest: str
    prepared_record_digest: str
    proof: QuorumProof

    def payload(self) -> dict[str, Any]:
        return {
            "tx_id": self.tx_id,
            "twin_id": self.twin_id,
            "prepare_epoch": self.prepare_epoch,
            "participant_set": self.participant_set,
            "intent_digest": self.intent_digest,
            "lock_digest": self.lock_digest,
            "prepared_record_digest": self.prepared_record_digest,
        }


@dataclass(frozen=True)
class FreezeCertificate(CanonicalCertificate):
    DOMAIN: ClassVar[str] = "carry2pc.freeze.v1"
    transfer_id: str
    twin_id: str
    epoch: int
    source: str
    target: str
    cut: int
    capsule_root: str
    owner_certificate_digest: str
    proof: QuorumProof

    def payload(self) -> dict[str, Any]:
        return {
            "transfer_id": self.transfer_id,
            "twin_id": self.twin_id,
            "epoch": self.epoch,
            "source": self.source,
            "target": self.target,
            "cut": self.cut,
            "capsule_root": self.capsule_root,
            "owner_certificate_digest": self.owner_certificate_digest,
        }


@dataclass(frozen=True)
class InstallCertificate(CanonicalCertificate):
    DOMAIN: ClassVar[str] = "carry2pc.install.v1"
    transfer_id: str
    twin_id: str
    new_epoch: int
    source: str
    target: str
    cut: int
    capsule_root: str
    freeze_certificate_digest: str
    proof: QuorumProof

    def payload(self) -> dict[str, Any]:
        return {
            "transfer_id": self.transfer_id,
            "twin_id": self.twin_id,
            "new_epoch": self.new_epoch,
            "source": self.source,
            "target": self.target,
            "cut": self.cut,
            "capsule_root": self.capsule_root,
            "freeze_certificate_digest": self.freeze_certificate_digest,
        }


@dataclass(frozen=True)
class ActivateCertificate(CanonicalCertificate):
    DOMAIN: ClassVar[str] = "carry2pc.activate.v1"
    transfer_id: str
    twin_id: str
    new_epoch: int
    target: str
    capsule_root: str
    freeze_certificate_digest: str
    install_certificate_digest: str
    owner_certificate_digest: str
    proof: QuorumProof

    def payload(self) -> dict[str, Any]:
        return {
            "transfer_id": self.transfer_id,
            "twin_id": self.twin_id,
            "new_epoch": self.new_epoch,
            "target": self.target,
            "capsule_root": self.capsule_root,
            "freeze_certificate_digest": self.freeze_certificate_digest,
            "install_certificate_digest": self.install_certificate_digest,
            "owner_certificate_digest": self.owner_certificate_digest,
        }


@dataclass(frozen=True)
class ResumeCertificate(CanonicalCertificate):
    DOMAIN: ClassVar[str] = "carry2pc.resume.v1"
    transfer_id: str
    twin_id: str
    epoch: int
    source: str
    capsule_root: str
    freeze_certificate_digest: str
    owner_certificate_digest: str
    proof: QuorumProof

    def payload(self) -> dict[str, Any]:
        return {
            "transfer_id": self.transfer_id,
            "twin_id": self.twin_id,
            "epoch": self.epoch,
            "source": self.source,
            "capsule_root": self.capsule_root,
            "freeze_certificate_digest": self.freeze_certificate_digest,
            "owner_certificate_digest": self.owner_certificate_digest,
        }


@dataclass(frozen=True)
class DecisionCertificate(CanonicalCertificate):
    DOMAIN: ClassVar[str] = "carry2pc.decision.v2"
    tx_id: str
    decision: Decision
    participant_set: tuple[str, ...]
    yes_record_digests: tuple[tuple[str, str], ...]
    proof: QuorumProof

    def __post_init__(self) -> None:
        if not self.tx_id or not self.participant_set:
            raise ValueError("decision record requires a transaction and participants")
        if self.participant_set != tuple(sorted(set(self.participant_set))):
            raise ValueError("decision participants must be unique and canonical")
        if any(not participant for participant in self.participant_set):
            raise ValueError("decision participant identifiers must not be empty")
        if self.yes_record_digests != tuple(sorted(self.yes_record_digests)):
            raise ValueError("YES record bindings must be canonically ordered")
        if any(
            not participant or not record_digest
            for participant, record_digest in self.yes_record_digests
        ):
            raise ValueError("YES record bindings must not contain empty fields")
        bound_participants = tuple(item[0] for item in self.yes_record_digests)
        if len(bound_participants) != len(set(bound_participants)):
            raise ValueError("decision record repeats a YES participant")
        if not set(bound_participants).issubset(self.participant_set):
            raise ValueError("decision record binds an unknown YES participant")
        if self.decision is Decision.COMMIT and set(bound_participants) != set(
            self.participant_set
        ):
            raise ValueError("COMMIT record requires one YES binding per participant")

    def payload(self) -> dict[str, Any]:
        return {
            "tx_id": self.tx_id,
            "decision": self.decision,
            "participant_set": self.participant_set,
            "yes_record_digests": self.yes_record_digests,
        }

    @property
    def record_digest(self) -> str:
        """Identify the canonical TDS decision independently of its QC proof."""
        return self.subject_hash


class CertificateIssuer:
    def __init__(self, registry: QuorumRegistry):
        self.registry = registry

    def _proof(
        self, domain: str, group_id: str, payload: dict[str, Any]
    ) -> QuorumProof:
        subject_hash = stable_hash(f"{domain}.payload", payload)
        return self.registry.attest(group_id, subject_hash)

    def owner(
        self,
        *,
        group_id: str,
        twin_id: str,
        epoch: int,
        owner: str,
        previous_certificate_digest: str,
    ) -> OwnerCertificate:
        payload = {
            "twin_id": twin_id,
            "epoch": epoch,
            "owner": owner,
            "previous_certificate_digest": previous_certificate_digest,
        }
        return OwnerCertificate(
            **payload,
            proof=self._proof(OwnerCertificate.DOMAIN, group_id, payload),
        )

    def yes(
        self,
        *,
        group_id: str,
        tx_id: str,
        twin_id: str,
        prepare_epoch: int,
        participant_set: tuple[str, ...],
        intent_digest: str,
        lock_digest: str,
        prepared_record_digest: str,
    ) -> YesCertificate:
        payload = {
            "tx_id": tx_id,
            "twin_id": twin_id,
            "prepare_epoch": prepare_epoch,
            "participant_set": participant_set,
            "intent_digest": intent_digest,
            "lock_digest": lock_digest,
            "prepared_record_digest": prepared_record_digest,
        }
        return YesCertificate(
            **payload,
            proof=self._proof(YesCertificate.DOMAIN, group_id, payload),
        )

    def freeze(self, *, group_id: str, **payload: Any) -> FreezeCertificate:
        return FreezeCertificate(
            **payload,
            proof=self._proof(FreezeCertificate.DOMAIN, group_id, payload),
        )

    def install(self, *, group_id: str, **payload: Any) -> InstallCertificate:
        return InstallCertificate(
            **payload,
            proof=self._proof(InstallCertificate.DOMAIN, group_id, payload),
        )

    def activate(self, *, group_id: str, **payload: Any) -> ActivateCertificate:
        return ActivateCertificate(
            **payload,
            proof=self._proof(ActivateCertificate.DOMAIN, group_id, payload),
        )

    def resume(self, *, group_id: str, **payload: Any) -> ResumeCertificate:
        return ResumeCertificate(
            **payload,
            proof=self._proof(ResumeCertificate.DOMAIN, group_id, payload),
        )

    def decision(self, *, group_id: str, **payload: Any) -> DecisionCertificate:
        return DecisionCertificate(
            **payload,
            proof=self._proof(DecisionCertificate.DOMAIN, group_id, payload),
        )
