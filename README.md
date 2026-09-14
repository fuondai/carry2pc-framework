# Carry2PC reference artifact

This package implements the Carry2PC handover state machine, canonical
certificate schemas, bounded state exploration, and deterministic evaluation
producer. The checked invariants cover ownership uniqueness, transfer lineage,
prepared-obligation persistence, decision consistency, intent fidelity, and
durable enqueue integrity.

## Environment

- CPython 3.10 through 3.14
- Dependencies pinned in `requirements.lock`

Install in an isolated environment:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
.venv/bin/python -m pip install --no-deps .
```

## Reference verification

Run the bounded reference-vector gate:

```bash
carry2pc verify \
  --config configs/full.yaml \
  --output verification \
  --expect artifacts/reference_vector.json
```

A successful check reports `passed: true` and 338 explored compliant states.
The semantic fields are checked against the known-answer vector. Timestamps and
runtime diagnostics are intentionally excluded from that vector.

## Manuscript chart

The fault-isolation chart uses every retained record from the 72-run matrix; it
does not estimate performance or add synthetic observations. After installing
the optional plotting dependencies, regenerate the vector figure with:

```bash
python -m pip install '.[figures]'
python scripts/plot_fault_isolation.py
```

Run the focused handover regressions with:

```bash
python -m pip install '.[test]'
python -m pytest -q
```

The regressions cover canonical capsule serialization and target-side parsing,
malformed, wrong-root, owner-detached, and tombstone-detached transfers,
service-specific quorum binding, write-lock coverage, post-activation resolution,
and duplicate delivery. The suite also exercises DecisionQC/YESQC evidence
restoration, cross-shard YES substitution protection, and obligations carried
through two sequential handovers with different source shards. Focused transition
regressions require Prepare retries to reproduce the same canonical pending
record, validate terminal transaction identifiers and record rebinding, and
prevent Install from overwriting a target whose prior transfer lineage awaits
terminal delivery.
Freeze retries for the same target return the stored FreezeQC without allocating
a new cut or transfer identifier.

These focused regressions extend the guard coverage; the retained 72-run matrix
and its manuscript figures remain the fixed reproducible baseline for the
reported counts.

## Evaluation producer

The complete declared matrix contains 12 protocol cells and six variants per
cell: the compliant model and five single-violation protocol mutants. The
mutants alter one transition rule at a time; they are model-level checks, not
Byzantine-replica or network-fault injections.

```bash
carry2pc evaluate-matrix \
  --config configs/full.yaml \
  --output output
```

The command writes raw JSON Lines records, aggregate metrics, and a manifest
that binds the configuration and producer source. Generated result directories
are not part of the source distribution.

## Scope

The executable is a deterministic protocol model. Quorum proofs use a configured
`3f+1` group and certificate contracts for canonical subjects, signer membership,
and threshold authorization. Collision resistance, replicated-state-machine
durability, and physical actuator deduplication are represented as environment
contracts. Before validating historical evidence, a successor restores the
durable TDS decision record, the source YES record for each committed tombstone,
and every unresolved YES record. An absent-participant ABORT uses its
domain-separated no-intent digest. The capsule carries the state needed for
resolution, while those service records remain the recovery authority.
Post-activation `Update` calls are prevalidated, RSM-ordered entries and retry
deduplication is an explicit transaction-layer rule.
