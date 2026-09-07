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

## Reviewer check

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

The regressions include canonical capsule serialization and target-side parsing,
malformed, wrong-root, owner-detached, and tombstone-detached transfer
rejection, service-specific quorum binding, write-lock coverage,
post-activation resolution, and duplicate delivery.
The suite also exercises DecisionQC/YESQC evidence restoration, rejects
cross-shard YES substitution, and carries obligations through two sequential
handovers with different source shards.

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

The executable is a protocol abstraction. Quorum proofs model authorization by
a configured `3f+1` group; they are not production signatures. Collision
resistance, replicated-state-machine durability, and physical actuator
deduplication are explicit environment contracts. A successor must restore the
durable TDS decision record and any unresolved YES records before validating
historical evidence; the capsule carries the evidence needed for resolution,
while those service records remain the recovery authority. Post-activation
`Update` calls are prevalidated, RSM-ordered entries; retry deduplication is an
external transaction-layer contract.
