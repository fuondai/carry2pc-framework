# Experimental Results

## 1. Environment

The experiments were run from the repository root with the project virtual environment enabled.

```powershell
python -m pytest -q

carry2pc verify `
  --config configs/full.yaml `
  --output verification `
  --expect artifacts/reference_vector.json

carry2pc evaluate-matrix `
  --config configs/full.yaml `
  --output results
```

## 2. Test and Verification

### Unit tests

```text
20 passed in 0.20s
```

### Reference verification

```text
passed: true
states_explored: 338
```

### Evaluation matrix

```text
passed: true
configuration_cells: 12
total_exhaustive_runs: 72
all_runs_bounded_complete: true
```

The evaluation produced:

```text
results/
├── aggregate_metrics.json
├── manifest.json
└── raw/
```

## 3. Overall Results

| Metric | Result |
|---|---:|
| Configuration cells | 12 |
| Variants per cell | 6 |
| Total exhaustive runs | 72 |
| Total states explored | 7,252 |
| Total transitions considered | 12,960 |
| State-cap hits | 0 |
| Applicable mutant runs | 48 |
| Bounded-complete runs | 72 / 72 |
| Compliant cells safe | 12 / 12 |
| Applicable mutant witnesses found | 48 / 48 |

## 4. Mutant Results

| Variant | Expected invariant | Applicable cells | Witness cells | Shortest witness depth |
|---|---|---:|---:|---:|
| `compliant` | — | 0 | 0 | — |
| `omit_obligation_on_install` | `obligation_persistence` | 12 | 12 | 4 |
| `dual_active_on_activate` | `ownership_uniqueness` | 12 | 12 | 3 |
| `epoch_guard_converts_commit_to_abort` | `decision_consistency` | 8 | 8 | 8 |
| `rewrite_intent_on_install` | `intent_fidelity` | 12 | 12 | 3 |
| `duplicate_outbox_enqueue` | `durable_enqueue_integrity` | 4 | 4 | 6 |

All 12 configuration cells were bounded-complete for every variant. All applicable mutant witnesses were found and all compliant cells were safe.

## 5. Witnesses

The exhaustive search produced a witness for every applicable mutant.

### `omit_obligation_on_install`

- Invariant: `obligation_persistence`
- Applicable cells: 12
- Witness cells: 12
- Shortest witness depth: 4
- Witness actions:

```text
prepare_yes
freeze
install
os_commit_activate
```

### `dual_active_on_activate`

- Invariant: `ownership_uniqueness`
- Applicable cells: 12
- Witness cells: 12
- Shortest witness depth: 3
- Witness actions:

```text
freeze
install
os_commit_activate
```

The recorded witness also violates `transfer_lineage`.

### `epoch_guard_converts_commit_to_abort`

- Invariant: `decision_consistency`
- Applicable cells: 8
- Witness cells: 8
- Shortest witness depth: 8
- Witness actions:

```text
prepare_yes
decide_commit
freeze
install
deliver_decision_target
os_commit_activate
deliver_activate_target
epoch_guard_converts_commit_to_abort
```

### `rewrite_intent_on_install`

- Invariant: `intent_fidelity`
- Applicable cells: 12
- Witness cells: 12
- Shortest witness depth: 3
- Witness actions:

```text
prepare_yes
freeze
install
```

### `duplicate_outbox_enqueue`

- Invariant: `durable_enqueue_integrity`
- Applicable cells: 4
- Witness cells: 4
- Shortest witness depth: 6
- Witness actions:

```text
prepare_yes
decide_commit
deliver_decision_source
deliver_decision_source
process_decision_source
reprocess_decision_source
```

The witness state contains two identical enqueue events for the same command, which is the observed `durable_enqueue_integrity` violation.

## 6. Additional Checks

The aggregate evaluation also reports the following checks as passed:

| Check | Result |
|---|---|
| Capsule wire contract | passed |
| Command namespace contract | passed |
| Decision record binding contract | passed |
| Participant migration contract | passed |
| Post-activation update/interleaving contract | passed |
| Reachable-transition conformance | passed |
| Reference implementation conformance | 3 / 3 passed |
| Sequential composition contract | passed |
| Service-group binding contract | passed |
| Terminal-lineage redelivery contract | passed |

For reachable-transition conformance, 635 transitions were checked and no mismatches were found.

## 7. Per-Variant Exploration

| Variant | States explored | Transitions considered |
|---|---:|---:|
| `compliant` | 42–338 | 64–655 |
| `omit_obligation_on_install` | 24–250 | 33–481 |
| `dual_active_on_activate` | 16–210 | 25–423 |
| `epoch_guard_converts_commit_to_abort` | 42–322 | 64–635 |
| `rewrite_intent_on_install` | 20–169 | 26–301 |
| `duplicate_outbox_enqueue` | 42–315 | 64–634 |

## 8. Conclusion

The full evaluation completed successfully.

The compliant variant stayed safe across all 12 configuration cells. Each mutant that was applicable to a cell produced the expected witness, while non-applicable mutants remained unwitnessed. No run hit the state cap, and all 72 runs were bounded-complete.

No failed or incomplete run was recorded in the supplied result files.
