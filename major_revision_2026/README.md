# Major Revision Experiment Package (2026)

Supplementary code and experimental results for the major revision of:

> **Traffic-Adaptive Field Ordering for Improving Tree-Rule Firewall Performance**
> (Journal of Advances in Information Technology, submission JAIT-22676; previously titled
> "Automatic Field-Level Positioning in Tree-Rule Firewall Based on Traffic Frequency
> for Processing Speed Improvement")

This folder contains everything needed to reproduce the **new experiments added during
the major revision** (manuscript Sections VI.C and VI.E–VI.K), together with the raw
result files cited in the revised paper and in the point-by-point response letter.
The original simulation code referenced by the main README remains at the repository
root (`aflp_simulation_v3.py`, `aflp_simulation_v4.py`); copies are included here so
that this folder is self-contained.

---

## Repository layout (this folder)

```
major_revision_2026/
|-- README.md
|-- Phase1_test_on_Intel_Core_i7/    code + Phase-1 results (deterministic metrics)
|-- Phase2_test_on_Intel_Core_i5/    code + Phase-2 results (timing metrics, declared environment)
`-- figures/                         updated Fig. 3 and Fig. 7 (300-dpi PNG + vector PDF)
```

The five `.py` files are **byte-identical in both phase folders** (one self-contained
code set per folder); only the commands executed and the machines differ, as described
below.

## 1. Code files

| File | Description |
|---|---|
| `fullscale_runner.py` | Main runner for all nine revision experiments (see Section 3). **Also contains `AFLPControllerFixed`**, the corrected Threshold-EMA controller: the original implementation never initialized its EMA baseline snapshot, so the trigger condition could never be evaluated; the fixed version establishes the baseline at the first post-cooldown checkpoint. This is the correction referred to in the response letter (comment B.12). |
| `exp11_proposition_verify.py` | Verification suite for Proposition 1 (decision invariance, Section VI.J): property-based test over 40 random wildcard-free rule sets (2,400 packets x all 24 field orders), the two counter-examples delimiting the proposition's scope, an instrumented re-implementation of the cost model C(P) = sum of child counts over visited nodes (Section VI.I), and the root-cardinality check (c(root) = 201, mean C = 204.893 at n = 200). |
| `aflp_core_v4.py` | Core simulation definitions (Sections 1-7 of `aflp_simulation_v4.py`) imported by `exp11_proposition_verify.py`. |
| `aflp_simulation_v3.py` | Copy of the root-level v3 simulation (Threshold-Naive variant); required by the `naive` experiment. |
| `aflp_simulation_v4.py` | Copy of the root-level v4 simulation (Threshold-EMA variant); required by `fullscale_runner.py`. |

## 2. Requirements

- Python 3.10+ (results in this folder were produced with **Python 3.12.8**; any 3.7+ preserves dict insertion order, on which the engine relies)
- `pip install pandas matplotlib numpy`

Run the commands below from inside either phase folder (each already contains all five `.py` files).

## 3. Reproducing the experiments

```
python fullscale_runner.py correctness   # Section VI.J, Tests 1-2            (< 1 min)
python exp11_proposition_verify.py       # Section VI.J, Proposition 1 gates  (~2-5 min)
python fullscale_runner.py naive         # Section VI.C, Threshold-Naive     (~3-10 min)
python fullscale_runner.py ema           # Section VI.C, 30-config EMA sweep (~10-20 min)
python fullscale_runner.py baselines     # Section VI.H (Table IX) + VI.I    (~10-20 min)
python fullscale_runner.py patterns      # Section VI.F                      (~15-30 min)
python fullscale_runner.py skew          # Section VI.E (Table VII)          (~20-40 min)
python fullscale_runner.py timing        # Section VI.G (Table VIII)         (~25-50 min)
python fullscale_runner.py throughput    # Section VI.K (Tables X-XI)        (~10-20 min)
python fullscale_runner.py crossover     # Sections VI.B / VII.C             (~10-20 min)
```

Each command writes `fullscale_<name>.csv` into the working directory.
(`python fullscale_runner.py all` runs everything, roughly 1.5-3 hours in total.)

## 4. Result files and where they appear in the paper

### 4.1 Deterministic results (machine-independent) — in `Phase1_test_on_Intel_Core_i7/`

These metrics are comparison/reorder **counts**, fully determined by the seeds in the
code. The files in this folder were produced on an Intel Core i7-8700 (Windows 11,
Python 3.12.8); they reproduce **bit-identically on any machine and OS** (verified on Windows 11 /
Intel Core i7-8700 and on x86-64 Linux, both with Python 3.12.x, and on the declared
environment below).

| File | Paper location |
|---|---|
| `fullscale_skew.csv` | Table VII, Section VI.E (skew ratios 50-95%) |
| `fullscale_patterns.csv` | Section VI.F (gradual / multi-stage / random-change traffic) |
| `fullscale_timing.csv` | Table VIII, Section VI.G (trigger-timing offsets) |
| `fullscale_baselines.csv` | Table IX, Section VI.H (fixed-order baselines) |
| `fullscale_optimality.csv` | Section VI.I (rank 3-5 of 24; mean gap 6.57%; 0/60 exact) |
| `fullscale_correctness.csv` | Section VI.J, Tests 1-2 (0 mismatches) |
| `exp11_result.txt` | Section VI.J, Proposition 1 verification (all gates pass) |
| `fullscale_naive.csv` | Section VI.C (bimodal Threshold-Naive: 4/5 repetitions ~100,000 events, 1/5 zero) |
| `fullscale_ema_sweep.csv` | Section VI.C (30 configurations, 0 reorders in every one) |

### 4.2 Timing results (machine-dependent) — in `Phase2_test_on_Intel_Core_i5/`

Wall-clock measurements, collected on the environment declared in Section V.A of the
paper: **Intel Core i5-11300H (3.10 GHz), 16 GB RAM, 64-bit Windows 11 Home (25H2),
Python 3.12.8**, using `time.perf_counter()`, 30 repetitions.

| File | Paper location |
|---|---|
| `fullscale_throughput.csv` | Table X, Section VI.K (throughput and per-packet response time) |
| `fullscale_rebuild.csv` | Table XI, Section VI.K (isolated tree-rebuild time vs. n) |
| `fullscale_crossover.csv` | Sections VI.B and VII.C (time-improvement crossover between n = 20 and n = 30) |

Re-running these on different hardware changes the absolute numbers but preserves the
qualitative findings (strategy ordering, linear rebuild scaling, crossover bracket);
cross-machine consistency was confirmed on an i7-8700, which reproduced the published
percentage improvements to within ~0.5 percentage points.

## 5. `figures/`

Source files for the two figures updated during the revision:

| File | Description |
|---|---|
| `Fig3_threshold_sensitivity_HiRes_300dpi.png` / `.pdf` | Fig. 3 — measured Threshold-Naive bimodality and the 30-configuration EMA sweep (Section VI.C) |
| `Fig7_time_improvement_HiRes_300dpi.png` / `.pdf` | Fig. 7 — processing-time improvement including the n = 20/30/40 crossover runs (Sections VI.B, VII.C) |

PDFs are vector graphics; PNGs are rendered at 300 dpi.

## 6. Quick sanity checks after running

- `correctness`: both tests must report **0 mismatches**
- `exp11_proposition_verify.py`: must end with **"OVERALL: ALL GATES PASS"**
- `baselines`: default = **204.893**, best fixed order = **19.775**
- `ema`: **avg_reorders = 0** for all 30 configurations

Any deviation in a deterministic value indicates a code/version mismatch.
