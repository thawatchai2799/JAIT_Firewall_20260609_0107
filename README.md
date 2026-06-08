# AFLP — Reproducibility Bundle

Source code, raw experimental data, and post-processing scripts for the paper
**"Automatic Field-Level Positioning in Tree-Rule Firewall Based on Traffic
Frequency for Processing Speed Improvement"** (Chomsiri & Phunsa).

## Contents

| File | Role |
|------|------|
| `aflp_simulation_v3.py` | Simulation with the **Threshold-Naive** variant (raw elimination-rate change checked every packet). Writes `aflp_results_v3.csv`. |
| `aflp_simulation_v4.py` | Simulation with the **Threshold-EMA** variant (EMA-smoothed elimination rate + cooldown), headless figure saving. Writes `aflp_results_v4.csv`. |
| `aflp_results_v3.csv` | Raw results from `v3`. **The paper's headline tables (V, VI) are computed from this file.** |
| `aflp_results_v4.csv` | Raw results from `v4`, used for the Threshold-EMA result in Section 6.3. |
| `compute_tables.py` | Reads `aflp_results_v3.csv` and prints Table V and Table VI exactly as reported. |
| `make_figs_data.py`, `make_fig23.py`, `make_fig19.py` | Regenerate the publication figures (300 dpi PNG + PDF). |

### Why two simulation programs?

`v3` and `v4` share the same Periodic and On-demand strategies and differ only in
the **Threshold** trigger. The paper reports measured results from **both**
variants, so both are needed for full reproducibility:

| Paper claim (Section 6.3 / Fig. 3) | Source | Where to see it |
|------------------------------------|--------|-----------------|
| Threshold-**Naive** thrashing: ~50,000–64,000 repositioning events per 100,000 packets | `aflp_simulation_v3.py` | `aflp_results_v3.csv`, `mode = threshold` rows, column `avg_reorder_count` (n_packets = 100,000: 59,999 / 63,332 / 56,666 / 49,999) |
| Threshold-**EMA** under-triggering: `avg_reorder_count = 0` in every scenario | `aflp_simulation_v4.py` | `aflp_results_v4.csv`, `mode = threshold` rows: all `avg_reorder_count = 0` |
| Tables V & VI (Periodic + On-demand) | `aflp_simulation_v3.py` | `aflp_results_v3.csv` via `compute_tables.py` |

### A note on v3 vs v4 Periodic/On-demand numbers

The Periodic and On-demand **strategy logic is identical** in both programs, but the
two CSVs do not match to the last decimal. The reason is purely the traffic sample:
`v4` reorganised the order of the random draws in `generate_skewed_traffic` (it calls
`random.choice(...)` before `random.random()`, whereas `v3` does the reverse). On the
same seed this yields a *different but statistically equivalent* 90%-skew two-phase
traffic stream, so averaged comparison counts differ by < 0.1% (e.g. comparison
reduction at n = 10 is 10.07% in v3 vs ~10.10% in v4). This is sampling noise, not a
behavioural difference. To avoid any ambiguity, **all headline numbers in the paper
are taken from `aflp_results_v3.csv`**; `aflp_results_v4.csv` is included only for the
Threshold-EMA reorder result.

## Quick start

```bash
# 1. (optional, slow) regenerate raw results — needs pandas, matplotlib, numpy
python3 aflp_simulation_v3.py        # -> aflp_results_v3.csv (Threshold-Naive)
python3 aflp_simulation_v4.py        # -> aflp_results_v4.csv (Threshold-EMA)

# 2. reproduce the paper tables (stdlib only)
python3 compute_tables.py            # prints Table V and Table VI

# 3. regenerate the figures
python3 make_figs_data.py            # Fig 4,5,6,7,8,10
python3 make_fig23.py                # Fig 2,3
python3 make_fig19.py                # Fig 1,9
```

## What is reproducible, and what is machine-dependent

* **Comparisons per packet and reposition counts — deterministic.** They depend only
  on the rule tree and the traffic phase structure, not on timing, so a given program
  reproduces them exactly (rules use `seed=42`, traffic uses `seed=0`, per-repetition
  shuffling uses `seed=rep`). This covers Table V and the Section 6.3 reorder counts
  (Naive ~50k–64k from v3; EMA 0 from v4).

* **Processing time (Table VI) — wall-clock, machine-dependent.** Times come from
  `time.perf_counter()` and depend on CPU, Python version, and system load. Re-running
  reproduces the *trends and relative improvements* but not the exact milliseconds; the
  paper's absolute times are therefore taken from the shipped `aflp_results_v3.csv`.

## How the time numbers in Table VI are derived (important)

Inside `run_experiment`, **each trigger mode measures its own static-TRF baseline** (a
fresh timed pass over the same traffic). Because time is wall-clock, these per-mode
baselines differ by a few percent (up to ~5.5% at n = 200) from measurement noise. To
report internally-consistent improvements, Table VI uses a **single baseline per
scenario = the mean of the three per-mode baseline measurements** (the grand mean over
~90 repetitions), and both AFLP strategies are compared against that shared baseline.
`compute_tables.py` implements exactly this. Dividing each mode by its own per-mode
baseline instead would shift the time improvements by 2–3 percentage points (e.g.
On-demand at n = 200 ≈ 29.5% vs. the paper's 29.19%); this is expected.

## Notes

- `n_rules` in the CSV is `actual_rules + 1` (the implicit default/catch-all rule),
  i.e. 11/51/101/201 = 10/50/100/200 rules in the paper.
- The figure functions inside the simulation programs produce quick draft plots; the
  publication-quality figures come from the separate `make_fig*.py` scripts.
