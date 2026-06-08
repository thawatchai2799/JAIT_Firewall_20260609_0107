#!/usr/bin/env python3
"""
Reproduce Table V (comparisons) and Table VI (processing time) of the AFLP paper
from the raw experimental results in aflp_results_v3.csv.

METHODOLOGY NOTE
----------------
The raw CSV records, for EACH trigger mode (periodic / ondemand / threshold), a
separately-measured baseline (static TRF, no AFLP). Because processing time is a
wall-clock quantity, these per-mode baselines differ by a few percent due to
measurement noise (up to ~5.5% at n = 200). Comparison counts are deterministic
and are identical across modes.

To report internally-consistent time numbers, Table VI uses a SINGLE baseline per
scenario = the mean of the three per-mode baseline measurements (i.e. the grand
mean over ~90 repetitions, the most stable estimate). Both AFLP strategies'
improvement percentages are then computed against that one shared baseline.
Comparison results (Table V) are deterministic and reported as-is.
"""
import csv, statistics
from collections import defaultdict

rows = list(csv.DictReader(open("aflp_results_v3.csv")))
g = defaultdict(dict)
for r in rows:
    g[(int(r["n_packets"]), int(r["n_rules"]))][r["mode"]] = r
F = float

def scenario(N, nc):
    d = g[(N, nc)]
    base = statistics.mean(F(d[m]["time_base_mean_ms"]) for m in ("periodic", "ondemand", "threshold"))
    cb   = F(d["periodic"]["comp_base_mean"])
    return {
        "rules": nc - 1,
        "comp_base": cb,
        "comp_per": F(d["periodic"]["comp_aflp_mean"]),
        "comp_od":  F(d["ondemand"]["comp_aflp_mean"]),
        "comp_per_pct": (1 - F(d["periodic"]["comp_aflp_mean"]) / cb) * 100,
        "comp_od_pct":  (1 - F(d["ondemand"]["comp_aflp_mean"]) / cb) * 100,
        "t_base": base,
        "t_per":  F(d["periodic"]["time_aflp_mean_ms"]),
        "t_od":   F(d["ondemand"]["time_aflp_mean_ms"]),
        "t_per_pct": (1 - F(d["periodic"]["time_aflp_mean_ms"]) / base) * 100,
        "t_od_pct":  (1 - F(d["ondemand"]["time_aflp_mean_ms"]) / base) * 100,
    }

for N in (100000, 10000):
    print(f"\n================  N = {N:,} packets  ================")
    print("\nTABLE V  — Average comparisons per packet")
    print(f"{'Rules':>6}{'Baseline':>11}{'Periodic':>11}{'On-demand':>11}{'Per %':>9}{'OD %':>9}")
    for nc in (11, 51, 101, 201):
        s = scenario(N, nc)
        print(f"{s['rules']:>6}{s['comp_base']:>11.3f}{s['comp_per']:>11.3f}{s['comp_od']:>11.3f}"
              f"{s['comp_per_pct']:>9.2f}{s['comp_od_pct']:>9.2f}")
    print("\nTABLE VI — Total processing time (ms), single shared baseline")
    print(f"{'Rules':>6}{'Baseline':>11}{'Periodic':>11}{'On-demand':>11}{'Per %':>9}{'OD %':>9}")
    for nc in (11, 51, 101, 201):
        s = scenario(N, nc)
        print(f"{s['rules']:>6}{s['t_base']:>11.3f}{s['t_per']:>11.3f}{s['t_od']:>11.3f}"
              f"{s['t_per_pct']:>9.2f}{s['t_od_pct']:>9.2f}")
