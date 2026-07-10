# =============================================================================
#  Simulation v4: Automatic Field-Level Positioning (AFLP) in Tree-Rule Firewall
#
#  Improvements over v3:
#  1. matplotlib.use('Agg') -> save figures without opening a window (headless mode)
#     fixes TclError: Can't find a usable init.tcl on Windows
#  2. New Threshold variant: uses EMA (Exponential Moving Average) + Cooldown
#     fixes the thrashing problem observed in v3
#     - EMA smooths elim_rate gradually, so it does not jump on a single packet
#     - Cooldown enforces a wait of min_interval packets between reorders
#  3. Added Section 10: prints a statistical summary to the console
#  4. Saves figures as .png (300 dpi) instead of plt.show()
#
#  Paper: "Automatic Field-Level Positioning in Tree-Rule Firewall Based on
#          Traffic Frequency for Processing Speed Improvement"
#  Author: Thawatchai Chomsiri
# =============================================================================

# ── Must be set before importing pyplot in all cases ─────────────────────────
import matplotlib
matplotlib.use('Agg')   # headless: save files without needing a display/Tk

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import random
import statistics
import time
import warnings
from collections import defaultdict
from dataclasses import dataclass
from typing import List, Tuple, Optional

warnings.filterwarnings("ignore")

# =============================================================================
# SECTION 1: Constants
# =============================================================================

FIELDS = ["src_ip", "dst_ip", "protocol", "dst_port"]
FIELD_LABELS = {
    "src_ip"  : "Source IP",
    "dst_ip"  : "Destination IP",
    "protocol": "Protocol",
    "dst_port": "Destination Port",
}

SRC_SUBNETS  = [f"192.168.{i}" for i in range(1, 11)]
DST_HOSTS    = [f"10.10.0.{i}"  for i in range(1, 21)]
PROTOCOLS    = ["TCP", "UDP", "ICMP"]
COMMON_PORTS = ["80", "443", "22", "53", "8080", "3306", "21", "25"]

MODE_COLOR = {"periodic": "#1976D2", "threshold": "#388E3C", "ondemand": "#F57C00"}
MODE_LABEL = {
    "periodic" : "AFLP-Periodic",
    "threshold": "AFLP-Threshold (EMA)",
    "ondemand" : "AFLP-On-demand",
}


# =============================================================================
# SECTION 2: Data Structures
# =============================================================================

@dataclass
class Rule:
    src_ip: str; dst_ip: str; protocol: str; dst_port: str; action: str
    def as_dict(self):
        return {"src_ip": self.src_ip, "dst_ip": self.dst_ip,
                "protocol": self.protocol, "dst_port": self.dst_port}

@dataclass
class Packet:
    src_ip: str; dst_ip: str; protocol: str; dst_port: str
    def as_dict(self):
        return {"src_ip": self.src_ip, "dst_ip": self.dst_ip,
                "protocol": self.protocol, "dst_port": self.dst_port}


# =============================================================================
# SECTION 3: Rule Generator
# =============================================================================

def generate_rules(n: int, seed: int = 42) -> List[Rule]:
    """Generate n synthetic rules spread evenly across all field values."""
    random.seed(seed)
    rules = []
    for i in range(n):
        src   = f"{SRC_SUBNETS[i % len(SRC_SUBNETS)]}.{(i * 7 + 1) % 254 + 1}"
        dst   = DST_HOSTS[i % len(DST_HOSTS)]
        proto = PROTOCOLS[i % len(PROTOCOLS)]
        port  = COMMON_PORTS[i % len(COMMON_PORTS)]
        action = "Accept" if i % 3 != 0 else "Deny"
        rules.append(Rule(src, dst, proto, port, action))
    rules.append(Rule("*", "*", "*", "*", "Deny"))   # default-deny
    return rules


# =============================================================================
# SECTION 4: Two-Phase Skewed Traffic Generator
# =============================================================================

def generate_skewed_traffic(rules: List[Rule],
                            n_packets: int,
                            skew_ratio: float = 0.90,
                            seed: int = 0) -> List[Packet]:
    """
    Phase 1 (first half): 90% → same dst_ip  (Destination IP dominant)
    Phase 2 (second half): 90% → same src_ip  (Source IP dominant)
    Uses EXACT values from rule set so tree nodes actually match.
    """
    random.seed(seed)
    real_rules = [r for r in rules if r.src_ip != "*"]
    hot_dst   = real_rules[0].dst_ip
    hot_src   = real_rules[0].src_ip
    packets, half = [], n_packets // 2

    for _ in range(half):
        r = random.choice(real_rules)
        if random.random() < skew_ratio:
            packets.append(Packet(r.src_ip, hot_dst, r.protocol, r.dst_port))
        else:
            packets.append(Packet(r.src_ip, r.dst_ip, r.protocol, r.dst_port))

    for _ in range(n_packets - half):
        r = random.choice(real_rules)
        if random.random() < skew_ratio:
            packets.append(Packet(hot_src, r.dst_ip, r.protocol, r.dst_port))
        else:
            packets.append(Packet(r.src_ip, r.dst_ip, r.protocol, r.dst_port))

    return packets


# =============================================================================
# SECTION 5: Tree-Rule Firewall Engine (Elimination-Rate Counting)
# =============================================================================

class TreeRuleFirewall:
    """
    Tree-Rule Firewall with Elimination-Rate frequency counting.

    Metric: elim_rate(F) = elim(F) / visit(F)
      visit(F) = packets that reached field F's level
      elim(F)  = packets where F had EXACTLY ONE matching child (unique resolution)

    High elim_rate → field is most discriminating → should be at Level 1 (Root).
    """

    def __init__(self, rules: List[Rule], field_order: List[str] = None):
        self.rules       = rules
        self.field_order = field_order or FIELDS[:]
        self.tree        = {}
        self.elim        = defaultdict(int)
        self.visit       = defaultdict(int)
        self.total_packets = 0
        self._build_tree()

    def _build_tree(self):
        self.tree = {}
        for rule in self.rules:
            node = self.tree
            rd   = rule.as_dict()
            for f in self.field_order:
                node = node.setdefault(rd[f], {})
            node["__action__"] = rule.action

    def _match(self, rv: str, pv: str) -> bool:
        return rv == "*" or rv == pv

    def match_packet(self, pkt: Packet) -> Tuple[str, int]:
        """Returns (action, n_comparisons)."""
        pd_ = pkt.as_dict()
        comparisons = [0]

        def _search(node: dict, depth: int) -> Optional[str]:
            if depth == len(self.field_order):
                return node.get("__action__", "Deny")
            f       = self.field_order[depth]
            pkt_val = pd_[f]
            matching = [(rv, child) for rv, child in node.items()
                        if rv != "__action__" and self._match(rv, pkt_val)]
            self.visit[f] += 1
            comparisons[0] += len(node) - (1 if "__action__" in node else 0)
            if len(matching) == 1:
                self.elim[f] += 1
            for rv, child in matching:
                result = _search(child, depth + 1)
                if result is not None:
                    return result
            return None

        action = _search(self.tree, 0) or "Deny"
        self.total_packets += 1
        return action, comparisons[0]

    def get_elim_rate(self) -> dict:
        return {f: self.elim[f] / max(self.visit[f], 1) for f in FIELDS}

    def optimal_order(self) -> List[str]:
        er = self.get_elim_rate()
        return sorted(FIELDS, key=lambda f: er.get(f, 0), reverse=True)

    def apply_order(self, new_order: List[str]):
        self.field_order   = new_order
        self.elim          = defaultdict(int)
        self.visit         = defaultdict(int)
        self.total_packets = 0
        self._build_tree()


# =============================================================================
# SECTION 6: AFLP Controller — Three Trigger Modes (v4: improved Threshold)
# =============================================================================

class AFLPController:
    """
    AFLP Controller with three trigger strategies.

    v4 Improvement — Threshold mode:
      OLD (v3): check raw elim_rate change every packet → thrashing
      NEW (v4): use EMA of elim_rate + cooldown period
        - EMA smooths packet-level noise
        - cooldown enforces minimum interval between reorders
        - threshold delta applied to EMA values (more stable)

    Parameters
    ----------
    mode        : 'periodic' | 'threshold' | 'ondemand'
    interval    : for periodic — reorder every `interval` packets
    threshold   : for threshold — EMA delta trigger (default 0.15 = 15%)
    ema_alpha   : EMA smoothing factor (0 < alpha ≤ 1, default 0.05)
    min_interval: for threshold — minimum packets between reorders (cooldown)
    """

    def __init__(self, firewall: TreeRuleFirewall,
                 mode: str = "periodic",
                 interval: int = 1000,
                 threshold: float = 0.15,
                 ema_alpha: float = 0.05,
                 min_interval: int = 500):
        assert mode in ("periodic", "threshold", "ondemand")
        self.fw           = firewall
        self.mode         = mode
        self.interval     = interval
        self.threshold    = threshold
        self.ema_alpha    = ema_alpha
        self.min_interval = min_interval

        self.reorder_count   = 0
        self._pkt_count      = 0
        self._last_reorder_at = 0

        # EMA state for threshold mode
        self._ema: dict = {}        # EMA of elim_rate per field
        self._ema_prev: dict = {}   # EMA snapshot at last reorder

        self.order_log: list = []   # [(pkt_idx, new_order)]

    # ── main entry ────────────────────────────────────────────────────────────
    def process_packet(self, pkt: Packet) -> Tuple[str, int]:
        action, comps = self.fw.match_packet(pkt)
        self._pkt_count += 1

        if self.mode == "periodic":
            if self._pkt_count % self.interval == 0:
                self._do_reorder()

        elif self.mode == "threshold":
            self._update_ema()
            cooldown_ok = (self._pkt_count - self._last_reorder_at) >= self.min_interval
            if cooldown_ok and self._ema_prev:
                for f in FIELDS:
                    old = self._ema_prev.get(f, 1e-9)
                    new = self._ema.get(f, 0.0)
                    if old > 1e-6 and abs(new - old) / old > self.threshold:
                        self._do_reorder()
                        break

        return action, comps

    def trigger(self):
        """Manual trigger for on-demand mode."""
        if self.mode == "ondemand":
            self._do_reorder()

    # ── internals ─────────────────────────────────────────────────────────────
    def _update_ema(self):
        """Update EMA of current elim_rate (called every packet in threshold mode)."""
        cur = self.fw.get_elim_rate()
        alpha = self.ema_alpha
        if not self._ema:
            self._ema = dict(cur)
        else:
            for f in FIELDS:
                self._ema[f] = alpha * cur.get(f, 0) + (1 - alpha) * self._ema.get(f, 0)

    def _do_reorder(self):
        new_order = self.fw.optimal_order()
        if new_order != self.fw.field_order:
            self.order_log.append((self._pkt_count, new_order[:]))
            self.fw.apply_order(new_order)
            self.reorder_count += 1
            # EMA: snapshot current EMA as baseline for next comparison
            self._ema_prev = dict(self._ema) if self._ema else {}
        self._last_reorder_at = self._pkt_count


# =============================================================================
# SECTION 7: Experiment Runner
# =============================================================================

def run_experiment(rules: List[Rule],
                   packets: List[Packet],
                   mode: str,
                   n_repeats: int = 30,
                   **aflp_kwargs) -> dict:
    """Run one scenario n_repeats times. Returns summary statistics."""
    cb_list, tb_list = [], []
    ca_list, ta_list = [], []
    rc_list = []

    for rep in range(n_repeats):
        p1 = packets[:len(packets) // 2][:]
        p2 = packets[len(packets) // 2:][:]
        random.seed(rep)
        random.shuffle(p1); random.shuffle(p2)
        sh = p1 + p2

        # ── Baseline (no AFLP) ────────────────────────────────────────────
        fw0 = TreeRuleFirewall(rules[:], FIELDS[:])
        cs, t0 = [], time.perf_counter()
        for pkt in sh:
            _, c = fw0.match_packet(pkt); cs.append(c)
        cb_list.append(statistics.mean(cs))
        tb_list.append((time.perf_counter() - t0) * 1000)

        # ── With AFLP ─────────────────────────────────────────────────────
        fw1  = TreeRuleFirewall(rules[:], FIELDS[:])
        ctrl = AFLPController(fw1, mode=mode, **aflp_kwargs)
        cs2, t1 = [], time.perf_counter()
        for i, pkt in enumerate(sh):
            _, c = ctrl.process_packet(pkt); cs2.append(c)
            if mode == "ondemand" and i == len(sh) // 2 - 1:
                ctrl.trigger()
        ca_list.append(statistics.mean(cs2))
        ta_list.append((time.perf_counter() - t1) * 1000)
        rc_list.append(ctrl.reorder_count)

    cb = statistics.mean(cb_list); ca = statistics.mean(ca_list)
    tb = statistics.mean(tb_list); ta = statistics.mean(ta_list)

    return {
        "mode"              : mode,
        "n_rules"           : len(rules),
        "n_packets"         : len(packets),
        "comp_base_mean"    : round(cb, 4),
        "comp_base_std"     : round(statistics.stdev(cb_list), 4),
        "comp_aflp_mean"    : round(ca, 4),
        "comp_aflp_std"     : round(statistics.stdev(ca_list), 4),
        "time_base_mean_ms" : round(tb, 3),
        "time_base_std_ms"  : round(statistics.stdev(tb_list), 3),
        "time_aflp_mean_ms" : round(ta, 3),
        "time_aflp_std_ms"  : round(statistics.stdev(ta_list), 3),
        "comp_improve_pct"  : round((1 - ca / cb) * 100, 2) if cb > 0 else 0,
        "time_improve_pct"  : round((1 - ta / tb) * 100, 2) if tb > 0 else 0,
        "avg_reorder_count" : round(statistics.mean(rc_list), 1),
    }


# =============================================================================
# SECTION 8: Main — Run All Scenarios
# =============================================================================

RULE_SIZES   = [10, 50, 100, 200]
PACKET_SIZES = [10_000, 100_000]
MODES        = ["periodic", "threshold", "ondemand"]
SKEW_RATIO   = 0.90
N_REPEATS    = 30

# ── Threshold v4 parameters ──────────────────────────────────────────────────
EMA_ALPHA    = 0.05   # slow EMA → smooth, stable
THR_DELTA    = 0.15   # 15% relative change in EMA triggers reorder
# min_interval = n_pkts // 20 per scenario (set dynamically below)

print("=" * 70)
print("  AFLP Simulation v4")
print("  Automatic Field-Level Positioning in Tree-Rule Firewall")
print("=" * 70)
print(f"  Skew ratio   : {SKEW_RATIO * 100:.0f}%  (2-phase traffic)")
print(f"  Rule sizes   : {RULE_SIZES}")
print(f"  Packet sizes : {PACKET_SIZES}")
print(f"  Modes        : {MODES}")
print(f"  Repeats      : {N_REPEATS}")
print(f"  Threshold v4 : EMA alpha={EMA_ALPHA}, delta={THR_DELTA*100:.0f}%")
print("=" * 70)

all_results = []

for n_rules in RULE_SIZES:
    rules = generate_rules(n_rules)
    for n_pkts in PACKET_SIZES:
        packets = generate_skewed_traffic(rules, n_pkts, SKEW_RATIO)
        for mode in MODES:
            kw = {}
            if mode == "periodic":
                kw = {"interval": n_pkts // 10}
            elif mode == "threshold":
                # v4: EMA + cooldown (min_interval = 5% of total packets)
                kw = {
                    "threshold"   : THR_DELTA,
                    "ema_alpha"   : EMA_ALPHA,
                    "min_interval": max(200, n_pkts // 20),
                }
            # ondemand has no extra kwargs

            print(f"  rules={n_rules:>3}  pkts={n_pkts:>7,}  "
                  f"mode={mode:<10} ", end="", flush=True)
            res = run_experiment(rules, packets, mode,
                                 n_repeats=N_REPEATS, **kw)
            all_results.append(res)
            print(f"comp↓{res['comp_improve_pct']:+6.2f}%  "
                  f"time↓{res['time_improve_pct']:+6.2f}%  "
                  f"reorders={res['avg_reorder_count']:.1f}")

df = pd.DataFrame(all_results)
df.to_csv("aflp_results_v4.csv", index=False)
print("\n✅ Saved: aflp_results_v4.csv")


# =============================================================================
# SECTION 9: Results Table (console)
# =============================================================================

print("\n" + "=" * 100)
print("  RESULTS SUMMARY")
print("=" * 100)
cols = ["mode", "n_rules", "n_packets",
        "comp_base_mean", "comp_aflp_mean", "comp_improve_pct",
        "time_base_mean_ms", "time_aflp_mean_ms", "time_improve_pct",
        "avg_reorder_count"]
labels = ["Mode", "Rules", "Packets",
          "Comp(base)", "Comp(AFLP)", "Comp↓%",
          "Time_base(ms)", "Time_AFLP(ms)", "Time↓%", "Reorders"]
print(df[cols].rename(columns=dict(zip(cols, labels))).to_string(index=False))


# =============================================================================
# SECTION 10: Statistical Summary (console)
# =============================================================================

print("\n" + "=" * 70)
print("  STATISTICAL SUMMARY  (N = 100,000 packets)")
print("=" * 70)
df100k = df[df["n_packets"] == 100_000]
for mode in MODES:
    sub = df100k[df100k["mode"] == mode]
    avg_comp = sub["comp_improve_pct"].mean()
    avg_time = sub["time_improve_pct"].mean()
    avg_reo  = sub["avg_reorder_count"].mean()
    print(f"  {MODE_LABEL[mode]:<28}  "
          f"avg comp↓={avg_comp:+6.2f}%  "
          f"avg time↓={avg_time:+6.2f}%  "
          f"avg reorders={avg_reo:.1f}")
print("=" * 70)


# =============================================================================
# SECTION 11: Figures — saved to PNG files (NO plt.show())
# =============================================================================
#
#  v4 change: matplotlib.use('Agg') at top of file prevents Tk/display error.
#  All figures are saved as PNG (300 dpi) without opening any window.
#  Files are saved in the current working directory.
# =============================================================================

plt.rcParams.update({
    "font.family": "serif",
    "font.size": 11,
    "axes.titlesize": 12,
    "axes.labelsize": 11,
    "legend.fontsize": 9,
    "xtick.labelsize": 10,
    "ytick.labelsize": 10,
    "figure.dpi": 300,
    "savefig.dpi": 300,
})

RULE_LABELS = [10, 50, 100, 200]   # display labels (without the +1 default rule)
BASE_COLOR  = "#424242"


def savefig(fname: str):
    """Save current figure to file and close (no display)."""
    plt.savefig(fname, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"  📊 Saved: {fname}")


# ── Figure 1: Avg Comparisons vs Rules ───────────────────────────────────────
def fig1_comparisons(df, n_packets):
    sub  = df[df["n_packets"] == n_packets]
    rule_sizes = sorted(sub["n_rules"].unique())

    fig, ax = plt.subplots(figsize=(8, 5))
    base = sub.groupby("n_rules")["comp_base_mean"].mean()
    ax.plot(RULE_LABELS, base.values, "--s",
            lw=2.5, ms=8, color=BASE_COLOR, label="Without AFLP (Baseline)")

    for mode in MODES:
        sm = sub[sub["mode"] == mode]
        v  = sm.groupby("n_rules")["comp_aflp_mean"].mean()
        ax.plot(RULE_LABELS, v.values, "o-",
                lw=2.2, ms=7, color=MODE_COLOR[mode], label=MODE_LABEL[mode])

    ax.set_xlabel("Number of Rules")
    ax.set_ylabel("Average Comparisons per Packet")
    ax.set_title(f"Average Comparisons per Packet vs Number of Rules\n"
                 f"(Packets = {n_packets:,}, Skew = {SKEW_RATIO*100:.0f}%)")
    ax.set_xticks(RULE_LABELS)
    ax.legend(); ax.grid(True, alpha=0.3)
    plt.tight_layout()
    savefig(f"fig1_comparisons_{n_packets}.png")


# ── Figure 2: Processing Time vs Rules ───────────────────────────────────────
def fig2_time(df, n_packets):
    sub = df[df["n_packets"] == n_packets]
    fig, ax = plt.subplots(figsize=(8, 5))
    base = sub.groupby("n_rules")["time_base_mean_ms"].mean()
    ax.plot(RULE_LABELS, base.values, "--s",
            lw=2.5, ms=8, color=BASE_COLOR, label="Without AFLP (Baseline)")

    for mode in MODES:
        sm = sub[sub["mode"] == mode]
        v  = sm.groupby("n_rules")["time_aflp_mean_ms"].mean()
        e  = sm.groupby("n_rules")["time_aflp_std_ms"].mean()
        ax.errorbar(RULE_LABELS, v.values, yerr=e.values,
                    fmt="o-", lw=2.2, ms=7, capsize=4,
                    color=MODE_COLOR[mode], label=MODE_LABEL[mode])

    ax.set_xlabel("Number of Rules")
    ax.set_ylabel("Processing Time (ms)")
    ax.set_title(f"Processing Time vs Number of Rules\n"
                 f"(Packets = {n_packets:,}, Skew = {SKEW_RATIO*100:.0f}%)")
    ax.set_xticks(RULE_LABELS)
    ax.legend(); ax.grid(True, alpha=0.3)
    plt.tight_layout()
    savefig(f"fig2_time_{n_packets}.png")


# ── Figure 3: Improvement % Grouped Bar ──────────────────────────────────────
def fig3_improvement(df):
    import numpy as np
    fig, axes = plt.subplots(1, 2, figsize=(13, 5))
    fig.suptitle("AFLP Improvement over Baseline (%) — All Scenarios",
                 fontsize=13, fontweight="bold")

    for ax, col, ylabel, title in [
        (axes[0], "comp_improve_pct",
         "Comparisons Reduction (%)", "(a) Comparisons Reduction"),
        (axes[1], "time_improve_pct",
         "Processing Time Reduction (%)", "(b) Processing Time Reduction"),
    ]:
        sub100k = df[df["n_packets"] == 100_000]
        x = np.arange(len(RULE_LABELS))
        w = 0.25
        for i, mode in enumerate(MODES):
            vals = []
            for rl in [11, 51, 101, 201]:   # internal rule count (with default)
                row = sub100k[(sub100k["mode"] == mode) &
                              (sub100k["n_rules"] == rl)]
                vals.append(row[col].values[0] if len(row) > 0 else 0)
            bars = ax.bar([xi + (i - 1) * w for xi in x], vals, w,
                          label=MODE_LABEL[mode],
                          color=MODE_COLOR[mode], alpha=0.85,
                          edgecolor="white")
            for bar, v in zip(bars, vals):
                ax.text(bar.get_x() + bar.get_width() / 2,
                        bar.get_height() + (0.5 if v >= 0 else -3),
                        f"{v:.1f}%", ha="center", va="bottom",
                        fontsize=7.5, fontweight="bold")

        ax.axhline(0, color="black", lw=0.8)
        ax.set_xticks(x)
        ax.set_xticklabels([f"{r} rules" for r in RULE_LABELS])
        ax.set_ylabel(ylabel); ax.set_title(title)
        ax.legend(); ax.grid(True, alpha=0.3, axis="y")

    plt.tight_layout()
    savefig("fig3_improvement.png")


# ── Figure 4: Threshold Reorder Count Comparison (v3 vs v4) ──────────────────
def fig4_reorder_comparison(df):
    import numpy as np
    sub = df[(df["n_packets"] == 100_000) & (df["mode"] == "threshold")]
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    fig.suptitle("AFLP-Threshold v4 (EMA+Cooldown): Reorder Count & Improvement\n"
                 "(N = 100,000 packets)", fontsize=12, fontweight="bold")

    # Reorder counts
    ax = axes[0]
    vals = [sub[sub["n_rules"] == rl]["avg_reorder_count"].values[0]
            for rl in [11, 51, 101, 201]]
    x = np.arange(len(RULE_LABELS))
    bars = ax.bar(x, vals, color=MODE_COLOR["threshold"], alpha=0.85, edgecolor="white")
    for bar, v in zip(bars, vals):
        ax.text(bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.3, f"{v:.1f}",
                ha="center", va="bottom", fontsize=9, fontweight="bold")
    ax.set_xticks(x); ax.set_xticklabels([f"{r} rules" for r in RULE_LABELS])
    ax.set_ylabel("Average Reorder Events per Run")
    ax.set_title("Reorder Count (v4 EMA+Cooldown)")
    ax.grid(True, alpha=0.3, axis="y")
    # Reference line: v3 had ~50,000+ reorders
    ax.axhline(10, color="red", ls="--", lw=1.5,
               label=f"v3 had ~50,000+\nv4 target: ≈{10}")
    ax.legend(fontsize=8)

    # Improvement %
    ax = axes[1]
    comp_vals = [sub[sub["n_rules"] == rl]["comp_improve_pct"].values[0]
                 for rl in [11, 51, 101, 201]]
    time_vals = [sub[sub["n_rules"] == rl]["time_improve_pct"].values[0]
                 for rl in [11, 51, 101, 201]]
    w = 0.35
    b1 = ax.bar(x - w / 2, comp_vals, w, label="Comparisons↓%",
                color="#1565C0", alpha=0.85, edgecolor="white")
    b2 = ax.bar(x + w / 2, time_vals, w, label="Time↓%",
                color="#E65100", alpha=0.85, edgecolor="white")
    for bars, vals_ in [(b1, comp_vals), (b2, time_vals)]:
        for bar, v in zip(bars, vals_):
            ax.text(bar.get_x() + bar.get_width() / 2,
                    bar.get_height() + (0.5 if v >= 0 else -3),
                    f"{v:.1f}%", ha="center", va="bottom",
                    fontsize=8, fontweight="bold")
    ax.axhline(0, color="black", lw=0.8)
    ax.set_xticks(x); ax.set_xticklabels([f"{r} rules" for r in RULE_LABELS])
    ax.set_ylabel("Improvement over Baseline (%)")
    ax.set_title("AFLP-Threshold v4: Performance Improvement")
    ax.legend(); ax.grid(True, alpha=0.3, axis="y")

    plt.tight_layout()
    savefig("fig4_threshold_v4.png")


# ── Figure 5: Phase-trace — comparisons over packet index ────────────────────
def fig5_phase_trace(rules, n_packets=10_000):
    """Show how comparisons change over time for each mode."""
    import numpy as np
    packets  = generate_skewed_traffic(rules, n_packets, SKEW_RATIO, seed=99)
    interval = n_packets // 10
    window   = max(n_packets // 50, 100)

    fig, axes = plt.subplots(1, 3, figsize=(15, 4))
    fig.suptitle(f"Comparisons per Packet over Time — Phase Transition Effect\n"
                 f"(Rules={len(rules)-1}, Packets={n_packets:,}, "
                 f"Skew={SKEW_RATIO*100:.0f}%)",
                 fontsize=12, fontweight="bold")

    for ax, mode in zip(axes, MODES):
        fw_b  = TreeRuleFirewall(rules[:], FIELDS[:])
        fw_a  = TreeRuleFirewall(rules[:], FIELDS[:])
        kw = {"interval": interval} if mode == "periodic" else \
             {"threshold": THR_DELTA, "ema_alpha": EMA_ALPHA,
              "min_interval": max(200, n_packets // 20)} if mode == "threshold" else {}
        ctrl = AFLPController(fw_a, mode=mode, **kw)

        bt, at, xs = [], [], []
        for i, pkt in enumerate(packets):
            _, cb = fw_b.match_packet(pkt)
            _, ca = ctrl.process_packet(pkt)
            if mode == "ondemand" and i == n_packets // 2 - 1:
                ctrl.trigger()
            if (i + 1) % window == 0:
                bt.append(cb); at.append(ca); xs.append(i + 1)

        ax.plot(xs, bt, "--", lw=1.8, color=BASE_COLOR, label="Without AFLP", alpha=0.8)
        ax.plot(xs, at, lw=2, color=MODE_COLOR[mode], label=MODE_LABEL[mode])
        ax.axvline(n_packets // 2, color="red", lw=1.5, ls=":",
                   label="Phase shift")
        for pkt_idx, _ in ctrl.order_log:
            ax.axvline(pkt_idx, color=MODE_COLOR[mode],
                       lw=0.8, ls="--", alpha=0.5)
        ax.set_xlabel("Packet Index")
        ax.set_ylabel("Comparisons / Packet")
        ax.set_title(MODE_LABEL[mode])
        ax.legend(fontsize=8); ax.grid(True, alpha=0.3)
        ax.text(0.98, 0.05, f"reorders={ctrl.reorder_count}",
                transform=ax.transAxes, ha="right", fontsize=8,
                color=MODE_COLOR[mode], fontweight="bold")

    plt.tight_layout()
    savefig("fig5_phase_trace.png")


# ── Generate all figures ──────────────────────────────────────────────────────
print("\n📊 Generating figures (saved to PNG, no display)...")

for npkt in PACKET_SIZES:
    fig1_comparisons(df, npkt)
    fig2_time(df, npkt)

fig3_improvement(df)
fig4_reorder_comparison(df)
fig5_phase_trace(generate_rules(100), n_packets=10_000)

print("\n✅ All done!")
print("\nFiles created:")
print("  aflp_results_v4.csv")
for npkt in PACKET_SIZES:
    print(f"  fig1_comparisons_{npkt}.png")
    print(f"  fig2_time_{npkt}.png")
print("  fig3_improvement.png")
print("  fig4_threshold_v4.png")
print("  fig5_phase_trace.png")
