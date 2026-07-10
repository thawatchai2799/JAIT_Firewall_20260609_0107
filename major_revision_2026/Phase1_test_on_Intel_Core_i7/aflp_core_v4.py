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


