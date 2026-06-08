# =============================================================================
#  Simulation v3: Automatic Field-Level Positioning (AFLP) in Tree-Rule Firewall
#  FIXED: Frequency counting uses "elimination rate" per field
#
#  Core idea (Chomsiri):
#    A field at Level k is "effective" if it eliminates many branches early.
#    We measure this by counting how many packets are RESOLVED (matched to
#    a unique sub-tree) at each level. The field that resolves the most
#    packets earliest should be placed at Level 1 (Root).
#
#  Concretely:
#    elim[F] = number of packets where field F reduced candidates to 1 subtree
#            = number of packets where only 1 child node matched at that level
#
#  Paper: "Automatic Field-Level Positioning in Tree-Rule Firewall Based on
#          Traffic Frequency for Processing Speed Improvement"
#  Author: Thawatchai Chomsiri
# =============================================================================

import time, random, statistics, warnings
import pandas as pd
import matplotlib.pyplot as plt
from collections import defaultdict
from dataclasses import dataclass
from typing import List, Tuple, Optional

warnings.filterwarnings("ignore")

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 1: Constants
# ─────────────────────────────────────────────────────────────────────────────

FIELDS = ["src_ip", "dst_ip", "protocol", "dst_port"]
FIELD_LABELS = {"src_ip":"Source IP","dst_ip":"Destination IP",
                "protocol":"Protocol","dst_port":"Destination Port"}

SRC_SUBNETS  = [f"192.168.{i}" for i in range(1, 11)]
DST_HOSTS    = [f"10.10.0.{i}"  for i in range(1, 21)]
PROTOCOLS    = ["TCP", "UDP", "ICMP"]
COMMON_PORTS = ["80", "443", "22", "53", "8080", "3306", "21", "25"]

MODE_COLOR = {"periodic":"#1976D2","threshold":"#388E3C","ondemand":"#F57C00"}
MODE_LABEL = {"periodic":"Periodic","threshold":"Threshold-based",
              "ondemand":"On-demand"}


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 2: Data Structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Rule:
    src_ip:str; dst_ip:str; protocol:str; dst_port:str; action:str
    def as_dict(self):
        return {"src_ip":self.src_ip,"dst_ip":self.dst_ip,
                "protocol":self.protocol,"dst_port":self.dst_port}

@dataclass
class Packet:
    src_ip:str; dst_ip:str; protocol:str; dst_port:str
    def as_dict(self):
        return {"src_ip":self.src_ip,"dst_ip":self.dst_ip,
                "protocol":self.protocol,"dst_port":self.dst_port}


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 3: Rule Generator
# ─────────────────────────────────────────────────────────────────────────────

def generate_rules(n:int, seed:int=42) -> List[Rule]:
    """
    Generate n rules with diverse field values so the tree has
    real branching at every level under any field ordering.
    """
    random.seed(seed)
    rules = []
    # Spread rules evenly across subnets and destinations
    for i in range(n):
        src   = f"{SRC_SUBNETS[i % len(SRC_SUBNETS)]}.{(i*7+1) % 254 + 1}"
        dst   = DST_HOSTS[i % len(DST_HOSTS)]
        proto = PROTOCOLS[i % len(PROTOCOLS)]
        port  = COMMON_PORTS[i % len(COMMON_PORTS)]
        action = "Accept" if i % 3 != 0 else "Deny"
        rules.append(Rule(src, dst, proto, port, action))
    rules.append(Rule("*","*","*","*","Deny"))
    return rules


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 4: 2-Phase Skewed Traffic Generator
# ─────────────────────────────────────────────────────────────────────────────

def generate_skewed_traffic(rules:List[Rule], n_packets:int,
                             skew_ratio:float=0.90,
                             seed:int=0) -> List[Packet]:
    """
    Phase 1 (first half):  skew_ratio of packets go to ONE dst_ip
                           → dst_ip should dominate → AFLP places it at L1
    Phase 2 (second half): skew_ratio of packets come from ONE src_ip
                           → src_ip should dominate → AFLP repositions to L1

    Uses EXACT values present in the rule set so the tree actually matches them.
    """
    random.seed(seed)
    real_rules = [r for r in rules if r.src_ip != "*"]

    # Hot values taken directly from the rule set
    hot_dst   = real_rules[0].dst_ip       # "10.10.0.1"
    hot_src   = real_rules[0].src_ip       # "192.168.1.1"
    hot_proto = real_rules[0].protocol
    hot_port  = real_rules[0].dst_port

    packets, half = [], n_packets // 2

    # ── Phase 1: dst_ip dominant ─────────────────────────────────────────────
    for _ in range(half):
        if random.random() < skew_ratio:
            r   = random.choice(real_rules)
            pkt = Packet(src_ip=r.src_ip,
                         dst_ip=hot_dst,         # ← fixed hot dst
                         protocol=r.protocol,
                         dst_port=r.dst_port)
        else:
            r   = random.choice(real_rules)
            pkt = Packet(r.src_ip, r.dst_ip, r.protocol, r.dst_port)
        packets.append(pkt)

    # ── Phase 2: src_ip dominant ─────────────────────────────────────────────
    for _ in range(n_packets - half):
        if random.random() < skew_ratio:
            r   = random.choice(real_rules)
            pkt = Packet(src_ip=hot_src,          # ← fixed hot src
                         dst_ip=r.dst_ip,
                         protocol=r.protocol,
                         dst_port=r.dst_port)
        else:
            r   = random.choice(real_rules)
            pkt = Packet(r.src_ip, r.dst_ip, r.protocol, r.dst_port)
        packets.append(pkt)

    return packets


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 5: Tree-Rule Firewall Engine  ← KEY FIX
# ─────────────────────────────────────────────────────────────────────────────

class TreeRuleFirewall:
    """
    Tree-Rule Firewall with Elimination-Rate frequency counting.

    elim[F] counts how many times field F had EXACTLY ONE matching child node,
    meaning it uniquely resolved the packet's path at that level.
    Fields with high elim[F] are the most discriminating and should be at L1.
    """

    def __init__(self, rules:List[Rule], field_order:List[str]=None):
        self.rules       = rules
        self.field_order = field_order or FIELDS[:]
        self.tree        = {}
        # elim[f]  = times field f had exactly 1 matching child (unique resolution)
        # visit[f] = times field f was checked at all
        self.elim  = defaultdict(int)
        self.visit = defaultdict(int)
        self.total_packets = 0
        self._build_tree()

    def _build_tree(self):
        self.tree = {}
        for rule in self.rules:
            node = self.tree
            rd   = rule.as_dict()
            for f in self.field_order:
                val = rd[f]
                node = node.setdefault(val, {})
            node["__action__"] = rule.action

    def _match(self, rv:str, pv:str) -> bool:
        return rv == "*" or rv == pv

    def match_packet(self, pkt:Packet) -> Tuple[str, int]:
        pd_ = pkt.as_dict()
        comparisons = [0]

        def _search(node:dict, depth:int) -> Optional[str]:
            if depth == len(self.field_order):
                return node.get("__action__", "Deny")

            f       = self.field_order[depth]
            pkt_val = pd_[f]

            # Count all children that would match (for elimination measure)
            matching_children = [
                (rv, child) for rv, child in node.items()
                if rv != "__action__" and self._match(rv, pkt_val)
            ]
            self.visit[f] += 1
            comparisons[0] += len(node) - (1 if "__action__" in node else 0)

            # Elimination: if exactly 1 child matched → field fully resolved
            if len(matching_children) == 1:
                self.elim[f] += 1

            for rv, child in matching_children:
                result = _search(child, depth + 1)
                if result is not None:
                    return result
            return None

        action = _search(self.tree, 0) or "Deny"
        self.total_packets += 1
        return action, comparisons[0]

    def get_elim_rate(self) -> dict:
        """Elimination rate per field = elim[f] / visit[f]."""
        return {
            f: self.elim[f] / max(self.visit[f], 1)
            for f in FIELDS
        }

    def optimal_order(self) -> List[str]:
        """Sort fields by elimination rate descending → best field at L1."""
        er = self.get_elim_rate()
        return sorted(FIELDS, key=lambda f: er.get(f, 0), reverse=True)

    def apply_order(self, new_order:List[str]):
        self.field_order = new_order
        self.elim  = defaultdict(int)
        self.visit = defaultdict(int)
        self.total_packets = 0
        self._build_tree()


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 6: AFLP Controller (3 Trigger Modes)
# ─────────────────────────────────────────────────────────────────────────────

class AFLPController:
    def __init__(self, firewall:TreeRuleFirewall,
                 mode:str="periodic",
                 interval:int=1000,
                 threshold:float=0.10):
        assert mode in ("periodic","threshold","ondemand")
        self.fw            = firewall
        self.mode          = mode
        self.interval      = interval
        self.threshold     = threshold
        self.reorder_count = 0
        self._pkt_count    = 0
        self._prev_er      = {}
        self.order_log     = []   # [(packet_idx, new_order)]

    def process_packet(self, pkt:Packet) -> Tuple[str,int]:
        action, comps = self.fw.match_packet(pkt)
        self._pkt_count += 1

        if self.mode == "periodic":
            if self._pkt_count % self.interval == 0:
                self._do_reorder()

        elif self.mode == "threshold":
            cur = self.fw.get_elim_rate()
            if self._prev_er:
                for f in FIELDS:
                    old = self._prev_er.get(f, 1e-9)
                    new = cur.get(f, 0)
                    if old > 0 and abs(new - old) / old > self.threshold:
                        self._do_reorder()
                        break
            self._prev_er = cur

        return action, comps

    def trigger(self):
        if self.mode == "ondemand":
            self._do_reorder()

    def _do_reorder(self):
        new_order = self.fw.optimal_order()
        if new_order != self.fw.field_order:
            self.order_log.append((self._pkt_count, new_order[:]))
            self.fw.apply_order(new_order)
            self.reorder_count += 1


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 7: Experiment Runner
# ─────────────────────────────────────────────────────────────────────────────

def run_experiment(rules:List[Rule], packets:List[Packet],
                   mode:str, n_repeats:int=30, **kwargs) -> dict:
    cb_list, tb_list, ca_list, ta_list, rc_list = [],[],[],[],[]

    for rep in range(n_repeats):
        p1 = packets[:len(packets)//2][:]
        p2 = packets[len(packets)//2:][:]
        random.seed(rep)
        random.shuffle(p1); random.shuffle(p2)
        sh = p1 + p2

        # Baseline
        fw0 = TreeRuleFirewall(rules[:], FIELDS[:])
        cs, t0 = [], time.perf_counter()
        for pkt in sh:
            _, c = fw0.match_packet(pkt); cs.append(c)
        cb_list.append(statistics.mean(cs))
        tb_list.append((time.perf_counter()-t0)*1000)

        # AFLP
        fw1  = TreeRuleFirewall(rules[:], FIELDS[:])
        ctrl = AFLPController(fw1, mode=mode, **kwargs)
        cs2, t1 = [], time.perf_counter()
        for i, pkt in enumerate(sh):
            _, c = ctrl.process_packet(pkt); cs2.append(c)
            if mode == "ondemand" and i == len(sh)//2 - 1:
                ctrl.trigger()
        ca_list.append(statistics.mean(cs2))
        ta_list.append((time.perf_counter()-t1)*1000)
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
        "comp_improve_pct"  : round((1-ca/cb)*100, 2) if cb>0 else 0,
        "time_improve_pct"  : round((1-ta/tb)*100, 2) if tb>0 else 0,
        "avg_reorder_count" : round(statistics.mean(rc_list), 1),
    }


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 8: Main
# ─────────────────────────────────────────────────────────────────────────────

RULE_SIZES   = [10, 50, 100, 200]
PACKET_SIZES = [10_000, 100_000]
MODES        = ["periodic","threshold","ondemand"]
SKEW_RATIO   = 0.90
N_REPEATS    = 30

print("="*70)
print("  AFLP Simulation v3 — Elimination-Rate Frequency Counting")
print("="*70)

all_results = []
for n_rules in RULE_SIZES:
    rules = generate_rules(n_rules)
    for n_pkts in PACKET_SIZES:
        packets = generate_skewed_traffic(rules, n_pkts, SKEW_RATIO)
        for mode in MODES:
            kw = {}
            if mode=="periodic"  : kw={"interval": n_pkts//10}
            if mode=="threshold" : kw={"threshold": 0.10}
            print(f"  rules={n_rules:>3}  pkts={n_pkts:>7,}  "
                  f"mode={mode:<10} ",end="",flush=True)
            res = run_experiment(rules, packets, mode,
                                 n_repeats=N_REPEATS, **kw)
            all_results.append(res)
            print(f"comp↓{res['comp_improve_pct']:+6.2f}%  "
                  f"time↓{res['time_improve_pct']:+6.2f}%  "
                  f"reorders={res['avg_reorder_count']:.1f}")

df = pd.DataFrame(all_results)
df.to_csv("aflp_results_v3.csv", index=False)
print("\n✅  Saved: aflp_results_v3.csv")


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 9: Quick Diagnostic — Elim-rate trace for 1 scenario
# ─────────────────────────────────────────────────────────────────────────────

print("\n── Elimination-rate diagnostic (100 rules, 10k pkts, periodic) ──")
rules_diag   = generate_rules(100)
packets_diag = generate_skewed_traffic(rules_diag, 10_000, SKEW_RATIO)
fw_diag      = TreeRuleFirewall(rules_diag[:], FIELDS[:])
ctrl_diag    = AFLPController(fw_diag, mode="periodic", interval=1000)

for i, pkt in enumerate(packets_diag):
    ctrl_diag.process_packet(pkt)
    if i == len(packets_diag)//2 - 1:
        er = fw_diag.get_elim_rate()
        print(f"\n  After Phase 1 (pkt {i+1}) — Elimination Rate:")
        for f in FIELDS:
            print(f"    {FIELD_LABELS[f]:<20}: {er[f]:.4f}")
        print(f"  Current field order  : {fw_diag.field_order}")
        print(f"  Optimal order would  : {fw_diag.optimal_order()}")

er2 = fw_diag.get_elim_rate()
print(f"\n  After Phase 2 (pkt {len(packets_diag)}) — Elimination Rate:")
for f in FIELDS:
    print(f"    {FIELD_LABELS[f]:<20}: {er2[f]:.4f}")
print(f"  Final field order    : {fw_diag.field_order}")
print(f"  Total reorders       : {ctrl_diag.reorder_count}")
print(f"  Order change log     : {ctrl_diag.order_log}")


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 10: Figures
# ─────────────────────────────────────────────────────────────────────────────

def fig1_comparisons(df, n_packets):
    sub  = df[df["n_packets"]==n_packets]
    fig, ax = plt.subplots(figsize=(8,5))
    base = sub.groupby("n_rules")["comp_base_mean"].mean()
    ax.plot(base.index, base.values, "k--s", lw=2.5, ms=7,
            label="Without AFLP", zorder=5)
    for mode in MODES:
        sm = sub[sub["mode"]==mode]
        v  = sm.groupby("n_rules")["comp_aflp_mean"].mean()
        ax.plot(v.index, v.values, "o-", lw=2, ms=6,
                color=MODE_COLOR[mode], label=f"AFLP-{MODE_LABEL[mode]}")
    ax.set_xlabel("Number of Rules", fontsize=12)
    ax.set_ylabel("Average Comparisons per Packet", fontsize=12)
    ax.set_title(f"Average Comparisons per Packet vs Number of Rules\n"
                 f"(Packets={n_packets:,}, Skew={SKEW_RATIO*100:.0f}%)",
                 fontsize=12)
    ax.set_xticks(RULE_SIZES); ax.legend(fontsize=10); ax.grid(True,alpha=0.3)
    plt.tight_layout()
    fn = f"fig1_comparisons_{n_packets}.png"
    plt.savefig(fn, dpi=150, bbox_inches="tight"); plt.show()
    print(f"📊 {fn}")

def fig2_improvement(df):
    fig, axes = plt.subplots(1,2,figsize=(13,5))
    fig.suptitle("AFLP Improvement over Baseline (%) — All Scenarios",
                 fontsize=13, fontweight="bold")
    for ax, col, ylabel, title in [
        (axes[0],"comp_improve_pct","Comparisons Reduction (%)","Comparisons"),
        (axes[1],"time_improve_pct","Time Reduction (%)","Processing Time"),
    ]:
        pivot = (df.groupby(["mode","n_rules"])[col]
                   .mean().unstack().reindex(MODES))
        x, w = range(len(RULE_SIZES)), 0.25
        for i, mode in enumerate(MODES):
            vals = [pivot.loc[mode,r] for r in RULE_SIZES]
            bars = ax.bar([xi+i*w for xi in x], vals, w,
                          label=MODE_LABEL[mode], color=MODE_COLOR[mode],
                          alpha=0.85, edgecolor="white")
            for bar, v in zip(bars, vals):
                ax.text(bar.get_x()+bar.get_width()/2,
                        bar.get_height()+0.2, f"{v:.1f}%",
                        ha="center", va="bottom", fontsize=7.5,
                        fontweight="bold")
        ax.axhline(0, color="black", lw=0.8)
        ax.set_xticks([xi+w for xi in x])
        ax.set_xticklabels([f"{r} rules" for r in RULE_SIZES])
        ax.set_ylabel(ylabel,fontsize=11); ax.set_title(title,fontsize=11)
        ax.legend(fontsize=9); ax.grid(True,alpha=0.3,axis="y")
    plt.tight_layout()
    plt.savefig("fig2_improvement.png",dpi=150,bbox_inches="tight")
    plt.show(); print("📊 fig2_improvement.png")

def fig3_phase_trace(rules, n_packets=10_000):
    """Show comparisons over packet index for all 3 modes."""
    fig, axes = plt.subplots(1,3,figsize=(15,4))
    fig.suptitle(f"Comparisons per Packet over Time — Phase Transition Effect\n"
                 f"(Rules={len(rules)-1}, Packets={n_packets:,}, "
                 f"Skew={SKEW_RATIO*100:.0f}%)",
                 fontsize=12, fontweight="bold")

    for ax, mode in zip(axes, MODES):
        packets = generate_skewed_traffic(rules, n_packets, SKEW_RATIO, seed=99)
        fw_b    = TreeRuleFirewall(rules[:], FIELDS[:])
        fw_a    = TreeRuleFirewall(rules[:], FIELDS[:])
        interval = n_packets // 10
        ctrl    = AFLPController(fw_a, mode=mode,
                                 interval=interval, threshold=0.10)
        window  = max(n_packets // 50, 100)
        bt, at, xs = [], [], []
        for i, pkt in enumerate(packets):
            _, cb = fw_b.match_packet(pkt)
            _, ca = ctrl.process_packet(pkt)
            if mode == "ondemand" and i == n_packets//2 - 1:
                ctrl.trigger()
            if (i+1) % window == 0:
                bt.append(cb); at.append(ca)
                xs.append(i+1)
        ax.plot(xs, bt, "k--", lw=1.8, label="Without AFLP", alpha=0.8)
        ax.plot(xs, at, color=MODE_COLOR[mode], lw=2,
                label=f"AFLP-{MODE_LABEL[mode]}")
        ax.axvline(n_packets//2, color="red", lw=1.5, ls=":",
                   label="Phase shift")
        # mark reorder events
        for pkt_idx, _ in ctrl.order_log:
            ax.axvline(pkt_idx, color=MODE_COLOR[mode],
                       lw=0.8, ls="--", alpha=0.5)
        ax.set_xlabel("Packet Index", fontsize=10)
        ax.set_ylabel("Comparisons / Packet", fontsize=10)
        ax.set_title(MODE_LABEL[mode], fontsize=11)
        ax.legend(fontsize=8); ax.grid(True,alpha=0.3)

    plt.tight_layout()
    plt.savefig("fig3_phase_trace.png",dpi=150,bbox_inches="tight")
    plt.show(); print("📊 fig3_phase_trace.png")

# Generate figures
for npkt in PACKET_SIZES:
    fig1_comparisons(df, npkt)
fig2_improvement(df)
fig3_phase_trace(generate_rules(100), n_packets=10_000)

print("\n✅ All done!")
print("Files ready for paper:")
for f in ["aflp_results_v3.csv",
          "fig1_comparisons_10000.png","fig1_comparisons_100000.png",
          "fig2_improvement.png","fig3_phase_trace.png"]:
    print(f"  {f}")
