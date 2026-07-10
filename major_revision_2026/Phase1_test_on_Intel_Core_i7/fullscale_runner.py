# =============================================================================
#  fullscale_runner.py — Full-scale confirmation runs for the JAIT-22676 revision
#
#  Reproduces every NEW experiment added during the major revision at the
#  paper-standard scale: N = 100,000 packets, 30 repetitions, n = 200 rules
#  (unless an experiment inherently varies these).
#
#  REQUIREMENTS:
#    - Place this file in the same directory as aflp_simulation_v4.py
#      (from https://github.com/thawatchai2799/JAIT_Firewall_20260609_0107)
#    - Python 3.9+; pandas, matplotlib (same as the original simulation)
#
#  USAGE:
#    python fullscale_runner.py all            # run everything (~1-2 hours)
#    python fullscale_runner.py skew           # or any single experiment:
#    #  skew | patterns | timing | baselines | correctness | throughput
#    #  ema | crossover | naive
#
#  Each experiment writes a CSV named fullscale_<name>.csv in the current
#  directory. All comparison-count metrics are deterministic; timing metrics
#  depend on the machine and should be reported from THIS machine's run.
# =============================================================================

import sys, random, statistics, itertools, json, time as timemod
import warnings; warnings.filterwarnings("ignore")

# ---- load core definitions (Sections 1-7) from the published v4 simulation ----
_src = open("aflp_simulation_v4.py", encoding="utf-8").read()
_cut = _src.split("# SECTION 8")[0]
exec(compile(_cut, "aflp_core_defs", "exec"))

N_PACKETS = 100_000
N_REPEATS = 30
N_RULES   = 200

# ---- Fixed Threshold-EMA controller (initialisation defect corrected) ----
class AFLPControllerFixed(AFLPController):
    """Corrects the initialisation defect: the EMA baseline snapshot is now
    established at the first post-cooldown checkpoint, so the trigger
    condition can actually be evaluated."""
    def process_packet(self, pkt):
        action, comps = self.fw.match_packet(pkt)
        self._pkt_count += 1
        if self.mode == "periodic":
            if self._pkt_count % self.interval == 0:
                self._do_reorder()
        elif self.mode == "threshold":
            self._update_ema()
            cooldown_ok = (self._pkt_count - self._last_reorder_at) >= self.min_interval
            if cooldown_ok:
                if not self._ema_prev:
                    self._ema_prev = dict(self._ema)
                    self._last_reorder_at = self._pkt_count
                else:
                    for f in FIELDS:
                        old = self._ema_prev.get(f, 1e-9)
                        new = self._ema.get(f, 0.0)
                        if old > 1e-6 and abs(new - old) / old > self.threshold:
                            self._do_reorder()
                            break
        return action, comps

    def _do_reorder(self):
        new_order = self.fw.optimal_order()
        if new_order != self.fw.field_order:
            self.order_log.append((self._pkt_count, new_order[:]))
            self.fw.apply_order(new_order)
            self.reorder_count += 1
        self._ema_prev = dict(self._ema)
        self._last_reorder_at = self._pkt_count


def _shuffled(packets, rep):
    half = len(packets) // 2
    p1, p2 = packets[:half][:], packets[half:][:]
    random.seed(rep)
    random.shuffle(p1); random.shuffle(p2)
    return p1 + p2


def _csv(name, rows, header):
    fn = f"fullscale_{name}.csv"
    with open(fn, "w") as f:
        f.write(",".join(header) + "\n")
        for r in rows:
            f.write(",".join(str(x) for x in r) + "\n")
    print(f"  -> saved {fn}")


# =============================================================================
# 1) SKEW — imbalance sensitivity 50-95% (manuscript Section VI.D.1)
# =============================================================================
def run_skew():
    print("[skew] imbalance sensitivity, n=200, N=100k, 30 reps per ratio")
    rules = generate_rules(N_RULES)
    rows = []
    for skew in [0.50, 0.60, 0.70, 0.80, 0.90, 0.95]:
        packets = generate_skewed_traffic(rules, N_PACKETS, skew)
        interval = N_PACKETS // 10
        ci_p, ti_p, ci_o, ti_o = [], [], [], []
        for rep in range(N_REPEATS):
            sh = _shuffled(packets, rep)
            fw0 = TreeRuleFirewall(rules[:], FIELDS[:])
            t0 = timemod.perf_counter(); cb = []
            for pkt in sh:
                _, c = fw0.match_packet(pkt); cb.append(c)
            tb = timemod.perf_counter() - t0; cbm = statistics.mean(cb)

            fw1 = TreeRuleFirewall(rules[:], FIELDS[:])
            ctrl = AFLPController(fw1, mode="periodic", interval=interval)
            t0 = timemod.perf_counter(); ca = []
            for pkt in sh:
                _, c = ctrl.process_packet(pkt); ca.append(c)
            ta = timemod.perf_counter() - t0
            ci_p.append((1 - statistics.mean(ca)/cbm)*100); ti_p.append((1 - ta/tb)*100)

            fw2 = TreeRuleFirewall(rules[:], FIELDS[:])
            ctrl2 = AFLPController(fw2, mode="ondemand")
            half = len(sh)//2
            t0 = timemod.perf_counter(); ca2 = []
            for i, pkt in enumerate(sh):
                _, c = ctrl2.process_packet(pkt); ca2.append(c)
                if i == half - 1: ctrl2.trigger()
            ta2 = timemod.perf_counter() - t0
            ci_o.append((1 - statistics.mean(ca2)/cbm)*100); ti_o.append((1 - ta2/tb)*100)
        rows.append([skew, round(statistics.mean(ci_p),2), round(statistics.mean(ti_p),2),
                     round(statistics.mean(ci_o),2), round(statistics.mean(ti_o),2)])
        print(f"  skew={skew:.2f}  Per comp {rows[-1][1]:+.2f}% time {rows[-1][2]:+.2f}%  |  OD comp {rows[-1][3]:+.2f}% time {rows[-1][4]:+.2f}%")
    _csv("skew", rows, ["skew","periodic_comp_improve","periodic_time_improve","ondemand_comp_improve","ondemand_time_improve"])


# =============================================================================
# 2) PATTERNS — gradual / multi-stage / random-change traffic (VI.D.2)
# =============================================================================
def run_patterns():
    print("[patterns] gradual / multi-stage / random-change, n=200, N=100k, 30 reps")
    rules = generate_rules(N_RULES)
    real_rules = [r for r in rules if r.src_ip != "*"]
    hot_dst, hot_src = real_rules[0].dst_ip, real_rules[0].src_ip
    hot_proto = real_rules[0].protocol

    def mk(r, ff=None, fv=None):
        d = {"src_ip": r.src_ip, "dst_ip": r.dst_ip, "protocol": r.protocol, "dst_port": r.dst_port}
        if ff: d[ff] = fv
        return Packet(**d)

    def gradual(n, seed):
        random.seed(seed); out = []
        ramp = int(n*0.2); mid = n//2
        for i in range(n):
            p_dst = 0.90 if i < mid - ramp//2 else (0.0 if i > mid + ramp//2
                     else 0.90*(1-(i-(mid-ramp//2))/ramp))
            r = random.choice(real_rules)
            if random.random() < p_dst: out.append(mk(r,"dst_ip",hot_dst))
            elif random.random() < 0.90: out.append(mk(r,"src_ip",hot_src))
            else: out.append(mk(r))
        return out

    def multistage(n, seed):
        random.seed(seed); out = []; q = n//4
        for i in range(n):
            st = min(i//q, 3); r = random.choice(real_rules)
            if random.random() < 0.90:
                if st==0: out.append(mk(r,"dst_ip",hot_dst))
                elif st==1: out.append(mk(r,"src_ip",hot_src))
                elif st==2: out.append(mk(r,"protocol",hot_proto))
                else: out.append(mk(r))
            else: out.append(mk(r))
        return out

    def randchange(n, seed):
        random.seed(seed)
        cps = sorted(random.sample(range(n//10, n-n//10), 3))
        fields = [("dst_ip",hot_dst),("src_ip",hot_src),("dst_ip",hot_dst)]
        out = []; bounds = [0]+cps+[n]
        for seg in range(len(bounds)-1):
            ff, fv = fields[seg % 3]
            for i in range(bounds[seg], bounds[seg+1]):
                r = random.choice(real_rules)
                out.append(mk(r,ff,fv) if random.random()<0.90 else mk(r))
        return out

    rows = []
    for name, gen in [("gradual",gradual),("multistage",multistage),("randomchange",randchange)]:
        imps = []
        for rep in range(N_REPEATS):
            pkts = gen(N_PACKETS, rep)
            fw0 = TreeRuleFirewall(rules[:], FIELDS[:])
            cb = [fw0.match_packet(p)[1] for p in pkts]
            fw1 = TreeRuleFirewall(rules[:], FIELDS[:])
            ctrl = AFLPController(fw1, mode="periodic", interval=N_PACKETS//10)
            ca = [ctrl.process_packet(p)[1] for p in pkts]
            imps.append((1 - statistics.mean(ca)/statistics.mean(cb))*100)
        rows.append([name, round(statistics.mean(imps),2), round(statistics.stdev(imps),2)])
        print(f"  {name:<14} comp_improve={rows[-1][1]:+.2f}% (sd={rows[-1][2]})")
    _csv("patterns", rows, ["pattern","comp_improve_mean","comp_improve_sd"])


# =============================================================================
# 3) TIMING — On-demand trigger offset sensitivity (VI.D.3)
# =============================================================================
def run_timing():
    print("[timing] On-demand trigger offsets, n=200, N=100k, 30 reps")
    rules = generate_rules(N_RULES)
    packets = generate_skewed_traffic(rules, N_PACKETS, 0.90)
    half = N_PACKETS // 2
    rows = []
    for off in [-0.40,-0.20,-0.10,-0.05,0.0,0.05,0.10,0.20,0.40]:
        trig = max(1, min(N_PACKETS-1, int(half + off*N_PACKETS)))
        imps = []
        for rep in range(N_REPEATS):
            sh = _shuffled(packets, rep)
            fw0 = TreeRuleFirewall(rules[:], FIELDS[:])
            cb = [fw0.match_packet(p)[1] for p in sh]
            fw1 = TreeRuleFirewall(rules[:], FIELDS[:])
            ctrl = AFLPController(fw1, mode="ondemand")
            ca = []
            for i, pkt in enumerate(sh):
                _, c = ctrl.process_packet(pkt); ca.append(c)
                if i == trig - 1: ctrl.trigger()
            imps.append((1 - statistics.mean(ca)/statistics.mean(cb))*100)
        rows.append([off, trig, round(statistics.mean(imps),2)])
        print(f"  offset={off:+.2f}N  comp_improve={rows[-1][2]:+.2f}%")
    _csv("timing", rows, ["offset_frac","trigger_pkt","comp_improve"])


# =============================================================================
# 4) BASELINES — fixed / random / trained / oracle orders (VI.F)
#     + 24-permutation optimality analysis (VI.G)
# =============================================================================
def run_baselines():
    print("[baselines] fixed-order baselines + optimality analysis, n=200, N=100k")
    rules = generate_rules(N_RULES)
    packets = generate_skewed_traffic(rules, N_PACKETS, 0.90)
    half = N_PACKETS // 2
    perms = list(itertools.permutations(FIELDS))

    def ev(order, pkts):
        fw = TreeRuleFirewall(rules[:], list(order))
        return statistics.mean(fw.match_packet(p)[1] for p in pkts)

    full = sorted(((ev(o, packets), o) for o in perms), key=lambda x: x[0])
    p1b  = sorted(((ev(o, packets[:half]), o) for o in perms), key=lambda x: x[0])[0]
    p2b  = sorted(((ev(o, packets[half:]), o) for o in perms), key=lambda x: x[0])[0]
    base = ev(FIELDS, packets)
    rand = statistics.mean(m for m, _ in full)
    orac = (ev(p1b[1], packets[:half])*half + ev(p2b[1], packets[half:])*(len(packets)-half))/len(packets)

    rows = [
        ["default", round(base,3), 0.0],
        ["random_avg_24", round(rand,3), round((1-rand/base)*100,2)],
        ["trained_phase1_fixed", round(ev(p1b[1], packets),3), round((1-ev(p1b[1],packets)/base)*100,2)],
        ["best_fixed", round(full[0][0],3), round((1-full[0][0]/base)*100,2)],
        ["worst_fixed", round(full[-1][0],3), round((1-full[-1][0]/base)*100,2)],
        ["oracle_per_phase", round(orac,3), round((1-orac/base)*100,2)],
    ]
    for r in rows: print(f"  {r[0]:<22} {r[1]:>10}  {r[2]:+.2f}%")
    _csv("baselines", rows, ["strategy","mean_comparisons","improve_vs_default"])

    # optimality analysis (multi-seed, n=100 as in the revision)
    print("  optimality analysis (60 configurations, n=100)...")
    ranks, gaps = [], []
    match = 0; total = 0
    for rseed in range(10):
        rl = generate_rules(100, seed=rseed if rseed>0 else 42)
        for tseed in range(3):
            pk = generate_skewed_traffic(rl, 40_000, 0.90, seed=tseed*100+rseed)
            h = len(pk)//2
            for pp in (pk[:h], pk[h:]):
                def ev2(order):
                    fw = TreeRuleFirewall(rl[:], list(order))
                    return statistics.mean(fw.match_packet(p)[1] for p in pp)
                sc = sorted(((ev2(o), o) for o in perms), key=lambda x: x[0])
                fw = TreeRuleFirewall(rl[:], FIELDS[:])
                for p in pp: fw.match_packet(p)
                ao = tuple(fw.optimal_order())
                rank = next(i for i,(m,o) in enumerate(sc,1) if o == ao)
                gap = (ev2(ao)/sc[0][0]-1)*100
                ranks.append(rank); gaps.append(gap); total += 1
                if ao == sc[0][1]: match += 1
    print(f"  rank mean={statistics.mean(ranks):.2f} min={min(ranks)} max={max(ranks)}; "
          f"gap mean={statistics.mean(gaps):.2f}% max={max(gaps):.2f}%; exact={match}/{total}")
    _csv("optimality", [[statistics.mean(ranks), min(ranks), max(ranks),
                         round(statistics.mean(gaps),2), round(max(gaps),2), match, total]],
         ["rank_mean","rank_min","rank_max","gap_mean_pct","gap_max_pct","exact_matches","total"])


# =============================================================================
# 5) CORRECTNESS — decision consistency (VI.H)
# =============================================================================
def run_correctness():
    print("[correctness] decision consistency across 24 orders + live reorders")
    rules = generate_rules(N_RULES)
    perms = list(itertools.permutations(FIELDS))
    pk = generate_skewed_traffic(rules, 5000, 0.90)
    random.seed(1)
    edge = [Packet(src_ip=f"10.99.99.{random.randint(1,254)}",
                   dst_ip=f"10.10.0.{random.randint(1,20)}",
                   protocol=random.choice(PROTOCOLS),
                   dst_port=random.choice(COMMON_PORTS)) for _ in range(500)]
    allp = pk + edge
    trees = {o: TreeRuleFirewall(rules[:], list(o)) for o in perms}
    mism = sum(1 for p in allp if len({fw.match_packet(p)[0] for fw in trees.values()}) > 1)
    print(f"  Test1: {len(allp)} packets x 24 orders -> mismatches = {mism}")

    fw = TreeRuleFirewall(rules[:], FIELDS[:])
    ctrl = AFLPController(fw, mode="periodic", interval=500)
    probe = pk[:50]
    ref = TreeRuleFirewall(rules[:], FIELDS[:])
    truth = [ref.match_packet(p)[0] for p in probe]
    bad = 0
    for i, p in enumerate(generate_skewed_traffic(rules, 5000, 0.90)):
        ctrl.process_packet(p)
        if (i+1) % 500 == 0 and [fw.match_packet(q)[0] for q in probe] != truth:
            bad += 1
    print(f"  Test2: {ctrl.reorder_count} live reorders -> mismatched checkpoints = {bad}")
    _csv("correctness", [[len(allp), mism, ctrl.reorder_count, bad]],
         ["test1_packets","test1_mismatches","test2_reorders","test2_mismatches"])


# =============================================================================
# 6) THROUGHPUT — pps, response time, isolated rebuild time (VI.I)
# =============================================================================
def run_throughput():
    print("[throughput] pps / response time / rebuild time, n=200, N=100k, 30 reps")
    rules = generate_rules(N_RULES)
    packets = generate_skewed_traffic(rules, N_PACKETS, 0.90)
    interval = N_PACKETS // 10
    agg = {"baseline": [], "periodic": [], "ondemand": []}
    for rep in range(N_REPEATS):
        sh = _shuffled(packets, rep)
        fw0 = TreeRuleFirewall(rules[:], FIELDS[:])
        t0 = timemod.perf_counter()
        for pkt in sh: fw0.match_packet(pkt)
        agg["baseline"].append(timemod.perf_counter()-t0)

        fw1 = TreeRuleFirewall(rules[:], FIELDS[:])
        ctrl = AFLPController(fw1, mode="periodic", interval=interval)
        t0 = timemod.perf_counter()
        for pkt in sh: ctrl.process_packet(pkt)
        agg["periodic"].append(timemod.perf_counter()-t0)

        fw2 = TreeRuleFirewall(rules[:], FIELDS[:])
        ctrl2 = AFLPController(fw2, mode="ondemand")
        half = len(sh)//2
        t0 = timemod.perf_counter()
        for i, pkt in enumerate(sh):
            ctrl2.process_packet(pkt)
            if i == half-1: ctrl2.trigger()
        agg["ondemand"].append(timemod.perf_counter()-t0)
    rows = []
    for k, v in agg.items():
        t = statistics.mean(v)
        rows.append([k, round(N_PACKETS/t,1), round(t/N_PACKETS*1e6,4), round(t*1000,2)])
        print(f"  {k:<10} {rows[-1][1]:>12,.1f} pps   {rows[-1][2]:>8} us/pkt   {rows[-1][3]:>9} ms total")
    _csv("throughput", rows, ["strategy","throughput_pps","avg_response_us","total_ms"])

    rrows = []
    for n in [10, 50, 100, 200]:
        rs = generate_rules(n)
        fw = TreeRuleFirewall(rs[:], FIELDS[:])
        orders = [["dst_port","dst_ip","protocol","src_ip"], ["protocol","dst_port","dst_ip","src_ip"]]
        ts = []
        for i in range(30):
            t0 = timemod.perf_counter()
            fw.apply_order(orders[i % 2])
            ts.append((timemod.perf_counter()-t0)*1000)
        rrows.append([n, round(statistics.mean(ts),4), round(statistics.stdev(ts),4)])
        print(f"  rebuild n={n:>3}: {rrows[-1][1]} ms (sd={rrows[-1][2]})")
    _csv("rebuild", rrows, ["n_rules","rebuild_ms_mean","rebuild_ms_sd"])


# =============================================================================
# 7) EMA — 28-configuration sensitivity sweep, fixed controller (VI.C)
# =============================================================================
def run_ema():
    print("[ema] Threshold-EMA sweep (fixed controller), n=200, N=100k, 5 reps/config")
    rules = generate_rules(N_RULES)
    packets = generate_skewed_traffic(rules, N_PACKETS, 0.90)
    streams, bases = [], []
    for rep in range(5):
        sh = _shuffled(packets, rep)
        fw0 = TreeRuleFirewall(rules[:], FIELDS[:])
        cb = [fw0.match_packet(p)[1] for p in sh]
        streams.append(sh); bases.append(statistics.mean(cb))
    rows = []
    for alpha in [0.05, 0.10, 0.15, 0.20, 0.30]:
        for delta in [0.05, 0.10, 0.15]:
            for cdn, cdv in [("N/20", N_PACKETS//20), ("N/10", N_PACKETS//10)]:
                rc, ci = [], []
                for rep in range(5):
                    fw1 = TreeRuleFirewall(rules[:], FIELDS[:])
                    ctrl = AFLPControllerFixed(fw1, mode="threshold", threshold=delta,
                                               ema_alpha=alpha, min_interval=cdv)
                    ca = [ctrl.process_packet(p)[1] for p in streams[rep]]
                    rc.append(ctrl.reorder_count)
                    ci.append((1 - statistics.mean(ca)/bases[rep])*100)
                rows.append([alpha, delta, cdn, round(statistics.mean(rc),1), round(statistics.mean(ci),2)])
                print(f"  a={alpha} d={delta} cd={cdn}: reorders={rows[-1][3]} improve={rows[-1][4]}%")
    _csv("ema_sweep", rows, ["alpha","delta","cooldown","avg_reorders","comp_improve"])


# =============================================================================
# 8) CROSSOVER — n = 10..50 time-improvement crossover (VI.B support)
# =============================================================================
def run_crossover():
    print("[crossover] n=10..50, N=100k, 30 reps — machine-dependent timing")
    rows = []
    for n in [10, 20, 30, 40, 50]:
        rules = generate_rules(n)
        packets = generate_skewed_traffic(rules, N_PACKETS, 0.90)
        ti, ci = [], []
        for rep in range(N_REPEATS):
            sh = _shuffled(packets, rep)
            fw0 = TreeRuleFirewall(rules[:], FIELDS[:])
            t0 = timemod.perf_counter(); cb = []
            for pkt in sh:
                _, c = fw0.match_packet(pkt); cb.append(c)
            tb = timemod.perf_counter()-t0
            fw1 = TreeRuleFirewall(rules[:], FIELDS[:])
            ctrl = AFLPController(fw1, mode="periodic", interval=N_PACKETS//10)
            t0 = timemod.perf_counter(); ca = []
            for pkt in sh:
                _, c = ctrl.process_packet(pkt); ca.append(c)
            ta = timemod.perf_counter()-t0
            ti.append((1-ta/tb)*100); ci.append((1-statistics.mean(ca)/statistics.mean(cb))*100)
        rows.append([n, round(statistics.mean(ci),2), round(statistics.mean(ti),2), round(statistics.stdev(ti),2)])
        print(f"  n={n:>3}  comp={rows[-1][1]:+.2f}%  time={rows[-1][2]:+.2f}% (sd={rows[-1][3]})")
    _csv("crossover", rows, ["n_rules","comp_improve","time_improve_mean","time_improve_sd"])


# =============================================================================
# 9) NAIVE — Threshold-Naive thrashing verification (VI.C support)
# =============================================================================
def run_naive():
    print("[naive] Threshold-Naive thrashing verification (needs aflp_simulation_v3.py)")
    _s = open("aflp_simulation_v3.py", encoding="utf-8").read()
    ns = {}
    exec(compile(_s.split("# SECTION 8: Main")[0], "v3defs", "exec"), ns)
    rows = []
    for n in [50, 200]:
        rules = ns["generate_rules"](n)
        packets = ns["generate_skewed_traffic"](rules, N_PACKETS, 0.90)
        counts = []
        for rep in range(5):
            half = len(packets)//2
            p1, p2 = packets[:half][:], packets[half:][:]
            random.seed(rep); random.shuffle(p1); random.shuffle(p2)
            fw = ns["TreeRuleFirewall"](rules[:], ns["FIELDS"][:])
            ctrl = ns["AFLPController"](fw, mode="threshold", threshold=0.10)
            for pkt in p1 + p2:
                ctrl.process_packet(pkt)
            counts.append(ctrl.reorder_count)
        rows.append([n, round(statistics.mean(counts),1), min(counts), max(counts)])
        print(f"  n={n:>3}: reorders mean={rows[-1][1]:,} range=[{rows[-1][2]:,}, {rows[-1][3]:,}]")
    _csv("naive", rows, ["n_rules","reorders_mean","reorders_min","reorders_max"])


# =============================================================================
EXPERIMENTS = {
    "skew": run_skew, "patterns": run_patterns, "timing": run_timing,
    "baselines": run_baselines, "correctness": run_correctness,
    "throughput": run_throughput, "ema": run_ema,
    "crossover": run_crossover, "naive": run_naive,
}

if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    t0 = timemod.perf_counter()
    if which == "all":
        for name, fn in EXPERIMENTS.items():
            fn()
    elif which in EXPERIMENTS:
        EXPERIMENTS[which]()
    else:
        print("usage: python fullscale_runner.py [all|" + "|".join(EXPERIMENTS) + "]")
        sys.exit(1)
    print(f"\nDone in {(timemod.perf_counter()-t0)/60:.1f} minutes.")
