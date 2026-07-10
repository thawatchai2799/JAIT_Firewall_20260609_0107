# ============================================================================
# exp11 — Verification suite for Proposition 1 (decision invariance) and the
#          expected-cost decomposition, before inserting them into the paper.
# ============================================================================
import warnings; warnings.filterwarnings('ignore')
exec(open('aflp_core_v4.py').read())
import itertools, random as rnd, statistics

perms = list(itertools.permutations(FIELDS))
PASS = True

# ---------------------------------------------------------------------------
# TEST A — Property-based test of Proposition 1:
#   Random wildcard-free rule sets (distinct tuples, RANDOM Accept/Deny mix)
#   + default-deny appended last. For random packets (matching and
#   non-matching), all 24 orders must agree AND agree with the reference
#   per-field semantics (unique matching rule's action, else Deny).
# ---------------------------------------------------------------------------
def reference_action(rules, pkt):
    """Order-free semantics: unique fully-matching specific rule, else Deny."""
    matches = [r for r in rules if r.src_ip != "*" and
               r.src_ip == pkt.src_ip and r.dst_ip == pkt.dst_ip and
               r.protocol == pkt.protocol and r.dst_port == pkt.dst_port]
    assert len(matches) <= 1, "distinct-tuple assumption violated"
    return matches[0].action if matches else "Deny"

total_pkts = 0; disagreements = 0; ref_mismatch = 0
for trial in range(40):
    rnd.seed(trial)
    n = rnd.choice([5, 20, 60])
    # random distinct tuples
    tuples = set()
    while len(tuples) < n:
        tuples.add((f"192.168.{rnd.randint(1,10)}.{rnd.randint(1,254)}",
                    f"10.10.0.{rnd.randint(1,20)}",
                    rnd.choice(PROTOCOLS), rnd.choice(COMMON_PORTS)))
    rules = [Rule(*t, rnd.choice(["Accept","Deny"])) for t in tuples]
    rules.append(Rule("*","*","*","*","Deny"))

    trees = {o: TreeRuleFirewall(rules[:], list(o)) for o in perms}
    pkts = []
    for _ in range(30):                      # packets that match a rule
        r = rnd.choice(rules[:-1])
        pkts.append(Packet(r.src_ip, r.dst_ip, r.protocol, r.dst_port))
    for _ in range(30):                      # partially/non-matching packets
        r = rnd.choice(rules[:-1])
        p = [r.src_ip, r.dst_ip, r.protocol, r.dst_port]
        for pos in rnd.sample(range(4), rnd.randint(1,4)):
            p[pos] = ["10.99.0.9","10.77.0.7","GRE","9999"][pos]
        pkts.append(Packet(*p))

    for pkt in pkts:
        total_pkts += 1
        acts = {fw.match_packet(pkt)[0] for fw in trees.values()}
        if len(acts) > 1: disagreements += 1
        if acts != {reference_action(rules, pkt)}: ref_mismatch += 1

print(f"TEST A (Proposition 1, property-based): {total_pkts} packets x 24 orders x 40 random rule sets")
print(f"  cross-order disagreements : {disagreements}")
print(f"  reference-semantics errors: {ref_mismatch}")
ok = disagreements == 0 and ref_mismatch == 0
print("  =>", "PASS" if ok else "FAIL"); PASS &= ok

# ---------------------------------------------------------------------------
# TEST B — Counter-example 1 (conflicting partial wildcards): invariance FAILS
#   Rules: (X,P)->Accept, (A,*)->Deny, (*,P)->Accept, default. Packet (A,P).
# ---------------------------------------------------------------------------
rules_ce = [Rule("X","P","TCP","80","Accept"),
            Rule("A","*","TCP","80","Deny"),
            Rule("*","P","TCP","80","Accept"),
            Rule("*","*","*","*","Deny")]
pkt_ce = Packet("A","P","TCP","80")
a_src = TreeRuleFirewall(rules_ce[:], ["src_ip","dst_ip","protocol","dst_port"]).match_packet(pkt_ce)[0]
a_dst = TreeRuleFirewall(rules_ce[:], ["dst_ip","src_ip","protocol","dst_port"]).match_packet(pkt_ce)[0]
print(f"TEST B (counter-example, conflicting wildcards): src-first={a_src}, dst-first={a_dst}")
ok = (a_src == "Deny" and a_dst == "Accept")
print("  =>", "PASS (invariance fails exactly as stated in the paper text)" if ok else "FAIL"); PASS &= ok

# ---------------------------------------------------------------------------
# TEST C — Counter-example 2 (wildcards WITHOUT action conflict among
#   matching specifics can still break invariance -> justifies scoping the
#   Proposition to wildcard-free rules, not merely 'conflict-free actions')
#   Rules: (*,Q)->Accept, (V,W)->Accept, default. Packet (V,W).
# ---------------------------------------------------------------------------
rules_c2 = [Rule("*","Q","TCP","80","Accept"),
            Rule("V","W","TCP","80","Accept"),
            Rule("*","*","*","*","Deny")]
pkt_c2 = Packet("V","W","TCP","80")
b_src = TreeRuleFirewall(rules_c2[:], ["src_ip","dst_ip","protocol","dst_port"]).match_packet(pkt_c2)[0]
b_dst = TreeRuleFirewall(rules_c2[:], ["dst_ip","src_ip","protocol","dst_port"]).match_packet(pkt_c2)[0]
print(f"TEST C (wildcard, no specific-action conflict): src-first={b_src}, dst-first={b_dst}")
ok = (b_src != b_dst)
print("  =>", "PASS (confirms hypothesis must exclude wildcards in specifics)" if ok else
      "NOTE: consistent here — hypothesis scoping still safest")
# not a PASS/FAIL gate for the paper text (paper uses example 1), informational

# ---------------------------------------------------------------------------
# TEST D — At most TWO children of any node can match a packet (m_u <= 2),
#   and cost decomposition C(P) = sum of child-counts over visited nodes
#   reproduces the engine's comparison count exactly.
# ---------------------------------------------------------------------------
def instrumented_match(fw, pkt):
    """Mirror of the engine's _search with independent accounting."""
    pd_ = pkt.as_dict()
    stats = {"cost": 0, "max_m": 0, "visits_per_depth": [0]*4}
    def search(node, depth):
        if depth == len(fw.field_order):
            return node.get("__action__", "Deny")
        f = fw.field_order[depth]
        pv = pd_[f]
        children = [(rv, ch) for rv, ch in node.items() if rv != "__action__"]
        stats["cost"] += len(children)
        stats["visits_per_depth"][depth] += 1
        matching = [(rv, ch) for rv, ch in children if rv == "*" or rv == pv]
        stats["max_m"] = max(stats["max_m"], len(matching))
        for rv, ch in matching:
            r = search(ch, depth+1)
            if r is not None:
                return r
        return None
    action = search(fw.tree, 0) or "Deny"
    return action, stats

rules_d = generate_rules(100)
packets_d = generate_skewed_traffic(rules_d, 2000, 0.90)
fw_ref = TreeRuleFirewall(rules_d[:], FIELDS[:])
fw_ins = TreeRuleFirewall(rules_d[:], FIELDS[:])
cost_mismatch = 0; act_mismatch = 0; max_m_seen = 0
for p in packets_d:
    a1, c1 = fw_ref.match_packet(p)
    a2, st = instrumented_match(fw_ins, p)
    if a1 != a2: act_mismatch += 1
    if c1 != st["cost"]: cost_mismatch += 1
    max_m_seen = max(max_m_seen, st["max_m"])
print(f"TEST D (cost decomposition vs engine): 2000 packets, n=100")
print(f"  action mismatches={act_mismatch}, cost mismatches={cost_mismatch}, max matching children observed={max_m_seen}")
ok = act_mismatch == 0 and cost_mismatch == 0 and max_m_seen <= 2
print("  =>", "PASS" if ok else "FAIL"); PASS &= ok

# ---------------------------------------------------------------------------
# TEST E — 'C(P) ~= c(root) + O(d)' claim for the experimental family:
#   n=200 default order: c(root) should be 201; measured mean ~204.9
# ---------------------------------------------------------------------------
rules_e = generate_rules(200)
fw_e = TreeRuleFirewall(rules_e[:], FIELDS[:])
c_root = len(fw_e.tree)
packets_e = generate_skewed_traffic(rules_e, 100_000, 0.90)
comps = []
for p in packets_e:
    _, c = fw_e.match_packet(p); comps.append(c)
mean_c = statistics.mean(comps)
print(f"TEST E (root-cardinality dominance): c(root)={c_root}, measured mean C={mean_c:.3f}, overhead beyond root={mean_c - c_root:.3f}")
ok = c_root == 201 and 0 < (mean_c - c_root) < 4*3   # deeper-level overhead within O(d) scale
print("  =>", "PASS" if ok else "FAIL"); PASS &= ok

print()
print("OVERALL:", "ALL GATES PASS — safe to insert into the paper" if PASS else "STOP — do not edit paper")
