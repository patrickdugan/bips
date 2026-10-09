"""Cross-check bitcoin/bips PR 2297 (NestedMuSig2) against the *upstream* BIP327 reference.

Usage: python crosscheck.py <pr-tree-root> <upstream-dir>

Everything below uses the upstream BIP327 reference (module `b327`) as the independent
oracle and the PR's reference (module `nm`) only to build the nested-specific objects
(subgroup keys, internal/external nonces, subgroup partial signatures).
"""
import importlib.util
import json
import sys
from pathlib import Path

PR = Path(sys.argv[1])
UP = Path(sys.argv[2])


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


b327 = load("b327", UP / "bip-0327-reference.py")
nm = load("nm", PR / "bip-nested-musig2" / "reference.py")

VEC327 = PR / "bip-nested-musig2" / "tests" / "bip327-tests" / "vectors"
VECNM = PR / "bip-nested-musig2" / "tests" / "multi-level-tests" / "vectors"
UPVEC = UP / "vectors"

results = []


def report(name, ok, detail=""):
    results.append((name, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  -- {detail}" if detail else ""))


def hx(b):
    return b.hex().upper()


# ---------------------------------------------------------------------------
# 1. The PR's modified copies of BIP327 sign/verify + tweak vectors: do the
#    regenerated expected values equal what *upstream* BIP327 produces on the
#    KeySort-ed key list?  (This is the Lambda = 1 "same as BIP327" claim.)
# ---------------------------------------------------------------------------
def sorted_session(pubkeys, pubnonces, signer_pk):
    pairs = sorted(zip(pubkeys, pubnonces), key=lambda t: t[0])
    pks = [p for p, _ in pairs]
    nonces = [q for _, q in pairs]
    idx = pks.index(signer_pk)
    return pks, nonces, idx


sv = json.loads((VEC327 / "sign_verify_vectors.json").read_text())
sv_up = json.loads((UPVEC / "sign_verify_vectors.json").read_text())
sk = bytes.fromhex(sv["sk"])
X = [bytes.fromhex(h) for h in sv["pubkeys"]]
pn = [bytes.fromhex(h) for h in sv["pnonces"]]
secn = [bytes.fromhex(h) for h in sv["secnonces"]]
aggn = [bytes.fromhex(h) for h in sv["aggnonces"]]
msgs = [bytes.fromhex(h) for h in sv["msgs"]]

for i, (case, up_case) in enumerate(zip(sv["valid_test_cases"], sv_up["valid_test_cases"])):
    pubkeys = [X[k] for k in case["key_indices"]]
    pubnonces = [pn[k] for k in case["nonce_indices"]]
    msg = msgs[case["msg_index"]]
    pks, nonces, idx = sorted_session(pubkeys, pubnonces, X[0])
    ctx = b327.SessionContext(aggn[case["aggnonce_index"]], pks, [], [], msg)
    psig = b327.sign(bytearray(secn[0]), sk, ctx)
    exp_pr = bytes.fromhex(case["expected"])
    exp_up = bytes.fromhex(up_case["expected"])
    report(f"L1/upstream-sign on sorted list reproduces PR vector sign_verify[{i}]", psig == exp_pr,
           f"upstream(sorted)={hx(psig)[:16]}.. PR={hx(exp_pr)[:16]}.. original-BIP327(unsorted order {case['key_indices']})={hx(exp_up)[:16]}..")
    ok = b327.partial_sig_verify(psig, nonces, pks, [], [], msg, idx)
    report(f"L1/upstream-verify of PR vector sign_verify[{i}]", ok)

tw = json.loads((VEC327 / "tweak_vectors.json").read_text())
tw_up = json.loads((UPVEC / "tweak_vectors.json").read_text())
tsk = bytes.fromhex(tw["sk"])
TX = [bytes.fromhex(h) for h in tw["pubkeys"]]
tpn = [bytes.fromhex(h) for h in tw["pnonces"]]
tsec = bytes.fromhex(tw["secnonce"])
ttweaks = [bytes.fromhex(h) for h in tw["tweaks"]]
tmsg = bytes.fromhex(tw["msg"])
for i, (case, up_case) in enumerate(zip(tw["valid_test_cases"], tw_up["valid_test_cases"])):
    pubkeys = [TX[k] for k in case["key_indices"]]
    pubnonces = [tpn[k] for k in case["nonce_indices"]]
    tweaks = [ttweaks[k] for k in case["tweak_indices"]]
    pks, nonces, idx = sorted_session(pubkeys, pubnonces, TX[0])
    aggnonce = b327.nonce_agg(nonces)
    ctx = b327.SessionContext(aggnonce, pks, tweaks, case["is_xonly"], tmsg)
    psig = b327.sign(bytearray(tsec), tsk, ctx)
    exp_pr = bytes.fromhex(case["expected"])
    exp_up = bytes.fromhex(up_case["expected"])
    report(f"L1/upstream-sign on sorted list reproduces PR vector tweak[{i}]", psig == exp_pr,
           f"upstream(sorted)={hx(psig)[:16]}.. PR={hx(exp_pr)[:16]}.. original-BIP327={hx(exp_up)[:16]}..")

# The point of the above: the PR's "bip327-tests" directory does NOT test against
# BIP327's published expected values for sign/verify and tweak cases; they were
# regenerated for sorted key lists. Show the original values are unreachable by nm:
case0 = sv_up["valid_test_cases"][1]  # key order [1,0,2]
pubkeys = [X[k] for k in case0["key_indices"]]
others = [p for p in pubkeys if p != X[0]]
ctx_nm = nm.SessionContext([aggn[case0["aggnonce_index"]]], [others], [], [], msgs[case0["msg_index"]])
_, psig_nm = nm.sign(bytearray(secn[0]), sk, ctx_nm)
report("L1/PR reference cannot represent BIP327's unsorted key order (expected: differs)",
       psig_nm != bytes.fromhex(case0["expected"]),
       f"nm(sorted)={hx(psig_nm)[:16]}.. BIP327 vector for order {case0['key_indices']}={case0['expected'][:16]}..")

# ---------------------------------------------------------------------------
# 2. Multi-level vectors: is the ROOT level literally a BIP327 session as seen by
#    the upstream reference?  (nested subgroups appear as plain participants)
# ---------------------------------------------------------------------------
sys.path.insert(0, str(PR / "bip-nested-musig2" / "tests" / "multi-level-tests"))
from tree import parse_forest  # noqa: E402  (PR helper; only parses the tree DSL)


def build(vectors, case):
    nodes = dict(parse_forest(case["tree"]).walk())
    pubkeys = [bytes.fromhex(h) for h in vectors["pubkeys"]]
    pubnonces = [bytes.fromhex(h) for h in vectors["pubnonces"]]
    for path, k in case["leaf_key_indices"].items():
        nodes[path].pk = pubkeys[k]
        nodes[path].out = pubnonces[case["leaf_nonce_indices"][path]]
    for path, node in reversed(list(nodes.items())):
        if node.is_leaf():
            continue
        node.keyagg_ctx = nm.key_agg(nm.key_sort([c.pk for c in node.children]))
        node.pk = nm.cbytes(node.keyagg_ctx.Q)
        node.out_internal = nm.nonce_agg([c.out for c in node.children])
        if not node.is_root:
            node.out = nm.nonce_agg_ext(node.out_internal, node.keyagg_ctx.Q)
    return nodes


sa = json.loads((VECNM / "sig_agg_vectors.json").read_text())
for case in sa["valid_test_cases"]:
    nodes = build(sa, case)
    root = nodes["root"]
    tweaks = [bytes.fromhex(t) for t in case["tweaks"]]
    msg = bytes.fromhex(sa["msgs"][case["msg_index"]])
    psigs = {p: bytes.fromhex(sa["psigs"][k]) for p, k in case["psig_indices"].items()}
    # root-level participants (the subgroups), sorted as BIP327 KeySort would
    parts = sorted(root.children, key=lambda c: c.pk)
    L0 = [c.pk for c in parts]
    nonces0 = [c.out for c in parts]            # external nonces
    psigs0 = [psigs[f"root/{c.value}"] for c in parts]
    assert b327.nonce_agg(nonces0) == root.out_internal
    ctx = b327.SessionContext(root.out_internal, L0, tweaks, case["is_xonly"], msg)
    for i, c in enumerate(parts):
        ok = b327.partial_sig_verify(psigs0[i], nonces0, L0, tweaks, case["is_xonly"], msg, i)
        report(f"root/upstream PartialSigVerify accepts subgroup {c.value} as a plain participant ({case['id']})", ok)
    sig = b327.partial_sig_agg(psigs0, ctx)
    exp = bytes.fromhex(case["expected"]["root"])
    report(f"root/upstream PartialSigAgg reproduces PR final signature ({case['id']})", sig == exp,
           f"{hx(sig)[:16]}.. vs {hx(exp)[:16]}..")
    aggpk = b327.get_xonly_pk(b327.key_agg_and_tweak(L0, tweaks, case["is_xonly"]))
    report(f"root/upstream BIP340 verify ({case['id']})", b327.schnorr_verify(msg, aggpk, sig))

# A root-level *leaf* signer in a nested tree, signed with the upstream BIP327 Sign:
svn = json.loads((VECNM / "sign_verify_vectors.json").read_text())
nsk = bytes.fromhex(svn["sk"])
for case in svn["valid_test_cases"]:
    if case["signer"].count("/") != 1:
        continue  # only Lambda = 1 signers (direct children of root)
    nodes = build(svn, case)
    root = nodes["root"]
    signer = nodes[case["signer"]]
    tweaks = [bytes.fromhex(t) for t in case["tweaks"]]
    msg = bytes.fromhex(svn["msgs"][case["msg_index"]])
    parts = sorted(root.children, key=lambda c: c.pk)
    L0 = [c.pk for c in parts]
    nonces0 = [c.out for c in parts]
    idx = parts.index(signer)
    ctx = b327.SessionContext(root.out_internal, L0, tweaks, case["is_xonly"], msg)
    secnonce = bytearray.fromhex(svn["secnonces"][case["secnonce_index"]])
    psig = b327.sign(secnonce, nsk, ctx)
    report(f"root-leaf/upstream BIP327 Sign reproduces PR nested vector ({case['id']}, signer {case['signer']})",
           psig == bytes.fromhex(case["expected"]))

# ---------------------------------------------------------------------------
# 3. Reference-vs-spec mismatches, demonstrated
# ---------------------------------------------------------------------------
print()
print("--- reference vs. spec text ---")
# 3a. Intermediate binding factor hashes xbytes(pk_agg) -> same b for Q and -Q.
case = next(c for c in svn["valid_test_cases"] if c["id"] == "balanced")
nodes = build(svn, case)
G_ = nodes["root/G"]
Q = G_.keyagg_ctx.Q
negQ = nm.point_negate(Q)
b_pos = nm.agg_nonce_coeff_hash(G_.out_internal, Q)
b_neg = nm.agg_nonce_coeff_hash(G_.out_internal, negQ)
report("3a/intermediate b identical for Q and -Q (x-only hashing, as in spec body)", b_pos == b_neg)
b_rationale = nm.int_from_bytes(nm.tagged_hash("NestedMuSig/aggnoncecoef", nm.cbytes(Q) + G_.out_internal)) % nm.n
report("3a/Rationale formula hash(pk_agg33 || aggnonce) gives a DIFFERENT b than the body/reference", b_rationale != b_pos,
       f"body/ref b={b_pos:064x}"[:60] + f"..  rationale b={b_rationale:064x}"[:60])

# 3b. Sign does not consume the secnonce before a failing GetSessionValues.
signer = nodes[case["signer"]]
siblings_G = [c.pk for c in G_.children if c is not signer]
good_ctx = nm.SessionContext([nodes["root"].out_internal, G_.out_internal], [[nodes["root/H"].pk], siblings_G], [], [], bytes.fromhex(svn["msgs"][0]))
secnonce = bytearray.fromhex(svn["secnonces"][case["secnonce_index"]])
bad_ctx = nm.SessionContext([nodes["root"].out_internal, bytes(65)], good_ctx.pk_tree, [], [], good_ctx.msg)
try:
    nm.sign(secnonce, nsk, bad_ctx)
    raised = False
except (nm.InvalidContributionError, ValueError):
    raised = True
intact = any(secnonce[:64])
report("3b/Sign raised on malformed nonce_path", raised)
report("3b/secnonce scalars still intact after the failed Sign (spec: MUST be consumed first)", intact)
_, psig_after = nm.sign(secnonce, nsk, good_ctx)
report("3b/the same secnonce is then accepted by a second Sign call", psig_after == bytes.fromhex(case["expected"]))

# 3c. PartialSigVerify accepts a 33-byte psig with a leading zero; PartialSigAgg rejects it.
psig = bytes.fromhex(case["expected"])
ok33 = nm.partial_sig_verify(bytes(1) + psig, signer.out, signer.pk, good_ctx)
report("3c/partial_sig_verify accepts 33-byte psig (spec: return failure if len != 32)", ok33 is True)
try:
    nm.partial_sig_agg([bytes(1) + psig], bytes(32))
    agg_rejects = False
except nm.InvalidContributionError:
    agg_rejects = True
report("3c/partial_sig_agg rejects the same 33-byte psig (inconsistent with verify)", agg_rejects)

# 3d. Sign accepts a non-32-byte sk (spec: Fail if len(sk) != 32).
secnonce2 = bytearray.fromhex(svn["secnonces"][case["secnonce_index"]])
_, psig_33sk = nm.sign(secnonce2, bytes(1) + nsk, good_ctx)
report("3d/Sign accepts a 33-byte sk with leading zero and produces the vector psig", psig_33sk == psig)

# 3e. schnorr_verify imposes the 32-byte message restriction the spec forbids.
try:
    nm.schnorr_verify(b"", bytes(32), bytes(64))
    restricted = False
except ValueError as e:
    restricted = "32-byte" in str(e)
report("3e/reference schnorr_verify rejects non-32-byte messages (spec: MUST NOT)", restricted)
all_msgs = set()
for f in ("sign_verify_vectors.json", "sig_agg_vectors.json"):
    all_msgs |= {len(bytes.fromhex(m)) for m in json.loads((VECNM / f).read_text())["msgs"]}
report("3e/nested vectors only ever use 32-byte messages", all_msgs == {32}, f"lengths={sorted(all_msgs)}")

# 3f. sign() returns a tuple (R_x, psig), spec says Sign returns only psig.
out = nm.sign(bytearray.fromhex(svn["secnonces"][case["secnonce_index"]]), nsk, good_ctx)
report("3f/reference sign returns a 2-tuple, not the 32-byte psig the spec describes", isinstance(out, tuple) and len(out) == 2)

print()
fails = [n for n, ok in results if not ok]
print(f"{len(results) - len(fails)} checks passed, {len(fails)} failed")
for n in fails:
    print("  FAILED:", n)
