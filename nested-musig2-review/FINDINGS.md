# NestedMuSig2 BIP draft (bitcoin/bips PR 2297) — review

Reviewed on 2026-10-09.

| What | Where |
|---|---|
| Pull request | https://github.com/bitcoin/bips/pull/2297 — "BIP Draft: NestedMuSig2 for BIP340-compatible Signatures", opened 2026-09-21 by BEULAHEVANJALIN, 1 commit, 20 files, +5730 |
| PR head | `b3b0aa240ee4ee9d5ccc2de480cfe74a3018b02d` on `BEULAHEVANJALIN/bips`, branch `nested-musig`. Files: `bip-nested-musig2.mediawiki` (820 lines), `bip-nested-musig2/reference.py` (473), `tests.sh`, `tests/bip327-tests/` (driver + 7 vector files), `tests/multi-level-tests/` (5 drivers/helpers + 4 vector files) |
| Oracle | `bitcoin/bips` master `927b6de9915c9262615a6399de51b200f81e5aa4`: `bip-0327/reference.py`, `bip-0327/tests.py`, `bip-0327/vectors/*.json`, `bip-0340/reference.py`, BIP 390, BIP 3 |
| Paper | Kohen, *Nested MuSig2*, ePrint 2026/223 (ASIACRYPT 2026). The ePrint PDF is behind a Cloudflare challenge that blocked every fetch path I have, so the construction and theorem statements below are taken from the recall in Gerhart, Kohen, Posner, Furszyfer, *Enabling Threshold Custody for the Lightning Network with Nested Threshold Multi-Signatures*, arXiv 2608.20705, §3, §5 and Appendix A (Figure 10 reproduces NestedMuSig2's pseudocode; Theorems 4 and 5 restate its security results). Anything that depends on the original paper is marked **[inferred]**. |

Line numbers are in the PR's files. Each claim carries a status:

- **[reproduced]** — run against the code; output in [REPRO-OUTPUT.txt](REPRO-OUTPUT.txt), re-run with `verify.sh`.
- **[read]** — the text or code was read end to end; nothing executed.
- **[inferred]** — depends on the Kohen paper, which I only have second-hand.

Severity is my judgement for a signing-protocol specification whose purpose is to let independent implementations interoperate and inherit a published security proof.

| # | Finding | Severity | Status |
|---|---|---|---|
| F1 | The document gives three different definitions of the intermediate nonce-binding hash input; the reference implements one of them | Medium | reproduced |
| F2 | The security argument cites the paper's theorems without their depth bound; the x-only hashing is not listed as an instantiation choice and the MuSig2\* coefficient is listed without noting its proof is flat-only | Medium | inferred / read |
| F3 | The "BIP327 vectors" in the PR are regenerated, not BIP327's; the Λ = 1 equivalence to BIP327 holds only for KeySort-ed lists and the text does not say so | Low | reproduced |
| F4 | `Sign` in the reference does not consume the secret nonce before operations that can fail, which the BIP itself makes a MUST | Low | reproduced |
| F5 | Seven smaller places where the reference does not implement the normative text | Low | reproduced |
| F6 | Editorial defects that change meaning | Info | read |
| V | What I verified holds: the PR's suite, the recursion algebra, root-level interoperability with unmodified BIP327 code | — | reproduced |

---

## F1 — Three definitions of the intermediate binding factor (Medium) [reproduced]

**What.** The factor `b_d` that `NonceAggExt` applies to a subgroup's second nonce point is defined in three incompatible ways:

| Location | Definition |
|---|---|
| Notation, `bip-nested-musig2.mediawiki:83` | "derived from `out_d` and the complete 33-byte plain aggregate public key `pk_{d−1}`" |
| `NonceAggExt`, `:209`, and `GetSessionValues`, `:261` | `b = int(hash_{NestedMuSig/aggnoncecoef}(aggnonce ‖ xbytes(pk_agg))) mod n` — nonce first, **x-only** key |
| Reference-implementation requirement, `:543–549` | "MUST compute `b = int(hash(pk_agg ‖ aggnonce)) mod n`", "`pk_agg` is exactly the 33-byte BIP327 plain aggregate public key", "MUST NOT replace `pk_agg` by an X-only public-key encoding" — key first, **33 bytes** |
| Security Considerations, `:658` | "derived from that node's aggregate plain public key and its internal aggregate nonce" |

`reference.py:352–353` and `:379` implement the second row (`aggnonce + xbytes(aggkey)`), so the code violates the MUST at `:543–549` of its own document. The published multi-level vectors therefore encode the x-only variant.

**Reproduction (3a).** For the `balanced` signing vector, `agg_nonce_coeff_hash(out_G, Q_G)` equals `agg_nonce_coeff_hash(out_G, −Q_G)`, and the formula at `:543` yields a different scalar from the one the body and vectors use.

**Consequence.** Two implementers following different sections of the same document produce different external nonces and cannot complete a session together. That is an interoperability failure in a specification whose stated purpose is interoperability, and it would surface only at signing time.

**Security.** The paper's `SignAggExt` hashes the subgroup's aggregate key as a group element (arXiv 2608.20705, Fig. 10: `b ← H_non(X̃, (R'_1 … R'_ν))`). The x-only variant identifies `Q` with `−Q`. I looked for a way to use that: a parent-level cosigner who registers `−Q_S` in place of an honest subgroup's `Q_S` gets the same external nonce from the subgroup, but every coefficient at the parent (`KeyAgg list` hash, all `a_0`, the root key) changes, so the honest leaf's partial signature is for a different root key and is useless to the attacker. I found no attack. It is nonetheless an unacknowledged departure from the proven construction, and the departure exists only because the document is inconsistent with itself. The 33-byte form stated in the Notation and the Rationale is the one that matches the paper; BIP327 uses x-only at the root only because the root key is itself x-only. Note also that the ordering in the body (`aggnonce ‖ key`) mirrors BIP327's `MuSig/noncecoef`, while the ordering in the Rationale (`key ‖ aggnonce`) mirrors the paper; either is fine, but pick one.

**Recommendation.** Define `b_d = int(hash_{NestedMuSig/aggnoncecoef}(cbytes(pk_{d−1}) ‖ out_d)) mod n` (or the nonce-first order) in exactly one place, make the other four mentions refer to it, fix `agg_nonce_coeff_hash`, and regenerate `nonce_agg_vectors.json`, `sign_verify_vectors.json` and `sig_agg_vectors.json`.

## F2 — Proof coverage: depth bound and two unacknowledged instantiation choices (Medium) [inferred / read]

**Depth.** The BIP places no bound on `Λ` (`:76`: "Different leaves in the same signer tree can have different values of Λ"), tests depth 3 in the vectors and a chain roughly 20 levels deep in `nested_examples.py`, and at `:606–608` states that the two-nonce instantiation "corresponds to the paper's compact ROM+AGM security result". The theorem statements as recalled in arXiv 2608.20705, Appendix A, are both bounded in depth: Theorem 4 is for `NestedMuSig2[GrGen, ν = 8, D = 2]` in the ROM ("the maximum depth of any signing session is at most 2"), and Theorem 5 is for `ν = 2` in the ROM+AGM "such that the depth Λ of any signing session or forgery is at most 2". I could not check whether Kohen's full version proves a general-`D` statement with bounds that grow with depth. The author should state exactly which `(ν, D)` the cited theorems cover and either bound `Λ` in the BIP or say plainly that depths beyond the proven one are unanalysed. The "Availability and Denial of Service" paragraph (`:779–780`) already asks implementations to limit nesting depth for resource reasons; the proof is a stronger reason.

**MuSig2\* second-key coefficient at every level.** The paper's `KeyAggCoef(L, X_i) = H_agg(L, X_i)` for every key (Fig. 10). The BIP reuses BIP327's `KeyAgg`, whose MuSig2\* optimization assigns coefficient 1 to the second distinct key; BIP327 cites the MuSig2 paper's appendix for the flat case. In the nested setting the adversary chooses cosigner keys at every level and `KeySort` is mandatory, so an adversary can make the honest leaf's key, and each aggregate key on the leaf's path, the "second key" at its level, giving the honest leaf a recursive coefficient `ǎ = 1`. That is not obviously a problem, but it is not the proven scheme. The BIP's list of "concrete interoperability choices not defined by the abstract construction" (`:610–616`) does name "BIP327 optimized key aggregation", but without saying that the MuSig2\* argument BIP327 relies on is for a single aggregation level and that no nested analysis of it exists. It should say so, or the author should obtain a statement from the paper's author that the argument lifts.

**x-only hashing in the intermediate binding factor.** See F1; this leaves the proven scheme as well and is absent from the same list.

**What does match the paper [read].** Modulo the two items above, `GetSessionValues` (`:242–279`) is a faithful transcription of Fig. 10's `Sign'`: `b_{d+1} = H_non(pk_{1,d}, out^{d+1})` for `d = Λ−2 … 0`, `b_0 = H̅_non(X̃, out^0, m)`, `b̌ = Π b_ℓ`, `č = c · Π a_{1,ℓ}`, `s = č·sk + r_1 + b̌·r_2` (the paper's `Σ_j r_j b̌^{j−1}` with `ν = 2`). `NonceAggExt` matches `SignAggExt`, intermediate aggregation is scalar addition as in `SignAgg'`, and the root-tweak term `c·g·tacc` is added exactly once as in BIP327. I also checked the recursion by hand: summing the leaf equations gives `(Σ s_ℓ + c·g·tacc)·G = R + c·g·Q` with `Q = gacc·Σ ǎ_ℓ P_ℓ + tacc·G`, which is the BIP340 equation; the upstream BIP327 verifier confirms it on the PR's own vectors (see V).

## F3 — The "bip327-tests" vectors were regenerated, and the Λ = 1 claim is conditional on sorting (Low) [reproduced]

**What.** `tests/bip327-tests/vectors/` presents itself, and is described at `:592` ("unchanged BIP327 primitives continue to satisfy their BIP327 vectors"), as BIP327's published vectors. Comparing with `bitcoin/bips` master:

| File | State |
|---|---|
| `key_agg_vectors.json`, `key_sort_vectors.json`, `nonce_agg_vectors.json`, `nonce_gen_vectors.json` | byte-identical (good) |
| `sign_verify_vectors.json` | all 6 `valid_test_cases[].expected` values replaced; cases 0–2 (the three orderings of the same keys) now share one value; one `sign_error_test_cases` entry deleted (signer's key absent from the list, inexpressible in the nested API) |
| `tweak_vectors.json` | all 5 `valid_test_cases[].expected` values replaced |
| `sig_agg_vectors.json` | a `"b"` field (the root nonce coefficient as a decimal integer) added to every valid and error case, because the reference's root `partial_sig_agg` takes `R` from the caller instead of deriving it (see F5) |

**Why the values changed.** The nested `SessionContext` holds a cosigner *multiset* and `GetSessionValues` applies `KeySort` (`:130`, `reference.py:373`), so BIP327's order-dependent vectors cannot be expressed. The PR's driver silently drops the signer's key and lets the reference sort (`test_sign_verify_vectors` in `tests/bip327-tests/test.py`).

**Reproduction (L1 checks).** Running upstream BIP327 `Sign` on the KeySort-ed key list reproduces every replaced value in both files, so the new numbers are correct; running the PR's reference on BIP327's original key order is impossible and the original expected values are unreachable.

**Consequence.** The claim "for the same sorted root public-key list … the flat session uses the BIP327 computations" (`:120`, `:189`, `:281`) is true, and I confirmed it with upstream code (V). But the Backward Compatibility section never states the contrapositive: an existing BIP327 deployment that aggregates keys in a non-sorted order cannot host a nested subgroup under this BIP. That is consistent with BIP 390, which mandates `KeySort` for `musig()`, but it is a real constraint for any protocol that fixed another order. The test directory name and `:592` overstate what is tested.

**Recommendation.** Keep the upstream vector files byte-identical and test them through an adapter that uses only the cases whose key order is sorted (or that re-sorts and compares against BIP327 code at test time, as `repro/crosscheck.py` does); rename or document the derived files; state the sorted-order requirement in Backward Compatibility; and add the positive statement that a root-level participant running unmodified BIP327 software interoperates when given the subgroup's 33-byte aggregate key, external nonce and aggregate partial signature.

## F4 — Secret nonce is not consumed before failing operations (Low) [reproduced]

**What.** `:296` and `:553` require that the secret nonce "MUST be marked consumed before performing any remaining operation that can fail". `reference.py:409` calls `get_session_values(session_ctx, individual_pk(sk))` first, and only zeroes the nonce at `:414`. `GetSessionValues` fails on any malformed element of a Session Context that, in the nested setting, is assembled from several aggregators.

**Reproduction (3b).** With the `balanced` vector, `sign` on a context whose second nonce-path entry is 65 bytes raises; the secret nonce scalars are still intact afterwards; a second `sign` with the correct context then succeeds and produces the vector's partial signature.

**Consequence.** The failed call releases nothing, so this is not a key leak by itself. It is a MUST in the document that its own reference breaks, and the pattern it demonstrates (fail, fix the context, retry with the same nonce object) is exactly the one the text warns against at `:633`. BIP327's reference has the same order of operations, but BIP327's text does not make the stronger promise.

**Recommendation.** Move the copy-and-zero of `secnonce[0:64]` above the `get_session_values` call in `sign` (two lines), or soften the two MUSTs to BIP327's wording.

## F5 — Reference does not implement the normative text in seven smaller places (Low) [reproduced unless noted]

1. **Root aggregation is not BIP327 `PartialSigAgg`.** `:389–398` require the root to build a BIP327 `root_session_ctx = (out_0, L_0, tweaks, is_xonly, m)` and call BIP327 `PartialSigAgg` unchanged, which derives `R` from `out_0`. `reference.py:457–473` instead takes `x_R` from the caller (the harness passes a leaf's `R`), ignores `nonce_path`, and never derives or checks `R`. The extra `"b"` fields in the vectors exist to feed this signature. A wrong `x_R` only yields an invalid signature, so there is no security impact, but the reference does not demonstrate the algorithm the BIP specifies, and `:570` ("MUST retain `c` and `č` as distinct values") is not met either: `get_session_values` returns only `č`. [read]
2. **Message length.** `:578`: the BIP340 helper "MUST NOT impose a 32-byte-only message restriction". `reference.py:86–87` raises on any other length (3e). Every nested vector uses 32-byte messages, whereas BIP327's vectors include a 0-byte and a 38-byte message, so variable-length messages are untested here.
3. **`Sign` returns a tuple.** `:310` and `:574` say `Sign` returns only the 32-byte partial signature; `reference.py:440` returns `(xbytes(R), psig)` (3f).
4. **`len(sk)` is not checked.** `:297` says fail if `len(sk) ≠ 32`; a 33-byte key with a leading zero signs and reproduces the vector (3d).
5. **`len(psig)` is not checked in `PartialSigVerify`.** `:336` says return failure if `len(psig) ≠ 32`; `reference.py:444` accepts a 33-byte value with a leading zero, while `partial_sig_agg` rejects the same bytes, so the two halves of the protocol disagree on validity (3c).
6. **`aggpk` passed to `NonceGen`.** `:165` says the optional `aggpk` "MUST be the … root aggregate public key after all … tweaks"; `nested_musig2_exec.py` passes the untweaked root key and only chooses tweaks after round 1, so the harness violates the MUST. The spec allows omitting `aggpk`; the harness should do that or the MUST should allow the untweaked key. [read]
7. **Blame has no level.** `GetSessionValues` blames aggregate-nonce faults by level (`reference.py:371`), but a malformed cosigner key surfaces as BIP327's `InvalidContributionError(i, "pubkey")` with `i` an index into the *sorted* `L_d` of an unstated level. `:242–273` only say "fail". Define the blame object (level, occurrence) or say the index refers to `L_d`. [read]

## F6 — Editorial defects that change meaning (Info) [read]

- `:279` returns a 6-tuple `(Q, gacc, tacc, b̌, R, č)`; `:301` and `:339` destructure seven values `(Q, gacc, _, b̌, R, _, č)`. Decide whether `c` is returned (see F5.1).
- `:185`: "For a non-root node, where `0 < d < λ − 1`" excludes `d = Λ − 1`, the node that a leaf participates in directly and that must call `NonceAggExt`; it should read `0 < d ≤ Λ − 1`, and `λ` should be `Λ`.
- `:18` and `:405` use `[[url|text]]`, which MediaWiki renders as an internal wiki link; external links are `[url text]` as used elsewhere in the file.
- `:743`: "MUST therefore must not be infinite".
- `:531–600` (reference-implementation requirements and Testing) are subsections of "Backward Compatibility"; BIP 3 expects a Reference Implementation / Test Vectors section.
- `tests/multi-level-tests/random_tree_tests.py` uses unseeded `random`, so a failure cannot be reproduced; `reference.py:355` (`print_tree_path`) is dead code; `tree.py` lists the paper's `Abby(Alice,Bob),Carol` example as commented-out code.

## V — What holds [reproduced]

- **The PR's suite passes** on Python 3.12.10: `tests/bip327-tests/test.py` (31 s), `tests/multi-level-tests/test.py` (91 s), `random_tree_tests.py` (68 s), `nested_examples.py` (77 s).
- **46 of 46 cross-checks pass** in `repro/crosscheck.py`, which uses the upstream BIP327 reference as the oracle:
  - upstream `Sign` on the KeySort-ed list reproduces all 11 regenerated sign/tweak expected values (F3);
  - for every valid `sig_agg` vector, upstream `PartialSigVerify` accepts each subgroup's `(aggregate key, external nonce, aggregate partial signature)` as an ordinary participant, upstream `PartialSigAgg` on the root `SessionContext` reproduces the PR's final signature byte for byte, and upstream `schnorr_verify` accepts it, with plain, x-only and mixed root tweaks;
  - for the `duplicate_direct` vector, upstream BIP327 `Sign` run by a root-level leaf, with a nested subgroup as its cosigner, reproduces the PR's partial signature. This is the deployment property that matters (a nesting-unaware counterparty needs no new code at the root) and the BIP should say it explicitly instead of only the negative statement at `:509–511`.
- **Vector coverage is good** where it exists: duplicate keys within a group and across levels, unary groups, unequal depths, plain/x-only/mixed tweaks, aggregate-nonce infinity at the root, cancellation inside a subgroup (must fail), consumed-nonce rejection, truncated-context verification of subgroup contributions.
- **Exceptional-point rules** (`NonceAggExt` fails on infinity, no `G` substitution except at the root, `b = 0` not replaced) are implemented as written and tested, including with a patched zero binding scalar.

## Proposed fixes

Branch [`nested-musig-review-fixes`](https://github.com/patrickdugan/bips/tree/nested-musig-review-fixes) on `patrickdugan/bips`, three commits on top of `b3b0aa2`, offered as a pull request against the author's `nested-musig` branch:

1. **Spec text corrections** (F6, plus the Backward Compatibility and Testing statements from F3 and the MuSig2\* note from F2).
2. **One definition of the intermediate binding-factor input** (F1): `b = int(hash_{NestedMuSig/aggnoncecoef}(pk_agg ‖ aggnonce)) mod n` with the 33-byte plain key, as the Notation, the Rationale and the paper's `SignAggExt` have it. `NonceAggExt` takes the 33-byte key. The 78 affected values in the three multi-level vector files were regenerated with a script that first reproduced every existing value from the inputs with the old code, then replaced only those values with the new code's output; input pools are untouched. If the author prefers the x-only variant instead, the same inconsistency is removed by editing the four text locations and no vector changes.
3. **Reference conformance and honest BIP327 testing** (F3, F4, F5): the secret nonce is consumed first; `sign` returns only the partial signature and checks `len(sk)`; `GetSessionValues` returns `c`; `PartialSigVerify` rejects wrong lengths; the root aggregator is BIP327 `PartialSigAgg` over a root session context and derives `R`; the BIP340 helper accepts any message length; the harness passes the tweaked root key to `NonceGen`. The copied BIP327 vectors are deleted; the suite reads `bip-0327/vectors` in place and uses `bip-0327/reference.py` as the oracle for the order-dependent signing vectors.

All four drivers pass on the branch. Not addressed, because they need the author or the paper's author: the depth bound of the theorems (F2) and level-aware blame (F5.7).

## Summary of requested changes

1. One definition of the intermediate binding-factor input (F1); regenerate the three affected vector files.
2. State the `(ν, D)` the cited theorems cover and bound or caveat the depth; add the MuSig2\* coefficient and the hash-input encoding to the list of unproven instantiation choices (F2).
3. Restore the upstream BIP327 vector files byte-identical and test them through an adapter; state the sorted-order requirement and the root-level BIP327 interoperability property in Backward Compatibility (F3).
4. Consume the secret nonce first in `sign`, or relax the MUST (F4).
5. Make the reference match the text on root aggregation, message length, return value, length checks, `aggpk`, and blame (F5); fix the tuple arity, the `λ` bound, and the link syntax (F6).
