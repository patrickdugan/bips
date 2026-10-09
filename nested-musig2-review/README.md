# nested-musig2-bip-review

Review of bitcoin/bips PR 2297, the NestedMuSig2 BIP draft (spec + Python reference + vectors), written 2026-10-09.

- [FINDINGS.md](FINDINGS.md) — the review. Written so it can be posted as a PR comment as-is.
- [REPRO-OUTPUT.txt](REPRO-OUTPUT.txt) — output of the PR's own test suite, a summary of the PR's vectors, and the cross-check against the upstream BIP327 reference.
- `repro/crosscheck.py` — uses `bitcoin/bips` master's `bip-0327/reference.py` as an independent oracle: reproduces the PR's regenerated "BIP327" vectors, verifies the PR's multi-level vectors at the root with upstream code, and demonstrates each reference-vs-spec mismatch cited in the findings (checks 3a–3f).
- `repro/vec_summary.py` — prints what the multi-level vector files cover.
- `verify.sh` — re-downloads the reviewed files at the pinned commits, runs the PR's suite and the cross-check, and rewrites `REPRO-OUTPUT.txt`. `verify.cmd` runs it from Windows through Git Bash.

Pinned inputs: PR head `b3b0aa240ee4ee9d5ccc2de480cfe74a3018b02d` (fork `BEULAHEVANJALIN/bips`), upstream `bitcoin/bips` master `927b6de9915c9262615a6399de51b200f81e5aa4`.

Not covered: the Kohen paper itself (ePrint 2026/223) sits behind a Cloudflare challenge; the construction and theorem statements were taken from the recall in arXiv 2608.20705 (Appendix A, Fig. 10). Findings that depend on it are marked [inferred] in FINDINGS.md.

Status: published as branch `nested-musig2-review` on `patrickdugan/bips`; proposed fixes on branch `nested-musig-review-fixes` there. Nothing in this folder is a vulnerability in deployed software; it is review feedback on an open, public proposal, so there is no disclosure constraint.

Run:

```bash
PYTHON=python3 ./verify.sh
```
