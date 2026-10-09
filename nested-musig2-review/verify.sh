#!/bin/sh
# Re-fetches bitcoin/bips PR 2297 at its reviewed head commit plus the upstream
# BIP327 files at a pinned master commit, runs the PR's own test suite, then runs
# the cross-check against upstream. Writes REPRO-OUTPUT.txt next to this script.
#
# Usage: [PYTHON=/path/to/python3] ./verify.sh [workdir]
set -e

HERE=$(cd "$(dirname "$0")" && pwd)
WORK=${1:-"$HERE/work"}
PY=${PYTHON:-}
if [ -z "$PY" ]; then
  if command -v python3 >/dev/null 2>&1; then PY=python3
  elif [ -x "$LOCALAPPDATA/Programs/Python/Python312/python.exe" ]; then PY="$LOCALAPPDATA/Programs/Python/Python312/python.exe"
  else echo "set PYTHON to a Python 3 interpreter" >&2; exit 1; fi
fi

FORK=https://raw.githubusercontent.com/BEULAHEVANJALIN/bips/b3b0aa240ee4ee9d5ccc2de480cfe74a3018b02d
UP=https://raw.githubusercontent.com/bitcoin/bips/927b6de9915c9262615a6399de51b200f81e5aa4

PR_FILES="bip-nested-musig2.mediawiki
bip-nested-musig2/reference.py
bip-nested-musig2/tests.sh
bip-nested-musig2/tests/bip327-tests/test.py
bip-nested-musig2/tests/bip327-tests/vectors/key_agg_vectors.json
bip-nested-musig2/tests/bip327-tests/vectors/key_sort_vectors.json
bip-nested-musig2/tests/bip327-tests/vectors/nonce_agg_vectors.json
bip-nested-musig2/tests/bip327-tests/vectors/nonce_gen_vectors.json
bip-nested-musig2/tests/bip327-tests/vectors/sig_agg_vectors.json
bip-nested-musig2/tests/bip327-tests/vectors/sign_verify_vectors.json
bip-nested-musig2/tests/bip327-tests/vectors/tweak_vectors.json
bip-nested-musig2/tests/multi-level-tests/nested_examples.py
bip-nested-musig2/tests/multi-level-tests/nested_musig2_exec.py
bip-nested-musig2/tests/multi-level-tests/random_tree_tests.py
bip-nested-musig2/tests/multi-level-tests/test.py
bip-nested-musig2/tests/multi-level-tests/tree.py
bip-nested-musig2/tests/multi-level-tests/vectors/key_agg_vectors.json
bip-nested-musig2/tests/multi-level-tests/vectors/nonce_agg_vectors.json
bip-nested-musig2/tests/multi-level-tests/vectors/sig_agg_vectors.json
bip-nested-musig2/tests/multi-level-tests/vectors/sign_verify_vectors.json"

UP_FILES="bip-0327/reference.py
bip-0327/tests.py
bip-0327/vectors/key_agg_vectors.json
bip-0327/vectors/key_sort_vectors.json
bip-0327/vectors/nonce_agg_vectors.json
bip-0327/vectors/nonce_gen_vectors.json
bip-0327/vectors/sig_agg_vectors.json
bip-0327/vectors/sign_verify_vectors.json
bip-0327/vectors/tweak_vectors.json"

OUT="$HERE/REPRO-OUTPUT.txt"
{
  echo "# REPRO-OUTPUT for nested-musig2-bip-review, generated $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# PR head b3b0aa240ee4ee9d5ccc2de480cfe74a3018b02d; upstream bitcoin/bips 927b6de9915c9262615a6399de51b200f81e5aa4"
  echo

  echo "## fetch"
  for f in $PR_FILES; do
    mkdir -p "$WORK/pr/$(dirname "$f")"
    curl -sSL -o "$WORK/pr/$f" "$FORK/$f"
    echo "fetched pr/$f ($(wc -c < "$WORK/pr/$f") bytes)"
  done
  for f in $UP_FILES; do
    case "$f" in
      bip-0327/reference.py) dst="$WORK/upstream/bip-0327-reference.py" ;;
      bip-0327/tests.py)     dst="$WORK/upstream/bip-0327-tests.py" ;;
      *)                     dst="$WORK/upstream/vectors/$(basename "$f")" ;;
    esac
    mkdir -p "$(dirname "$dst")"
    curl -sSL -o "$dst" "$UP/$f"
    echo "fetched upstream/$f ($(wc -c < "$dst") bytes)"
  done
  echo

  echo "## upstream BIP327 vector files vs the PR's bip327-tests copies"
  for v in "$WORK"/upstream/vectors/*.json; do
    b=$(basename "$v")
    if diff -q --strip-trailing-cr "$v" "$WORK/pr/bip-nested-musig2/tests/bip327-tests/vectors/$b" >/dev/null; then
      echo "$b: identical"
    else
      echo "$b: DIFFERS ($(diff --strip-trailing-cr "$v" "$WORK/pr/bip-nested-musig2/tests/bip327-tests/vectors/$b" | grep -c '^[<>]') changed lines)"
    fi
  done
  echo

  echo "## the PR's own test suite (tests.sh order)"
  for t in tests/bip327-tests/test.py tests/multi-level-tests/test.py tests/multi-level-tests/random_tree_tests.py; do
    start=$(date +%s)
    if (cd "$WORK/pr/bip-nested-musig2" && "$PY" "$t"); then rc=0; else rc=$?; fi
    echo "$t: exit=$rc elapsed=$(( $(date +%s) - start ))s"
  done
  echo

  echo "## vector coverage summary"
  (cd "$WORK/pr/bip-nested-musig2/tests/multi-level-tests/vectors" && "$PY" -I "$HERE/repro/vec_summary.py")
  echo

  echo "## cross-check against upstream BIP327 (repro/crosscheck.py)"
  "$PY" "$HERE/repro/crosscheck.py" "$WORK/pr" "$WORK/upstream"
} 2>&1 | tee "$OUT"
