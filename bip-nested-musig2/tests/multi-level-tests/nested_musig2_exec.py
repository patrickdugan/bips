from tree import Node, print_tree
import secrets

from pathlib import Path
import sys
TEST_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = TEST_DIR.parent.parent

sys.path.insert(0, str(PROJECT_ROOT))

from reference import *

def key_gen_tree(node: Node):
    if node.is_leaf():
        node.sk = secrets.token_bytes(32)
        node.pk = individual_pk(node.sk)
    else:
        for w in node.children:
            key_gen_tree(w)
        child_pks =  key_sort([w.pk for w in node.children])
        node.keyagg_ctx = key_agg(child_pks)
        node.pk = PlainPk(cbytes(node.keyagg_ctx.Q))


def round1(node: Node, aggpk: XonlyPk = None, msg: bytes = None, extra_in = None):
    if node.is_leaf():
        (secnonce, pubnonce) = nonce_gen(node.sk, node.pk, aggpk, msg, extra_in)
        node.out = pubnonce
        node.state = secnonce
    else:
        for w in node.children:
            round1(w, aggpk, msg, extra_in)
        node.out_internal = nonce_agg([w.out for w in node.children])
        if not node.is_root:
            node.out = nonce_agg_ext(node.out_internal, node.pk)

def round2(node: Node, session_ctx: SessionContext):
    if node.is_leaf():
        node.out_ = sign(node.state, node.sk, session_ctx)
    else:
        nonce_path, pk_tree, tweaks, is_xonly, msg = session_ctx
        for child_index, w in enumerate(node.children):
            siblings = [u.pk for sibling_index, u in enumerate(node.children) if sibling_index != child_index]
            session_ctx_ = SessionContext(nonce_path + [node.out_internal], pk_tree + [siblings], tweaks, is_xonly, msg)
            round2(w, session_ctx_)

        psigs = [w.out_ for w in node.children]

        # Aggregating signatures of the children
        if node.is_root:
            # The root runs the unchanged BIP327 PartialSigAgg over L_0 and out_0
            # and derives the effective nonce R itself.
            root_ctx = RootSessionContext(node.out_internal, key_sort([w.pk for w in node.children]), tweaks, is_xonly, msg)
            node.out_ = partial_sig_agg_root(psigs, root_ctx)
        else:
            node.out_ = partial_sig_agg_intermediate(psigs)


def simulate_sign_test(node):
    msg = secrets.token_bytes(32)
    # Setup
    key_gen_tree(node)

    # Root tweaks are fixed before the first round so that NonceGen can be
    # given the final, tweaked root key as the specification requires.
    tweaks = [secrets.token_bytes(32) for _ in range(4)]
    is_xonly = [secrets.choice([False, True]) for _ in range(4)]
    aggx = get_xonly_pk(apply_tweaks(node.keyagg_ctx, tweaks, is_xonly))
    round1(node, aggx, msg)

    session_ctx = SessionContext(
        nonce_path=[],
        pk_tree=[],
        tweaks = tweaks,
        is_xonly = is_xonly,
        msg=msg,
    )
    round2(node, session_ctx)

    assert(schnorr_verify(msg, aggx, node.out_))
