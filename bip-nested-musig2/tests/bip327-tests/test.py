"""Check the NestedMuSig2 reference against the unmodified BIP327 test vectors.

The vectors are read from bip-0327/vectors in this repository, so they cannot
drift from BIP327. The algorithms this specification reuses unchanged (KeySort,
KeyAgg, ApplyTweak, NonceGen, NonceAgg, root PartialSigAgg) are checked against
the published values directly.

BIP327's signing vectors fix a participant-key order, whereas this
specification applies KeySort at every aggregation node, so for those vectors
the Lambda = 1 session is run on the KeySort-ed key list and compared with the
BIP327 reference implementation (bip-0327/reference.py) run on the same list.
Where a vector's own key order is already sorted, the published value is
checked directly as well.
"""
import importlib.util
import json
import sys
from pathlib import Path

TEST_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = TEST_DIR.parent.parent           # bip-nested-musig2/
BIP327_DIR = PROJECT_ROOT.parent / "bip-0327"   # bips/bip-0327/
VECTORS_DIR = BIP327_DIR / "vectors"

sys.path.insert(0, str(PROJECT_ROOT))
from reference import *


def _load_bip327():
    spec = importlib.util.spec_from_file_location("bip327", BIP327_DIR / "reference.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bip327 = _load_bip327()


def fromhex_all(l):
    return [bytes.fromhex(l_i) for l_i in l]


def load_vectors(name):
    with open(VECTORS_DIR / name) as f:
        return json.load(f)


# Check if calling `try_fn` raises an exception. If yes, examine it with `except_fn`.
def assert_raises(exception, try_fn, except_fn):
    raised = False
    try:
        try_fn()
    except exception as e:
        raised = True
        assert(except_fn(e))
    except BaseException:
        raise AssertionError("Wrong exception raised in a test.")
    if not raised:
        raise AssertionError("Exception was _not_ raised in a test where it was required.")


def get_error_details(test_case, signer_map=None):
    """Exception type and checker for a vector's `error` field.

    BIP327 blames a participant by its index in the vector's key order; the
    nested session sees the KeySort-ed list, so `signer_map` translates the
    index when the blamed contribution is a public key. An aggregate-nonce
    fault is blamed on the aggregator level, which for Lambda = 1 is level 0.
    """
    error = test_case["error"]
    if error["type"] == "invalid_contribution":
        exception = InvalidContributionError
        signer = error["signer"]
        if error.get("contrib") == "aggnonce":
            signer = 0
        elif error.get("contrib") == "pubkey" and signer_map is not None:
            signer = signer_map(signer)
        if "contrib" in error:
            except_fn = lambda e: e.signer == signer and e.contrib == error["contrib"]
        else:
            except_fn = lambda e: e.signer == signer
    elif error["type"] == "value":
        exception = ValueError
        except_fn = lambda e: str(e) == error["message"]
    else:
        raise RuntimeError(f"Invalid error type: {error['type']}")
    return exception, except_fn


def sorted_session(pubkeys, pubnonces, signer_index):
    """KeySort the participants, keeping each key with its nonce.

    Returns the sorted keys, the correspondingly ordered nonces, and the
    signer's position in the sorted list.
    """
    order = sorted(range(len(pubkeys)), key=lambda i: pubkeys[i])
    keys = [pubkeys[i] for i in order]
    nonces = [pubnonces[i] for i in order]
    return keys, nonces, order.index(signer_index)


def nested_ctx(keys, idx, aggnonce, tweaks, is_xonly, msg):
    """The signer's Lambda = 1 Session Context: cosigners are everyone but the signer."""
    return SessionContext([aggnonce], [keys[:idx] + keys[idx + 1:]], tweaks, is_xonly, msg)


def test_key_sort_vectors() -> None:
    test_data = load_vectors("key_sort_vectors.json")
    X = fromhex_all(test_data["pubkeys"])
    X_sorted = fromhex_all(test_data["sorted_pubkeys"])
    assert key_sort(X) == X_sorted


def test_key_agg_vectors() -> None:
    test_data = load_vectors("key_agg_vectors.json")
    X = fromhex_all(test_data["pubkeys"])
    T = fromhex_all(test_data["tweaks"])

    for test_case in test_data["valid_test_cases"]:
        pubkeys = [X[i] for i in test_case["key_indices"]]
        expected = bytes.fromhex(test_case["expected"])
        assert get_xonly_pk(key_agg(pubkeys)) == expected

    for test_case in test_data["error_test_cases"]:
        exception, except_fn = get_error_details(test_case)
        pubkeys = [X[i] for i in test_case["key_indices"]]
        tweaks = [T[i] for i in test_case["tweak_indices"]]
        is_xonly = test_case["is_xonly"]
        assert_raises(exception, lambda: apply_tweaks(key_agg(pubkeys), tweaks, is_xonly), except_fn)


def test_nonce_gen_vectors() -> None:
    test_data = load_vectors("nonce_gen_vectors.json")

    for test_case in test_data["test_cases"]:
        def get_value(key) -> bytes:
            return bytes.fromhex(test_case[key])

        def get_value_maybe(key) -> Optional[bytes]:
            if test_case[key] is not None:
                return get_value(key)
            else:
                return None

        rand_ = get_value("rand_")
        sk = get_value_maybe("sk")
        pk = PlainPk(get_value("pk"))
        aggpk = get_value_maybe("aggpk")
        if aggpk is not None:
            aggpk = XonlyPk(aggpk)
        msg = get_value_maybe("msg")
        extra_in = get_value_maybe("extra_in")
        expected_secnonce = get_value("expected_secnonce")
        expected_pubnonce = get_value("expected_pubnonce")

        assert nonce_gen_internal(rand_, sk, pk, aggpk, msg, extra_in) == (expected_secnonce, expected_pubnonce)


def test_nonce_agg_vectors() -> None:
    test_data = load_vectors("nonce_agg_vectors.json")
    pnonce = fromhex_all(test_data["pnonces"])

    for test_case in test_data["valid_test_cases"]:
        pubnonces = [pnonce[i] for i in test_case["pnonce_indices"]]
        expected = bytes.fromhex(test_case["expected"])
        assert nonce_agg(pubnonces) == expected

    for test_case in test_data["error_test_cases"]:
        exception, except_fn = get_error_details(test_case)
        pubnonces = [pnonce[i] for i in test_case["pnonce_indices"]]
        assert_raises(exception, lambda: nonce_agg(pubnonces), except_fn)


def check_sorted_signing(sk, secnonce, pubkeys, pubnonces, signer_index, aggnonce, tweaks, is_xonly, msg, expected):
    """Lambda = 1 signing on the KeySort-ed list, cross-checked with bip-0327/reference.py."""
    keys, nonces, idx = sorted_session(pubkeys, pubnonces, signer_index)
    assert nonce_agg(nonces) == aggnonce
    ctx = nested_ctx(keys, idx, aggnonce, tweaks, is_xonly, msg)
    # WARNING: An actual implementation should _not_ copy the secnonce.
    # Reusing the secnonce, as we do here for testing purposes, can leak the
    # secret key.
    psig = sign(bytearray(secnonce), sk, ctx)
    ref_ctx = bip327.SessionContext(aggnonce, keys, tweaks, is_xonly, msg)
    assert psig == bip327.sign(bytearray(secnonce), sk, ref_ctx)
    assert partial_sig_verify(psig, nonces[idx], keys[idx], ctx)
    assert bip327.partial_sig_verify(psig, nonces, keys, tweaks, is_xonly, msg, idx)
    if keys == pubkeys:
        # The vector's own order is sorted, so the published value applies directly.
        assert psig == expected
    return keys, nonces, idx, ctx


def test_sign_verify_vectors() -> None:
    test_data = load_vectors("sign_verify_vectors.json")

    sk = bytes.fromhex(test_data["sk"])
    X = fromhex_all(test_data["pubkeys"])
    # The public key corresponding to sk is at index 0
    assert X[0] == individual_pk(sk)

    secnonces = fromhex_all(test_data["secnonces"])
    pnonce = fromhex_all(test_data["pnonces"])
    # The public nonce corresponding to secnonces[0] is at index 0
    k_1 = int_from_bytes(secnonces[0][0:32])
    k_2 = int_from_bytes(secnonces[0][32:64])
    R_s1 = point_mul(G, k_1)
    R_s2 = point_mul(G, k_2)
    assert R_s1 is not None and R_s2 is not None
    assert pnonce[0] == cbytes(R_s1) + cbytes(R_s2)

    aggnonces = fromhex_all(test_data["aggnonces"])
    # The aggregate of the first three elements of pnonce is at index 0
    assert (aggnonces[0] == nonce_agg([pnonce[0], pnonce[1], pnonce[2]]))
    # The aggregate of the first and fourth elements of pnonce is at index 1,
    # which is the infinity point encoded as a zeroed 33-byte array
    assert (aggnonces[1] == nonce_agg([pnonce[0], pnonce[3]]))

    msgs = fromhex_all(test_data["msgs"])

    for test_case in test_data["valid_test_cases"]:
        pubkeys = [X[i] for i in test_case["key_indices"]]
        pubnonces = [pnonce[i] for i in test_case["nonce_indices"]]
        aggnonce = aggnonces[test_case["aggnonce_index"]]
        msg = msgs[test_case["msg_index"]]
        expected = bytes.fromhex(test_case["expected"])
        check_sorted_signing(sk, secnonces[0], pubkeys, pubnonces, test_case["signer_index"],
                             aggnonce, [], [], msg, expected)

    for test_case in test_data["sign_error_test_cases"]:
        pubkeys = [X[i] for i in test_case["key_indices"]]
        if X[0] not in pubkeys:
            # BIP327 fails because the signer's key is absent from the key list.
            # A nested Session Context lists only the cosigners and the signer's
            # key is implied by sk, so this case cannot be expressed.
            assert test_case["error"]["type"] == "value"
            continue
        keys = key_sort(list(pubkeys))
        exception, except_fn = get_error_details(test_case, lambda i: keys.index(pubkeys[i]))
        aggnonce = aggnonces[test_case["aggnonce_index"]]
        msg = msgs[test_case["msg_index"]]
        secnonce = bytearray(secnonces[test_case["secnonce_index"]])
        ctx = nested_ctx(keys, keys.index(X[0]), aggnonce, [], [], msg)
        assert_raises(exception, lambda: sign(secnonce, sk, ctx), except_fn)

    for test_case in test_data["verify_fail_test_cases"]:
        sig = bytes.fromhex(test_case["sig"])
        pubkeys = [X[i] for i in test_case["key_indices"]]
        pubnonces = [pnonce[i] for i in test_case["nonce_indices"]]
        msg = msgs[test_case["msg_index"]]
        keys, nonces, idx = sorted_session(pubkeys, pubnonces, test_case["signer_index"])
        ctx = nested_ctx(keys, idx, nonce_agg(nonces), [], [], msg)
        assert not partial_sig_verify(sig, nonces[idx], keys[idx], ctx)

    for test_case in test_data["verify_error_test_cases"]:
        sig = bytes.fromhex(test_case["sig"])
        pubkeys = [X[i] for i in test_case["key_indices"]]
        pubnonces = [pnonce[i] for i in test_case["nonce_indices"]]
        msg = msgs[test_case["msg_index"]]
        keys, nonces, idx = sorted_session(pubkeys, pubnonces, test_case["signer_index"])
        exception, except_fn = get_error_details(test_case, lambda i: keys.index(pubkeys[i]))

        def verify():
            # Aggregating the nonces in the vector's order keeps BIP327's blame index.
            aggnonce = nonce_agg(pubnonces)
            return partial_sig_verify(sig, nonces[idx], keys[idx], nested_ctx(keys, idx, aggnonce, [], [], msg))

        assert_raises(exception, verify, except_fn)


def test_tweak_vectors() -> None:
    test_data = load_vectors("tweak_vectors.json")

    sk = bytes.fromhex(test_data["sk"])
    X = fromhex_all(test_data["pubkeys"])
    # The public key corresponding to sk is at index 0
    assert X[0] == individual_pk(sk)

    secnonce = bytes.fromhex(test_data["secnonce"])
    pnonce = fromhex_all(test_data["pnonces"])
    # The public nonce corresponding to secnonce is at index 0
    k_1 = int_from_bytes(secnonce[0:32])
    k_2 = int_from_bytes(secnonce[32:64])
    R_s1 = point_mul(G, k_1)
    R_s2 = point_mul(G, k_2)
    assert R_s1 is not None and R_s2 is not None
    assert pnonce[0] == cbytes(R_s1) + cbytes(R_s2)

    aggnonce = bytes.fromhex(test_data["aggnonce"])
    # The aggnonce is the aggregate of the first three elements of pnonce
    assert(aggnonce == nonce_agg([pnonce[0], pnonce[1], pnonce[2]]))

    tweak = fromhex_all(test_data["tweaks"])
    msg = bytes.fromhex(test_data["msg"])

    for test_case in test_data["valid_test_cases"]:
        pubkeys = [X[i] for i in test_case["key_indices"]]
        pubnonces = [pnonce[i] for i in test_case["nonce_indices"]]
        tweaks = [tweak[i] for i in test_case["tweak_indices"]]
        is_xonly = test_case["is_xonly"]
        expected = bytes.fromhex(test_case["expected"])
        check_sorted_signing(sk, secnonce, pubkeys, pubnonces, test_case["signer_index"],
                             nonce_agg(pubnonces), tweaks, is_xonly, msg, expected)

    for test_case in test_data["error_test_cases"]:
        exception, except_fn = get_error_details(test_case)
        pubkeys = [X[i] for i in test_case["key_indices"]]
        pubnonces = [pnonce[i] for i in test_case["nonce_indices"]]
        tweaks = [tweak[i] for i in test_case["tweak_indices"]]
        is_xonly = test_case["is_xonly"]
        keys, nonces, idx = sorted_session(pubkeys, pubnonces, test_case["signer_index"])
        ctx = nested_ctx(keys, idx, nonce_agg(nonces), tweaks, is_xonly, msg)
        assert_raises(exception, lambda: sign(bytearray(secnonce), sk, ctx), except_fn)


def test_sig_agg_vectors() -> None:
    test_data = load_vectors("sig_agg_vectors.json")

    X = fromhex_all(test_data["pubkeys"])
    pnonce = fromhex_all(test_data["pnonces"])
    tweak = fromhex_all(test_data["tweaks"])
    psig = fromhex_all(test_data["psigs"])
    msg = bytes.fromhex(test_data["msg"])

    # Root aggregation is BIP327 PartialSigAgg unchanged, so the published
    # vectors apply in the vector's own key order.
    for test_case in test_data["valid_test_cases"]:
        pubnonces = [pnonce[i] for i in test_case["nonce_indices"]]
        aggnonce = bytes.fromhex(test_case["aggnonce"])
        assert aggnonce == nonce_agg(pubnonces)
        pubkeys = [X[i] for i in test_case["key_indices"]]
        tweaks = [tweak[i] for i in test_case["tweak_indices"]]
        is_xonly = test_case["is_xonly"]
        psigs = [psig[i] for i in test_case["psig_indices"]]
        expected = bytes.fromhex(test_case["expected"])

        root_ctx = RootSessionContext(aggnonce, pubkeys, tweaks, is_xonly, msg)
        sig = partial_sig_agg_root(psigs, root_ctx)
        assert sig == expected
        aggpk = get_xonly_pk(apply_tweaks(key_agg(pubkeys), tweaks, is_xonly))
        assert schnorr_verify(msg, aggpk, sig)

    for test_case in test_data["error_test_cases"]:
        exception, except_fn = get_error_details(test_case)
        pubnonces = [pnonce[i] for i in test_case["nonce_indices"]]
        aggnonce = nonce_agg(pubnonces)
        pubkeys = [X[i] for i in test_case["key_indices"]]
        tweaks = [tweak[i] for i in test_case["tweak_indices"]]
        is_xonly = test_case["is_xonly"]
        psigs = [psig[i] for i in test_case["psig_indices"]]
        root_ctx = RootSessionContext(aggnonce, pubkeys, tweaks, is_xonly, msg)
        assert_raises(exception, lambda: partial_sig_agg_root(psigs, root_ctx), except_fn)


if __name__ == '__main__':
    test_key_sort_vectors()
    test_key_agg_vectors()
    test_nonce_gen_vectors()
    test_nonce_agg_vectors()
    test_sign_verify_vectors()
    test_tweak_vectors()
    test_sig_agg_vectors()
