"""Cross-check our HKDF + BIP32 derivation against an *independent* oracle.

For a 32-byte (legacy) hsm_secret, `lightning-hsmtool dumponchaindescriptors`
emits a `tr(xprv.../0/0/*)` descriptor whose master xprv is computed from the
exact same hkdf-loop CLN's hsmd uses at runtime. Bitcoin Core's
`deriveaddresses` then turns "<descriptor> at index N" into a P2TR address.

If our Python derivation agrees with Bitcoin Core derivation from the SAME
hsmtool-emitted xprv, then:
  - our HKDF-loop reproduces hsmtool's HKDF-loop, AND
  - our BIP32 non-hardened CKD reproduces libwally's BIP32 CKD, AND
  - our BIP86 taptweak reproduces Core's BIP86 taptweak.

That is the "is the derivation correct?" oracle. The end-to-end
broadcast test in test_e2e_recovery.py is the "is the signing correct?"
oracle.

NB: this test uses a 32-byte hsm_secret only as a probe to compare
derivation primitives. The user-facing script refuses 32-byte secrets;
we bypass that by calling the derivation functions directly.
"""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
from pathlib import Path

import pytest


# Base58check helpers (mainnet xprv -> regtest tprv version-byte swap)
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58_decode(s: str) -> bytes:
    n = 0
    for c in s:
        n = n * 58 + _B58.index(c)
    h = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + h


def _b58_encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    pad = len(b) - len(b.lstrip(b"\x00"))
    return "1" * pad + out


def _b58check_reencode(s: str, new_version: bytes) -> str:
    raw = _b58_decode(s)
    body, _csum = raw[:-4], raw[-4:]
    assert len(new_version) == 4
    new_body = new_version + body[4:]
    csum = hashlib.sha256(hashlib.sha256(new_body).digest()).digest()[:4]
    return _b58_encode(new_body + csum)


def _xprv_to_tprv(xprv: str) -> str:
    # mainnet xprv version = 0x0488ADE4 ; testnet/regtest tprv = 0x04358394
    assert xprv.startswith("xprv")
    return _b58check_reencode(xprv, bytes.fromhex("04358394"))


def _hsmtool_dump_tr_descriptor(hsmtool: str, hsm_secret_path: Path,
                                network: str) -> str:
    out = subprocess.check_output(
        [hsmtool, "dumponchaindescriptors", "--show-secrets",
         str(hsm_secret_path), network],
        text=True,
    )
    tr_lines = [l for l in out.splitlines() if l.startswith("tr(")]
    assert tr_lines, f"no tr() descriptor in hsmtool output:\n{out}"
    return tr_lines[0]


def _retarget_descriptor_to_regtest(descriptor: str) -> str:
    """Strip checksum and replace any xprv... key with its tprv... equivalent.

    Used only when hsmtool was asked for 'bitcoin' (mainnet) but Core is
    running regtest. For hsmtool networks 'testnet'/'regtest'/'signet' the
    descriptor already uses tprv and this is a no-op."""
    descriptor = descriptor.split("#", 1)[0]
    return re.sub(r"xprv[1-9A-HJ-NP-Za-km-z]+", lambda m: _xprv_to_tprv(m.group(0)),
                  descriptor)


@pytest.mark.parametrize(
    # lightning-hsmtool supports bitcoin/testnet/signet; regtest reuses
    # the testnet xprv version, so testing 'testnet' here also covers
    # the regtest case from the user's perspective.
    "hsmtool_network",
    ["bitcoin", "testnet", "signet"],
)
def test_legacy_bip32_matches_hsmtool_and_bitcoin_core(
    bitcoind, hsmtool_path, script_module, tmp_path, hsmtool_network
):
    """For a 32-byte hsm_secret across every chainparams that hsmtool
    supports: our Python derivation produces the same P2TR scriptPubKey
    that Core would derive from hsmtool's `tr(xprv.../0/0/*)` at the
    same index. The derivation math is network-agnostic; this test
    confirms that interpreting hsmtool's output on any chain doesn't
    perturb the result."""
    hsm_secret = os.urandom(32)
    secret_path = tmp_path / "hsm_secret"
    secret_path.write_bytes(hsm_secret)
    # hsmtool refuses to read a hsm_secret that is world-readable.
    secret_path.chmod(0o600)

    # Oracle: hsmtool-emitted descriptor (in the requested chain's xprv
    # version) via Core's deriveaddresses on its regtest daemon. For the
    # mainnet "bitcoin" hsmtool call we need to swap mainnet xprv -> tprv
    # so the regtest daemon will parse it; for testnet/regtest/signet
    # hsmtool already emits tprv.
    descriptor = _hsmtool_dump_tr_descriptor(
        hsmtool_path, secret_path, hsmtool_network
    )
    if hsmtool_network == "bitcoin":
        descriptor = _retarget_descriptor_to_regtest(descriptor)
    else:
        # Strip hsmtool's checksum -- Core re-computes it.
        descriptor = descriptor.split("#", 1)[0]

    info = bitcoind.rpc("getdescriptorinfo", descriptor)
    descriptor_with_csum = info["descriptor"]
    derived = bitcoind.rpc("deriveaddresses", descriptor_with_csum, [0, 5])
    assert isinstance(derived, list) and len(derived) == 6

    for idx, oracle_addr in enumerate(derived):
        py_script, _ = script_module.derived_p2tr_script_for(hsm_secret, idx)
        oracle_script_hex = bitcoind.rpc(
            "getaddressinfo", oracle_addr
        )["scriptPubKey"]
        assert py_script.hex() == oracle_script_hex, (
            f"derivation mismatch at idx={idx} on {hsmtool_network}: "
            f"python={py_script.hex()}, core/hsmtool={oracle_script_hex}"
        )


@pytest.mark.parametrize(
    "network,hrp",
    [
        ("bitcoin", "bc"),
        ("testnet", "tb"),
        ("signet", "tb"),
        ("regtest", "bcrt"),
    ],
)
def test_bech32m_address_encoding_per_network(script_module, network, hrp):
    """The derived address printed in --print-only must use the right HRP
    for each supported network."""
    secret = b"\x00" * 32 + (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    ).encode("utf-8")
    sd = script_module.hsmd_secret_data_from_file(secret)
    script, _ = script_module.derived_p2tr_script_for(sd, 0)
    addr = script_module.encode_segwit_addr(
        script_module.NETWORK_HRPS[network], 1, script[2:]
    )
    assert addr.startswith(hrp + "1p")
    # Round-trip
    rt_hrp, witver, program = script_module.decode_segwit_addr(addr)
    assert rt_hrp == hrp and witver == 1 and program == script[2:]


def test_assert_addr_matches_network_rejects_mismatch(script_module):
    # encode a regtest address, then claim --network=bitcoin
    secret = b"\x00" * 32 + b"x" * 64
    sd = script_module.hsmd_secret_data_from_file(secret)
    script, _ = script_module.derived_p2tr_script_for(sd, 0)
    bcrt_addr = script_module.encode_segwit_addr("bcrt", 1, script[2:])
    with pytest.raises(ValueError, match="HRP"):
        script_module.assert_addr_matches_network(bcrt_addr, "bitcoin")
    # but the correct network passes:
    script_module.assert_addr_matches_network(bcrt_addr, "regtest")


def test_bip32_master_invalid_seed_loop_converges(script_module):
    """The hkdf-loop must keep incrementing salt until it gets a valid
    BIP32 master. Just exercise the no-op happy path: a random secret
    should succeed within a few iterations (typically iteration 0)."""
    for _ in range(8):
        secret = os.urandom(64)
        master = script_module.derive_cln_legacy_bip32_master(secret)
        assert 0 < master.k < script_module.SECP256K1_N
        assert len(master.c) == 32


# Canonical Trezor BIP39 vector. Source:
# github.com/trezor/python-mnemonic/blob/master/vectors.json (first row, en).
BIP39_VECTOR_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)
BIP39_VECTOR_PASSPHRASE = "TREZOR"
BIP39_VECTOR_SEED_HEX = (
    "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
    "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
)


def test_bip39_mnemonic_to_seed_matches_trezor_vector(script_module):
    """Verify our BIP39 PBKDF2 matches the standard Trezor test vector."""
    seed = script_module.bip39_mnemonic_to_seed(
        BIP39_VECTOR_MNEMONIC, BIP39_VECTOR_PASSPHRASE
    )
    assert seed.hex() == BIP39_VECTOR_SEED_HEX


def test_bip39_no_passphrase_vector(script_module):
    """Same mnemonic, empty passphrase -- canonical vector from BIP39 itself."""
    # No-pass version of the same first vector:
    # seed = c552...  with passphrase "" is *different* from "TREZOR".
    expected = (
        "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
        "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
    )
    seed = script_module.bip39_mnemonic_to_seed(BIP39_VECTOR_MNEMONIC, "")
    assert seed.hex() == expected


def test_hsmd_secret_data_from_file_plain_passthrough(script_module):
    """For 32-byte plain hsm_secret, secret_data == the file bytes."""
    raw = os.urandom(32)
    assert script_module.hsmd_secret_data_from_file(raw) == raw


def test_hsmd_secret_data_from_file_mnemonic_no_pass(script_module):
    """For a 32-zero + mnemonic file, secret_data is the BIP39 seed."""
    hsm_secret = b"\x00" * 32 + BIP39_VECTOR_MNEMONIC.encode()
    sd = script_module.hsmd_secret_data_from_file(hsm_secret)
    assert sd.hex() == script_module.bip39_mnemonic_to_seed(
        BIP39_VECTOR_MNEMONIC, ""
    ).hex()
    assert len(sd) == 64


def test_hsmd_secret_data_from_file_with_passphrase_validates_hash(
    script_module,
):
    """Wrong passphrase must raise; right one must pass through to seed."""
    seed = script_module.bip39_mnemonic_to_seed(
        BIP39_VECTOR_MNEMONIC, BIP39_VECTOR_PASSPHRASE
    )
    tag = __import__("hashlib").sha256(seed).digest()
    hsm_secret = tag + BIP39_VECTOR_MNEMONIC.encode()

    # Wrong passphrase -> ValueError
    with pytest.raises(ValueError, match="passphrase does not match"):
        script_module.hsmd_secret_data_from_file(hsm_secret, "wrong")

    # No passphrase supplied for a tagged file -> ValueError
    with pytest.raises(ValueError, match="hsm_secret has a stored"):
        script_module.hsmd_secret_data_from_file(hsm_secret, "")

    # Correct passphrase
    sd = script_module.hsmd_secret_data_from_file(
        hsm_secret, BIP39_VECTOR_PASSPHRASE
    )
    assert sd == seed
