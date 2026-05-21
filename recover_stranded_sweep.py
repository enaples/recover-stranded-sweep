#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import hmac
import struct
import sys
import unicodedata
from dataclasses import dataclass
from typing import Tuple

try:
    from coincurve import PrivateKey
except ImportError:  # pragma: no cover
    sys.exit("ERROR: this script requires `coincurve` (pip install coincurve)")


# secp256k1 group order.
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Layout of CLN's mnemonic-format hsm_secret file: first 32 bytes are a
# "passphrase tag" (all zeros for no-passphrase wallets, sha256 of the
# BIP39 seed for wallets with a passphrase) followed by the UTF-8
# mnemonic phrase. See common/hsm_secret.c::extract_mnemonic_secret().
PASSPHRASE_HASH_LEN = 32


# =============================================================================
# 1. HKDF-SHA256 (RFC 5869) -- matches ccan/crypto/hkdf_sha256 used by CLN.
# =============================================================================
def hkdf_sha256(out_len: int, salt: bytes, ikm: bytes, info: bytes) -> bytes:
    if len(salt) == 0:
        salt = b"\x00" * hashlib.sha256().digest_size
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    t, okm, counter = b"", b"", 1
    while len(okm) < out_len:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:out_len]


# =============================================================================
# 2. BIP32: master from seed + non-hardened CKD on the private side only.
#    (We only ever traverse m/0/0/<idx>, all non-hardened, so this is enough.)
# =============================================================================
@dataclass
class XPriv:
    k: int        # private key as int
    c: bytes      # 32-byte chain code

    def pub_compressed(self) -> bytes:
        return PrivateKey.from_int(self.k).public_key.format(compressed=True)


def bip32_master_from_seed(seed: bytes) -> XPriv:
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    k = int.from_bytes(I[:32], "big")
    if k == 0 or k >= SECP256K1_N:
        raise ValueError("invalid BIP32 master seed")
    return XPriv(k=k, c=I[32:])


def bip32_ckd_priv(parent: XPriv, idx: int) -> XPriv:
    assert 0 <= idx < 0x80000000, "only non-hardened CKD supported here"
    data = parent.pub_compressed() + idx.to_bytes(4, "big")
    I = hmac.new(parent.c, data, hashlib.sha512).digest()
    IL = int.from_bytes(I[:32], "big")
    if IL >= SECP256K1_N:
        raise ValueError("invalid CKD step (IL >= n)")
    k_child = (IL + parent.k) % SECP256K1_N
    if k_child == 0:
        raise ValueError("invalid CKD step (k_child == 0)")
    return XPriv(k=k_child, c=I[32:])


def bip32_derive_path(master: XPriv, path: Tuple[int, ...]) -> XPriv:
    cur = master
    for idx in path:
        cur = bip32_ckd_priv(cur, idx)
    return cur


# =============================================================================
# 3a. BIP39 mnemonic -> 64-byte seed (PBKDF2-HMAC-SHA512, 2048 iters).
#     Used only for mnemonic-format hsm_secret files (>32 bytes).
# =============================================================================
def _nfkd(s: str) -> bytes:
    return unicodedata.normalize("NFKD", s).encode("utf-8")


def bip39_mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha512",
        password=_nfkd(mnemonic),
        salt=b"mnemonic" + _nfkd(passphrase),
        iterations=2048,
        dklen=64,
    )


# =============================================================================
# 3b. Reproduce what hsmd stores in `secretstuff.bip32_seed`.
#
#     - Legacy plain hsm_secret (==32 bytes): the raw file bytes.
#     - Mnemonic hsm_secret  (> 32 bytes):
#           file = <32-byte passphrase-hash> + <UTF-8 mnemonic>
#           seed = bip39_mnemonic_to_seed(mnemonic, passphrase)
#
#     This is the value the legacy hkdf("bip32 seed", ...) loop will
#     consume as IKM, both in production and in this recovery tool.
# =============================================================================
def hsmd_secret_data_from_file(
    hsm_secret_bytes: bytes,
    passphrase: str = "",
) -> bytes:
    if len(hsm_secret_bytes) < PASSPHRASE_HASH_LEN:
        raise ValueError("hsm_secret file too short")

    if len(hsm_secret_bytes) == PASSPHRASE_HASH_LEN:
        # Legacy 32-byte plain. (Not what this recovery tool targets, but
        # exposed for the cross-check test against `lightning-hsmtool`.)
        return hsm_secret_bytes

    stored_hash = hsm_secret_bytes[:PASSPHRASE_HASH_LEN]
    mnemonic = hsm_secret_bytes[PASSPHRASE_HASH_LEN:].decode("utf-8")
    has_passphrase = stored_hash != b"\x00" * PASSPHRASE_HASH_LEN

    if has_passphrase and not passphrase:
        raise ValueError(
            "hsm_secret has a stored passphrase hash; pass --passphrase"
        )
    if (not has_passphrase) and passphrase:
        raise ValueError(
            "hsm_secret has no passphrase but one was provided"
        )

    bip39_seed = bip39_mnemonic_to_seed(mnemonic, passphrase)
    if has_passphrase:
        computed = hashlib.sha256(bip39_seed).digest()
        if computed != stored_hash:
            raise ValueError(
                "passphrase does not match the hash stored in hsm_secret"
            )
    return bip39_seed


# =============================================================================
# 3c. CLN's legacy "bip32 seed" hkdf-loop -> BIP32 master xprv.
#     Mirrors hsmd/libhsmd.c (do { hkdf(...) } while !bip32_key_from_seed).
# =============================================================================
def derive_cln_legacy_bip32_master(secret_data: bytes) -> XPriv:
    """`secret_data` is whatever hsmd stores in secretstuff.bip32_seed --
    use hsmd_secret_data_from_file() to obtain it from a hsm_secret file."""
    salt_iter = 0
    while True:
        salt = struct.pack("<I", salt_iter)
        seed32 = hkdf_sha256(32, salt, secret_data, b"bip32 seed")
        try:
            return bip32_master_from_seed(seed32)
        except ValueError:
            salt_iter += 1
            if salt_iter > 1024:
                raise RuntimeError(
                    "hkdf loop did not converge (corrupt hsm_secret?)"
                )


def derive_legacy_p2tr_internal_priv(secret_data: bytes,
                                     final_key_idx: int) -> XPriv:
    """Return the (untweaked) BIP32 private key at m/0/0/<final_key_idx>
    starting from CLN's `secretstuff.bip32_seed`-equivalent."""
    master = derive_cln_legacy_bip32_master(secret_data)
    return bip32_derive_path(master, (0, 0, final_key_idx))


# =============================================================================
# 4. BIP341/BIP86 taptweak (empty merkle root => key-only output).
# =============================================================================
def tagged_hash(tag: str, data: bytes) -> bytes:
    th = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(th + th + data).digest()


def bip86_tweak_keypair(internal_priv: int) -> Tuple[int, bytes]:
    """Apply BIP86 (empty merkle root) taptweak to a 32-byte internal privkey.

    Returns (tweaked_priv_for_signing, x_only_output_pubkey).
    `tweaked_priv_for_signing` is normalised so the corresponding output
    pubkey has even Y (BIP340 requirement).
    """
    P = PrivateKey.from_int(internal_priv).public_key.format(compressed=True)
    # BIP341: the taptweak commits to the x-only internal key; if the
    # parent Y is odd, we use the negated private key.
    parent_even_y = (P[0] == 0x02)
    x_only_internal = P[1:]
    priv_adj = internal_priv if parent_even_y else (SECP256K1_N - internal_priv)

    t = int.from_bytes(tagged_hash("TapTweak", x_only_internal), "big")
    if t >= SECP256K1_N:
        raise ValueError("invalid taptweak (t >= n)")

    tweaked_priv = (priv_adj + t) % SECP256K1_N
    if tweaked_priv == 0:
        raise ValueError("tweaked privkey is zero")

    Q = PrivateKey.from_int(tweaked_priv).public_key.format(compressed=True)
    # Normalise to even-Y output so libsecp256k1 schnorrsig is well-defined.
    if Q[0] == 0x03:
        tweaked_priv = SECP256K1_N - tweaked_priv
        Q = PrivateKey.from_int(tweaked_priv).public_key.format(compressed=True)
    assert Q[0] == 0x02
    return tweaked_priv, Q[1:]  # 32-byte x-only output key


def p2tr_script(x_only_pub: bytes) -> bytes:
    assert len(x_only_pub) == 32
    return bytes([0x51, 0x20]) + x_only_pub  # OP_1 PUSH32 <x-only>


def derived_p2tr_script_for(secret_data: bytes,
                            final_key_idx: int) -> Tuple[bytes, int]:
    """Return (scriptPubKey, tweaked_signing_priv) for the buggy sweep target.

    `secret_data` is the `secretstuff.bip32_seed`-equivalent: 32-byte file
    bytes for legacy wallets, or 64-byte BIP39 seed for mnemonic wallets.
    See hsmd_secret_data_from_file().
    """
    internal = derive_legacy_p2tr_internal_priv(secret_data, final_key_idx)
    tweaked_priv, x_only_out = bip86_tweak_keypair(internal.k)
    return p2tr_script(x_only_out), tweaked_priv


# =============================================================================
# 5. Bech32 / Bech32m decoding (BIP173 + BIP350) for destination addr.
# =============================================================================
_B32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_CONST = 1
_BECH32M_CONST = 0x2BC830A3


def _polymod(values):
    GEN = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= GEN[i] if (b >> i) & 1 else 0
    return chk


def _hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _verify_checksum(hrp, data):
    pm = _polymod(_hrp_expand(hrp) + list(data))
    return pm == _BECH32_CONST or pm == _BECH32M_CONST


def _convertbits(data, frombits, tobits, pad=True):
    acc, bits, out = 0, 0, []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            out.append((acc >> bits) & maxv)
    if pad and bits:
        out.append((acc << (tobits - bits)) & maxv)
    return out


def decode_segwit_addr(addr: str) -> Tuple[str, int, bytes]:
    """Return (hrp, witness_version, program). Accepts bech32 and bech32m."""
    if addr.lower() != addr and addr.upper() != addr:
        raise ValueError("mixed-case address")
    addr = addr.lower()
    pos = addr.rfind("1")
    hrp, data_part = addr[:pos], addr[pos + 1:]
    data = [_B32.index(c) for c in data_part]
    if not _verify_checksum(hrp, data):
        raise ValueError("bech32 checksum failure")
    witver = data[0]
    program = bytes(_convertbits(data[1:-6], 5, 8, pad=False))
    return hrp, witver, program


def address_to_scriptpubkey(addr: str) -> bytes:
    _hrp, witver, program = decode_segwit_addr(addr)
    if witver == 0:
        if len(program) == 20:
            return bytes([0x00, 0x14]) + program
        if len(program) == 32:
            return bytes([0x00, 0x20]) + program
    elif witver == 1 and len(program) == 32:
        return p2tr_script(program)
    raise ValueError(f"unsupported witness version/program "
                     f"(v={witver}, len={len(program)})")


# ----- Bech32m encoding & network <-> HRP mapping ---------------------------

# Same set chainparams.c uses (less liquid, which has its own quirks).
NETWORK_HRPS = {
    "bitcoin": "bc",
    "testnet": "tb",
    "signet":  "tb",
    "regtest": "bcrt",
}
HRP_TO_NETWORKS = {
    "bc":   ("bitcoin",),
    "tb":   ("testnet", "signet"),
    "bcrt": ("regtest",),
}


def _create_checksum(hrp: str, data: list[int], spec_const: int) -> list[int]:
    values = _hrp_expand(hrp) + list(data) + [0] * 6
    polymod = _polymod(values) ^ spec_const
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def encode_segwit_addr(hrp: str, witver: int, program: bytes) -> str:
    """BIP173 (v0) / BIP350 (v1+) segwit address encoder."""
    data = [witver] + _convertbits(program, 8, 5, pad=True)
    spec_const = _BECH32_CONST if witver == 0 else _BECH32M_CONST
    checksum = _create_checksum(hrp, data, spec_const)
    return hrp + "1" + "".join(_B32[d] for d in data + checksum)


def assert_addr_matches_network(addr: str, network: str) -> None:
    hrp, _, _ = decode_segwit_addr(addr)
    expected = NETWORK_HRPS[network]
    if hrp != expected:
        raise ValueError(
            f"address HRP {hrp!r} does not match --network={network} "
            f"(expected HRP {expected!r})"
        )


# =============================================================================
# 6. Minimal Bitcoin tx serialization (1-in, 1-out, SegWit v1).
# =============================================================================
def varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def cs_data(data: bytes) -> bytes:
    return varint(len(data)) + data


def parse_outpoint(arg: str) -> Tuple[bytes, int]:
    txid_hex, vout_s = arg.split(":")
    txid = bytes.fromhex(txid_hex)
    if len(txid) != 32:
        raise ValueError("txid must be 32 bytes")
    return txid, int(vout_s)


# =============================================================================
# 7. BIP341 sighash for a single-input key-path spend.
# =============================================================================
def bip341_sighash_keypath(
    prev_txid: bytes, prev_vout: int,
    input_sats: int, input_script: bytes,
    output_script: bytes, output_sats: int,
    sighash_type: int = 0x00,
    locktime: int = 0,
    version: int = 2,
    sequence: int = 0xFFFFFFFF,
) -> bytes:
    """BIP341 sighash: 1 input, 1 output, no annex, key-path (ext_flag = 0)."""
    assert sighash_type in (0x00, 0x01)  # DEFAULT or ALL

    sha_prevouts = hashlib.sha256(
        prev_txid[::-1] + prev_vout.to_bytes(4, "little")
    ).digest()
    sha_amounts = hashlib.sha256(input_sats.to_bytes(8, "little")).digest()
    sha_scriptpubkeys = hashlib.sha256(cs_data(input_script)).digest()
    sha_sequences = hashlib.sha256(sequence.to_bytes(4, "little")).digest()
    sha_outputs = hashlib.sha256(
        output_sats.to_bytes(8, "little") + cs_data(output_script)
    ).digest()

    msg = b""
    msg += bytes([sighash_type])
    msg += struct.pack("<I", version)
    msg += struct.pack("<I", locktime)
    msg += sha_prevouts
    msg += sha_amounts
    msg += sha_scriptpubkeys
    msg += sha_sequences
    msg += sha_outputs
    msg += bytes([0x00])           # spend_type: ext_flag=0, no annex
    msg += struct.pack("<I", 0)    # input_index

    return tagged_hash("TapSighash", b"\x00" + msg)


def serialize_signed_tx(prev_txid: bytes, prev_vout: int,
                        output_script: bytes, output_sats: int,
                        witness_sig: bytes,
                        locktime: int = 0,
                        version: int = 2,
                        sequence: int = 0xFFFFFFFF) -> bytes:
    out = b""
    out += struct.pack("<I", version)
    out += b"\x00\x01"                          # segwit marker + flag
    out += varint(1)                            # vin
    out += prev_txid[::-1] + prev_vout.to_bytes(4, "little")
    out += varint(0)                            # empty scriptSig
    out += sequence.to_bytes(4, "little")
    out += varint(1)                            # vout
    out += output_sats.to_bytes(8, "little") + cs_data(output_script)
    out += varint(1)                            # witness stack count
    out += cs_data(witness_sig)
    out += struct.pack("<I", locktime)
    return out


def schnorr_sign(tweaked_priv: int, msg32: bytes,
                 aux_rand: bytes | None = None) -> bytes:
    sk = PrivateKey.from_int(tweaked_priv)
    if aux_rand is None:
        return sk.sign_schnorr(msg32)
    return sk.sign_schnorr(msg32, aux_rand)


# =============================================================================
# 8. CLI driver
# =============================================================================
def main() -> None:
    p = argparse.ArgumentParser(
        description="Recover funds stranded by the v25.12 BIP86 "
                    "force-close derivation bug.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Run with --print-only first to verify the derived scriptPubKey "
               "matches your stranded UTXO before signing anything.",
    )
    p.add_argument("--hsm-secret", required=True,
                   help="path to lightning's hsm_secret file (>32 bytes; "
                        "mnemonic format)")
    p.add_argument("--passphrase", default="",
                   help="BIP39 passphrase, if your wallet has one set "
                        "(default: none)")
    p.add_argument("--network", default="bitcoin",
                   choices=sorted(NETWORK_HRPS.keys()),
                   help="bitcoin network (controls address HRP); "
                        "default: bitcoin (mainnet)")
    p.add_argument("--final-key-idx", type=int, required=True,
                   help="shutdown_keyidx_local of the closed channel")
    p.add_argument("--outpoint",
                   help="<txid>:<vout> of the stranded sweep output "
                        "(omit with --print-only)")
    p.add_argument("--input-sats", type=int,
                   help="value of the stranded output in satoshis")
    p.add_argument("--dest-addr",
                   help="destination address (bech32 / bech32m). HRP must "
                        "match --network.")
    p.add_argument("--fee-sats", type=int,
                   help="absolute fee in satoshis")
    p.add_argument("--locktime", type=int, default=0)
    p.add_argument("--print-only", action="store_true",
                   help="just print the derived scriptPubKey/address and exit")
    args = p.parse_args()

    with open(args.hsm_secret, "rb") as f:
        hsm_secret_bytes = f.read()
    if len(hsm_secret_bytes) <= 32:
        sys.exit("ERROR: hsm_secret is <=32 bytes; this script targets "
                 "BIP86/mnemonic-wallet stranding. A legacy 32-byte secret "
                 "is already exportable via "
                 "`lightning-hsmtool dumponchaindescriptors`.")

    try:
        secret_data = hsmd_secret_data_from_file(
            hsm_secret_bytes, passphrase=args.passphrase
        )
    except ValueError as e:
        sys.exit(f"ERROR: {e}")

    script, tweaked_priv = derived_p2tr_script_for(
        secret_data, args.final_key_idx
    )
    derived_addr = encode_segwit_addr(
        NETWORK_HRPS[args.network], witver=1, program=script[2:]
    )
    print(f"derived scriptPubKey (P2TR): {script.hex()}", file=sys.stderr)
    print(f"derived address ({args.network}): {derived_addr}", file=sys.stderr)

    if args.print_only:
        return

    for required in ("outpoint", "input_sats", "dest_addr", "fee_sats"):
        if getattr(args, required) is None:
            sys.exit(f"ERROR: --{required.replace('_', '-')} required "
                     f"unless --print-only")

    if args.fee_sats <= 0 or args.fee_sats >= args.input_sats:
        sys.exit("ERROR: --fee-sats must be > 0 and < --input-sats")
    output_sats = args.input_sats - args.fee_sats
    if output_sats < 330:
        sys.exit(f"ERROR: output {output_sats} sats < dust limit (330)")

    try:
        assert_addr_matches_network(args.dest_addr, args.network)
    except ValueError as e:
        sys.exit(f"ERROR: {e}")

    prev_txid, prev_vout = parse_outpoint(args.outpoint)
    output_script = address_to_scriptpubkey(args.dest_addr)

    sighash = bip341_sighash_keypath(
        prev_txid=prev_txid,
        prev_vout=prev_vout,
        input_sats=args.input_sats,
        input_script=script,
        output_script=output_script,
        output_sats=output_sats,
        locktime=args.locktime,
    )
    sig = schnorr_sign(tweaked_priv, sighash)
    raw_tx = serialize_signed_tx(
        prev_txid=prev_txid, prev_vout=prev_vout,
        output_script=output_script, output_sats=output_sats,
        witness_sig=sig, locktime=args.locktime,
    )
    print(raw_tx.hex())


if __name__ == "__main__":
    main()
