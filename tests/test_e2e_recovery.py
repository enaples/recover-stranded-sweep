"""End-to-end recovery test against a regtest Bitcoin Core.

Flow (run for both no-passphrase and with-passphrase hsm_secret formats):

  1. Build a hsm_secret file in CLN's mnemonic layout:
       - first 32 bytes: zeros (no-pass), or sha256(BIP39-seed) (with-pass)
       - rest:          UTF-8 mnemonic phrase (a valid BIP39 12-word)
  2. Ask the recovery script (--print-only) for the P2TR scriptPubKey at
     some final_key_idx, exactly as the buggy v25.12 sweep would have
     produced it.
  3. Pay regtest sats to that script via bitcoind.
  4. Invoke the recovery script to construct & sign a spend.
  5. Broadcast the signed tx via bitcoind -- if mempool acceptance fails,
     the script's derivation/sighash/schnorr signing is wrong.
  6. Mine a confirmation and assert the destination received the funds.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "recover_stranded_sweep.py"

# Standard BIP39 test vector (Trezor): proven valid mnemonic.
TEST_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)


def _build_hsm_secret(mnemonic: str, passphrase: str) -> bytes:
    """Reproduce CLN's mnemonic-format hsm_secret file layout."""
    if passphrase:
        # `hsmd` stores sha256(BIP39-seed) as the verification tag.
        # We import here so the test still works if the script
        # module fails to import for unrelated reasons.
        import recover_stranded_sweep as rss  # noqa: F401
        from recover_stranded_sweep import bip39_mnemonic_to_seed
        tag = hashlib.sha256(
            bip39_mnemonic_to_seed(mnemonic, passphrase)
        ).digest()
    else:
        tag = b"\x00" * 32
    return tag + mnemonic.encode("utf-8")


def _run_script(*args: str) -> str:
    """Invoke the recovery script and return its stdout (decoded, stripped)."""
    res = subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        check=True, text=True, capture_output=True,
    )
    return res.stdout.strip()


@pytest.mark.parametrize("passphrase", ["", "TREZOR"], ids=["no-pass", "with-pass"])
def test_recovery_roundtrip(bitcoind, tmp_path, passphrase):
    # 1. Mnemonic-format hsm_secret in CLN's layout.
    hsm_secret = _build_hsm_secret(TEST_MNEMONIC, passphrase)
    secret_path = tmp_path / "hsm_secret"
    secret_path.write_bytes(hsm_secret)
    secret_path.chmod(0o600)

    final_key_idx = 42

    cli_passphrase_args = ["--passphrase", passphrase] if passphrase else []
    # The bitcoind fixture runs in regtest; tell the script to expect that.
    cli_network_args = ["--network", "regtest"]

    # 2. Get the buggy-derived scriptPubKey via --print-only.
    proc = subprocess.run(
        [sys.executable, str(SCRIPT),
         "--hsm-secret", str(secret_path),
         "--final-key-idx", str(final_key_idx),
         "--print-only",
         *cli_network_args,
         *cli_passphrase_args],
        check=True, text=True, capture_output=True,
    )
    # The printed address should be a regtest bech32m (`bcrt1p...`).
    addr_line = next(l for l in proc.stderr.splitlines()
                     if "derived address" in l)
    derived_addr = addr_line.rsplit(":", 1)[1].strip()
    assert derived_addr.startswith("bcrt1p"), derived_addr
    # The script prints the scriptPubKey on stderr (so --print-only stdout is
    # empty and signed-tx mode is unambiguous).
    line = next(l for l in proc.stderr.splitlines()
                if "scriptPubKey" in l)
    script_hex = line.split(":", 1)[1].strip()
    assert script_hex.startswith("5120") and len(script_hex) == 4 + 64

    # Use bitcoind to turn that script into a P2TR address.
    decoded = bitcoind.rpc("decodescript", script_hex)
    p2tr_addr = decoded["address"]
    assert decoded["type"] == "witness_v1_taproot"

    # 3. Pay 0.005 BTC into our buggy-derived script.
    pay_amount_btc = "0.00500000"
    pay_amount_sats = 500_000
    pay_txid = bitcoind.cli(
        "-rpcwallet=miner", "sendtoaddress", p2tr_addr, pay_amount_btc
    )
    bitcoind.cli(
        "-rpcwallet=miner", "generatetoaddress", "1",
        bitcoind.cli("-rpcwallet=miner", "getnewaddress"),
    )

    # Find which vout received our funds (wallet sees its own outgoing tx).
    gt_out = bitcoind.cli(
        "-rpcwallet=miner", "gettransaction", pay_txid, "true", "true",
    )
    tx_json = json.loads(gt_out)
    pay_vout = next(
        v["n"] for v in tx_json["decoded"]["vout"]
        if v["scriptPubKey"]["hex"] == script_hex
    )
    assert tx_json["decoded"]["vout"][pay_vout]["value"] == 0.005

    # 4. Pick a destination owned by the miner wallet so we can verify
    #    receipt by listunspent.
    dest_addr = bitcoind.cli("-rpcwallet=miner", "getnewaddress",
                             "recovery", "bech32m")
    fee_sats = 500
    outpoint = f"{pay_txid}:{pay_vout}"

    # 5. Sign the recovery tx via the script.
    signed_hex = _run_script(
        "--hsm-secret", str(secret_path),
        "--final-key-idx", str(final_key_idx),
        "--outpoint", outpoint,
        "--input-sats", str(pay_amount_sats),
        "--dest-addr", dest_addr,
        "--fee-sats", str(fee_sats),
        *cli_network_args,
        *cli_passphrase_args,
    )
    assert all(c in "0123456789abcdef" for c in signed_hex), signed_hex

    # 6. Mempool-accept it (this is the real correctness check).
    accept = bitcoind.rpc("testmempoolaccept", [signed_hex])
    assert accept[0]["allowed"] is True, accept

    # Broadcast + confirm + check destination received the right amount.
    rec_txid = bitcoind.cli("sendrawtransaction", signed_hex)
    bitcoind.cli(
        "-rpcwallet=miner", "generatetoaddress", "1",
        bitcoind.cli("-rpcwallet=miner", "getnewaddress"),
    )
    listunspent = bitcoind.rpc(
        "listunspent", 1, 9999, [dest_addr]
    )
    assert len(listunspent) == 1
    received_sats = int(round(listunspent[0]["amount"] * 1e8))
    assert received_sats == pay_amount_sats - fee_sats


def test_print_only_does_not_require_dest(tmp_path):
    """--print-only should derive even without spending args."""
    hsm_secret = _build_hsm_secret(TEST_MNEMONIC, "")
    secret_path = tmp_path / "hsm_secret"
    secret_path.write_bytes(hsm_secret)
    secret_path.chmod(0o600)

    proc = subprocess.run(
        [sys.executable, str(SCRIPT),
         "--hsm-secret", str(secret_path),
         "--final-key-idx", "0",
         "--print-only"],
        check=True, text=True, capture_output=True,
    )
    assert "scriptPubKey" in proc.stderr
    assert proc.stdout.strip() == ""


def test_rejects_wrong_passphrase(tmp_path):
    """With a stored passphrase tag, supplying the wrong passphrase
    must fail loudly rather than silently derive garbage."""
    hsm_secret = _build_hsm_secret(TEST_MNEMONIC, "correct horse")
    secret_path = tmp_path / "hsm_secret"
    secret_path.write_bytes(hsm_secret)
    secret_path.chmod(0o600)

    proc = subprocess.run(
        [sys.executable, str(SCRIPT),
         "--hsm-secret", str(secret_path),
         "--final-key-idx", "0",
         "--print-only",
         "--passphrase", "battery staple"],
        text=True, capture_output=True,
    )
    assert proc.returncode != 0
    assert "passphrase does not match" in proc.stderr


def test_rejects_wrong_network_dest_addr(bitcoind, tmp_path):
    """If --dest-addr's HRP doesn't match --network, the script must
    refuse to sign rather than build a tx for the wrong chain."""
    hsm_secret = _build_hsm_secret(TEST_MNEMONIC, "")
    secret_path = tmp_path / "hsm_secret"
    secret_path.write_bytes(hsm_secret)
    secret_path.chmod(0o600)

    # Mainnet bech32m address (any valid one will do)
    mainnet_addr = "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y"

    proc = subprocess.run(
        [sys.executable, str(SCRIPT),
         "--hsm-secret", str(secret_path),
         "--final-key-idx", "0",
         "--outpoint", "00" * 32 + ":0",
         "--input-sats", "100000",
         "--dest-addr", mainnet_addr,
         "--fee-sats", "1000",
         "--network", "regtest"],
        text=True, capture_output=True,
    )
    assert proc.returncode != 0
    assert "HRP" in proc.stderr and "regtest" in proc.stderr


def test_requires_passphrase_when_tagged(tmp_path):
    """If the file has a nonzero passphrase tag, the script must demand
    --passphrase rather than guessing."""
    hsm_secret = _build_hsm_secret(TEST_MNEMONIC, "the-real-one")
    secret_path = tmp_path / "hsm_secret"
    secret_path.write_bytes(hsm_secret)
    secret_path.chmod(0o600)

    proc = subprocess.run(
        [sys.executable, str(SCRIPT),
         "--hsm-secret", str(secret_path),
         "--final-key-idx", "0",
         "--print-only"],
        text=True, capture_output=True,
    )
    assert proc.returncode != 0
    assert "passphrase" in proc.stderr.lower()


def test_rejects_legacy_32byte_secret(tmp_path):
    """The script must refuse legacy 32-byte secrets: those are recoverable
    through `lightning-hsmtool dumponchaindescriptors` directly."""
    secret_path = tmp_path / "hsm_secret"
    secret_path.write_bytes(os.urandom(32))
    secret_path.chmod(0o600)

    proc = subprocess.run(
        [sys.executable, str(SCRIPT),
         "--hsm-secret", str(secret_path),
         "--final-key-idx", "0",
         "--print-only"],
        text=True, capture_output=True,
    )
    assert proc.returncode != 0
    assert "32 bytes" in proc.stderr or "<=32" in proc.stderr
