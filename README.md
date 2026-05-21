# recover-stranded-sweep

A one-shot recovery tool for funds stranded by the **v25.12 force-close BIP86 derivation bug** in Core Lightning.

Fixed upstream in **v25.12.1** via [ElementsProject/lightning#8831](https://github.com/ElementsProject/lightning/pull/8831) (commit `d6170cfa1d`, *"lightningd: Fix penalty tx output derivation for BIP86 wallets"*). Upgrading prevents the bug from stranding any *new* sweeps but does **not** retroactively rescue an already-stranded UTXO. This tool does.

## What this script does

Given the four pieces of state required to identify the stuck UTXO, it reproduces the entire CLN derivation chain and signs a key-path Schnorr spend:

1. **Read the hsm_secret file** ([`hsmd_secret_data_from_file`](recover_stranded_sweep.py)).
   For mnemonic format: validates the stored passphrase-hash (when present) and computes the 64-byte BIP39 seed via PBKDF2-HMAC-SHA512. For 32-byte plain: passes through.
2. **HKDF "bip32 seed" loop** ([`derive_cln_legacy_bip32_master`](recover_stranded_sweep.py)).
   Mirrors `hsmd/libhsmd.c`: HKDF-SHA256 with a little-endian `u32` salt, retrying until the output is a valid BIP32 master seed.
3. **BIP32 non-hardened CKD** down `m/0/0/<final_key_idx>` ([`bip32_ckd_priv`](recover_stranded_sweep.py)).
4. **BIP86 taptweak** with an empty merkle root ([`bip86_tweak_keypair`](recover_stranded_sweep.py)). Produces the x-only output pubkey and the normalised tweaked private key.
5. **BIP341 sighash** for a 1-in / 1-out key-path spend ([`bip341_sighash_keypath`](recover_stranded_sweep.py)).
6. **BIP340 Schnorr signature** via libsecp256k1 (through `coincurve`).
7. **Serialize** the SegWit-v1 transaction and print the hex.

There is exactly one stack item in the witness, the 64-byte Schnorr signature, because BIP86 is key-only.

### What it explicitly is not

- It is **not** a `hsm_secret` backup or wallet recovery tool. `lightning-hsmtool dumponchaindescriptors` covers normal wallet exports but does not cover the bug's stranded address; that's why this script exists.
- It does **not** mutate CLN state. No DB writes, no RPC calls. The signed transaction is for the operator to broadcast.
- It does **not** try to detect stranded UTXOs. The caller provides the outpoint; the script signs a spend.

## The bug, in one paragraph

CLN's mnemonic-format wallet uses **BIP86** (taproot, `m/86'/0'/0'/0/N`) for everything on-chain. But on v25.12 the helper that builds onchaind sweep transactions ([`lightningd/onchain_control.c::onchaind_tx_unsigned`](https://github.com/ElementsProject/lightning/blob/v25.12/lightningd/onchain_control.c)) always derived the sweep's destination key with the **legacy BIP32** helper (`m/0/0/N`) regardless of wallet type. The output script committed to that legacy-derived key. The wallet's incoming-output scanner (`wallet_can_spend`) only checks BIP86-derived scripts, so it silently walked past the sweep output. The bookkeeper recorded the `to_wallet` move based on onchaind's status messages, hiding the mismatch from `listbalances`.

## Disclaimer

This software is provided "as is", without warranty of any kind, express or implied. It handles the wallet seed and signs Bitcoin transactions that move real funds; mistakes (a wrong `--final-key-idx`, a wrong `--passphrase`, a misread on-chain script, an undersized fee, a compromised host, an unintended broadcast) can result in **permanent and unrecoverable loss of funds**. You are solely responsible for verifying the derivation against the on-chain UTXO before signing, for the safety of the machine running the script, and for the transaction you broadcast. The author accepts no liability for any loss, damage, or other consequence arising from the use of this tool. If you are not comfortable independently auditing the derivation steps in [`recover_stranded_sweep.py`](recover_stranded_sweep.py) and the resulting transaction, do not use it.

## Safety

- The script writes nothing to disk. It reads `--hsm-secret` and prints the signed tx to stdout. The derived scriptPubKey goes to stderr.
- It refuses 32-byte legacy `hsm_secret` files. Those wallets are unaffected by the bug and can be exported with the existing `lightning-hsmtool dumponchaindescriptors` instead.
- The BIP340 signing path uses `libsecp256k1` (via `coincurve`), the same library Bitcoin Core uses for verification.

## Recovering a stranded sweep

These are the steps to go from "I think I have a stranded sweep" to a broadcast spend.

### Step 1: Confirm the UTXO is stranded by this bug

After a unilateral close on **v25.12** with a **mnemonic / BIP86** hsm_secret, the symptom is: `bkpr-listaccountevents` shows `delayed_to_us → to_wallet` for the closed channel, but `listfunds` doesn't show the output, and `bitcoin-cli gettxout` confirms it's unspent on-chain as a P2TR.

Run, replacing `<CID>` with the closed channel's hex `channel_id`:

```sh
lightning-cli bkpr-listaccountevents <CID>
```

You should see a `to_wallet` event whose `outpoint` is the sweep output, plus a `txid` field which is the sweep transaction:

```json
{
   "account": "adfeb5611f982ff21b4d8245d34f19f1f9a20e8b4cb7260ef4e78e6ba41d2c78",
   "type": "chain",
   "tag": "to_wallet",
   "credit_msat": 0,
   "debit_msat": 997935000,
   "outpoint": "d55d68d0e5f9a3ef970c250c22aac511dc8133a04d05adadf8ca4cbfa8e4850c:3",
   "txid": "cd5b3052d3f0ff7b4b7d46d018179fa50dde197612a836ac111a7b84f196f49c",
   "timestamp": 1779277060,
   "blockheight": 217
}
```

Take the sweep `txid` and look it up on-chain. The vout you want is the one whose `scriptPubKey.type` is `witness_v1_taproot`:

```sh
bitcoin-cli gettxout <sweep_txid> 0
```

```json
{
  "value": 0.00997801,
  "scriptPubKey": {
    "hex": "5120246876cf176b777a5d8380c11d2364cdb6d1537b2bb153f062c423d02f821601",
    "address": "bcrt1py358dnchddmh5hvrsrq36gmyekmdz5mm9wc48urzcs3aqtuzzcqsk3m9nk",
    "type": "witness_v1_taproot"
  }
}
```

Record three things from the previous output: the **outpoint** (`<txid>:<vout>`), the **input amount in satoshis** (`value` × 10^8, here `997801`), and the **scriptPubKey hex** (for the verification step).

If `listfunds` already shows this output, or `bkpr-listbalances` reports the closed channel as `account_resolved: true`, you are not looking at a UTXO stranded by this bug, and this tool is not the right one.

### Step 2: Find `--final-key-idx`

The index lives in CLN's wallet DB on the closed channel's row. Replace `<CID>` with the same hex `channel_id`:

```sh
sqlite3 ~/.lightning/bitcoin/lightningd.sqlite3 \
    "SELECT shutdown_keyidx_local
       FROM channels
      WHERE hex(full_channel_id) = upper('<CID>');"
```

`bkpr-listbalances` is a good sanity check that the right closed channel is being addressed (`account_closed: true`, `account_resolved: false`, `balance_msat: 0`):

```json
{
   "account": "adfeb5611f982ff21b4d8245d34f19f1f9a20e8b4cb7260ef4e78e6ba41d2c78",
   "peer_id": "0337e09946a884fc4f7421764aee6701795bc262f58900dac31c0707e99da4f48b",
   "we_opened": true,
   "account_closed": true,
   "account_resolved": false,
   "balances": [ { "balance_msat": 0, "coin_type": "bcrt" } ]
}
```

### Step 3: Pick a destination address and a fee

The destination is any address controlled by a wallet that is *not* affected by the bug. Typically a fresh address from the same CLN node (`lightning-cli newaddr`) or a cold wallet. The address HRP must match the network (`bc1…`, `tb1…`, or `bcrt1…`).

`--fee-sats` is an absolute fee in satoshis. See the next section, [Computing `--fee-sats`](#computing---fee-sats), for the calculation.

### Step 4: Verify the derivation (dry run)

Before signing anything, confirm that the script derives the same P2TR scriptPubKey as the on-chain UTXO:

```sh
uv sync                                                          # install coincurve
uv run python recover_stranded_sweep.py \
    --hsm-secret /home/lightning/.lightning/bitcoin/hsm_secret \
    --network bitcoin \
    --final-key-idx <N> \
    [--passphrase <bip39_passphrase>] \
    --print-only
```

This prints:

```
derived scriptPubKey (P2TR): 5120...
derived address (bitcoin): bc1p...
```

Compare against the on-chain script:

```sh
bitcoin-cli gettxout <sweep_txid> 0 | jq -r .scriptPubKey.hex
```

The two hex strings **must** be identical. If they're not, either `--final-key-idx` is wrong, `--passphrase` is wrong, or the UTXO is not stranded by this bug. If this is the case, stop and re-check Step 1 and Step 2 before going further.

### Step 5: Sign and broadcast

Run the script for real with all required arguments:

```sh
uv run python recover_stranded_sweep.py \
    --hsm-secret /home/lightning/.lightning/bitcoin/hsm_secret \
    --network bitcoin \
    --final-key-idx <N> \
    --outpoint <sweep_txid>:0 \
    --input-sats <value_in_sats> \
    --dest-addr <bc1p...> \
    --fee-sats <fee> \
    [--passphrase <bip39_passphrase>]
```

`--network` controls the bech32m HRP and accepts `bitcoin` (default), `testnet`, `regtest`, or `signet`. The derivation math is identical across networks; only the address encoding differs.

The script prints the signed transaction hex to stdout. Broadcast it:

```sh
bitcoin-cli sendrawtransaction <signed_tx_hex>
```

A successful `sendrawtransaction` returns the transaction's txid. The funds are now in the destination wallet once the tx confirms.

---

## Computing `--fee-sats`

The recovery transaction is exactly **1 input, 1 output, both P2TR (BIP86 key-path)**. That shape has a fixed virtual size of **111 vbytes**:

| Component | Size |
| --- | --- |
| Non-witness bytes (× 4 weight) | 94 bytes → 376 wu |
| Witness (marker+flag + 1-item stack with 64-byte Schnorr sig) | 68 wu |
| Total weight | 444 wu |
| **vsize** | **⌈444 / 4⌉ = 111 vbytes** |

So:

```
fee_sats = ceil(target_feerate_sat_per_vbyte × 111)
```

To pick `target_feerate_sat_per_vbyte`, check the current mempool. Bitcoin Core's `estimatesmartfee` returns BTC/kvB, so convert:

```sh
bitcoin-cli estimatesmartfee 6 | jq -r '.feerate'   # BTC per kvB, e.g. 0.00002000
```

`feerate_sat_per_vbyte = feerate_BTC_per_kvB × 10^5`. For the example above, `0.00002000 × 100000 = 2 sat/vB`, so `--fee-sats 222` (`2 × 111`).

Alternative sources for a feerate:

- [mempool.space](https://mempool.space) (or the equivalent for testnet/signet), read off "Low / Medium / High Priority" sat/vB directly.
- Match a recent confirmed tx of similar urgency.

A few sanity rules the script enforces:

- `--fee-sats` must be `> 0` and `< --input-sats`.
- The resulting output (`input_sats − fee_sats`) must be `≥ 330` sats (dust limit).
- There is no fee-bumping path: this script signs one tx with one input and one output. If the broadcast feerate turns out too low, the only options are to wait, or to re-sign with a higher fee once the original is dropped from mempools. There is no RBF flag set, so a replacement requires the same outpoint to still be unspent in the mempool.

Pick a fee high enough to confirm within the timeframe you actually care about; the input is yours and not under any HTLC timeout, so there is no rush beyond your own preference.


## CLN's derivation chain, ground truth

Reading the relevant source paths, the chain used by hsmd at runtime for **mnemonic (>32-byte) hsm_secret** files is:

```
hsm_secret file
    └── [32 byte passphrase-hash][UTF-8 mnemonic]
            │
            │  extract_mnemonic_secret()  →  common/hsm_secret.c:265
            ▼
mnemonic + passphrase
            │
            │  BIP39 PBKDF2-HMAC-SHA512(iter=2048, dklen=64)
            ▼
64-byte BIP39 seed                                  ← hsmd_init(secret_data, …)
            │
            │  hkdf-loop("bip32 seed", IKM=seed, salt=u32_LE iter++)
            │  in hsmd/libhsmd.c around L2462-2471
            ▼
32-byte BIP32 master seed
            │
            │  BIP32 master derivation (HMAC-SHA512 "Bitcoin seed")
            ▼
BIP32 master xprv (= secretstuff.bip32 after / 0 / 0)
            │
            │  CKDpriv  / 0 / 0 / <final_key_idx>     (all non-hardened)
            ▼
"legacy" private key  ←──── this is what onchaind_tx_unsigned() picked on v25.12
            │
            │  BIP86 key-only taptweak (BIP341 with empty merkle root)
            ▼
P2TR scriptPubKey  ←──── what the buggy sweep tx paid to
```

For a **32-byte legacy plain** `hsm_secret`, the first two boxes collapse: `secret_data` is just the file's 32 bytes and everything else is identical.

The wallet matcher (`wallet/wallet.c::wallet_can_spend`) only generates scripts using the *BIP86* path (`m/86'/0'/0'/0/N`) for mnemonic wallets, so the legacy-derived P2TR above is never matched. The fix in [#8831](https://github.com/ElementsProject/lightning/pull/8831) makes `onchaind_tx_unsigned()` use the BIP86 helper too but only for sweeps produced after the upgrade.

## How the tests cover correctness

Running `uv run pytest tests/` exercises 21 checks against an in-process regtest `bitcoind`. They're organised so the chain is verified in *overlapping slices*:

| File | Check | Oracle |
| --- | --- | --- |
| `test_derivation.py::test_bip39_mnemonic_to_seed_matches_trezor_vector` | mnemonic+passphrase → 64-byte seed | Canonical Trezor BIP39 test vector |
| `test_derivation.py::test_bip39_no_passphrase_vector` | mnemonic → 64-byte seed (empty passphrase) | Published BIP39 vector |
| `test_derivation.py::test_legacy_bip32_matches_hsmtool_and_bitcoin_core[bitcoin\|testnet\|signet]` | HKDF-loop + BIP32 / 0 / 0 / N + BIP86 taptweak: parameterised across networks | `lightning-hsmtool dumponchaindescriptors <net>` + `bitcoin-cli deriveaddresses` |
| `test_derivation.py::test_bech32m_address_encoding_per_network[bitcoin\|testnet\|signet\|regtest]` | bech32m encode/decode for each network | Round-trip + HRP literal check |
| `test_derivation.py::test_assert_addr_matches_network_rejects_mismatch` | HRP mismatch rejection | Mismatch raises, match passes |
| `test_derivation.py::test_hsmd_secret_data_from_file_*` | Hsm_secret file → `secret_data` semantics (plain, mnemonic no-pass, mnemonic with-pass) | Direct comparison to `common/hsm_secret.c::extract_*_secret` behaviour |
| `test_e2e_recovery.py::test_recovery_roundtrip[no-pass\|with-pass]` | Full chain → P2TR pay → signed key-path spend on regtest with `--network regtest` and a `bcrt1p…` derived address | `bitcoin-cli testmempoolaccept` + on-chain confirmation |
| `test_e2e_recovery.py::test_rejects_wrong_network_dest_addr` | `--network=regtest` + a `bc1p…` `--dest-addr` | Script exits nonzero with HRP/network in stderr |
| `test_e2e_recovery.py::test_rejects_wrong_passphrase` | Wrong `--passphrase` against a tagged file | Script exits nonzero |
| `test_e2e_recovery.py::test_requires_passphrase_when_tagged` | Missing `--passphrase` on a tagged file | Script exits nonzero |
| `test_e2e_recovery.py::test_rejects_legacy_32byte_secret` | Plain 32-byte secret on the CLI | Script exits nonzero (use hsmtool instead) |
| `test_e2e_recovery.py::test_print_only_does_not_require_dest` | `--print-only` derive-only mode | Script exits zero, stdout empty |

Together these pin down each link of the chain against an independent oracle:

- **BIP39 PBKDF2** ↔ Trezor vectors.
- **HKDF "bip32 seed" loop + BIP32 + BIP86 taptweak** ↔ hsmtool's own primitives (libwally), via Bitcoin Core descriptor derivation.
- **BIP341 sighash + BIP340 Schnorr + tx serialization** ↔ Bitcoin Core's full-node mempool verifier.

The only link not verified against a runtime oracle is *"hsmd really does feed the BIP39 seed into the hkdf-loop for mnemonic wallets"*, which is established by reading [common/hsm_secret.c:320-326](https://github.com/ElementsProject/lightning/blob/master/common/hsm_secret.c#L320-L326) and [hsmd/libhsmd.c:2462-2471](https://github.com/ElementsProject/lightning/blob/master/hsmd/libhsmd.c#L2462-L2471).

## Requirements

- Python ≥ 3.11
- `coincurve >= 20` (libsecp256k1 bindings)
- For the tests: `bitcoind` / `bitcoin-cli` (Bitcoin Core 25+) and `lightning-hsmtool` somewhere on `PATH`.

Resolve everything with [uv](https://docs.astral.sh/uv/):

```sh
uv sync
uv run pytest tests/ -v
```

## References

- Bug fix PR: <https://github.com/ElementsProject/lightning/pull/8831>
- Release notes (v25.12.1): <https://github.com/ElementsProject/lightning/releases/tag/v25.12.1>
- BIP32 (HD wallets): <https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki>
- BIP39 (mnemonic + PBKDF2): <https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki>
- BIP86 (single-key taproot): <https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki>
- BIP340 (Schnorr): <https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki>
- BIP341 (Taproot): <https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki>
- BIP350 (Bech32m): <https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki>
