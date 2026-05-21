"""Shared bitcoind regtest fixture for the recovery-tool tests."""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Bitcoind:
    def __init__(self, datadir: Path, rpc_port: int, p2p_port: int):
        self.datadir = datadir
        self.rpc_port = rpc_port
        self.p2p_port = p2p_port
        self.user = "u"
        self.pw = "p"
        self.proc: subprocess.Popen | None = None

    def cli(self, *args: str) -> str:
        cmd = [
            "bitcoin-cli",
            f"-datadir={self.datadir}",
            f"-rpcport={self.rpc_port}",
            f"-rpcuser={self.user}",
            f"-rpcpassword={self.pw}",
            "-regtest",
            *args,
        ]
        return subprocess.check_output(cmd, text=True).strip()

    def rpc(self, method: str, *params) -> object:
        out = self.cli(method, *[json.dumps(p) if not isinstance(p, str) else p
                                 for p in params])
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            return out

    def start(self) -> None:
        self.datadir.mkdir(parents=True, exist_ok=True)
        conf = (
            "regtest=1\n"
            "fallbackfee=0.0001\n"
            "[regtest]\n"
            f"rpcuser={self.user}\n"
            f"rpcpassword={self.pw}\n"
            f"rpcport={self.rpc_port}\n"
            f"port={self.p2p_port}\n"
            "rpcallowip=127.0.0.1\n"
            "rpcbind=127.0.0.1\n"
        )
        (self.datadir / "bitcoin.conf").write_text(conf)
        self.proc = subprocess.Popen(
            ["bitcoind", f"-datadir={self.datadir}", "-daemon=0"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # Wait for RPC ready.
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                self.cli("getblockchaininfo")
                return
            except subprocess.CalledProcessError:
                time.sleep(0.2)
        raise RuntimeError("bitcoind regtest did not become RPC-ready in 30s")

    def stop(self) -> None:
        if self.proc is None:
            return
        try:
            self.cli("stop")
            self.proc.wait(timeout=15)
        except Exception:
            self.proc.kill()
            self.proc.wait()


@pytest.fixture(scope="session")
def bitcoind():
    if not shutil.which("bitcoind") or not shutil.which("bitcoin-cli"):
        pytest.skip("bitcoind/bitcoin-cli not in PATH")
    tmp = Path(tempfile.mkdtemp(prefix="recover-stranded-bitcoind-"))
    bd = Bitcoind(datadir=tmp, rpc_port=_free_port(), p2p_port=_free_port())
    bd.start()
    # Create a default wallet and load it; descriptor wallet by default.
    bd.cli("-named", "createwallet", "wallet_name=miner", "descriptors=true")
    # Mine 101 blocks so coinbase is spendable.
    miner_addr = bd.cli("-rpcwallet=miner", "getnewaddress")
    bd.cli("-rpcwallet=miner", "generatetoaddress", "101", miner_addr)
    yield bd
    bd.stop()
    shutil.rmtree(tmp, ignore_errors=True)


@pytest.fixture(scope="session")
def script_module():
    """Import the recover_stranded_sweep module from the repo root."""
    here = Path(__file__).resolve().parent
    repo_root = here.parent
    sys.path.insert(0, str(repo_root))
    import recover_stranded_sweep  # type: ignore
    return recover_stranded_sweep


@pytest.fixture
def hsmtool_path():
    p = shutil.which("lightning-hsmtool")
    if not p:
        pytest.skip("lightning-hsmtool not in PATH")
    return p
