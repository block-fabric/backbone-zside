#!/usr/bin/env python3
"""Side-by-side regtest: THEIR thunder-orchard (iwakura-rein b225827) and OUR thunder-orchard
(backbone-zside) on one eCash regtest chain (ecash-com/bitcoin + electrs + bip300301_enforcer),
peered only with each other over QUIC. Blocks are mined alternately by each node (BMM through the
enforcer); after every block both nodes' JSON-RPC replies are compared byte for byte.

    zside_regtest.py up        # mainchain + slot 98 active + both nodes, funded
    zside_regtest.py scenario  # transfers, shield / shielded transfer / unshield both ways, withdrawals, reorgs
    zside_regtest.py down      # stop exactly the recorded PIDs

Local only (user approval: running their code locally for tests). Ports 49530-49549.
"""
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

SKY = Path.home() / "skydoge"
sys.path.insert(0, str(SKY / "tools/linked-regtest"))
import connect  # noqa: E402

DIR = Path(os.environ.get("ZS_DIR", "/tmp/claude-1000/-home-louis-skydoge/7356a361-1f43-4339-9758-6b3a575878c3/scratchpad/zs/regtest"))
BASE = 49530
P = {"ecash_rpc": BASE, "ecash_p2p": BASE + 1, "ecash_zmq": BASE + 3, "electrum": BASE + 5, "esplora": BASE + 6,
     "electrs_monitor": BASE + 7, "enf_grpc": BASE + 10, "enf_rpc": BASE + 11,
     "their_p2p": BASE + 13, "their_rpc": BASE + 14, "our_p2p": BASE + 16, "our_rpc": BASE + 17}
BIN = {
    "ecashd": SKY / "ext/ecash-bitcoin/build/bin/bitcoind",
    "ecash_cli": SKY / "ext/ecash-bitcoin/build/bin/bitcoin-cli",
    "electrs": SKY / "ext/electrs/target/release/electrs",
    "enforcer": SKY / "ext/enforcer/target/release/bip300301_enforcer",
    "theirs": SKY / "ext/thunder-orchard/target/release/thunder_orchard_app",
    "their_cli": SKY / "ext/thunder-orchard/target/release/thunder_orchard_app_cli",
    "ours": SKY / "backbone-zside/build/chains/zside/thunder-orchard",
    "our_cli": SKY / "backbone-zside/build/chains/zside/thunder-orchard-cli",
}
SLOT = 98
USER = PASS = "zs"
MAGIC = "eca5b134"
MNEMONIC = {"theirs": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "ours": "legal winner thank year wave sausage worth useful legal winner thank yellow"}
LOG = []


def log(*a):
    s = " ".join(str(x) for x in a)
    print(s, flush=True)
    LOG.append(s)


def spawn(name, argv, cwd=None):
    (DIR / "logs").mkdir(parents=True, exist_ok=True)
    out = open(DIR / "logs" / f"{name}.out", "ab")
    p = subprocess.Popen([str(a) for a in argv], stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
                         start_new_session=True, cwd=cwd)
    with open(DIR / "pids", "a") as f:
        f.write(f"{name} {p.pid}\n")
    return p.pid


def pids():
    f = DIR / "pids"
    if not f.exists():
        return {}
    r = {}
    for line in f.read_text().splitlines():
        if line.strip():
            n, p = line.split()
            r[n] = int(p)
    return r


def alive(pid):
    try:
        os.kill(pid, 0)
        return open(f"/proc/{pid}/stat").read().split(") ")[-1].split()[0] != "Z"
    except OSError:
        return False


def wait_for(f, what, timeout=120, step=0.5):
    end = time.time() + timeout
    last = None
    while time.time() < end:
        try:
            r = f()
            if r:
                return r
        except Exception as e:  # noqa: BLE001
            last = e
        time.sleep(step)
    raise RuntimeError(f"timeout waiting for {what} ({last})")


def ecash(method, *params):
    body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
    import base64
    req = urllib.request.Request(f"http://127.0.0.1:{P['ecash_rpc']}", body,
                                 {"Authorization": "Basic " + base64.b64encode(f"{USER}:{PASS}".encode()).decode()})
    try:
        r = json.loads(urllib.request.urlopen(req, timeout=120).read())
    except urllib.error.HTTPError as e:
        r = json.loads(e.read())
    if r.get("error"):
        raise RuntimeError(f"{method}: {r['error']}")
    return r["result"]


def grpc(method, req=None, timeout=120):
    return connect.call(f"127.0.0.1:{P['enf_grpc']}", method, req or {}, timeout=timeout)


class Side:
    """jsonrpsee JSON-RPC of one sidechain node; raw() keeps the reply bytes."""

    def __init__(self, name, port):
        self.name, self.port = name, port

    def raw(self, method, params=None, timeout=600):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params if params is not None else []}).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}", body, {"Content-Type": "application/json"})
        try:
            return urllib.request.urlopen(req, timeout=timeout).read()
        except urllib.error.HTTPError as e:
            return e.read()

    def call(self, method, *params, timeout=600):
        r = json.loads(self.raw(method, list(params), timeout))
        if "error" in r:
            raise RuntimeError(f"{self.name} {method}: {r['error']}")
        return r["result"]


THEIRS = Side("theirs", P["their_rpc"])
OURS = Side("ours", P["our_rpc"])
NODES = [THEIRS, OURS]


def node_argv(which):
    d = DIR / which
    seedf = DIR / f"{which}.mnemonic"
    seedf.write_text(MNEMONIC[which])
    p2p, rpc, peer = (P["their_p2p"], P["their_rpc"], P["our_p2p"]) if which == "theirs" else (P["our_p2p"], P["our_rpc"], P["their_p2p"])
    argv = [BIN[which], "--headless", "--datadir", d, "--network", "regtest",
            "--mainchain-grpc-url", f"http://127.0.0.1:{P['enf_grpc']}", "--net-addr", f"127.0.0.1:{p2p}",
            "--rpc-addr", f"127.0.0.1:{rpc}", "--private-rpc-addr", f"127.0.0.1:{rpc}", "--add-peer", f"127.0.0.1:{peer}",
            "--mnemonic-seed-phrase-path", seedf, "--log-level", "info", "--log-level-file", "debug"]
    return argv


def start_node(which):
    spawn(which, node_argv(which))
    s = THEIRS if which == "theirs" else OURS
    wait_for(lambda: s.call("getblockcount") is not None, f"{which} RPC", 180, 1)


def stop_node(which):
    s = THEIRS if which == "theirs" else OURS
    pid = pids().get(which)
    try:
        s.call("stop", timeout=10)
    except Exception:  # noqa: BLE001
        pass
    if pid:
        end = time.time() + 30
        while alive(pid) and time.time() < end:
            time.sleep(0.5)
        if alive(pid):
            os.kill(pid, 15)
            time.sleep(2)
    lines = [ln for ln in (DIR / "pids").read_text().splitlines() if not ln.startswith(which + " ")]
    (DIR / "pids").write_text("\n".join(lines) + "\n")


def enforcer_mine(n=1):
    for _ in range(n):
        grpc("MiningService/GenerateToAddress", {"address": STATE["enf_addr"], "blocks": 1}, timeout=300)


STATE = {}


def save():
    (DIR / "state.json").write_text(json.dumps(STATE))


def load():
    STATE.update(json.loads((DIR / "state.json").read_text()))


def up():
    if any(alive(p) for p in pids().values()):
        sys.exit("already running")
    if DIR.exists():
        import shutil
        shutil.rmtree(DIR)
    DIR.mkdir(parents=True)
    def busy():
        r = []
        for k, v in P.items():
            with socket.socket() as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    s.bind(("127.0.0.1", v))
                except OSError:
                    r.append((k, v))
        return r
    end = time.time() + 300  # other test suites on this machine take random ports for a while
    while busy() and time.time() < end:
        time.sleep(5)
    if busy():
        sys.exit(f"ports busy: {busy()}")
    ed = DIR / "ecash"
    ed.mkdir()
    spawn("ecashd", [BIN["ecashd"], "-regtest", f"-datadir={ed}", f"-rpcport={P['ecash_rpc']}", f"-port={P['ecash_p2p']}",
                     f"-bind=127.0.0.1:{P['ecash_p2p']}", "-rest", f"-zmqpubsequence=tcp://127.0.0.1:{P['ecash_zmq']}",
                     "-disablewallet", f"-rpcuser={USER}", f"-rpcpassword={PASS}", "-server", "-dnsseed=0",
                     "-fixedseeds=0", "-discover=0", "-printtoconsole=0", "-txindex"])
    wait_for(lambda: ecash("getblockcount") >= 0, "ecashd", 120)
    burn = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
    ecash("generatetoaddress", 1, burn)
    start_electrs()
    start_enforcer()
    wait_for(lambda: grpc("ValidatorService/GetChainTip")["blockHeaderInfo"]["height"] == 1, "enforcer sync", 180)
    STATE["enf_addr"] = wait_for(lambda: grpc("WalletService/CreateNewAddress")["address"], "enforcer wallet", 120)
    save()
    enforcer_mine(101)
    grpc("BlockProducerService/SetAckAllProposals", {"policy": "ACK_ALL_PROPOSALS_POLICY_ALL"})
    grpc("BlockProducerService/SubmitSidechainProposal", {
        "sidechainId": SLOT, "declaration": {"v0": {"title": "zSide", "description": "zSide drop-in regtest",
                                                    "hashId1": {"hex": "11" * 32}, "hashId2": {"hex": "22" * 20}}}})

    def active():
        enforcer_mine(1)
        return any(s.get("sidechainNumber") == SLOT for s in grpc("ValidatorService/GetSidechains").get("sidechains", []))
    wait_for(active, "slot 98 active", 600, 0.1)
    log("slot 98 active at mainchain height", ecash("getblockcount"))
    start_node("theirs")
    start_node("ours")
    for s in NODES:
        STATE[f"{s.name}_t"] = s.call("get_new_transparent_address")
    save()
    log("nodes up:", STATE)


def start_electrs():
    import shutil
    ed = DIR / "ecash"
    xd = DIR / "electrs"
    shutil.rmtree(xd, ignore_errors=True)
    xd.mkdir()
    spawn("electrs", [BIN["electrs"], "-v", f"--db-dir={xd}", f"--daemon-dir={ed}", f"--daemon-rpc-addr=127.0.0.1:{P['ecash_rpc']}",
                      f"--electrum-rpc-addr=127.0.0.1:{P['electrum']}", f"--http-addr=127.0.0.1:{P['esplora']}",
                      f"--monitoring-addr=127.0.0.1:{P['electrs_monitor']}", "--network=regtest", f"--cookie={USER}:{PASS}",
                      "--jsonrpc-import"])
    wait_for(lambda: urllib.request.urlopen(f"http://127.0.0.1:{P['esplora']}/blocks/tip/height", timeout=5).read(), "electrs", 120)


def start_enforcer():
    nd = DIR / "enforcer"
    nd.mkdir(exist_ok=True)
    spawn("enforcer", [BIN["enforcer"], f"--data-dir={nd}", f"--node-rpc-addr=127.0.0.1:{P['ecash_rpc']}",
                       f"--node-rpc-user={USER}", f"--node-rpc-pass={PASS}", f"--node-zmq-addr-sequence=tcp://127.0.0.1:{P['ecash_zmq']}",
                       f"--network-magic={MAGIC}", "--op-drivechain=nop8", "--enable-wallet", "--wallet-auto-create",
                       "--enable-mempool", "--enable-block-template-server", f"--wallet-esplora-url=http://127.0.0.1:{P['esplora']}",
                       f"--serve-grpc-addr=127.0.0.1:{P['enf_grpc']}", f"--serve-rpc-addr=127.0.0.1:{P['enf_rpc']}",
                       f"--log-directory={nd / 'logs'}", "--log-level=info"])
    wait_for(lambda: grpc("ValidatorService/GetChainTip"), "enforcer gRPC", 180)


def restart_main():
    """electrs (fresh index) and the enforcer again, after a mainchain reorg."""
    ps = pids()
    for n in ("enforcer", "electrs"):
        if n in ps and alive(ps[n]):
            os.kill(ps[n], 15)
    time.sleep(3)
    start_electrs()
    start_enforcer()
    wait_for(lambda: grpc("ValidatorService/GetChainTip")["blockHeaderInfo"]["height"] == ecash("getblockcount"), "enforcer sync", 300)


def down():
    order = ["theirs", "ours", "enforcer", "electrs", "ecashd"]
    ps = pids()
    for n in order + [k for k in ps if k not in order]:
        if n in ps and alive(ps[n]):
            if n in ("theirs", "ours"):
                stop_node(n)
                continue
            if n == "ecashd":
                try:
                    ecash("stop")
                except Exception:  # noqa: BLE001
                    os.kill(ps[n], 15)
            else:
                os.kill(ps[n], 15)
            end = time.time() + 60
            while alive(ps[n]) and time.time() < end:
                time.sleep(0.5)
            if alive(ps[n]):
                os.kill(ps[n], 9)
    still = [n for n, p in pids().items() if alive(p)]
    print("stopped; alive:", still)


# ------------------------------------------------------------------ mining and comparison

def mine_with(s, fee=None):
    """Their `mine` (and ours) send the BMM request, then wait for the next mainchain block."""
    res = {}

    def run():
        try:
            res["r"] = s.call("mine", fee, timeout=600)
        except Exception as e:  # noqa: BLE001
            res["e"] = e
    t = threading.Thread(target=run)
    t.start()
    time.sleep(3)
    try:
        enforcer_mine(1)
    except Exception as e:  # noqa: BLE001  fall back to ecashd (upstream issue, details held for coordinated disclosure)
        log(f"  enforcer GenerateToAddress failed ({str(e)[:80]}); mining with ecashd")
        ecash("generatetoaddress", 1, STATE["enf_addr"])
    t.join(300)
    if "e" in res:
        raise res["e"]


READS = ["getblockcount", "get_best_sidechain_block_hash", "get_best_mainchain_block_hash", "list_utxos",
         "pending_withdrawal_bundle", "latest_failed_withdrawal_bundle_height", "sidechain_wealth"]
CHECKS = {"n": 0, "diff": 0}


def canon(method, raw):
    j = json.loads(raw)
    if method in ("list_utxos", "get_utxos", "get_stxos"):
        r = j.get("result")
        if isinstance(r, list):
            j["result"] = sorted(r, key=lambda x: json.dumps(x, sort_keys=True))
            return json.dumps(j, sort_keys=True).encode()
    return raw


def same(method, params=None, sets=False):
    a = THEIRS.raw(method, params)
    b = OURS.raw(method, params)
    if sets:
        a, b = canon(method, a), canon(method, b)
    CHECKS["n"] += 1
    if a != b:
        CHECKS["diff"] += 1
        log(f"DIFF {method} {params}:\n  theirs {a[:600]}\n  ours   {b[:600]}")
        return False
    return True


def sync_tips(timeout=180):
    return wait_for(lambda: THEIRS.call("get_best_sidechain_block_hash") == OURS.call("get_best_sidechain_block_hash")
                    and THEIRS.call("get_best_sidechain_block_hash") is not None
                    and THEIRS.call("get_best_sidechain_block_hash"), "same sidechain tip", timeout)


def compare_all():
    tip = sync_tips()
    for m in READS:
        same(m, sets=m == "list_utxos")
    h = THEIRS.call("getblockcount")
    for height in range(max(0, h - 3), h):
        bh = THEIRS.call("get_block_hash", height)
        same("get_block_hash", [height])
        same("get_block", [bh])
        same("get_block", [bh, True])
        same("get_bmm_inclusions", [bh])
    for a in (STATE["theirs_t"], STATE["ours_t"]):
        same("get_utxos", [[a]], sets=True)
        same("get_stxos", [[a]], sets=True)
    return tip


def compare_history():
    """get_block (both verbosities), get_block_hash and get_bmm_inclusions at every height."""
    sync_tips()
    h = THEIRS.call("getblockcount")
    for height in range(h):
        bh = THEIRS.call("get_block_hash", height)
        same("get_block_hash", [height])
        same("get_block", [bh])
        same("get_block", [bh, True])
        same("get_bmm_inclusions", [bh])
    log(f"history compared: {h} blocks, checks {CHECKS['n']}, diffs {CHECKS['diff']}")


def mine_and_compare(s, fee=None):
    mine_with(s, fee)
    tip = compare_all()
    log(f"  block by {s.name}: height {THEIRS.call('getblockcount')}, tip {tip[:16]}, checks {CHECKS['n']}, diffs {CHECKS['diff']}")


def scenario():
    load()
    alt = [THEIRS, OURS]
    k = 0

    def mine(n=1):
        nonlocal k
        for _ in range(n):
            mine_and_compare(alt[k % 2])
            k += 1
    log("== empty blocks, alternately mined")
    mine(4)
    log("== deposits: 2 ECX to each node's transparent address (bare base58)")
    for who in ("theirs", "ours"):
        grpc("WalletService/CreateDepositTransaction", {"sidechainId": SLOT, "address": STATE[f"{who}_t"],
                                                         "valueSats": str(200_000_000), "feeSats": "10000"})
        enforcer_mine(1)
    mine(3)
    for s in NODES:
        log(f"  {s.name} balance {s.call('balance')}")
    log("== transparent transfers both ways")
    THEIRS.call("create_transparent_transfer", STATE["ours_t"], 10_000_000, 1000)
    OURS.call("create_transparent_transfer", STATE["theirs_t"], 7_000_000, 1000)
    wait_for(lambda: len(THEIRS.call("get_wallet_utxos_unconfirmed")) and len(OURS.call("get_wallet_utxos_unconfirmed")), "mempool relay", 60)
    mine(2)
    log("== shields: theirs shields 50,000,000; ours shields 40,000,000")
    their_wallet(mine, "create_shield", 50_000_000, 1000)
    mine(1)
    OURS.call("create_shield", 40_000_000, 1000)
    mine(4)
    for s in NODES:
        log(f"  {s.name} balance {s.call('balance')}")
    STATE["theirs_z"] = THEIRS.call("get_new_shielded_address")
    STATE["ours_z"] = OURS.call("get_new_shielded_address")
    save()
    phase2(mine)


def their_wallet(mine, method, *params):
    """Their wallet's shard tree intermittently has no root at the anchor checkpoint ("Tree does
    not contain a root at address ..."; their issue #29 / PR #41): retry after another block."""
    for _ in range(8):
        try:
            return THEIRS.call(method, *params)
        except RuntimeError as e:
            if "ShardTree" not in str(e):
                raise
            log(f"  their {method} failed ({str(e)[:90]}); mining another block")
            mine(1)
    raise RuntimeError(f"their {method} kept failing")


def phase2(mine):
    log("== shielded transfers: ours -> theirs 9,876,543; theirs -> ours 12,345,678")
    mine(3)  # notes must be under the anchor (3 blocks below the tip on both wallets)
    OURS.call("create_shielded_transfer", STATE["theirs_z"], 9_876_543, 1000)
    mine(1)
    their_wallet(mine, "create_shielded_transfer", STATE["ours_z"], 12_345_678, 1000)
    mine(4)
    for s in NODES:
        log(f"  {s.name} balance {s.call('balance')}")
    log("== unshields: each unshields 5,000,000")
    their_wallet(mine, "create_unshield", 5_000_000, 1000)
    OURS.call("create_unshield", 5_000_000, 1000)
    mine(4)
    for s in NODES:
        log(f"  {s.name} balance {s.call('balance')}")
    log("== withdrawals: each 1 ECX to the enforcer's wallet")
    THEIRS.call("create_withdrawal", STATE["enf_addr"], 100_000_000, 1000, 10_000)
    OURS.call("create_withdrawal", STATE["enf_addr"], 50_000_000, 1000, 10_000)
    mine(3)
    log("  pending bundle:", json.dumps(THEIRS.call("pending_withdrawal_bundle"))[:200])
    log(f"checks {CHECKS['n']}, diffs {CHECKS['diff']}")
    (DIR / "scenario.log").write_text("\n".join(LOG))


def state_line():
    return [(s.name, s.call("getblockcount"), s.call("get_best_sidechain_block_hash")[:16]) for s in NODES]


def phase3():
    """Bundle payout, relay across implementations, a mainchain reorg, fresh syncs, wallet keys."""
    log("== withdrawal bundle until paid (Succeeded on both)")
    m6id = None
    for s in NODES:
        for x in s.call("get_wallet_stxos"):
            ip = x["inpoint"]
            if "Withdrawal" in ip:
                m6id = ip["Withdrawal"]["m6id"]
    for i in range(40):
        st = THEIRS.call("get_withdrawal_bundle", m6id)
        same("get_withdrawal_bundle", [m6id])
        if st and st["status"] == "Confirmed":
            log(f"  bundle {m6id[:16]} Confirmed after {i} blocks; CTIP {grpc('ValidatorService/GetCtip', {'sidechainNumber': SLOT})['ctip']['value']}")
            break
        mine_and_compare(NODES[i % 2])
    log("== relay across implementations: ours' shielded transfer mined by theirs, theirs' unshield mined by ours")
    OURS.call("create_shielded_transfer", STATE["theirs_z"], 1_111_111, 2000)
    time.sleep(3)
    mine_and_compare(THEIRS)
    blk = THEIRS.call("get_block", THEIRS.call("get_best_sidechain_block_hash"))
    log(f"  block by theirs carries {sum(1 for t in blk['body']['transactions'] if t['orchard_bundle'])} bundle(s) from ours")
    for i in range(3):
        mine_and_compare(NODES[i % 2])
    their_wallet(lambda n: [mine_and_compare(NODES[i % 2]) for i in range(n)], "create_unshield", 2_222_222, 3000)
    time.sleep(3)
    mine_and_compare(OURS)
    blk = OURS.call("get_block", OURS.call("get_best_sidechain_block_hash"))
    log(f"  block by ours carries {sum(1 for t in blk['body']['transactions'] if t['orchard_bundle'])} bundle(s) from theirs")
    log("== mainchain reorg over the last two side blocks")
    mine_and_compare(THEIRS)
    mine_and_compare(OURS)
    log(f"  before: {state_line()}")
    h = ecash("getblockcount")
    ecash("invalidateblock", ecash("getblockhash", h - 1))
    ecash("generatetoaddress", 1, STATE["enf_addr"])
    time.sleep(20)
    log(f"  after the reorg (mainchain {ecash('getblockcount')}): {state_line()}")
    for n, pid in pids().items():
        if n in ("theirs", "ours", "enforcer", "electrs"):
            log(f"    {n} alive: {alive(pid)}")
    restart_main()
    stop_node("theirs")
    start_node("theirs")
    time.sleep(10)
    log(f"  after restarting electrs, the enforcer and their node: {state_line()}")
    for i in range(4):
        mine_and_compare(NODES[i % 2])
    log("== fresh nodes syncing only from the other implementation")
    for kind, peer, name in (("theirs", P["our_p2p"], "theirs-from-ours"), ("ours", P["their_p2p"], "ours-from-theirs")):
        d = DIR / name
        spawn(name, [BIN[kind], "--headless", "--datadir", d, "--network", "regtest", "--mainchain-grpc-url",
                     f"http://127.0.0.1:{P['enf_grpc']}", "--net-addr", "127.0.0.1:49548", "--rpc-addr", "127.0.0.1:49549",
                     "--private-rpc-addr", "127.0.0.1:49549", "--add-peer", f"127.0.0.1:{peer}", "--log-level", "info"])
        f = Side(name, 49549)
        wait_for(lambda: f.call("getblockcount") is not None, "rpc", 180, 1)
        wait_for(lambda: f.call("get_best_sidechain_block_hash") == THEIRS.call("get_best_sidechain_block_hash"), "sync", 600, 1)
        n = f.call("getblockcount")
        ok = all(f.raw("get_block", [THEIRS.call("get_block_hash", x)]) == THEIRS.raw("get_block", [THEIRS.call("get_block_hash", x)]) for x in range(n))
        log(f"  {name}: synced {n} blocks, every block identical: {ok}")
        try:
            f.call("stop", timeout=10)
        except Exception:  # noqa: BLE001
            pass
        wait_for(lambda: not alive(pids()[name]), f"{name} stop", 60)
    log("== wallet keys: our node with their mnemonic derives their addresses")
    for i in range(4):
        THEIRS.call("get_new_transparent_address")
        THEIRS.call("get_new_shielded_address")
    tt, ts = THEIRS.call("get_transparent_wallet_addresses"), THEIRS.call("get_shielded_wallet_addresses")
    spawn("seedcheck", [BIN["ours"], "--headless", "--datadir", DIR / "ours-seedcheck", "--network", "regtest",
                        "--mainchain-grpc-url", f"http://127.0.0.1:{P['enf_grpc']}", "--rpc-addr", "127.0.0.1:49548",
                        "--private-rpc-addr", "127.0.0.1:49548", "--mnemonic-seed-phrase-path", DIR / "theirs.mnemonic", "--bt-no-p2p"])
    sc = Side("seedcheck", 49548)
    wait_for(lambda: sc.call("getblockcount") is not None, "rpc", 120, 1)
    for _ in tt:
        sc.call("get_new_transparent_address")
    for _ in ts:
        sc.call("get_new_shielded_address")
    log(f"  transparent {len(tt)} equal: {sc.call('get_transparent_wallet_addresses') == tt}; shielded {len(ts)} equal: {sc.call('get_shielded_wallet_addresses') == ts}")
    sc.call("stop")
    wait_for(lambda: not alive(pids()["seedcheck"]), "seedcheck stop", 60)
    for s in NODES:
        log(f"  {s.name} balance {s.call('balance')}")
    compare_history()
    same("openapi_schema")
    log(f"checks {CHECKS['n']}, diffs {CHECKS['diff']}")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "help"
    if cmd == "up":
        up()
    elif cmd == "down":
        down()
    elif cmd == "scenario":
        scenario()
    elif cmd == "full":
        up()
        scenario()
        phase3()
        (DIR / "full.log").write_text("\n".join(LOG))
    elif cmd == "phase2":
        load()
        alt = [THEIRS, OURS]
        k = [0]

        def mine(n=1):
            for _ in range(n):
                mine_and_compare(alt[k[0] % 2])
                k[0] += 1
        phase2(mine)
        log(f"checks {CHECKS['n']}, diffs {CHECKS['diff']}")
        (DIR / "phase2.log").write_text("\n".join(LOG))
    elif cmd == "history":
        load()
        compare_history()
    elif cmd == "restart-main":
        load()
        restart_main()
    elif cmd == "restart":
        load()
        stop_node(sys.argv[2])
        start_node(sys.argv[2])
    elif cmd == "mine":
        load()
        mine_and_compare(THEIRS if (len(sys.argv) < 3 or sys.argv[2] == "theirs") else OURS)
    else:
        print(__doc__)
