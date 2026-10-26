// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
//
// `thunder-orchard`: drop-in replacement for iwakura-rein/thunder-orchard's
// `thunder_orchard_app` (zSide, eCash slot 98). Accepts the same command-line flags
// (app/cli.rs), the same defaults (P2P 0.0.0.0:4098, RPC 127.0.0.1:6098, datadir
// <data_dir>/thunder-orchard, logs <datadir>/logs/v<version>), and
// serves the same JSON-RPC methods. There is no GUI: without --headless it runs headless.
// Our own options use the --bt- prefix so they can never collide with theirs. Unknown
// flags are reported and ignored (the orchestrator stops a daemon that fails to parse).
#include <zside/app.h>
#include <zside/appui.h>

#include <bt/agent.h>
#include <bt/frost.h>
#include <bt/fsperm.h>
#include <bt/hd.h>
#include <bt/jsonrpc.h>
#include <bt/log.h>
#include <bt/parse.h>

#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <thread>

using namespace zside;

static const char* VERSION = "0.18.1";
static const std::string OUR_VERSION = bt::agent() + " (Backbone drop-in; thunder-orchard 0.18.1 compatible)";

static std::atomic<bool> g_stop{false};
static void on_signal(int) { g_stop = true; }

static std::string default_datadir()
{
#ifdef _WIN32
    const char* app = std::getenv("APPDATA");
    return std::string(app ? app : ".") + "\\thunder-orchard";
#elif defined(__APPLE__)
    const char* home = std::getenv("HOME");
    return std::string(home ? home : ".") + "/Library/Application Support/thunder-orchard";
#else
    if (const char* x = std::getenv("XDG_DATA_HOME"); x && *x) return std::string(x) + "/thunder-orchard";
    const char* home = std::getenv("HOME");
    return std::string(home ? home : ".") + "/.local/share/thunder-orchard";
#endif
}

static bool parse_sockaddr(const std::string& s, bt::quic::SockAddr& out)
{
    auto hp = bt::split_hostport(s, std::nullopt, true);
    if (!hp) return false;
    out = {hp->first, hp->second};
    return true;
}

static void usage()
{
    std::printf(
        "Usage: thunder-orchard [OPTIONS]\n\n"
        "Options (thunder-orchard 0.18.1 compatible):\n"
        "      --add-peer <ADD_PEERS>                 Additional peers to dial on startup, as host:port\n"
        "  -d, --datadir <DATADIR>                    Data directory [default: %s]\n"
        "      --headless                             Accepted; there is no GUI\n"
        "      --log-dir <LOG_DIR>                    [default: <DATADIR>/logs/v%s]; empty disables file logs\n"
        "      --log-level-file <LOG_LEVEL_FILE>      [default: WARN]\n"
        "      --log-level <LOG_LEVEL>                [default: DEBUG]\n"
        "      --mainchain-grpc-url <URL>             [default: http://localhost:50051]\n"
        "      --mainchain-grpc-ca-cert <PEM>         Extra CA for an https mainchain URL\n"
        "      --mnemonic-seed-phrase-path <PATH>     Path to a mnemonic seed phrase\n"
        "  -n, --net-addr <NET_ADDR>                  [default: 0.0.0.0:4098]\n"
        "      --network <NETWORK>                    betanet | forknet | regtest | signet [default: betanet]\n"
        "      --network-magic <HEX>                  Override the 4-byte network magic\n"
        "  -p, --private-rpc-addr <ADDR>              [default: 127.0.0.1:6098]\n"
        "  -r, --rpc-addr <ADDR>                      [default: 127.0.0.1:6098]\n"
        "      --server-name <NAME>                   Host name for the P2P certificate (repeatable)\n"
        "      --wallet-dir <DIR>                     [default: <DATADIR>]\n"
        "  -h, --help / -V, --version\n\n"
        "Backbone options:\n"
        "      --bt-rpc-allowed-origin <ORIGIN>       Allow browser requests from this Origin (repeatable; \"*\" = any).\n"
        "                                             Default: none (their node allows any origin)\n"
        "      --bt-rpc-allowed-host <HOST>           Extra Host header name accepted by the RPC server\n"
        "      --bt-rpc-allow-external                Allow binding the unauthenticated RPC to a non-loopback address\n"
        "      --bt-no-seeds                          Do not dial the built-in seed peers\n"
        "      --bt-no-p2p                            Disable P2P networking\n"
        "      --bt-rebuild-side-tips                 Drop and rebuild the side-tips index from the mainchain\n"
        "      --bt-wallet-derivation <v0.18.1|v0.18.0>  Key derivation of an imported mnemonic: v0.18.1 = BLAKE3 (current),\n"
        "                                             v0.18.0 = HMAC-SHA512 (wallets made before 6f54f21) [default: v0.18.1]\n",
        default_datadir().c_str(), VERSION);
    std::printf("\n%s", bt::appui::usage().c_str());
}

int main(int argc, char** argv)
{
#ifndef _WIN32
    // A gRPC (TLS) or RPC peer that goes away must not kill the node with SIGPIPE: the
    // enforcer restarting did exactly that (regtest, 2026-10-22).
    std::signal(SIGPIPE, SIG_IGN);
#endif
    NodeConfig cfg;
    cfg.datadir = default_datadir();
    std::optional<std::string> log_dir, wallet_dir, mnemonic_path;
    bt::log::Level log_level = bt::log::Level::Debug, log_level_file = bt::log::Level::Warn;
    bt::quic::SockAddr rpc_addr{"127.0.0.1", net::DEFAULT_RPC_PORT}, private_rpc_addr = rpc_addr;
    bool headless = false;
    KeyDerivation variant = KeyDerivation::Blake3;
    std::vector<std::string> unknown;
    bt::jsonrpc::Options rpc_opts;
    bt::appui::AppOptions app_opts;
    for (int i = 1; i < argc; i++) {
        // Our app layer's options (--bt-app-*): beside the LayerTwo ones, never instead of one.
        {
            std::string app_err;
            if (bt::appui::take_option(app_opts, argc, argv, i, app_err)) {
                if (!app_err.empty()) {
                    std::fprintf(stderr, "error: %s\n", app_err.c_str());
                    return 2;
                }
                continue;
            }
        }
        std::string a = argv[i], val;
        bool has_eq = false;
        if (a.rfind("--", 0) == 0) {
            auto eq = a.find('=');
            if (eq != std::string::npos) {
                val = a.substr(eq + 1);
                a = a.substr(0, eq);
                has_eq = true;
            }
        } else if (a.size() > 2 && a[0] == '-' && a[1] != '-') { // -dVALUE
            val = a.substr(2);
            a = a.substr(0, 2);
            has_eq = true;
        }
        auto next = [&](std::string& out) -> bool {
            if (has_eq) {
                out = val;
                return true;
            }
            if (i + 1 < argc) {
                out = argv[++i];
                return true;
            }
            std::fprintf(stderr, "error: a value is required for '%s'\n", a.c_str());
            return false;
        };
        std::string v;
        if (a == "-h" || a == "--help") {
            usage();
            return 0;
        } else if (a == "-V" || a == "--version") {
            std::printf("thunder_orchard_app %s\n%s\n", VERSION, OUR_VERSION.c_str());
            return 0;
        } else if (a == "--add-peer") {
            if (!next(v)) return 2;
            if (!bt::split_hostport(v, net::DEFAULT_PORT)) {
                std::fprintf(stderr, "error: invalid value '%s' for '--add-peer'\n", v.c_str());
                return 2;
            }
            cfg.add_peers.push_back(v);
        } else if (a == "-d" || a == "--datadir") {
            if (!next(v)) return 2;
            cfg.datadir = v;
        } else if (a == "--headless") {
            headless = true;
        } else if (a == "--log-dir") {
            if (!next(v)) return 2;
            log_dir = v;
        } else if (a == "--log-level" || a == "--log-level-file") {
            if (!next(v)) return 2;
            auto l = bt::log::parse_level(v);
            if (!l) {
                std::fprintf(stderr, "error: invalid log level '%s'\n", v.c_str());
                return 2;
            }
            (a == "--log-level" ? log_level : log_level_file) = *l;
        } else if (a == "--mainchain-grpc-url") {
            if (!next(v)) return 2;
            cfg.mainchain_grpc_url = v;
        } else if (a == "--mainchain-grpc-ca-cert") {
            if (!next(v)) return 2;
            cfg.mainchain_grpc_ca_cert = v;
        } else if (a == "--mnemonic-seed-phrase-path") {
            if (!next(v)) return 2;
            mnemonic_path = v;
        } else if (a == "-n" || a == "--net-addr") {
            if (!next(v) || !parse_sockaddr(v, cfg.net_addr)) {
                std::fprintf(stderr, "error: invalid --net-addr\n");
                return 2;
            }
        } else if (a == "--network") {
            if (!next(v)) return 2;
            if (v == "betanet") cfg.network = net::Network::Betanet;
            else if (v == "forknet") cfg.network = net::Network::Forknet;
            else if (v == "regtest") cfg.network = net::Network::Regtest;
            else if (v == "signet") cfg.network = net::Network::Signet;
            else {
                std::fprintf(stderr, "error: invalid value '%s' for '--network'\n", v.c_str());
                return 2;
            }
        } else if (a == "--network-magic") {
            if (!next(v)) return 2;
            auto m = bt::hex_decode(v);
            if (!m || m->size() != 4) {
                std::fprintf(stderr, "error: invalid --network-magic\n");
                return 2;
            }
            cfg.magic_override = std::array<uint8_t, 4>{(*m)[0], (*m)[1], (*m)[2], (*m)[3]};
        } else if (a == "-p" || a == "--private-rpc-addr") {
            if (!next(v) || !parse_sockaddr(v, private_rpc_addr)) return 2;
        } else if (a == "-r" || a == "--rpc-addr") {
            if (!next(v) || !parse_sockaddr(v, rpc_addr)) return 2;
        } else if (a == "--server-name") {
            if (!next(v)) return 2;
            cfg.server_names.push_back(v);
        } else if (a == "--wallet-dir") {
            if (!next(v)) return 2;
            wallet_dir = v;
        } else if (a == "--bt-rpc-allowed-origin") {
            if (!next(v)) return 2;
            rpc_opts.allowed_origins.push_back(v);
        } else if (a == "--bt-rpc-allowed-host") {
            if (!next(v)) return 2;
            rpc_opts.allowed_hosts.push_back(v);
        } else if (a == "--bt-rpc-allow-external") {
            rpc_opts.allow_external = true;
        } else if (a == "--bt-no-seeds") {
            cfg.use_seeds = false;
        } else if (a == "--bt-rebuild-side-tips") {
            cfg.rebuild_side_tips = true;
        } else if (a == "--bt-no-p2p") {
            cfg.p2p = false;
        } else if (a == "--bt-wallet-derivation") {
            if (!next(v)) return 2;
            variant = v == "v0.18.0" ? KeyDerivation::Hmac : KeyDerivation::Blake3;
        } else {
            unknown.push_back(argv[i]);
        }
    }
    if (!cfg.mainchain_grpc_ca_cert.empty() && cfg.mainchain_grpc_url.rfind("https://", 0) != 0) {
        std::fprintf(stderr, "Error: --mainchain-grpc-ca-cert needs an https --mainchain-grpc-url\n");
        return 2;
    }
    std::string logs = log_dir ? *log_dir : cfg.datadir + "/logs/v" + VERSION;
    bt::log::set_console_level(log_level);
    bt::log::set_file(logs, log_level_file);
    for (auto& u : unknown) LOG_WARN("ignoring unknown argument '%s'", u.c_str());
    if (!headless) LOG_INFO("no GUI in this build; running headless");
    LOG_INFO("%s starting: datadir %s, network magic override %s, mainchain %s", OUR_VERSION.c_str(), cfg.datadir.c_str(),
             cfg.magic_override ? "yes" : "no", cfg.mainchain_grpc_url.c_str());

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);
    bt::frost::init();
    Node node(cfg);
    std::string err;
    if (!node.start(err)) {
        LOG_ERROR("startup failed: %s", err.c_str());
        return 1;
    }
    std::string wdir = wallet_dir ? *wallet_dir : cfg.datadir;
    if (!bt::fsperm::private_dir(wdir)) { // the wallet holds the seed
        LOG_ERROR("cannot create %s", wdir.c_str());
        return 1;
    }
    Wallet wallet(wdir + "/backbone-wallet.sqlite", node, variant);
    if (mnemonic_path) {
        std::ifstream f(*mnemonic_path);
        std::string m((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        try {
            wallet.set_seed_from_mnemonic(m);
        } catch (const std::exception& e) {
            LOG_ERROR("mnemonic: %s", e.what());
            return 1;
        }
    }
    App app(node, wallet);
    app.on_stop = [] { g_stop = true; };
    bt::jsonrpc::Server pub, priv;
    pub.options = priv.options = rpc_opts;
    if (private_rpc_addr == rpc_addr) {
        register_rpc(pub, app, true, true);
        if (!pub.listen(rpc_addr.ip, rpc_addr.port, err)) {
            LOG_ERROR("%s", err.c_str());
            return 1;
        }
    } else {
        register_rpc(pub, app, true, false);
        register_rpc(priv, app, false, true);
        if (!pub.listen(rpc_addr.ip, rpc_addr.port, err) || !priv.listen(private_rpc_addr.ip, private_rpc_addr.port, err)) {
            LOG_ERROR("%s", err.c_str());
            return 1;
        }
    }
    LOG_INFO("JSON-RPC on %s (%zu methods)", rpc_addr.to_string().c_str(), pub.methods().size());
    // Our app layer (--bt-app-rpc-port): a server of its own; the LayerTwo servers above are the same with or without it.
    std::unique_ptr<AppLayer> app_layer;
    if (app_opts.enabled) {
        const char* names[] = {"betanet", "forknet", "regtest", "signet"};
        app_layer = std::make_unique<AppLayer>(app, names[static_cast<int>(cfg.network)], cfg.datadir, app_opts);
        if (!app_layer->start(err)) {
            LOG_ERROR("app RPC: %s", err.c_str());
            pub.stop();
            priv.stop();
            node.stop();
            return 1;
        }
    }
    if (app_opts.exit_with_stdin) {
        // The app that started this node holds our standard input: when it goes (even killed), we stop.
        std::thread([] {
            char buf[64];
            while (std::fread(buf, 1, sizeof(buf), stdin) > 0) {
            }
            LOG_INFO("standard input closed: stopping");
            g_stop = true;
        }).detach();
    }
    while (!g_stop) std::this_thread::sleep_for(std::chrono::milliseconds(200));
    LOG_INFO("shutting down");
    if (app_layer) app_layer->stop();
    pub.stop();
    priv.stop();
    node.stop();
    return 0;
}
