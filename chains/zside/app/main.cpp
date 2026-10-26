// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
//
// zside-app: zSide with our app's interface (doc/app.md). The node is `thunder-orchard` (LayerTwo's name), next to the
// app, unchanged: the app runs it as a child and talks to its app RPC; its LayerTwo RPC, P2P and consensus are the
// drop-in's own. Its data folder by default is the node's own (<data_dir>/thunder-orchard).
#include <bt/desktop/app.h>

#include <app_manifest.h>

int main(int argc, char** argv)
{
    bt::desktop::ChainSpec spec;
    spec.name = app_manifest::NAME;
    spec.stem = app_manifest::STEM;
    spec.program = app_manifest::PROGRAM;
    spec.datadir_name = app_manifest::DATADIR_NAME;
    spec.address_flags = app_manifest::ADDRESS_FLAGS;
    spec.version = std::string{app_manifest::VERSION} + " (thunder-orchard 0.18.1 compatible)";
    spec.networks = app_manifest::NETWORKS;
    spec.rpc_port = app_manifest::RPC_PORT;
    spec.p2p_port = app_manifest::P2P_PORT;
    spec.mainchain_url_flag = app_manifest::MAINCHAIN_URL_FLAG;
    spec.whitelist = app_manifest::WHITELIST;
    spec.node_host_methods = app_manifest::HOST;
    spec.bugreport = "https://github.com/block-fabric/backbone-zside/issues";
    return bt::desktop::Main(argc, argv, spec);
}
