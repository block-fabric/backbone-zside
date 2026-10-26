// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
//
// JSON forms of zSide types exactly as serde_json renders them in thunder-orchard's
// JSON-RPC (human-readable serde): hex hashes, base58 addresses, externally tagged
// enums, [u8; 32] as arrays of numbers where serde does that, etc.
#pragma once

#include <zside/state.h>

#include <bt/jsonrpc.h>
#include <univalue.h>

namespace zside::json {

UniValue hash(const Hash32& h);            // hex (BlockHash, Txid, MerkleRoot, ...)
UniValue btc_hash(const Hash32& h);        // display order (bitcoin::BlockHash, Txid, M6id)
UniValue bytes_array(ByteSpan b);          // serde of [u8; N] / Vec<u8>: array of numbers
UniValue address(const Address& a);
UniValue outpoint(const OutPoint& o);
UniValue content(const Content& c);
UniValue output(const Output& o);
UniValue pointed_output(const OutPoint& op, const Output& o);
UniValue spent_output(const SpentOutput& s);
UniValue pointed_spent_output(const OutPoint& op, const SpentOutput& s);
UniValue node_hash(const bt::utreexo::NodeHash& n);
UniValue proof(const bt::utreexo::Proof& p);
UniValue orchard_bundle(const OrchardBundle& b);
UniValue shielded_address(const ShieldedAddress& a);
UniValue transaction(const Transaction& t);
UniValue authorization(const Authorization& a);
UniValue authorized_transaction(const AuthorizedTransaction& t);
UniValue coinbase(const Coinbase& c);
UniValue body(const Body& b, bool verbose);
UniValue header(const Header& h);
UniValue block(const Header& h, const Body& b, bool verbose = false);
UniValue bitcoin_tx(const std::vector<bt::btc::TxOut>& outs);
UniValue withdrawal_bundle(const WithdrawalBundle& w);
UniValue withdrawal_bundle_info(const WithdrawalBundleInfo& i);

/** A request value that does not parse: jsonrpsee's -32602 "Invalid params", the cause (serde's) as data. */
struct Error : bt::jsonrpc::RpcError {
    /** `at`: the request value it is about (the server adds serde_json's position of it). */
    explicit Error(const std::string& cause, const UniValue* at = nullptr) : bt::jsonrpc::RpcError(-32602, "Invalid params", cause, at) {}
};
/** serde's Unexpected of a JSON value ("string \"x\"", "integer `5`", "sequence", ...). */
std::string serde_unexpected(const UniValue& v);
uint32_t parse_u32(const UniValue& v);
/** serde's derived Deserialize of a struct: an object with the (non-Option) `fields`, else serde's error. */
void require_struct(const UniValue& v, const char* name, std::initializer_list<const char*> fields);
Hash32 parse_hash(const UniValue& v);
Hash32 parse_btc_hash(const UniValue& v);
Address parse_address(const UniValue& v);
bt::btc::Address parse_btc_address(const UniValue& v);
OutPoint parse_outpoint(const UniValue& v);
Output parse_output(const UniValue& v);
bt::utreexo::Proof parse_proof(const UniValue& v);
OrchardBundle parse_orchard_bundle(const UniValue& v);
ShieldedAddress parse_shielded_address(const UniValue& v);
Transaction parse_transaction(const UniValue& v);
AuthorizedTransaction parse_authorized_transaction(const UniValue& v);
Header parse_header(const UniValue& v);
Body parse_body(const UniValue& v);
uint64_t parse_u64(const UniValue& v);

} // namespace zside::json
