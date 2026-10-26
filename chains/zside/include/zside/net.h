// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
//
// zSide P2P messages (thunder-rust's message set; thunder-orchard b225827 lib/net/peer/message.rs)
// and lib/net/peer/mod.rs (PeerState, TipInfo).
#pragma once

#include <zside/types.h>

#include <array>
#include <set>

namespace zside::net {

enum class Network : uint8_t { Betanet, Forknet, Regtest, Signet };

/** message.rs:19-37: "ZSIDE" Baudot prefix 8d 19 28, low bits of byte 4 = network (betanet 04). */
std::array<uint8_t, 4> magic_bytes(Network n);
/** types/net.rs: DEFAULT_PORT = 4000 + slot */
constexpr uint16_t DEFAULT_PORT = 4098;
constexpr uint16_t DEFAULT_RPC_PORT = 6098;

struct Version {
    uint64_t major = 0, minor = 18, patch = 1;
};

struct Tip {
    Hash32 block_hash;
    Hash32 main_block_hash; // internal order
    bool operator==(const Tip&) const = default;
};

struct TipInfo {
    uint32_t block_height = 0;
    Tip tip;
    Hash32 total_work_be; // bitcoin::Work, serde = 32 big-endian bytes
};

struct PeerState {
    std::optional<TipInfo> tip_info;
    Version version;
};

// Request message tags (RequestMessageRef::Repr): Heartbeat, GetBlock, GetHeaders, PushTransaction
struct Request {
    enum Kind : uint32_t { Heartbeat = 0, GetBlock = 1, GetHeaders = 2, PushTransaction = 3 } kind = Heartbeat;
    PeerState heartbeat;
    Hash32 block_hash;            // GetBlock
    std::vector<Hash32> start;    // GetHeaders (HashSet: any order on the wire)
    Hash32 end;                   // GetHeaders
    AuthorizedTransaction tx;     // PushTransaction
};

struct Response {
    enum Kind : uint32_t { Block = 0, Headers = 1, NoBlock = 2, NoHeader = 3, TransactionAccepted = 4, TransactionRejected = 5 } kind = NoBlock;
    zside::Block block;
    std::vector<Header> headers;
    Hash32 hash; // NoBlock / NoHeader block hash; tx accepted/rejected txid
};

Bytes encode(const Request& r);
Request decode_request(ByteSpan b);
Bytes encode(const Response& r);
Response decode_response(ByteSpan b);

/** Response read limits (message.rs:61-125). */
constexpr size_t READ_REQUEST_LIMIT = 100 * 1024;
constexpr size_t BLOCK_RESPONSE_LIMIT = 10 * 1024 * 1024;
inline size_t headers_response_limit(uint32_t height)
{
    uint64_t l = (uint64_t(height) + 1) * 2048;
    return size_t(std::min<uint64_t>(l, 64ull * 1024 * 1024));
}
constexpr size_t TX_ACK_LIMIT = 256;

} // namespace zside::net
