// zSide codec/hash known answers from public eCash betanet data (slot 98).
#include "test.h"

#include <zside/net.h>
#include <zside/types.h>

#include <bt/crypto.h>

using namespace zside;

TEST(zside_empty_merkle_root)
{
    // plain-CBMT empty body: blake3(blake3(borsh(memo=[], zero outputs root)) || zero txs root),
    // the same value as the fee/size trees of Thunder/BitNames/BitAssets
    CHECK_EQ(bt::hex_encode(compute_merkle_root(Coinbase{}, {})), std::string("812c97082cde521a6128a777b45d9221259e8e3e33d6f84b7b496ef43ca6bdbb"));
}

TEST(zside_betanet_genesis)
{
    Header g;
    g.merkle_root = compute_merkle_root(Coinbase{}, {});
    // prev_main = betanet block 973,756 (the genesis BMM sits in 973,757)
    g.prev_main_hash = *bt::hash_from_rev_hex("00000000000000005809cb0d526ce6a3726b68ed6929a1038bdfc3200874c9a4");
    CHECK_EQ(bt::hex_encode(g.hash()), std::string("f87359e619a2127d9550808c7e5704828bf7e9f92e653bcac70079fa4f5712c0"));
    Writer w;
    bincode(w, g);
    Reader r(w.buf);
    CHECK(de_header(r) == g);
    CHECK(r.empty());
}

TEST(zside_limits)
{
    CHECK_EQ(body_size_limit(0), uint64_t(8 * 1024 * 1024));
    CHECK_EQ(body_sigops_limit(0), uint64_t(42800));
    CHECK_EQ(body_sigops_limit(4320), uint64_t(44512));
}

TEST(zside_network)
{
    auto m = net::magic_bytes(net::Network::Betanet);
    CHECK_EQ(bt::hex_encode(bt::ByteSpan(m.data(), 4)), std::string("8d192804"));
    CHECK_EQ(bt::hex_encode(bt::ByteSpan(net::magic_bytes(net::Network::Regtest).data(), 4)), std::string("8d192800"));
    CHECK_EQ(net::DEFAULT_PORT, 4098);
    CHECK_EQ(net::DEFAULT_RPC_PORT, 6098);
}

TEST(zside_address_forms)
{
    auto a = Address::from_base58("3zTJGK3PZDUJjjoV7HtgRBJ1Q9y5");
    REQUIRE(a.has_value());
    auto dep = a->format_for_deposit();
    CHECK(dep.rfind("s98_3zTJGK3PZDUJjjoV7HtgRBJ1Q9y5_", 0) == 0);
    CHECK(!Address::from_base58(dep).has_value()); // the s98_ form burns on deposit
    // t-shld: Bech32m over the raw 43 bytes; every byte string orchard refuses is refused
    bt::ByteArray<43> zero{};
    ShieldedAddress z{zero};
    CHECK(!ShieldedAddress::parse(z.to_string()).has_value());
    CHECK(!ShieldedAddress::parse("t-shld1qqqq").has_value());
}
