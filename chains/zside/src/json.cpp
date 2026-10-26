// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
#include <zside/json.h>

#include <bt/parse.h>

#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstdlib>

namespace zside::json {

static UniValue obj() { return UniValue(UniValue::VOBJ); }
static UniValue arr() { return UniValue(UniValue::VARR); }

UniValue hash(const Hash32& h) { return UniValue(bt::hex_encode(h)); }
UniValue btc_hash(const Hash32& h) { return UniValue(bt::hex_encode_rev(h.span())); }
UniValue bytes_array(ByteSpan b)
{
    UniValue a = arr();
    for (uint8_t x : b) a.push_back(UniValue(int(x)));
    return a;
}
UniValue address(const Address& a) { return UniValue(a.to_base58()); }

UniValue outpoint(const OutPoint& o)
{
    UniValue r = obj();
    if (o.kind == OutPoint::Deposit) {
        r.pushKV("Deposit", bt::hex_encode_rev(o.txid.span()) + ":" + std::to_string(o.vout));
        return r;
    }
    UniValue inner = obj();
    inner.pushKV("txid", hash(o.txid));
    inner.pushKV("vout", UniValue(uint64_t(o.vout)));
    r.pushKV(o.kind == OutPoint::Regular ? "Regular" : "Coinbase", inner);
    return r;
}

UniValue content(const Content& c)
{
    UniValue r = obj();
    if (c.kind == Content::Value) {
        r.pushKV("Value", UniValue(c.value));
    } else {
        UniValue w = obj();
        // OutputContent's serde is IfIsHumanReadable<FromInto<DefaultRepr>, ...>: JSON (human readable)
        // takes DefaultRepr, whose fields are "value" and "main_fee" (amounts in sats).
        w.pushKV("value", UniValue(c.value));
        w.pushKV("main_fee", UniValue(c.main_fee));
        w.pushKV("main_address", c.main_address.to_string());
        r.pushKV("Withdrawal", w);
    }
    return r;
}

UniValue output(const Output& o)
{
    UniValue r = obj();
    r.pushKV("address", address(o.address));
    r.pushKV("content", content(o.content));
    return r;
}

UniValue pointed_output(const OutPoint& op, const Output& o)
{
    UniValue r = obj();
    r.pushKV("outpoint", outpoint(op));
    r.pushKV("output", output(o));
    return r;
}

UniValue spent_output(const SpentOutput& s)
{
    UniValue r = obj();
    r.pushKV("output", output(s.output));
    UniValue ip = obj();
    if (s.inpoint.kind == InPoint::Regular) {
        UniValue i = obj();
        i.pushKV("txid", hash(s.inpoint.id));
        i.pushKV("vin", UniValue(uint64_t(s.inpoint.vin)));
        ip.pushKV("Regular", i);
    } else {
        UniValue i = obj();
        i.pushKV("m6id", btc_hash(s.inpoint.id));
        ip.pushKV("Withdrawal", i);
    }
    r.pushKV("inpoint", ip);
    return r;
}

UniValue pointed_spent_output(const OutPoint& op, const SpentOutput& s)
{
    UniValue r = obj();
    r.pushKV("outpoint", outpoint(op));
    r.pushKV("output", spent_output(s));
    return r;
}

UniValue node_hash(const bt::utreexo::NodeHash& n)
{
    if (n.tag == bt::utreexo::NodeHash::Empty) return UniValue("Empty");
    if (n.tag == bt::utreexo::NodeHash::Placeholder) return UniValue("Placeholder");
    UniValue r = obj();
    r.pushKV("Some", bytes_array(n.h.span()));
    return r;
}

UniValue proof(const bt::utreexo::Proof& p)
{
    UniValue r = obj();
    UniValue t = arr(), h = arr();
    for (auto x : p.targets) t.push_back(UniValue(x));
    for (auto& x : p.hashes) h.push_back(node_hash(x));
    r.pushKV("targets", t);
    r.pushKV("hashes", h);
    return r;
}

// types/orchard/mod.rs BundleRepr / ActionRepr / AuthorizedRepr, human-readable serde:
// nullifier, rk, cmx, cv_net and anchor through const_hex::serde ("0x" + hex); epk, the
// ciphertexts, the proof and the signatures through serde_with's Hex (plain hex); flags a
// number, balance i64 sats.
UniValue orchard_bundle(const OrchardBundle& b)
{
    UniValue r = obj();
    UniValue acts = arr();
    for (auto& a : b.actions) {
        UniValue o = obj();
        o.pushKV("nullifier", "0x" + bt::hex_encode(a.nf));
        o.pushKV("rk", "0x" + bt::hex_encode(a.rk));
        o.pushKV("cmx", "0x" + bt::hex_encode(a.cmx));
        UniValue e = obj();
        e.pushKV("epk_bytes", bt::hex_encode(a.epk));
        e.pushKV("enc_ciphertext", bt::hex_encode(a.enc));
        e.pushKV("out_ciphertext", bt::hex_encode(a.out));
        o.pushKV("encrypted_note", e);
        o.pushKV("cv_net", "0x" + bt::hex_encode(a.cv));
        o.pushKV("authorization", bt::hex_encode(a.spend_auth_sig));
        acts.push_back(o);
    }
    r.pushKV("actions", acts);
    r.pushKV("flags", UniValue(uint64_t(b.flags)));
    r.pushKV("balance", UniValue(b.value_balance));
    r.pushKV("anchor", "0x" + bt::hex_encode(b.anchor));
    UniValue au = obj();
    au.pushKV("proof", bt::hex_encode(b.proof));
    au.pushKV("binding_signature", bt::hex_encode(b.binding_sig));
    r.pushKV("authorization", au);
    return r;
}

UniValue shielded_address(const ShieldedAddress& a) { return UniValue(a.to_string()); }

static void tx_fields(UniValue& r, const Transaction& t)
{
    UniValue ins = arr();
    for (auto& [op, h] : t.inputs) {
        UniValue pair = arr();
        pair.push_back(outpoint(op));
        pair.push_back(bytes_array(h.span())); // Hash = [u8; 32]
        ins.push_back(pair);
    }
    r.pushKV("inputs", ins);
    r.pushKV("proof", proof(t.proof));
    r.pushKV("orchard_bundle", t.orchard_bundle ? orchard_bundle(*t.orchard_bundle) : UniValue());
    UniValue outs = arr();
    for (auto& o : t.outputs) outs.push_back(output(o));
    r.pushKV("outputs", outs);
}

UniValue transaction(const Transaction& t)
{
    UniValue r = obj();
    tx_fields(r, t);
    return r;
}

UniValue authorization(const Authorization& a)
{
    UniValue r = obj();
    r.pushKV("verifying_key", bt::hex_encode(a.verifying_key));
    bt::Bytes sig(a.signature.R.begin(), a.signature.R.end());
    sig.insert(sig.end(), a.signature.z.begin(), a.signature.z.end());
    r.pushKV("signature", bt::hex_encode(sig));
    return r;
}

UniValue authorized_transaction(const AuthorizedTransaction& t)
{
    UniValue r = obj();
    r.pushKV("transaction", transaction(t.transaction));
    UniValue a = arr();
    for (auto& x : t.authorizations) a.push_back(authorization(x));
    r.pushKV("authorizations", a);
    return r;
}

UniValue coinbase(const Coinbase& c)
{
    UniValue r = obj();
    r.pushKV("memo", bytes_array(c.memo));
    UniValue o = arr();
    for (auto& x : c.outputs) o.push_back(output(x));
    r.pushKV("outputs", o);
    return r;
}

UniValue body(const Body& b, bool verbose)
{
    UniValue r = obj();
    r.pushKV("coinbase", coinbase(b.coinbase));
    UniValue txs = arr();
    for (auto& t : b.transactions) {
        UniValue tv = obj();
        tx_fields(tv, t);
        if (verbose) tv.pushKV("canonical_bytes", "0x" + bt::hex_encode(t.canonical_bytes())); // #[serde(with = "const_hex")]: 0x-prefixed
        txs.push_back(tv);
    }
    r.pushKV("transactions", txs);
    UniValue a = arr();
    for (auto& x : b.authorizations) a.push_back(authorization(x));
    r.pushKV("authorizations", a);
    return r;
}

UniValue header(const Header& h)
{
    UniValue r = obj();
    r.pushKV("merkle_root", hash(h.merkle_root));
    r.pushKV("prev_side_hash", h.prev_side_hash ? hash(*h.prev_side_hash) : UniValue());
    r.pushKV("prev_main_hash", btc_hash(h.prev_main_hash));
    UniValue roots = arr();
    for (auto& x : h.roots) roots.push_back(node_hash(x)); // thunder-orchard: plain serde (no DisplayFromStr)
    r.pushKV("roots", roots);
    return r;
}

UniValue block(const Header& h, const Body& b, bool verbose)
{
    UniValue r = obj();
    r.pushKV("header", header(h));
    r.pushKV("body", body(b, verbose));
    return r;
}

UniValue bitcoin_tx(const std::vector<bt::btc::TxOut>& outs)
{
    UniValue r = obj();
    r.pushKV("version", 2);
    r.pushKV("lock_time", 0);
    r.pushKV("input", arr());
    UniValue o = arr();
    for (auto& x : outs) {
        UniValue t = obj();
        t.pushKV("value", UniValue(x.value));
        t.pushKV("script_pubkey", bt::hex_encode(x.script_pubkey));
        o.push_back(t);
    }
    r.pushKV("output", o);
    return r;
}

UniValue withdrawal_bundle(const WithdrawalBundle& w)
{
    UniValue r = obj();
    UniValue su = arr();
    for (auto& [op, o] : w.spend_utxos) {
        UniValue p = arr();
        p.push_back(outpoint(op));
        p.push_back(output(o));
        su.push_back(p);
    }
    r.pushKV("spend_utxos", su);
    r.pushKV("tx", bitcoin_tx(w.outputs));
    return r;
}

UniValue withdrawal_bundle_info(const WithdrawalBundleInfo& i)
{
    if (i.kind == WithdrawalBundleInfo::Unknown) return UniValue("Unknown");
    UniValue r = obj();
    if (i.kind == WithdrawalBundleInfo::Known) {
        r.pushKV("Known", withdrawal_bundle(i.bundle));
    } else {
        // serde_json cannot serialize a map with OutPoint keys; theirs fails here
        throw std::runtime_error("key must be a string");
    }
    return r;
}

// ------------------------------------------------------------------ parsing
std::string serde_unexpected(const UniValue& v)
{
    if (v.isNull()) return "null";
    if (v.isBool()) return std::string("boolean `") + (v.get_bool() ? "true" : "false") + "`";
    if (v.isArray()) return "sequence";
    if (v.isObject()) return "map";
    if (v.isStr()) {
        // Rust's Debug of a str.
        std::string r = "string \"";
        for (unsigned char ch : v.get_str()) {
            if (ch == '"') r += "\\\"";
            else if (ch == '\\') r += "\\\\";
            else if (ch == '\n') r += "\\n";
            else if (ch == '\t') r += "\\t";
            else if (ch == '\r') r += "\\r";
            else if (ch < 0x20 || ch == 0x7f) {
                char b[16];
                std::snprintf(b, sizeof(b), "\\u{%x}", ch);
                r += b;
            } else r += char(ch);
        }
        return r + "\"";
    }
    const std::string& s = v.getValStr();
    if (s.find_first_of(".eE") != std::string::npos) {
        // serde_json reads it as an f64; Rust's Display of an f64: the shortest form, no ".0" when integral.
        double d = std::strtod(s.c_str(), nullptr);
        char b[64];
        for (int prec = 1; prec <= 17; prec++) {
            std::snprintf(b, sizeof(b), "%.*g", prec, d);
            if (std::strtod(b, nullptr) == d) break;
        }
        std::string f = b;
        if (f.find('e') != std::string::npos) {
            // Rust prints the digits out in full (no exponent) for f64 Display.
            std::snprintf(b, sizeof(b), "%.0f", d);
            if (d == std::floor(d)) f = b;
        }
        return "floating point `" + f + "`";
    }
    return "integer `" + s + "`";
}

static uint64_t parse_uint(const UniValue& v, uint64_t max, const char* type)
{
    if (!v.isNum()) throw Error("invalid type: " + serde_unexpected(v) + ", expected " + type, &v);
    const std::string& s = v.getValStr();
    if (s.find_first_of(".eE") != std::string::npos) throw Error("invalid type: " + serde_unexpected(v) + ", expected " + type, &v);
    auto x = s.empty() || s[0] == '-' ? std::nullopt : bt::parse_u64(s);
    if (!x || *x > max) throw Error("invalid value: " + serde_unexpected(v) + ", expected " + type, &v);
    return *x;
}

uint64_t parse_u64(const UniValue& v) { return parse_uint(v, UINT64_MAX, "u64"); }
uint32_t parse_u32(const UniValue& v) { return uint32_t(parse_uint(v, UINT32_MAX, "u32")); }

// const-hex's decode_to_array, which the 32-byte hashes' serde uses: an optional 0x prefix, then an odd length,
// the length, the first character that is not hex, in its words.
static std::string rust_char_debug(unsigned char b)
{
    switch (b) {
    case 0: return "'\\0'";
    case '\t': return "'\\t'";
    case '\n': return "'\\n'";
    case '\r': return "'\\r'";
    case '\'': return "'\\''";
    case '\\': return "'\\\\'";
    }
    char buf[16];
    if (b < 0x20 || b == 0x7f) {
        std::snprintf(buf, sizeof(buf), "'\\u{%x}'", b);
        return buf;
    }
    if (b < 0x80) return std::string("'") + char(b) + "'";
    // const-hex reports the byte as a char (latin-1), whatever the UTF-8.
    return std::string("'") + char(0xc0 | (b >> 6)) + char(0x80 | (b & 0x3f)) + "'";
}

Hash32 parse_hash(const UniValue& v)
{
    if (!v.isStr()) throw Error("expected a hex string", &v);
    std::string s = v.get_str();
    if (s.rfind("0x", 0) == 0) s = s.substr(2);
    if (s.size() % 2) throw Error("odd number of digits", &v);
    if (s.size() != 64) throw Error("invalid string length", &v);
    for (size_t i = 0; i < s.size(); i++) {
        if (!std::isxdigit((unsigned char)s[i])) throw Error("invalid character " + rust_char_debug((unsigned char)s[i]) + " at position " + std::to_string(i), &v);
    }
    auto h = bt::hex_to_array<32>(s);
    if (!h) throw Error("invalid hash", &v);
    return *h;
}
Hash32 parse_btc_hash(const UniValue& v)
{
    if (!v.isStr()) throw Error("expected a hex string", &v);
    auto h = bt::hash_from_rev_hex(v.get_str());
    if (!h) throw Error("invalid hash", &v);
    return *h;
}
Address parse_address(const UniValue& v)
{
    if (!v.isStr()) throw Error("expected an address string", &v);
    // thunder_types::ParseAddress: "bs58 error", or "wrong address length {n} != 20".
    auto d = bt::base58_decode(v.get_str());
    if (!d) throw Error("bs58 error", &v);
    if (d->size() != 20) throw Error("wrong address length " + std::to_string(d->size()) + " != 20", &v);
    auto a = Address::from_base58(v.get_str());
    if (!a) throw Error("invalid address", &v);
    return *a;
}
bt::btc::Address parse_btc_address(const UniValue& v)
{
    if (!v.isStr()) throw Error("expected a bitcoin address", &v);
    auto a = bt::btc::Address::parse(v.get_str());
    // rust-bitcoin 0.32 falls back to base58 when bech32 does not decode: "base58 error".
    if (!a) throw Error(bt::base58check_decode(v.get_str()) ? "invalid bitcoin address" : "base58 error", &v);
    return *a;
}

static Hash32 parse_byte_array32(const UniValue& v)
{
    if (v.isStr()) return parse_hash(v); // tolerate hex
    if (!v.isArray() || v.size() != 32) throw Error("expected 32 bytes", &v);
    Hash32 h;
    for (size_t i = 0; i < 32; i++) {
        uint64_t b = parse_u64(v[i]);
        if (b > 255) throw Error("byte out of range", &v);
        h[i] = uint8_t(b);
    }
    return h;
}

OutPoint parse_outpoint(const UniValue& v)
{
    if (!v.isObject() || v.size() != 1) throw Error("invalid OutPoint", &v);
    const std::string& k = v.getKeys()[0];
    const UniValue& x = v.getValues()[0];
    OutPoint o;
    if (k == "Deposit") {
        if (!x.isStr()) throw Error("invalid deposit outpoint", &v);
        auto s = x.get_str();
        auto c = s.rfind(':');
        if (c == std::string::npos) throw Error("invalid deposit outpoint", &v);
        o.kind = OutPoint::Deposit;
        o.txid = parse_btc_hash(UniValue(s.substr(0, c)));
        auto vout = bt::parse_u64(s.substr(c + 1));
        if (!vout || *vout > UINT32_MAX) throw Error("invalid deposit outpoint", &v);
        o.vout = uint32_t(*vout);
        return o;
    }
    if (k != "Regular" && k != "Coinbase") throw Error("invalid OutPoint variant", &v);
    o.kind = k == "Regular" ? OutPoint::Regular : OutPoint::Coinbase;
    o.txid = parse_hash(x["txid"]);
    uint64_t vout = parse_u64(x["vout"]);
    if (vout > UINT32_MAX) throw Error("vout out of range", &v);
    o.vout = uint32_t(vout);
    return o;
}

Output parse_output(const UniValue& v)
{
    Output o;
    o.address = parse_address(v["address"]);
    const UniValue& c = v["content"];
    if (!c.isObject() || c.size() != 1) throw Error("invalid content", &v);
    const std::string& k = c.getKeys()[0];
    const UniValue& x = c.getValues()[0];
    if (k == "Value") {
        o.content.kind = Content::Value;
        o.content.value = parse_u64(x);
    } else if (k == "Withdrawal") {
        o.content.kind = Content::Withdrawal;
        o.content.value = parse_u64(x["value"]);
        o.content.main_fee = parse_u64(x["main_fee"]);
        o.content.main_address = parse_btc_address(x["main_address"]);
    } else {
        throw Error("invalid content variant", &v);
    }
    return o;
}

static bt::utreexo::NodeHash parse_node_hash(const UniValue& v)
{
    if (v.isStr()) {
        if (v.get_str() == "Empty") return bt::utreexo::NodeHash::empty();
        if (v.get_str() == "Placeholder") return bt::utreexo::NodeHash{bt::utreexo::NodeHash::Placeholder, {}};
        throw Error("invalid node hash", &v);
    }
    if (!v.isObject() || v.size() != 1 || v.getKeys()[0] != "Some") throw Error("invalid node hash", &v);
    return bt::utreexo::NodeHash::some(parse_byte_array32(v.getValues()[0]));
}

bt::utreexo::Proof parse_proof(const UniValue& v)
{
    bt::utreexo::Proof p;
    if (v.isNull()) return p;
    for (auto& t : v["targets"].getValues()) p.targets.push_back(parse_u64(t));
    for (auto& h : v["hashes"].getValues()) p.hashes.push_back(parse_node_hash(h));
    return p;
}

static std::optional<int64_t> parse_i64_str(const std::string& s)
{
    bool neg = !s.empty() && s[0] == '-';
    auto m = bt::parse_u64(neg ? s.substr(1) : s);
    if (!m) return std::nullopt;
    if (neg) {
        if (*m > uint64_t(INT64_MAX) + 1) return std::nullopt;
        return int64_t(uint64_t(0) - *m);
    }
    if (*m > uint64_t(INT64_MAX)) return std::nullopt;
    return int64_t(*m);
}

template <size_t N>
static bt::ByteArray<N> hex_n(const UniValue& v)
{
    if (!v.isStr()) throw Error("invalid type: " + serde_unexpected(v) + ", expected a hex string", &v);
    std::string s = v.get_str();
    if (s.rfind("0x", 0) == 0) s = s.substr(2);
    auto b = bt::hex_decode(s);
    if (!b || b->size() != N) throw Error("invalid length " + std::to_string(b ? b->size() : 0) + ", expected an array of length " + std::to_string(N), &v);
    return bt::ByteArray<N>::from_span(*b);
}

OrchardBundle parse_orchard_bundle(const UniValue& v)
{
    require_struct(v, "BundleRepr", {"actions", "flags", "balance", "anchor", "authorization"});
    OrchardBundle b;
    if (!v["actions"].isArray() || v["actions"].empty()) throw Error("Non-Empty vector is empty", &v);
    for (auto& a : v["actions"].getValues()) {
        require_struct(a, "ActionRepr", {"nullifier", "rk", "cmx", "encrypted_note", "cv_net", "authorization"});
        OrchardAction x;
        x.nf = hex_n<32>(a["nullifier"]);
        x.rk = hex_n<32>(a["rk"]);
        x.cmx = hex_n<32>(a["cmx"]);
        const UniValue& e = a["encrypted_note"];
        require_struct(e, "TransmittedNoteCiphertextRepr", {"epk_bytes", "enc_ciphertext", "out_ciphertext"});
        x.epk = hex_n<32>(e["epk_bytes"]);
        x.enc = hex_n<580>(e["enc_ciphertext"]);
        x.out = hex_n<80>(e["out_ciphertext"]);
        x.cv = hex_n<32>(a["cv_net"]);
        x.spend_auth_sig = hex_n<64>(a["authorization"]);
        b.actions.push_back(x);
    }
    uint64_t f = parse_u64(v["flags"]);
    if (f > 255) throw Error("invalid value: " + serde_unexpected(v["flags"]) + ", expected u8", &v["flags"]);
    b.flags = uint8_t(f);
    const UniValue& bal = v["balance"];
    auto bv = bal.isNum() ? parse_i64_str(bal.getValStr()) : std::nullopt;
    if (!bv) throw Error("invalid type: " + serde_unexpected(bal) + ", expected i64", &bal);
    b.value_balance = *bv;
    b.anchor = hex_n<32>(v["anchor"]);
    const UniValue& au = v["authorization"];
    require_struct(au, "AuthorizedRepr", {"proof", "binding_signature"});
    auto pr = au["proof"].isStr() ? bt::hex_decode(au["proof"].get_str().rfind("0x", 0) == 0 ? au["proof"].get_str().substr(2) : au["proof"].get_str()) : std::nullopt;
    if (!pr) throw Error("invalid proof hex", &au["proof"]);
    b.proof = *pr;
    b.binding_sig = hex_n<64>(au["binding_signature"]);
    if (!orchard_bundle_decodes(b)) throw Error("invalid orchard bundle", &v);
    return b;
}

ShieldedAddress parse_shielded_address(const UniValue& v)
{
    if (!v.isStr()) throw Error("invalid type: " + serde_unexpected(v) + ", expected a borrowed string", &v);
    auto a = ShieldedAddress::parse(v.get_str());
    if (!a) throw Error("invalid shielded address", &v);
    return *a;
}

void require_struct(const UniValue& v, const char* name, std::initializer_list<const char*> fields)
{
    // serde's derived Deserialize: a map, then each non-Option field present (the first one missing named).
    if (!v.isObject()) throw Error("invalid type: " + serde_unexpected(v) + ", expected struct " + name, &v);
    for (const char* f : fields)
        if (!v.exists(f)) throw Error(std::string("missing field `") + f + "`", &v);
}

Transaction parse_transaction(const UniValue& v)
{
    require_struct(v, "Transaction", {"inputs", "proof", "outputs"});
    Transaction t;
    for (auto& in : v["inputs"].getValues()) {
        if (!in.isArray() || in.size() != 2) throw Error("invalid input", &v);
        t.inputs.emplace_back(parse_outpoint(in[0]), parse_byte_array32(in[1]));
    }
    t.proof = parse_proof(v["proof"]);
    if (v.exists("orchard_bundle") && !v["orchard_bundle"].isNull()) t.orchard_bundle = parse_orchard_bundle(v["orchard_bundle"]);
    for (auto& o : v["outputs"].getValues()) t.outputs.push_back(parse_output(o));
    return t;
}

static Authorization parse_authorization(const UniValue& v)
{
    Authorization a;
    auto vk = bt::hex_to_array<32>(v["verifying_key"].getValStr());
    auto sig = bt::hex_decode(v["signature"].getValStr());
    if (!vk || !sig || sig->size() != 64) throw Error("invalid authorization", &v);
    a.verifying_key = *vk;
    std::memcpy(a.signature.R.data(), sig->data(), 32);
    std::memcpy(a.signature.z.data(), sig->data() + 32, 32);
    if (!bt::frost::valid_element(a.verifying_key) || !bt::frost::valid_element(a.signature.R) || !bt::frost::canonical_scalar(a.signature.z))
        throw Error("invalid authorization encoding", &v);
    return a;
}

AuthorizedTransaction parse_authorized_transaction(const UniValue& v)
{
    require_struct(v, "Authorized", {"transaction", "authorizations"});
    AuthorizedTransaction t;
    t.transaction = parse_transaction(v["transaction"]);
    for (auto& a : v["authorizations"].getValues()) t.authorizations.push_back(parse_authorization(a));
    return t;
}

Header parse_header(const UniValue& v)
{
    require_struct(v, "Header", {"merkle_root", "prev_main_hash", "roots"});
    Header h;
    h.merkle_root = parse_hash(v["merkle_root"]);
    if (!v["prev_side_hash"].isNull()) h.prev_side_hash = parse_hash(v["prev_side_hash"]);
    h.prev_main_hash = parse_btc_hash(v["prev_main_hash"]);
    for (auto& r : v["roots"].getValues()) h.roots.push_back(parse_node_hash(r));
    return h;
}

Body parse_body(const UniValue& v)
{
    require_struct(v, "Body", {"coinbase", "transactions", "authorizations"});
    Body b;
    const UniValue& cb = v["coinbase"];
    for (auto& m : cb["memo"].getValues()) {
        uint64_t x = parse_u64(m);
        if (x > 255) throw Error("memo byte out of range", &v);
        b.coinbase.memo.push_back(uint8_t(x));
    }
    for (auto& o : cb["outputs"].getValues()) b.coinbase.outputs.push_back(parse_output(o));
    for (auto& t : v["transactions"].getValues()) b.transactions.push_back(parse_transaction(t));
    for (auto& a : v["authorizations"].getValues()) b.authorizations.push_back(parse_authorization(a));
    return b;
}

} // namespace zside::json
