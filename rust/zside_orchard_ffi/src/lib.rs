//! zSide drop-in: the reference Orchard crates behind a C ABI.
//!
//! Everything cryptographic that zSide's consensus and wallet need comes from the exact crates
//! thunder-orchard v0.18.1 (b225827) links: orchard 0.14.0 (FixedPostNu6_2 circuit,
//! `VerifyingKey::build()`), halo2_proofs 0.3.2, incrementalmerkletree 0.8.2, reddsa 0.5.1.
//! The C++ node does every byte format (bincode wire, borsh hashing, txid) itself and hands the
//! raw fields here. Each function mirrors one step of thunder-orchard's code, cited by
//! `types/orchard/mod.rs:<line>` / `types/authorization.rs:<line>` at b225827.
//!
//! Action layout used across the ABI (884 bytes, one per action):
//!   nf 32 | rk 32 | cmx 32 | epk 32 | enc 580 | out 80 | cv_net 32 | spend_auth_sig 64
//! Note layout (115 bytes): recipient 43 | value u64 LE | rho 32 | rseed 32
#![allow(clippy::missing_safety_doc)]

use std::sync::LazyLock;

use incrementalmerkletree::{frontier, Hashable, Level};
use nonempty::NonEmpty;
use orchard::{
    builder::{Builder, BundleType, InProgress, Unauthorized, Unproven},
    bundle::{Authorized, Flags, ProofSizeEnforcement},
    circuit::{ProvingKey, VerifyingKey},
    keys::{FullViewingKey, OutgoingViewingKey, PreparedIncomingViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    note::{ExtractedNoteCommitment, Nullifier, RandomSeed, Rho, TransmittedNoteCiphertext},
    primitives::redpallas::{self, Binding, SpendAuth},
    tree::{Anchor, MerkleHashOrchard, MerklePath},
    value::{NoteValue, ValueCommitment},
    Action, Address, Bundle, Note, Proof,
};
use rand_core::{OsRng, RngCore};

pub const ACTION_LEN: usize = 884;
pub const NOTE_LEN: usize = 115;
const DEPTH: u8 = 32; // orchard::NOTE_COMMITMENT_TREE_DEPTH

/// types/orchard/mod.rs:1440-1444 (`ProvingKey::build`, `VerifyingKey::build` = FixedPostNu6_2).
static VK: LazyLock<VerifyingKey> = LazyLock::new(VerifyingKey::build);
static PK: LazyLock<ProvingKey> = LazyLock::new(ProvingKey::build);

pub struct ZsBundle(Bundle<Authorized, i64>);
pub struct ZsBuilder {
    inner: Option<Builder>,
    ovk: Option<OutgoingViewingKey>,
}
pub struct ZsUnsigned(Bundle<InProgress<Proof, Unauthorized>, i64>);

unsafe fn arr<const N: usize>(p: *const u8) -> [u8; N] {
    let mut a = [0u8; N];
    a.copy_from_slice(std::slice::from_raw_parts(p, N));
    a
}

fn buffer_out(v: Vec<u8>, out: *mut *mut u8, out_len: *mut usize) {
    let b = v.into_boxed_slice();
    unsafe {
        *out_len = b.len();
        *out = Box::into_raw(b) as *mut u8;
    }
}

#[no_mangle]
pub unsafe extern "C" fn zs_buffer_free(p: *mut u8, len: usize) {
    if !p.is_null() {
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(p, len)));
    }
}

#[no_mangle]
pub extern "C" fn zs_init_verifier() {
    LazyLock::force(&VK);
}

#[no_mangle]
pub extern "C" fn zs_init_prover() {
    LazyLock::force(&PK);
}

/// One action's parts as their serde Deserialize checks them (mod.rs:131-153 Nullifier,
/// :206-227 rk, :336-364 cmx, :557-584 cv_net; Signature<SpendAuth> from 64 bytes is
/// infallible), then `orchard::Action::from_parts` (mod.rs:856-874: identity rk, and in orchard
/// 0.14 an invalid or identity epk, are refused).
unsafe fn parse_action(a: &[u8]) -> Option<Action<redpallas::Signature<SpendAuth>>> {
    let nf = Option::<Nullifier>::from(Nullifier::from_bytes(&a[0..32].try_into().unwrap()))?;
    let rk_bytes: [u8; 32] = a[32..64].try_into().unwrap();
    let rk = redpallas::VerificationKey::<SpendAuth>::try_from(rk_bytes).ok()?;
    let cmx = Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&a[64..96].try_into().unwrap()))?;
    let enc = TransmittedNoteCiphertext {
        epk_bytes: a[96..128].try_into().unwrap(),
        enc_ciphertext: a[128..708].try_into().unwrap(),
        out_ciphertext: a[708..788].try_into().unwrap(),
    };
    let cv = Option::<ValueCommitment>::from(ValueCommitment::from_bytes(&a[788..820].try_into().unwrap()))?;
    let sig_bytes: [u8; 64] = a[820..884].try_into().unwrap();
    let sig = redpallas::Signature::<SpendAuth>::from(sig_bytes);
    Action::from_parts(nf, rk, cmx, enc, cv, sig).ok()
}

/// Decode a bundle the way `Bundle<Authorized>`'s serde Deserialize does (mod.rs:1625-1643 ->
/// `bundle_from_parts`, :700-760): every action's parts, flags via `Flags::from_byte`
/// (:1009-1028), the anchor via `Anchor::from_bytes` (:1064-1087), then
/// `try_from_parts(.., ProofSizeEnforcement::Strict)`. NULL = their decoding fails.
#[no_mangle]
pub unsafe extern "C" fn zs_bundle_parse(
    actions: *const u8,
    n: usize,
    flags: u8,
    value_balance: i64,
    anchor: *const u8,
    proof: *const u8,
    proof_len: usize,
    binding_sig: *const u8,
) -> *mut ZsBundle {
    if n == 0 {
        return std::ptr::null_mut();
    }
    let raw = std::slice::from_raw_parts(actions, n * ACTION_LEN);
    let mut v = Vec::with_capacity(n);
    for i in 0..n {
        match parse_action(&raw[i * ACTION_LEN..(i + 1) * ACTION_LEN]) {
            Some(a) => v.push(a),
            None => return std::ptr::null_mut(),
        }
    }
    let Some(flags) = Flags::from_byte(flags) else { return std::ptr::null_mut() };
    let Some(anchor) = Option::<Anchor>::from(Anchor::from_bytes(arr::<32>(anchor))) else {
        return std::ptr::null_mut();
    };
    let proof = Proof::new(if proof_len == 0 { Vec::new() } else { std::slice::from_raw_parts(proof, proof_len).to_vec() });
    let bsig = redpallas::Signature::<Binding>::from(arr::<64>(binding_sig));
    let auth = Authorized::from_parts(proof, bsig);
    let actions = NonEmpty::from_vec(v).unwrap();
    match Bundle::try_from_parts(actions, flags, value_balance, anchor, auth, ProofSizeEnforcement::Strict) {
        Ok(b) => Box::into_raw(Box::new(ZsBundle(b))),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn zs_bundle_free(b: *mut ZsBundle) {
    if !b.is_null() {
        drop(Box::from_raw(b));
    }
}

/// authorization.rs verify_orchard (:146-157): binding signature over the txid, then every
/// spend-auth signature (mod.rs:1823-1834), then the halo2 proof (mod.rs:1814-1819).
/// 0 = valid, 1 = binding sig, 2 = spend-auth sig, 3 = proof.
#[no_mangle]
pub unsafe extern "C" fn zs_bundle_verify(b: *const ZsBundle, sighash: *const u8) -> i32 {
    let b = &(*b).0;
    let msg = std::slice::from_raw_parts(sighash, 32);
    if b.binding_validating_key().verify(msg, b.authorization().binding_signature()).is_err() {
        return 1;
    }
    for a in b.actions().iter() {
        if a.rk().verify(msg, a.authorization()).is_err() {
            return 2;
        }
    }
    if b.verify_proof(&VK).is_err() {
        return 3;
    }
    0
}

/// Anchor::empty_tree() (mod.rs:1044-1046) = the root of the empty depth-32 tree.
#[no_mangle]
pub unsafe extern "C" fn zs_empty_root(out: *mut u8) {
    let r = Anchor::empty_tree().to_bytes();
    std::ptr::copy_nonoverlapping(r.as_ptr(), out, 32);
}

// ------------------------------------------------------------------ frontier
// Blob = their serde-bincode Frontier (mod.rs:2092-2235): Option<{position u64, leaf [u8;32],
// ommers Vec<[u8;32]>}> (bincode: u8 tag, u64 LE, 32 bytes, u64 count, 32 each).

type OFrontier = frontier::Frontier<MerkleHashOrchard, DEPTH>;

fn frontier_from_blob(b: &[u8]) -> Option<OFrontier> {
    if b.is_empty() {
        return None;
    }
    match b[0] {
        0 if b.len() == 1 => Some(OFrontier::empty()),
        1 => {
            if b.len() < 1 + 8 + 32 + 8 {
                return None;
            }
            let pos = u64::from_le_bytes(b[1..9].try_into().unwrap());
            let leaf = Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(&b[9..41].try_into().unwrap()))?;
            let n = u64::from_le_bytes(b[41..49].try_into().unwrap()) as usize;
            if b.len() != 49 + 32 * n {
                return None;
            }
            let mut ommers = Vec::with_capacity(n);
            for i in 0..n {
                let o = &b[49 + 32 * i..49 + 32 * (i + 1)];
                ommers.push(Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(&o.try_into().unwrap()))?);
            }
            let ne = frontier::NonEmptyFrontier::from_parts(pos.into(), leaf, ommers).ok()?;
            OFrontier::try_from(ne).ok()
        }
        _ => None,
    }
}

fn frontier_to_blob(f: &OFrontier) -> Vec<u8> {
    match f.value() {
        None => vec![0u8],
        Some(ne) => {
            let mut v = vec![1u8];
            v.extend_from_slice(&u64::from(ne.position()).to_le_bytes());
            v.extend_from_slice(&ne.leaf().to_bytes());
            v.extend_from_slice(&(ne.ommers().len() as u64).to_le_bytes());
            for o in ne.ommers() {
                v.extend_from_slice(&o.to_bytes());
            }
            v
        }
    }
}

/// Frontier::append for each cmx in order (block.rs connect_orchard :455-461, mod.rs:2198-2200).
/// 0 = ok (new blob + root out), 1 = append returned false (tree full), -1 = bad input.
#[no_mangle]
pub unsafe extern "C" fn zs_frontier_append(
    blob: *const u8,
    blob_len: usize,
    cmxs: *const u8,
    n: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
    root: *mut u8,
) -> i32 {
    let Some(mut f) = frontier_from_blob(std::slice::from_raw_parts(blob, blob_len)) else { return -1 };
    let c = if n == 0 { &[][..] } else { std::slice::from_raw_parts(cmxs, n * 32) };
    for i in 0..n {
        let Some(cmx) = Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&c[i * 32..i * 32 + 32].try_into().unwrap())) else {
            return -1;
        };
        if !f.append(MerkleHashOrchard::from_cmx(&cmx)) {
            return 1;
        }
    }
    let r = f.root().to_bytes();
    std::ptr::copy_nonoverlapping(r.as_ptr(), root, 32);
    buffer_out(frontier_to_blob(&f), out, out_len);
    0
}

/// Frontier::root of a blob. 0 ok, -1 bad blob.
#[no_mangle]
pub unsafe extern "C" fn zs_frontier_root(blob: *const u8, blob_len: usize, root: *mut u8) -> i32 {
    let Some(f) = frontier_from_blob(std::slice::from_raw_parts(blob, blob_len)) else { return -1 };
    let r = f.root().to_bytes();
    std::ptr::copy_nonoverlapping(r.as_ptr(), root, 32);
    0
}

/// Wallet: the authentication path of leaf `position` in the tree holding exactly the first
/// `n` leaves (`leaves` = n cmx), and that tree's root (the anchor). -1 on bad input.
#[no_mangle]
pub unsafe extern "C" fn zs_merkle_path(leaves: *const u8, n: usize, position: u32, path_out: *mut u8, root_out: *mut u8) -> i32 {
    if (position as usize) >= n {
        return -1;
    }
    let c = std::slice::from_raw_parts(leaves, n * 32);
    let mut level: Vec<MerkleHashOrchard> = Vec::with_capacity(n);
    for i in 0..n {
        let Some(cmx) = Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&c[i * 32..i * 32 + 32].try_into().unwrap())) else {
            return -1;
        };
        level.push(MerkleHashOrchard::from_cmx(&cmx));
    }
    let mut idx = position as usize;
    let mut path = Vec::with_capacity(DEPTH as usize);
    for l in 0..DEPTH {
        let lv = Level::from(l);
        let sib = idx ^ 1;
        path.push(if sib < level.len() { level[sib] } else { MerkleHashOrchard::empty_root(lv) });
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let l0 = level[i];
            let r0 = if i + 1 < level.len() { level[i + 1] } else { MerkleHashOrchard::empty_root(lv) };
            next.push(MerkleHashOrchard::combine(lv, &l0, &r0));
            i += 2;
        }
        if next.is_empty() {
            next.push(MerkleHashOrchard::empty_root(Level::from(l + 1)));
        }
        level = next;
        idx >>= 1;
    }
    for (i, h) in path.iter().enumerate() {
        std::ptr::copy_nonoverlapping(h.to_bytes().as_ptr(), path_out.add(32 * i), 32);
    }
    std::ptr::copy_nonoverlapping(level[0].to_bytes().as_ptr(), root_out, 32);
    0
}

// ------------------------------------------------------------------ keys and notes

/// SpendingKey::from_zip32_seed(seed, coin_type, account) (lib/wallet/mod.rs:427-433).
#[no_mangle]
pub unsafe extern "C" fn zs_sk_from_zip32_seed(seed: *const u8, len: usize, coin_type: u32, account: u32, out: *mut u8) -> i32 {
    let Ok(acct) = zip32::AccountId::try_from(account) else { return -1 };
    match SpendingKey::from_zip32_seed(std::slice::from_raw_parts(seed, len), coin_type, acct) {
        Ok(sk) => {
            std::ptr::copy_nonoverlapping(sk.to_bytes().as_ptr(), out, 32);
            0
        }
        Err(_) => -1,
    }
}

unsafe fn sk_of(p: *const u8) -> Option<SpendingKey> {
    Option::from(SpendingKey::from_bytes(arr::<32>(p)))
}
unsafe fn fvk_of(p: *const u8) -> Option<FullViewingKey> {
    FullViewingKey::from_bytes(&arr::<96>(p))
}
unsafe fn addr_of(p: *const u8) -> Option<Address> {
    Option::from(Address::from_raw_address_bytes(&arr::<43>(p)))
}
fn scope(s: i32) -> Scope {
    if s == 1 { Scope::Internal } else { Scope::External }
}

#[no_mangle]
pub unsafe extern "C" fn zs_fvk(sk: *const u8, out: *mut u8) -> i32 {
    let Some(sk) = sk_of(sk) else { return -1 };
    std::ptr::copy_nonoverlapping(FullViewingKey::from(&sk).to_bytes().as_ptr(), out, 96);
    0
}

/// fvk.address_at(index, scope) (lib/wallet/mod.rs:476-478): 43 raw bytes.
#[no_mangle]
pub unsafe extern "C" fn zs_address(fvk: *const u8, index: u32, scope_: i32, out: *mut u8) -> i32 {
    let Some(fvk) = fvk_of(fvk) else { return -1 };
    std::ptr::copy_nonoverlapping(fvk.address_at(index, scope(scope_)).to_raw_address_bytes().as_ptr(), out, 43);
    0
}

/// Address::from_raw_address_bytes succeeds (their ShieldedAddress parse, types/address.rs).
#[no_mangle]
pub unsafe extern "C" fn zs_address_valid(addr: *const u8) -> bool {
    addr_of(addr).is_some()
}

/// fvk.scope_for_address: 0 external, 1 internal, -1 not ours.
#[no_mangle]
pub unsafe extern "C" fn zs_address_scope(fvk: *const u8, addr: *const u8) -> i32 {
    let (Some(fvk), Some(a)) = (fvk_of(fvk), addr_of(addr)) else { return -1 };
    match fvk.scope_for_address(&a) {
        Some(Scope::External) => 0,
        Some(Scope::Internal) => 1,
        None => -1,
    }
}

fn note_to_bytes(n: &Note) -> [u8; NOTE_LEN] {
    let mut o = [0u8; NOTE_LEN];
    o[0..43].copy_from_slice(&n.recipient().to_raw_address_bytes());
    o[43..51].copy_from_slice(&n.value().inner().to_le_bytes());
    o[51..83].copy_from_slice(&n.rho().to_bytes());
    o[83..115].copy_from_slice(n.rseed().as_bytes());
    o
}

unsafe fn note_of(p: *const u8) -> Option<Note> {
    let b = std::slice::from_raw_parts(p, NOTE_LEN);
    let recipient = Option::<Address>::from(Address::from_raw_address_bytes(&b[0..43].try_into().unwrap()))?;
    let value = NoteValue::from_raw(u64::from_le_bytes(b[43..51].try_into().unwrap()));
    let rho = Option::<Rho>::from(Rho::from_bytes(&b[51..83].try_into().unwrap()))?;
    let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(b[83..115].try_into().unwrap(), &rho))?;
    Option::from(Note::from_parts(recipient, value, rho, rseed))
}

/// Trial-decrypt action i with the fvk's external then internal ivk (their wallet tries both,
/// lib/wallet/mod.rs:444-453). Returns the scope (0/1) or -1.
#[no_mangle]
pub unsafe extern "C" fn zs_bundle_decrypt(b: *const ZsBundle, i: usize, fvk: *const u8, note_out: *mut u8, memo_out: *mut u8) -> i32 {
    let b = &(*b).0;
    let Some(fvk) = fvk_of(fvk) else { return -1 };
    for s in [Scope::External, Scope::Internal] {
        let ivk = fvk.to_ivk(s);
        if let Some((note, _addr, memo)) = b.decrypt_output_with_key(i, &ivk) {
            std::ptr::copy_nonoverlapping(note_to_bytes(&note).as_ptr(), note_out, NOTE_LEN);
            std::ptr::copy_nonoverlapping(memo.as_ptr(), memo_out, 512);
            return if s == Scope::External { 0 } else { 1 };
        }
    }
    let _ = PreparedIncomingViewingKey::new;
    -1
}

/// Recover action i's note with the fvk's external then internal ovk (outgoing view).
#[no_mangle]
pub unsafe extern "C" fn zs_bundle_recover(b: *const ZsBundle, i: usize, fvk: *const u8, note_out: *mut u8, memo_out: *mut u8) -> i32 {
    let b = &(*b).0;
    let Some(fvk) = fvk_of(fvk) else { return -1 };
    for s in [Scope::External, Scope::Internal] {
        let ovk = fvk.to_ovk(s);
        if let Some((note, _addr, memo)) = b.recover_output_with_ovk(i, &ovk) {
            std::ptr::copy_nonoverlapping(note_to_bytes(&note).as_ptr(), note_out, NOTE_LEN);
            std::ptr::copy_nonoverlapping(memo.as_ptr(), memo_out, 512);
            return if s == Scope::External { 0 } else { 1 };
        }
    }
    -1
}

#[no_mangle]
pub unsafe extern "C" fn zs_note_nullifier(note: *const u8, fvk: *const u8, out: *mut u8) -> i32 {
    let (Some(n), Some(fvk)) = (note_of(note), fvk_of(fvk)) else { return -1 };
    std::ptr::copy_nonoverlapping(n.nullifier(&fvk).to_bytes().as_ptr(), out, 32);
    0
}

#[no_mangle]
pub unsafe extern "C" fn zs_note_cmx(note: *const u8, out: *mut u8) -> i32 {
    let Some(n) = note_of(note) else { return -1 };
    std::ptr::copy_nonoverlapping(ExtractedNoteCommitment::from(n.commitment()).to_bytes().as_ptr(), out, 32);
    0
}

// ------------------------------------------------------------------ builder
// Mirrors their `orchard::Builder` wrapper (types/orchard/mod.rs:1943-2064).

/// Builder::new(flags, bundle_required, anchor) (mod.rs:1953-1963); `ovk_fvk` (nullable) and
/// `ovk_scope` select the ovk used for outputs and dummy outputs (their wallet passes the
/// internal ovk, lib/wallet/mod.rs:822).
#[no_mangle]
pub unsafe extern "C" fn zs_builder_new(flags: u8, bundle_required: bool, anchor: *const u8, ovk_fvk: *const u8, ovk_scope: i32) -> *mut ZsBuilder {
    let Some(flags) = Flags::from_byte(flags) else { return std::ptr::null_mut() };
    let Some(anchor) = Option::<Anchor>::from(Anchor::from_bytes(arr::<32>(anchor))) else { return std::ptr::null_mut() };
    let ovk = if ovk_fvk.is_null() {
        None
    } else {
        match fvk_of(ovk_fvk) {
            Some(f) => Some(f.to_ovk(scope(ovk_scope))),
            None => return std::ptr::null_mut(),
        }
    };
    let inner = Builder::new(BundleType::Transactional { flags, bundle_required }, anchor);
    Box::into_raw(Box::new(ZsBuilder { inner: Some(inner), ovk }))
}

#[no_mangle]
pub unsafe extern "C" fn zs_builder_free(b: *mut ZsBuilder) {
    if !b.is_null() {
        drop(Box::from_raw(b));
    }
}

#[no_mangle]
pub unsafe extern "C" fn zs_builder_add_spend(b: *mut ZsBuilder, fvk: *const u8, note: *const u8, position: u32, path: *const u8) -> i32 {
    let (Some(fvk), Some(note)) = (fvk_of(fvk), note_of(note)) else { return -1 };
    let p = std::slice::from_raw_parts(path, 32 * 32);
    let mut auth = [MerkleHashOrchard::empty_leaf(); 32];
    for (i, a) in auth.iter_mut().enumerate() {
        let Some(h) = Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(&p[32 * i..32 * i + 32].try_into().unwrap())) else {
            return -1;
        };
        *a = h;
    }
    let mp = MerklePath::from_parts(position, auth);
    match (*b).inner.as_mut().unwrap().add_spend(fvk, note, mp) {
        Ok(()) => 0,
        Err(_) => -2,
    }
}

#[no_mangle]
pub unsafe extern "C" fn zs_builder_add_output(b: *mut ZsBuilder, addr: *const u8, value: u64, memo: *const u8) -> i32 {
    let Some(a) = addr_of(addr) else { return -1 };
    let memo = if memo.is_null() { [0u8; 512] } else { arr::<512>(memo) };
    let ovk = (*b).ovk.clone();
    match (*b).inner.as_mut().unwrap().add_output(ovk, a, NoteValue::from_raw(value), memo) {
        Ok(()) => 0,
        Err(_) => -2,
    }
}

/// Builder::build (mod.rs:2022-2063: dummy outputs up to max(2, spends) when an ovk is given),
/// then create_proof (transaction/mod.rs create_proof -> mod.rs:1764-1786). NULL on failure
/// (`*err`: 1 = build error, 2 = no bundle, 3 = proof).
#[no_mangle]
pub unsafe extern "C" fn zs_builder_build(b: *mut ZsBuilder, err: *mut i32) -> *mut ZsUnsigned {
    let bb = &mut *b;
    let mut inner = bb.inner.take().unwrap();
    let mut rng = OsRng;
    if let Some(ovk) = bb.ovk.clone() {
        let need = std::cmp::max(2, inner.spends().len()).saturating_sub(inner.outputs().len());
        for _ in 0..need {
            let sk = loop {
                let mut r = [0u8; 32];
                rng.fill_bytes(&mut r);
                if let Some(sk) = Option::<SpendingKey>::from(SpendingKey::from_bytes(r)) {
                    break sk;
                }
            };
            let dfvk = FullViewingKey::from(&sk);
            let daddr = dfvk.address_at(0u32, Scope::External);
            if inner.add_output(Some(ovk.clone()), daddr, NoteValue::from_raw(0), [0u8; 512]).is_err() {
                *err = 1;
                return std::ptr::null_mut();
            }
        }
    }
    let built: Option<(Bundle<InProgress<Unproven, Unauthorized>, i64>, _)> = match inner.build(&mut rng) {
        Ok(x) => x,
        Err(_) => {
            *err = 1;
            return std::ptr::null_mut();
        }
    };
    let Some((unproven, _meta)) = built else {
        *err = 2;
        return std::ptr::null_mut();
    };
    match unproven.create_proof(&PK, &mut rng) {
        Ok(p) => Box::into_raw(Box::new(ZsUnsigned(p))),
        Err(_) => {
            *err = 3;
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn zs_unsigned_free(u: *mut ZsUnsigned) {
    if !u.is_null() {
        drop(Box::from_raw(u));
    }
}

fn put_action_effects<A>(v: &mut Vec<u8>, a: &Action<A>) {
    v.extend_from_slice(&a.nullifier().to_bytes());
    v.extend_from_slice(&<[u8; 32]>::from(a.rk()));
    v.extend_from_slice(&a.cmx().to_bytes());
    let e = a.encrypted_note();
    v.extend_from_slice(&e.epk_bytes);
    v.extend_from_slice(&e.enc_ciphertext);
    v.extend_from_slice(&e.out_ciphertext);
    v.extend_from_slice(&a.cv_net().to_bytes());
}

/// Effects of a proven, unsigned bundle (what the txid commits to): u32 n | n x 884-byte
/// actions with zero signatures | flags u8 | value_balance i64 | anchor 32.
#[no_mangle]
pub unsafe extern "C" fn zs_unsigned_effects(u: *const ZsUnsigned, out: *mut *mut u8, out_len: *mut usize) -> i32 {
    let b = &(*u).0;
    let mut v = Vec::new();
    v.extend_from_slice(&(b.actions().len() as u32).to_le_bytes());
    for a in b.actions().iter() {
        put_action_effects(&mut v, a);
        v.extend_from_slice(&[0u8; 64]);
    }
    v.push(b.flags().to_byte());
    v.extend_from_slice(&b.value_balance().to_le_bytes());
    v.extend_from_slice(&b.anchor().to_bytes());
    buffer_out(v, out, out_len);
    0
}

/// sign_orchard (authorization.rs:250-276): apply_signatures(sighash = txid, spend-authorizing
/// keys of `sks`). Output: the same layout as effects with signatures, then u32 proof_len |
/// proof | binding_sig 64. Consumes `u`.
#[no_mangle]
pub unsafe extern "C" fn zs_unsigned_finish(u: *mut ZsUnsigned, sighash: *const u8, sks: *const u8, n_sks: usize, out: *mut *mut u8, out_len: *mut usize) -> i32 {
    let u = Box::from_raw(u);
    let mut keys = Vec::new();
    for i in 0..n_sks {
        let Some(sk) = sk_of(sks.add(32 * i)) else { return -1 };
        keys.push(SpendAuthorizingKey::from(&sk));
    }
    let Ok(b) = u.0.apply_signatures(OsRng, arr::<32>(sighash), &keys) else { return -2 };
    let mut v = Vec::new();
    v.extend_from_slice(&(b.actions().len() as u32).to_le_bytes());
    for a in b.actions().iter() {
        put_action_effects(&mut v, a);
        v.extend_from_slice(&<[u8; 64]>::from(a.authorization()));
    }
    v.push(b.flags().to_byte());
    v.extend_from_slice(&b.value_balance().to_le_bytes());
    v.extend_from_slice(&b.anchor().to_bytes());
    let proof = b.authorization().proof().as_ref();
    v.extend_from_slice(&(proof.len() as u32).to_le_bytes());
    v.extend_from_slice(proof);
    v.extend_from_slice(&<[u8; 64]>::from(b.authorization().binding_signature()));
    buffer_out(v, out, out_len);
    0
}
