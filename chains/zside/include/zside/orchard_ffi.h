// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
//
// C ABI of rust/zside_orchard_ffi: the reference orchard 0.14.0 / halo2_proofs 0.3.2 crates
// (the exact versions thunder-orchard b225827 links). See that crate's lib.rs for the
// thunder-orchard code each function mirrors.
//
// Action layout (884 bytes): nf 32 | rk 32 | cmx 32 | epk 32 | enc 580 | out 80 | cv 32 | sig 64
// Note layout (115 bytes): recipient 43 | value u64 LE | rho 32 | rseed 32
#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ZsBundle ZsBundle;
typedef struct ZsBuilder ZsBuilder;
typedef struct ZsUnsigned ZsUnsigned;

void zs_buffer_free(uint8_t* p, size_t len);
void zs_init_verifier(void);
void zs_init_prover(void);

ZsBundle* zs_bundle_parse(const uint8_t* actions, size_t n, uint8_t flags, int64_t value_balance, const uint8_t* anchor,
                          const uint8_t* proof, size_t proof_len, const uint8_t* binding_sig);
void zs_bundle_free(ZsBundle* b);
int32_t zs_bundle_verify(const ZsBundle* b, const uint8_t* sighash);
void zs_empty_root(uint8_t* out);

int32_t zs_frontier_append(const uint8_t* blob, size_t blob_len, const uint8_t* cmxs, size_t n, uint8_t** out, size_t* out_len,
                           uint8_t* root);
int32_t zs_frontier_root(const uint8_t* blob, size_t blob_len, uint8_t* root);
int32_t zs_merkle_path(const uint8_t* leaves, size_t n, uint32_t position, uint8_t* path_out, uint8_t* root_out);

int32_t zs_sk_from_zip32_seed(const uint8_t* seed, size_t len, uint32_t coin_type, uint32_t account, uint8_t* out);
int32_t zs_fvk(const uint8_t* sk, uint8_t* out);
int32_t zs_address(const uint8_t* fvk, uint32_t index, int32_t scope, uint8_t* out);
bool zs_address_valid(const uint8_t* addr);
int32_t zs_address_scope(const uint8_t* fvk, const uint8_t* addr);
int32_t zs_bundle_decrypt(const ZsBundle* b, size_t i, const uint8_t* fvk, uint8_t* note_out, uint8_t* memo_out);
int32_t zs_bundle_recover(const ZsBundle* b, size_t i, const uint8_t* fvk, uint8_t* note_out, uint8_t* memo_out);
int32_t zs_note_nullifier(const uint8_t* note, const uint8_t* fvk, uint8_t* out);
int32_t zs_note_cmx(const uint8_t* note, uint8_t* out);

ZsBuilder* zs_builder_new(uint8_t flags, bool bundle_required, const uint8_t* anchor, const uint8_t* ovk_fvk, int32_t ovk_scope);
void zs_builder_free(ZsBuilder* b);
int32_t zs_builder_add_spend(ZsBuilder* b, const uint8_t* fvk, const uint8_t* note, uint32_t position, const uint8_t* path);
int32_t zs_builder_add_output(ZsBuilder* b, const uint8_t* addr, uint64_t value, const uint8_t* memo);
ZsUnsigned* zs_builder_build(ZsBuilder* b, int32_t* err);
void zs_unsigned_free(ZsUnsigned* u);
int32_t zs_unsigned_effects(const ZsUnsigned* u, uint8_t** out, size_t* out_len);
int32_t zs_unsigned_finish(ZsUnsigned* u, const uint8_t* sighash, const uint8_t* sks, size_t n_sks, uint8_t** out, size_t* out_len);

#ifdef __cplusplus
}
#endif
