#ifndef LIGHTNING_CLOSE_TX_H
#define LIGHTNING_CLOSE_TX_H
#include "config.h"
#include "lightning.pb-c.h"
#include <ccan/tal/tal.h>
#include <secp256k1.h>

struct sha256_double;
struct pubkey;

/* Create close tx to spend the anchor tx output; doesn't fill in
 * input scriptsig. */
struct bitcoin_tx *create_close_tx(secp256k1_context *secpctx,
				   const tal_t *ctx,
				   const u8 *our_script,
				   const u8 *their_script,
				   const struct sha256_double *anchor_txid,
				   unsigned int anchor_index,
				   u64 anchor_satoshis,
				   uint64_t to_us, uint64_t to_them);
#endif
