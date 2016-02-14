#include "bitcoin/script.h"
#include "bitcoin/tx.h"
#include "close_tx.h"
#include "commit_tx.h"
#include "controlled_time.h"
#include "find_p2sh_out.h"
#include "lightningd.h"
#include "log.h"
#include "names.h"
#include "peer.h"
#include "protobuf_convert.h"
#include "secrets.h"
#include "state.h"
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/mem/mem.h>
#include <ccan/str/hex/hex.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/str/str.h>
#include <inttypes.h>

#define FIXME_STUB(peer) do { log_broken((peer)->dstate->base_log, "%s:%u: Implement %s!", __FILE__, __LINE__, __func__); abort(); } while(0)

static char *hex_of(const tal_t *ctx, const void *p, size_t n)
{
	char *hex = tal_arr(ctx, char, hex_str_size(n));
	hex_encode(p, n, hex, hex_str_size(n));
	return hex;
}

static void dump_tx(const char *str, const struct bitcoin_tx *tx)
{
	u8 *linear = linearize_tx(NULL, tx);
	printf("%s:%s\n", str, hex_of(linear, linear, tal_count(linear)));
	tal_free(linear);
}

static void dump_key(const char *str, const struct pubkey *key)
{
	printf("%s:%s\n", str, hex_of(NULL, key->der, pubkey_derlen(key)));
}

/* Wrap (and own!) member inside Pkt */
static Pkt *make_pkt(const tal_t *ctx, Pkt__PktCase type, const void *msg)
{
	Pkt *pkt = tal(ctx, Pkt);

	pkt__init(pkt);
	pkt->pkt_case = type;
	/* This is a union, so doesn't matter which we assign. */
	pkt->error = (Error *)tal_steal(ctx, msg);

	/* This makes sure all packets are valid. */
#ifndef NDEBUG
	{
		size_t len;
		u8 *packed;
		Pkt *cpy;
		
		len = pkt__get_packed_size(pkt);
		packed = tal_arr(pkt, u8, len);
		pkt__pack(pkt, packed);
		cpy = pkt__unpack(NULL, len, memcheck(packed, len));
		assert(cpy);
		pkt__free_unpacked(cpy, NULL);
		tal_free(packed);
	}
#endif
	return pkt;
}

Pkt *pkt_open(const tal_t *ctx, const struct peer *peer,
	      OpenChannel__AnchorOffer anchor)
{
	OpenChannel *o = tal(ctx, OpenChannel);

	open_channel__init(o);
	o->revocation_hash = sha256_to_proto(ctx, &peer->us.revocation_hash);
	o->next_revocation_hash = sha256_to_proto(ctx, &peer->us.next_revocation_hash);
	o->commit_key = pubkey_to_proto(o, &peer->us.commitkey);
	o->final_key = pubkey_to_proto(o, &peer->us.finalkey);
	o->delay = tal(o, Locktime);
	locktime__init(o->delay);
	o->delay->locktime_case = LOCKTIME__LOCKTIME_SECONDS;
	o->delay->seconds = rel_locktime_to_seconds(&peer->us.locktime);
	o->commitment_fee = peer->us.commit_fee;
	if (anchor == OPEN_CHANNEL__ANCHOR_OFFER__WILL_CREATE_ANCHOR)
		assert(peer->us.offer_anchor == CMD_OPEN_WITH_ANCHOR);
	else {
		assert(anchor == OPEN_CHANNEL__ANCHOR_OFFER__WONT_CREATE_ANCHOR);
		assert(peer->us.offer_anchor == CMD_OPEN_WITHOUT_ANCHOR);
	}
		
	o->anch = anchor;
	o->min_depth = peer->us.mindepth;
	return make_pkt(ctx, PKT__PKT_OPEN, o);
}
	
Pkt *pkt_anchor(const tal_t *ctx, const struct peer *peer)
{
	struct signature sig;
	OpenAnchor *a = tal(ctx, OpenAnchor);

	open_anchor__init(a);
	a->txid = sha256_to_proto(a, &peer->anchor.txid.sha);
	a->output_index = peer->anchor.index;
	a->amount = peer->anchor.satoshis;

	/* Sign their commit sig */
	peer_sign_theircommit(peer, peer->them.commit, &sig);
	a->commit_sig = signature_to_proto(a, &sig);

	return make_pkt(ctx, PKT__PKT_OPEN_ANCHOR, a);
}

Pkt *pkt_open_commit_sig(const tal_t *ctx, const struct peer *peer)
{
	struct signature sig;
	OpenCommitSig *s = tal(ctx, OpenCommitSig);

	open_commit_sig__init(s);

	dump_tx("Creating sig for:", peer->them.commit);
	dump_key("Using key:", &peer->us.commitkey);

	peer_sign_theircommit(peer, peer->them.commit, &sig);
	s->sig = signature_to_proto(s, &sig);

	return make_pkt(ctx, PKT__PKT_OPEN_COMMIT_SIG, s);
}

Pkt *pkt_open_complete(const tal_t *ctx, const struct peer *peer)
{
	OpenComplete *o = tal(ctx, OpenComplete);

	open_complete__init(o);
	return make_pkt(ctx, PKT__PKT_OPEN_COMPLETE, o);
}

Pkt *pkt_htlc_add(const tal_t *ctx, const struct peer *peer,
		  const struct htlc_progress *htlc_prog)
{
	UpdateAddHtlc *u = tal(ctx, UpdateAddHtlc);

	update_add_htlc__init(u);
	assert(htlc_prog->stage.type == HTLC_ADD);

	u->amount_msat = htlc_prog->stage.add.htlc.msatoshis;
	u->r_hash = sha256_to_proto(u, &htlc_prog->stage.add.htlc.rhash);
	u->expiry = abs_locktime_to_proto(u, &htlc_prog->stage.add.htlc.expiry);

	return make_pkt(ctx, PKT__PKT_UPDATE_ADD_HTLC, u);
}

Pkt *pkt_htlc_unadd(const tal_t *ctx, const struct peer *peer,
		    const struct htlc_progress *htlc_prog)
{
	UpdateUnaddHtlc *u = tal(ctx, UpdateUnaddHtlc);

	update_unadd_htlc__init(u);
	assert(htlc_prog->stage.type == HTLC_UNADD);

	u->r_hash = sha256_to_proto(u, &htlc_prog->stage.unadd.rhash);

	return make_pkt(ctx, PKT__PKT_UPDATE_UNADD_HTLC, u);
}

Pkt *pkt_htlc_fulfill(const tal_t *ctx, const struct peer *peer,
		      const struct htlc_progress *htlc_prog)
{
	UpdateFulfillHtlc *f = tal(ctx, UpdateFulfillHtlc);

	update_fulfill_htlc__init(f);
	assert(htlc_prog->stage.type == HTLC_FULFILL);

	f->r = sha256_to_proto(f, &htlc_prog->stage.fulfill.r);

	return make_pkt(ctx, PKT__PKT_UPDATE_FULFILL_HTLC, f);
}

Pkt *pkt_htlc_timedout(const tal_t *ctx, const struct peer *peer,
		       const struct htlc_progress *htlc_prog)
{
	UpdateTimedoutHtlc *t = tal(ctx, UpdateTimedoutHtlc);

	assert(htlc_prog->stage.type == HTLC_TIMEDOUT);
	update_timedout_htlc__init(t);

	t->r_hash = sha256_to_proto(t, &htlc_prog->stage.timedout.rhash);

	return make_pkt(ctx, PKT__PKT_UPDATE_TIMEDOUT_HTLC, t);
}

Pkt *pkt_htlc_fail(const tal_t *ctx, const struct peer *peer,
		   const struct htlc_progress *htlc_prog)
{
	UpdateFailHtlc *f = tal(ctx, UpdateFailHtlc);

	update_fail_htlc__init(f);
	assert(htlc_prog->stage.type == HTLC_FAIL);

	f->r_hash = sha256_to_proto(f, &htlc_prog->stage.fail.rhash);

	return make_pkt(ctx, PKT__PKT_UPDATE_FAIL_HTLC, f);
}

Pkt *pkt_commit(const tal_t *ctx, const struct peer *peer)
{
	UpdateCommit *u = tal(ctx, UpdateCommit);
	struct signature sig;
	struct bitcoin_tx *their_tx;
	struct channel_state their_cstate;

	update_commit__init(u);

	/* We have something to commit, right? */
	assert(tal_count(peer->them.staging) != 0);
	
	/* FIXME: Don't create tx every time! */
	/* Shallow copy OK here for temporary. */
	their_cstate = *peer->them.staging_cstate;
	invert_cstate(&their_cstate);
	their_tx = create_commit_tx(u,
				    &peer->them.finalkey,
				    &peer->us.finalkey,
				    &peer->us.locktime,
				    &peer->anchor.txid,
				    peer->anchor.index,
				    peer->anchor.satoshis,
				    &peer->them.next_revocation_hash,
				    &their_cstate);

	log_debug(peer->log, "Signing tx for %u/%u msatoshis, %zu/%zu htlcs",
		  their_cstate.a.pay_msat,
		  their_cstate.b.pay_msat,
		  tal_count(their_cstate.a.htlcs),
		  tal_count(their_cstate.b.htlcs));
	peer_sign_theircommit(peer, their_tx, &sig);
	u->sig = signature_to_proto(u, &sig);

	{
		size_t n, i;

		n = tal_count(peer->them.staging);
		for (i = 0; i < n; i++)
			log_debug(peer->log,
				  "Committing to stage %zu/%zu: type %u\n",
				  i, n, peer->them.staging[i].type);
	}

	return make_pkt(ctx, PKT__PKT_UPDATE_COMMIT, u);
}

Pkt *pkt_complete(const tal_t *ctx, const struct peer *peer)
{
	UpdateComplete *u = tal(ctx, UpdateComplete);
	struct sha256 preimage;

	update_complete__init(u);

	assert(peer->commit_tx_counter > 0);
	peer_get_revocation_preimage(peer, peer->commit_tx_counter-1, &preimage);
	u->revocation_preimage = sha256_to_proto(u, &preimage);
	u->next_revocation_hash = sha256_to_proto(u,
						  &peer->us.next_revocation_hash);

	return make_pkt(ctx, PKT__PKT_UPDATE_COMPLETE, u);
}

Pkt *pkt_err(const tal_t *ctx, const char *msg, ...)
{
	Error *e = tal(ctx, Error);
	va_list ap;

	error__init(e);
	va_start(ap, msg);
	e->problem = tal_vfmt(ctx, msg, ap);
	va_end(ap);

	return make_pkt(ctx, PKT__PKT_ERROR, e);
}

Pkt *pkt_close(const tal_t *ctx, const struct peer *peer)
{
	CloseChannel *c = tal(ctx, CloseChannel);

	close_channel__init(c);

	c->close_fee = peer->close_tx->fee;
	c->sig = signature_to_proto(c, &peer->our_close_sig.sig);

	return make_pkt(ctx, PKT__PKT_CLOSE, c);
}

Pkt *pkt_close_complete(const tal_t *ctx, const struct peer *peer)
{
	CloseChannelComplete *c = tal(ctx, CloseChannelComplete);

	close_channel_complete__init(c);
	assert(peer->close_tx);
	c->sig = signature_to_proto(c, &peer->our_close_sig.sig);

	return make_pkt(ctx, PKT__PKT_CLOSE_COMPLETE, c);
}

Pkt *pkt_close_ack(const tal_t *ctx, const struct peer *peer)
{
	CloseChannelAck *a = tal(ctx, CloseChannelAck);

	close_channel_ack__init(a);
	return make_pkt(ctx, PKT__PKT_CLOSE_ACK, a);
}

Pkt *pkt_err_unexpected(const tal_t *ctx, const Pkt *pkt)
{
	return pkt_err(ctx, "Unexpected packet %s", state_name(pkt->pkt_case));
}

/* Process various packets: return an error packet on failure. */
Pkt *accept_pkt_open(const tal_t *ctx,
		     struct peer *peer, const Pkt *pkt)
{
	struct rel_locktime locktime;
	const OpenChannel *o = pkt->open;

	if (!proto_to_rel_locktime(o->delay, &locktime))
		return pkt_err(ctx, "Invalid delay");
	/* FIXME: handle blocks in locktime */
	if (o->delay->locktime_case != LOCKTIME__LOCKTIME_SECONDS)
		return pkt_err(ctx, "Delay in blocks not accepted");
	if (o->delay->seconds > peer->dstate->config.rel_locktime_max)
		return pkt_err(ctx, "Delay too great");
	if (o->min_depth > peer->dstate->config.anchor_confirms_max)
		return pkt_err(ctx, "min_depth too great");
	if (o->commitment_fee < peer->dstate->config.commitment_fee_min)
		return pkt_err(ctx, "Commitment fee too low");
	if (o->anch == OPEN_CHANNEL__ANCHOR_OFFER__WILL_CREATE_ANCHOR)
		peer->them.offer_anchor = CMD_OPEN_WITH_ANCHOR;
	else if (o->anch == OPEN_CHANNEL__ANCHOR_OFFER__WONT_CREATE_ANCHOR)
		peer->them.offer_anchor = CMD_OPEN_WITHOUT_ANCHOR;
	else
		return pkt_err(ctx, "Unknown offer anchor value");

	if (peer->them.offer_anchor == peer->us.offer_anchor)
		return pkt_err(ctx, "Only one side can offer anchor");

	if (!proto_to_rel_locktime(o->delay, &peer->them.locktime))
		return pkt_err(ctx, "Malformed locktime");
	peer->them.mindepth = o->min_depth;
	peer->them.commit_fee = o->commitment_fee;
	if (!proto_to_pubkey(peer->dstate->secpctx,
			     o->commit_key, &peer->them.commitkey))
		return pkt_err(ctx, "Bad commitkey");
	if (!proto_to_pubkey(peer->dstate->secpctx,
			     o->final_key, &peer->them.finalkey))
		return pkt_err(ctx, "Bad finalkey");
	proto_to_sha256(o->revocation_hash, &peer->them.revocation_hash);
	proto_to_sha256(o->next_revocation_hash, &peer->them.next_revocation_hash);

	/* Redeemscript for anchor. */
	peer->anchor.redeemscript
		= bitcoin_redeem_2of2(peer, &peer->us.commitkey,
				      &peer->them.commitkey);
	return NULL;
}

Pkt *accept_pkt_anchor(const tal_t *ctx,
		       struct peer *peer,
		       const Pkt *pkt)
{
	const OpenAnchor *a = pkt->open_anchor;
	u64 commitfee;

	/* They must be offering anchor for us to try accepting */
	assert(peer->us.offer_anchor == CMD_OPEN_WITHOUT_ANCHOR);
	assert(peer->them.offer_anchor == CMD_OPEN_WITH_ANCHOR);

	proto_to_sha256(a->txid, &peer->anchor.txid.sha);
	peer->anchor.index = a->output_index;
	peer->anchor.satoshis = a->amount;

	/* Create funder's cstate, invert to get ours. */
	commitfee = commit_fee(peer->them.commit_fee, peer->us.commit_fee);
	peer->cstate = initial_funding(peer,
				       peer->us.offer_anchor,
				       peer->anchor.satoshis,
				       commitfee);
	if (!peer->cstate)
		return pkt_err(ctx, "Insufficient funds for fee");
	invert_cstate(peer->cstate);

	/* Staging starts with same state we're in now. */
	peer->us.staging_cstate = copy_funding(peer, peer->cstate);
	peer->them.staging_cstate = copy_funding(peer, peer->cstate);

	/* Now we can make initial (unsigned!) commit txs. */
	make_commit_txs(peer, peer,
			&peer->us.revocation_hash,
			&peer->them.revocation_hash,
			peer->cstate,
			&peer->us.commit,
			&peer->them.commit);

	peer->cur_commit.theirsig.stype = SIGHASH_ALL;
	if (!proto_to_signature(a->commit_sig, &peer->cur_commit.theirsig.sig))
		return pkt_err(ctx, "Malformed signature");

	/* Their sig should sign our commit tx. */
	if (!check_tx_sig(peer->dstate->secpctx,
			  peer->us.commit, 0,
			  peer->anchor.redeemscript,
			  tal_count(peer->anchor.redeemscript),
			  &peer->them.commitkey,
			  &peer->cur_commit.theirsig))
		return pkt_err(ctx, "Bad signature");

	return NULL;
}

Pkt *accept_pkt_open_commit_sig(const tal_t *ctx,
				struct peer *peer, const Pkt *pkt)
{
	const OpenCommitSig *s = pkt->open_commit_sig;

	peer->cur_commit.theirsig.stype = SIGHASH_ALL;
	if (!proto_to_signature(s->sig, &peer->cur_commit.theirsig.sig))
		return pkt_err(ctx, "Malformed signature");

	dump_tx("Checking sig for:", peer->us.commit);
	dump_key("Using key:", &peer->them.commitkey);

	/* Their sig should sign our commit tx. */
	if (!check_tx_sig(peer->dstate->secpctx,
			  peer->us.commit, 0,
			  peer->anchor.redeemscript,
			  tal_count(peer->anchor.redeemscript),
			  &peer->them.commitkey,
			  &peer->cur_commit.theirsig))
		return pkt_err(ctx, "Bad signature");

	return NULL;
}

Pkt *accept_pkt_open_complete(const tal_t *ctx,
			      struct peer *peer, const Pkt *pkt)
{
	return NULL;
}

Pkt *accept_pkt_htlc_add(const tal_t *ctx,
			 struct peer *peer, const Pkt *pkt)
{
	const UpdateAddHtlc *u = pkt->update_add_htlc;
	union htlc_staging add;

	add.add.add = HTLC_ADD;
	add.add.htlc.msatoshis = u->amount_msat;
	proto_to_sha256(u->r_hash, &add.add.htlc.rhash);
	if (!proto_to_abs_locktime(u->expiry, &add.add.htlc.expiry))
		return pkt_err(ctx, "Invalid HTLC expiry");

	/* FIXME: Handle block-based expiry! */
	if (!abs_locktime_is_seconds(&add.add.htlc.expiry))
		return pkt_err(ctx, "HTLC expiry in blocks not supported!");

	/* FIXME: Add CSV in here. */
	if (abs_locktime_to_seconds(&add.add.htlc.expiry) <
	    controlled_time().ts.tv_sec + peer->dstate->config.min_expiry)
		return pkt_err(ctx, "HTLC expiry too soon!");

	/* FIXME: do we care if they set a long HTLC timeout? */
	if (abs_locktime_to_seconds(&add.add.htlc.expiry) >
	    controlled_time().ts.tv_sec + peer->dstate->config.max_expiry)
		return pkt_err(ctx, "HTLC expiry too far!");

	if (!add_staging(peer, &peer->us.staging,
			 &peer->us.staging_cstate->b,
			 &peer->us.staging_cstate->a,
			 &add))
		return pkt_err(ctx, "Failed to stage HTLC add");

	return NULL;
}

Pkt *accept_pkt_htlc_fail(const tal_t *ctx, struct peer *peer, const Pkt *pkt)
{
	const UpdateFailHtlc *f = pkt->update_fail_htlc;
	union htlc_staging fail;

	fail.fail.fail = HTLC_FAIL;
	proto_to_sha256(f->r_hash, &fail.fail.rhash);

	if (!add_staging(peer, &peer->us.staging,
			 &peer->us.staging_cstate->b,
			 &peer->us.staging_cstate->a,
			 &fail))
		return pkt_err(ctx, "Failed to stage HTLC fail");
	return NULL;
}

Pkt *accept_pkt_htlc_unadd(const tal_t *ctx, struct peer *peer, const Pkt *pkt)
{
	const UpdateUnaddHtlc *u = pkt->update_unadd_htlc;
	union htlc_staging unadd;

	unadd.unadd.unadd = HTLC_UNADD;
	proto_to_sha256(u->r_hash, &unadd.unadd.rhash);

	if (!add_staging(peer, &peer->us.staging,
			 &peer->us.staging_cstate->b,
			 &peer->us.staging_cstate->a,
			 &unadd))
		return pkt_err(ctx, "Failed to stage HTLC unadd");
	return NULL;
}

Pkt *accept_pkt_htlc_timedout(const tal_t *ctx,
			      struct peer *peer, const Pkt *pkt)
{
	const UpdateTimedoutHtlc *t = pkt->update_timedout_htlc;
	union htlc_staging timedout;

	timedout.timedout.timedout = HTLC_TIMEDOUT;
	proto_to_sha256(t->r_hash, &timedout.timedout.rhash);

	if (!add_staging(peer, &peer->us.staging,
			 &peer->us.staging_cstate->b,
			 &peer->us.staging_cstate->a,
			 &timedout))
		return pkt_err(ctx, "Faileed to stage HTLC timedout");
	return NULL;
}

Pkt *accept_pkt_htlc_fulfill(const tal_t *ctx,
			     struct peer *peer, const Pkt *pkt)
{
	const UpdateFulfillHtlc *f = pkt->update_fulfill_htlc;
	union htlc_staging fulfill;

	fulfill.fulfill.fulfill = HTLC_FULFILL;
	proto_to_sha256(f->r, &fulfill.fulfill.r);

	if (!add_staging(peer, &peer->us.staging,
			 &peer->us.staging_cstate->b,
			 &peer->us.staging_cstate->a,
			 &fulfill))
		return pkt_err(ctx, "Faileed to stage HTLC fulfill");

	return NULL;
}

Pkt *accept_pkt_commit(const tal_t *ctx, struct peer *peer, const Pkt *pkt)
{
	const UpdateCommit *c = pkt->update_commit;
	struct bitcoin_signature sig;
	struct bitcoin_tx *new_tx;

	sig.stype = SIGHASH_ALL;
	if (!proto_to_signature(c->sig, &sig.sig))
		return pkt_err(ctx, "Malformed signature");

	if (tal_count(peer->us.staging) == 0)
		return pkt_err(ctx, "Empty commit");

	/* They've signed our commit tx with their changes in it. */
	new_tx = create_commit_tx(ctx,
				  &peer->us.finalkey,
				  &peer->them.finalkey,
				  &peer->them.locktime,
				  &peer->anchor.txid,
				  peer->anchor.index,
				  peer->anchor.satoshis,
				  &peer->us.next_revocation_hash,
				  peer->us.staging_cstate);
	log_debug(peer->log, "Created tx for %u/%u msatoshis, %zu/%zu htlcs",
		  peer->us.staging_cstate->a.pay_msat,
		  peer->us.staging_cstate->b.pay_msat,
		  tal_count(peer->us.staging_cstate->a.htlcs),
		  tal_count(peer->us.staging_cstate->b.htlcs));

	if (!check_tx_sig(peer->dstate->secpctx,
			  new_tx, 0,
			  peer->anchor.redeemscript,
			  tal_count(peer->anchor.redeemscript),
			  &peer->them.commitkey,
			  &sig))
		return pkt_err(ctx, "Bad signature");

	/* Switch ourselves over to this new commit transaction. */
	peer->cur_commit.theirsig = sig;
	tal_free(peer->us.commit);
	peer->us.commit = tal_steal(peer, new_tx);
	tal_resize(&peer->us.staging, 0);

	peer->commit_tx_counter++;
	peer->us.revocation_hash = peer->us.next_revocation_hash;
	peer_get_revocation_hash(peer, peer->commit_tx_counter + 1,
				 &peer->us.next_revocation_hash);
	return NULL;
}

static bool check_preimage(const Sha256Hash *preimage, const struct sha256 *hash)
{
	struct sha256 h;

	proto_to_sha256(preimage, &h);
	sha256(&h, &h, sizeof(h));
	return structeq(&h, hash);
}

Pkt *accept_pkt_complete(const tal_t *ctx,
			 struct peer *peer, const Pkt *pkt)
{
	const UpdateComplete *c = pkt->update_complete;
	struct channel_state their_cstate;
	size_t i, n;

	/* We had something to commit, right? */
	assert(tal_count(peer->them.staging) != 0);

	/* FIXME: Save preimage in shachain too. */
	if (!check_preimage(c->revocation_preimage, &peer->them.revocation_hash))
		return pkt_err(ctx, "complete preimage incorrect");

	peer->them.revocation_hash = peer->them.next_revocation_hash;
	proto_to_sha256(c->next_revocation_hash,
			&peer->them.next_revocation_hash);

	/* Now stage changes which were applied to their commit: since
	 * we don't send updates during the COMMIT/COMPLETE handshake, this
	 * is simple. */
	n = tal_count(peer->them.staging);
	for (i = 0; i < n; i++) {
		if (!add_staging(peer, &peer->us.staging,
				 &peer->us.staging_cstate->a,
				 &peer->us.staging_cstate->b,
				 &peer->them.staging[i]))
			fatal("Failed to committed staging %zu/%zu (type %u)",
			      i, n, peer->them.staging[i].type);
	}

	/* Update their new commit tx, clear staging. */
	tal_free(peer->them.commit);
	tal_resize(&peer->them.staging, 0);

	/* FIXME: Don't create tx every time! */
	/* Shallow copy OK here for temporary. */
	their_cstate = *peer->them.staging_cstate;
	invert_cstate(&their_cstate);
	peer->them.commit = create_commit_tx(peer,
				    &peer->them.finalkey,
				    &peer->us.finalkey,
				    &peer->us.locktime,
				    &peer->anchor.txid,
				    peer->anchor.index,
				    peer->anchor.satoshis,
				    &peer->them.next_revocation_hash,
				    &their_cstate);

	return NULL;
}

static bool peer_sign_close_tx(struct peer *peer, const Signature *theirs)
{
	struct bitcoin_signature theirsig;

	/* We never sign twice! */
	assert(peer->close_tx->input[0].script_length == 0);

	theirsig.stype = SIGHASH_ALL;
	if (!proto_to_signature(theirs, &theirsig.sig))
		return false;

	/* Their sig + ours should sign the close tx. */
	if (!check_2of2_sig(peer->dstate->secpctx,
			    peer->close_tx, 0,
			    peer->anchor.redeemscript,
			    tal_count(peer->anchor.redeemscript),
			    &peer->them.commitkey, &peer->us.commitkey,
			    &theirsig, &peer->our_close_sig))
		return false;

	/* Complete the close_tx, using signatures. */
	peer->close_tx->input[0].script
		= scriptsig_p2sh_2of2(peer->close_tx,
				      &theirsig, &peer->our_close_sig,
				      &peer->them.commitkey,
				      &peer->us.commitkey);
	peer->close_tx->input[0].script_length
		= tal_count(peer->close_tx->input[0].script);
	return true;
}

Pkt *accept_pkt_close(const tal_t *ctx, struct peer *peer, const Pkt *pkt)
{
	const CloseChannel *c = pkt->close;

	/* FIXME: Don't accept tiny close fee! */
	if (!peer_create_close_tx(peer, c->close_fee))
		return pkt_err(ctx, "Invalid close fee");

	if (!peer_sign_close_tx(peer, c->sig))
		return pkt_err(ctx, "Invalid signature");
	return NULL;
}

Pkt *accept_pkt_close_complete(const tal_t *ctx,
			       struct peer *peer, const Pkt *pkt)
{
	const CloseChannelComplete *c = pkt->close_complete;
	if (!peer_sign_close_tx(peer, c->sig))
		return pkt_err(ctx, "Invalid signature");
	return NULL;
}

Pkt *accept_pkt_simultaneous_close(const tal_t *ctx,
				   struct peer *peer,
				   const Pkt *pkt)
{
	FIXME_STUB(peer);
}

/* FIXME: Since this packet is empty, is it worth having? */
Pkt *accept_pkt_close_ack(const tal_t *ctx, struct peer *peer, const Pkt *pkt)
{
	return NULL;
}
