#include <ccan/build_assert/build_assert.h>
#ifndef TEST_STATE_COVERAGE
#include <daemon/peer.h>
#endif
#include <state.h>

static inline bool high_priority(enum state state)
{
	return (state & 1) == (STATE_NORMAL_HIGHPRIO & 1);
}
	
#define prio(state, name) \
	(high_priority(state) ? name##_HIGHPRIO : name##_LOWPRIO)

#define toggle_prio(state, name) \
	(!high_priority(state) ? name##_HIGHPRIO : name##_LOWPRIO)

/* STATE_CLOSE* can be treated as a bitset offset from STATE_CLOSED */
#define BITS_TO_STATE(bits) (STATE_CLOSED + (bits))
#define STATE_TO_BITS(state) ((state) - STATE_CLOSED)

/* For the rare cases where state may not change */
static enum command_status next_state_nocheck(struct peer *peer,
					      enum command_status cstatus,
					      const enum state state)
{
	peer->state = state;
	return cstatus;
}

static enum command_status next_state(struct peer *peer,
				      enum command_status cstatus,
				      const enum state state)
{
	assert(peer->state != state);
	return next_state_nocheck(peer, cstatus, state);
}

/*
 * Simple marker to note we don't update state.
 *
 * This happens in two cases:
 * - We're ignoring packets while closing.
 * - We stop watching an on-chain HTLC: we indicate that we want
 *   INPUT_NO_MORE_HTLCS when we get the last one.
 */
static enum command_status unchanged_state(enum command_status cstatus)
{
	return cstatus;
}

/* This may not actually change the state. */
static enum command_status next_state_bits(struct peer *peer,
					   enum command_status cstatus,
					   unsigned int bits)
{
	return next_state_nocheck(peer, cstatus, BITS_TO_STATE(bits));
}

static void set_peer_cond(struct peer *peer, enum state_peercond cond)
{
	assert(peer->cond != cond);
	peer->cond = cond;
}

static void change_peer_cond(struct peer *peer,
			      enum state_peercond old,
			      enum state_peercond new)
{
	assert(peer->cond == old);
	peer->cond = new;
}

static void complete_cmd(struct peer *peer, enum command_status *statusp,
			 enum command_status status)
{
	change_peer_cond(peer, PEER_BUSY, PEER_CMD_OK);
	*statusp = status;
}

static void queue_pkt(Pkt **out, Pkt *pkt)
{
	assert(!*out);
	assert(pkt);
	*out = pkt;
}

static void queue_tx_broadcast(const struct bitcoin_tx **broadcast,
			       const struct bitcoin_tx *tx)
{
	assert(!*broadcast);
	assert(tx);
	*broadcast = tx;
}

enum command_status state(const tal_t *ctx,
			  struct peer *peer,
			  const enum state_input input,
			  const union input *idata,
			  Pkt **out,
			  const struct bitcoin_tx **broadcast)
{
	Pkt *decline;
	const struct bitcoin_tx *tx;
	Pkt *err;
	enum command_status cstatus = CMD_NONE;

	*out = NULL;
	*broadcast = NULL;

	switch (peer->state) {
	/*
	 * Initial channel opening states.
	 */
	case STATE_INIT:
		if (input_is(input, CMD_OPEN_WITH_ANCHOR)) {
			queue_pkt(out,
				   pkt_open(ctx, peer,
					    OPEN_CHANNEL__ANCHOR_OFFER__WILL_CREATE_ANCHOR));
			change_peer_cond(peer, PEER_CMD_OK, PEER_BUSY);
			return next_state(peer, cstatus,
					  STATE_OPEN_WAIT_FOR_OPEN_WITHANCHOR);
		} else if (input_is(input, CMD_OPEN_WITHOUT_ANCHOR)) {
			change_peer_cond(peer, PEER_CMD_OK, PEER_BUSY);
			queue_pkt(out,
				   pkt_open(ctx, peer,
					    OPEN_CHANNEL__ANCHOR_OFFER__WONT_CREATE_ANCHOR));
			return next_state(peer, cstatus,
					  STATE_OPEN_WAIT_FOR_OPEN_NOANCHOR);
		}
		break;
	case STATE_OPEN_WAIT_FOR_OPEN_NOANCHOR:
		if (input_is(input, PKT_OPEN)) {
			err = accept_pkt_open(ctx, peer, idata->pkt);
			if (err) {
				complete_cmd(peer, &cstatus, CMD_FAIL);
				goto err_close_nocleanup;
			}
			return next_state(peer, cstatus, STATE_OPEN_WAIT_FOR_ANCHOR);
		} else if (input_is(input, CMD_CLOSE)) {
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto instant_close;
		} else if (input_is_pkt(input)) {
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto unexpected_pkt_nocleanup;
		}
		break;
	case STATE_OPEN_WAIT_FOR_OPEN_WITHANCHOR:
		if (input_is(input, PKT_OPEN)) {
			err = accept_pkt_open(ctx, peer, idata->pkt);
			if (err) {
				complete_cmd(peer, &cstatus, CMD_FAIL);
				goto err_close_nocleanup;
			}
			bitcoin_create_anchor(peer, BITCOIN_ANCHOR_CREATED);
			return next_state(peer, cstatus,
					  STATE_OPEN_WAIT_FOR_ANCHOR_CREATE);
		} else if (input_is(input, CMD_CLOSE)) {
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto instant_close;
		} else if (input_is_pkt(input)) {
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto unexpected_pkt_nocleanup;
		}
		break;
	case STATE_OPEN_WAIT_FOR_ANCHOR_CREATE:
		if (input_is(input, BITCOIN_ANCHOR_CREATED)) {
			queue_pkt(out, pkt_anchor(ctx, peer));
			return next_state(peer, cstatus,
					  STATE_OPEN_WAIT_FOR_COMMIT_SIG);
		} else if (input_is(input, CMD_CLOSE)) {
			bitcoin_release_anchor(peer, BITCOIN_ANCHOR_CREATED);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto instant_close;
		} else if (input_is_pkt(input)) {
			bitcoin_release_anchor(peer, BITCOIN_ANCHOR_CREATED);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto unexpected_pkt_nocleanup;
		}
		break;
	case STATE_OPEN_WAIT_FOR_ANCHOR:
		if (input_is(input, PKT_OPEN_ANCHOR)) {
			err = accept_pkt_anchor(ctx, peer, idata->pkt);
			if (err) {
				complete_cmd(peer, &cstatus, CMD_FAIL);
				goto err_close_nocleanup;
			}
			queue_pkt(out,
				   pkt_open_commit_sig(ctx, peer));
			peer_watch_anchor(peer, 
					  BITCOIN_ANCHOR_DEPTHOK,
					  BITCOIN_ANCHOR_TIMEOUT,
					  BITCOIN_ANCHOR_UNSPENT,
					  BITCOIN_ANCHOR_THEIRSPEND,
					  BITCOIN_ANCHOR_OTHERSPEND);

			return next_state(peer, cstatus,
					  STATE_OPEN_WAITING_THEIRANCHOR);
		} else if (input_is(input, CMD_CLOSE)) {
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto instant_close;
		} else if (input_is_pkt(input)) {
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto unexpected_pkt_nocleanup;
		}
		break;
	case STATE_OPEN_WAIT_FOR_COMMIT_SIG:
		if (input_is(input, PKT_OPEN_COMMIT_SIG)) {
			err = accept_pkt_open_commit_sig(ctx, peer, idata->pkt);
			if (err) {
				bitcoin_release_anchor(peer, INPUT_NONE);
				complete_cmd(peer, &cstatus, CMD_FAIL);
				goto err_start_unilateral_close;
			}
			queue_tx_broadcast(broadcast, bitcoin_anchor(ctx, peer));
			peer_watch_anchor(peer,
					  BITCOIN_ANCHOR_DEPTHOK,
					  INPUT_NONE,
					  BITCOIN_ANCHOR_UNSPENT,
					  BITCOIN_ANCHOR_THEIRSPEND,
					  BITCOIN_ANCHOR_OTHERSPEND);
			return next_state(peer, cstatus,
					  STATE_OPEN_WAITING_OURANCHOR);
		} else if (input_is(input, CMD_CLOSE)) {
			bitcoin_release_anchor(peer, INPUT_NONE);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto instant_close;
		} else if (input_is_pkt(input)) {
			bitcoin_release_anchor(peer, INPUT_NONE);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto unexpected_pkt_nocleanup;
		}
		break;
	case STATE_OPEN_WAITING_OURANCHOR:
		if (input_is(input, PKT_OPEN_COMPLETE)) {
			err = accept_pkt_open_complete(ctx, peer, idata->pkt);
			if (err) {
				complete_cmd(peer, &cstatus, CMD_FAIL);
				/* We no longer care about anchor depth. */
				peer_unwatch_anchor_depth(peer, 
							  BITCOIN_ANCHOR_DEPTHOK,
							  INPUT_NONE);
				goto err_start_unilateral_close;
			}
			return next_state(peer, cstatus,
					  STATE_OPEN_WAITING_OURANCHOR_THEYCOMPLETED);
		}
	/* Fall thru */
	case STATE_OPEN_WAITING_OURANCHOR_THEYCOMPLETED:
		if (input_is(input, BITCOIN_ANCHOR_DEPTHOK)) {
			queue_pkt(out,
				   pkt_open_complete(ctx, peer));
			if (peer->state == STATE_OPEN_WAITING_OURANCHOR_THEYCOMPLETED) {
				complete_cmd(peer, &cstatus, CMD_SUCCESS);
				return next_state(peer, cstatus,
						  STATE_NORMAL_HIGHPRIO);
			}
			return next_state(peer, cstatus,
					  STATE_OPEN_WAIT_FOR_COMPLETE_OURANCHOR);
		} else if (input_is(input, BITCOIN_ANCHOR_UNSPENT)) {
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto anchor_unspent;
		} else if (input_is(input, BITCOIN_ANCHOR_THEIRSPEND)) {
			/* We no longer care about anchor depth. */
			peer_unwatch_anchor_depth(peer, 
						  BITCOIN_ANCHOR_DEPTHOK,
						  INPUT_NONE);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto them_unilateral;
		} else if (input_is(input, BITCOIN_ANCHOR_OTHERSPEND)) {
			/* This should be impossible. */
			return next_state(peer, cstatus, STATE_ERR_INFORMATION_LEAK);
		} else if (input_is(input, CMD_CLOSE)) {
			/* We no longer care about anchor depth. */
			peer_unwatch_anchor_depth(peer,
						  BITCOIN_ANCHOR_DEPTHOK,
						  INPUT_NONE);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto start_closing;
		} else if (input_is(input, PKT_CLOSE)) {
			/* We no longer care about anchor depth. */
			peer_unwatch_anchor_depth(peer,
						  BITCOIN_ANCHOR_DEPTHOK,
						  INPUT_NONE);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto accept_closing;
		} else if (input_is_pkt(input)) {
			/* We no longer care about anchor depth. */
			peer_unwatch_anchor_depth(peer,
						  BITCOIN_ANCHOR_DEPTHOK,
						  INPUT_NONE);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto unexpected_pkt;
		}
		break;
	case STATE_OPEN_WAITING_THEIRANCHOR:
		if (input_is(input, PKT_OPEN_COMPLETE)) {
			err = accept_pkt_open_complete(ctx, peer, idata->pkt);
			if (err) {
				complete_cmd(peer, &cstatus, CMD_FAIL);
				/* We no longer care about anchor depth. */
				peer_unwatch_anchor_depth(peer, 
							  BITCOIN_ANCHOR_DEPTHOK,
							  BITCOIN_ANCHOR_TIMEOUT);
				goto err_start_unilateral_close;
			}
			return next_state(peer, cstatus,
					  STATE_OPEN_WAITING_THEIRANCHOR_THEYCOMPLETED);
		}
	/* Fall thru */
	case STATE_OPEN_WAITING_THEIRANCHOR_THEYCOMPLETED:
		if (input_is(input, BITCOIN_ANCHOR_TIMEOUT)) {
			/* Anchor didn't reach blockchain in reasonable time. */
			queue_pkt(out,
				   pkt_err(ctx, "Anchor timed out"));
			return next_state(peer, cstatus, STATE_ERR_ANCHOR_TIMEOUT);
		} else if (input_is(input, BITCOIN_ANCHOR_DEPTHOK)) {
			queue_pkt(out,
				   pkt_open_complete(ctx, peer));
			if (peer->state == STATE_OPEN_WAITING_THEIRANCHOR_THEYCOMPLETED) {
				complete_cmd(peer, &cstatus, CMD_SUCCESS);
				return next_state(peer, cstatus,
						  STATE_NORMAL_LOWPRIO);
			}
			return next_state(peer, cstatus,
					  STATE_OPEN_WAIT_FOR_COMPLETE_THEIRANCHOR);
		} else if (input_is(input, BITCOIN_ANCHOR_UNSPENT)) {
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto anchor_unspent;
		} else if (input_is(input, BITCOIN_ANCHOR_OTHERSPEND)) {
			/* This should be impossible. */
			return next_state(peer, cstatus,
					  STATE_ERR_INFORMATION_LEAK);
		} else if (input_is(input, BITCOIN_ANCHOR_THEIRSPEND)) {
			/* We no longer care about anchor depth. */
			peer_unwatch_anchor_depth(peer,
						  BITCOIN_ANCHOR_DEPTHOK,
						  BITCOIN_ANCHOR_TIMEOUT);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto them_unilateral;
		} else if (input_is(input, CMD_CLOSE)) {
			/* We no longer care about anchor depth. */
			peer_unwatch_anchor_depth(peer,
						  BITCOIN_ANCHOR_DEPTHOK,
						  BITCOIN_ANCHOR_TIMEOUT);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto start_closing;
		} else if (input_is(input, PKT_CLOSE)) {
			/* We no longer care about anchor depth. */
			peer_unwatch_anchor_depth(peer,
						  BITCOIN_ANCHOR_DEPTHOK,
						  BITCOIN_ANCHOR_TIMEOUT);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto accept_closing;
		} else if (input_is_pkt(input)) {
			/* We no longer care about anchor depth. */
			peer_unwatch_anchor_depth(peer,
						  BITCOIN_ANCHOR_DEPTHOK,
						  BITCOIN_ANCHOR_TIMEOUT);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto unexpected_pkt;
		}
		break;
	case STATE_OPEN_WAIT_FOR_COMPLETE_OURANCHOR:
	case STATE_OPEN_WAIT_FOR_COMPLETE_THEIRANCHOR:
		if (input_is(input, PKT_OPEN_COMPLETE)) {
			/* Ready for business!  Anchorer goes first. */
			if (peer->state == STATE_OPEN_WAIT_FOR_COMPLETE_OURANCHOR) {
				complete_cmd(peer, &cstatus, CMD_SUCCESS);
				return next_state(peer, cstatus,
						  STATE_NORMAL_HIGHPRIO);
			} else {
				complete_cmd(peer, &cstatus, CMD_SUCCESS);
				return next_state(peer, cstatus,
						  STATE_NORMAL_LOWPRIO);
			}
		} else if (input_is(input, BITCOIN_ANCHOR_UNSPENT)) {
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto anchor_unspent;
		/* Nobody should be able to spend anchor, except via the
		 * commit txs. */
		} else if (input_is(input, BITCOIN_ANCHOR_OTHERSPEND)) {
			return next_state(peer, cstatus,
					  STATE_ERR_INFORMATION_LEAK);
		} else if (input_is(input, BITCOIN_ANCHOR_THEIRSPEND)) {
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto them_unilateral;
		} else if (input_is(input, CMD_CLOSE)) {
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto start_closing;
		} else if (input_is(input, PKT_CLOSE)) {
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto accept_closing;
		} else if (input_is_pkt(input)) {
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto unexpected_pkt;
		}
		break;

	/*
	 * Channel normal operating states.
	 */
	case STATE_NORMAL_LOWPRIO:
	case STATE_NORMAL_HIGHPRIO:
		assert(peer->cond == PEER_CMD_OK);
		if (input_is(input, CMD_SEND_HTLC_ADD)) {
			/* We are to send an HTLC update. */
			queue_pkt(out,
				  pkt_htlc_add(ctx, peer, idata->htlc_prog));
			change_peer_cond(peer, PEER_CMD_OK, PEER_BUSY);
			return next_state(peer, cstatus,
					  prio(peer->state, STATE_WAIT_FOR_HTLC_ACCEPT));
		} else if (input_is(input, CMD_SEND_HTLC_FULFILL)) {
			/* We are to send an HTLC fulfill. */
			queue_pkt(out,
				   pkt_htlc_fulfill(ctx, peer,
						    idata->htlc_prog));
			change_peer_cond(peer, PEER_CMD_OK, PEER_BUSY);
			return next_state(peer, cstatus,
					  prio(peer->state, STATE_WAIT_FOR_UPDATE_ACCEPT));
		} else if (input_is(input, CMD_SEND_HTLC_TIMEDOUT)) {
			/* We are to send an HTLC timedout. */
			queue_pkt(out,
				   pkt_htlc_timedout(ctx, peer,
						     idata->htlc_prog));
			change_peer_cond(peer, PEER_CMD_OK, PEER_BUSY);
			return next_state(peer, cstatus,
					  prio(peer->state, STATE_WAIT_FOR_UPDATE_ACCEPT));
		} else if (input_is(input, CMD_SEND_HTLC_FAIL)) {
			/* We are to send an HTLC fail. */
			queue_pkt(out,
				   pkt_htlc_fail(ctx, peer,
						      idata->htlc_prog));
			change_peer_cond(peer, PEER_CMD_OK, PEER_BUSY);
			return next_state(peer, cstatus,
					  prio(peer->state, STATE_WAIT_FOR_UPDATE_ACCEPT));
		} else if (input_is(input, CMD_CLOSE)) {
			goto start_closing;
		} else if (input_is(input, PKT_UPDATE_ADD_HTLC)) {
			change_peer_cond(peer, PEER_CMD_OK, PEER_BUSY);
			goto accept_htlc_add;
		} else if (input_is(input, PKT_UPDATE_FULFILL_HTLC)) {
			change_peer_cond(peer, PEER_CMD_OK, PEER_BUSY);
			goto accept_htlc_fulfill;
		} else if (input_is(input, PKT_UPDATE_TIMEDOUT_HTLC)) {
			change_peer_cond(peer, PEER_CMD_OK, PEER_BUSY);
			goto accept_htlc_timedout;
		} else if (input_is(input, PKT_UPDATE_FAIL_HTLC)) {
			change_peer_cond(peer, PEER_CMD_OK, PEER_BUSY);
			goto accept_htlc_fail;
		} else if (input_is(input, BITCOIN_ANCHOR_THEIRSPEND)) {
			goto them_unilateral;
		} else if (input_is(input, BITCOIN_ANCHOR_OTHERSPEND)) {
			goto old_commit_spotted;
		} else if (input_is(input, BITCOIN_ANCHOR_UNSPENT)) {
			goto anchor_unspent;
		} else if (input_is(input, PKT_CLOSE)) {
			goto accept_closing;
		} else if (input_is_pkt(input)) {
			goto unexpected_pkt;
		}
		break;
	case STATE_WAIT_FOR_HTLC_ACCEPT_LOWPRIO:
	case STATE_WAIT_FOR_HTLC_ACCEPT_HIGHPRIO:
		/* HTLCs can also evoke a refusal. */
		if (input_is(input, PKT_UPDATE_DECLINE_HTLC)) {
			peer_htlc_declined(peer, idata->pkt);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			/* No update means no priority change. */
			return next_state(peer, cstatus,
					  prio(peer->state, STATE_NORMAL));
		}
		/* Fall thru */
	case STATE_WAIT_FOR_UPDATE_ACCEPT_LOWPRIO:
	case STATE_WAIT_FOR_UPDATE_ACCEPT_HIGHPRIO:
		if (input_is(input, PKT_UPDATE_ADD_HTLC)) {
			/* If we're high priority, ignore their packet */
			if (high_priority(peer->state))
				return cstatus;

			/* Otherwise, process their request first: defer ours */
			peer_htlc_ours_deferred(peer);
			complete_cmd(peer, &cstatus, CMD_REQUEUE);
			/* Stay busy, since we're processing theirs. */
			change_peer_cond(peer, PEER_CMD_OK, PEER_BUSY);
			goto accept_htlc_add;
		} else if (input_is(input, PKT_UPDATE_FULFILL_HTLC)) {
			/* If we're high priority, ignore their packet */
			if (high_priority(peer->state))
				return cstatus;

			/* Otherwise, process their request first: defer ours */
			peer_htlc_ours_deferred(peer);
			complete_cmd(peer, &cstatus, CMD_REQUEUE);
			/* Stay busy, since we're processing theirs. */
			change_peer_cond(peer, PEER_CMD_OK, PEER_BUSY);
			goto accept_htlc_fulfill;
		} else if (input_is(input, PKT_UPDATE_TIMEDOUT_HTLC)) {
			/* If we're high priority, ignore their packet */
			if (high_priority(peer->state))
				return cstatus;

			/* Otherwise, process their request first: defer ours */
			peer_htlc_ours_deferred(peer);
			complete_cmd(peer, &cstatus, CMD_REQUEUE);
			/* Stay busy, since we're processing theirs. */
			change_peer_cond(peer, PEER_CMD_OK, PEER_BUSY);
			goto accept_htlc_timedout;
		} else if (input_is(input, PKT_UPDATE_FAIL_HTLC)) {
			/* If we're high priority, ignore their packet */
			if (high_priority(peer->state))
				return cstatus;

			/* Otherwise, process their request first: defer ours */
			peer_htlc_ours_deferred(peer);
			complete_cmd(peer, &cstatus, CMD_REQUEUE);
			/* Stay busy, since we're processing theirs. */
			change_peer_cond(peer, PEER_CMD_OK, PEER_BUSY);
			goto accept_htlc_fail;
		} else if (input_is(input, PKT_UPDATE_ACCEPT)) {
			err = accept_pkt_update_accept(ctx, peer, idata->pkt);
			if (err) {
				peer_htlc_aborted(peer);
				complete_cmd(peer, &cstatus, CMD_FAIL);
				goto err_start_unilateral_close;
			}
			queue_pkt(out,
				   pkt_update_signature(ctx, peer));
			/* HTLC is signed (though old tx not revoked yet!) */
			return next_state(peer, cstatus,
					  prio(peer->state, STATE_WAIT_FOR_UPDATE_COMPLETE));
		} else if (input_is(input, BITCOIN_ANCHOR_UNSPENT)) {
			peer_htlc_aborted(peer);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto anchor_unspent;
		} else if (input_is(input, BITCOIN_ANCHOR_THEIRSPEND)) {
			peer_htlc_aborted(peer);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto them_unilateral;
		} else if (input_is(input, BITCOIN_ANCHOR_OTHERSPEND)) {
			peer_htlc_aborted(peer);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto old_commit_spotted;
		} else if (input_is(input, CMD_CLOSE)) {
			peer_htlc_aborted(peer);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto start_closing;
		} else if (input_is(input, PKT_CLOSE)) {
			peer_htlc_aborted(peer);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto accept_closing;
		} else if (input_is_pkt(input)) {
			peer_htlc_aborted(peer);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto unexpected_pkt;
		}
		break;
	case STATE_WAIT_FOR_UPDATE_COMPLETE_LOWPRIO:
	case STATE_WAIT_FOR_UPDATE_COMPLETE_HIGHPRIO:
		if (input_is(input, PKT_UPDATE_COMPLETE)) {
			err = accept_pkt_update_complete(ctx, peer, idata->pkt);
			if (err) {
				peer_htlc_aborted(peer);
				complete_cmd(peer, &cstatus, CMD_FAIL);
				goto err_start_unilateral_close;
			}
			peer_htlc_done(peer);
			complete_cmd(peer, &cstatus, CMD_SUCCESS);
			return next_state(peer, cstatus,
					  toggle_prio(peer->state, STATE_NORMAL));
		} else if (input_is(input, BITCOIN_ANCHOR_UNSPENT)) {
			peer_htlc_aborted(peer);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto anchor_unspent;
		} else if (input_is(input, BITCOIN_ANCHOR_THEIRSPEND)) {
			peer_htlc_aborted(peer);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto them_unilateral;
		} else if (input_is(input, BITCOIN_ANCHOR_OTHERSPEND)) {
			peer_htlc_aborted(peer);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto old_commit_spotted;
		} else if (input_is(input, PKT_CLOSE)) {
			peer_htlc_aborted(peer);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto accept_closing;
		} else if (input_is(input, CMD_CLOSE)) {
			peer_htlc_aborted(peer);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto start_closing;
		} else if (input_is_pkt(input)) {
			peer_htlc_aborted(peer);
			complete_cmd(peer, &cstatus, CMD_FAIL);
			goto unexpected_pkt;
		}
		break;
	case STATE_WAIT_FOR_UPDATE_SIG_LOWPRIO:
	case STATE_WAIT_FOR_UPDATE_SIG_HIGHPRIO:
		if (input_is(input, PKT_UPDATE_SIGNATURE)) {
			err = accept_pkt_update_signature(ctx, peer, idata->pkt);
			if (err) {
				peer_htlc_aborted(peer);
				goto err_start_unilateral_close;
			}
			queue_pkt(out,
				   pkt_update_complete(ctx, peer));
			
			peer_htlc_done(peer);
			change_peer_cond(peer, PEER_BUSY, PEER_CMD_OK);
			/* Toggle between high and low priority states. */
			return next_state(peer, cstatus,
					  toggle_prio(peer->state, STATE_NORMAL));
		} else if (input_is(input, BITCOIN_ANCHOR_UNSPENT)) {
			peer_htlc_aborted(peer);
			goto anchor_unspent;
		} else if (input_is(input, BITCOIN_ANCHOR_THEIRSPEND)) {
			peer_htlc_aborted(peer);
			goto them_unilateral;
		} else if (input_is(input, BITCOIN_ANCHOR_OTHERSPEND)) {
			peer_htlc_aborted(peer);
			goto old_commit_spotted;
		} else if (input_is(input, CMD_CLOSE)) {
			peer_htlc_aborted(peer);
			goto start_closing;
		} else if (input_is(input, PKT_CLOSE)) {
			peer_htlc_aborted(peer);
			goto accept_closing;
		} else if (input_is_pkt(input)) {
			peer_htlc_aborted(peer);
			goto unexpected_pkt;
		}
		break;

	case STATE_WAIT_FOR_CLOSE_COMPLETE:
		if (input_is(input, PKT_CLOSE_COMPLETE)) {
			peer_unwatch_close_timeout(peer,
						   INPUT_CLOSE_COMPLETE_TIMEOUT);
			err = accept_pkt_close_complete(ctx, peer, idata->pkt);
			if (err)
				goto err_start_unilateral_close_already_closing;
			queue_pkt(out,
				   pkt_close_ack(ctx, peer));
			queue_tx_broadcast(broadcast, bitcoin_close(ctx, peer));
			change_peer_cond(peer, PEER_CLOSING, PEER_CLOSED);
			return next_state(peer, cstatus, STATE_CLOSE_WAIT_CLOSE);
		} else if (input_is(input, PKT_CLOSE)) {
			peer_unwatch_close_timeout(peer,
						   INPUT_CLOSE_COMPLETE_TIMEOUT);
			/* We can use the sig just like CLOSE_COMPLETE */
			err = accept_pkt_simultaneous_close(ctx, peer,
							    idata->pkt);
			if (err)
				goto err_start_unilateral_close_already_closing;
			queue_pkt(out,
				   pkt_close_ack(ctx, peer));
			queue_tx_broadcast(broadcast, bitcoin_close(ctx, peer));
			set_peer_cond(peer, PEER_CLOSED);
			return next_state(peer, cstatus, STATE_CLOSE_WAIT_CLOSE);
		} else if (input_is(input, PKT_ERROR)) {
			peer_unwatch_close_timeout(peer,
						   INPUT_CLOSE_COMPLETE_TIMEOUT);
			peer_unexpected_pkt(peer, idata->pkt);
			goto start_unilateral_close_already_closing;
		} else if (input_is_pkt(input)) {
			/* We ignore all other packets while closing. */
			return unchanged_state(cstatus);
		} else if (input_is(input, INPUT_CLOSE_COMPLETE_TIMEOUT)) {
			/* They didn't respond in time.  Unilateral close. */
			err = pkt_err(ctx, "Close timed out");
			goto err_start_unilateral_close_already_closing;
		}
		peer_unwatch_close_timeout(peer, INPUT_CLOSE_COMPLETE_TIMEOUT);
		goto fail_during_close;

	case STATE_WAIT_FOR_CLOSE_ACK:
		if (input_is(input, PKT_CLOSE_ACK)) {
			err = accept_pkt_close_ack(ctx, peer, idata->pkt);
			if (err)
				queue_pkt(out, err);
			set_peer_cond(peer, PEER_CLOSED);
			/* Just wait for close to happen now. */
			return next_state(peer, cstatus, STATE_CLOSE_WAIT_CLOSE);
		} else if (input_is_pkt(input)) {
			peer_unexpected_pkt(peer, idata->pkt);
			/* Don't reply to an error with an error. */
			if (!input_is(input, PKT_ERROR)) {
				queue_pkt(out,
					   pkt_err_unexpected(ctx, idata->pkt));
			}
			set_peer_cond(peer, PEER_CLOSED);
			/* Just wait for close to happen now. */
			return next_state(peer, cstatus, STATE_CLOSE_WAIT_CLOSE);
		} else if (input_is(input, BITCOIN_CLOSE_DONE)) {
			/* They didn't ack, but we're closed, so stop. */
			set_peer_cond(peer, PEER_CLOSED);
			return next_state(peer, cstatus, STATE_CLOSED);
		}
		goto fail_during_close;

	/* Close states are regular: handle as a group. */
	case STATE_CLOSE_WAIT_HTLCS:
	case STATE_CLOSE_WAIT_STEAL:
	case STATE_CLOSE_WAIT_SPENDTHEM:
	case STATE_CLOSE_WAIT_SPENDTHEM_WITH_HTLCS:
	case STATE_CLOSE_WAIT_STEAL_SPENDTHEM:
	case STATE_CLOSE_WAIT_STEAL_SPENDTHEM_WITH_HTLCS:
	case STATE_CLOSE_WAIT_CLOSE:
	case STATE_CLOSE_WAIT_STEAL_CLOSE:
	case STATE_CLOSE_WAIT_SPENDTHEM_CLOSE:
	case STATE_CLOSE_WAIT_SPENDTHEM_CLOSE_WITH_HTLCS:
	case STATE_CLOSE_WAIT_STEAL_SPENDTHEM_CLOSE:
	case STATE_CLOSE_WAIT_STEAL_SPENDTHEM_CLOSE_WITH_HTLCS:
	case STATE_CLOSE_WAIT_STEAL_OURCOMMIT:
	case STATE_CLOSE_WAIT_STEAL_OURCOMMIT_WITH_HTLCS:
	case STATE_CLOSE_WAIT_SPENDTHEM_OURCOMMIT:
	case STATE_CLOSE_WAIT_SPENDTHEM_OURCOMMIT_WITH_HTLCS:
	case STATE_CLOSE_WAIT_STEAL_SPENDTHEM_OURCOMMIT:
	case STATE_CLOSE_WAIT_STEAL_SPENDTHEM_OURCOMMIT_WITH_HTLCS:
	case STATE_CLOSE_WAIT_CLOSE_OURCOMMIT:
	case STATE_CLOSE_WAIT_STEAL_CLOSE_OURCOMMIT:
	case STATE_CLOSE_WAIT_SPENDTHEM_CLOSE_OURCOMMIT:
	case STATE_CLOSE_WAIT_SPENDTHEM_CLOSE_OURCOMMIT_WITH_HTLCS:
	case STATE_CLOSE_WAIT_STEAL_SPENDTHEM_CLOSE_OURCOMMIT:
	case STATE_CLOSE_WAIT_STEAL_SPENDTHEM_CLOSE_OURCOMMIT_WITH_HTLCS:
	case STATE_CLOSE_WAIT_STEAL_SPENDOURS:
	case STATE_CLOSE_WAIT_STEAL_SPENDOURS_WITH_HTLCS:
	case STATE_CLOSE_WAIT_SPENDTHEM_SPENDOURS:
	case STATE_CLOSE_WAIT_SPENDTHEM_SPENDOURS_WITH_HTLCS:
	case STATE_CLOSE_WAIT_STEAL_SPENDTHEM_SPENDOURS:
	case STATE_CLOSE_WAIT_STEAL_SPENDTHEM_SPENDOURS_WITH_HTLCS:
	case STATE_CLOSE_WAIT_CLOSE_SPENDOURS:
	case STATE_CLOSE_WAIT_STEAL_CLOSE_SPENDOURS:
	case STATE_CLOSE_WAIT_SPENDTHEM_CLOSE_SPENDOURS:
	case STATE_CLOSE_WAIT_SPENDTHEM_CLOSE_SPENDOURS_WITH_HTLCS:
	case STATE_CLOSE_WAIT_STEAL_SPENDTHEM_CLOSE_SPENDOURS:
	case STATE_CLOSE_WAIT_STEAL_SPENDTHEM_CLOSE_SPENDOURS_WITH_HTLCS:
	case STATE_CLOSE_WAIT_OURCOMMIT:
	case STATE_CLOSE_WAIT_OURCOMMIT_WITH_HTLCS:
	case STATE_CLOSE_WAIT_SPENDOURS:
	case STATE_CLOSE_WAIT_SPENDOURS_WITH_HTLCS: {
		unsigned int bits;
		enum state_input closed;

		bits = STATE_TO_BITS(peer->state);

		/* Once we see a steal or spend completely buried, we
		 * close unless we're still waiting for htlcs*/
		if (bits & STATE_CLOSE_HTLCS_BIT)
			closed = STATE_CLOSE_WAIT_HTLCS;
		else
			closed = STATE_CLOSED;

		if ((bits & STATE_CLOSE_STEAL_BIT)
		    && input_is(input, BITCOIN_STEAL_DONE)) {
			/* One a steal is complete, we don't care about htlcs
			 * (we stole them all) */
			if (bits & STATE_CLOSE_HTLCS_BIT)
				peer_unwatch_all_htlc_outputs(peer);
			return next_state(peer, cstatus, STATE_CLOSED);
		}

		if ((bits & STATE_CLOSE_SPENDTHEM_BIT)
		    && input_is(input, BITCOIN_SPEND_THEIRS_DONE)) {
			BUILD_ASSERT(!(STATE_TO_BITS(STATE_CLOSE_WAIT_HTLCS)
				       & STATE_CLOSE_SPENDTHEM_BIT));
			return next_state(peer, cstatus, closed);
		}

		if ((bits & STATE_CLOSE_CLOSE_BIT)
		    && input_is(input, BITCOIN_CLOSE_DONE)) {
			BUILD_ASSERT(!(STATE_TO_BITS(STATE_CLOSE_WAIT_HTLCS)
				       & STATE_CLOSE_CLOSE_BIT));
			return next_state(peer, cstatus, closed);
		}

		if ((bits & STATE_CLOSE_OURCOMMIT_BIT)
		    && input_is(input, BITCOIN_ANCHOR_OURCOMMIT_DELAYPASSED)) {
			BUILD_ASSERT(!(STATE_TO_BITS(STATE_CLOSE_WAIT_HTLCS)
				       & STATE_CLOSE_OURCOMMIT_BIT));
			tx = bitcoin_spend_ours(ctx, peer);
			/* Now we need to wait for our commit to be done. */
			queue_tx_broadcast(broadcast, tx);
			peer_watch_tx(peer, tx, BITCOIN_SPEND_OURS_DONE);
			bits &= ~STATE_CLOSE_OURCOMMIT_BIT;
			bits |= STATE_CLOSE_SPENDOURS_BIT;
			return next_state(peer, cstatus, BITS_TO_STATE(bits));
		}

		if ((bits & STATE_CLOSE_SPENDOURS_BIT)
		    && input_is(input, BITCOIN_SPEND_OURS_DONE)) {
			BUILD_ASSERT(!(STATE_TO_BITS(STATE_CLOSE_WAIT_HTLCS)
				       & STATE_CLOSE_SPENDOURS_BIT));
			return next_state(peer, cstatus, closed);
		}

		/* If we have htlcs, we can get other inputs... */
		if (bits & STATE_CLOSE_HTLCS_BIT) {
			if (input_is(input, INPUT_NO_MORE_HTLCS)) {
				/* Clear bit, might lead to STATE_CLOSED. */
				BUILD_ASSERT((BITS_TO_STATE(STATE_TO_BITS(STATE_CLOSE_WAIT_HTLCS) & ~STATE_CLOSE_HTLCS_BIT)) == STATE_CLOSED);
				bits &= ~STATE_CLOSE_HTLCS_BIT;
				return next_state(peer, cstatus,
						  BITS_TO_STATE(bits));
			} else if (input_is(input, BITCOIN_HTLC_TOTHEM_SPENT)) {
				const struct htlc *htlc;
				/* They revealed R value. */
				htlc = peer_tx_revealed_r_value(peer, idata->btc);
				/* We don't care any more. */
				peer_unwatch_htlc_output(peer, htlc,
							 INPUT_NO_MORE_HTLCS);
				return unchanged_state(cstatus);
			} else if (input_is(input, BITCOIN_HTLC_TOTHEM_TIMEOUT)){
				tx = bitcoin_htlc_timeout(ctx,
							  peer,
							  idata->htlc);
				/* HTLC timed out, spend it back to us. */
				queue_tx_broadcast(broadcast, tx);
				/* Don't unwatch yet; they could yet
				 * try to spend, revealing rvalue. */

				/* We're done when that gets buried. */
				peer_watch_htlc_spend(peer, tx, idata->htlc,
						      BITCOIN_HTLC_RETURN_SPEND_DONE);
				return unchanged_state(cstatus);
			} else if (input_is(input, INPUT_RVALUE)) {
				tx = bitcoin_htlc_spend(ctx, peer,
							idata->htlc);

				/* Spend it... */
				queue_tx_broadcast(broadcast, tx);
				/* We're done when it gets buried. */
				peer_watch_htlc_spend(peer, tx, idata->htlc,
						 BITCOIN_HTLC_FULFILL_SPEND_DONE);
				/* Don't care about this one any more. */
				peer_unwatch_htlc_output(peer, idata->htlc,
							 INPUT_NO_MORE_HTLCS);
				return unchanged_state(cstatus);
			} else if (input_is(input, BITCOIN_HTLC_FULFILL_SPEND_DONE)) {
				/* Stop watching spend, send
				 * INPUT_NO_MORE_HTLCS when done. */
				peer_unwatch_htlc_spend(peer, idata->htlc,
							INPUT_NO_MORE_HTLCS);
				return unchanged_state(cstatus);
			} else if (input_is(input, BITCOIN_HTLC_RETURN_SPEND_DONE)) {
				/* Stop watching spend, send
				 * INPUT_NO_MORE_HTLCS when done. */
				peer_unwatch_htlc_spend(peer, idata->htlc,
							INPUT_NO_MORE_HTLCS);

				/* Don't need to watch the HTLC output any more,
				 * either. */
				peer_unwatch_htlc_output(peer, idata->htlc,
							 INPUT_NO_MORE_HTLCS);
				return unchanged_state(cstatus);
			} else if (input_is(input, BITCOIN_HTLC_TOUS_TIMEOUT)) {
				/* They can spend, we no longer care
				 * about this HTLC. */
				peer_unwatch_htlc_output(peer, idata->htlc,
							 INPUT_NO_MORE_HTLCS);
				return unchanged_state(cstatus);
			}
		}

		/* If we're just waiting for HTLCs, anything else is an error */
		if (peer->state == STATE_CLOSE_WAIT_HTLCS)
			break;

		/*
		 * Now, other side can always spring a commit transaction on us
		 * (even if they already have, due to tx malleability).
		 */
		if (input_is(input, BITCOIN_ANCHOR_THEIRSPEND)) {
			tx = bitcoin_spend_theirs(ctx, peer, idata->btc);
			queue_tx_broadcast(broadcast, tx);
			peer_watch_tx(peer, tx, BITCOIN_SPEND_THEIRS_DONE);
			/* HTLC watches: if any, set HTLCs bit. */
			if (peer_watch_their_htlc_outputs(peer, idata->btc,
						BITCOIN_HTLC_TOUS_TIMEOUT,
						BITCOIN_HTLC_TOTHEM_SPENT,
						BITCOIN_HTLC_TOTHEM_TIMEOUT))
				bits |= STATE_CLOSE_HTLCS_BIT;

			bits |= STATE_CLOSE_SPENDTHEM_BIT;
			return next_state_bits(peer, cstatus, bits);
			/* This can happen multiple times: need to steal ALL */
		} else if (input_is(input, BITCOIN_ANCHOR_OTHERSPEND)) {
			tx = bitcoin_steal(ctx, peer, idata->btc);
			if (!tx)
				return next_state(peer, cstatus,
						  STATE_ERR_INFORMATION_LEAK);
			queue_tx_broadcast(broadcast, tx);
			peer_watch_tx(peer, tx, BITCOIN_STEAL_DONE);
			bits |= STATE_CLOSE_STEAL_BIT;
			return next_state_bits(peer, cstatus, bits);
		} else if (input_is(input, BITCOIN_ANCHOR_UNSPENT))
			goto anchor_unspent;

		break;
	}

	/* Should never happen. */
	case STATE_ERR_INTERNAL:
	case STATE_ERR_INFORMATION_LEAK:
	case STATE_ERR_ANCHOR_TIMEOUT:
	case STATE_ERR_ANCHOR_LOST:
	case STATE_CLOSED:
	case STATE_MAX:
	case STATE_UNUSED_CLOSE_WAIT_STEAL_WITH_HTLCS:
	case STATE_UNUSED_CLOSE_WAIT_CLOSE_WITH_HTLCS:
	case STATE_UNUSED_CLOSE_WAIT_STEAL_CLOSE_WITH_HTLCS:
	case STATE_UNUSED_CLOSE_WAIT_CLOSE_OURCOMMIT_WITH_HTLCS:
	case STATE_UNUSED_CLOSE_WAIT_STEAL_CLOSE_OURCOMMIT_WITH_HTLCS:
	case STATE_UNUSED_CLOSE_WAIT_CLOSE_SPENDOURS_WITH_HTLCS:
	case STATE_UNUSED_CLOSE_WAIT_STEAL_CLOSE_SPENDOURS_WITH_HTLCS:
		return next_state(peer, cstatus, STATE_ERR_INTERNAL);
	}

	/* State machine should handle all possible states. */
	return next_state(peer, cstatus, STATE_ERR_INTERNAL);

unexpected_pkt:
	/*
	 * We got a weird packet, so we need to close unilaterally.
	 */
	peer_unexpected_pkt(peer, idata->pkt);

	/* Don't reply to an error with an error. */
	if (input_is(input, PKT_ERROR)) {
		goto start_unilateral_close;
	}
	err = pkt_err_unexpected(ctx, idata->pkt);
	goto err_start_unilateral_close;

unexpected_pkt_nocleanup:
	/*
	 * Unexpected packet, but nothing sent to chain yet, so no cleanup.
	 */
	/* Don't reply to an error with an error. */
	if (input_is(input, PKT_ERROR)) {
		goto close_nocleanup;
	}
	err = pkt_err_unexpected(ctx, idata->pkt);
	goto err_close_nocleanup;

anchor_unspent:
	/*
	 * Bitcoind tells us anchor got double-spent.  If we double-spent it
	 * then we're malfunctioning.  If they double-spent it, then they
	 * managed to cheat us: post_to_reddit();
	 */
	return next_state(peer, cstatus, STATE_ERR_ANCHOR_LOST);

err_close_nocleanup:
	/*
	 * Something went wrong, but we haven't sent anything to the blockchain
	 * so there's nothing to clean up.
	 */
	queue_pkt(out, err);

close_nocleanup:
	change_peer_cond(peer, PEER_CMD_OK, PEER_CLOSED);
	return next_state(peer, cstatus, STATE_CLOSED);

err_start_unilateral_close:
	/*
	 * They timed out, or were broken; we are going to close unilaterally.
	 */
	queue_pkt(out, err);

start_unilateral_close:
	/*
	 * Close unilaterally.
	 */
	/* No more inputs, no more commands. */
	set_peer_cond(peer, PEER_CLOSED);
	tx = bitcoin_commit(ctx, peer);
	queue_tx_broadcast(broadcast, tx);
	peer_watch_delayed(peer, tx, BITCOIN_ANCHOR_OURCOMMIT_DELAYPASSED);

	/* HTLC watches. */
	if (peer_watch_our_htlc_outputs(peer, tx,
					BITCOIN_HTLC_TOUS_TIMEOUT,
					BITCOIN_HTLC_TOTHEM_SPENT,
					BITCOIN_HTLC_TOTHEM_TIMEOUT))
		return next_state(peer, cstatus,
				  STATE_CLOSE_WAIT_OURCOMMIT_WITH_HTLCS);

	return next_state(peer, cstatus, STATE_CLOSE_WAIT_OURCOMMIT);

err_start_unilateral_close_already_closing:
	/*
	 * They timed out, or were broken; we are going to close unilaterally.
	 */
	queue_pkt(out, err);

start_unilateral_close_already_closing:
	/*
	 * Close unilaterally.
	 */
	/* No more inputs, no more commands. */
	set_peer_cond(peer, PEER_CLOSED);
	tx = bitcoin_commit(ctx, peer);
	queue_tx_broadcast(broadcast, tx);
	peer_watch_delayed(peer, tx, BITCOIN_ANCHOR_OURCOMMIT_DELAYPASSED);

	/* We agreed to close: shouldn't have any HTLCs */
	if (committed_to_htlcs(peer))
		return next_state(peer, cstatus, STATE_ERR_INTERNAL);

	return next_state(peer, cstatus, STATE_CLOSE_WAIT_CLOSE_OURCOMMIT);
	
them_unilateral:
	assert(input == BITCOIN_ANCHOR_THEIRSPEND);

	/*
	 * Bitcoind tells us they did unilateral close.
	 */
	queue_pkt(out, pkt_err(ctx, "Commit tx noticed"));

	/* No more inputs, no more commands. */
	set_peer_cond(peer, PEER_CLOSED);
	tx = bitcoin_spend_theirs(ctx, peer, idata->btc);
	queue_tx_broadcast(broadcast, tx);
	peer_watch_tx(peer, tx, BITCOIN_SPEND_THEIRS_DONE);

	/* HTLC watches (based on what they broadcast, which *may* be out
	 * of step with our current state by +/- 1 htlc. */
	if (peer_watch_their_htlc_outputs(peer, idata->btc,
					  BITCOIN_HTLC_TOUS_TIMEOUT,
					  BITCOIN_HTLC_TOTHEM_SPENT,
					  BITCOIN_HTLC_TOTHEM_TIMEOUT))
		return next_state(peer, cstatus,
				  STATE_CLOSE_WAIT_SPENDTHEM_WITH_HTLCS);

	return next_state(peer, cstatus, STATE_CLOSE_WAIT_SPENDTHEM);

accept_htlc_add:
	err = accept_pkt_htlc_add(ctx, peer, idata->pkt, &decline);
	if (err)
		goto err_start_unilateral_close;
	if (decline) {
		queue_pkt(out, decline);
		peer_htlc_declined(peer, decline);
		/* No update means no priority change. */
		change_peer_cond(peer, PEER_BUSY, PEER_CMD_OK);
		/* We may already be in STATE_NORMAL */
		return next_state_nocheck(peer, cstatus,
					  prio(peer->state, STATE_NORMAL));
	}
	queue_pkt(out, pkt_update_accept(ctx, peer));
	return next_state(peer, cstatus,
			  prio(peer->state, STATE_WAIT_FOR_UPDATE_SIG));

accept_htlc_fail:
	err = accept_pkt_htlc_fail(ctx, peer, idata->pkt);
	if (err)
		goto err_start_unilateral_close;
	queue_pkt(out, pkt_update_accept(ctx, peer));
	return next_state(peer, cstatus,
			  prio(peer->state, STATE_WAIT_FOR_UPDATE_SIG));

accept_htlc_timedout:
	err = accept_pkt_htlc_timedout(ctx, peer, idata->pkt);
	if (err)
		goto err_start_unilateral_close;
	queue_pkt(out, pkt_update_accept(ctx, peer));
	return next_state(peer, cstatus,
			  prio(peer->state, STATE_WAIT_FOR_UPDATE_SIG));

accept_htlc_fulfill:
	err = accept_pkt_htlc_fulfill(ctx, peer, idata->pkt);
	if (err)
		goto err_start_unilateral_close;
	queue_pkt(out, pkt_update_accept(ctx, peer));
	return next_state(peer, cstatus,
			  prio(peer->state, STATE_WAIT_FOR_UPDATE_SIG));

start_closing:
	/*
	 * Start a mutual close.
	 */
	/* Protocol doesn't (currently?) allow closing with HTLCs. */
	if (committed_to_htlcs(peer)) {
		err = pkt_err(ctx, "Close forced due to HTLCs");
		goto err_start_unilateral_close;
	}
	peer_watch_close(peer, BITCOIN_CLOSE_DONE, INPUT_CLOSE_COMPLETE_TIMEOUT);

	/* No more commands, we're already closing. */
	set_peer_cond(peer, PEER_CLOSING);

	/* As soon as we send packet, they could close. */
	queue_pkt(out, pkt_close(ctx, peer));
	return next_state(peer, cstatus, STATE_WAIT_FOR_CLOSE_COMPLETE);

accept_closing:
	err = accept_pkt_close(ctx, peer, idata->pkt);
	if (err)
		goto err_start_unilateral_close;
	peer_watch_close(peer, BITCOIN_CLOSE_DONE, INPUT_NONE);
	/* Send close TX. */
	queue_tx_broadcast(broadcast, bitcoin_close(ctx, peer));
	queue_pkt(out, pkt_close_complete(ctx, peer));
	/* No more commands, we're already closing. */
	set_peer_cond(peer, PEER_CLOSING);
	return next_state(peer, cstatus, STATE_WAIT_FOR_CLOSE_ACK);
	
instant_close:
	/*
	 * Closing, but we haven't sent anything to the blockchain so
	 * there's nothing to clean up.
	 */
	/* FIXME: Should we tell other side we're going? */
	set_peer_cond(peer, PEER_CLOSED);

	/* We can't have any HTLCs, since we haven't started. */
	if (committed_to_htlcs(peer))
		return next_state(peer, cstatus, STATE_ERR_INTERNAL);
	return next_state(peer, cstatus, STATE_CLOSED);

fail_during_close:
	/*
	 * We've broadcast close tx; if anything goes wrong, we just close
	 * connection and wait.
	 */
	set_peer_cond(peer, PEER_CLOSED);

	/* Once close tx is deep enough, we consider it done. */
	if (input_is(input, BITCOIN_CLOSE_DONE)) {
		return next_state(peer, cstatus, STATE_CLOSED);
	} else if (input_is(input, BITCOIN_ANCHOR_THEIRSPEND)) {
		/* A reorganization could make this happen. */
		tx = bitcoin_spend_theirs(ctx, peer, idata->btc);
		queue_tx_broadcast(broadcast, tx);
		peer_watch_tx(peer, tx, BITCOIN_SPEND_THEIRS_DONE);
		if (peer_watch_their_htlc_outputs(peer, idata->btc,
						  BITCOIN_HTLC_TOUS_TIMEOUT,
						  BITCOIN_HTLC_TOTHEM_SPENT,
						  BITCOIN_HTLC_TOTHEM_TIMEOUT)) {
			/* Expect either close or spendthem to complete */
			/* FIXME: Make sure caller uses INPUT_RVAL
			 * if they were in the middle of FULFILL! */
			return next_state(peer, cstatus,
					  STATE_CLOSE_WAIT_SPENDTHEM_CLOSE_WITH_HTLCS);
		}
		return next_state(peer, cstatus,
				  STATE_CLOSE_WAIT_SPENDTHEM_CLOSE);
	} else if (input_is(input, BITCOIN_ANCHOR_OTHERSPEND)) {
		tx = bitcoin_steal(ctx, peer, idata->btc);
		if (!tx)
			return next_state(peer, cstatus,
					  STATE_ERR_INFORMATION_LEAK);
		queue_tx_broadcast(broadcast, tx);
		peer_watch_tx(peer, tx, BITCOIN_STEAL_DONE);
		/* Expect either close or steal to complete */
		return next_state(peer, cstatus,
				  STATE_CLOSE_WAIT_STEAL_CLOSE);
	} else if (input_is(input, BITCOIN_ANCHOR_UNSPENT)) {
		return next_state(peer, cstatus, STATE_ERR_ANCHOR_LOST);
	}
	return next_state(peer, cstatus, STATE_ERR_INTERNAL);
	
old_commit_spotted:
	/*
	 * bitcoind reported a broadcast of the not-latest commit tx.
	 */
	queue_pkt(out, pkt_err(ctx, "Otherspend noticed"));

	/* No more packets, no more commands. */
	set_peer_cond(peer, PEER_CLOSED);

	/* If we can't find it, we're lost. */
	tx = bitcoin_steal(ctx, peer, idata->btc);
	if (!tx)
		return next_state(peer, cstatus,
				  STATE_ERR_INFORMATION_LEAK);
	queue_tx_broadcast(broadcast, tx);
	peer_watch_tx(peer, tx, BITCOIN_STEAL_DONE);
	return next_state(peer, cstatus, STATE_CLOSE_WAIT_STEAL);
}
