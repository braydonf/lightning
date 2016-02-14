#ifndef LIGHTNING_STATE_TYPES_H
#define LIGHTNING_STATE_TYPES_H
#include "config.h"
/* FIXME: cdump is really dumb, so we put these in their own header. */
#include "lightning.pb-c.h"

#define STATE_CLOSE_HTLCS_BIT 1
#define STATE_CLOSE_STEAL_BIT 2
#define STATE_CLOSE_SPENDTHEM_BIT 4
#define STATE_CLOSE_CLOSE_BIT 8
#define STATE_CLOSE_OURCOMMIT_BIT 16
#define STATE_CLOSE_SPENDOURS_BIT 32

enum state {
	STATE_INIT,

	/*
	 * Opening.
	 */
	STATE_OPEN_WAIT_FOR_OPEN_NOANCHOR,
	STATE_OPEN_WAIT_FOR_OPEN_WITHANCHOR,
	STATE_OPEN_WAIT_FOR_ANCHOR_CREATE,
	STATE_OPEN_WAIT_FOR_ANCHOR,
	STATE_OPEN_WAIT_FOR_COMMIT_SIG,
	STATE_OPEN_WAITING_OURANCHOR,
	STATE_OPEN_WAITING_THEIRANCHOR,
	STATE_OPEN_WAITING_OURANCHOR_THEYCOMPLETED,
	STATE_OPEN_WAITING_THEIRANCHOR_THEYCOMPLETED,
	STATE_OPEN_WAIT_FOR_COMPLETE_OURANCHOR,
	STATE_OPEN_WAIT_FOR_COMPLETE_THEIRANCHOR,

	/*
	 * Normal state.
	 */
	STATE_NORMAL,
	STATE_NORMAL_COMMITTING,
	
	/*
	 * Closing.
	 */
	/* We told them to close, waiting for complete msg. */
	STATE_WAIT_FOR_CLOSE_COMPLETE,
	/* They told us to close, waiting for ack msg. */
	STATE_WAIT_FOR_CLOSE_ACK,	

	/* All closed. */
	STATE_CLOSED,
	/* Just waiting for HTLCs to resolve. */
	STATE_CLOSE_WAIT_HTLCS,

	/*
	 * They can broadcast one or more revoked commit tx, or their latest
	 * commit tx at any time.  We respond to revoked commit txs by stealing
	 * their funds (steal).  We respond to their latest commit tx by
	 * spending (spend_them).  They can also (with our help) broadcast
	 * a mutual close tx (mutual_close).
	 *
	 * We can also broadcast one of the following:
	 * 1) Our latest commit tx (our_commit).
	 * 2) After delay has passed, spend of our tx (spend_ours).
	 * 3) Mutual close tx (mutual_close), already covered above.
	 *
	 * Thus, we could be waiting for the following combinations:
	 * - steal
	 * - spend_them
	 * - steal + spend_them
	 * - mutual_close
	 * - steal + mutual_close
	 * - spend_them + mutual_close
	 * - steal + spend_them + mutual_close
	 *
	 * - our_commit
	 * - steal + our_commit
	 * - spend_them + our_commit
	 * - steal + spend_them + our_commit
	 * - mutual_close + our_commit
	 * - steal + mutual_close + our_commit
	 * - spend_them + mutual_close + our_commit
	 * - steal + spend_them + mutual_close + our_commit
	 *
	 * - spend_ours
	 * - steal + spend_ours
	 * - spend_them + spend_ours
	 * - steal + spend_them + spend_ours
	 * - mutual_close + spend_ours
	 * - steal + mutual_close + spend_ours
	 * - spend_them + mutual_close + spend_ours
	 * - steal + spend_them + mutual_close + spend_ours
	 *
	 * Each of these has with-HTLC and without-HTLC variants, except:
	 *
	 * 1) We never agree to close with HTLCs,
	 * 2) We don't care about htlcs if we steal (we steal all outputs).
	 *
	 * Now, it is possible for us to CLOSE and them to have an HTLC,
	 * because we could close partway through negotiation.  So, any
	 * commit tx they publish could introduce HTLCs.
	 *
	 * Thus, HTLC variants are only possible with SPENDTHEM, OR
	 * OURCOMMIT/SPENDOURS, and only no CLOSE (since CLOSE implies no HTLCs).
	 */
	STATE_CLOSE_WAIT_STEAL,
	STATE_UNUSED_CLOSE_WAIT_STEAL_WITH_HTLCS,
	STATE_CLOSE_WAIT_SPENDTHEM,
	STATE_CLOSE_WAIT_SPENDTHEM_WITH_HTLCS,
	STATE_CLOSE_WAIT_STEAL_SPENDTHEM,
	STATE_CLOSE_WAIT_STEAL_SPENDTHEM_WITH_HTLCS,
	STATE_CLOSE_WAIT_CLOSE,
	STATE_UNUSED_CLOSE_WAIT_CLOSE_WITH_HTLCS,
	STATE_CLOSE_WAIT_STEAL_CLOSE,
	STATE_UNUSED_CLOSE_WAIT_STEAL_CLOSE_WITH_HTLCS,
	STATE_CLOSE_WAIT_SPENDTHEM_CLOSE,
	STATE_CLOSE_WAIT_SPENDTHEM_CLOSE_WITH_HTLCS,
	STATE_CLOSE_WAIT_STEAL_SPENDTHEM_CLOSE,
	STATE_CLOSE_WAIT_STEAL_SPENDTHEM_CLOSE_WITH_HTLCS,

	STATE_CLOSE_WAIT_OURCOMMIT,
	STATE_CLOSE_WAIT_OURCOMMIT_WITH_HTLCS,
	STATE_CLOSE_WAIT_STEAL_OURCOMMIT,
	STATE_CLOSE_WAIT_STEAL_OURCOMMIT_WITH_HTLCS,
	STATE_CLOSE_WAIT_SPENDTHEM_OURCOMMIT,
	STATE_CLOSE_WAIT_SPENDTHEM_OURCOMMIT_WITH_HTLCS,
	STATE_CLOSE_WAIT_STEAL_SPENDTHEM_OURCOMMIT,
	STATE_CLOSE_WAIT_STEAL_SPENDTHEM_OURCOMMIT_WITH_HTLCS,
	STATE_CLOSE_WAIT_CLOSE_OURCOMMIT,
	STATE_UNUSED_CLOSE_WAIT_CLOSE_OURCOMMIT_WITH_HTLCS,
	STATE_CLOSE_WAIT_STEAL_CLOSE_OURCOMMIT,
	STATE_UNUSED_CLOSE_WAIT_STEAL_CLOSE_OURCOMMIT_WITH_HTLCS,
	STATE_CLOSE_WAIT_SPENDTHEM_CLOSE_OURCOMMIT,
	STATE_CLOSE_WAIT_SPENDTHEM_CLOSE_OURCOMMIT_WITH_HTLCS,
	STATE_CLOSE_WAIT_STEAL_SPENDTHEM_CLOSE_OURCOMMIT,
	STATE_CLOSE_WAIT_STEAL_SPENDTHEM_CLOSE_OURCOMMIT_WITH_HTLCS,

	STATE_CLOSE_WAIT_SPENDOURS,
	STATE_CLOSE_WAIT_SPENDOURS_WITH_HTLCS,
	STATE_CLOSE_WAIT_STEAL_SPENDOURS,
	STATE_CLOSE_WAIT_STEAL_SPENDOURS_WITH_HTLCS,
	STATE_CLOSE_WAIT_SPENDTHEM_SPENDOURS,
	STATE_CLOSE_WAIT_SPENDTHEM_SPENDOURS_WITH_HTLCS,
	STATE_CLOSE_WAIT_STEAL_SPENDTHEM_SPENDOURS,
	STATE_CLOSE_WAIT_STEAL_SPENDTHEM_SPENDOURS_WITH_HTLCS,
	STATE_CLOSE_WAIT_CLOSE_SPENDOURS,
	STATE_UNUSED_CLOSE_WAIT_CLOSE_SPENDOURS_WITH_HTLCS,
	STATE_CLOSE_WAIT_STEAL_CLOSE_SPENDOURS,
	STATE_UNUSED_CLOSE_WAIT_STEAL_CLOSE_SPENDOURS_WITH_HTLCS,
	STATE_CLOSE_WAIT_SPENDTHEM_CLOSE_SPENDOURS,
	STATE_CLOSE_WAIT_SPENDTHEM_CLOSE_SPENDOURS_WITH_HTLCS,
	STATE_CLOSE_WAIT_STEAL_SPENDTHEM_CLOSE_SPENDOURS,
	STATE_CLOSE_WAIT_STEAL_SPENDTHEM_CLOSE_SPENDOURS_WITH_HTLCS,

	/*
	 * Where angels fear to tread.
	 */
	/* Their anchor didn't reach blockchain in reasonable time. */
	STATE_ERR_ANCHOR_TIMEOUT,
	/* Anchor was double-spent, after both considered it sufficient depth. */
	STATE_ERR_ANCHOR_LOST,
	/* A commitment tx we didn't recognise spent the anchor (impossible) */
	STATE_ERR_INFORMATION_LEAK,
	/* We ended up in an unexpected state. */
	STATE_ERR_INTERNAL,

	STATE_MAX
};

enum state_input {
	/*
	 * Packet inputs.
	 */
	PKT_OPEN = PKT__PKT_OPEN,
	PKT_OPEN_ANCHOR = PKT__PKT_OPEN_ANCHOR,
	PKT_OPEN_COMMIT_SIG = PKT__PKT_OPEN_COMMIT_SIG,
	PKT_OPEN_COMPLETE = PKT__PKT_OPEN_COMPLETE,

	/* Updating the commit transaction: new HTLC */
	PKT_UPDATE_ADD_HTLC = PKT__PKT_UPDATE_ADD_HTLC,
	/* Updating the commit transaction: remove new HTLC */
	PKT_UPDATE_UNADD_HTLC = PKT__PKT_UPDATE_UNADD_HTLC,
	/* Updating the commit transaction: I have your R value! */
	PKT_UPDATE_FULFILL_HTLC = PKT__PKT_UPDATE_FULFILL_HTLC,
	/* Updating the commit transaction: my HTLC timed out! */
	PKT_UPDATE_TIMEDOUT_HTLC = PKT__PKT_UPDATE_TIMEDOUT_HTLC,
	/* Updating the commit transaction: your HTLC failed upstream */
	PKT_UPDATE_FAIL_HTLC = PKT__PKT_UPDATE_FAIL_HTLC,

	/* Committing updates */
	PKT_UPDATE_COMMIT = PKT__PKT_UPDATE_COMMIT,
	PKT_UPDATE_COMPLETE = PKT__PKT_UPDATE_COMPLETE,

	/* Mutual close sequence. */
	PKT_CLOSE = PKT__PKT_CLOSE,
	PKT_CLOSE_COMPLETE = PKT__PKT_CLOSE_COMPLETE,
	PKT_CLOSE_ACK = PKT__PKT_CLOSE_ACK,

	/* Something unexpected went wrong. */
	PKT_ERROR = PKT__PKT_ERROR,

	/*
	 * Non-packet inputs.
	 */
	INPUT_NONE,

	/*
	 * Bitcoin events
	 */
	/* Bitcoin anchor tx created. */
	BITCOIN_ANCHOR_CREATED,
	/* It reached the required depth. */
	BITCOIN_ANCHOR_DEPTHOK,
	/* It didn't reach the required depth in time. */
	BITCOIN_ANCHOR_TIMEOUT,
	/* It reached the required depth, then was forked off. */
	BITCOIN_ANCHOR_UNSPENT,
	/* Anchor was spent by our commit, and we can now spend it. */
	BITCOIN_ANCHOR_OURCOMMIT_DELAYPASSED,
	/* Anchor was spent by their commit tx. */
	BITCOIN_ANCHOR_THEIRSPEND,
	/* Anchor was spent by another commit tx (eg. expired). */
	BITCOIN_ANCHOR_OTHERSPEND,
	/* They spent an HTLC to them (revealing R value). */
	BITCOIN_HTLC_TOTHEM_SPENT,
	/* HTLC to them timed out, we can get funds now. */
	BITCOIN_HTLC_TOTHEM_TIMEOUT,
	/* HTLC to us timed out. */
	BITCOIN_HTLC_TOUS_TIMEOUT,
	
	/* Our spend of their commit tx is completely buried. */
	BITCOIN_SPEND_THEIRS_DONE,
	/* Our spend of our own tx is completely buried. */
	BITCOIN_SPEND_OURS_DONE,
	/* Our spend of their revoked tx is completely buried. */
	BITCOIN_STEAL_DONE,
	/* Bitcoin close transaction considered completely buried. */
	BITCOIN_CLOSE_DONE,
	/* Our HTLC spend is completely buried. */
	BITCOIN_HTLC_FULFILL_SPEND_DONE,
	/* Our HTLC refund spend has is completely buried. */
	BITCOIN_HTLC_RETURN_SPEND_DONE,

	/* We are not watching any HTLCs any more. */
	INPUT_NO_MORE_HTLCS,

	/*
	 * Timeouts.
	 */
	INPUT_CLOSE_COMPLETE_TIMEOUT,

	/*
	 * Inject a known R value.
	 *
	 * In normal operation, use CMD_SEND_HTLC_FULFILL; this is for
	 * after a unilateral close.
	 */
	INPUT_RVALUE,

	/* Commands */
	CMD_OPEN_WITH_ANCHOR,
	CMD_OPEN_WITHOUT_ANCHOR,
	CMD_SEND_HTLC_ADD,
	CMD_SEND_HTLC_UNADD,
	CMD_SEND_HTLC_FULFILL,
	CMD_SEND_HTLC_TIMEDOUT,
	CMD_SEND_HTLC_FAIL,
	CMD_SEND_COMMIT,
	CMD_CLOSE,

	INPUT_MAX
};

enum state_peercond {
	/* Ready to accept a new command. */
	PEER_CMD_OK,
	/* Don't send me commands, I'm busy. */
	PEER_BUSY,
	/* No more commands, I'm closing. */
	PEER_CLOSING,
	/* No more packets, I'm closed. */
	PEER_CLOSED
};

enum command_status {
	/* Nothing changed. */
	CMD_NONE,
	/* Command succeeded. */
	CMD_SUCCESS,
	/* HTLC-command needs re-issuing (theirs takes preference) */
	CMD_REQUEUE,
	/* Failed. */
	CMD_FAIL
};

#endif /* LIGHTNING_STATE_TYPES_H */
