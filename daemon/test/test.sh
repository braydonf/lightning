#! /bin/sh -e

# We steal the test-cli scripts.
cd test-cli

. scripts/vars.sh

scripts/setup.sh

DIR1=/tmp/lightning.$$.1
DIR2=/tmp/lightning.$$.2

REDIR1="$DIR1/output"
REDIR2="$DIR2/output"
REDIRERR1="$DIR1/errors"
REDIRERR2="$DIR2/errors"
FGREP="fgrep -q"

# Always use valgrind.
PREFIX="valgrind -q --error-exitcode=7"

while [ $# != 0 ]; do
    case x"$1" in
	x"--valgrind-vgdb")
	    PREFIX="valgrind --vgdb-error=1"
	    REDIR1="/dev/tty"
	    REDIRERR1="/dev/tty"
	    REDIR2="/dev/tty"
	    REDIRERR2="/dev/tty"
	    ;;
	x"--gdb1")
	    GDB1=1
	    ;;
	x"--gdb2")
	    GDB2=1
	    ;;
	x"--timeout-anchor")
	    TIMEOUT_ANCHOR=1
	    ;;
	x"--verbose")
	    VERBOSE=1
	    ;;
	*)
	    echo Unknown arg "$1" >&2
	    exit 1
    esac
    shift
done

LCLI1="../daemon/lightning-cli --lightning-dir=$DIR1"
LCLI2="../daemon/lightning-cli --lightning-dir=$DIR2"

if [ -n "$VERBOSE" ]; then
    FGREP="fgrep"
else
    # Suppress command output.
    exec >/dev/null
fi

lcli1()
{
    if [ -n "$VERBOSE" ]; then
	echo $LCLI1 "$@" >&2
    fi
    $LCLI1 "$@"
}

lcli2()
{
    if [ -n "$VERBOSE" ]; then
	echo $LCLI2 "$@" >&2
    fi
    $LCLI2 "$@"
}

check_status_single()
{
    lcli="$1"
    us_pay=$2
    us_fee=$3
    us_htlcs="$4"
    them_pay=$5
    them_fee=$6
    them_htlcs="$7"

    if $lcli getpeers | tr -s '\012\011 ' ' ' | $FGREP '"channel" : { "us" : { "pay" : '$us_pay', "fee" : '$us_fee', "htlcs" : [ '"$us_htlcs"'] }, "them" : { "pay" : '$them_pay', "fee" : '$them_fee', "htlcs" : [ '"$them_htlcs"'] } }'; then :; else
	echo Cannot find $lcli output: '"channel" : { "us" : { "pay" : '$us_pay', "fee" : '$us_fee', "htlcs" : [ '"$us_htlcs"'] }, "them" : { "pay" : '$them_pay', "fee" : '$them_fee', "htlcs" : [ '"$them_htlcs"'] } }' >&2
	$lcli getpeers | tr -s '\012\011 ' ' ' >&2
	return 1
    fi
}

check_status()
{
    us_pay=$1
    us_fee=$2
    us_htlcs="$3"
    them_pay=$4
    them_fee=$5
    them_htlcs="$6"

    check_status_single lcli1 "$us_pay" "$us_fee" "$us_htlcs" "$them_pay" "$them_fee" "$them_htlcs" 
    check_status_single lcli2 "$them_pay" "$them_fee" "$them_htlcs" "$us_pay" "$us_fee" "$us_htlcs"
}

check_tx_spend()
{
    $CLI generate 1
    if [ $($CLI getblock $($CLI getbestblockhash) | grep -c '^    "') = 2 ]; then
	:
    else
	echo "Block didn't include tx:" >&2
	$($CLI getblock $($CLI getbestblockhash) ) >&2
	exit 1
    fi
}

all_ok()
{
    # Look for valgrind errors.
    if grep ^== $DIR1/errors; then exit 1; fi
    if grep ^== $DIR2/errors; then exit 1; fi
    scripts/shutdown.sh

    trap "rm -rf $DIR1 $DIR2" EXIT
    exit 0
}

trap "echo Results in $DIR1 and $DIR2 >&2; cat $DIR1/errors $DIR2/errors >&2" EXIT
mkdir $DIR1 $DIR2
if [ -n "$GDB1" ]; then
    echo Press return once you run: gdb --args daemon/lightningd --log-level=debug --bitcoind-poll=1 --min-expiry=900 --lightning-dir=$DIR1
    read REPLY
else
    $PREFIX ../daemon/lightningd --log-level=debug --bitcoind-poll=1 --min-expiry=900 --lightning-dir=$DIR1 > $REDIR1 2> $REDIRERR1 &
fi

if [ -n "$GDB2" ]; then
    echo Press return once you run: gdb --args daemon/lightningd --log-level=debug --bitcoind-poll=1 --min-expiry=900 --lightning-dir=$DIR2
    read REPLY
else
    $PREFIX ../daemon/lightningd --log-level=debug --bitcoind-poll=1 --min-expiry=900 --lightning-dir=$DIR2 > $REDIR2 2> $REDIRERR2 &
fi

i=0
while ! $LCLI1 getlog 2>/dev/null | $FGREP Hello; do
    sleep 1
    i=$(($i + 1))
    if [ $i -gt 10 ]; then
	echo Failed to start daemon 1 >&2
	exit 1
    fi
done

while ! $LCLI2 getlog 2>/dev/null | $FGREP 'listener on port'; do
    sleep 1
    i=$(($i + 1))
    if [ $i -gt 10 ]; then
	echo Failed to start daemon 2 >&2
	exit 1
    fi
done

ID1=`$LCLI1 getlog | sed -n 's/.*"ID: \([0-9a-f]*\)".*/\1/p'`
ID2=`$LCLI2 getlog | sed -n 's/.*"ID: \([0-9a-f]*\)".*/\1/p'`

PORT2=`$LCLI2 getlog | sed -n 's/.*on port \([0-9]*\).*/\1/p'`

lcli1 connect localhost $PORT2 999999
sleep 2

# Expect them to be waiting for anchor.
lcli1 getpeers | $FGREP STATE_OPEN_WAITING_OURANCHOR
lcli2 getpeers | $FGREP STATE_OPEN_WAITING_THEIRANCHOR

if [ -n "$TIMEOUT_ANCHOR" ]; then
    # Anchor gets 1 commit.
    check_tx_spend

    # Timeout before anchor committed deep enough.
    TIME=$((`date +%s` + 7200 + 3 * 1200 + 1))

    lcli1 dev-mocktime $TIME

    # This will crash immediately
    if $LCLI2 dev-mocktime $TIME 2> /dev/null; then
	echo Node2 did not crash >&2
	exit 1
    fi
    $FGREP 'Entered error state STATE_ERR_ANCHOR_TIMEOUT' $DIR2/crash.log

    sleep 2

    # It should send out commit tx.
    lcli1 getpeers | $FGREP -w STATE_CLOSE_WAIT_CLOSE_OURCOMMIT

    # Generate a block (should include commit tx)
    check_tx_spend
   
    # Now "wait" for 1 day, which is what node2 asked for on commit.
    TIME=$(($TIME + 24 * 60 * 60))
    lcli1 dev-mocktime $TIME

    # Due to laziness, we trigger by block generation.
    $CLI generate 1
    TIME=$(($TIME + 1))
    lcli1 dev-mocktime $TIME
    sleep 2

    # Sometimes it skips poll because it's busy.  Do it again.
    TIME=$(($TIME + 1))
    lcli1 dev-mocktime $TIME
    sleep 2
    
    lcli1 getpeers | $FGREP -w STATE_CLOSE_WAIT_CLOSE_SPENDOURS
    
    # Now it should have spent the commit tx.
    check_tx_spend

    # 99 more blocks pass...
    $CLI generate 99
    TIME=$(($TIME + 1))
    lcli1 dev-mocktime $TIME
    sleep 2

    # Considers it all done now.
    lcli1 getpeers | tr -s '\012\011 ' ' ' | $FGREP '"peers" : [ ]'

    lcli1 stop
    all_ok
fi
    
# Now make it pass anchor (should be in first block, then two more to bury it)
check_tx_spend
$CLI generate 2

# They poll every second, so give them time to process.
sleep 2

lcli1 getpeers | $FGREP STATE_NORMAL_HIGHPRIO
lcli2 getpeers | $FGREP STATE_NORMAL_LOWPRIO

check_status 949999000 50000000 "" 0 0 ""

EXPIRY=$(( $(date +%s) + 1000))
SECRET=1de08917a61cb2b62ed5937d38577f6a7bfe59c176781c6d8128018e8b5ccdfd
RHASH=`lcli1 dev-rhash $SECRET | sed 's/.*"\([0-9a-f]*\)".*/\1/'`
lcli1 newhtlc $ID2 1000000 $EXPIRY $RHASH

# Check channel status
check_status 948999000 50000000 '{ "msatoshis" : 1000000, "expiry" : { "second" : '$EXPIRY' }, "rhash" : "'$RHASH'" } ' 0 0 ""

lcli2 fulfillhtlc $ID1 $SECRET

# We've transferred the HTLC amount to 2, who now has to pay fees.
check_status 949999000 49000000 "" 0 1000000 ""

# A new one, at 10x the amount.
lcli1 newhtlc $ID2 10000000 $EXPIRY $RHASH

# Check channel status
check_status 939999000 49000000 '{ "msatoshis" : 10000000, "expiry" : { "second" : '$EXPIRY' }, "rhash" : "'$RHASH'" } ' 0 1000000 ""

lcli2 failhtlc $ID1 $RHASH

# Back to how we were before.
check_status 949999000 49000000 "" 0 1000000 ""

# Same again, but this time it expires.
lcli1 newhtlc $ID2 10000000 $EXPIRY $RHASH

# Check channel status
check_status 939999000 49000000 '{ "msatoshis" : 10000000, "expiry" : { "second" : '$EXPIRY' }, "rhash" : "'$RHASH'" } ' 0 1000000 ""

# Make sure node2 accepts the expiry packet.
lcli2 dev-mocktime $(($EXPIRY))

# This should make node1 send it.
lcli1 dev-mocktime $(($EXPIRY + 31))
sleep 1

# Back to how we were before.
check_status 949999000 49000000 "" 0 1000000 ""

lcli1 close $ID2

sleep 1

# They should be waiting for close.
lcli1 getpeers | tr -s '\012\011 ' ' ' | $FGREP '"STATE_CLOSE_WAIT_CLOSE"'
lcli2 getpeers | tr -s '\012\011 ' ' ' | $FGREP '"STATE_CLOSE_WAIT_CLOSE"'

# Give it 99 blocks.
$CLI generate 99

# Make sure they saw it!
lcli1 dev-mocktime $(($EXPIRY + 32))
lcli2 dev-mocktime $(($EXPIRY + 32))
sleep 1
lcli1 getpeers | tr -s '\012\011 ' ' ' | $FGREP '"STATE_CLOSE_WAIT_CLOSE"'
lcli2 getpeers | tr -s '\012\011 ' ' ' | $FGREP '"STATE_CLOSE_WAIT_CLOSE"'

# Now the final one.
$CLI generate 1
TIME=$(($EXPIRY + 33))
lcli1 dev-mocktime $TIME
lcli2 dev-mocktime $TIME
sleep 1

lcli1 getpeers | tr -s '\012\011 ' ' ' | $FGREP '"peers" : [ ]'
lcli2 getpeers | tr -s '\012\011 ' ' ' | $FGREP '"peers" : [ ]'

lcli1 stop
lcli2 stop

all_ok
