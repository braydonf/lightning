#! /usr/bin/make
NAME=Butterfly Labs' Timely Delivery

# Needs to have oneof support: Ubuntu vivid's is too old :(
PROTOCC:=protoc-c

# We use our own internal ccan copy.
CCANDIR := ccan

# Alpha has checksequenceverify, segregated witness+input-amount-in-sig+confidentual-transactions, schnorr, checklocktimeverify
ALPHA_FEATURES :=				\
	-DALPHA_TXSTYLE=1			\
	-DHAS_BIP68=0				\
	-DHAS_CLTV=1				\
	-DHAS_CSV=1				\
	-DSCRIPTS_USE_DER=0			\
	-DUSE_SCHNORR=1

# Bitcoin uses DER for signatures (Add BIP68 & HAS_CSV if it's supported)
BITCOIN_FEATURES :=				\
	-DALPHA_TXSTYLE=0			\
	-DHAS_BIP68=0				\
	-DHAS_CLTV=1				\
	-DHAS_CSV=0				\
	-DSCRIPTS_USE_DER=1			\
	-DUSE_SCHNORR=0

#FEATURES := $(ALPHA_FEATURES)
FEATURES := $(BITCOIN_FEATURES)

TEST_PROGRAMS :=				\
	test/test_state_coverage		\
	test/onion_key				\
	test/test_onion

BITCOIN_SRC :=					\
	bitcoin/address.c			\
	bitcoin/base58.c			\
	bitcoin/locktime.c			\
	bitcoin/pubkey.c			\
	bitcoin/script.c			\
	bitcoin/shadouble.c			\
	bitcoin/signature.c			\
	bitcoin/tx.c
BITCOIN_OBJS := $(BITCOIN_SRC:.c=.o)

CORE_SRC :=					\
	close_tx.c				\
	commit_tx.c				\
	find_p2sh_out.c				\
	funding.c				\
	lightning.pb-c.c			\
	opt_bits.c				\
	permute_tx.c				\
	protobuf_convert.c			\
	version.c
CORE_OBJS := $(CORE_SRC:.c=.o)

CCAN_OBJS :=					\
	ccan-crypto-ripemd160.o			\
	ccan-crypto-sha256.o			\
	ccan-crypto-shachain.o			\
	ccan-err.o				\
	ccan-hash.o				\
	ccan-htable.o				\
	ccan-ilog.o				\
	ccan-io-io.o				\
	ccan-io-poll.o				\
	ccan-isaac.o				\
	ccan-isaac64.o				\
	ccan-list.o				\
	ccan-noerr.o				\
	ccan-opt-helpers.o			\
	ccan-opt-parse.o			\
	ccan-opt-usage.o			\
	ccan-opt.o				\
	ccan-pipecmd.o				\
	ccan-read_write_all.o			\
	ccan-str-hex.o				\
	ccan-str.o				\
	ccan-take.o				\
	ccan-tal-grab_file.o			\
	ccan-tal-path.o				\
	ccan-tal-str.o				\
	ccan-tal.o				\
	ccan-time.o				\
	ccan-timer.o

CCAN_HEADERS :=						\
	$(CCANDIR)/config.h				\
	$(CCANDIR)/ccan/alignof/alignof.h		\
	$(CCANDIR)/ccan/array_size/array_size.h		\
	$(CCANDIR)/ccan/asort/asort.h			\
	$(CCANDIR)/ccan/build_assert/build_assert.h	\
	$(CCANDIR)/ccan/cast/cast.h			\
	$(CCANDIR)/ccan/cdump/cdump.h			\
	$(CCANDIR)/ccan/check_type/check_type.h		\
	$(CCANDIR)/ccan/compiler/compiler.h		\
	$(CCANDIR)/ccan/container_of/container_of.h	\
	$(CCANDIR)/ccan/crypto/ripemd160/ripemd160.h	\
	$(CCANDIR)/ccan/crypto/sha256/sha256.h		\
	$(CCANDIR)/ccan/crypto/shachain/shachain.h	\
	$(CCANDIR)/ccan/endian/endian.h			\
	$(CCANDIR)/ccan/err/err.h			\
	$(CCANDIR)/ccan/hash/hash.h			\
	$(CCANDIR)/ccan/htable/htable.h			\
	$(CCANDIR)/ccan/htable/htable_type.h		\
	$(CCANDIR)/ccan/ilog/ilog.h			\
	$(CCANDIR)/ccan/io/backend.h			\
	$(CCANDIR)/ccan/io/io.h				\
	$(CCANDIR)/ccan/io/io_plan.h			\
	$(CCANDIR)/ccan/isaac/isaac.h			\
	$(CCANDIR)/ccan/isaac/isaac64.h			\
	$(CCANDIR)/ccan/likely/likely.h			\
	$(CCANDIR)/ccan/list/list.h			\
	$(CCANDIR)/ccan/mem/mem.h			\
	$(CCANDIR)/ccan/noerr/noerr.h			\
	$(CCANDIR)/ccan/opt/opt.h			\
	$(CCANDIR)/ccan/opt/private.h			\
	$(CCANDIR)/ccan/order/order.h			\
	$(CCANDIR)/ccan/pipecmd/pipecmd.h		\
	$(CCANDIR)/ccan/ptrint/ptrint.h			\
	$(CCANDIR)/ccan/read_write_all/read_write_all.h	\
	$(CCANDIR)/ccan/short_types/short_types.h	\
	$(CCANDIR)/ccan/str/hex/hex.h			\
	$(CCANDIR)/ccan/str/str.h			\
	$(CCANDIR)/ccan/str/str_debug.h			\
	$(CCANDIR)/ccan/strmap/strmap.h			\
	$(CCANDIR)/ccan/structeq/structeq.h		\
	$(CCANDIR)/ccan/take/take.h			\
	$(CCANDIR)/ccan/tal/grab_file/grab_file.h	\
	$(CCANDIR)/ccan/tal/link/link.h			\
	$(CCANDIR)/ccan/tal/path/path.h			\
	$(CCANDIR)/ccan/tal/stack/stack.h		\
	$(CCANDIR)/ccan/tal/str/str.h			\
	$(CCANDIR)/ccan/tal/tal.h			\
	$(CCANDIR)/ccan/tal/talloc/talloc.h		\
	$(CCANDIR)/ccan/tcon/tcon.h			\
	$(CCANDIR)/ccan/time/time.h			\
	$(CCANDIR)/ccan/timer/timer.h			\
	$(CCANDIR)/ccan/typesafe_cb/typesafe_cb.h

BITCOIN_HEADERS := bitcoin/address.h		\
	bitcoin/base58.h			\
	bitcoin/locktime.h			\
	bitcoin/privkey.h			\
	bitcoin/pubkey.h			\
	bitcoin/script.h			\
	bitcoin/shadouble.h			\
	bitcoin/signature.h			\
	bitcoin/tx.h

CORE_HEADERS := close_tx.h			\
	commit_tx.h				\
	find_p2sh_out.h				\
	funding.h				\
	names.h					\
	opt_bits.h				\
	overflows.h				\
	permute_tx.h				\
	protobuf_convert.h			\
	state.h					\
	state_types.h				\
	version.h

GEN_HEADERS := 	gen_state_names.h		\
	gen_version.h				\
	lightning.pb-c.h

CDUMP_OBJS := ccan-cdump.o ccan-strmap.o

PROGRAMS := $(TEST_PROGRAMS)

CWARNFLAGS := -Werror -Wall -Wundef -Wmissing-prototypes -Wmissing-declarations -Wstrict-prototypes -Wold-style-definition
CDEBUGFLAGS := -g -fstack-protector
CFLAGS := $(CWARNFLAGS) $(CDEBUGFLAGS) -I $(CCANDIR) -I secp256k1/include/ -I . $(FEATURES)

LDLIBS := -lcrypto -lprotobuf-c
$(PROGRAMS): CFLAGS+=-I.

default: $(PROGRAMS) daemon-all

# Everything depends on the CCAN headers.
$(CCAN_OBJS) $(CDUMP_OBJS) $(HELPER_OBJS) $(BITCOIN_OBJS) $(TEST_PROGRAMS:=.o): $(CCAN_HEADERS)

# Except for CCAN, everything depends on bitcoin/ and core headers.
$(HELPER_OBJS) $(BITCOIN_OBJS) $(TEST_PROGRAMS:=.o): $(BITCOIN_HEADERS) $(CORE_HEADERS) $(GEN_HEADERS)

# These don't work in parallel, so we open-code them
daemon-tests: daemon-all
	cd test-cli; scripts/shutdown.sh 2>/dev/null || true
	set -e; for arg in "" "--timeout-anchor"; do daemon/test/test.sh $$arg; done

test-onion: test/test_onion test/onion_key
	set -e; TMPF=/tmp/onion.$$$$; test/test_onion --generate $$(test/onion_key --pub `seq 20`) > $$TMPF; for k in `seq 20`; do test/test_onion --decode $$(test/onion_key --priv $$k) < $$TMPF > $$TMPF.unwrap; mv $$TMPF.unwrap $$TMPF; done; rm -f $$TMPF

test-onion2: test/test_onion test/onion_key
	set -e; TMPF=/tmp/onion.$$$$; python test/test_onion.py generate $$(test/onion_key --pub `seq 20`) > $$TMPF; for k in `seq 20`; do test/test_onion --decode $$(test/onion_key --priv $$k) < $$TMPF > $$TMPF.unwrap; mv $$TMPF.unwrap $$TMPF; done; rm -f $$TMPF

test-onion3: test/test_onion test/onion_key
	set -e; TMPF=/tmp/onion.$$$$; test/test_onion --generate $$(test/onion_key --pub `seq 20`) > $$TMPF; for k in `seq 20`; do python test/test_onion.py decode $$(test/onion_key --priv $$k) $$(test/onion_key --pub $$k) < $$TMPF > $$TMPF.unwrap; mv $$TMPF.unwrap $$TMPF; done; rm -f $$TMPF

test-onion4: test/test_onion test/onion_key
	set -e; TMPF=/tmp/onion.$$$$; python test/test_onion.py generate $$(test/onion_key --pub `seq 20`) > $$TMPF; for k in `seq 20`; do python test/test_onion.py decode $$(test/onion_key --priv $$k) $$(test/onion_key --pub $$k) < $$TMPF > $$TMPF.unwrap; mv $$TMPF.unwrap $$TMPF; done; rm -f $$TMPF

check: daemon-tests test-onion

# Keep includes in alpha order.
check-src-include-order/%: %
	@if [ "$$(grep '^#include' < $<)" != "$$(grep '^#include' < $< | LC_ALL=C sort)" ]; then echo "$<:1: includes out of order"; grep '^#include' < $<; echo VERSUS; grep '^#include' < $< | LC_ALL=C sort; exit 1; fi

# Keep includes in alpha order, after including "config.h"
check-hdr-include-order/%: %
	@if [ "$$(grep '^#include' < $< | head -n1)" != '#include "config.h"' ]; then echo "$<:1: doesn't include config.h first"; exit 1; fi
	@if [ "$$(grep '^#include' < $< | tail -n +2)" != "$$(grep '^#include' < $< | tail -n +2 | LC_ALL=C sort)" ]; then echo "$<:1: includes out of order"; exit 1; fi

# Make sure Makefile includes all headers.
check-makefile: check-daemon-makefile
	@if [ "`echo bitcoin/*.h`" != "$(BITCOIN_HEADERS)" ]; then echo BITCOIN_HEADERS incorrect; exit 1; fi
	@if [ x"`ls *.h | grep -v ^gen_ | fgrep -v lightning.pb-c.h | tr '\n' ' '`" != x"$(CORE_HEADERS) " ]; then echo CORE_HEADERS incorrect; exit 1; fi
	@if [ x"$(CCANDIR)/config.h `find $(CCANDIR)/ccan -name '*.h' | grep -v /test/ | LC_ALL=C sort | tr '\n' ' '`" != x"$(CCAN_HEADERS) " ]; then echo CCAN_HEADERS incorrect; exit 1; fi

check-source: check-makefile				\
	$(CORE_SRC:%=check-src-include-order/%)		\
	$(BITCOIN_SRC:%=check-src-include-order/%)	\
	$(CORE_HEADERS:%=check-hdr-include-order/%)	\
	$(BITCOIN_HEADERS:%=check-hdr-include-order/%)

full-check: check $(TEST_PROGRAMS) check-source
	test/test_state_coverage

TAGS: FORCE
	$(RM) TAGS; find . -name '*.[ch]' | xargs etags --append
FORCE::

ccan/ccan/cdump/tools/cdump-enumstr: ccan/ccan/cdump/tools/cdump-enumstr.o $(CDUMP_OBJS) $(CCAN_OBJS)

gen_state_names.h: state_types.h ccan/ccan/cdump/tools/cdump-enumstr
	ccan/ccan/cdump/tools/cdump-enumstr state_types.h > $@

# We build a static libsecpk1, since we need schnorr for alpha
# (and it's not API stable yet!).
libsecp256k1.a: secp256k1/libsecp256k1.la

secp256k1/libsecp256k1.la:
	cd secp256k1 && ./autogen.sh && ./configure --enable-static=yes --enable-shared=no --enable-tests=no --enable-module-schnorr=yes --enable-module-ecdh=yes --libdir=`pwd`/..
	$(MAKE) -C secp256k1 install-exec

lightning.pb-c.c lightning.pb-c.h: lightning.proto
	$(PROTOCC) lightning.proto --c_out=.

$(TEST_PROGRAMS): % : %.o $(BITCOIN_OBJS) $(CCAN_OBJS) version.o libsecp256k1.a

ccan/config.h: ccan/tools/configurator/configurator
	$< > $@

doc/deployable-lightning.pdf: doc/deployable-lightning.lyx doc/bitcoin.bib
	lyx -E pdf $@ $<

doc/deployable-lightning.tex: doc/deployable-lightning.lyx
	lyx -E latex $@ $<

state-diagrams: doc/normal-states.svg doc/simplified-states.svg doc/error-states.svg doc/full-states.svg

%.svg: %.dot
	dot -Tsvg $< > $@ || (rm -f $@; false)

doc/simplified-states.dot: test/test_state_coverage
	test/test_state_coverage --dot --dot-simplify > $@

doc/normal-states.dot: test/test_state_coverage
	test/test_state_coverage --dot > $@

doc/error-states.dot: test/test_state_coverage
	test/test_state_coverage --dot-all --dot-include-errors > $@

doc/full-states.dot: test/test_state_coverage
	test/test_state_coverage --dot-all --dot-include-errors --dot-include-nops > $@

gen_version.h: FORCE
	@(echo "#define VERSION \"`git describe --always --dirty`\"" && echo "#define VERSION_NAME \"$(NAME)\"" && echo "#define BUILD_FEATURES \"$(FEATURES)\"") > $@.new
	@if cmp $@.new $@ >/dev/null 2>&2; then rm -f $@.new; else mv $@.new $@; fi

version.o: gen_version.h

update-ccan:
	mv ccan ccan.old
	DIR=$$(pwd)/ccan; cd ../ccan && ./tools/create-ccan-tree -a $$DIR `cd $$DIR.old/ccan && find * -name _info | sed s,/_info,, | sort` $(CCAN_NEW)
	mkdir -p ccan/tools/configurator
	cp ../ccan/tools/configurator/configurator.c ccan/tools/configurator/
	$(MAKE) ccan/config.h
	grep -v '^CCAN version:' ccan.old/README > ccan/README
	echo CCAN version: `git -C ../ccan describe` >> ccan/README
	$(RM) -r ccan.old

distclean: clean
	$(MAKE) -C secp256k1/ distclean || true
	$(RM) libsecp256k1.a

maintainter-clean: distclean
	@echo 'This command is intended for maintainers to use; it'
	@echo 'deletes files that may need special tools to rebuild.'
	$(RM) lightning.pb-c.c lightning.pb-c.h ccan/config.h gen_version.h
	$(RM) doc/deployable-lightning.pdf

clean: daemon-clean
	$(MAKE) -C secp256k1/ clean || true
	$(RM) libsecp256k1.{a,la}
	$(RM) $(PROGRAMS)
	$(RM) bitcoin/*.o *.o $(PROGRAMS:=.o) $(CCAN_OBJS)
	$(RM) doc/deployable-lightning.{aux,bbl,blg,dvi,log,out,tex}

include daemon/Makefile

ccan-tal.o: $(CCANDIR)/ccan/tal/tal.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-tal-str.o: $(CCANDIR)/ccan/tal/str/str.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-tal-path.o: $(CCANDIR)/ccan/tal/path/path.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-tal-grab_file.o: $(CCANDIR)/ccan/tal/grab_file/grab_file.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-take.o: $(CCANDIR)/ccan/take/take.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-list.o: $(CCANDIR)/ccan/list/list.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-read_write_all.o: $(CCANDIR)/ccan/read_write_all/read_write_all.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-str.o: $(CCANDIR)/ccan/str/str.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-opt.o: $(CCANDIR)/ccan/opt/opt.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-opt-helpers.o: $(CCANDIR)/ccan/opt/helpers.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-opt-parse.o: $(CCANDIR)/ccan/opt/parse.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-opt-usage.o: $(CCANDIR)/ccan/opt/usage.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-err.o: $(CCANDIR)/ccan/err/err.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-noerr.o: $(CCANDIR)/ccan/noerr/noerr.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-str-hex.o: $(CCANDIR)/ccan/str/hex/hex.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-crypto-shachain.o: $(CCANDIR)/ccan/crypto/shachain/shachain.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-crypto-sha256.o: $(CCANDIR)/ccan/crypto/sha256/sha256.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-crypto-ripemd160.o: $(CCANDIR)/ccan/crypto/ripemd160/ripemd160.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-cdump.o: $(CCANDIR)/ccan/cdump/cdump.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-strmap.o: $(CCANDIR)/ccan/strmap/strmap.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-hash.o: $(CCANDIR)/ccan/hash/hash.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-htable.o: $(CCANDIR)/ccan/htable/htable.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-ilog.o: $(CCANDIR)/ccan/ilog/ilog.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-isaac.o: $(CCANDIR)/ccan/isaac/isaac.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-isaac64.o: $(CCANDIR)/ccan/isaac/isaac64.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-time.o: $(CCANDIR)/ccan/time/time.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-timer.o: $(CCANDIR)/ccan/timer/timer.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-io-io.o: $(CCANDIR)/ccan/io/io.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-io-poll.o: $(CCANDIR)/ccan/io/poll.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-pipecmd.o: $(CCANDIR)/ccan/pipecmd/pipecmd.c
	$(CC) $(CFLAGS) -c -o $@ $<
