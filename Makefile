# Builds the host benchmark and rejection harnesses against the bundled ascon-c.
#
#   make            build everything for the default implementation (opt64)
#   make run        build, then write the CSVs into results/
#   make IMPL=ref   use another ascon-c implementation (ref, opt64, opt64_lowsize, ...)
#
# OpenSSL is found with pkg-config, falling back to Homebrew's openssl@3.

CC      = clang
CFLAGS  ?= -O3
IMPL    ?= opt64
ASCON   ?= ascon-c
OUT     ?= build
RESULTS ?= results

AEAD_DIR := $(ASCON)/crypto_aead/asconaead128/$(IMPL)
HASH_DIR := $(ASCON)/crypto_hash/asconhash256/$(IMPL)

OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null || echo -I$$(brew --prefix openssl@3 2>/dev/null)/include)
OPENSSL_LIBS   := $(shell pkg-config --libs openssl 2>/dev/null || echo -L$$(brew --prefix openssl@3 2>/dev/null)/lib -lcrypto)

BINS := $(OUT)/bench_aead_$(IMPL) $(OUT)/bench_hash_$(IMPL) \
        $(OUT)/aead_negative_tests_$(IMPL) $(OUT)/bench_competitor_aead

.PHONY: all run clean

all: $(BINS)

$(ASCON)/LICENSE: ascon-c.zip
	unzip -qo ascon-c.zip -x '__MACOSX/*'
	touch $@

$(OUT):
	mkdir -p $@

$(OUT)/bench_aead_$(IMPL): benchmark_harness_aead.c $(ASCON)/LICENSE | $(OUT)
	$(CC) $(CFLAGS) -I$(AEAD_DIR) -I$(ASCON)/tests $(AEAD_DIR)/*.c $< -o $@

$(OUT)/aead_negative_tests_$(IMPL): aead_negative_tests.c $(ASCON)/LICENSE | $(OUT)
	$(CC) $(CFLAGS) -I$(AEAD_DIR) -I$(ASCON)/tests $(AEAD_DIR)/*.c $< -o $@

$(OUT)/bench_hash_$(IMPL): benchmark_harness_hash.c $(ASCON)/LICENSE | $(OUT)
	$(CC) $(CFLAGS) -I$(HASH_DIR) -I$(ASCON)/tests $(HASH_DIR)/*.c $< -o $@

$(OUT)/bench_competitor_aead: benchmark_harness_competitor_aead.c | $(OUT)
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) $< $(OPENSSL_LIBS) -o $@

run: all
	mkdir -p $(RESULTS)
	$(OUT)/bench_aead_$(IMPL) > $(RESULTS)/aead_$(IMPL).csv
	$(OUT)/bench_hash_$(IMPL) > $(RESULTS)/hash_$(IMPL).csv
	$(OUT)/aead_negative_tests_$(IMPL) > $(RESULTS)/aead_negative_tests.csv
	$(OUT)/bench_competitor_aead > $(RESULTS)/competitor_aead_openssl.csv

clean:
	rm -rf $(OUT) $(RESULTS)
