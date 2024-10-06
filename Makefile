SOLANA_PERF_LIBS_REPO=https://github.com/sadeghte/solana-perf-libs.git
BUILD_DIR=solana-perf-libs
MODULE_DIR=cuda_crypt
ABSOLUTE_MODULE_DIR=$(shell realpath $(MODULE_DIR))

.PHONY: all clone build clean

all: clone build

clone:
	@if [ ! -d "$(BUILD_DIR)" ]; then \
		git clone $(SOLANA_PERF_LIBS_REPO); \
	fi

build: clone
	@export PATH=/usr/local/cuda/bin:$$PATH && \
	cd $(BUILD_DIR) && \
	make -e -j$$(nproc) && \
	make DESTDIR=$(ABSOLUTE_MODULE_DIR) install

clean:
	rm -rf $(BUILD_DIR)
