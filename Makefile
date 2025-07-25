# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation

# binary name
APP = DDD

# all source are stored in SRCS-y
SRCS-y := main.c

PKGCONF ?= pkg-config

# Build using pkg-config variables if possible
ifneq ($(shell $(PKGCONF) --exists libdpdk && echo 0),0)
$(error "no installation of DPDK found")
endif

all: shared
.PHONY: shared static
shared: build/$(APP)-shared
	ln -sf $(APP)-shared build/$(APP)
static: build/$(APP)-static
	ln -sf $(APP)-static build/$(APP)

PC_FILE := $(shell $(PKGCONF) --path libdpdk 2>/dev/null)
CFLAGS += -pthread  -O2 $(shell $(PKGCONF) --cflags libdpdk) 
# Add flag to allow experimental API as l2fwd uses rte_ethdev_set_ptype API
CFLAGS += -Wno-attributes  -DALLOW_EXPERIMENTAL_API 
LDFLAGS_SHARED = $(shell $(PKGCONF) --libs libdpdk)
LDFLAGS_STATIC = $(shell $(PKGCONF) --static --libs libdpdk)
# Add math library
CFLAGS += -lm -Wl,--copy-dt-needed-entries
# GDB debugging symbols
CFLAGS += -g 
# nDPI
LIBNDPI=/opt/nDPI/src/lib/libndpi.a
LIBS=$(LIBNDPI) @PCAP_LIB@ @ADDITIONAL_LIBS@ @LIBS@ @GPROF_LIBS@
HEADERS=db_scan.h reader_utils.h /opt/nDPI/src/include/ndpi_api.h /opt/nDPI/src/include/ndpi_typedefs.h /opt/nDPI/src/include/ndpi_protocol_ids.h 
CFLAGS += -fPIC -DPIC
CFLAGS += -I/opt/nDPI/src/include  -lpcap 

CFLAGS +=  -W -Wall -Wno-attributes -Wno-strict-prototypes -Wno-missing-prototypes -Wno-missing-declarations -Wno-unused-parameter -I /opt/nDPI/src/include  -DUSE_DPDK -Wno-unused-function -D_DEFAULT_SOURCE=1 -D_GNU_SOURCE=1
LDLIBS = $(LIBNDPI) -lpthread 
# SRCS-y := reader_util.c


ifeq ($(MAKECMDGOALS),static)
# check for broken pkg-config
ifeq ($(shell echo $(LDFLAGS_STATIC) | grep 'whole-archive.*l:lib.*no-whole-archive'),)
$(warning "pkg-config output list does not contain drivers between 'whole-archive'/'no-whole-archive' flags.")
$(error "Cannot generate statically-linked binaries with this version of pkg-config")
endif
endif

build/$(APP)-shared: $(SRCS-y) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCS-y) /opt/nDPI/src/lib/libndpi.a  -o $@ $(LDFLAGS) $(LDFLAGS_SHARED)

build/$(APP)-static: $(SRCS-y) Makefile $(PC_FILE) $(HEADERS) | build
	$(CC) $(CFLAGS) $(SRCS-y)  /opt/nDPI/src/lib/libndpi.a -o $@ $(LDFLAGS) $(LDFLAGS_STATIC)

build:
	@mkdir -p $@


.PHONY: clean
clean:
	rm -f build/$(APP) build/$(APP)-static build/$(APP)-shared
	test -d build && rmdir -p build || true
