#!/usr/bin/make -f

#define variables
EPID_ROOT_DIR = ../epid-sdk/
IPP_API_INCLUDE_DIR = $(EPID_ROOT_DIR)/ext/ipp/include

INCLUDE_DIR = ./
UTIL_INCLUDE_DIR = ../
SRC = $(wildcard ./*.c)
OBJ = $(SRC:.c=.o)
EXE = ./signmsg

EPID_LIB_DIR = $(EPID_ROOT_DIR)/lib/posix-x86_64/
LIB_UTIL_DIR = ../util/
LIB_DROPT_DIR = $(EPID_ROOT_DIR)/ext/dropt/src
LIB_IPPCP_DIR = $(EPID_ROOT_DIR)/ext/ipp/sources/ippcp/src
LIB_IPPCPEPID_DIR = $(EPID_ROOT_DIR)/ext/ipp/sources/ippcpepid/src
LIB_MEMBER_DIR = $(EPID_ROOT_DIR)/include/epid/member
LIB_COMMON_DIR = $(EPID_ROOT_DIR)/epid/common

#set linker flags
LDFLAGS += -L$(LIB_UTIL_DIR) \
	-L$(LIB_DROPT_DIR) \
	-L$(LIB_IPPCP_DIR) \
	-L$(LIB_COMMON_DIR) \
	-L$(LIB_IPPCPEPID_DIR) \
	-lcommon -lippcpepid \
	-lippcp -lutil -ldropt

all: $(EXE)

$(EXE): $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) -L$(EPID_LIB_DIR) -lmember $(LDFLAGS)

$(OBJ): %.o: %.c
	$(CC) -o $@ $(CFLAGS) -I$(LIB_UTIL_DIR)/../.. \
			-I$(LIB_DROPT_DIR)/../include \
			-I$(LIB_MEMBER_DIR)/../.. \
			-I$(INCLUDE_DIR) \
			-I$(UTIL_INCLUDE_DIR) \
			-I$(IPP_API_INCLUDE_DIR) -c $^

clean:
	rm -f $(OBJ) \
		$(EXE) \
		sig.dat
