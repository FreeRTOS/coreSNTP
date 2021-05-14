# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

HARNESS_ENTRY = harness
HARNESS_FILE = Sntp_SendTimeRequest_harness

# Please see test/cbmc/stubs/core_sntp_stubs.c for
# more information on MAX_NETWORK_SEND_TRIES.
MAX_NETWORK_SEND_TRIES=3

# This should be a unique identifier for this proof, and will appear on the
# Litani dashboard. It can be human-readable and contain spaces if you wish.
PROOF_UID = Sntp_SendTimeRequest

DEFINES +=
INCLUDES +=

REMOVE_FUNCTION_BODY +=Sntp_SerializeRequest
UNWINDSET +=__CPROVER_file_local_core_sntp_client_c_sendSntpPacket.0:$(MAX_NETWORK_SEND_TRIES)

PROOF_SOURCES += $(SRCDIR)/test/cbmc/sources/core_sntp_cbmc_state.c
PROOF_SOURCES += $(SRCDIR)/test/cbmc/stubs/core_sntp_stubs.c
PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE).c
PROJECT_SOURCES += $(SRCDIR)/source/core_sntp_client.c

include ../Makefile.common
