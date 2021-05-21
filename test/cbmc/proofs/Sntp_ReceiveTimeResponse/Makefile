# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

HARNESS_ENTRY = harness
HARNESS_FILE = Sntp_ReceiveTimeResponse_harness

# Please see test/cbmc/stubs/core_sntp_stubs.c for
# more information on MAX_NETWORK_RECV_TRIES.
MAX_NETWORK_RECV_TRIES=5

# Maximum number of sntp time servers
MAX_NO_OF_SERVERS=5

# Maximum number of attempts in outer loop of Sntp_ReceiveTimeResponse needed to receive a response from server.
MAX_ITERATIONS_RECEIVE_RESPONSE=2

# This should be a unique identifier for this proof, and will appear on the
# Litani dashboard. It can be human-readable and contain spaces if you wish.
PROOF_UID = Sntp_ReceiveTimeResponse

DEFINES +=-DMAX_NO_OF_SERVERS=$(MAX_NO_OF_SERVERS)
INCLUDES +=

REMOVE_FUNCTION_BODY +=Sntp_DeserializeResponse
UNWINDSET +=__CPROVER_file_local_core_sntp_client_c_receiveSntpResponse.0:$(MAX_NETWORK_RECV_TRIES)
UNWINDSET +=__CPROVER_file_local_core_sntp_client_c_Sntp_ReceiveTimeResponse.0:$(MAX_ITERATIONS_RECEIVE_RESPONSE)
UNWINDSET +=allocateCoreSntpContext.0:$(shell expr $(MAX_NO_OF_SERVERS) + 1 )


PROOF_SOURCES += $(SRCDIR)/test/cbmc/sources/core_sntp_cbmc_state.c
PROOF_SOURCES += $(SRCDIR)/test/cbmc/stubs/core_sntp_stubs.c
PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE).c
PROJECT_SOURCES += $(SRCDIR)/source/core_sntp_client.c

include ../Makefile.common
