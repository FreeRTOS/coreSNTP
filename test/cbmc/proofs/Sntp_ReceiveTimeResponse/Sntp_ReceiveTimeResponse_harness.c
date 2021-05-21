// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/*
 * Insert copyright notice
 */

/**
 * @file Sntp_ReceiveTimeResponse_harness.c
 * @brief Implements the proof harness for Sntp_ReceiveTimeResponse function.
 */

#include <stddef.h>
#include "core_sntp_cbmc_state.h"
#include "core_sntp_client.h"

void harness()
{
  SntpContext_t * pContext;
  uint32_t blockTimeMs;
  SntpStatus_t sntpStatus;

  pContext=allocateCoreSntpContext();
  sntpStatus=Sntp_ReceiveTimeResponse( pContext, blockTimeMs);

   __CPROVER_assert( ( sntpStatus == SntpErrorBadParameter || sntpStatus == SntpSuccess ||
                        sntpStatus == SntpNoResponseReceived || sntpStatus == SntpErrorChangeServer ||
                        sntpStatus == SntpRejectedResponse || sntpStatus == SntpErrorResponseTimeout ||
                        sntpStatus == SntpErrorNetworkFailure ), "The return value is not a valid SNTP Status" );
}
