/*
 * coreSNTP v1.2.1
 * Copyright (C) 2021 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/**
 * @file Sntp_CalculatePollInterval_harness.c
 * @brief Implements the proof harness for Sntp_CalculatePollInterval function.
 */

#include "core_sntp_serializer.h"

void harness()
{
    uint16_t clockFreqTolerance;
    uint16_t desiredAccuracy;
    uint32_t * pPollInterval;
    SntpStatus_t sntpStatus;

    pPollInterval = malloc( sizeof( uint32_t ) );
    sntpStatus = Sntp_CalculatePollInterval( clockFreqTolerance, desiredAccuracy, pPollInterval );

    __CPROVER_assert( ( sntpStatus == SntpErrorBadParameter || sntpStatus == SntpSuccess || sntpStatus == SntpZeroPollInterval ), "The return value is not a valid SNTP status." );
}
