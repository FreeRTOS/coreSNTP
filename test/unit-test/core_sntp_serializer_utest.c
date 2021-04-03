/*
 * coreSNTP v1.0.0
 * Copyright (C) 2021 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
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

#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>

/* Unity include. */
#include "unity.h"

/* Backoff Algorithm library include */
#include "core_sntp_serializer.h"

static const SntpTime_t testTime =
{
    .seconds      = UINT32_MAX,
    .microseconds = 1000
};

static uint8_t testBuffer[ SNTP_REQUEST_RESPONSE_MINIMUM_PACKET_SIZE ];

/* ============================   UNITY FIXTURES ============================ */

/* / * Called before each test method. * / */
/* void setUp() */
/* { */
/*     / * Initialize context. * / */
/*     BackoffAlgorithm_InitializeParams( &retryParams, */
/*                                        TEST_BACKOFF_BASE_VALUE, */
/*                                        TEST_BACKOFF_MAX_VALUE, */
/*                                        TEST_MAX_ATTEMPTS ); */
/* } */

/* / * Called after each test method. * / */
/* void tearDown() */
/* { */
/*     testRandomVal = 0; */
/*     BackoffAlgorithmStatus = BackoffAlgorithmSuccess; */
/*     nextBackoff = 0; */
/* } */

/* Called at the beginning of the whole suite. */
void suiteSetUp()
{
}

/* Called at the end of the whole suite. */
int suiteTearDown( int numFailures )
{
    return numFailures;
}

/* ========================================================================== */

/**
 * @brief Test @ref Sntp_SerializeRequest with invalid parameters.
 */
void test_SerializeRequest_InvalidParams( void )
{
    /* Pass invalid time object. */
    TEST_ASSERT_EQUAL( SntpErrorBadParameter,
                       Sntp_SerializeRequest( NULL,
                                              ( rand() % UINT32_MAX ),
                                              testBuffer,
                                              sizeof( testBuffer ) ) );

    /* Pass invalid buffer. */
    TEST_ASSERT_EQUAL( SntpErrorBadParameter,
                       Sntp_SerializeRequest( &testTime,
                                              ( rand() % UINT32_MAX ),
                                              NULL,
                                              sizeof( testBuffer ) ) );

    /* Pass a buffer size less than 48 bytes of minimum SNTP packet size. */
    TEST_ASSERT_EQUAL( SntpErrorInsufficientSpace,
                       Sntp_SerializeRequest( &testTime,
                                              ( rand() % UINT32_MAX ),
                                              testBuffer,
                                              1 ) );
}

/**
 * @brief Test @ref Sntp_SerializeRequest with invalid parameters.
 */
void test_SerializeRequest_NominalCase( void )
{
    const uint32_t randomVal = 0xAABBCCDD;
    const uint32_t expectedTxTimeFraction = ( ( testTime.microseconds * 4295 ) | ( randomVal >> 16 ) );

    uint8_t expectedSerialization[ SNTP_REQUEST_RESPONSE_MINIMUM_PACKET_SIZE ] =
    {
        0x00 /* Leap Indicator */ | 0x20 /* Version */ | 0x03, /* Client Mode */
        0x00,                                                  /* stratum */
        0x00,                                                  /* poll interval */
        0x00,                                                  /* precision */
        0x00,                                                  /* root delay */
        0x00,                                                  /* root dispersion */
        0x00,                                                  /* reference ID */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,        /* reference time */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,        /* origin timestamp */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,        /* receive timestamp */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00         /* transmit timestamp */
    };

    /* Update the expected transmit timestamp value. */
    uint32_t * pTransmitTimePtr = ( uint32_t * ) ( &expectedSerialization[ SNTP_REQUEST_RESPONSE_MINIMUM_PACKET_SIZE - 8 ] );

    *pTransmitTimePtr = htonl( testTime.seconds );
    *( ++pTransmitTimePtr ) = htonl( expectedTxTimeFraction );


    /* Call the API under test. */
    TEST_ASSERT_EQUAL( SntpSuccess,
                       Sntp_SerializeRequest( &testTime,
                                              randomVal,
                                              testBuffer,
                                              sizeof( testBuffer ) ) );

    /* Validate that serialization operation by the API. */
    TEST_ASSERT_EQUAL_UINT8_ARRAY( expectedSerialization,
                                   testBuffer,
                                   SNTP_REQUEST_RESPONSE_MINIMUM_PACKET_SIZE );
}
