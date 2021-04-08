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

/* coreSNTP API include */
#include "core_sntp_serializer.h"

#define TEST_TIMESTAMP         \
    {                          \
        .seconds = UINT32_MAX, \
        .fractions = 1000      \
    }

static uint8_t testBuffer[ SNTP_PACKET_MINIMUM_SIZE ];

/* ============================   UNITY FIXTURES ============================ */

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
    SntpTimestamp_t testTime = TEST_TIMESTAMP;

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
    TEST_ASSERT_EQUAL( SntpErrorBufferTooSmall,
                       Sntp_SerializeRequest( &testTime,
                                              ( rand() % UINT32_MAX ),
                                              testBuffer,
                                              1 ) );
}

/**
 * @brief Validate the serialization operation of the @ref Sntp_SerializeRequest API.
 */
void test_SerializeRequest_NominalCase( void )
{
    SntpTimestamp_t testTime = TEST_TIMESTAMP;
    const uint32_t randomVal = 0xAABBCCDD;

    /* Expected transmit timestamp in the SNTP request packet. */
    const SntpTimestamp_t expectedTxTime =
    {
        .seconds   = testTime.seconds,
        .fractions = ( testTime.fractions | ( randomVal >> 16 ) )
    };

    /* The expected serialization of the SNTP request packet. */
    uint8_t expectedSerialization[ SNTP_PACKET_MINIMUM_SIZE ] =
    {
        0x00 /* Leap Indicator */ | 0x20 /* Version */ | 0x03, /* Client Mode */
        0x00,                                                  /* stratum */
        0x00,                                                  /* poll interval */
        0x00,                                                  /* precision */
        0x00, 0x00, 0x00, 0x00,                                /* root delay */
        0x00, 0x00, 0x00, 0x00,                                /* root dispersion */
        0x00, 0x00, 0x00, 0x00,                                /* reference ID */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,        /* reference time */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,        /* origin timestamp */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,        /* receive timestamp */
        htonl( expectedTxTime.seconds ) >> 24,                 /* transmit timestamp - seconds, byte 1 */
        htonl( expectedTxTime.seconds ) >> 16,                 /* transmit timestamp - seconds, byte 2 */
        htonl( expectedTxTime.seconds ) >> 8,                  /* transmit timestamp - seconds, byte 3 */
        htonl( expectedTxTime.seconds ),                       /* transmit timestamp - seconds, byte 4 */
        htonl( expectedTxTime.fractions ) >> 24,               /* transmit timestamp - fractions, byte 1 */
        htonl( expectedTxTime.fractions ) >> 16,               /* transmit timestamp - fractions, byte 2 */
        htonl( expectedTxTime.fractions ) >> 8,                /* transmit timestamp - fractions, byte 3 */
        htonl( expectedTxTime.fractions ),                     /* transmit timestamp - fractions, byte 4 */
    };

    /* Call the API under test. */
    TEST_ASSERT_EQUAL( SntpSuccess,
                       Sntp_SerializeRequest( &testTime,
                                              randomVal,
                                              testBuffer,
                                              sizeof( testBuffer ) ) );

    /* Validate that serialization operation by the API. */
    TEST_ASSERT_EQUAL_UINT8_ARRAY( expectedSerialization,
                                   testBuffer,
                                   SNTP_PACKET_MINIMUM_SIZE );

    /* Check that the request timestamp object has been updated with the random value. */
    TEST_ASSERT_EQUAL( 0, memcmp( &expectedTxTime,
                                  &testTime,
                                  sizeof( SntpTimestamp_t ) ) );
}
