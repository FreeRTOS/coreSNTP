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

/* Standard includes. */
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

/* POSIX include. */
#include <arpa/inet.h>

/* Unity include. */
#include "unity.h"

/* coreSNTP Serializer API include */
#include "core_sntp_serializer.h"

#define TEST_TIMESTAMP         \
    {                          \
        .seconds = UINT32_MAX, \
        .fractions = 1000      \
    }

/* The word positions of SNTP packet fields in the 12-word (or 48 bytes)
 * sized packet format. */
#define SNTP_PACKET_KOD_CODE_FIRST_BYTE_POS            ( 12 )
#define SNTP_PACKET_ORIGIN_TIMESTAMP_FIRST_BYTE_POS    ( 24 )

/* ASCII string codes that a server can send in a Kiss-o'-Death response. */
#define KOD_CODE_DENY                                  "DENY"
#define KOD_CODE_RSTR                                  "RSTR"
#define KOD_CODE_RATE                                  "RATE"
#define KOD_CODE_OTHER_EXAMPLE_1                       "AUTH"
#define KOD_CODE_OTHER_EXAMPLE_2                       "CRYP"

#define INTEGER_VAL_OF_KOD_CODE( codePtr )                 \
    ( ( uint32_t ) ( ( ( uint32_t ) codePtr[ 0 ] << 24 ) | \
                     ( ( uint32_t ) codePtr[ 1 ] << 16 ) | \
                     ( ( uint32_t ) codePtr[ 2 ] << 8 ) |  \
                     ( ( uint32_t ) codePtr[ 3 ] ) ) )

static uint8_t testBuffer[ SNTP_REQUEST_RESPONSE_MINIMUM_PACKET_SIZE ];

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
    TEST_ASSERT_EQUAL( SntpErrorInsufficientSpace,
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

    *pTransmitTimePtr = htonl( expectedTxTime.seconds );
    *( ++pTransmitTimePtr ) = htonl( expectedTxTime.fractions );


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

    /* Check that the request timestamp object has been updated with the random value. */
    TEST_ASSERT_EQUAL( 0, memcmp( &expectedTxTime,
                                  &testTime,
                                  sizeof( SntpTimestamp_t ) ) );
}


/**
 * @brief Test @ref Sntp_DeserializeResponse with invalid parameters.
 */
void test_DeserializeResponse_InvalidParams( void )
{
    SntpTimestamp_t testTime = TEST_TIMESTAMP;
    SntpResponseData_t responseData;

    /* Pass invalid time objects. */
    TEST_ASSERT_EQUAL( SntpErrorBadParameter,
                       Sntp_DeserializeResponse( NULL,
                                                 &testTime,
                                                 testBuffer,
                                                 sizeof( testBuffer ),
                                                 &responseData ) );
    TEST_ASSERT_EQUAL( SntpErrorBadParameter,
                       Sntp_DeserializeResponse( &testTime,
                                                 NULL,
                                                 testBuffer,
                                                 sizeof( testBuffer ),
                                                 &responseData ) );

    /* Pass invalid buffer. */
    TEST_ASSERT_EQUAL( SntpErrorBadParameter,
                       Sntp_DeserializeResponse( &testTime,
                                                 &testTime,
                                                 NULL,
                                                 sizeof( testBuffer ),
                                                 &responseData ) );

    /* Pass a buffer size less than 48 bytes of minimum SNTP packet size. */
    TEST_ASSERT_EQUAL( SntpErrorInsufficientSpace,
                       Sntp_DeserializeResponse( &testTime,
                                                 &testTime,
                                                 testBuffer,
                                                 sizeof( testBuffer ) / 2,
                                                 &responseData ) );

    /* Pass invalid output parameter. */
    TEST_ASSERT_EQUAL( SntpErrorBadParameter,
                       Sntp_DeserializeResponse( &testTime,
                                                 &testTime,
                                                 testBuffer,
                                                 sizeof( testBuffer ),
                                                 NULL ) );
}

/**
 * @brief Test @ref Sntp_DeserializeResponse API to de-serialize Kiss-o'-Death
 * responses from SNTP server.
 *
 * The API should return an error code appropriate for the Kiss-o'-Death code
 * and update the member of output parameter to point the ASCII string code
 * in the response packet.
 */
void test_DeserializeResponse_KoD_packets( void )
{
    /* Use same value for request and response times, as API should not process
     * them for Kiss-o'-Death response packets. */
    SntpTimestamp_t testTime = TEST_TIMESTAMP;
    SntpResponseData_t parsedData = { 0 };
    uint32_t KodCodeNetworkOrder = 0;
    /* SNTP packet representing a Kiss-o'-Death message. */
    uint8_t KodResponse[] =
    {
        0 | ( 4 << 3 ) | 4,                                /* Leap Indicator | Version | Server mode */
        0x00,                                              /* Stratum (value 0 for KoD) */
        0x00,                                              /* Poll Interval (Ignore) */
        0x00,                                              /* Precision (Ignore) */
        0x00, 0x00, 0x00, 0x00,                            /* root delay (Ignore)*/
        0x00, 0x00, 0x00, 0x00,                            /* root dispersion (Ignore) */
        0x00, 0x00, 0x00, 0x00,                            /* KoD Code  (Will be filled with specific codes in test) */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    /* reference time (Ignore) */
        htonl( testTime.seconds ) >> 24,                   /* origin timestamp - seconds, byte 1*/
        ( uint8_t ) ( htonl( testTime.seconds ) >> 16 ),   /* origin timestamp - seconds, byte 2 */
        ( uint8_t ) ( htonl( testTime.seconds ) >> 8 ),    /* origin timestamp - seconds, byte 3 */
        ( uint8_t ) htonl( testTime.seconds ),             /* origin timestamp - seconds, byte 4 */
        htonl( testTime.fractions ) >> 24,                 /* origin timestamp - fractions, byte 1*/
        ( uint8_t ) ( htonl( testTime.fractions ) >> 16 ), /* origin timestamp - fractions, byte 2 */
        ( uint8_t ) ( htonl( testTime.fractions ) >> 8 ),  /* origin timestamp - fractions, byte 3 */
        ( uint8_t ) htonl( testTime.fractions ),           /* origin timestamp - fractions, byte 4 */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    /* receive timestamp (Ignore)*/
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00     /* transmit timestamp (Ignore)*/
    };

    /* Test Kiss-o'-Death server response with "DENY" code. */
    KodCodeNetworkOrder = htonl( INTEGER_VAL_OF_KOD_CODE( KOD_CODE_DENY ) );
    KodResponse[ SNTP_PACKET_KOD_CODE_FIRST_BYTE_POS ] = KodCodeNetworkOrder >> 24;
    KodResponse[ SNTP_PACKET_KOD_CODE_FIRST_BYTE_POS + 1 ] = KodCodeNetworkOrder >> 16;
    KodResponse[ SNTP_PACKET_KOD_CODE_FIRST_BYTE_POS + 2 ] = KodCodeNetworkOrder >> 8;
    KodResponse[ SNTP_PACKET_KOD_CODE_FIRST_BYTE_POS + 3 ] = KodCodeNetworkOrder;

    /* Call API under test. */
    TEST_ASSERT_EQUAL( SntpRejectedResponseChangeServer,
                       Sntp_DeserializeResponse( &testTime,
                                                 &testTime,
                                                 KodResponse,
                                                 sizeof( KodResponse ),
                                                 &parsedData ) );

    /* Test that API has populated the output parameter with the parsed
     * KoD code. */

    /* Test Kiss-o'-Death server response with "RSTR" code. */
    KodCodeNetworkOrder = htonl( INTEGER_VAL_OF_KOD_CODE( KOD_CODE_RSTR ) );
    KodResponse[ SNTP_PACKET_KOD_CODE_FIRST_BYTE_POS ] = KodCodeNetworkOrder >> 24;
    KodResponse[ SNTP_PACKET_KOD_CODE_FIRST_BYTE_POS + 1 ] = KodCodeNetworkOrder >> 16;
    KodResponse[ SNTP_PACKET_KOD_CODE_FIRST_BYTE_POS + 2 ] = KodCodeNetworkOrder >> 8;
    KodResponse[ SNTP_PACKET_KOD_CODE_FIRST_BYTE_POS + 3 ] = KodCodeNetworkOrder;

    /* Call API under test. */
    TEST_ASSERT_EQUAL( SntpRejectedResponseChangeServer,
                       Sntp_DeserializeResponse( &testTime,
                                                 &testTime,
                                                 KodResponse,
                                                 sizeof( KodResponse ),
                                                 &parsedData ) );

    /* Test Kiss-o'-Death server response with "RATE" code. */
    KodCodeNetworkOrder = htonl( INTEGER_VAL_OF_KOD_CODE( KOD_CODE_RATE ) );
    KodResponse[ SNTP_PACKET_KOD_CODE_FIRST_BYTE_POS ] = KodCodeNetworkOrder >> 24;
    KodResponse[ SNTP_PACKET_KOD_CODE_FIRST_BYTE_POS + 1 ] = KodCodeNetworkOrder >> 16;
    KodResponse[ SNTP_PACKET_KOD_CODE_FIRST_BYTE_POS + 2 ] = KodCodeNetworkOrder >> 8;
    KodResponse[ SNTP_PACKET_KOD_CODE_FIRST_BYTE_POS + 3 ] = KodCodeNetworkOrder;

    /* Call API under test. */
    TEST_ASSERT_EQUAL( SntpRejectedResponseRetryWithBackoff,
                       Sntp_DeserializeResponse( &testTime,
                                                 &testTime,
                                                 KodResponse,
                                                 sizeof( KodResponse ),
                                                 &parsedData ) );

    /* ***** Test de-serialization of Kiss-o'-Death server response with other codes ***** */


    KodCodeNetworkOrder = htonl( INTEGER_VAL_OF_KOD_CODE( KOD_CODE_OTHER_EXAMPLE_1 ) );
    KodResponse[ SNTP_PACKET_KOD_CODE_FIRST_BYTE_POS ] = KodCodeNetworkOrder >> 24;
    KodResponse[ SNTP_PACKET_KOD_CODE_FIRST_BYTE_POS + 1 ] = KodCodeNetworkOrder >> 16;
    KodResponse[ SNTP_PACKET_KOD_CODE_FIRST_BYTE_POS + 2 ] = KodCodeNetworkOrder >> 8;
    KodResponse[ SNTP_PACKET_KOD_CODE_FIRST_BYTE_POS + 3 ] = KodCodeNetworkOrder;

    /* Call API under test. */
    TEST_ASSERT_EQUAL( SntpRejectedResponseCodeOther,
                       Sntp_DeserializeResponse( &testTime,
                                                 &testTime,
                                                 KodResponse,
                                                 sizeof( KodResponse ),
                                                 &parsedData ) );


    KodCodeNetworkOrder = htonl( INTEGER_VAL_OF_KOD_CODE( KOD_CODE_OTHER_EXAMPLE_2 ) );
    KodResponse[ SNTP_PACKET_KOD_CODE_FIRST_BYTE_POS ] = KodCodeNetworkOrder >> 24;
    KodResponse[ SNTP_PACKET_KOD_CODE_FIRST_BYTE_POS + 1 ] = KodCodeNetworkOrder >> 16;
    KodResponse[ SNTP_PACKET_KOD_CODE_FIRST_BYTE_POS + 2 ] = KodCodeNetworkOrder >> 8;
    KodResponse[ SNTP_PACKET_KOD_CODE_FIRST_BYTE_POS + 3 ] = KodCodeNetworkOrder;

    /* Call API under test. */
    TEST_ASSERT_EQUAL( SntpRejectedResponseCodeOther,
                       Sntp_DeserializeResponse( &testTime,
                                                 &testTime,
                                                 KodResponse,
                                                 sizeof( KodResponse ),
                                                 &parsedData ) );
}
