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

/* Bits 3-5 are used for Version in 1st byte of SNTP packet. */
#define SNTP_PACKET_VERSION_VAL                        ( 4 << 3 )

#define SNTP_PACKET_MODE_SERVER                        ( 4 )
#define SNTP_PACKET_MODE_CLIENT                        ( 3 )

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
 * @brief Test that @ref Sntp_DeserializeResponse API can detect invalid
 * SNTP response packets.
 */
void test_DeserializeResponse_Invalid_Responses( void )
{
    SntpTimestamp_t testTime = TEST_TIMESTAMP;
    SntpResponseData_t parsedData = { 0 };

    /* Clear the global buffer. */
    memset( testBuffer, 0, sizeof( testBuffer ) );

    /* Set the SNTP response packet to contain the "originate" timestamp
     * correctly, as matching the SNTP request timestamp. */
    testBuffer[ SNTP_PACKET_ORIGIN_TIMESTAMP_FIRST_BYTE_POS ] = htonl( testTime.seconds ) >> 24;       /* origin timestamp - seconds, byte 1*/
    testBuffer[ SNTP_PACKET_ORIGIN_TIMESTAMP_FIRST_BYTE_POS + 1 ] = htonl( testTime.seconds ) >> 16;   /* origin timestamp - seconds, byte 2 */
    testBuffer[ SNTP_PACKET_ORIGIN_TIMESTAMP_FIRST_BYTE_POS + 2 ] = htonl( testTime.seconds ) >> 8;    /* origin timestamp - seconds, byte 3 */
    testBuffer[ SNTP_PACKET_ORIGIN_TIMESTAMP_FIRST_BYTE_POS + 3 ] = htonl( testTime.seconds );         /* origin timestamp - seconds, byte 4 */
    testBuffer[ SNTP_PACKET_ORIGIN_TIMESTAMP_FIRST_BYTE_POS + 4 ] = htonl( testTime.fractions ) >> 24; /* origin timestamp - fractions, byte 1*/
    testBuffer[ SNTP_PACKET_ORIGIN_TIMESTAMP_FIRST_BYTE_POS + 5 ] = htonl( testTime.fractions ) >> 16; /* origin timestamp - fractions, byte 2 */
    testBuffer[ SNTP_PACKET_ORIGIN_TIMESTAMP_FIRST_BYTE_POS + 6 ] = htonl( testTime.fractions ) >> 8;  /* origin timestamp - fractions, byte 3 */
    testBuffer[ SNTP_PACKET_ORIGIN_TIMESTAMP_FIRST_BYTE_POS + 7 ] = htonl( testTime.fractions );       /* origin timestamp - fractions, byte 4 */

    /* Test with SNTP packet containing a non-server value in the "Mode" field. */
    testBuffer[ 0 ] = SNTP_PACKET_VERSION_VAL | SNTP_PACKET_MODE_CLIENT;

    /* Call the API under test. */
    TEST_ASSERT_EQUAL( SntpInvalidResponse, Sntp_DeserializeResponse( &testTime,
                                                                      &testTime,
                                                                      testBuffer,
                                                                      sizeof( testBuffer ),
                                                                      &parsedData ) );

    /* Set the Mode field to the correct value for Server. */
    testBuffer[ 0 ] = SNTP_PACKET_VERSION_VAL | SNTP_PACKET_MODE_SERVER;

    /* Corrupt the "originate" timestamp to test with an SNTP response packet that does not
     * have the "originate" timestamp matching the timestamp sent in the request. */
    testBuffer[ SNTP_PACKET_ORIGIN_TIMESTAMP_FIRST_BYTE_POS ]++;
    testBuffer[ SNTP_PACKET_ORIGIN_TIMESTAMP_FIRST_BYTE_POS + 1 ]++;

    /* Call the API under test. */
    TEST_ASSERT_EQUAL( SntpInvalidResponse, Sntp_DeserializeResponse( &testTime,
                                                                      &testTime,
                                                                      testBuffer,
                                                                      sizeof( testBuffer ),
                                                                      &parsedData ) );
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
        0 | SNTP_PACKET_VERSION_VAL | 4,                /* Leap Indicator | Version | Server mode */
        0x00,                                           /* Stratum (value 0 for KoD) */
        0x00,                                           /* Poll Interval (Ignore) */
        0x00,                                           /* Precision (Ignore) */
        0x00, 0x00, 0x00, 0x00,                         /* root delay (Ignore)*/
        0x00, 0x00, 0x00, 0x00,                         /* root dispersion (Ignore) */
        0x00, 0x00, 0x00, 0x00,                         /* KoD Code  (Will be filled with specific codes in test) */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* reference time (Ignore) */
        htonl( testTime.seconds ) >> 24,                /* origin timestamp - seconds, byte 1*/
        htonl( testTime.seconds ) >> 16,                /* origin timestamp - seconds, byte 2 */
        htonl( testTime.seconds ) >> 8,                 /* origin timestamp - seconds, byte 3 */
        htonl( testTime.seconds ),                      /* origin timestamp - seconds, byte 4 */
        htonl( testTime.fractions ) >> 24,              /* origin timestamp - fractions, byte 1*/
        htonl( testTime.fractions ) >> 16,              /* origin timestamp - fractions, byte 2 */
        htonl( testTime.fractions ) >> 8,               /* origin timestamp - fractions, byte 3 */
        htonl( testTime.fractions ),                    /* origin timestamp - fractions, byte 4 */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* receive timestamp (Ignore)*/
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  /* transmit timestamp (Ignore)*/
    };

/* Common test code for testing de-serialization of Kiss-o'-Death packet containing a specific
 * code with@ref Sntp_DeserializeResponse API. */
#define TEST_API_FOR_KOD_CODE( code, expectedStatus )                                       \
    do {                                                                                    \
        KodCodeNetworkOrder = htonl( INTEGER_VAL_OF_KOD_CODE( KOD_CODE_DENY ) );            \
        KodResponse[ SNTP_PACKET_KOD_CODE_FIRST_BYTE_POS ] = KodCodeNetworkOrder >> 24;     \
        KodResponse[ SNTP_PACKET_KOD_CODE_FIRST_BYTE_POS + 1 ] = KodCodeNetworkOrder >> 16; \
        KodResponse[ SNTP_PACKET_KOD_CODE_FIRST_BYTE_POS + 2 ] = KodCodeNetworkOrder >> 8;  \
        KodResponse[ SNTP_PACKET_KOD_CODE_FIRST_BYTE_POS + 3 ] = KodCodeNetworkOrder;       \
                                                                                            \
        /* Call API under test. */                                                          \
        TEST_ASSERT_EQUAL( expectedStatus,                                                  \
                           Sntp_DeserializeResponse( &testTime,                             \
                                                     &testTime,                             \
                                                     KodResponse,                           \
                                                     sizeof( KodResponse ),                 \
                                                     &parsedData ) );                       \
                                                                                            \
        /* Test that API has populated the output parameter with the parsed \
         * KoD code. */                                              \
        TEST_ASSERT_EQUAL( INTEGER_VAL_OF_KOD_CODE( KOD_CODE_DENY ), \
                           parsedData.rejectedResponseCode );        \
                                                                     \
    } while( 0 )

    /* Test Kiss-o'-Death server response with "DENY" code. */
    TEST_API_FOR_KOD_CODE( KOD_CODE_DENY, SntpRejectedResponseChangeServer );

    /* Test Kiss-o'-Death server response with "RSTR" code. */
    TEST_API_FOR_KOD_CODE( KOD_CODE_RSTR, SntpRejectedResponseChangeServer );

    /* Test Kiss-o'-Death server response with "RATE" code. */
    TEST_API_FOR_KOD_CODE( KOD_CODE_RATE, SntpRejectedResponseChangeServer );

    /* ***** Test de-serialization of Kiss-o'-Death server response with other codes ***** */
    TEST_API_FOR_KOD_CODE( KOD_CODE_OTHER_EXAMPLE_1, SntpRejectedResponseChangeServer );
    TEST_API_FOR_KOD_CODE( KOD_CODE_OTHER_EXAMPLE_2, SntpRejectedResponseChangeServer );
}
