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
#define SNTP_PACKET_VERSION_VAL                    ( 4 << 3 )

/* Values for "Mode" field in an SNTP packet. */
#define SNTP_PACKET_MODE_SERVER                    ( 4 )
#define SNTP_PACKET_MODE_CLIENT                    ( 3 )

/* The byte positions of SNTP packet fields in the 48 bytes sized
 * packet format. */
#define SNTP_PACKET_STRATUM_BYTE_POS               ( 1 )
#define SNTP_PACKET_KOD_CODE_FIRST_BYTE_POS        ( 12 )
#define SNTP_PACKET_ORIGIN_TIME_FIRST_BYTE_POS     ( 24 )
#define SNTP_PACKET_RX_TIMESTAMP_FIRST_BYTE_POS    ( 32 )
#define SNTP_PACKET_TX_TIMESTAMP_FIRST_BYTE_POS    ( 40 )

/* Values of "Stratum" field in an SNTP packet. */
#define SNTP_PACKET_STRATUM_KOD                    ( 0 )
#define SNTP_PACKET_STRATUM_SECONDARY_SERVER       ( 15 )

/* ASCII string codes that a server can send in a Kiss-o'-Death response. */
#define KOD_CODE_DENY                              "DENY"
#define KOD_CODE_RSTR                              "RSTR"
#define KOD_CODE_RATE                              "RATE"
#define KOD_CODE_OTHER_EXAMPLE_1                   "AUTH"
#define KOD_CODE_OTHER_EXAMPLE_2                   "CRYP"

#define INTEGER_VAL_OF_KOD_CODE( codePtr )                 \
    ( ( uint32_t ) ( ( ( uint32_t ) codePtr[ 0 ] << 24 ) | \
                     ( ( uint32_t ) codePtr[ 1 ] << 16 ) | \
                     ( ( uint32_t ) codePtr[ 2 ] << 8 ) |  \
                     ( ( uint32_t ) codePtr[ 3 ] ) ) )

static uint8_t testBuffer[ SNTP_PACKET_MINIMUM_SIZE ];

/* ============================ Helper Functions ============================ */

void addTimestampToResponseBuffer( SntpTimestamp_t * pTime,
                                   uint8_t * pResponseBuffer,
                                   size_t startingPos )
{
    /* Convert the request time into network byte order to use to fill in buffer. */
    uint32_t secsInNetOrder = htonl( pTime->seconds );
    uint32_t fracsInNetOrder = htonl( pTime->fractions );

    pResponseBuffer[ startingPos ] = secsInNetOrder >> 24;      /* seconds, byte 1*/
    pResponseBuffer[ startingPos + 1 ] = secsInNetOrder >> 16;  /* seconds, byte 2 */
    pResponseBuffer[ startingPos + 2 ] = secsInNetOrder >> 8;   /* seconds, byte 3 */
    pResponseBuffer[ startingPos + 3 ] = secsInNetOrder;        /* seconds, byte 4 */
    pResponseBuffer[ startingPos + 4 ] = fracsInNetOrder >> 24; /* fractions, byte 1*/
    pResponseBuffer[ startingPos + 5 ] = fracsInNetOrder >> 16; /* fractions, byte 2 */
    pResponseBuffer[ startingPos + 6 ] = fracsInNetOrder >> 8;  /* fractions, byte 3 */
    pResponseBuffer[ startingPos + 7 ] = fracsInNetOrder;       /* fractions, byte 4 */
}

void fillValidSntpResponseData( uint8_t * pBuffer,
                                SntpTimestamp_t * pRequestTime )
{
    /* Clear the buffer. */
    memset( pBuffer, 0, SNTP_PACKET_MINIMUM_SIZE );

    /* Set the "Version" and "Mode" fields in the first byte of SNTP packet. */
    pBuffer[ 0 ] = SNTP_PACKET_VERSION_VAL | SNTP_PACKET_MODE_SERVER;

    /* Set the SNTP response packet to contain the "originate" timestamp
     * correctly, as matching the SNTP request timestamp. */
    addTimestampToResponseBuffer( pRequestTime,
                                  pBuffer,
                                  SNTP_PACKET_ORIGIN_TIME_FIRST_BYTE_POS );

    /* Set the "Stratum" byte in the response packet to represent a
     * secondary NTP server. */
    pBuffer[ SNTP_PACKET_STRATUM_BYTE_POS ] = SNTP_PACKET_STRATUM_SECONDARY_SERVER;
}

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
    TEST_ASSERT_EQUAL( SntpErrorBufferTooSmall,
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

    /* Fill buffer with general SNTP response data. */
    fillValidSntpResponseData( testBuffer, &testTime );

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
    testBuffer[ SNTP_PACKET_ORIGIN_TIME_FIRST_BYTE_POS ]++;
    testBuffer[ SNTP_PACKET_ORIGIN_TIME_FIRST_BYTE_POS + 1 ]++;

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

    /* Populate the buffer with a valid SNTP response before converting it
     * into a Kiss-o'-Death message. */
    fillValidSntpResponseData( testBuffer, &testTime );

    /* Update the "Stratum" field in the buffer to make the packet a Kiss-o'-Death message. */
    testBuffer[ SNTP_PACKET_STRATUM_BYTE_POS ] = SNTP_PACKET_STRATUM_KOD;

/* Common test code for testing de-serialization of Kiss-o'-Death packet containing a specific
 * code with@ref Sntp_DeserializeResponse API. */
#define TEST_API_FOR_KOD_CODE( code, expectedStatus )                                      \
    do {                                                                                   \
        KodCodeNetworkOrder = htonl( INTEGER_VAL_OF_KOD_CODE( KOD_CODE_DENY ) );           \
        testBuffer[ SNTP_PACKET_KOD_CODE_FIRST_BYTE_POS ] = KodCodeNetworkOrder >> 24;     \
        testBuffer[ SNTP_PACKET_KOD_CODE_FIRST_BYTE_POS + 1 ] = KodCodeNetworkOrder >> 16; \
        testBuffer[ SNTP_PACKET_KOD_CODE_FIRST_BYTE_POS + 2 ] = KodCodeNetworkOrder >> 8;  \
        testBuffer[ SNTP_PACKET_KOD_CODE_FIRST_BYTE_POS + 3 ] = KodCodeNetworkOrder;       \
                                                                                           \
        /* Call API under test. */                                                         \
        TEST_ASSERT_EQUAL( expectedStatus,                                                 \
                           Sntp_DeserializeResponse( &testTime,                            \
                                                     &testTime,                            \
                                                     testBuffer,                           \
                                                     sizeof( testBuffer ),                 \
                                                     &parsedData ) );                      \
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

/**
 * @brief Test that @ref Sntp_DeserializeResponse API can process an accepted
 * SNTP server response, and determine that the clock offset cannot be calculated
 * when the client clock is beyond 34 years from server.
 */
void test_DeserializeResponse_AcceptedResponse_Overflow_Case( void )
{
    SntpTimestamp_t clientTxTime = TEST_TIMESTAMP;
    SntpResponseData_t parsedData = { 0 };

    /* Fill buffer with general SNTP response data. */
    fillValidSntpResponseData( testBuffer, &clientTxTime );

/* Common test code to validate that API can de-serialize response packet
 * that results in a clock offset calculation overflow. */
#define TEST_API_FOR_OFFSET_OVERFLOW_CASE( serverTime )                                             \
    do {                                                                                            \
        /* Update the response packet with the server time. */                                      \
        addTimestampToResponseBuffer( &serverTime,                                                  \
                                      testBuffer,                                                   \
                                      SNTP_PACKET_RX_TIMESTAMP_FIRST_BYTE_POS );                    \
        addTimestampToResponseBuffer( &serverTime,                                                  \
                                      testBuffer,                                                   \
                                      SNTP_PACKET_TX_TIMESTAMP_FIRST_BYTE_POS );                    \
                                                                                                    \
        /* Call the API under test. */                                                              \
        TEST_ASSERT_EQUAL( SntpClockOffsetOverflow, Sntp_DeserializeResponse( &clientTxTime,        \
                                                                              &clientTxTime,        \
                                                                              testBuffer,           \
                                                                              sizeof( testBuffer ), \
                                                                              &parsedData ) );      \
                                                                                                    \
        /* Make sure that the API has indicated in the output parameter that
         * clock-offset could not be calculated. */                                                       \
        TEST_ASSERT_EQUAL( SNTP_CLOCK_OFFSET_OVERFLOW,                                                    \
                           parsedData.clockOffset.seconds );                                              \
                                                                                                          \
        /* Validate other fields in the output parameter. */                                              \
        TEST_ASSERT_EQUAL( 0, memcmp( &parsedData.serverTime, &serverTime, sizeof( SntpTimestamp_t ) ) ); \
        TEST_ASSERT_EQUAL( NoLeapSecond, parsedData.leapSecondType );                                     \
        TEST_ASSERT_EQUAL( SNTP_KISS_OF_DEATH_CODE_INVALID, parsedData.rejectedResponseCode );            \
    } while( 0 )

    /* Test when the client is 40 years ahead of server time .*/
    SntpTimestamp_t serverTime =
    {
        clientTxTime.seconds - ( 40 * 365 * 24 * 3600 ),
        clientTxTime.fractions
    };
    TEST_API_FOR_OFFSET_OVERFLOW_CASE( serverTime );

    /* Now test when the client is 40 years ahead of server time .*/
    serverTime.seconds = clientTxTime.seconds + ( 40 * 365 * 24 * 3600 );
    TEST_API_FOR_OFFSET_OVERFLOW_CASE( serverTime );
}
