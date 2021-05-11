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

/*#define SNTP_DO_NOT_USE_CUSTOM_CONFIG    1 */

/* coreSNTP Client API include */
#include "core_sntp_client.h"

/* Include mock header of Serializer API of coreSNTP. */
#include "mock_core_sntp_serializer.h"

/* Test IPv4 address for time server. */
#define TEST_SERVER_ADDR         ( 0xAABBCCDD )

#define TEST_RESPONSE_TIMEOUT    ( 1000 )

/* Utility to convert milliseconds to fractions value in
 * SNTP timestamp. */
#define CONVERT_MS_TO_FRACTIONS( MS ) \
    ( MS * 1000 * SNTP_FRACTION_VALUE_PER_MICROSECOND )

/* Test definition of NetworkContext_t structure. */
typedef struct NetworkContext
{
    int udpSocket;
} NetworkContext_t;

/* Test definition of SntpAuthContext_t structure. */
typedef struct SntpAuthContext
{
    uint32_t keyId;
} SntpAuthContext_t;

/* Global variables common to test cases. */
static SntpContext_t context;
static uint8_t testBuffer[ 100 ];
static SntpServerInfo_t testServers[] =
{
    {
        "my.ntp.server.1",
        strlen( "my.ntp.server.1" ),
        SNTP_DEFAULT_SERVER_PORT
    },
    {
        "my.ntp.server.2",
        strlen( "my.ntp.server.2" ),
        SNTP_DEFAULT_SERVER_PORT
    }
};
static UdpTransportInterface_t transportIntf;
static NetworkContext_t netContext;
static SntpAuthenticationInterface_t authIntf;
static SntpAuthContext_t authContext;

/* Variables for configuring behavior of interface functions. */
static bool dnsResolveRetCode = true;
static uint32_t dnsResolveAddr = TEST_SERVER_ADDR;
static SntpTimestamp_t currentTimeList[ 4 ];
static uint8_t currentTimeIndex;
static size_t expectedBytesToSend = SNTP_PACKET_BASE_SIZE;
static int32_t udpSendRetCodes[ 2 ];
static uint8_t currentUdpSendCodeIndex;
static int32_t udpRecvCode = 0;
static SntpStatus_t generateClientAuthRetCode = SntpSuccess;
static size_t authCodeSize;
static SntpStatus_t validateServerAuthRetCode = SntpSuccess;

/* ========================= Helper Functions ============================ */

/* Test definition of the @ref SntpResolveDns_t interface. */
bool dnsResolve( const SntpServerInfo_t * pServerAddr,
                 uint32_t * pIpV4Addr )
{
    TEST_ASSERT_NOT_NULL( pServerAddr );
    TEST_ASSERT_NOT_NULL( pIpV4Addr );

    *pIpV4Addr = TEST_SERVER_ADDR;

    return dnsResolveRetCode;
}

/* Test definition of the @ref SntpGetTime_t interface. */
void getTime( SntpTimestamp_t * pCurrentTime )
{
    TEST_ASSERT_NOT_NULL( pCurrentTime );

    /* Set the current time output parameter based on index
     * in the time list. */
    pCurrentTime->seconds = currentTimeList[ currentTimeIndex ].seconds;
    pCurrentTime->fractions = currentTimeList[ currentTimeIndex ].fractions;

    /* Increment the index to point to the next in the list. */
    currentTimeIndex = ( currentTimeIndex + 1 ) %
                       ( sizeof( currentTimeList ) / sizeof( SntpTimestamp_t ) );
}

/* Test definition of the @ref SntpSetTime_t interface. */
void setTime( const SntpServerInfo_t * pTimeServer,
              const SntpTimestamp_t * pServerTime,
              int32_t clockOffsetSec,
              SntpLeapSecondInfo_t leapSecondInfo )
{
    TEST_ASSERT_NOT_NULL( pTimeServer );
    TEST_ASSERT_NOT_NULL( pServerTime );

    ( void ) clockOffsetSec;
    ( void ) leapSecondInfo;
}

/* Test definition of the @ref UdpTransportSendTo_t interface. */
int32_t UdpSendTo( NetworkContext_t * pNetworkContext,
                   uint32_t serverAddr,
                   uint16_t serverPort,
                   const void * pBuffer,
                   size_t bytesToSend )
{
    TEST_ASSERT_EQUAL_PTR( &netContext, pNetworkContext );
    TEST_ASSERT_NOT_NULL( pBuffer );
    TEST_ASSERT_EQUAL( dnsResolveAddr, serverAddr );
    TEST_ASSERT_EQUAL( SNTP_DEFAULT_SERVER_PORT, serverPort );
    TEST_ASSERT_EQUAL( expectedBytesToSend, bytesToSend );

    ( void ) serverAddr;
    ( void ) serverPort;

    int32_t retCode = udpSendRetCodes[ currentUdpSendCodeIndex ];

    /* Update the expected remaining bytes to send for the next call
     * to the function when no OR partial data sent is represented by the return
     * code. */
    if( retCode > 0 )
    {
        expectedBytesToSend -= retCode;
    }

    /* Increment the index in the return code list to the next. */
    currentUdpSendCodeIndex = ( currentUdpSendCodeIndex + 1 ) %
                              ( sizeof( udpSendRetCodes ) / sizeof( int32_t ) );

    return retCode;
}

/* Test definition of the @ref UdpTransportRecvFrom_t interface. */
int32_t UdpRecvFrom( NetworkContext_t * pNetworkContext,
                     uint32_t serverAddr,
                     uint16_t serverPort,
                     void * pBuffer,
                     size_t bytesToRecv )
{
    TEST_ASSERT_EQUAL_PTR( &netContext, pNetworkContext );
    TEST_ASSERT_NOT_NULL( pBuffer );
    TEST_ASSERT_EQUAL( dnsResolveAddr, serverAddr );
    TEST_ASSERT_EQUAL( SNTP_DEFAULT_SERVER_PORT, serverPort );
    TEST_ASSERT_GREATER_OR_EQUAL( SNTP_PACKET_BASE_SIZE, bytesToRecv );

    ( void ) serverAddr;
    ( void ) serverPort;

    return udpRecvCode;
}

/* Test definition for @ref SntpGenerateAuthCode_t interface. */
SntpStatus_t generateClientAuth( SntpAuthContext_t * pContext,
                                 const SntpServerInfo_t * pTimeServer,
                                 void * pBuffer,
                                 size_t bufferSize,
                                 size_t * pAuthCodeSize )
{
    TEST_ASSERT_EQUAL_PTR( &authContext, pContext );
    TEST_ASSERT_NOT_NULL( pTimeServer );
    TEST_ASSERT_EQUAL_PTR( testBuffer, pBuffer );
    TEST_ASSERT_NOT_NULL( pAuthCodeSize );
    TEST_ASSERT_GREATER_OR_EQUAL( SNTP_PACKET_BASE_SIZE, bufferSize );

    *pAuthCodeSize = authCodeSize;

    return generateClientAuthRetCode;
}

/* Test definition for @ref SntpValidateServerAuth_t interface. */
SntpStatus_t validateServerAuth( SntpAuthContext_t * pContext,
                                 const SntpServerInfo_t * pTimeServer,
                                 const void * pResponseData,
                                 size_t responseSize )
{
    TEST_ASSERT_EQUAL_PTR( &authContext, pContext );
    TEST_ASSERT_NOT_NULL( pTimeServer );
    TEST_ASSERT_EQUAL_PTR( testBuffer, pResponseData );
    TEST_ASSERT_GREATER_OR_EQUAL( SNTP_PACKET_BASE_SIZE, responseSize );

    return validateServerAuthRetCode;
}

/* ============================   UNITY FIXTURES ============================ */

/* Called before each test method. */
void setUp()
{
    /* Reset the global variables. */
    dnsResolveRetCode = true;
    dnsResolveAddr = TEST_SERVER_ADDR;
    udpRecvCode = 0;
    generateClientAuthRetCode = SntpSuccess;
    validateServerAuthRetCode = SntpSuccess;
    currentTimeIndex = 0;
    authCodeSize = 0;
    expectedBytesToSend = SNTP_PACKET_BASE_SIZE;

    /* Reset array of UDP send function return codes. */
    memset( udpSendRetCodes, 0, sizeof( udpSendRetCodes ) );

    /* Reset the current time list for the SntpGetTime_t
     * interface function. */
    memset( currentTimeList, 0, sizeof( currentTimeList ) );

    /* Set the transport interface object. */
    transportIntf.pUserContext = &netContext;
    transportIntf.sendTo = UdpSendTo;
    transportIntf.recvFrom = UdpRecvFrom;

    /* Set the auth interface object. */
    authIntf.pAuthContext = &authContext;
    authIntf.generateClientAuth = generateClientAuth;
    authIntf.validateServerAuth = validateServerAuth;

    /* Clear the network buffer. */
    memset( &testBuffer, 0, sizeof( testBuffer ) );

    /* Initialize context. */
    TEST_ASSERT_EQUAL( SntpSuccess,
                       Sntp_Init( &context,
                                  testServers,
                                  sizeof( testServers ) / sizeof( SntpServerInfo_t ),
                                  TEST_RESPONSE_TIMEOUT,
                                  testBuffer,
                                  sizeof( testBuffer ),
                                  dnsResolve,
                                  getTime,
                                  setTime,
                                  &transportIntf,
                                  &authIntf ) );
}

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
 * @brief Test @ref Sntp_Init with invalid parameters.
 */
void test_Init_InvalidParams( void )
{
    /* Pass invalid context memory. */
    TEST_ASSERT_EQUAL( SntpErrorBadParameter,
                       Sntp_Init( NULL,
                                  testServers,
                                  sizeof( testServers ) / sizeof( SntpServerInfo_t ),
                                  TEST_RESPONSE_TIMEOUT,
                                  testBuffer,
                                  sizeof( testBuffer ),
                                  dnsResolve,
                                  getTime,
                                  setTime,
                                  &transportIntf,
                                  NULL ) );

    /* Pass invalid list of time servers. */
    TEST_ASSERT_EQUAL( SntpErrorBadParameter,
                       Sntp_Init( &context,
                                  NULL,
                                  sizeof( testServers ) / sizeof( SntpServerInfo_t ),
                                  TEST_RESPONSE_TIMEOUT,
                                  testBuffer,
                                  sizeof( testBuffer ),
                                  dnsResolve,
                                  getTime,
                                  setTime,
                                  &transportIntf,
                                  NULL ) );
    TEST_ASSERT_EQUAL( SntpErrorBadParameter,
                       Sntp_Init( &context,
                                  testServers,
                                  0,
                                  TEST_RESPONSE_TIMEOUT,
                                  testBuffer,
                                  sizeof( testBuffer ),
                                  dnsResolve,
                                  getTime,
                                  setTime,
                                  &transportIntf,
                                  NULL ) );

    /* Pass invalid network buffer. */
    TEST_ASSERT_EQUAL( SntpErrorBadParameter,
                       Sntp_Init( &context,
                                  testServers,
                                  sizeof( testServers ) / sizeof( SntpServerInfo_t ),
                                  TEST_RESPONSE_TIMEOUT,
                                  NULL,
                                  sizeof( testBuffer ),
                                  dnsResolve,
                                  getTime,
                                  setTime,
                                  &transportIntf,
                                  NULL ) );
    TEST_ASSERT_EQUAL( SntpErrorBufferTooSmall,
                       Sntp_Init( &context,
                                  testServers,
                                  sizeof( testServers ) / sizeof( SntpServerInfo_t ),
                                  TEST_RESPONSE_TIMEOUT,
                                  testBuffer,
                                  SNTP_PACKET_BASE_SIZE / 2,
                                  dnsResolve,
                                  getTime,
                                  setTime,
                                  &transportIntf,
                                  NULL ) );

    /* Pass invalid required interface definitions. */
    TEST_ASSERT_EQUAL( SntpErrorBadParameter,
                       Sntp_Init( &context,
                                  testServers,
                                  sizeof( testServers ) / sizeof( SntpServerInfo_t ),
                                  TEST_RESPONSE_TIMEOUT,
                                  testBuffer,
                                  sizeof( testBuffer ),
                                  NULL,
                                  getTime,
                                  setTime,
                                  &transportIntf,
                                  NULL ) );
    TEST_ASSERT_EQUAL( SntpErrorBadParameter,
                       Sntp_Init( &context,
                                  testServers,
                                  sizeof( testServers ) / sizeof( SntpServerInfo_t ),
                                  TEST_RESPONSE_TIMEOUT,
                                  testBuffer,
                                  sizeof( testBuffer ),
                                  dnsResolve,
                                  NULL,
                                  setTime,
                                  &transportIntf,
                                  NULL ) );
    TEST_ASSERT_EQUAL( SntpErrorBadParameter,
                       Sntp_Init( &context,
                                  testServers,
                                  sizeof( testServers ) / sizeof( SntpServerInfo_t ),
                                  TEST_RESPONSE_TIMEOUT,
                                  testBuffer,
                                  sizeof( testBuffer ),
                                  dnsResolve,
                                  getTime,
                                  NULL,
                                  &transportIntf,
                                  NULL ) );
    TEST_ASSERT_EQUAL( SntpErrorBadParameter,
                       Sntp_Init( &context,
                                  testServers,
                                  sizeof( testServers ) / sizeof( SntpServerInfo_t ),
                                  TEST_RESPONSE_TIMEOUT,
                                  testBuffer,
                                  sizeof( testBuffer ),
                                  dnsResolve,
                                  getTime,
                                  setTime,
                                  NULL,
                                  NULL ) );

    /* Pass valid transport interface object but invalid members. */
    transportIntf.recvFrom = NULL;
    TEST_ASSERT_EQUAL( SntpErrorBadParameter,
                       Sntp_Init( &context,
                                  testServers,
                                  sizeof( testServers ) / sizeof( SntpServerInfo_t ),
                                  TEST_RESPONSE_TIMEOUT,
                                  testBuffer,
                                  sizeof( testBuffer ),
                                  dnsResolve,
                                  getTime,
                                  setTime,
                                  &transportIntf,
                                  NULL ) );
    transportIntf.recvFrom = UdpRecvFrom;
    transportIntf.sendTo = NULL;
    TEST_ASSERT_EQUAL( SntpErrorBadParameter,
                       Sntp_Init( &context,
                                  testServers,
                                  sizeof( testServers ) / sizeof( SntpServerInfo_t ),
                                  TEST_RESPONSE_TIMEOUT,
                                  testBuffer,
                                  sizeof( testBuffer ),
                                  dnsResolve,
                                  getTime,
                                  setTime,
                                  &transportIntf,
                                  NULL ) );

    /* Set the transport interface object to be valid for next test. */
    transportIntf.sendTo = UdpSendTo;

    /* Pass valid authentication interface object but invalid members. */
    authIntf.generateClientAuth = NULL;
    TEST_ASSERT_EQUAL( SntpErrorBadParameter,
                       Sntp_Init( &context,
                                  testServers,
                                  sizeof( testServers ) / sizeof( SntpServerInfo_t ),
                                  TEST_RESPONSE_TIMEOUT,
                                  testBuffer,
                                  sizeof( testBuffer ),
                                  dnsResolve,
                                  getTime,
                                  setTime,
                                  &transportIntf,
                                  &authIntf ) );
    authIntf.generateClientAuth = generateClientAuth;
    authIntf.validateServerAuth = NULL;
    TEST_ASSERT_EQUAL( SntpErrorBadParameter,
                       Sntp_Init( &context,
                                  testServers,
                                  sizeof( testServers ) / sizeof( SntpServerInfo_t ),
                                  TEST_RESPONSE_TIMEOUT,
                                  testBuffer,
                                  sizeof( testBuffer ),
                                  dnsResolve,
                                  getTime,
                                  setTime,
                                  &transportIntf,
                                  &authIntf ) );
}

/**
 * @brief Test @ref Sntp_Init API correctly initializes a context.
 */
void test_Init_Nominal( void )
{
#define TEST_SNTP_INIT_SUCCESS( pAuthIntf )                                                                    \
    do {                                                                                                       \
        /* Call the API under test. */                                                                         \
        TEST_ASSERT_EQUAL( SntpSuccess,                                                                        \
                           Sntp_Init( &context,                                                                \
                                      testServers,                                                             \
                                      sizeof( testServers ) / sizeof( SntpServerInfo_t ),                      \
                                      TEST_RESPONSE_TIMEOUT,                                                   \
                                      testBuffer,                                                              \
                                      sizeof( testBuffer ),                                                    \
                                      dnsResolve,                                                              \
                                      getTime,                                                                 \
                                      setTime,                                                                 \
                                      &transportIntf,                                                          \
                                      pAuthIntf ) );                                                           \
                                                                                                               \
        /* Make sure that the passed parameters have been set in the context. */                               \
        TEST_ASSERT_EQUAL( testServers, context.pTimeServers );                                                \
        TEST_ASSERT_EQUAL( sizeof( testServers ) / sizeof( SntpServerInfo_t ), context.numOfServers );         \
        TEST_ASSERT_EQUAL_PTR( testBuffer, context.pNetworkBuffer );                                           \
        TEST_ASSERT_EQUAL( TEST_RESPONSE_TIMEOUT, context.responseTimeoutMs );                                 \
        TEST_ASSERT_EQUAL( sizeof( testBuffer ), context.bufferSize );                                         \
        TEST_ASSERT_EQUAL_PTR( dnsResolve, context.resolveDnsFunc );                                           \
        TEST_ASSERT_EQUAL_PTR( getTime, context.getTimeFunc );                                                 \
        TEST_ASSERT_EQUAL_PTR( setTime, context.setTimeFunc );                                                 \
        TEST_ASSERT_EQUAL_MEMORY( &transportIntf,                                                              \
                                  &context.networkIntf,                                                        \
                                  sizeof( UdpTransportInterface_t ) );                                         \
        if( pAuthIntf == NULL )                                                                                \
        {                                                                                                      \
            TEST_ASSERT_NULL( context.authIntf.pAuthContext );                                                 \
            TEST_ASSERT_NULL( context.authIntf.generateClientAuth );                                           \
            TEST_ASSERT_NULL( context.authIntf.validateServerAuth );                                           \
        }                                                                                                      \
        else                                                                                                   \
        {                                                                                                      \
            TEST_ASSERT_EQUAL_MEMORY( &authIntf, &context.authIntf, sizeof( SntpAuthenticationInterface_t ) ); \
        }                                                                                                      \
                                                                                                               \
        /* Validate the initialization of the state members of the context. */                                 \
        TEST_ASSERT_EQUAL( 0, context.currentServerIndex );                                                    \
        TEST_ASSERT_EQUAL( 0, context.currentServerAddr );                                                     \
        TEST_ASSERT_EQUAL( 0, context.lastRequestTime.seconds );                                               \
        TEST_ASSERT_EQUAL( 0, context.lastRequestTime.fractions );                                             \
        TEST_ASSERT_EQUAL( SNTP_PACKET_BASE_SIZE, context.sntpPacketSize );                                    \
    } while( 0 )

    /* Test when an authentication interface is not passed. */
    TEST_SNTP_INIT_SUCCESS( NULL );

    /* Reset the context memory. */
    memset( &context, 0, sizeof( SntpContext_t ) );

    /* Test with a valid authentication interface. */
    TEST_SNTP_INIT_SUCCESS( &authIntf );
}

/**
 * @brief Validate the behavior of @ref Sntp_SendTimeRequest for all error cases.
 */
void test_Sntp_SendTimeRequest_ErrorCases()
{
    /* Set the behavior of the serializer function dependency to always return
     * success. */
    Sntp_SerializeRequest_IgnoreAndReturn( SntpSuccess );

    /* Test with NULL context parameter. */
    TEST_ASSERT_EQUAL( SntpErrorBadParameter,
                       Sntp_SendTimeRequest( NULL, rand() % UINT32_MAX ) );

    /* Test case when no remaining server exists to request time from. */
    context.currentServerIndex = sizeof( testServers ) / sizeof( SntpServerInfo_t );
    TEST_ASSERT_EQUAL( SntpErrorChangeServer,
                       Sntp_SendTimeRequest( &context, rand() % UINT32_MAX ) );

    /* Reset the context member for current server to a valid value. */
    context.currentServerIndex = 0U;

    /* Test case when DNS resolution of server fails. */
    dnsResolveRetCode = false;
    TEST_ASSERT_EQUAL( SntpErrorDnsFailure,
                       Sntp_SendTimeRequest( &context, rand() % UINT32_MAX ) );

    /* Reset DNS resolution interface return code. */
    dnsResolveRetCode = true;

    /* Test case when authentication interface call for adding client authentication
     * fails. */
    generateClientAuthRetCode = SntpErrorBufferTooSmall;
    TEST_ASSERT_EQUAL( SntpErrorBufferTooSmall,
                       Sntp_SendTimeRequest( &context, rand() % UINT32_MAX ) );
    generateClientAuthRetCode = SntpErrorAuthFailure;
    TEST_ASSERT_EQUAL( SntpErrorAuthFailure,
                       Sntp_SendTimeRequest( &context, rand() % UINT32_MAX ) );

    /* Reset authentication interface function return code. */
    generateClientAuthRetCode = SntpSuccess;

    /* Test when authentication interface returns an invalid authentication data
     * size.*/
    authCodeSize = sizeof( testBuffer ) - SNTP_PACKET_BASE_SIZE + 1; /* 1 byte more than buffer can
                                                                      * take for holding auth data. */
    TEST_ASSERT_EQUAL( SntpErrorAuthFailure,
                       Sntp_SendTimeRequest( &context, rand() % UINT32_MAX ) );

    /* Reset authentication code size variable. */
    authCodeSize = sizeof( testBuffer ) - SNTP_PACKET_BASE_SIZE;
    expectedBytesToSend = SNTP_PACKET_BASE_SIZE + authCodeSize;

    /* Test case when transport send fails with negative error code sent in the first
     * call to transport interface send function. */
    udpSendRetCodes[ currentUdpSendCodeIndex ] = -2;
    TEST_ASSERT_EQUAL( SntpErrorNetworkFailure,
                       Sntp_SendTimeRequest( &context, rand() % UINT32_MAX ) );

    /* Reset the index in the current time list. */
    currentTimeIndex = 0;

    /* Test case when transport send fails with negative error code sent after some
     * calls to transport interface send function. */
    udpSendRetCodes[ 0 ] = 1;  /* 1st call sending 1 byte.*/
    udpSendRetCodes[ 1 ] = -1; /* 2nd call returning error.*/
    TEST_ASSERT_EQUAL( SntpErrorNetworkFailure,
                       Sntp_SendTimeRequest( &context, rand() % UINT32_MAX ) );

    /* Reset the index in the current time list. */
    currentTimeIndex = 0;

    /* Test case when transport send operation times out due to no data being
     * sent for #SNTP_SEND_RETRY_TIMEOUT_MS duration. */
    currentTimeList[ 1 ].fractions = 0;                                                         /* SntpGetTime_t call before the loop in sendSntpPacket. */
    currentTimeList[ 2 ].fractions = CONVERT_MS_TO_FRACTIONS( SNTP_SEND_RETRY_TIMEOUT_MS / 2 ); /* SntpGetTime_t call in 1st iteration of loop. */
    currentTimeList[ 3 ].fractions = CONVERT_MS_TO_FRACTIONS( SNTP_SEND_RETRY_TIMEOUT_MS + 1 ); /* SntpGetTime_t call in 2nd iteration of loop. */
    udpSendRetCodes[ currentUdpSendCodeIndex ] = 0;
    TEST_ASSERT_EQUAL( SntpErrorNetworkFailure,
                       Sntp_SendTimeRequest( &context, rand() % UINT32_MAX ) );

    /* Reset the indices of lists that control behavior of interface functions. */
    currentTimeIndex = 0;
    currentUdpSendCodeIndex = 0;

    /* Test case when transport send timeout occurs with partial data being initially
     * no data sent for #SNTP_SEND_RETRY_TIMEOUT_MS duration after that. */
    udpSendRetCodes[ 0 ] = 5;                                                               /* 1st return value for partial data send. */
    udpSendRetCodes[ 1 ] = 0;                                                               /* 2nd return value for no data send. */
    currentTimeList[ 2 ].fractions = 0;                                                     /* SntpGetTime_t call in 1st iteration of loop. */
    currentTimeList[ 3 ].fractions = CONVERT_MS_TO_FRACTIONS( SNTP_SEND_RETRY_TIMEOUT_MS ); /* SntpGetTime_t call in 2nd iteration of loop. */
    TEST_ASSERT_EQUAL( SntpErrorNetworkFailure,
                       Sntp_SendTimeRequest( &context, rand() % UINT32_MAX ) );
}

/**
 * @brief Validate behavior of @ref Sntp_SendTimeRequest in success cases.
 */
void test_SendTimeRequest_Nominal( void )
{
    uint32_t randNum = ( rand() % UINT32_MAX );

    /* Set the size of authentication data within the SNTP packet. */
    authCodeSize = sizeof( testBuffer ) - SNTP_PACKET_BASE_SIZE - 1;

#define TEST_SUCCESS_CASE( generateClientAuthFunc, timeBeforeLoop, timeIn1stIteration )                                         \
    do {                                                                                                                        \
        /* Reset indices to lists controlling behavior of interface functions. */                                               \
        currentTimeIndex = 0;                                                                                                   \
        currentUdpSendCodeIndex = 0;                                                                                            \
                                                                                                                                \
        /* Set the parameter expectations and behavior of call to serializer function .*/                                       \
        Sntp_SerializeRequest_ExpectAndReturn( &context.lastRequestTime, randNum,                                               \
                                               testBuffer, sizeof( testBuffer ), SntpSuccess );                                 \
                                                                                                                                \
        /* Set expected packet size of SNTP request, depending on whether client  authentication data is used. */               \
        expectedBytesToSend = ( generateClientAuthFunc == NULL ) ?                                                              \
                              SNTP_PACKET_BASE_SIZE : SNTP_PACKET_BASE_SIZE + authCodeSize;                                     \
                                                                                                                                \
        /* Set the @ref SntpGenerateAuthCode_t interface in the context. */                                                     \
        context.authIntf.generateClientAuth = generateClientAuthFunc;                                                           \
                                                                                                                                \
        /* Set the behavior of the transport send and get time interface functions. */                                          \
        udpSendRetCodes[ 0 ] = 0;                                      /* 1st return value for partial data send. */            \
        udpSendRetCodes[ 1 ] = expectedBytesToSend;                    /* 2nd return value for no data send. */                 \
        currentTimeList[ 1 ].seconds = timeBeforeLoop.seconds;         /* Time call in before loop  in sendSntpPacket. */       \
        currentTimeList[ 1 ].fractions = timeBeforeLoop.fractions;     /* Time call in before loop in sendSntpPacket loop. */   \
        currentTimeList[ 2 ].seconds = timeIn1stIteration.seconds;     /* Time call in 1st iteration of sendSntpPacket loop. */ \
        currentTimeList[ 2 ].fractions = timeIn1stIteration.fractions; /* Time call in 1st iteration of sendSntpPacket loop. */ \
        TEST_ASSERT_EQUAL( SntpSuccess, Sntp_SendTimeRequest( &context, randNum ) );                                            \
    } while( 0 )

    SntpTimestamp_t beforeLoopTime;
    SntpTimestamp_t inLoopTime;
    beforeLoopTime.seconds = 0;
    beforeLoopTime.fractions = 0;
    inLoopTime.seconds = 0;
    inLoopTime.fractions = CONVERT_MS_TO_FRACTIONS( SNTP_SEND_RETRY_TIMEOUT_MS / 2 );

    /* Test when no authentication interface is provided. */
    TEST_SUCCESS_CASE( NULL, beforeLoopTime, inLoopTime );

    /* Test when an authentication interface is provided. */
    TEST_SUCCESS_CASE( generateClientAuth, beforeLoopTime, inLoopTime );

    /* Test edge case when SNTP time overflows (i.e. at 7 Feb 2036 6h 28m 16s UTC )
     * during the send operation. */
    beforeLoopTime.seconds = UINT32_MAX;
    beforeLoopTime.fractions = UINT32_MAX; /* Last time in SNTP era 0. */
    inLoopTime.seconds = 0;                /* Time in SNTP era 1. */
    inLoopTime.fractions = CONVERT_MS_TO_FRACTIONS( SNTP_SEND_RETRY_TIMEOUT_MS / 2 );
    /* Test when an authentication interface is provided. */
    TEST_SUCCESS_CASE( generateClientAuth, beforeLoopTime, inLoopTime );
}

/**
 * @brief Validates the @ref Sntp_StatusToStr function.
 */
void test_StatusToStr( void )
{
    TEST_ASSERT_EQUAL_STRING( "SntpSuccess", Sntp_StatusToStr( SntpSuccess ) );
    TEST_ASSERT_EQUAL_STRING( "SntpErrorBadParameter", Sntp_StatusToStr( SntpErrorBadParameter ) );
    TEST_ASSERT_EQUAL_STRING( "SntpRejectedResponseChangeServer", Sntp_StatusToStr( SntpRejectedResponseChangeServer ) );
    TEST_ASSERT_EQUAL_STRING( "SntpRejectedResponseRetryWithBackoff", Sntp_StatusToStr( SntpRejectedResponseRetryWithBackoff ) );
    TEST_ASSERT_EQUAL_STRING( "SntpRejectedResponseOtherCode", Sntp_StatusToStr( SntpRejectedResponseOtherCode ) );
    TEST_ASSERT_EQUAL_STRING( "SntpErrorBufferTooSmall", Sntp_StatusToStr( SntpErrorBufferTooSmall ) );
    TEST_ASSERT_EQUAL_STRING( "SntpInvalidResponse", Sntp_StatusToStr( SntpInvalidResponse ) );
    TEST_ASSERT_EQUAL_STRING( "SntpClockOffsetOverflow", Sntp_StatusToStr( SntpClockOffsetOverflow ) );
    TEST_ASSERT_EQUAL_STRING( "SntpZeroPollInterval", Sntp_StatusToStr( SntpZeroPollInterval ) );
    TEST_ASSERT_EQUAL_STRING( "SntpErrorTimeNotSupported", Sntp_StatusToStr( SntpErrorTimeNotSupported ) );
    TEST_ASSERT_EQUAL_STRING( "SntpErrorChangeServer", Sntp_StatusToStr( SntpErrorChangeServer ) );
    TEST_ASSERT_EQUAL_STRING( "SntpErrorDnsFailure", Sntp_StatusToStr( SntpErrorDnsFailure ) );
    TEST_ASSERT_EQUAL_STRING( "SntpErrorNetworkFailure", Sntp_StatusToStr( SntpErrorNetworkFailure ) );
    TEST_ASSERT_EQUAL_STRING( "SntpServerNotAuthenticated", Sntp_StatusToStr( SntpServerNotAuthenticated ) );
    TEST_ASSERT_EQUAL_STRING( "SntpErrorAuthFailure", Sntp_StatusToStr( SntpErrorAuthFailure ) );
    TEST_ASSERT_EQUAL_STRING( "Invalid status code!", Sntp_StatusToStr( 100 ) );
}
