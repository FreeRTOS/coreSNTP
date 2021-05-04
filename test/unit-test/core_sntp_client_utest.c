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

/* coreSNTP Client API include */
#include "core_sntp_client.h"

/* Test IPv4 address for time server. */
#define TEST_SERVER_ADDR    ( 0xAABBCCDD )

typedef struct NetworkContext
{
    int udpSocket;
} NetworkContext_t;

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
static bool setTimeRetCode = true;
static int32_t UpdSendRetCode = 0;
static int32_t UpdRecvCode = 0;

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
}

/* Test definition of the @ref SntpSetTime_t interface. */
bool setTime( const SntpServerInfo_t * pTimeServer,
              const SntpTimestamp_t * pServerTime,
              int32_t clockOffsetSec )
{
    TEST_ASSERT_NOT_NULL( pTimeServer );
    TEST_ASSERT_NOT_NULL( pServerTime );
    ( void ) clockOffsetSec;

    return setTimeRetCode;
}

/* Test definition of the @ref UdpTransportSendTo_t interface. */
int32_t UdpSendTo( NetworkContext_t * pNetworkContext,
                   uint32_t serverAddr,
                   uint16_t serverPort,
                   const void * pBuffer,
                   size_t bytesToSend )
{
    TEST_ASSERT_NOT_NULL( pNetworkContext );
    TEST_ASSERT_NOT_NULL( pBuffer );
    TEST_ASSERT_GREATER_OR_EQUAL( SNTP_PACKET_BASE_SIZE, bytesToSend );

    ( void ) serverAddr;
    ( void ) serverPort;

    return UpdSendRetCode;
}

/* Test definition of the @ref UdpTransportRecvFrom_t interface. */
int32_t UdpRecvFrom( NetworkContext_t * pNetworkContext,
                     uint32_t serverAddr,
                     uint16_t serverPort,
                     void * pBuffer,
                     size_t bytesToRecv )
{
    TEST_ASSERT_NOT_NULL( pNetworkContext );
    TEST_ASSERT_NOT_NULL( pBuffer );
    TEST_ASSERT_GREATER_OR_EQUAL( SNTP_PACKET_BASE_SIZE, bytesToRecv );

    ( void ) serverAddr;
    ( void ) serverPort;

    return UpdRecvCode;
}

/* Test definition for @ref SntpGenerateAuthCode_t interface. */
SntpStatus_t generateClientAuth( SntpAuthContext_t * pContext,
                                 const SntpServerInfo_t * pTimeServer,
                                 void * pBuffer,
                                 size_t bufferSize,
                                 size_t * pAuthCodeSize )
{
    TEST_ASSERT_NOT_NULL( pContext );
    TEST_ASSERT_NOT_NULL( pTimeServer );
    TEST_ASSERT_NOT_NULL( pBuffer );
    TEST_ASSERT_NOT_NULL( pAuthCodeSize );
    TEST_ASSERT_GREATER_OR_EQUAL( SNTP_PACKET_BASE_SIZE, bufferSize );

    return SntpSuccess;
}

/* Test definition for @ref SntpValidateAuthCode_t interface. */
SntpStatus_t validateServerAuth( SntpAuthContext_t * pContext,
                                 const SntpServerInfo_t * pTimeServer,
                                 const void * pResponseData,
                                 size_t responseSize )
{
    TEST_ASSERT_NOT_NULL( pContext );
    TEST_ASSERT_NOT_NULL( pTimeServer );
    TEST_ASSERT_NOT_NULL( pResponseData );
    TEST_ASSERT_GREATER_OR_EQUAL( SNTP_PACKET_BASE_SIZE, responseSize );

    return SntpSuccess;
}

/* ============================   UNITY FIXTURES ============================ */

/* Called before each test method. */
void setUp()
{
    /* Reset the global variables. */
    dnsResolveRetCode = true;
    dnsResolveAddr = TEST_SERVER_ADDR;
    setTimeRetCode = true;
    UpdSendRetCode = 0;
    UpdRecvCode = 0;

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
        TEST_ASSERT_EQUAL( 0, context.currentServerIpV4Addr );                                                 \
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
