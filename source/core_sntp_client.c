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

/**
 * @file core_sntp_client.c
 * @brief Implementation of the client API of the coreSNTP library.
 */

/* Standard includes. */
#include <assert.h>
#include <string.h>

/* SNTP client library API include. */
#include "core_sntp_client.h"


SntpStatus_t Sntp_Init( SntpContext_t * pContext,
                        const SntpServerInfo_t * pTimeServers,
                        size_t numOfServers,
                        uint8_t * pNetworkBuffer,
                        size_t bufferSize,
                        SntpResolveDns_t resolveDnsFunc,
                        SntpGetTime_t getSystemTimeFunc,
                        SntpSetTime_t setSystemTimeFunc,
                        const UdpTransportInterface_t * pTransportIntf,
                        const SntpAuthenticationInterface_t * pAuthIntf )
{
    SntpStatus_t status = SntpSuccess;

    /* Validate pointer parameters are not NULL. */
    if( ( pContext == NULL ) || ( pTimeServers == NULL ) ||
        ( pNetworkBuffer == NULL ) || ( resolveDnsFunc == NULL ) ||
        ( getSystemTimeFunc == NULL ) || ( setSystemTimeFunc == NULL ) ||
        ( pTransportIntf == NULL ) )
    {
        LogError( ( "Invalid parameter: Following pointer parameters cannot be NULL: "
                    "pContext=%p, pTimeServers=%p, pNetworkBuffer=%p, resolveDnsFunc=%p, "
                    "getSystemTimeFunc=%p, setSystemTimeFunc=%p, pTransportIntf=%p",
                    ( void * ) pContext, ( void * ) pTimeServers,
                    ( void * ) pNetworkBuffer, ( void * ) resolveDnsFunc,
                    ( void * ) getSystemTimeFunc, ( void * ) setSystemTimeFunc,
                    ( void * ) pTransportIntf ) );

        status = SntpErrorBadParameter;
    }
    /* Validate the length of the servers list.*/
    else if( numOfServers == 0U )
    {
        LogError( ( "Invalid parameter: Size of server list cannot be zero" ) );
        status = SntpErrorBadParameter;
    }
    /* Validate that the members of the UDP transport interface. */
    else if( ( pTransportIntf->recvFrom == NULL ) || ( pTransportIntf->sendTo == NULL ) )
    {
        LogError( ( "Invalid parameter: Function members of UDP transport interface "
                    "cannot be NULL: sendTo=%p, recvFrom=%p",
                    ( void * ) pTransportIntf->recvFrom,
                    ( void * ) pTransportIntf->sendTo ) );
        status = SntpErrorBadParameter;
    }

    /* If an authentication interface is provided, validate that its function pointer
     * members are valid. */
    else if( ( pAuthIntf != NULL ) &&
             ( ( pAuthIntf->generateClientAuth == NULL ) ||
               ( pAuthIntf->validateServerAuth == NULL ) ) )
    {
        LogError( ( "Invalid parameter: Function members of passed authentication interface "
                    "cannot be NULL: generateClientAuth=%p, validateServerAuth=%p",
                    ( void * ) pTransportIntf->recvFrom,
                    ( void * ) pTransportIntf->sendTo ) );
        status = SntpErrorBadParameter;
    }
    else if( bufferSize < SNTP_PACKET_BASE_SIZE )
    {
        LogError( ( "Cannot initialize context: Passed network buffer size is less than %u bytes: "
                    "bufferSize=%lu", SNTP_PACKET_BASE_SIZE, ( unsigned long ) bufferSize ) );
        status = SntpErrorBufferTooSmall;
    }
    else
    {
        /* Reset the context memory to zero. */
        ( void ) memset( pContext, 0, sizeof( SntpContext_t ) );

        /* Set the members of the context with passed parameters. */
        pContext->pTimeServers = pTimeServers;
        pContext->numOfServers = numOfServers;

        pContext->pNetworkBuffer = pNetworkBuffer;
        pContext->bufferSize = bufferSize;

        pContext->resolveDnsFunc = resolveDnsFunc;
        pContext->getTimeFunc = getSystemTimeFunc;
        pContext->setTimeFunc = setSystemTimeFunc;

        /* Copy contents of UDP transport interface to context. */
        ( void ) memcpy( &pContext->networkIntf, pTransportIntf, sizeof( UdpTransportInterface_t ) );

        /* If authentication interface has been passed, copy its contents to the context. */
        if( pAuthIntf != NULL )
        {
            ( void ) memcpy( &pContext->authIntf, pAuthIntf, sizeof( SntpAuthenticationInterface_t ) );
        }

        /* Initialize the packet size member to the standard minimum SNTP packet size.*/
        pContext->sntpPacketSize = SNTP_PACKET_BASE_SIZE;
    }

    return status;
}

/**
 * @brief Sends SNTP request packet to the passed server over the network
 * using transport interface's send function.
 *
 * @note For the cases of partial or zero byte data transmissions over the
 * network, this function repeatedly retries send operation by calling the
 * transport interface until either:
 * 1. The requested number of bytes @p packetSize have been sent.
 *                    OR
 * 2. No byte cannot be sent over the network for the
 * #SNTP_SEND_RETRY_TIMEOUT_MS duration.
 *                    OR
 * 3. There is an error in sending data over the network.
 *
 * @param[in] pNetworkIntf The UDP transport interface to use for
 * sending data over the network.
 * @param[in] timeServer The IP address of the server to send the
 * SNTP request packet to.
 * @param[in] serverPort The port of the @p timeServer to send the
 * request to.
 * @param[in] getTimeFunc The function to query system time for
 * tracking retry time period of no data transmissions.
 * @param[in] pPacket The buffer containing the SNTP packet data
 * to send over the network.
 * @param[in] packetSize The size of data in the SNTP request packet.
 *
 * @return Returns #SntpSuccess on successful transmission of the entire
 * SNTP request packet over the network; otherwise #SntpErrorNetworkFailure
 * to indicate failure.
 */
static SntpStatus_t sendSntpPacket( UdpTransportInterface_t * pNetworkIntf,
                                    uint32_t timeServer,
                                    uint16_t serverPort,
                                    SntpGetTime_t getTimeFunc,
                                    const uint8_t * pPacket,
                                    size_t packetSize )
{
    const uint8_t * pIndex = pPacket;
    size_t bytesRemaining = packetSize;
    int32_t totalBytesSent = 0, bytesSent = 0;
    SntpTimestamp_t lastSendTime;
    uint16_t timeSinceLastSendMs;
    bool sendError = false;

    assert( pPacket != NULL );
    assert( pTimeServer != NULL );
    assert( pContext != NULL );
    assert( getTimeFunc != NULL );
    assert( pNetworkIntf != NULL );
    assert( packetSize > SNTP_PACKET_BASE_SIZE );

    /* Record the starting time of attempting to send data. This begins the retry timeout
     * window. */
    getTimeFunc( &lastSendTime );

    /* Loop until the entire packet is sent. */
    while( ( bytesRemaining > 0UL ) && ( sendError == false ) )
    {
        bytesSent = pNetworkIntf->sendTo( pNetworkIntf->pUserContext,
                                          timeServer,
                                          serverPort,
                                          pIndex,
                                          bytesRemaining );

        if( bytesSent < 0 )
        {
            LogError( ( "Unable to send request packet: Transport send failed. "
                        "ErrorCode=%ld.", ( long int ) bytesSent ) );
            totalBytesSent = bytesSent;
            sendError = true;
        }
        else if( bytesSent > 0 )
        {
            /* Record the time of successful transmission. This resets the retry timeout window.*/
            getTimeFunc( &lastSendTime );

            /* It is a bug in the application's transport send implementation if
             * more bytes than expected are sent. To avoid a possible overflow
             * in converting bytesRemaining from unsigned to signed, this assert
             * must exist after the check for bytesSent being negative. */
            assert( ( size_t ) bytesSent <= bytesRemaining );

            bytesRemaining -= ( size_t ) bytesSent;
            totalBytesSent += bytesSent;
            pIndex += bytesSent;
            LogDebug( ( "BytesSent=%ld, BytesRemaining=%lu",
                        ( long int ) bytesSent,
                        ( unsigned long ) bytesRemaining ) );
        }
        else
        {
            /* No bytes were sent over the network. Retry send if we have not timed out. */
            SntpTimestamp_t currentTime;

            getTimeFunc( &currentTime );

            /* Calculate time elapsed since last data was sent over network. */
            timeSinceLastSendMs = ( currentTime.seconds - lastSendTime.seconds ) * 1000U +
                                  ( ( currentTime.fractions - lastSendTime.fractions ) /
                                    ( SNTP_FRACTION_VALUE_PER_MICROSECOND * 1000U ) );

            /* Check for timeout if we have been waiting to send any data over the network. */
            if( timeSinceLastSendMs >= SNTP_SEND_RETRY_TIMEOUT_MS )
            {
                LogError( ( "Unable to send request packet: Timed out retrying send: "
                            "SendRetryTimeout=%uMs",
                            ( unsigned int ) SNTP_SEND_RETRY_TIMEOUT_MS ) );
                sendError = true;
            }
        }
    }

    return ( sendError == false ) ? SntpSuccess : SntpErrorNetworkFailure;
}


SntpStatus_t Sntp_SendTimeRequest( SntpContext_t * pContext,
                                   uint32_t randomNumber )
{
    SntpStatus_t status = SntpSuccess;

    if( pContext == NULL )
    {
        status = SntpErrorBadParameter;
        LogError( ( "Invalid context parameter: Context cannot be NULL" ) );
    }
    else
    {
        const SntpServerInfo_t * pServer = NULL;

        /* Check if there is any time server available for requesting time
         * that has not already rejected a prior request. */
        if( pContext->currentServerIndex >= pContext->numOfServers )
        {
            LogError( ( "Cannot request time: All configured servers rejected prior time "
                        "requests: Re-initialize context with new servers" ) );
            status = SntpErrorChangeServer;
        }
        else
        {
            /* Set local variable for the currently indexed server to use for time
             * query. */
            pServer = &pContext->pTimeServers[ pContext->currentServerIndex ];
            LogDebug( ( "Using server %.*s at index %lu for time query",
                        pServer->serverNameLength, pServer->pServerName,
                        ( unsigned long ) pContext->currentServerIndex ) );
        }

        if( status == SntpSuccess )
        {
            /* Perform DNS resolution of the currently indexed server in the list
             * of configured servers. */
            if( pContext->resolveDnsFunc( pServer,
                                          &pContext->currentServerIpV4Addr ) == false )
            {
                LogError( ( "Unable to send time request: DNS resolution failed: Server=%.*s",
                            pServer->serverNameLength, pServer->pServerName ) );
                status = SntpErrorDnsFailure;
            }
            else
            {
                LogInfo( ( "Time Server DNS resolved: Server=%.*s, Address=0x%08X",
                           pServer->serverNameLength, pServer->pServerName,
                           ( unsigned int ) &pContext->currentServerIpV4Addr ) );
            }
        }

        if( status == SntpSuccess )
        {
            /* Obtain current system time to generate SNTP request packet. */
            pContext->getTimeFunc( &pContext->lastRequestTime );

            LogInfo( ( "Obtained current time for SNTP request: Seconds=%u, Fractions=%s",
                       pContext->lastRequestTime.seconds,
                       pContext->lastRequestTime.fractions ) );

            /* Generate SNTP request packet with the current system time and
             * the passed random number. */
            status = Sntp_SerializeRequest( &pContext->lastRequestTime,
                                            randomNumber,
                                            pContext->pNetworkBuffer,
                                            pContext->bufferSize );

            /* The serialization should be successful as all parameter validation has
             * been done before. */
            assert( status == SntpSuccess );
        }

        /* If an authentication interface has been configured, call the function to append client
         * authentication data to SNTP request buffer. */
        if( ( status == SntpSuccess ) && ( pContext->authIntf.generateClientAuth != NULL ) )
        {
            size_t authDataSize = 0U;
            status = pContext->authIntf.generateClientAuth( pContext->authIntf.pAuthContext,
                                                            pServer,
                                                            pContext->pNetworkBuffer,
                                                            pContext->bufferSize,
                                                            &authDataSize );

            if( status != SntpSuccess )
            {
                LogError( ( "Unable to send time request: Client authentication function failed: "
                            "RetStatus=%u", status ) );
            }

            /* Sanity check that the returned authentication data size fits in the remaining space
             * of the request buffer besides the first #SNTP_PACKET_BASE_SIZE bytes. */
            else if( authDataSize > ( pContext->bufferSize - SNTP_PACKET_BASE_SIZE ) )
            {
                LogError( ( "Unable to send time request: Invalid authentication code size "
                            "returned by interface function: AuthCodeSize=%lu, "
                            "NetworkBufferSize=%lu",
                            ( unsigned long ) authDataSize,
                            ( unsigned long ) pContext->bufferSize ) );
            }
            else
            {
                /* With the authentication data added. calculate total SNTP request packet size. The same
                 * size would be expected in the SNTP response from server. */
                pContext->sntpPacketSize = SNTP_PACKET_BASE_SIZE + authDataSize;
                LogInfo( ( "Appended client authentication code to SNTP request packet:"
                           " AuthCodeSize=%lu, TotalPacketSize=%lu",
                           ( unsigned long ) pContext->sntpPacketSize,
                           ( unsigned long ) pContext->sntpPacketSize ) );
            }
        }

        if( status == SntpSuccess )
        {
            /* Send the request packet over the network to the time server. */
            status = sendSntpPacket( &pContext->networkIntf,
                                     pContext->currentServerIpV4Addr,
                                     pContext->pTimeServers[ pContext->currentServerIndex ].port,
                                     pContext->getTimeFunc,
                                     pContext->pNetworkBuffer,
                                     pContext->sntpPacketSize );
        }
    }

    return status;
}
