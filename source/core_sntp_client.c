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

/**
 * @brief Utility to convert fractions part of SNTP timestamp to milliseconds.
 *
 * @param[in] fractions The fractions value in an SNTP timestamp.
 */
#define FRACTIONS_TO_MS( fractions ) \
    ( fractions / ( SNTP_FRACTION_VALUE_PER_MICROSECOND * 1000U ) )

SntpStatus_t Sntp_Init( SntpContext_t * pContext,
                        const SntpServerInfo_t * pTimeServers,
                        size_t numOfServers,
                        uint32_t serverResponseTimeoutMs,
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
        LogError( ( "Invalid parameter: Pointer parameters (except pAuthIntf) cannot be NULL" ) );

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
        LogError( ( "Invalid parameter: Function members of UDP transport interface cannot be NULL" ) );
        status = SntpErrorBadParameter;
    }

    /* If an authentication interface is provided, validate that its function pointer
     * members are valid. */
    else if( ( pAuthIntf != NULL ) &&
             ( ( pAuthIntf->generateClientAuth == NULL ) ||
               ( pAuthIntf->validateServerAuth == NULL ) ) )
    {
        LogError( ( "Invalid parameter: Function members of authentication interface cannot be NULL" ) );
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

        pContext->responseTimeoutMs = serverResponseTimeoutMs;

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
 * @brief Utility to calculate the difference in milliseconds between 2
 * SNTP timestamps.
 *
 * @param[in] pCurrentTime The more recent timestamp.
 * @param[in] pOlderTime The older timestamp.
 *
 * @note This functions supports the edge case of SNTP timestamp overflow
 * when @p pCurrentTime represents time in NTP era 1 (i.e. time since 7 Feb 2036)
 * and the @p OlderTime represents time in NTP era 0 (i.e. time since 1st Jan 1900).
 *
 * @return Returns the calculated time duration between the two timestamps.
 */
static uint32_t calculateElapsedTimeMs( const SntpTimestamp_t * pCurrentTime,
                                        const SntpTimestamp_t * pOlderTime )
{
    uint32_t timeDiffMs = 0U;

    assert( pCurrentTime != NULL );
    assert( pOlderTime != NULL );

    timeDiffMs = ( pCurrentTime->seconds - pOlderTime->seconds ) * 1000U;

    if( pCurrentTime->fractions > pOlderTime->fractions )
    {
        timeDiffMs += ( pCurrentTime->fractions - pOlderTime->fractions ) /
                      ( SNTP_FRACTION_VALUE_PER_MICROSECOND * 1000U );
    }
    else
    {
        timeDiffMs -= ( pOlderTime->fractions - pCurrentTime->fractions ) /
                      ( SNTP_FRACTION_VALUE_PER_MICROSECOND * 1000U );
    }

    return timeDiffMs;
}

/**
 * @brief Sends SNTP request packet to the passed server over the network
 * using transport interface's send function.
 *
 * @note For the cases of partial or zero byte data transmissions over the
 * network, this function repeatedly retries the send operation by calling the
 * transport interface until either:
 * 1. The requested number of bytes @p packetSize have been sent.
 *                    OR
 * 2. Any byte cannot be sent over the network for the
 * #SNTP_SEND_RETRY_TIMEOUT_MS duration.
 *                    OR
 * 3. There is an error in sending data over the network.
 *
 * @param[in] pNetworkIntf The UDP transport interface to use for
 * sending data over the network.
 * @param[in] timeServer The IPv4 address of the server to send the
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
static SntpStatus_t sendSntpPacket( const UdpTransportInterface_t * pNetworkIntf,
                                    uint32_t timeServer,
                                    uint16_t serverPort,
                                    SntpGetTime_t getTimeFunc,
                                    const uint8_t * pPacket,
                                    size_t packetSize )
{
    const uint8_t * pIndex = pPacket;
    size_t bytesRemaining = packetSize;
    int32_t bytesSent = 0;
    SntpTimestamp_t lastSendTime;
    uint32_t timeSinceLastSendMs;
    bool sendError = false;

    assert( pPacket != NULL );
    assert( getTimeFunc != NULL );
    assert( pNetworkIntf != NULL );
    assert( packetSize >= SNTP_PACKET_BASE_SIZE );

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
            pIndex += bytesSent;
            LogDebug( ( "BytesSent=%d, BytesRemaining=%lu", bytesSent, bytesRemaining ) );
        }
        else
        {
            /* No bytes were sent over the network. Retry send if we have not timed out. */
            SntpTimestamp_t currentTime;

            getTimeFunc( &currentTime );

            /* Calculate time elapsed since last data was sent over network. */
            timeSinceLastSendMs = calculateElapsedTimeMs( &currentTime, &lastSendTime );

            /* Check for timeout if we have been waiting to send any data over the network. */
            if( timeSinceLastSendMs >= SNTP_SEND_RETRY_TIMEOUT_MS )
            {
                LogError( ( "Unable to send request packet: Timed out retrying send: "
                            "SendRetryTimeout=%ums", SNTP_SEND_RETRY_TIMEOUT_MS ) );
                sendError = true;
            }
        }
    }

    return ( sendError == false ) ? SntpSuccess : SntpErrorNetworkFailure;
}

/**
 * @brief Adds client authentication data to SNTP request packet by calling the
 * authentication interface.
 *
 * @param[in] pContext The SNTP context.
 *
 * @return Returns one of the following:
 * - #SntpSuccess if the interface function successfully appends client
 * authentication data.
 * - #SntpErrorAuthError when the interface returns either an error OR an
 * incorrect size of the client authentication data.
 * - #SntpBufferTooSmall if the request packet buffer is too small to add client
 * authentication data.
 */
static SntpStatus_t addClientAuthentication( SntpContext_t * pContext )
{
    SntpStatus_t status = SntpSuccess;
    size_t authDataSize = 0U;

    assert( pContext != NULL );
    assert( pContext->authIntf.generateClientAuth != NULL );
    assert( pContext->currentServerIndex <= pContext->numOfServers );

    status = pContext->authIntf.generateClientAuth( pContext->authIntf.pAuthContext,
                                                    &pContext->pTimeServers[ pContext->currentServerIndex ],
                                                    pContext->pNetworkBuffer,
                                                    pContext->bufferSize,
                                                    &authDataSize );

    if( status != SntpSuccess )
    {
        LogError( ( "Unable to send time request: Client authentication function failed: "
                    "RetStatus=%s", Sntp_StatusToStr( status ) ) );
    }

    /* Sanity check that the returned authentication data size fits in the remaining space
     * of the request buffer besides the first #SNTP_PACKET_BASE_SIZE bytes. */
    else if( authDataSize > ( pContext->bufferSize - SNTP_PACKET_BASE_SIZE ) )
    {
        LogError( ( "Unable to send time request: Invalid authentication code size: "
                    "AuthCodeSize=%lu, NetworkBufferSize=%lu",
                    ( unsigned long ) authDataSize, ( unsigned long ) pContext->bufferSize ) );
        status = SntpErrorAuthFailure;
    }
    else
    {
        /* With the authentication data added. calculate total SNTP request packet size. The same
         * size would be expected in the SNTP response from server. */
        pContext->sntpPacketSize = SNTP_PACKET_BASE_SIZE + authDataSize;

        LogInfo( ( "Appended client authentication code to SNTP request packet:"
                   " AuthCodeSize=%lu, TotalPacketSize=%lu",
                   ( unsigned long ) authDataSize,
                   ( unsigned long ) pContext->sntpPacketSize ) );
    }

    return status;
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

    /* Check if there is any time server available for requesting time
     * that has not already rejected a prior request. */
    else if( pContext->currentServerIndex >= pContext->numOfServers )
    {
        LogError( ( "Cannot request time: All servers have rejected time requests: "
                    "Re-initialize context with new servers" ) );
        status = SntpErrorChangeServer;
    }
    else
    {
        const SntpServerInfo_t * pServer = NULL;

        /* Set local variable for the currently indexed server to use for time
         * query. */
        pServer = &pContext->pTimeServers[ pContext->currentServerIndex ];

        LogDebug( ( "Using server %.*s for time query", ( int ) pServer->serverNameLen, pServer->pServerName ) );

        /* Perform DNS resolution of the currently indexed server in the list
         * of configured servers. */
        if( pContext->resolveDnsFunc( pServer, &pContext->currentServerAddr ) == false )
        {
            LogError( ( "Unable to send time request: DNS resolution failed: Server=%.*s",
                        ( int ) pServer->serverNameLen, pServer->pServerName ) );

            status = SntpErrorDnsFailure;
        }
        else
        {
            LogDebug( ( "Server DNS resolved: Address=0x%08X", pContext->currentServerAddr ) );
        }

        if( status == SntpSuccess )
        {
            /* Obtain current system time to generate SNTP request packet. */
            pContext->getTimeFunc( &pContext->lastRequestTime );

            LogDebug( ( "Obtained current time for SNTP request packet: Time=%us %ums",
                        pContext->lastRequestTime.seconds, FRACTIONS_TO_MS( pContext->lastRequestTime.fractions ) ) );

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
            status = addClientAuthentication( pContext );
        }

        if( status == SntpSuccess )
        {
            LogInfo( ( "Sending serialized SNTP request packet to the server: Addr=%u, Port=%u",
                       pContext->currentServerAddr,
                       pContext->pTimeServers[ pContext->currentServerIndex ].port ) );

            /* Send the request packet over the network to the time server. */
            status = sendSntpPacket( &pContext->networkIntf,
                                     pContext->currentServerAddr,
                                     pContext->pTimeServers[ pContext->currentServerIndex ].port,
                                     pContext->getTimeFunc,
                                     pContext->pNetworkBuffer,
                                     pContext->sntpPacketSize );
        }
    }

    return status;
}

/**
 * @brief This function attempts to receive the SNTP response packet from a server
 * if the time window for server response has not timed out.
 *
 * @note This function does not block on receiving the response packet from the network.
 * Instead, it determines whether the response packet is already available on the network
 * by first reading ONLY a single byte of data first.
 * If the single byte is available from the network, then rest of the SNTP response packet is
 * read from the network with retries for zero or partial reads until either:
 * - All the remaining bytes of server response are received
 *                     OR
 * - A timeout of #SNTP_RECV_POLLING_TIMEOUT_MS occurs of receiving no data over the network.
 *
 * @param[in] pTransportIntf The UDP transport interface to use for receiving data from
 * the network.
 * @param[in] timeServer The server to read the response from the network.
 * @param[in] serverPort The port of the server to read the response from.
 * @param[in, out] pBuffer This will be filled with the server response read from the
 * network.
 * @param[in] responseSize The size of server response to read from the network.
 * @param[in] getTimeFunc The interface for obtaining system time.
 *
 * @return It returns one of the following:
 * - #SntpSuccess if an SNTP response packet is received from the network.
 * - #SntpNoResponse if a server response is not received from the network.
 * - #SntpErrorNetworkFailure if there is an internal failure in reading from the network
 * in the user-defined transport interface.
 */
static SntpStatus_t receiveSntpResponse( const UdpTransportInterface_t * pTransportIntf,
                                         uint32_t timeServer,
                                         uint16_t serverPort,
                                         uint8_t * pBuffer,
                                         size_t responseSize,
                                         SntpGetTime_t getTimeFunc )
{
    SntpStatus_t status = SntpSuccess;
    int32_t bytesRead = 0;


    /* Check whether there is any data available on the network to read by attempting to read
     * a single byte. */
    bytesRead = pTransportIntf->recvFrom( pTransportIntf->pUserContext,
                                          timeServer,
                                          serverPort,
                                          pBuffer,
                                          1U );

    if( bytesRead > 0 )
    {
        size_t bytesRemaining = responseSize - 1U;
        SntpTimestamp_t startTime;

        assert( bytesRead == 1 );

        getTimeFunc( &startTime );

        while( ( bytesRemaining > 0U ) && ( status == SntpSuccess ) )
        {
            bytesRead = pTransportIntf->recvFrom( pTransportIntf->pUserContext,
                                                  timeServer,
                                                  serverPort,
                                                  pBuffer,
                                                  1U );

            if( bytesRead > 0 )
            {
                bytesRemaining -= ( size_t ) bytesRead;

                /* Read the current system time to set it as the new base line
                 * for evaluating the receive retry timeout, #SNTP_RECV_POLLING_TIMEOUT_MS.*/
                getTimeFunc( &startTime );
            }
            else if( bytesRead == 0 )
            {
                SntpTimestamp_t currentTime;
                uint32_t timeSinceLastRecv = calculateElapsedTimeMs( &currentTime, &startTime );

                if( timeSinceLastRecv >= SNTP_RECV_POLLING_TIMEOUT_MS )
                {
                    LogError( ( "Unable to receive server response: Timed out retrying reads: Timeout=%ums", SNTP_RECV_POLLING_TIMEOUT_MS ) );
                    status = SntpErrorNetworkFailure;
                }
            }
            else
            {
                status = SntpErrorNetworkFailure;
            }
        }
    }
    else if( bytesRead == 0 )
    {
        LogDebug( ( "No data available on the network to read." ) );
        status = SntpNoResponseReceived;
    }
    else
    {
        /* Empty else marker. */
    }

    if( bytesRead < 0 )
    {
        status = SntpErrorNetworkFailure;
        LogError( ( "Unable to receive server response: Transport receive failed: Code=%ld",
                    ( long int ) bytesRead ) );
    }

    return status;
}

/**
 * @brief Processes the response from a server by de-serializing the SNTP packet to
 * validate the server (if an authentication interface has been configured), determine
 * whether server has accepted or rejected the time request, and update the system clock
 * if the server responded positively with time.
 *
 * @param[in] pContext The SNTP context representing the SNTP client.
 * @param[in] pResponseRxTime The time of receiving the server response from the network.
 *
 * @return It returns one of the following:
 * - #SntpSuccess if the server response is successfully de-serialized and system clock
 * updated.
 * - #SntpErrorAuthFailure if there is internal failure in user-defined authentication
 * interface when validating server from the response.
 * - #SntpServerNotAuthenticated if the server failed authenticated check in the user-defined
 * interface.
 * - #SntpRejectedResponse if the server has rejected the time request in its response.
 * - #SntpInvalidResponse if the server response failed sanity checks.
 */
static SntpStatus_t processServerResponse( SntpContext_t * pContext,
                                           SntpTimestamp_t * pResponseRxTime )
{
    SntpStatus_t status = SntpSuccess;
    const SntpServerInfo_t * pServer = &pContext->pTimeServers[ pContext->currentServerIndex ];

    assert( pContext != NULL );
    assert( pResponseRxTime != NULL );

    if( pContext->authIntf.validateServerAuth != NULL )
    {
        /* Verify the server from the authentication data in the SNTP response packet. */
        status = pContext->authIntf.validateServerAuth( pContext->authIntf.pAuthContext,
                                                        pServer,
                                                        pContext->pNetworkBuffer,
                                                        pContext->bufferSize );
        assert( ( status == SntpSuccess ) || ( status == SntpErrorAuthFailure ) ||
                ( status == SntpServerNotAuthenticated ) );

        if( status != SntpSuccess )
        {
            LogError( ( "Unable to use server response: Server authentication function failed: "
                        "ReturnStatus=%s", Sntp_StatusToStr( status ) ) );
        }
        else
        {
            LogDebug( ( "Server response has been validated: Server=%.s",
                        ( int ) pServer->serverNameLen, pServer->pServerName ) );
        }
    }

    if( status == SntpSuccess )
    {
        SntpResponseData_t parsedResponse;

        /* De-serialize response packet to determine whether the server accepted or rejected
         * the request for time. Also, calculate the system clock offset if the server responded
         * with time. */
        status = Sntp_DeserializeResponse( &pContext->lastRequestTime,
                                           pResponseRxTime,
                                           pContext->pNetworkBuffer,
                                           pContext->sntpPacketSize,
                                           &parsedResponse );

        if( ( status == SntpRejectedResponseChangeServer ) ||
            ( status == SntpRejectedResponseRetryWithBackoff ) ||
            ( status == SntpRejectedResponseOtherCode ) )
        {
            /* Server has rejected the time request. Thus, we will rotate to the next time server
            * in the list, if we have not exhausted time requests with all configured servers. */
            pContext->currentServerIndex++;

            LogError( ( "Unable to use server response: Server has rejected request for time: RejectionCode=%.*s",
                        ( int ) SNTP_KISS_OF_DEATH_CODE_LENGTH, parsedResponse.rejectedResponseCode ) );
            status = SntpRejectedResponse;
        }
        else if( status == SntpInvalidResponse )
        {
            LogError( ( "Unable to use server response: Server response failed sanity checks." ) );
        }
        else
        {
            /* If the system clock is not within 34 years of server time, clock offset value cannot be
             * calculated. This case is only treated as a warning instead of an error because one the system
             * clock is updated with the time from server, the issue will be resolved for time queries. */
            if( status == SntpClockOffsetOverflow )
            {
                LogWarn( ( "Failed to calculate clock offset: System time SHOULD be within 34 years of server time." ) );
            }

            /* Server has responded successfully with time, and we have calculated the clock offset
             * of system clock relative to the server.*/
            LogDebug( ( "Updating system time: ServerTime=%u %ums ClockOffset=%us",
                        parsedResponse.serverTime.seconds, FRACTIONS_TO_MS( parsedResponse.serverTime.fractions ),
                        parsedResponse.clockOffsetSec ) );

            /* Update the system clock with the calculated offset. */
            pContext->setTimeFunc( pServer, &parsedResponse.serverTime,
                                   parsedResponse.clockOffsetSec, parsedResponse.leapSecondType );

            status = SntpSuccess;
        }
    }

    return status;
}

SntpStatus_t Sntp_ReceiveTimeResponse( SntpContext_t * pContext,
                                       uint32_t blockTimeMs )
{
    SntpStatus_t status = SntpNoResponseReceived;

    if( pContext == NULL )
    {
        status = SntpErrorBadParameter;
        LogError( ( "Invalid context parameter: Context cannot be NULL" ) );
    }

    /* Check whether there is any remaining server to in the list of configured
     * servers that it is reasonable to expect a response from. */
    else if( pContext->currentServerIndex >= pContext->numOfServers )
    {
        status = SntpErrorChangeServer;
        LogError( ( "Invalid API call: All servers have already rejected time requests: "
                    "Re-initialize context to change configured servers." ) );
    }
    else
    {
        SntpTimestamp_t startTime, loopIterTime;
        uint32_t timeSinceTimeRequest = 0;

        pContext->getTimeFunc( &startTime );

        do
        {
            status = receiveSntpResponse( &pContext->networkIntf,
                                          pContext->currentServerAddr,
                                          pContext->pTimeServers[ pContext->currentServerIndex ].port,
                                          pContext->pNetworkBuffer,
                                          pContext->sntpPacketSize,
                                          pContext->getTimeFunc );

            /* Get current time to either de-serialize the SNTP packet if a server response has been
             * received OR utilize for determining whether another attempt for reading the packet can
             * be made. */
            pContext->getTimeFunc( &loopIterTime );

            /* If the server response is received, deserialize it, validate the server
             * (if authentication interface is provided), and update system time with
             * the calculated clock offset. */
            if( status == SntpSuccess )
            {
                status = processServerResponse( pContext, &loopIterTime );
            }

            /* Check whether a response timeout has occurred before re-trying the
             * read in the next iteration. */
            else if( ( timeSinceTimeRequest = calculateElapsedTimeMs( &loopIterTime, &pContext->lastRequestTime ) )
                     >= pContext->responseTimeoutMs )
            {
                status = SntpErrorResponseTimeout;
                LogError( ( "Unable to receive response: Server response has timed out: "
                            "RequestTime=%us %ums, TimeoutDuration=%ums", pContext->lastRequestTime.seconds,
                            FRACTIONS_TO_MS( pContext->lastRequestTime.fractions ),
                            timeSinceTimeRequest ) );
            }
            else
            {
                /* Empty else marker. */
            }
        } while( ( status == SntpNoResponseReceived ) &&
                 ( calculateElapsedTimeMs( &loopIterTime, &startTime ) < blockTimeMs ) );
    }

    return status;
}

const char * Sntp_StatusToStr( SntpStatus_t status )
{
    const char * pString = NULL;

    switch( status )
    {
        case SntpSuccess:
            pString = "SntpSuccess";
            break;

        case SntpErrorBadParameter:
            pString = "SntpErrorBadParameter";
            break;

        case SntpRejectedResponseChangeServer:
            pString = "SntpRejectedResponseChangeServer";
            break;

        case SntpRejectedResponseRetryWithBackoff:
            pString = "SntpRejectedResponseRetryWithBackoff";
            break;

        case SntpRejectedResponseOtherCode:
            pString = "SntpRejectedResponseOtherCode";
            break;

        case SntpErrorBufferTooSmall:
            pString = "SntpErrorBufferTooSmall";
            break;

        case SntpInvalidResponse:
            pString = "SntpInvalidResponse";
            break;

        case SntpClockOffsetOverflow:
            pString = "SntpClockOffsetOverflow";
            break;

        case SntpZeroPollInterval:
            pString = "SntpZeroPollInterval";
            break;

        case SntpErrorTimeNotSupported:
            pString = "SntpErrorTimeNotSupported";
            break;

        case SntpErrorChangeServer:
            pString = "SntpErrorChangeServer";
            break;

        case SntpErrorDnsFailure:
            pString = "SntpErrorDnsFailure";
            break;

        case SntpErrorNetworkFailure:
            pString = "SntpErrorNetworkFailure";
            break;

        case SntpServerNotAuthenticated:
            pString = "SntpServerNotAuthenticated";
            break;

        case SntpErrorAuthFailure:
            pString = "SntpErrorAuthFailure";
            break;

        default:
            pString = "Invalid status code!";
            break;
    }

    return pString;
}
