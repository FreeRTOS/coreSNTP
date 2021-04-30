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
                        const UdpTransportIntf_t * pTransportIntf,
                        const SntpAuthenticationIntf_t * pAuthIntf )
{
    SntpStatus_t status = SntpSuccess;

    /* Validate pointer parameters are not NULL. */
    if( ( pContext == NULL ) || ( pTimeServers == NULL ) || ( numOfServers == 0U ) ||
        ( pNetworkBuffer == NULL ) || ( resolveDnsFunc == NULL ) || ( getSystemTimeFunc == NULL ) ||
        ( setSystemTimeFunc == NULL ) || ( pTransportIntf == NULL ) )
    {
        status = SntpErrorBadParameter;
    }
    /* Validate that the members of the UDP transport interface. */
    else if( ( pTransportIntf->recvFrom == NULL ) || ( pTransportIntf->sendTo == NULL ) )
    {
        status = SntpErrorBadParameter;
    }

    /* If an authentication interface is provided, validate that its function pointer
     * members are valid. */
    else if( ( pAuthIntf != NULL ) &&
             ( ( pAuthIntf->generateClientAuth == NULL ) ||
               ( pAuthIntf->validateServer == NULL ) ) )
    {
        status = SntpErrorBadParameter;
    }
    else if( bufferSize < SNTP_PACKET_BASE_SIZE )
    {
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
        ( void ) memcpy( &pContext->networkIntf, pTransportIntf, sizeof( UdpTransportIntf_t ) );

        /* If authentication interface has been passed, copy its contents to the context. */
        if( pAuthIntf != NULL )
        {
            ( void ) memcpy( &pContext->authIntf, pAuthIntf, sizeof( SntpAuthenticationIntf_t ) );
        }

        /* Initialize the packet size member to the standard minimum SNTP packet size.*/
        pContext->sntpPacketSize = SNTP_PACKET_BASE_SIZE;
    }

    return status;
}
