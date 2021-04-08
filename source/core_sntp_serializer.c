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
 * @file core_sntp_serializer.c
 * @brief Implementation of the Serializer API of the coreSNTP library.
 */

/* Standard includes. */
#include <string.h>
#include <assert.h>

/* Include API header. */
#include "core_sntp_serializer.h"

/**
 * @brief The version of SNTP supported by the coreSNTP library by complying
 * with the SNTPv4 specification defined in [RFC 4330](https://tools.ietf.org/html/rfc4330).
 */
#define SNTP_VERSION            ( 4 )

/**
 * @brief The value indicating a "client" in the "Mode" field of an SNTP packet.
 * @note Refer to the [RFC 4330 Section 4](https://tools.ietf.org/html/rfc4330#section-4)
 * for more information.
 */
#define SNTP_MODE_CLIENT        ( 3 )

/**
 * @brief The value indicating a "server" in the "Mode" field of an SNTP packet.
 * @note Refer to the [RFC 4330 Section 4](https://tools.ietf.org/html/rfc4330#section-4)
 * for more information.
 */
#define SNTP_MODE_SERVER        ( 4 )

/**
 * @brief Constant to represent an empty SNTP timestamp value.
 */
#define SNTP_ZERO_TIMESTAMP     { 0U, 0U }

/**
 * @brief The position of the "Version" information
 * in the first byte of an SNTP packet.
 * @note Refer to the [RFC 4330 Section 4](https://tools.ietf.org/html/rfc4330#section-4)
 * for more information.
 */
#define VERSION_POSITION    ( 3 )

/**
 * @brief Structure representing an SNTP packet header.
 * For more information on SNTP packet format, refer to
 * [RFC 4330 Section 4](https://tools.ietf.org/html/rfc4330#section-4).
 *
 * @note This does not include extension fields for authentication data
 * for secure SNTP communication. Authentication data follows the
 * packet header represented by this structure.
 */
typedef struct SntpPacket
{
    char leapVersionMode;         /* Bits 6-7 leap indicator, bits 3-5 are version number, bits 0-2 are mode */
    uint8_t stratum;              /* stratum */
    uint8_t poll;                 /* poll interval */
    uint8_t precision;            /* precision */
    uint32_t rootDelay;           /* root delay */
    uint32_t rootDispersion;            /* root dispersion */
    uint32_t refId;               /* reference ID */
    SntpTimestamp_t refTime;      /* reference time */
    SntpTimestamp_t originTime;   /* origin timestamp */
    SntpTimestamp_t receiveTime;  /* receive timestamp */
    SntpTimestamp_t transmitTime; /* transmit timestamp */
} SntpPacket_t;

/**
 * @brief Object representing data that is common to any SNTP request.
 *
 * @note The @ref Sntp_SerializeRequest API will fill the "originate
 * timestamp" with value provided by the application.
 */
static const SntpPacket_t requestPacket =
{
    0 | ( SNTP_VERSION << VERSION_LSB_POSITION ) | SNTP_MODE_CLIENT, /*leap indicator | version number | mode */
    0,                                                               /* stratum */
    0,                                                               /* poll interval */
    0,                                                               /* precision */
    0,                                                               /* root delay */
    0,                                                               /* root dispersion */
    0,                                                               /* reference ID */
    SNTP_ZERO_TIMESTAMP,                                             /* reference time */
    SNTP_ZERO_TIMESTAMP,                                             /* origin timestamp */
    SNTP_ZERO_TIMESTAMP,                                             /* receive timestamp */
    SNTP_ZERO_TIMESTAMP                                              /* transmit timestamp */
};

/**
 * @brief Utility macro to fill 32-bit integer in word-sized
 * memory in network byte (or Little Endian) order.
 *
 * @param[out] wordMemory Pointer to the word-sized memory in which
 * the 32-bit integer will be filled.
 * @param[in] data The 32-bit integer to fill in the @p wordMemory
 * in network byte order.
 *
 * @note This utility ensures that data is filled in memory
 * in expected network byte order, as an assignment operation
 * (like *pWordMemory = htonl(wordVal)) can cause undesired side-effect
 * of network-byte ordering getting reversed on Little Endian platforms.
 */
static void fillWordMemoryInNetworkOrder( uint32_t * pWordMemory,
                                          uint32_t data )
{
    assert( pWordMemory != NULL );

    *( ( uint8_t * ) pWordMemory ) = ( uint8_t ) data;
    *( ( uint8_t * ) pWordMemory + 1 ) = ( uint8_t ) ( data >> 8 );
    *( ( uint8_t * ) pWordMemory + 2 ) = ( uint8_t ) ( data >> 16 );
    *( ( uint8_t * ) pWordMemory + 3 ) = ( uint8_t ) ( data >> 24 );
}

SntpStatus_t Sntp_SerializeRequest( SntpTimestamp_t * pCurrentTime,
                                    uint32_t randomNumber,
                                    void * pBuffer,
                                    size_t bufferSize )
{
    SntpStatus_t status = SntpSuccess;

    if( pCurrentTime == NULL )
    {
        status = SntpErrorBadParameter;
    }
    else if( pBuffer == NULL )
    {
        status = SntpErrorBadParameter;
    }
    else if( bufferSize < SNTP_PACKET_MINIMUM_SIZE )
    {
        status = SntpErrorBufferTooSmall;
    }
    else
    {
        SntpPacket_t * pRequestPacket = ( SntpPacket_t * ) pBuffer;

        /* Fill the buffer with standard data for an SNTP request packet.*/
        memcpy( pBuffer, &requestPacket, sizeof( SntpPacket_t ) );

        /* Add passed random number to non-significant bits of the fractions part
         * of the transmit timestamp.
         * This is suggested by the SNTPv4 (and NTPv4) specification(s)
         * to protect against replay attacks. Refer to RFC 4330 Section 3 for
         * more information.
         * Adding random bits to the least significant 16 bits of the fractions
         * part of the timestamp affects only ~15 microseconds of information
         * (calculated as 0xFFFF * 232 picoseconds).
         */
        pCurrentTime->fractions = ( pCurrentTime->fractions
                                    | ( randomNumber >> 16 ) );

        /* Update the request buffer with request timestamp in network byte order. */
        fillWordMemoryInNetworkOrder( &pRequestPacket->transmitTime.seconds,
                                      pCurrentTime->seconds );
        fillWordMemoryInNetworkOrder( &pRequestPacket->transmitTime.fractions,
                                      pCurrentTime->fractions );
    }

    return status;
}
