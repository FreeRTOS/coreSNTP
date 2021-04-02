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

/* Standard include. */
#include <string.h>

/* Include API header. */
#include "core_sntp_serializer.h"

/**
 * @brief The version of SNTP supported by the coreSNTP library.
 */
#define SNTP_VERSION                                ( 4 )

/**
 * @brief The value indicating a "client" in the "Mode" field of an SNTP packet.
 * @note Refer to the [RFC4330 Section 4](https://tools.ietf.org/html/rfc4330#section-4)
 * for more information.
 */
#define SNTP_MODE_CLIENT                            ( 3 )

/**
 * @brief The value indicating a "server" in the "Mode" field of an SNTP packet.
 * @note Refer to the [RFC4330 Section 4](https://tools.ietf.org/html/rfc4330#section-4)
 * for more information.
 */
#define SNTP_MODE_SERVER                            ( 4 )

/**
 * @brief Number of 232 picoseconds per microsecond.
 * @note The resolution of an SNTP timestamp fractions part is (1/2^32) ~ 232 picoseconds.
 */
#define SNTP_FRACTION_RESOLUTION_PER_MICROSECOND    ( 4295U )

/**
 * @brief Structure representing the timestamp format of SNTP.
 */
typedef struct SntpTimestamp
{
    /* Number of seconds since primary epoch (1st Jan 1900 UTC). */
    uint32_t secs;
    /* Fraction part as a multiple of 232 picoseconds resolution. */
    uint32_t fraction;
} SntpTimestamp_t;

#define SNTP_ZERO_TIMESTAMP    { 0U, 0U }

/**
 * @brief Structure representing an (S)NTP packet header.
 * @note This does not include extension fields for authentication data
 * for secure SNTP communication. Authentication data follows the
 * packet header represented by this structure.
 */
typedef struct SntpPacket
{
    char leap : 2;                /* leap indicator */
    char version : 3;             /* version number */
    char mode : 3;                /* mode */
    uint8_t stratum : 8;          /* stratum */
    uint8_t poll : 8;             /* poll interval */
    uint8_t precision : 8;        /* precision */
    uint32_t rootDelay;           /* root delay */
    uint32_t rootDisp;            /* root dispersion */
    uint32_t refId;               /* reference ID */
    SntpTimestamp_t refTime;      /* reference time */
    SntpTimestamp_t originTime;   /* origin timestamp */
    SntpTimestamp_t receiveTime;  /* receive timestamp */
    SntpTimestamp_t transmitTime; /* transmit timestamp */
} SntpPacket_t;

/**
 * @brief Object representing data that is common any SNTP request.
 * @note The @ref Sntp_SerializeRequest API will fill the "originate
 * timestamp" with value provided by the application.
 */
static const SntpPacket_t requestPacket =
{
    0,                   /* leap indicator */
    SNTP_VERSION,        /* version number */
    SNTP_MODE_CLIENT,    /* mode */
    0,                   /* stratum */
    0,                   /* poll interval */
    0,                   /* precision */
    0,                   /* root delay */
    0,                   /* root dispersion */
    0,                   /* reference ID */
    SNTP_ZERO_TIMESTAMP, /* reference time */
    SNTP_ZERO_TIMESTAMP, /* origin timestamp */
    SNTP_ZERO_TIMESTAMP, /* receive timestamp */
    SNTP_ZERO_TIMESTAMP  /* transmit timestamp */
};

/**
 * @brief Utility macro to convert a 32-bit integer from host to
 * network byte order.
 */
#define SNTP_HTONL( wordData )                           \
    ( uint32_t ) ( ( 0x000000FF & ( wordData >> 24 ) ) | \
                   ( 0x0000FF00 & ( wordData >> 8 ) ) |  \
                   ( 0x00FF0000 & ( wordData << 8 ) ) |  \
                   ( 0xFF000000 & ( wordData << 24 ) ) )


SntpStatus_t Sntp_SerializeRequest( SntpTime_t * pCurrentTime,
                                    void * pBuffer,
                                    size_t bufferSize )
{
    SntpStatus_t status = SntpErrorInternal;

    if( pCurrentTime == NULL )
    {
        status = SntpErrorBadParameter;
    }
    else if( pBuffer == NULL )
    {
        status = SntpErrorBadParameter;
    }
    else if( bufferSize < SNTP_REQUEST_RESPONSE_MINIMUM_PACKET_SIZE )
    {
        status = SntpErrorInsufficientSpace;
    }
    else
    {
        SntpPacket_t * pRequestPacket = ( SntpPacket_t * ) pBuffer;

        /* Fill the buffer with standard data for an SNTP request packet.*/
        memcpy( pBuffer, &requestPacket, sizeof( SntpPacket_t ) );

        /* Convert the passed time into NTP timestamp format. */
        pRequestPacket->transmitTime.secs = SNTP_HTONL( pCurrentTime->seconds );
        pRequestPacket->transmitTime.fraction = SNTP_HTONL( pCurrentTime->microseconds *
                                                            SNTP_FRACTION_RESOLUTION_PER_MICROSECOND );

        status = SntpSuccess;
    }

    return status;
}
