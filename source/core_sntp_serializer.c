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
#include <stdbool.h>
#include <assert.h>

/* Include API header. */
#include "core_sntp_serializer.h"

/**
 * @brief The version of SNTP supported by the coreSNTP library.
 */
#define SNTP_VERSION                                        ( 4 )

/**
 * @brief The bit mask for the Mode information in the first byte of
 * an SNTP packet. The "Mode" field occupies bits 0-2 of the byte.
 * @note Refer to the [RFC 4330 Section 4](https://tools.ietf.org/html/rfc4330#section-4)
 * for more information.
 */
#define SNTP_MODE_BITS_MASK                                 ( 0x07 )

/**
 * @brief The bit mask for the Mode information in the first byte of
 * an SNTP packet. The "Mode" field occupies bits 0-2 of the byte.
 * @note Refer to the [RFC 4330 Section 4](https://tools.ietf.org/html/rfc4330#section-4)
 * for more information.
 */
#define SNTP_MODE_BITS_MASK                                 ( 0x07 )

/**
 * @brief The value indicating a "client" in the "Mode" field of an SNTP packet.
 * @note Refer to the [RFC 4330 Section 4](https://tools.ietf.org/html/rfc4330#section-4)
 * for more information.
 */
#define SNTP_MODE_CLIENT                                    ( 3 )

/**
 * @brief The value indicating a "server" in the "Mode" field of an SNTP packet.
 * @note Refer to the [RFC 4330 Section 4](https://tools.ietf.org/html/rfc4330#section-4)
 * for more information.
 */
#define SNTP_MODE_SERVER                                    ( 4 )

/**
 * @brief The position of the least significant bit of the "Leap Indicator" field
 * in first byte of an SNTP packet. The "Leap Indicator" field occupies bits 6-7 of the byte.
 * @note Refer to the [RFC 4330 Section 4](https://tools.ietf.org/html/rfc4330#section-4)
 * for more information.
 */
#define SNTP_LEAP_INDICATOR_LSB_POSITION                    ( 6 )

/**
 * @brief Value of Stratum field in SNTP packet representing a Kiss-o'-Death message
 * from server.
 */
#define SNTP_KISS_OF_DEATH_STRATUM                          ( 0 )

/**
 * @brief Constant to represent an empty SNTP timestamp value.
 */
#define SNTP_ZERO_TIMESTAMP                                 { 0U, 0U }

/**
 * @brief The least-significant bit position of the "Version" information
 * in the first byte of an SNTP packet.
 */
#define VERSION_LSB_POSITION                                ( 3 )

/**
 * @brief The integer value of the Kiss-o'-Death ASCII code, "DENY", used
 * for comparison with data in an SNTP response.
 * @note Refer to [RFC 4330 Section 8](https://tools.ietf.org/html/rfc4330#section-8)
 * for more information.
 */
#define KOD_CODE_DENY_UINT_VALUE                            ( 0x44454e59U )

/**
 * @brief The integer value of the Kiss-o'-Death ASCII code, "RSTR", used
 * for comparison with data in an SNTP response.
 * @note Refer to [RFC 4330 Section 8](https://tools.ietf.org/html/rfc4330#section-8)
 * for more information.
 */
#define KOD_CODE_RSTR_UINT_VALUE                            ( 0x52535452U )

/**
 * @brief The integer value of the Kiss-o'-Death ASCII code, "RATE", used
 * for comparison with data in an SNTP response.
 * @note Refer to [RFC 4330 Section 8](https://tools.ietf.org/html/rfc4330#section-8)
 * for more information.
 */
#define KOD_CODE_RATE_UINT_VALUE                            ( 0x52415445U )

/**
 * @brief The bit mask for the first order difference between system clock and
 * server second part of timestamps to determine whether calculation for
 * system clock-offset relative to server will overflow.
 * If any of the bits represented by the mask are set in the first order timestamp
 * difference value, it represents that clock offset calculations will overflow.
 *
 * @note The bit mask represents the 2 most significant bits of a 32 bit integer
 * as the clock-offset value uses the bits as sign bits, thereby, requiring that
 * the value be representable within 30 bits of the seconds part of timestamp width.
 */
#define CLOCK_OFFSET_FIRST_ORDER_DIFF_OVERFLOW_BITS_MASK    ( 0xC0000000U )

/**
 * @brief Structure representing an (S)NTP packet header.
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
    0 | ( SNTP_VERSION << VERSION_LSB_POSITION ) | SNTP_MODE_CLIENT, /* leap indicator | version number | mode */
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
 * @brief Utility macro to convert a 32-bit integer from host to
 * network byte order or from network to host byte order.
 */
#define SNTP_HTONL_NTOHL( wordData )                     \
    ( uint32_t ) ( ( 0x000000FF & ( wordData >> 24 ) ) | \
                   ( 0x0000FF00 & ( wordData >> 8 ) ) |  \
                   ( 0x00FF0000 & ( wordData << 8 ) ) |  \
                   ( 0xFF000000 & ( wordData << 24 ) ) )


/**
 * @brief Utility to calculate clock offset of system relative to the
 * server using the on-wire protocol specified in the NTPv4 specification.
 * For more information on on-wire protocol, refer to
 * [RFC 5905 Section 8](https://tools.ietf.org/html/rfc5905#section-8).
 *
 * If the clock offset will result in an overflow, this function sets
 * the clock offset, @p pClockOffset, as #SNTP_CLOCK_OFFSET_OVERFLOW.
 *
 * @note The following diagram explains the calculation of the clock
 * offset:
 *
 *                 T2      T3
 *      ---------------------------------   <-----   *SNTP/NTP server*
 *               /\         \
 *               /           \
 *     Request* /             \ *Response*
 *             /              \/
 *      ---------------------------------   <-----   *SNTP client*
 *           T1                T4
 *
 *  The four most recent timestamps, T1 through T4, are used to compute
 *  the clock offset of SNTP client relative to the server where:
 *
 *     T1 = Client Request Transmit Time
 *     T2 = Server Receive Time (of client request)
 *     T3 = Server Response Transmit Time
 *     T4 = Client Receive Time (of server response)
 *
 *  Clock Offset = T(NTP/SNTP server) - T(SNTP client)
 *               = [( T2 - T1 ) + ( T3 - T4 )]
 *                 ---------------------------
 *                              2
 *
 * @note Both NTPv4 and SNTPv4 specifications suggest calculating the
 * clock offset value, if possible. As the timestamp format uses 64 bit
 * integer and there exist 2 orders of arithmetic calculations on the
 * timestamp values (subtraction followed by addition as shown in the
 * diagram above), the clock offset for the system can be calculated
 * ONLY if the value can be represented in 62 significant bits and 2 sign
 * bits i.e. if the system clock is within 34 years (in the future or past)
 * of the server time.
 *
 * @param[in] pClientTxTime The system time of sending the SNTP request.
 * This is the same as "T1" in the above diagram.
 * @param[in] pServerRxTime The server time of receiving the SNTP request
 * packet from the client. This is the same as "T2" in the above diagram.
 * @param[in] pServerTxTime The server time of sending the SNTP response
 * packet. This is the same as "T3" in the above diagram.
 * @param[in] pClientRxTime The system time of receiving the SNTP response
 * from the server. This is the same as "T4" in the above diagram.
 * @param[out] pClockOffset The calculated offset value of the system clock
 * relative to the server time, if the system clock is within 34 years of
 * server time; otherwise, the seconds part of clock offset is set to
 * #SNTP_CLOCK_OFFSET_OVERFLOW.
 */
static void calculateClockOffset( const SntpTimestamp_t * pClientTxTime,
                                  const SntpTimestamp_t * pServerRxTime,
                                  const SntpTimestamp_t * pServerTxTime,
                                  const SntpTimestamp_t * pClientRxTime,
                                  SntpTimestamp_t * pClockOffset )
{
    int32_t firstOrderDiff = 0;

    assert( pClientTxTime != NULL );
    assert( pServerRxTime != NULL );
    assert( pServerTxTime != NULL );
    assert( pClientRxTime != NULL );
    assert( pClockOffset != NULL );

    /* Calculate a sample first order difference value between the
     * server and system timestamps. */
    if( pClientRxTime->seconds > pServerTxTime->seconds )
    {
        firstOrderDiff = pClientRxTime->seconds - pServerTxTime->seconds;
    }
    else
    {
        firstOrderDiff = pServerTxTime->seconds - pClientRxTime->seconds;
    }

    /* Determine from the first order difference if the system time is within
     * 34 years of server time to be able to calculate clock offset. */
    if( ( firstOrderDiff & CLOCK_OFFSET_FIRST_ORDER_DIFF_OVERFLOW_BITS_MASK )
        == 0 )
    {
        /* Calculate the clock-offset as system time is within 34 years window
         * of server time. */
        SntpTimestamp_t firstOrderDiffSend;
        SntpTimestamp_t firstOrderDiffRecv;

        /* Perform ( T2 - T1 ) offset calculation of SNTP Request packet path. */
        firstOrderDiffSend.seconds = pServerRxTime->seconds - pClientTxTime->seconds;
        firstOrderDiffSend.fractions = pServerRxTime->fractions - pClientTxTime->fractions;

        /* Perform ( T3 - T4 ) offset calculation of SNTP Response packet path. */
        firstOrderDiffRecv.seconds = pServerTxTime->seconds - pClientRxTime->seconds;
        firstOrderDiffRecv.fractions = pServerTxTime->fractions - pClientRxTime->fractions;

        /* Perform second order calculation of using average of the above offsets. */
        pClockOffset->seconds = ( firstOrderDiffSend.seconds + firstOrderDiffRecv.seconds ) >> 2;
        pClockOffset->fractions = ( firstOrderDiffSend.fractions + firstOrderDiffRecv.fractions ) >> 2;
    }
    else
    {
        pClockOffset->seconds = SNTP_CLOCK_OFFSET_OVERFLOW;
        pClockOffset->fractions = 0;
    }
}

/**
 * @brief Parse a SNTP response packet by determining whether it is a rejected
 * or accepted response to an SNTP request, and accordingly, populate the
 * @p pParsedResponse parameter with the parsed data.
 *
 * @note If the server has rejected the request with the a Kiss-o'-Death message,
 * then this function will set the associated rejection code in the output parameter
 * while setting the remaining members to zero.
 * If the server has accepted the time request, then the function will set the
 * pRejectedResponseCode member of the output parameter to #SNTP_KISS_OF_DEATH_CODE_INVALID,
 * and set the other the members with appropriate data extracted from the response
 * packet.
 *
 * @param[in] pResponsePacket The SNTP response packet from server to parse.
 * @param[in] pResponseRxTime The system time (in SNTP timestamp format) of
 * receiving the SNTP response from server.
 * @param[out] pParsedResponse The parameter that will be populated with data
 * parsed from the response packet, @p pResponsePacket.
 *
 * @return This function returns one of the following:
 * - #SntpSuccess if the server response does not represent a Kiss-o'-Death
 * message.
 * - #SntpRejectedResponseChangeServer if the server rejected with a code
 * indicating that client cannot be retry requests to it.
 * - #SntpRejectedResponseRetryWithBackoff if the server rejected with a code
 * indicating that client should back-off before retrying request.
 * - #SntpRejectedResponseCodeOther if the server rejected with a code
 * other than "DENY", "RSTR" and "RATE".
 */
static SntpStatus_t parseValidSntpResponse( const SntpPacket_t * pResponsePacket,
                                            const SntpTimestamp_t * pResponseRxTime,
                                            SntpResponseData_t * pParsedResponse )
{
    SntpStatus_t status = SntpSuccess;

    assert( pResponsePacket != NULL );
    assert( pResponseRxTime != NULL );
    assert( pParsedResponse != NULL );

    /* Clear the output parameter memory to zero. */
    memset( pParsedResponse, 0, sizeof( *pParsedResponse ) );

    /* Determine if the server has accepted or rejected the request for time. */
    if( pResponsePacket->stratum == SNTP_KISS_OF_DEATH_STRATUM )
    {
        /* Server has sent a Kiss-o'-Death message i.e. rejected the request. */

        /* Extract the kiss-code sent by the server from the "Reference ID" field
         * of the SNTP packet. */
        pParsedResponse->pRejectedResponseCode = ( const char * ) ( &( pResponsePacket->refId ) );

        /* Determine the return code based on the Kiss-o'-Death code. */
        switch( pResponsePacket->refId )
        {
            case KOD_CODE_DENY_UINT_VALUE:
            case KOD_CODE_RSTR_UINT_VALUE:
                status = SntpRejectedResponseChangeServer;
                break;

            case KOD_CODE_RATE_UINT_VALUE:
                status = SntpRejectedResponseRetryWithBackoff;
                break;

            default:
                status = SntpRejectedResponseCodeOther;
        }
    }
    else
    {
        /* Server has responded successfully to the time request. */

        /* Set the Kiss-o'-Death code value to NULL as server has responded favorably
         * to the time request. */
        pParsedResponse->pRejectedResponseCode = SNTP_KISS_OF_DEATH_CODE_INVALID;

        /* Fill the output parameter with the server time which is the
         * "transmit" time in the response packet. */
        pParsedResponse->serverTime.seconds =
            SNTP_HTONL_NTOHL( pResponsePacket->transmitTime.seconds );
        pParsedResponse->serverTime.fractions =
            SNTP_HTONL_NTOHL( pResponsePacket->transmitTime.fractions );

        /* Extract information of any upcoming leap second from the response. */
        pParsedResponse->leapSecondType = ( SntpLeapSecondInfo_t )
                                          ( pResponsePacket->leapVersionMode
                                            >> SNTP_LEAP_INDICATOR_LSB_POSITION );

        /* Calculate system clock offset relative to server time, if possible, within
         * the 64 bit integer width of the SNTP timestamp. */
        calculateClockOffset( &pResponsePacket->originTime,
                              &pResponsePacket->receiveTime,
                              &pResponsePacket->transmitTime,
                              pResponseRxTime,
                              &pParsedResponse->clockOffset );
    }

    return status;
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
    else if( bufferSize < SNTP_REQUEST_RESPONSE_MINIMUM_PACKET_SIZE )
    {
        status = SntpErrorInsufficientSpace;
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
        pRequestPacket->transmitTime.seconds = SNTP_HTONL_NTOHL( pCurrentTime->seconds );
        pRequestPacket->transmitTime.fractions = SNTP_HTONL_NTOHL( pCurrentTime->fractions );

        status = SntpSuccess;
    }

    return status;
}


SntpStatus_t Sntp_DeserializeResponse( const SntpTimestamp_t * pRequestTime,
                                       const SntpTimestamp_t * pResponseRxTime,
                                       const void * pResponseBuffer,
                                       size_t bufferSize,
                                       SntpResponseData_t * pParsedResponse )
{
    SntpStatus_t status = SntpSuccess;
    SntpPacket_t * pResponsePacket = ( SntpPacket_t * ) pResponseBuffer;

    if( pRequestTime == NULL )
    {
        status = SntpErrorBadParameter;
    }
    else if( pResponseBuffer == NULL )
    {
        status = SntpErrorBadParameter;
    }
    else if( bufferSize < SNTP_REQUEST_RESPONSE_MINIMUM_PACKET_SIZE )
    {
        status = SntpErrorInsufficientSpace;
    }
    else
    {
        /* Check that the server response is valid. */

        /* Check if the packet represents a server in the "Mode" field. */
        if( ( pResponsePacket->leapVersionMode & SNTP_MODE_BITS_MASK ) != SNTP_MODE_SERVER )
        {
            status = SntpInvalidResponse;
        }

        if( status == SntpSuccess )
        {
            /* Validate that the server has sent the client's request timestamp in the
             * "originate" timestamp field of the response. */
            if( ( pRequestTime->seconds !=
                  SNTP_HTONL_NTOHL( pResponsePacket->originTime.seconds ) ) ||
                ( pRequestTime->fractions !=
                  SNTP_HTONL_NTOHL( pResponsePacket->originTime.fractions ) ) )
            {
                status = SntpInvalidResponse;
            }
        }
    }

    if( status == SntpSuccess )
    {
        /* As the response packet is valid, parse more information from it and
         * populate the output parameter. */

        status = parseValidSntpResponse( pResponsePacket,
                                         pResponseRxTime,
                                         pParsedResponse );
    }

    return status;
}
