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
 * @brief The version of SNTP supported by the coreSNTP library by complying
 * with the SNTPv4 specification defined in [RFC 4330](https://tools.ietf.org/html/rfc4330).
 */
#define SNTP_VERSION                        ( 4U )

/**
 * @brief The bit mask for the "Mode" information in the first byte of an SNTP packet.
 * The "Mode" field occupies bits 0-2 of the byte.
 * @note Refer to the [RFC 4330 Section 4](https://tools.ietf.org/html/rfc4330#section-4)
 * for more information.
 */
#define SNTP_MODE_BITS_MASK                 ( 0x07U )

/**
 * @brief The value indicating a "client" in the "Mode" field of an SNTP packet.
 * @note Refer to the [RFC 4330 Section 4](https://tools.ietf.org/html/rfc4330#section-4)
 * for more information.
 */
#define SNTP_MODE_CLIENT                    ( 3U )

/**
 * @brief The value indicating a "server" in the "Mode" field of an SNTP packet.
 * @note Refer to the [RFC 4330 Section 4](https://tools.ietf.org/html/rfc4330#section-4)
 * for more information.
 */
#define SNTP_MODE_SERVER                    ( 4U )

/**
 * @brief The position of the least significant bit of the "Leap Indicator" field
 * in first byte of an SNTP packet. The "Leap Indicator" field occupies bits 6-7 of the byte.
 * @note Refer to the [RFC 4330 Section 4](https://tools.ietf.org/html/rfc4330#section-4)
 * for more information.
 */
#define SNTP_LEAP_INDICATOR_LSB_POSITION    ( 6 )

/**
 * @brief Value of Stratum field in SNTP packet representing a Kiss-o'-Death message
 * from server.
 */
#define SNTP_KISS_OF_DEATH_STRATUM          ( 0U )

/**
 * @brief The position of least significant bit of the "Version" information
 * in the first byte of an SNTP packet. "Version" field occupies bits 3-5 of
 * the byte.
 * @note Refer to the [RFC 4330 Section 4](https://tools.ietf.org/html/rfc4330#section-4)
 * for more information.
 */
#define SNTP_VERSION_LSB_POSITION           ( 3 )

/**
 * @brief The integer value of the Kiss-o'-Death ASCII code, "DENY", used
 * for comparison with data in an SNTP response.
 * @note Refer to [RFC 4330 Section 8](https://tools.ietf.org/html/rfc4330#section-8)
 * for more information.
 */
#define KOD_CODE_DENY_UINT_VALUE            ( 0x44454e59U )

/**
 * @brief The integer value of the Kiss-o'-Death ASCII code, "RSTR", used
 * for comparison with data in an SNTP response.
 * @note Refer to [RFC 4330 Section 8](https://tools.ietf.org/html/rfc4330#section-8)
 * for more information.
 */
#define KOD_CODE_RSTR_UINT_VALUE            ( 0x52535452U )

/**
 * @brief The integer value of the Kiss-o'-Death ASCII code, "RATE", used
 * for comparison with data in an SNTP response.
 * @note Refer to [RFC 4330 Section 8](https://tools.ietf.org/html/rfc4330#section-8)
 * for more information.
 */
#define KOD_CODE_RATE_UINT_VALUE            ( 0x52415445U )

/**
 * @brief Macro to represent the total seconds that are represented in an NTP era period.
 * The macro value represents a duration of ~136 years.
 *
 * @note As the "seconds" part of an NTP timestamp is represented in unsigned 32 bit width,
 * the total number of seconds it can represent is 2^32, i.e. (UINT32_MAX + 1).
 */
#define TOTAL_SECONDS_IN_NTP_ERA            ( ( int64_t ) ( UINT32_MAX ) + ( int64_t ) 1 )

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
    uint8_t leapVersionMode;      /* Bits 6-7 leap indicator, bits 3-5 are version number, bits 0-2 are mode */
    uint8_t stratum;              /* stratum */
    uint8_t poll;                 /* poll interval */
    uint8_t precision;            /* precision */
    uint32_t rootDelay;           /* root delay */
    uint32_t rootDispersion;      /* root dispersion */
    uint32_t refId;               /* reference ID */
    SntpTimestamp_t refTime;      /* reference time */
    SntpTimestamp_t originTime;   /* origin timestamp */
    SntpTimestamp_t receiveTime;  /* receive timestamp */
    SntpTimestamp_t transmitTime; /* transmit timestamp */
} SntpPacket_t;

/**
 * @brief Utility macro to fill 32-bit integer in word-sized
 * memory in network byte (or Big Endian) order.
 *
 * @param[out] pWordMemory Pointer to the word-sized memory in which
 * the 32-bit integer will be filled.
 * @param[in] data The 32-bit integer to fill in the @p wordMemory
 * in network byte order.
 *
 * @note This utility ensures that data is filled in memory
 * in expected network byte order, as an assignment operation
 * (like *pWordMemory = word) can cause undesired side-effect
 * of network-byte ordering getting reversed on Little Endian platforms.
 */
static void fillWordMemoryInNetworkOrder( uint32_t * pWordMemory,
                                          uint32_t data )
{
    assert( pWordMemory != NULL );

    *( ( uint8_t * ) pWordMemory ) = ( uint8_t ) ( data >> 24 );
    *( ( uint8_t * ) pWordMemory + 1 ) = ( uint8_t ) ( ( data >> 16 ) & 0x000000FFU );
    *( ( uint8_t * ) pWordMemory + 2 ) = ( uint8_t ) ( ( data >> 8 ) & 0x000000FFU );
    *( ( uint8_t * ) pWordMemory + 3 ) = ( uint8_t ) ( ( data ) & 0x000000FFU );
}

/**
 * @brief Utility macro to generate a 32-bit integer from memory containing
 * integer in network (or Big Endian) byte order.
 * @param[in] ptr Pointer to the memory containing 32-bit integer in network
 * byte order.
 *
 * @return The host representation of the 32-bit integer in the passed word
 * memory.
 */
static uint32_t readWordFromNetworkByteOrderMemory( const uint32_t * ptr )
{
    const uint8_t * pMemStartByte = ( const uint8_t * ) ptr;

    assert( ptr != NULL );

    return ( uint32_t ) ( ( ( uint32_t ) *( pMemStartByte ) << 24 ) |
                          ( 0x00FF0000U & ( ( uint32_t ) *( pMemStartByte + 1 ) << 16 ) ) |
                          ( 0x0000FF00U & ( ( uint32_t ) *( pMemStartByte + 2 ) << 8 ) ) |
                          ( ( uint32_t ) *( pMemStartByte + 3 ) ) );
}

/**
 * @brief Utility to return absolute (or positively signed) value of an signed
 * 64 bit integer.
 *
 * @param[in] value The integer to return the absolute value of.
 *
 * @return The absolute value of @p value.
 */
static int64_t absoluteOf( int64_t value )
{
    return ( value >= ( int64_t ) 0 ) ?
           value : ( ( int64_t ) 0 - value );
}

/**
 * @brief Utility to safely calculate difference between server and client timestamps of
 * unsigned integer type and return the value as a signed 64 bit integer. The calculated value
 * represents the effective subtraction as ( @p serverTimeSec - @p clientTimeSec ).
 *
 * @note This utility SUPPORTS the cases of server and client timestamps being in different NTP eras,
 * and ASSUMES that the server and client systems are within 68 years of each other.
 * To handle the case of different NTP eras, this function calculates difference values for all
 * possible combinations of NTP eras of server and client times (i.e. 1. both timestamps in same era,
 * 2. server timestamp one era ahead, and 3. client timestamp being one era ahead), and determines
 * the NTP era configuration by choosing the difference value of the smallest absolute value.
 *
 * @param[in] serverTimeSec The "seconds" part of the server timestamp.
 * @param[in] clientTimeSec The "seconds" part of the client timestamp.
 *
 * @return The calculated difference between server and client times as a signed 64 bit integer.
 */
static int64_t safeTimeDifference( uint32_t serverTimeSec,
                                   uint32_t clientTimeSec )
{
    int64_t eraAdjustedDiff = 0;

    /* Convert the "seconds" part of timestamps to signed 64 bit integer along with determining
     * relative NTP era presence of server time relative to client time. */
    int64_t serverTime = ( int64_t ) serverTimeSec;
    int64_t clientTime = ( int64_t ) clientTimeSec;

    /* First, calculate the first order time difference assuming that server and client times
     * are in the same NTP era. */
    int64_t diffWithNoEraAdjustment = serverTime - clientTime;

    /* If the difference value is INT32_MIN, it means that the server and client times are away by
     * exactly half the range of SNTP timestamp "second" values representable in unsigned 32 bits.
     * In this case, the NTP era presence of the server and client systems cannot be determined just
     * by comparing the first order differences of different era configurations, thus, we will ASSUME
     * that the server time is AHEAD of client time.
     * Note: As a signed 32 bit integer cannot represent value of 2^31 (or 2147483648 ) as a positive
     * value, but we are assuming that the server is ahead of client, thereby, generating a positive clock offset
     *, we will return the maximum value representable by signed 2^31, i.e. 2147483647, resulting in
     * an inaccuracy of 1 second in the clock-offset value.
     */
    if( diffWithNoEraAdjustment == INT32_MIN )
    {
        /* It does not matter whether server and client are in the same era for this
         * special case as the difference value for both same and adjacent eras will yield
         * the same absolute value of 2^31.*/
        eraAdjustedDiff = INT32_MAX;
    }
    else
    {
        /* Determine if server time belongs to an NTP era different than the client time, and accordingly
         * choose the 64 bit representation of the first order difference to account for the era.
         * The logic for determining the relative era presence of the timestamps is by calculating the
         * first order difference (of "Server Time - Client Time") for all the 3 different era combinations
         * (1. both timestamps in same era, 2. server time one era ahead, 3. client time one era ahead)
         * and choosing the NTP era configuration that has the smallest first order difference value.
         */
        int64_t diffWithServerEraAdjustment = serverTime + TOTAL_SECONDS_IN_NTP_ERA -
                                              clientTime;                                /* This helps determine whether server is an
                                                                                          * era ahead of client time. */
        int64_t diffWithClientEraAdjustment = serverTime -
                                              ( TOTAL_SECONDS_IN_NTP_ERA + clientTime ); /* This helps determine whether server is an
                                                                                          * era behind of client time. */

        /* Store the absolute value equivalents of all the time difference configurations
         * for easier comparison to smallest value from them. */
        int64_t absSameEraDiff = absoluteOf( diffWithNoEraAdjustment );
        int64_t absServerEraAheadDiff = absoluteOf( diffWithServerEraAdjustment );
        int64_t absClientEraAheadDiff = absoluteOf( diffWithClientEraAdjustment );

        /* Determine the correct relative era of client and server times by checking which era
         * configuration of difference value represents the least difference. */
        if( ( absSameEraDiff <= absServerEraAheadDiff ) && ( absSameEraDiff <= absClientEraAheadDiff ) )
        {
            /* Both server and client times are in the same era. */
            eraAdjustedDiff = diffWithNoEraAdjustment;
        }
        /* Check if server time is an NTP era ahead of client time. */
        else if( absSameEraDiff <= absServerEraAheadDiff )
        {
            /* Server time is in NTP era 1 while client time is in NTP era 0. */
            eraAdjustedDiff = diffWithServerEraAdjustment;
        }
        /* Now, we know that the client time is an era ahead of server time. */
        else
        {
            /* Server time is in NTP era 0 while client time is in NTP era 1. */
            eraAdjustedDiff = diffWithClientEraAdjustment;
        }
    }

    return eraAdjustedDiff;
}

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
 *
 * @return #SntpSuccess if clock-offset is calculated; #SntpClockOffsetOverflow
 * otherwise for inability to calculate from arithmetic overflow.
 */
static SntpStatus_t calculateClockOffset( const SntpTimestamp_t * pClientTxTime,
                                          const SntpTimestamp_t * pServerRxTime,
                                          const SntpTimestamp_t * pServerTxTime,
                                          const SntpTimestamp_t * pClientRxTime,
                                          int32_t * pClockOffset )
{
    SntpStatus_t status = SntpSuccess;

    /* Variable for storing the first-order difference between timestamps. */
    int64_t firstOrderDiffSend = 0;
    int64_t firstOrderDiffRecv = 0;
    int64_t clockOffSet = 0;

    assert( pClientTxTime != NULL );
    assert( pServerRxTime != NULL );
    assert( pServerTxTime != NULL );
    assert( pClientRxTime != NULL );
    assert( pClockOffset != NULL );

    /* Perform first order difference of timestamps on the network send path i.e. T2 - T1.
     * Note: The calculated difference value will always represent years in the range of
     *[-68 years, +68 years] i.e. a value in the range of [INT32_MIN, INT32_MAX]. */
    firstOrderDiffSend = safeTimeDifference( pServerRxTime->seconds, pClientTxTime->seconds );

    /* Perform first order difference of timestamps on the network receive path i.e. T3 - T4 .
     * Note: The calculated difference value will always represent years in the range of
     *[-68 years, +68 years] i.e. a value in the range of [INT32_MIN, INT32_MAX]. */
    firstOrderDiffRecv = safeTimeDifference( pServerTxTime->seconds, pClientRxTime->seconds );

    /* Now calculate the system clock-offset relative to server time as the average of the
     * first order difference of timestamps in both directions of network path.
     * Note: This will ALWAYS represent offset in the range of [-68 years, +68 years]. */
    clockOffSet = ( firstOrderDiffSend + firstOrderDiffRecv ) / 2;

    /* We can represent the calculated clock-offset as signed 32 integer as the calculated
     * clock offset will ALWAYS be in the signed 32 integer range. */
    *pClockOffset = ( int32_t ) clockOffSet;

    return status;
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
 * rejectedResponseCode member of the output parameter to #SNTP_KISS_OF_DEATH_CODE_NONE,
 * and set the other the members with appropriate data extracted from the response
 * packet.
 *
 * @param[in] pResponsePacket The SNTP response packet from server to parse.
 * @param[in] pRequestTxTime The system time (in SNTP timestamp format) of
 * sending the SNTP request to server.
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
 * - #SntpRejectedResponseOtherCode if the server rejected with a code
 * other than "DENY", "RSTR" and "RATE".
 */
static SntpStatus_t parseValidSntpResponse( const SntpPacket_t * pResponsePacket,
                                            const SntpTimestamp_t * pRequestTxTime,
                                            const SntpTimestamp_t * pResponseRxTime,
                                            SntpResponseData_t * pParsedResponse )
{
    SntpStatus_t status = SntpSuccess;

    assert( pResponsePacket != NULL );
    assert( pResponseRxTime != NULL );
    assert( pParsedResponse != NULL );

    /* Clear the output parameter memory to zero. */
    ( void ) memset( pParsedResponse, 0, sizeof( *pParsedResponse ) );

    /* Determine if the server has accepted or rejected the request for time. */
    if( pResponsePacket->stratum == SNTP_KISS_OF_DEATH_STRATUM )
    {
        /* Server has sent a Kiss-o'-Death message i.e. rejected the request. */

        /* Extract the kiss-code sent by the server from the "Reference ID" field
         * of the SNTP packet. */
        pParsedResponse->rejectedResponseCode =
            readWordFromNetworkByteOrderMemory( &pResponsePacket->refId );

        /* Determine the return code based on the Kiss-o'-Death code. */
        switch( pParsedResponse->rejectedResponseCode )
        {
            case KOD_CODE_DENY_UINT_VALUE:
            case KOD_CODE_RSTR_UINT_VALUE:
                status = SntpRejectedResponseChangeServer;
                break;

            case KOD_CODE_RATE_UINT_VALUE:
                status = SntpRejectedResponseRetryWithBackoff;
                break;

            default:
                status = SntpRejectedResponseOtherCode;
                break;
        }
    }
    else
    {
        /* Server has responded successfully to the time request. */

        SntpTimestamp_t serverRxTime;

        /* Map of integer value to SntpLeapSecondInfo_t enumeration type for the
         * "Leap Indicator" field in the first byte of an SNTP packet.
         * Note: This map is used to not violate MISRA Rule 10.5 when directly
         * converting an integer to enumeration type.
         */
        const SntpLeapSecondInfo_t leapIndicatorTypeMap[] =
        {
            NoLeapSecond,
            LastMinuteHas61Seconds,
            LastMinuteHas59Seconds,
            AlarmServerNotSynchronized
        };

        /* Set the Kiss-o'-Death code value to NULL as server has responded favorably
         * to the time request. */
        pParsedResponse->rejectedResponseCode = SNTP_KISS_OF_DEATH_CODE_NONE;

        /* Fill the output parameter with the server time which is the
         * "transmit" time in the response packet. */
        pParsedResponse->serverTime.seconds =
            readWordFromNetworkByteOrderMemory( &pResponsePacket->transmitTime.seconds );
        pParsedResponse->serverTime.fractions =
            readWordFromNetworkByteOrderMemory( &pResponsePacket->transmitTime.fractions );

        /* Extract information of any upcoming leap second from the response. */
        pParsedResponse->leapSecondType = leapIndicatorTypeMap[
            ( pResponsePacket->leapVersionMode
              >> SNTP_LEAP_INDICATOR_LSB_POSITION ) ];

        /* Store the "receive" time in SNTP response packet in host order. */
        serverRxTime.seconds =
            readWordFromNetworkByteOrderMemory( &pResponsePacket->receiveTime.seconds );
        serverRxTime.fractions =
            readWordFromNetworkByteOrderMemory( &pResponsePacket->receiveTime.fractions );

        /* Calculate system clock offset relative to server time, if possible, within
         * the 64 bit integer width of the SNTP timestamp. */
        status = calculateClockOffset( pRequestTxTime,
                                       &serverRxTime,
                                       &pParsedResponse->serverTime,
                                       pResponseRxTime,
                                       &pParsedResponse->clockOffsetSec );
    }

    return status;
}


SntpStatus_t Sntp_SerializeRequest( SntpTimestamp_t * pRequestTime,
                                    uint32_t randomNumber,
                                    void * pBuffer,
                                    size_t bufferSize )
{
    SntpStatus_t status = SntpSuccess;

    if( pRequestTime == NULL )
    {
        status = SntpErrorBadParameter;
    }
    else if( pBuffer == NULL )
    {
        status = SntpErrorBadParameter;
    }
    else if( bufferSize < SNTP_PACKET_BASE_SIZE )
    {
        status = SntpErrorBufferTooSmall;
    }
    else
    {
        SntpPacket_t * pRequestPacket = ( SntpPacket_t * ) pBuffer;

        /* Fill the buffer with zero as most fields are zero for a standard SNTP
         * request packet.*/
        ( void ) memset( pBuffer, 0, sizeof( SntpPacket_t ) );

        /* Set the first byte of the request packet for "Version" and "Mode" fields */
        pRequestPacket->leapVersionMode = 0U /* Leap Indicator */ |
                                          ( SNTP_VERSION << SNTP_VERSION_LSB_POSITION ) /* Version Number */ |
                                          SNTP_MODE_CLIENT /* Mode */;


        /* Add passed random number to non-significant bits of the fractions part
         * of the transmit timestamp.
         * This is suggested by the SNTPv4 (and NTPv4) specification(s)
         * to protect against replay attacks. Refer to RFC 4330 Section 3 for
         * more information.
         * Adding random bits to the least significant 16 bits of the fractions
         * part of the timestamp affects only ~15 microseconds of information
         * (calculated as 0xFFFF * 232 picoseconds).
         */
        pRequestTime->fractions = ( pRequestTime->fractions
                                    | ( randomNumber >> 16 ) );

        /* Update the request buffer with request timestamp in network byte order. */
        fillWordMemoryInNetworkOrder( &pRequestPacket->transmitTime.seconds,
                                      pRequestTime->seconds );
        fillWordMemoryInNetworkOrder( &pRequestPacket->transmitTime.fractions,
                                      pRequestTime->fractions );
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
    const SntpPacket_t * pResponsePacket = ( const SntpPacket_t * ) pResponseBuffer;

    if( ( pRequestTime == NULL ) || ( pResponseRxTime == NULL ) ||
        ( pResponseBuffer == NULL ) || ( pParsedResponse == NULL ) )
    {
        status = SntpErrorBadParameter;
    }
    else if( bufferSize < SNTP_PACKET_BASE_SIZE )
    {
        status = SntpErrorBufferTooSmall;
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
                  readWordFromNetworkByteOrderMemory( &pResponsePacket->originTime.seconds ) ) ||
                ( pRequestTime->fractions !=
                  readWordFromNetworkByteOrderMemory( &pResponsePacket->originTime.fractions ) ) )
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
                                         pRequestTime,
                                         pResponseRxTime,
                                         pParsedResponse );
    }

    return status;
}

SntpStatus_t Sntp_CalculatePollInterval( uint16_t clockFreqTolerance,
                                         uint16_t desiredAccuracy,
                                         uint32_t * pPollInterval )
{
    SntpStatus_t status = SntpSuccess;

    if( ( clockFreqTolerance == 0U ) || ( desiredAccuracy == 0U ) || ( pPollInterval == NULL ) )
    {
        status = SntpErrorBadParameter;
    }
    else
    {
        uint32_t exactIntervalForAccuracy = 0U;
        uint8_t log2PollInterval = 0U;

        /* Calculate the poll interval required for achieving the exact desired clock accuracy
         * with the following formulae:
         *
         * System Clock Drift Rate ( microseconds / second ) = Clock Frequency Tolerance (in PPM )
         * Maximum Clock Drift ( milliseconds ) = Desired Accuracy ( milliseconds )
         *
         * Poll Interval ( seconds ) =     Maximum Clock Drift
         *                              ---------------------------
         *                                System Clock Drift Rate
         *
         *                           =  Maximum Drift ( milliseconds ) * 1000 ( microseconds / millisecond )
         *                             ------------------------------------------------------------------------
         *                                        System Clock Drift Rate ( microseconds / second )
         *
         *                           =    Desired Accuracy * 1000
         *                             ------------------------------
         *                               Clock Frequency Tolerance
         */
        exactIntervalForAccuracy = ( ( uint32_t ) desiredAccuracy * 1000U ) / clockFreqTolerance;

        /* Check if calculated poll interval value falls in the supported range of seconds. */
        if( exactIntervalForAccuracy == 0U )
        {
            /* Poll interval value is less than 1 second, and is not supported by the function. */
            status = SntpZeroPollInterval;
        }
        else
        {
            /* To calculate the log 2 value of the exact poll interval value, first determine the highest
             * bit set in the value. */
            while( exactIntervalForAccuracy != 0U )
            {
                log2PollInterval++;
                exactIntervalForAccuracy /= 2U;
            }

            /* Convert the highest bit in the exact poll interval value to the nearest integer
             * value lower or equal to the log2 of the exact poll interval value. */
            log2PollInterval--;

            /* Calculate the poll interval as the closest exponent of 2 value that achieves
             * equal or higher accuracy than the desired accuracy. */
            *pPollInterval = ( ( ( uint32_t ) 1U ) << log2PollInterval );
        }
    }

    return status;
}

SntpStatus_t Sntp_ConvertToUnixTime( const SntpTimestamp_t * pSntpTime,
                                     uint32_t * pUnixTimeSecs,
                                     uint32_t * pUnixTimeMicrosecs )
{
    SntpStatus_t status = SntpSuccess;

    if( ( pSntpTime == NULL ) || ( pUnixTimeSecs == NULL ) || ( pUnixTimeMicrosecs == NULL ) )
    {
        status = SntpErrorBadParameter;
    }
    /* Check if passed time does not lie in the [UNIX epoch in 1970, UNIX time overflow in 2038] time range. */
    else if( ( pSntpTime->seconds > SNTP_TIME_AT_LARGEST_UNIX_TIME_SECS ) &&
             ( pSntpTime->seconds < SNTP_TIME_AT_UNIX_EPOCH_SECS ) )
    {
        /* The SNTP timestamp is outside the supported time range for conversion. */
        status = SntpErrorTimeNotSupported;
    }
    else
    {
        /* Handle case when timestamp represents date in SNTP era 1
         * (i.e. time from 7 Feb 2036 6:28:16 UTC onwards). */
        if( pSntpTime->seconds <= SNTP_TIME_AT_LARGEST_UNIX_TIME_SECS )
        {
            /* Unix Time ( seconds ) = Seconds Duration in
             *                         [UNIX epoch, SNTP Era 1 Epoch Time]
             *                                        +
             *                           Sntp Time since Era 1 Epoch
             */
            *pUnixTimeSecs = UNIX_TIME_SECS_AT_SNTP_ERA_1_SMALLEST_TIME + pSntpTime->seconds;
        }
        /* Handle case when SNTP timestamp is in SNTP era 1 time range. */
        else
        {
            *pUnixTimeSecs = pSntpTime->seconds - SNTP_TIME_AT_UNIX_EPOCH_SECS;
        }

        /* Convert SNTP fractions to microseconds for UNIX time. */
        *pUnixTimeMicrosecs = pSntpTime->fractions / SNTP_FRACTION_VALUE_PER_MICROSECOND;
    }

    return status;
}
