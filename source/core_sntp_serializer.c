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
#define SNTP_VERSION                                        ( 4U )

/**
 * @brief The bit mask for the "Mode" information in the first byte of an SNTP packet.
 * The "Mode" field occupies bits 0-2 of the byte.
 * @note Refer to the [RFC 4330 Section 4](https://tools.ietf.org/html/rfc4330#section-4)
 * for more information.
 */
#define SNTP_MODE_BITS_MASK                                 ( 0x07U )

/**
 * @brief The value indicating a "client" in the "Mode" field of an SNTP packet.
 * @note Refer to the [RFC 4330 Section 4](https://tools.ietf.org/html/rfc4330#section-4)
 * for more information.
 */
#define SNTP_MODE_CLIENT                                    ( 3U )

/**
 * @brief The value indicating a "server" in the "Mode" field of an SNTP packet.
 * @note Refer to the [RFC 4330 Section 4](https://tools.ietf.org/html/rfc4330#section-4)
 * for more information.
 */
#define SNTP_MODE_SERVER                                    ( 4U )

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
#define SNTP_KISS_OF_DEATH_STRATUM                          ( 0U )

/**
 * @brief The position of least significant bit of the "Version" information
 * in the first byte of an SNTP packet. "Version" field occupies bits 3-5 of
 * the byte.
 * @note Refer to the [RFC 4330 Section 4](https://tools.ietf.org/html/rfc4330#section-4)
 * for more information.
 */
#define SNTP_VERSION_LSB_POSITION                           ( 3 )

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
 * @brief The bit mask for the most-significant bit in an unsigned 32 bit integer.
 * This value is used in the intermediate conversion of unsigned integer to signed
 * integer for the first order difference values during clock-offset calculation.
 *
 * @note The conversion from unsigned to signed integer of first order difference
 * values uses this macro to check whether assignment of the unsigned value to signed
 * integer will overflow, and accordingly, change the unsigned value to safely perform
 * the conversion.
 */
#define UINT32_MOST_SIGNIFICANT_BIT_BIT_MASK                ( 0x80000000U )

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
 * @brief Utility to determine whether the passed first order difference value
 * between server and client timestamps represents that the server and client
 * are within 34 years of each other to be able to calculate the clock-offset
 * value according to the NTPv4 specification's on-wire protocol.
 *
 * @param[in] firstOrderDiff A first-order difference value between the client
 * and server.
 *
 * @note As the SNTP timestamp value wraps around after ~136 years (exactly at
 * 7 Feb 2036 6h 28m 16s), the utility logic checks the first order difference
 * in both polarities (i.e. as (Server - Client) and (Client - Server) time values )
 * to support the edge case when the two timestamps are in different SNTP eras (for
 * example, server time is in 2037 and client time is in 2035 ).
 */
static bool isEligibleForClockOffsetCalculation( uint32_t firstOrderDiff )
{
    /* Note: The (~firstOrderDiff + 1U) expression represents 2's complement or negation of value.
     * This is done to be compliant with both CBMC and MISRA Rule 10.1.
     * CBMC flags overflow for (unsigned int = 0U - positive value) whereas
     * MISRA rule forbids use of unary minus operator on unsigned integers. */
    return( ( ( firstOrderDiff & CLOCK_OFFSET_FIRST_ORDER_DIFF_OVERFLOW_BITS_MASK ) == 0U ) ||
            ( ( ( ~firstOrderDiff + 1U ) & CLOCK_OFFSET_FIRST_ORDER_DIFF_OVERFLOW_BITS_MASK ) == 0U ) );
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
    uint32_t firstOrderDiffSend = 0;
    uint32_t firstOrderDiffRecv = 0;
    bool sendPolarity, recvPolarity;

    assert( pClientTxTime != NULL );
    assert( pServerRxTime != NULL );
    assert( pServerTxTime != NULL );
    assert( pClientRxTime != NULL );
    assert( pClockOffset != NULL );

    /* On-wire protocol formula's polarity for first order difference in the send network
     * path is T2 (Server Rx) - T1 (Client Tx) .*/
    sendPolarity = ( pServerRxTime->seconds >= pClientTxTime->seconds ) ? true : false;

    /* On-wire protocol formula's polarity for first order difference in the receive network
     * path is T3 (Server Tx) - T4 (Client Rx) .*/
    recvPolarity = ( pServerTxTime->seconds >= pClientRxTime->seconds ) ? true : false;

    /* Calculate first order difference values between the server and system timestamps
     * to determine whether they are within 34 years of each other. */

    /* To avoid overflow issue, we will store only the positive first order difference
     * values in the unsigned integer now, and later store the values with correct polarity
     * (according to the formula) later. */
    firstOrderDiffSend = sendPolarity ? ( pServerRxTime->seconds - pClientTxTime->seconds ) :
                         ( pClientTxTime->seconds - pServerRxTime->seconds );
    firstOrderDiffRecv = recvPolarity ? ( pServerTxTime->seconds - pClientRxTime->seconds ) :
                         ( pClientRxTime->seconds - pServerTxTime->seconds );

    /* Determine from the first order differences if the system time is within
     * 34 years of server time to be able to calculate clock offset.
     */
    if( isEligibleForClockOffsetCalculation( firstOrderDiffSend ) &&
        isEligibleForClockOffsetCalculation( firstOrderDiffRecv ) )
    {
        /* Now that we have validated that system and server times are within 34 years
         * of each other, we will prepare for the clock-offset calculation. To calculate
         * clock-offset, the first order difference values need to be stored as signed integers
         * in the correct polarity of differences according to the formula. */
        int32_t signedFirstOrderDiffSend = 0;
        int32_t signedFirstOrderDiffRecv = 0;

        /* To avoid overflow issues in assigning the unsigned values of first order differences
         * to signed integers, we will inverse the values if they represent a large value that cannot be
         * represented in a signed integer. */
        if( ( firstOrderDiffSend & UINT32_MOST_SIGNIFICANT_BIT_BIT_MASK )
            == UINT32_MOST_SIGNIFICANT_BIT_BIT_MASK )

        {
            /* Negate the unsigned integer by performing 2's complement operation.
             * Note: This is done to be compliant with both CBMC and MISRA Rule 10.1.
             * CBMC flags overflow for (unsigned int = 0U - positive value) whereas
             * MISRA rule forbids use of unary minus operator on unsigned integers. */
            firstOrderDiffSend = ~firstOrderDiffSend + 1U;
            sendPolarity = !sendPolarity;
        }

        if( ( firstOrderDiffRecv & UINT32_MOST_SIGNIFICANT_BIT_BIT_MASK )
            == UINT32_MOST_SIGNIFICANT_BIT_BIT_MASK )

        {
            /* Negate the unsigned integer by performing 2's complement operation.
             * Note: This is done to be compliant with both CBMC and MISRA Rule 10.1.
             * CBMC flags overflow for (unsigned int = 0U - positive value) whereas
             * MISRA rule forbids use of unary minus operator on unsigned integers. */
            firstOrderDiffRecv = ~firstOrderDiffRecv + 1U;
            recvPolarity = !recvPolarity;
        }

        /* Now we can safely store the first order differences as signed integer values. */
        signedFirstOrderDiffSend = ( int32_t ) firstOrderDiffSend;
        signedFirstOrderDiffRecv = ( int32_t ) firstOrderDiffRecv;

        /* To calculate the clock-offset value, we will correct the signed first order difference
        * values to match the subtraction polarity direction of "Server Time" - "Client Time". */
        if( sendPolarity == false )
        {
            signedFirstOrderDiffSend = 0 - signedFirstOrderDiffSend;
        }

        if( recvPolarity == false )
        {
            signedFirstOrderDiffRecv = 0 - signedFirstOrderDiffRecv;
        }

        /* We are now sure that each of the first order differences represents the values in
         * the correct direction of polarities, i.e.
         * signedFirstOrderDiffSend represents (T2 - T1)
         *                AND
         *  signedFirstOrderDiffRecv represents (T3 - T4)
         *
         * We are now safe to complete the calculation of the clock-offset as the average
         * of the signed first order difference values.
         */

        /* Use division instead of a bit shift to guarantee sign extension
         * regardless of compiler implementation. */
        *pClockOffset = ( ( signedFirstOrderDiffSend + signedFirstOrderDiffRecv ) / 2 );
    }
    else
    {
        /* System clock-offset cannot be calculated as arithmetic operation will overflow. */
        *pClockOffset = SNTP_CLOCK_OFFSET_OVERFLOW;

        status = SntpClockOffsetOverflow;
    }

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
