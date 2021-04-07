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
 * @file core_sntp_serializer.h
 * @brief API for serializing SNTP request packets and, and de-serializing SNTP
 * response packets.
 * This API layer adheres to the SNTPv4 specification defined in
 * [RFC 4330](https://tools.ietf.org/html/rfc4330).
 */

#ifndef CORE_SNTP_SERIALIZER_H_
#define CORE_SNTP_SERIALIZER_H_

/* Standard include. */
#include <stdint.h>

/**
 * @brief The base packet size of request and response of the (S)NTP protocol.
 * @note This is the packet size without any authentication headers for security
 * mechanism. If the application uses a security mechanism for communicating with
 * an (S)NTP server, it can perform add authentication data after the SNTP packet
 * is serialized with the @ref Sntp_SerializeRequest API function.
 */
#define SNTP_REQUEST_RESPONSE_MINIMUM_PACKET_SIZE    ( 48U )

/**
 * @brief Number of SNTP timestamp resolution of 232 picoseconds per microsecond.
 *
 * The fraction's part of an SNTP timestamp is 32-bits wide, thereby, giving a
 * resolution of 2^(-32) seconds ~ 232 picoseconds.
 *
 * @note The application can use this value to convert fractions part of system
 * time into SNTP timestamp format.
 */
#define SNTP_FRACTION_RESOLUTIONS_PER_MICROSECOND    ( 4295U )

/**
 * @brief The fixed-length of any Kiss-o'-Death message ASCII code sent
 * in an SNTP server response.
 * @note An SNTP server sends a Kiss-o'-Death message to reject a time request
 * from the client. For more information on the Kiss-o'-Death codes, refer to the
 * [SNTPv4 specification Section 8](https://tools.ietf.org/html/rfc4330#section-8).
 */
#define SNTP_KISS_OF_DEATH_CODE_LENGTH               ( 4U )

/**
 * @brief The value for the #SntpResponseData_t.pRejectedResponseCode member
 * when that the server response packet does not contain a Kiss-o'-Death
 * message, and therefore, does not have a "kiss code".
 * The server sends a "kiss-code" only when it rejects an SNTP request
 * with a Kiss-o'-Death message.
 */
#define SNTP_KISS_OF_DEATH_CODE_INVALID              ( NULL )

/**
 * @brief The value for clock offset that indicates inability to perform
 * arithmetic calculation of system clock offset relative to the server time
 * due to overflow.
 *
 * The application should use this macro against the seconds part of the clock
 * offset value i.e. @ref SntpResponseData_t.clockOffset.seconds. If the seconds
 * part is set to this macro, then the entire clock offset value is unusable.
 *
 * @note A clock offset overflow occurs if the system time is beyond 34 years
 * (in the past or future) of the server time.
 *
 * @note The clock offset as a value with 62 significant bits and 2 sign bits
 * in a 64 bit integer. This macro uses a value that cannot be a valid clock
 * offset value as a valid value will always have the 2 most significant
 * bits set as either zero (i.e. to represent positive offset) or one
 * (i.e. to represent negative offset).
 */
#define SNTP_CLOCK_OFFSET_OVERFLOW                   ( 0x7FFFFFFFU )

/**
 * @ingroup core_sntp_enum_types
 * @brief Enumeration of status codes that can be returned
 * by the coreSNTP Library API.
 */
typedef enum SntpStatus
{
    /**
     * @brief Successful operation of an SNTP API.
     */
    SntpSuccess,

    /**
     * @brief Invalid parameter passed to an API function.
     */
    SntpErrorBadParameter,

    /**
     * @brief Server sent a Kiss-o'-Death message with non-retryable code (i.e. DENY or RSTR).
     */
    SntpRejectedResponseChangeServer,

    /**
     * @brief Server sent a Kiss-o'-Death message with a RATE code, which means that
     * client should back-off before retrying.
     */
    SntpRejectedResponseRetryWithBackoff,

    /**
     * @brief Server sent a Kiss-o'-Death message with a code, specific to the server.
     * Application can inspect the ASCII kiss-code from @ref Sntp_DeserializeResponse API.
     */
    SntpRejectedResponseCodeOther,

    /**
     * @brief Application provided insufficient buffer space for serializing
     * or de-serializing an SNTP packet.
     * The minimum size of an SNTP packet is #SNTP_REQUEST_RESPONSE_MINIMUM_PACKET_SIZE
     * bytes. */
    SntpErrorInsufficientSpace,

    /**
     * @brief Server response failed validation checks for expected data in SNTP packet.
     */
    SntpInvalidResponse
} SntpStatus_t;

/**
 * @brief Enumeration for leap second information that an SNTP server can
 * send its response to a time request. An SNTP server sends information about
 * whether there is an upcoming leap second adjustment in the last day of the
 * current month.
 *
 * @note A leap second is an adjustment made in atomic clock time because Earth's rotation
 * can be inconsistent. Leap seconds are usually incorporated as an extra second insertion
 * or second deletion in the last minute before midnight i.e. in the minute of 23h:59h UTC
 * on the 31st of June or December. For more information on leap seconds, refer to
 * https://www.nist.gov/pml/time-and-frequency-division/leap-seconds-faqs.
 */
typedef enum SntpLeapSecondInfo
{
    NoLeapSecond = 0x00,              /** <@brief There is no upcoming leap second adjustment. */
    LastMinuteHas61Seconds = 0x01,    /** <@brief A leap second should be inserted in the last minute before midnight. */
    LastMinuteHas59Seconds = 0x02,    /** <@brief A leap second should be deleted from the last minute before midnight. */
    AlarmServerNotSynchronized = 0x03 /** <@brief An alarm condition meaning that server's time is not synchronized
                                       * to an upstream NTP (or SNTP) server. */
} SntpLeapSecondInfo_t;


/**
 * @ingroup core_sntp_struct_types
 * @brief Structure representing an SNTP timestamp.
 * @note The SNTP timestamp uses 1st January 1900 0h 0m 0s Coordinated Universal Time (UTC)
 * as the primary epoch i.e. the timestamp represents current time as the amount of time since
 * the epoch time.
 */
typedef struct SntpTimestamp
{
    uint32_t seconds;   /**< @brief Number of seconds since epoch time. */
    uint32_t fractions; /**< @brief The fractions part of the SNTP timestamp with resolution
                         *   of 2^(-32) ~ 232 picoseconds. */
} SntpTimestamp_t;

/**
 * @ingroup core_sntp_struct_types
 * @brief Structure representing data parsed from an SNTP response from server
 * as well as data of arithmetic calculations derived from the response.
 */
typedef struct SntpResponse
{
    /**
     * @brief The timestamp sent by the server.
     */
    SntpTimestamp_t serverTime;

    /**
     * @brief The information of an upcoming leap second in the
     * server response.
     */
    SntpLeapSecondInfo_t leapSecondType;

    /**
     * @brief If a server responded with Kiss-o'-Death message to reject
     * time request, this is the fixed length ASCII code for the rejection.
     *
     * The Kiss-o'-Death code is always #SNTP_KISS_OF_DEATH_CODE_LENGTH
     * bytes long.
     *
     * @note If the server does not send a Kiss-o'-Death message in its
     * response, this value will be #SNTP_KISS_OF_DEATH_CODE_INVALID.
     */
    const char * pRejectedResponseCode;

    /**
     * @brief The offset (in seconds) of the system clock relative to the
     * server time calculated from client request and server response
     * times. This information can be used to synchronize the system clock
     * with a "slew" or "step" correction approach.
     *
     * @note The system clock MUST be within 34 years (in the past or future)
     * of the server time for this calculation. This is a fundamental limitation
     * of 64 bit integer arithmetic.
     * If the system clock is beyond 34 years of server time, then this value
     * will be set to #SNTP_CLOCK_OFFSET_OVERFLOW.
     */
    SntpTimestamp_t clockOffset;
} SntpResponseData_t;


/**
 * @brief Serializes an SNTP request packet to use for querying a
 * time server.
 *
 * This function will fill only #SNTP_REQUEST_RESPONSE_MINIMUM_PACKET_SIZE
 * bytes of data in the passed buffer.
 *
 * @param[in, out] pCurrentTime The current time of the system, expressed as time
 * since the SNTP epoch (i.e. 0h of 1st Jan 1900 ). This time will be serialized
 * in the SNTP request packet. If a non-zero random @p randomNumber value is passed,
 * the function will update this parameter to store the timestamp serialized
 * in the SNTP request.
 * @param[in] randomNum A random number (generated by a True Random Generator)
 * for use in the SNTP request packet to protect against replay attacks as suggested
 * by SNTPv4 specification. For more information, refer to
 * [RFC 4330 Section 5](https://tools.ietf.org/html/rfc4330#section-3).
 * @param[out] pBuffer The buffer that will be populated with the serialized
 * SNTP request packet.
 * @param[in] bufferSize The size of the @p pBuffer buffer. It MUST be at least
 * #SNTP_REQUEST_RESPONSE_MINIMUM_PACKET_SIZE bytes in size.
 *
 * @note It is recommended to use a True Random Generator (TRNG) to generate
 * the random number.
 * @note The application MUST save the @p pRequestTime value for de-serializing
 * the server response with @ref Sntp_DeserializeResponse API.
 *
 * @return This function returns one of the following:
 * - #SntpSuccess when serialization operation is successful.
 * - #SntpBadParameter if an invalid parameter is passed.
 * - #SntpErrorInsufficientSpace if the buffer does not have the minimum size
 * for serializing an SNTP request packet.
 */
/* @[define_sntp_serializerequest] */
SntpStatus_t Sntp_SerializeRequest( SntpTimestamp_t * pRequestTime,
                                    uint32_t randomNumber,
                                    void * pBuffer,
                                    size_t bufferSize );
/* @[define_sntp_serializerequest] */

/**
 * @brief De-serializes an SNTP packet received from a server as a response
 * to a SNTP request.
 *
 * This function will parse only the #SNTP_REQUEST_RESPONSE_MINIMUM_PACKET_SIZE
 * bytes of data in the passed buffer.
 *
 * @note If the server has sent a Kiss-o'-Death message to reject the associated
 * time request, the API function will return the appropriate return code and,
 * also, provide the ASCII code (of fixed length, #SNTP_KISS_OF_DEATH_CODE_LENGTH bytes)
 * in the #SntpResponseData_t.pRejectedResponseCode member of @p pParsedResponse parameter,
 * parsed from the response packet.
 * The application SHOULD respect the server rejection and take appropriate action
 * based on the rejection code.
 * If the server response represents an accepted SNTP client request, then the API
 * function will set the #SntpResponseData_t.pRejectedResponseCode member of
 * @p pParsedResponse parameter to #SNTP_KISS_OF_DEATH_CODE_INVALID.
 *
 * @note If the server has positively responded with its clock time, then this API
 * function will calculate the clock-offset ONLY if the system clock is within
 * 34 years of the server time mentioned in the response packet; otherwise the
 * seconds part of the clock offset in @p pParsedResponse parameter will be set to
 * #SNTP_CLOCK_OFFSET_OVERFLOW.
 *
 * @param[in] pRequestTime The system time used in the SNTP request packet
 * that is associated with the server response. This MUST be the same as the
 * time returned by the @ref Sntp_SerializeRequest API.
 * @param[in] pResponseRxTime The time of the system, expressed as time since the
 * SNTP epoch (i.e. 0h of 1st Jan 1900 ), at receiving SNTP response from server.
 * This time will be used to calculate system clock offset relative to server.
 * @param[in] pResponseBuffer The buffer containing the SNTP response from the
 * server.
 * @param[in] bufferSize The size of the @p pResponseBuffer containing the SNTP
 * response. It MUST be at least #SNTP_REQUEST_RESPONSE_MINIMUM_PACKET_SIZE bytes
 * long for a valid SNTP response.
 * @param[out] pParsedResponse The information parsed from the SNTP response packet.
 * If possible to calculate, it also contains the system clock offset relative
 * to the server time.
 *
 * @return This function returns one of the following:
 * - #SntpSuccess if the de-serialization operation is successful.
 * - #SntpBadParameter if an invalid parameter is passed.
 * - #SntpErrorInsufficientSpace if the buffer does not have the minimum size
 * required for a valid SNTP response packet.
 * - #SntpInvalidResponse if the response fails sanity checks expected in an
 * SNTP response.
 * - #SntpRejectedResponseChangeServer if the server rejected with a code
 * indicating that client cannot be retry requests to it.
 * - #SntpRejectedResponseRetryWithBackoff if the server rejected with a code
 * indicating that client should back-off before retrying request.
 * - #SntpRejectedResponseCodeOther if the server rejected with a code that
 * application can inspect in the @p pParsedResponse parameter.
 */
/* @[define_sntp_deserializeresponse] */
SntpStatus_t Sntp_DeserializeResponse( const SntpTimestamp_t * pRequestTime,
                                       const SntpTimestamp_t * pResponseRxTime,
                                       const void * pBuffer,
                                       size_t bufferSize,
                                       SntpResponseData_t * pParsedResponse );
/* @[define_sntp_deserializeresponse] */

#endif /* ifndef CORE_SNTP_SERIALIZER_H_ */
