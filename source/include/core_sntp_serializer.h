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
 * an (S)NTP server, it can add authentication data after the SNTP packet is
 * serialized with the @ref Sntp_SerializeRequest API function.
 */
#define SNTP_PACKET_MINIMUM_SIZE               ( 48U )

/**
 * @brief Number  timestamp fraction's value for 1 microsecond.
 *
 * The fraction's part of an SNTP timestamp is 32-bits wide, thereby, giving a
 * resolution of 2^(-32) seconds ~ 232 picoseconds.
 *
 * @note The application can use this value to convert fractions part of system
 * time into SNTP timestamp format. For example, if the microseconds
 * part of system time is n microseconds, the fractions value to be used for the
 * SNTP timestamp fraction part will be n * SNTP_FRACTIONS_PER_MICROSECOND.
 */
#define SNTP_FRACTION_VALUE_PER_MICROSECOND    ( 4295U )

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
     * @brief Server sent a Kiss-o'-Death message with non-retryable code (i.e. DENY or RESTR).
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
    SntpRejectedResponseRetryOther,

    /**
     * @brief Application provided insufficient buffer space for serializing
     * or de-serializing an SNTP packet.
     * The minimum size of an SNTP packet is #SNTP_PACKET_MINIMUM_SIZE
     * bytes. */
    SntpErrorBufferTooSmall,

    /**
     * @brief Server response failed validation checks for expected data in SNTP packet.
     */
    SntpInvalidResponse
} SntpStatus_t;


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
 * @brief Serializes an SNTP request packet to use for querying a
 * time server.
 *
 * This function will fill only #SNTP_PACKET_MINIMUM_SIZE
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
 * @param[in] bufferSize The size of the @p pBuffer buffer. It should be at least
 * #SNTP_PACKET_MINIMUM_SIZE bytes in size.
 *
 * @note It is recommended to use a True Random Generator (TRNG) to generate
 * the random number.
 * @note The application MUST save the @p pRequestTime value for de-serializing
 * the server response with @ref Sntp_DeserializeResponse API.
 *
 * @return This functions returns one of the following:
 * - #SntpSuccess when serialization operation is successful.
 * - #SntpBadParameter if an invalid parameter is passed.
 * - #SntpErrorBufferTooSmall if the buffer does not have the minimum size
 * for serializing an SNTP request packet.
 */
/* @[define_sntp_serializerequest] */
SntpStatus_t Sntp_SerializeRequest( SntpTimestamp_t * pRequestTime,
                                    uint32_t randomNumber,
                                    void * pBuffer,
                                    size_t bufferSize );
/* @[define_sntp_serializerequest] */

#endif /* ifndef CORE_SNTP_SERIALIZER_H_ */
