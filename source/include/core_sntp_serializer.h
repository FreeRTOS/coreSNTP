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
 * [RFC4330](https://tools.ietf.org/html/rfc4330).
 */

#ifndef CORE_SNTP_SERIALIZER_H_
#define CORE_SNTP_SERIALIZER_H_

/* Standard include. */
#include <stdint.h>

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

    /* Invalid parameter passed to any API function. */
    SntpErrorBadParameter,

    /* Server sent a Kiss-o'-Death message with non-retryable code of DENY or */
    /* RESTR. */
    SntpRejectedResponseChangeServer,

    /* Server sent KoD message with the RATE code which allows retrying with */
    /* back-off. */
    SntpRejectedResponseRetryWithBackoff,

    /* Server sent Kiss-o'-Death message with a different kiss code. */
    /* Application can access ASCII code in SntpResponse_t parameter */
    /* of Sntp_DeserializeResponse API. */
    SntpRejectedResponseRetryOther,

    /* Application provided insufficient buffer for serializing/de-serializing */
    SntpErrorInsufficientSpace,

    /* Internal error like error in security interface functions */
    /* for generating/validating authentication codes. */
    SntpErrorInternal,

    /* Server response failed validation checks (for replay attack protection) */
    /* or is malformed. */
    SntpInvalidResponse
} SntpStatus_t;

/**
 * @ingroup core_sntp_struct_types
 * @brief Structure representing an SNTP timestamp.
 * @note The (S)NTP timestamps use 1st January 1900 0h 0m 0s Coordinated Universal Time (UTC)
 * as the epoch time i.e. an NTP timestamp represents the amount of time since
 * the epoch time.
 */
typedef struct SntpTime
{
    uint32_t seconds;      /**< @brief Number of seconds since epoch time. */
    uint32_t microseconds; /** <@brief The fractions part of the NTP
                            * time in microseconds. */
} SntpTime_t;

/**
 * @brief The base packet size of request and response of the (S)NTP protocol.
 * @note This is the packet size without any authentication headers for security
 * mechanism. If the application uses a security mechanism for communicating with
 * an (S)NTP server, it can perform add authentication data after the SNTP packet
 * is serialized with the @ref Sntp_SerializeRequest API function.
 */
#define SNTP_REQUEST_RESPONSE_MINIMUM_PACKET_SIZE    ( 48U )

/**
 * @brief Serializes an SNTP request packet to use for querying a
 * time server.
 *
 * This function will fill only #SNTP_REQUEST_RESPONSE_MINIMUM_PACKET_SIZE
 * bytes of data in the passed buffer.
 *
 * @param[in] pCurrentTime The current time of the system, expressed as time
 * since the NTP epoch (i.e. 0h of 1st Jan 1900 ). This time will be serialized
 * in the SNTP request packet.
 * @param[out] pBuffer The buffer that will be populated with the serialized
 * SNTP request packet.
 * @param[in] bufferSize The size of the @p pBuffer buffer. It should be at least
 * #SNTP_REQUEST_RESPONSE_MINIMUM_PACKET_SIZE bytes in size.
 *
 * @return This functions returns one of the following:
 * - #SntpSuccess when serialization operation is successful.
 * - #SntpBadParameter if an invalid parameter is passed.
 * - #SntpErrorInsufficientSpace if the buffer does not have the minimum size
 * for serializing an SNTP request packet.
 */
/* @[define_sntp_serializerequest] */
SntpStatus_t Sntp_SerializeRequest( SntpTime_t * pCurrentTime,
                                    void * pBuffer,
                                    size_t bufferSize );
/* @[define_sntp_serializerequest] */

#endif /* ifndef CORE_SNTP_SERIALIZER_H_ */
