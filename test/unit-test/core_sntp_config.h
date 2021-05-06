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
 * @file core_sntp_config.h
 * @brief This header sets configuration macros for the SNTP library.
 */
#ifndef CORE_SNTP_CONFIG_H_
#define CORE_SNTP_CONFIG_H_

/* Standard include. */
#include <stdio.h>

/************* Define Logging Macros using printf function ***********/

#define PrintfError( str, ... )    printf( "Error:"str,  ## __VA_ARGS__ )
#define PrintfWarn( str, ... )     printf( "Warn:"str,  ## __VA_ARGS__ )
#define PrintfInfo( str, ... )     printf( "Info:"str,  ## __VA_ARGS__ )
#define PrintfDebug( str, ... )    printf( "Debug:"str,  ## __VA_ARGS__ )

/*#define LOGGING_LEVEL_ERROR */

#ifdef LOGGING_LEVEL_ERROR
    #define LogError( message )    PrintfError message
#elif defined( LOGGING_LEVEL_WARNING )
    #define LogError( message )    PrintfError message
    #define LogError( message )    PrintfWarn message
#elif defined( LOGGING_LEVEL_INFO )
    #define LogError( message )    PrintfError message
    #define LogError( message )    PrintfWarn message
    #define LogError( message )    PrintfInfo message
#elif defined( LOGGING_INFO_DEBUG )
    #define LogError( message )    PrintfError message
    #define LogError( message )    PrintfWarn message
    #define LogError( message )    PrintfInfo message
    #define LogError( message )    PrintfDebug message
#endif /* ifdef LOGGING_LEVEL_ERROR */

/**************************************************/

#endif /* ifndef CORE_SNTP_CONFIG_H_ */
