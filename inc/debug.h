/*------------------------------------------------------------------
 * Tracing & debugging utilities
 *
 * November 2014, Jan Omasta
 *
 * Copyright (c) 2014-2015 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------*/

#ifndef DEBUG_H_
#define DEBUG_H_

#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <time.h>
#include <unistd.h>
#include <logging.h>
#include <mem.h>

struct cfg_ctx;

/**
 * concatenation - two macros to force arguments expansion before join
 */
#define PARAM_JOIN(a, b) PARAM_JOIN2(a, b)

#define PARAM_JOIN2(a, b) a##b

/**
 * return number of arguments
 */
#define PARAM_NUM(...)                                                       \
    PARAM_NUM2(__VA_ARGS__, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, \
               2, 1, 0)

#define PARAM_NUM2(_0, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, \
                   _14, _15, _16, N, ...)                                      \
    N

#define LINE2STR_(a) #a
#define LINE2STR(a) LINE2STR_(a)

#ifdef TESTING
#define LOG_MSG(log_level, ...) \
    log_syslog(log_level, __func__, __FILE__, __LINE__, __VA_ARGS__);
#else
#define LOG_MSG(log_level, ...)                                      \
    do {                                                             \
        static const char *__debug_file_name = NULL;                 \
        if (!__debug_file_name) {                                    \
            __debug_file_name = strrchr(__FILE__, '/') + 1;          \
        }                                                            \
        log_syslog(log_level, __func__, __debug_file_name, __LINE__, \
                   __VA_ARGS__);                                     \
    } while (0)
#endif

/**
 * log alert message
 */
#define LOG_ALERT(...)                         \
    do {                                       \
        LOG_MSG(LOG_LEVEL_ALERT, __VA_ARGS__); \
    } while (0)

/**
 * log error message
 */
#define LOG_ERROR(...)                         \
    do {                                       \
        LOG_MSG(LOG_LEVEL_ERROR, __VA_ARGS__); \
    } while (0)

/**
 * log trace message
 */
#define LOG_TRACE(...)                         \
    do {                                       \
        LOG_MSG(LOG_LEVEL_TRACE, __VA_ARGS__); \
    } while (0)

/**
 * log debug message
 */
#define LOG_DEBUG(...)                         \
    do {                                       \
        LOG_MSG(LOG_LEVEL_DEBUG, __VA_ARGS__); \
    } while (0)

#define DEBUG_SIN_FMT "%d.%d.%d.%d:%" PRIu16
#define DEBUG_SIN_PRINT(sin)                         \
    (ntohl((sin).sin_addr.s_addr) >> 24 & 0xff),     \
        (ntohl((sin).sin_addr.s_addr) >> 16 & 0xff), \
        (ntohl((sin).sin_addr.s_addr) >> 8 & 0xff),  \
        (ntohl((sin).sin_addr.s_addr) & 0xff), ntohs((sin).sin_port)

#define DEBUG_V4_FMT "%d.%d.%d.%d"
#define DEBUG_V4_PRINT(ip)                              \
    (ntohl(ip) >> 24 & 0xff), (ntohl(ip) >> 16 & 0xff), \
        (ntohl(ip) >> 8 & 0xff), (ntohl(ip) & 0xff)

#define DEBUG_4B_FMT "%02" PRIx8 "%02" PRIx8 "%02" PRIx8 "%02" PRIx8
#define DEBUG_4B_PRINT(x)                                             \
    ((uint8_t *)&(x))[0], ((uint8_t *)&(x))[1], ((uint8_t *)&(x))[2], \
        ((uint8_t *)&(x))[3]

#define DECL_DEBUG_V6_STATIC_BUFFER \
    static char __debug_global_ipv6_print_buffer[INET6_ADDRSTRLEN + 1] = { 0 };
#define DEBUG_V6_FMT "%s"
#define DEBUG_V6_PRINT(ip)                                    \
    inet_ntop(AF_INET6, ip, __debug_global_ipv6_print_buffer, \
              sizeof(__debug_global_ipv6_print_buffer))

/** helper macro */
#define IS_PRINTABLE(x) ((x >= 0x20) && (x <= 0x7e))

/** helper macro */
#define LOG_TRACE_BYTES4(offset, data)                                     \
    LOG_MSG(LOG_LEVEL_TRACE, "%p + 0x%04zx: 0x%02x%02x%02x%02x[%c%c%c%c]", \
            data, offset, ((uint8_t *)data)[0], ((uint8_t *)data)[1],      \
            ((uint8_t *)data)[2], ((uint8_t *)data)[3],                    \
            IS_PRINTABLE(((char *)data)[0]) ? ((char *)data)[0] : '.',     \
            IS_PRINTABLE(((char *)data)[1]) ? ((char *)data)[1] : '.',     \
            IS_PRINTABLE(((char *)data)[2]) ? ((char *)data)[2] : '.',     \
            IS_PRINTABLE(((char *)data)[3]) ? ((char *)data)[3] : '.')

/** helper macro */
#define LOG_TRACE_BYTES3(offset, data)                                     \
    LOG_MSG(LOG_LEVEL_TRACE, "%p + 0x%04zx: 0x%02x%02x%02x[%c%c%c]", data, \
            offset, ((uint8_t *)data)[0], ((uint8_t *)data)[1],            \
            ((uint8_t *)data)[2],                                          \
            IS_PRINTABLE(((char *)data)[0]) ? ((char *)data)[0] : '.',     \
            IS_PRINTABLE(((char *)data)[1]) ? ((char *)data)[1] : '.',     \
            IS_PRINTABLE(((char *)data)[2]) ? ((char *)data)[2] : '.')

/** helper macro */
#define LOG_TRACE_BYTES2(offset, data)                                       \
    LOG_MSG(LOG_LEVEL_TRACE, "%p + 0x%04zx: 0x%02x%02x[%c%c]", data, offset, \
            ((uint8_t *)data)[0], ((uint8_t *)data)[1],                      \
            IS_PRINTABLE(((char *)data)[0]) ? ((char *)data)[0] : '.',       \
            IS_PRINTABLE(((char *)data)[1]) ? ((char *)data)[1] : '.')

/** helper macro */
#define LOG_TRACE_BYTES1(offset, data)                                 \
    LOG_MSG(LOG_LEVEL_TRACE, "%p + 0x%04zx: 0x%02x[%c]", data, offset, \
            ((uint8_t *)data)[0],                                      \
            IS_PRINTABLE(((char *)data)[0]) ? ((char *)data)[0] : '.')

/** macro used for hex-dumping data of known size */
#define LOG_TRACE_BYTES(__data, __data_len)                              \
    do {                                                                 \
        if (__data_len) {                                                \
            size_t __ltb__data_len = (unsigned)__data_len;               \
            size_t __ltb__rounds = 0;                                    \
            do {                                                         \
                size_t __ltb__offset = __ltb__rounds * 4;                \
                switch (__ltb__data_len > 4 ? 0 : __ltb__data_len % 4) { \
                case 0:                                                  \
                    LOG_TRACE_BYTES4(__ltb__offset,                      \
                                     (uint8_t *)__data + __ltb__offset); \
                    break;                                               \
                case 1:                                                  \
                    LOG_TRACE_BYTES1(__ltb__offset,                      \
                                     (uint8_t *)__data + __ltb__offset); \
                    break;                                               \
                case 2:                                                  \
                    LOG_TRACE_BYTES2(__ltb__offset,                      \
                                     (uint8_t *)__data + __ltb__offset); \
                    break;                                               \
                case 3:                                                  \
                    LOG_TRACE_BYTES3(__ltb__offset,                      \
                                     (uint8_t *)__data + __ltb__offset); \
                    break;                                               \
                }                                                        \
                __ltb__rounds++;                                         \
                if (__ltb__data_len > 4) {                               \
                    __ltb__data_len -= 4;                                \
                } else {                                                 \
                    break;                                               \
                }                                                        \
            } while (1);                                                 \
        }                                                                \
    } while (0)

#endif /* DEBUG_H_ */
