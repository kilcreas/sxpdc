/*------------------------------------------------------------------
 * helper utilities
 *
 * November 2014, Jan Omasta
 *
 * Copyright (c) 2014-2015 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------*/

#ifndef UTIL_H_
#define UTIL_H_

#include <errno.h>
#include <assert.h>

#include "debug.h"

#define PARAM_NULL_CHECK0(rc, arg_num, param)                            \
    if (RC_ISOK(rc) && NULL == param) {                                  \
        LOG_MSG(LOG_LEVEL_ERROR,                                         \
                "Argument #" #arg_num " " #param " == NULL is invalid"); \
        rc = EINVAL;                                                     \
    }

#define PARAM_NULL_CHECK_0(...)

#define PARAM_NULL_CHECK_1(rc, param1) PARAM_NULL_CHECK0(rc, 1, param1)

#define PARAM_NULL_CHECK_2(rc, param1, param2) \
    PARAM_NULL_CHECK0(rc, 1, param1) PARAM_NULL_CHECK0(rc, 2, param2)

#define PARAM_NULL_CHECK_3(rc, param1, param2, param3) \
    PARAM_NULL_CHECK_2(rc, param1, param2) PARAM_NULL_CHECK0(rc, 3, param3)

#define PARAM_NULL_CHECK_4(rc, param1, param2, param3, param4) \
    PARAM_NULL_CHECK_3(rc, param1, param2, param3)             \
    PARAM_NULL_CHECK0(rc, 4, param4)

#define PARAM_NULL_CHECK_5(rc, param1, param2, param3, param4, param5) \
    PARAM_NULL_CHECK_4(rc, param1, param2, param3, param4)             \
    PARAM_NULL_CHECK0(rc, 5, param5)

#define PARAM_NULL_CHECK_6(rc, param1, param2, param3, param4, param5, param6) \
    PARAM_NULL_CHECK_5(rc, param1, param2, param3, param4, param5)             \
    PARAM_NULL_CHECK0(rc, 6, param6)

#define PARAM_NULL_CHECK_7(rc, param1, param2, param3, param4, param5, param6, \
                           param7)                                             \
    PARAM_NULL_CHECK_6(rc, param1, param2, param3, param4, param5, param6)     \
    PARAM_NULL_CHECK0(rc, 7, param7)

#define PARAM_NULL_CHECK_8(rc, param1, param2, param3, param4, param5, param6, \
                           param7, param8)                                     \
    PARAM_NULL_CHECK_7(rc, param1, param2, param3, param4, param5, param6,     \
                       param7) PARAM_NULL_CHECK0(rc, 8, param8)

#define PARAM_NULL_CHECK_9(rc, param1, param2, param3, param4, param5, param6, \
                           param7, param8, param9)                             \
    PARAM_NULL_CHECK_8(rc, param1, param2, param3, param4, param5, param6,     \
                       param7, param8) PARAM_NULL_CHECK0(rc, 9, param9)

#define PARAM_NULL_CHECK_10(rc, param1, param2, param3, param4, param5,    \
                            param6, param7, param8, param9, param10)       \
    PARAM_NULL_CHECK_9(rc, param1, param2, param3, param4, param5, param6, \
                       param7, param8, param9)                             \
    PARAM_NULL_CHECK0(rc, 10, param10)

#define PARAM_NULL_CHECK_11(rc, param1, param2, param3, param4, param5,       \
                            param6, param7, param8, param9, param10, param11) \
    PARAM_NULL_CHECK_10(rc, param1, param2, param3, param4, param5, param6,   \
                        param7, param8, param9, param10)                      \
    PARAM_NULL_CHECK0(rc, 11, param11)

#define PARAM_NULL_CHECK_12(rc, param1, param2, param3, param4, param5,       \
                            param6, param7, param8, param9, param10, param11, \
                            param12)                                          \
    PARAM_NULL_CHECK_11(rc, param1, param2, param3, param4, param5, param6,   \
                        param7, param8, param9, param10, param11)             \
    PARAM_NULL_CHECK0(rc, 12, param12)

/**
 * parameters NULL check
 */
#define PARAM_NULL_CHECK(rc, ...)                                 \
    do {                                                          \
        PARAM_JOIN(PARAM_NULL_CHECK_,                             \
                   PARAM_NUM(0, ##__VA_ARGS__)(rc, __VA_ARGS__)); \
    } while (0)

#define RC_ISOK(rc) ((0) == (rc))

#define RC_ISNOTOK(rc) (!RC_ISOK(rc))

#define RC_CHECK(rc, label) \
    if (RC_ISNOTOK(rc)) {   \
        goto label;         \
    }
struct v4_v6_prefix {
    uint8_t len;
    union {
        uint8_t data[32];
        uint32_t v4;
        uint32_t v6[4];
    } ip;
};

#endif /* UTIL_H_ */
