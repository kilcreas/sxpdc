/*------------------------------------------------------------------
 * Timestamp generation / linux code
 *
 * January 2015, Klement Sekera
 *
 * Copyright (c) 2014-2015 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------*/

#include <time.h>

#include "util.h"
#include "debug.h"
#include "timestamp.h"

struct timestamp {
    struct timespec t;
};

/**
 * @brief compare timestamps
 *
 * @param t1 timestamp
 * @param t2 timestamp
 * @param result integer less than, equal to, or greater than zero if t1 is
 *found, respectively, to be less than, to match or be greater than t2
 *
 * @return 0 on success, -1 on failure
 */
int timestamp_cmp(struct timestamp *t1, struct timestamp *t2, int *result)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, t1, t2, result);
    if (RC_ISOK(rc)) {
        if (t1->t.tv_sec < t2->t.tv_sec) {
            *result = -1;
        } else if (t1->t.tv_sec > t2->t.tv_sec) {
            *result = 1;
        } else {
            if (t1->t.tv_nsec < t2->t.tv_nsec) {
                *result = -1;
            } else if (t1->t.tv_nsec > t2->t.tv_nsec) {
                *result = 1;
            } else {
                *result = 0;
            }
        }
    }
    return rc;
}

/**
 * @brief return current timestamp
 *
 * @return non-NULL timestamp on success, NULL on failure
 */
struct timestamp *get_timestamp(void)
{
    struct timestamp *t = mem_calloc(1, sizeof(*t));
    if (t && clock_gettime(CLOCK_MONOTONIC, &t->t)) {
        LOG_ERROR("Cannot get time from CLOCK_MONOTONIC, errno=%d:%s", errno,
                  strerror(errno));
        mem_free(t);
        t = NULL;
    }
    return t;
}

/**
 * @brief destroy timestamp and free memory
 *
 * @param t timestamp to destroy
 */
void destroy_timestamp(struct timestamp *t)
{
    mem_free(t);
}

/**
 * @brief return time in seconds approximate to timestamp
 *
 * @param t timestamp
 *
 * @return seconds approximate to timestamp
 */
#if 0
double timestamp_seconds(struct timestamp *t)
{
    return t->t.tv_sec + t->t.tv_nsec / 1E9;
}
#endif
