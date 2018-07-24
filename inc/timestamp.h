/*------------------------------------------------------------------
 * Timestamp generation API
 *
 * January 2015, Klement Sekera
 *
 * Copyright (c) 2014-2015 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------*/

#ifndef TIMESTAMP_H
#define TIMESTAMP_H

/**
 * @defgroup tstamp Timestamp generator
 * @htmlinclude timestamp_generator.html
 * @addtogroup tstamp
 * @{
 */

/**
 * @brief opaque implementation-specific timestamp structure
 */
struct timestamp;

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
int timestamp_cmp(struct timestamp *t1, struct timestamp *t2, int *result);

/**
 * @brief return current timestamp
 *
 * @return non-NULL timestamp on success, NULL on failure
 */
struct timestamp *get_timestamp(void);

/**
 * @brief destroy timestamp and free memory
 *
 * @param t timestamp to destroy
 */
void destroy_timestamp(struct timestamp *t);

/**
 * @brief return time in seconds approximate to timestamp
 *
 * @param t timestamp
 *
 * @return seconds approximate to timestamp
 */
#if 0
double timestamp_seconds(struct timestamp *t);
#endif

/** @} */

#endif /* TIMESTAMP_H */
