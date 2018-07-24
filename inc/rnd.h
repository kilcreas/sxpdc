/*------------------------------------------------------------------
 * Random number generator API
 *
 * March 2015, Klement Sekera
 *
 * Copyright (c) 2014-2015 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------*/

#ifndef RND_H
#define RND_H

#include <stdint.h>

/**
 * @defgroup rnd Random number generator
 * @htmlinclude random_number_generator.html
 * @addtogroup rnd
 * @{
 */

/**
 * @brief implementation-specific maximum random number returned
 */
extern const uint32_t random_max;

/**
 * @brief initialize the random generator
 */
void random_init(void);

/**
 * @brief get a random number in the range [0 .. random_max]
 *
 * @return random number
 */
uint32_t random_get(void);

/** @} */

#endif
