/*------------------------------------------------------------------
 * Random number generator implementation - linux code
 *
 * March 2015, Klement Sekera
 *
 * Copyright (c) 2014-2015 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------*/

#include <time.h>
#include <bsd/stdlib.h>
#include <rnd.h>

const uint32_t random_max = UINT32_MAX;

/**
 * @brief initialize the random generator
 */
void random_init(void)
{
}

/**
 * @brief get a random number in the range [0 .. random_max]
 *
 * @return random number
 */
uint32_t random_get(void)
{
    return arc4random();
}
