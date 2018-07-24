/*------------------------------------------------------------------
 * Memory abstraction API
 *
 * November 2014, Klement Sekera
 *
 * Copyright (c) 2014-2015 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------*/

#ifndef MEM_H
#define MEM_H

#include <string.h>

/**
 * @defgroup mem Memory management
 * @htmlinclude memory_management.html
 * @addtogroup mem
 * @{
 */

/**
 * @brief allocate memory the same way as POSIX malloc does
 *
 * @param size number of bytes to allocate
 * @return pointer to allocated block of memory of given size or NULL in case of
 *error
 */
void *mem_malloc(size_t size);

/**
 * @brief free memory the same way as POSIX free does
 *
 * @param ptr pointer to free
 */
void mem_free(void *ptr);

/**
 * @brief allocate memory the same way as POSIX calloc does
 *
 * @param nmemb number of elements to allocate
 * @param size size of each element to allocate
 *
 * @return pointer to allocated array of nmemb elements of size bytes each or
 *NULL if allocation failed
 */
void *mem_calloc(size_t nmemb, size_t size);

/**
 * @brief reallocate memory the same way as POSIX realloc does
 *
 * @param ptr pointer to reallocate
 * @param size size of the new block of memory
 *
 * @return pointer to new block if reallocated or NULL if reallocation not
 *possible
 */
void *mem_realloc(void *ptr, size_t size);

/** @} */

#endif
