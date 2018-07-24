/*------------------------------------------------------------------
 * Memory abstraction implementation - linux code
 *
 * November 2014, Klement Sekera
 *
 * Copyright (c) 2014-2015 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------*/

#include <mem.h>
#include <stdlib.h>

void *mem_malloc(size_t size)
{
    return malloc(size);
}

void mem_free(void *ptr)
{
    free(ptr);
}

void *mem_calloc(size_t nmemb, size_t size)
{
    return calloc(nmemb, size);
}

void *mem_realloc(void *ptr, size_t size)
{
    return realloc(ptr, size);
}
