/*------------------------------------------------------------------
 * logging helper header
 *
 * March 2015, Klement Sekera
 *
 * Copyright (c) 2014-2015 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------*/

#ifndef LOGGING_HELPER
#define LOGGING_HELPER

/* this header is to avoid name clash - since sxpd project uses LOG_DEBUG as
 * macro and syslog.h declares LOG_DEBUG as int constant (log-level) */

void logging_open(void);

void logging_close(void);

#endif
