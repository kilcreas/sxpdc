/*------------------------------------------------------------------
 * Logging API
 *
 * April 2015, Klement Sekera
 *
 * Copyright (c) 2014-2015 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------*/
#ifndef LOGGING_H
#define LOGGING_H

#include <stddef.h>

/**
 * @defgroup logging Logging
 * @htmlinclude logging.html
 * @addtogroup logging
 * @{
 */

/**
 * @brief log levels
 */
enum log_level {
    LOG_LEVEL_ALERT = 1, /*!< immediate user action is required */
    LOG_LEVEL_ERROR,     /*!< error occured */
    LOG_LEVEL_TRACE,     /*!< informational */
    LOG_LEVEL_DEBUG,     /*!< debugging */
};

/**
 * @brief set the log level to log only messages with level higher or equal to
 *the level set
 *
 * @param loglevel level to set
 */
void log_setloglevel(enum log_level loglevel);

/**
 * @brief get log level string by log level enum
 *
 * @param l log level
 * @return log level string
 */
const char *log_level_to_string(enum log_level l);

/**
 * @brief get log level enum by log level string
 *
 * @param loglevel log level
 * @param parse_from string to be parsed
 * @return returns 0 on success, -1 on error
 */
int parse_log_level(enum log_level *loglevel, const char *parse_from);

/**
 * @brief write message to system log
 *
 * @param loglevel importance of the message
 * @param function_name function where the log message originates from
 * @param file_name file where the function is located
 * @param file_line line in the file on which the message is generated
 * @param format printf-like format string
 * @param ... printf-like arguments to formatted
 */
void log_syslog(enum log_level loglevel, const char *function_name,
                const char *file_name, size_t file_line, const char *format,
                ...) __attribute__((format(printf, 5, 6)));

/** @} */

#endif
