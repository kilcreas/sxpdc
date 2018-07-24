/*------------------------------------------------------------------
+ * logging check API
 *
 * May 2015, Jan Omasta
 *
 * Copyright (c) 2014-2015 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------*/

#ifndef LOG_CHECK_H_
#define LOG_CHECK_H_

#include <stdint.h>
#include <sys/queue.h>
#include <evmgr.h>
#include <regex.h>

#define LOG_CHECK_MAST_MATCH_SIZE 2048

/**
 * @brief type of log check rule
 */
enum log_pattern_type {
    LOG_EXPECTED,   //!< LOG_EXPECTED
    LOG_OPTIONAL,   //!< LOG_OPTIONAL
    LOG_UNEXPECTED, //!< LOG_UNEXPECTED
};

/**
 * @brief log rule list item
 */
struct log_pattern {
    const char *desc; /*!< description */
    enum log_pattern_type rule_type;
    enum log_level log_level;
    const char *func_name;
    const char *file_name;
    size_t hit_num; /*!< number of log records hit this rule */
    const char *regex_pattern;
    bool regex_compiled;
    regex_t regex;
    char last_match[LOG_CHECK_MAST_MATCH_SIZE];
};

/**
 * @brief log pattern initialization
 */
#define LOG_PATTERN_STATIC_INIT(desc_, rule_type_, log_level_, file_name_, \
                                func_name_, regex_pattern_)                \
    {                                                                      \
        .desc = desc_, .rule_type = rule_type_, .log_level = log_level_,   \
        .func_name = func_name_, .file_name = file_name_, .hit_num = 0,    \
        .regex_pattern = regex_pattern_, .regex_compiled = false,          \
        .regex = { 0 }, .last_match = { '\0' }                             \
    }

/**
 * @brief reinitializes log check context. Must be used when forking process
 * to prevent from mutex deadlock.
 */
void log_check_ctx_reinit(void);

/**
 * @brief set log patterns
 *
 * @param log_patterns array of log patterns
 * @param patterns_num size of log patterns array
 *
 * @return 0 on success, other on error
 */
int log_check_set_patterns(struct log_pattern *log_patterns,
                           size_t patterns_num);

/**
 * @brief analyze log record
 *
 * @param log_level
 * @param function_name
 * @param file_name
 * @param format
 */
void log_check_analyze_log(const char *original_log, enum log_level log_level,
                           const char *function_name, const char *file_name,
                           const char *format, ...);

/**
 * @brief check result of log record analysis
 *
 * @return 0 on success, other on error
 */
int log_check_run();

void log_check_destroy_patterns();

#endif /* LOG_CHECK_H_ */
