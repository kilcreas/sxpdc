#include <util.h>
#include <logging.h>
#include <syslog.h>
#include <stdarg.h>
#include <sys/queue.h>
#include <pthread.h>

#include "../inc/log_check.h"

#pragma GCC diagnostic ignored "-Wunused-but-set-variable"

#define LOG_RECORD_SIZE (1024 * 16)
#define FUNC_NAME_MAX 256

struct log_check_ctx {
    struct log_pattern *log_patterns;
    size_t patterns_num;
    bool logging_paused;   /*!< pause storing when analyzing */
    pthread_mutex_t mutex; /*!< concurrent logging lock */
};

#define LOG_CHECK_BUF_SIZE (1024 * 16)

static int log_check_loglevel_to_linux_level(enum log_level ll)
{
    switch (ll) {
    case LOG_LEVEL_ALERT:
        return LOG_ALERT;
    case LOG_LEVEL_ERROR:
        return LOG_ERR;
    case LOG_LEVEL_TRACE:
        return LOG_INFO;
    case LOG_LEVEL_DEBUG:
        return LOG_DEBUG;
    }
    return LOG_LEVEL_ALERT;
}

void log_check_syslog(enum log_level loglevel, const char *function_name,
                      const char *file_name, size_t file_line,
                      const char *format, ...)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, format);
    RC_CHECK(rc, out);
#define BUF_SIZE (1024 * 16)
    char buffer[BUF_SIZE];
    buffer[0] = '\0';
    int written = snprintf(buffer, BUF_SIZE, "%s:%zu %s():", file_name,
                           file_line, function_name);
    if ((written < 0) || (written >= BUF_SIZE)) {
        /* this cannot be written, throw away the info and try to at least log
         * the message itself */
        buffer[0] = '\0';
        written = 0;
    }
    va_list argptr;
    va_start(argptr, format);
    vsnprintf(buffer + written, (size_t)(BUF_SIZE - written), format, argptr);
    va_end(argptr);
    syslog(log_check_loglevel_to_linux_level(loglevel), "%s", buffer);
#ifdef ENABLE_LOG_PRINTING
    pid_t pid = getpid();
    time_t ltime = time(NULL);
    struct tm tm;
    localtime_r(&ltime, &tm);
    switch (loglevel) {
    case LOG_LEVEL_ALERT:
        fprintf(stderr, "[%lu]ALERT:%02d:%02d:%02d:%s\n", (long unsigned)pid,
                tm.tm_hour, tm.tm_min, tm.tm_sec, buffer);
        break;
    case LOG_LEVEL_ERROR:
        fprintf(stderr, "[%lu]ERROR:%02d:%02d:%02d:%s\n", (long unsigned)pid,
                tm.tm_hour, tm.tm_min, tm.tm_sec, buffer);
        break;
    case LOG_LEVEL_TRACE:
        fprintf(stderr, "[%lu]TRACE:%02d:%02d:%02d:%s\n", (long unsigned)pid,
                tm.tm_hour, tm.tm_min, tm.tm_sec, buffer);
        break;
    case LOG_LEVEL_DEBUG:
        fprintf(stderr, "[%lu]DEBUG:%02d:%02d:%02d:%s\n", (long unsigned)pid,
                tm.tm_hour, tm.tm_min, tm.tm_sec, buffer);
        break;
    }
#endif
out:
    ;
}

#define LOG_CHECK_MSG(log_level, ...) \
    log_check_syslog(log_level, __func__, __FILE__, __LINE__, __VA_ARGS__);

/**
 * log error message
 */
#define LOG_CHECK_ERROR(...)                         \
    do {                                             \
        LOG_CHECK_MSG(LOG_LEVEL_ERROR, __VA_ARGS__); \
    } while (0)

/**
 * log trace message
 */
#define LOG_CHECK_TRACE(...)                         \
    do {                                             \
        LOG_CHECK_MSG(LOG_LEVEL_TRACE, __VA_ARGS__); \
    } while (0)

static struct log_check_ctx log_check = {.log_patterns = NULL,
                                         .patterns_num = 0,
                                         .logging_paused = false,
                                         .mutex = PTHREAD_MUTEX_INITIALIZER };

void log_check_ctx_reinit(void)
{
    log_check.log_patterns = NULL;
    log_check.patterns_num = 0;
    log_check.logging_paused = false;
    pthread_mutex_init(&log_check.mutex, NULL);
}

static const char *log_pattern_type_str(enum log_pattern_type pt)
{
    switch (pt) {
    case LOG_EXPECTED:
        return "expected";
    case LOG_OPTIONAL:
        return "optional";
    case LOG_UNEXPECTED:
        return "unexpected";
    }

    return NULL;
}

/**
 * @brief test if log rule match log record
 *
 * @param log_pattern
 * @param log_item
 * @return return 0 when not match, 1 on match or -1 on error
 */
static int log_pattern_match_log_item(struct log_pattern *log_pattern,
                                      enum log_level log_level,
                                      const char *function_name,
                                      const char *file_name, const char *log)
{
    int rc = 0;
    const char *file_name_ = NULL;

    assert(log_pattern && function_name && file_name && log);

    if (log_pattern->log_level == log_level) {

        if (NULL == log_pattern->func_name ||
            strncmp(log_pattern->func_name, function_name, FUNC_NAME_MAX) ==
                0) {

            file_name_ = strrchr(file_name, '/');
            if (NULL == file_name_) {
                file_name_ = file_name;
            } else {
                file_name_ += 1;
            }

            if (NULL == log_pattern->file_name ||
                strcmp(log_pattern->file_name, file_name_) == 0) {

                if (NULL != log_pattern->regex_pattern) {

                    if (false == log_pattern->regex_compiled) {
                        LOG_CHECK_ERROR(
                            "regular expression <%s> is not compiled",
                            log_pattern->regex_pattern);
                        rc = -1;
                        goto out;
                    }

                    rc = regexec(&log_pattern->regex, log, 0, NULL, 0);
                    if (RC_ISOK(rc)) {
                        rc = 1;
                    } else if (REG_NOMATCH != rc) {
                        LOG_CHECK_ERROR(
                            "regular expression <%s> execute failed",
                            log_pattern->regex_pattern);
                        rc = -1;
                        goto out;
                    } else {
                        rc = 0;
                    }
                } else {
                    rc = 1;
                }
            }
        }
    }

out:
    return rc;
}

void log_check_analyze_log(const char *original_log, enum log_level log_level,
                           const char *function_name, const char *file_name,
                           const char *format, ...)
{
    int rc = 0;
    struct log_pattern *log_pattern = NULL;
    static char log[LOG_RECORD_SIZE];
    size_t i = 0;

    assert(function_name && file_name && format);

    int tmp_rc = pthread_mutex_lock(&log_check.mutex);
    assert(RC_ISOK(tmp_rc));

    if (true == log_check.logging_paused) {
        goto out;
    }

    va_list argptr;
    va_start(argptr, format);
    vsnprintf(log, LOG_RECORD_SIZE, format, argptr);
    va_end(argptr);

    if (NULL != log_check.log_patterns) {
        for (i = 0; i < log_check.patterns_num; ++i) {
            log_pattern = &log_check.log_patterns[i];

            rc = log_pattern_match_log_item(log_pattern, log_level,
                                            function_name, file_name, log);
            if (1 == rc) {
                log_pattern->hit_num++;
                LOG_CHECK_TRACE(
                    "Found <%s> log record <%s> matching pattern loglevel "
                    "<%s> file <%s> function <%s> regexp <%s>",
                    log_pattern_type_str(log_pattern->rule_type), log,
                    log_level_to_string(log_pattern->log_level),
                    log_pattern->file_name ? log_pattern->file_name : "*",
                    log_pattern->func_name ? log_pattern->func_name : "*",
                    log_pattern->regex_pattern ? log_pattern->regex_pattern
                                               : "*");
                snprintf(log_pattern->last_match, LOG_CHECK_MAST_MATCH_SIZE,
                         "%s", original_log);
                break;
            } else {
                assert(RC_ISOK(rc));
            }
        }
    }

out:
    tmp_rc = pthread_mutex_unlock(&log_check.mutex);
    assert(RC_ISOK(tmp_rc));

    return;
}

static void log_check_destroy_patterns_priv()
{
    size_t i = 0;
    struct log_pattern *log_pattern = NULL;

    if (NULL != log_check.log_patterns) {
        for (i = 0; i < log_check.patterns_num; ++i) {
            log_pattern = &log_check.log_patterns[i];
            if (true == log_pattern->regex_compiled) {
                regfree(&log_pattern->regex);
                log_pattern->regex_compiled = false;
            }
        }
    }
}

void log_check_destroy_patterns()
{
    int tmp_rc = 0;

    tmp_rc = pthread_mutex_lock(&log_check.mutex);
    assert(RC_ISOK(tmp_rc));

    log_check_destroy_patterns_priv();

    tmp_rc = pthread_mutex_unlock(&log_check.mutex);
    assert(RC_ISOK(tmp_rc));
}

int log_check_set_patterns(struct log_pattern *log_patterns,
                           size_t patterns_num)
{
    int rc = 0;
    int tmp_rc = 0;
    struct log_pattern *log_pattern = NULL;
    size_t i = 0;

    tmp_rc = pthread_mutex_lock(&log_check.mutex);
    assert(RC_ISOK(tmp_rc));

    PARAM_NULL_CHECK(rc, log_patterns);
    RC_CHECK(rc, out);

    /* destroy previous patterns */
    log_check_destroy_patterns_priv();

    /* set new patterns */
    log_check.log_patterns = log_patterns;
    log_check.patterns_num = patterns_num;

    /* compile patterns regexp's */
    if (NULL != log_check.log_patterns) {
        LOG_CHECK_TRACE("compiling %zu regular expressions",
                        log_check.patterns_num);
        for (i = 0; i < log_check.patterns_num; ++i) {
            log_pattern = &log_check.log_patterns[i];
            if ((NULL != log_pattern->regex_pattern) &&
                (false == log_pattern->regex_compiled)) {
                rc = regcomp(&log_pattern->regex, log_pattern->regex_pattern,
                             REG_EXTENDED | REG_NOSUB);
                if (RC_ISNOTOK(rc)) {
                    LOG_CHECK_ERROR(
                        "regular expression <%s> compilation failed",
                        log_pattern->regex_pattern);
                    log_check_destroy_patterns_priv();
                    rc = -1;
                    goto out;
                }
                log_pattern->regex_compiled = true;
                log_pattern->hit_num = 0;
            }
        }
    }

out:

    tmp_rc = pthread_mutex_unlock(&log_check.mutex);
    assert(RC_ISOK(tmp_rc));

    return rc;
}

int log_check_run()
{
    int rc = 0;
    int tmp_rc = 0;
    size_t i = 0;
    struct log_pattern *log_pattern = NULL;

    /* temporary turn log check logging off */
    tmp_rc = pthread_mutex_lock(&log_check.mutex);
    assert(RC_ISOK(tmp_rc));
    log_check.logging_paused = true;
    tmp_rc = pthread_mutex_unlock(&log_check.mutex);
    assert(RC_ISOK(tmp_rc));

    for (i = 0; i < log_check.patterns_num; ++i) {
        log_pattern = &log_check.log_patterns[i];
        if (LOG_EXPECTED == log_pattern->rule_type) {
            if (0 == log_pattern->hit_num) {
                LOG_ERROR("Expected log record which match pattern loglevel "
                          "<%s> file <%s> function <%s> pattern <%s> not found",
                          log_level_to_string(log_pattern->log_level),
                          log_pattern->file_name ? log_pattern->file_name : "*",
                          log_pattern->func_name ? log_pattern->func_name : "*",
                          log_pattern->regex_pattern
                              ? log_pattern->regex_pattern
                              : "*");
                rc = -1;
                goto out;
            }
        } else if (LOG_UNEXPECTED == log_pattern->rule_type) {
            if (0 != log_pattern->hit_num) {
                LOG_ERROR("Unexpected log record which match pattern loglevel "
                          "<%s> file <%s> function <%s> pattern <%s> found",
                          log_level_to_string(log_pattern->log_level),
                          log_pattern->file_name ? log_pattern->file_name : "*",
                          log_pattern->func_name ? log_pattern->func_name : "*",
                          log_pattern->regex_pattern
                              ? log_pattern->regex_pattern
                              : "*");
                LOG_ERROR("Last matching log record is: %s",
                          log_pattern->last_match);
                rc = -1;
                goto out;
            }
        } else if (LOG_OPTIONAL != log_pattern->rule_type) {
            assert(0);
        }
    }

out:
    /* turn log check logging on */
    tmp_rc = pthread_mutex_lock(&log_check.mutex);
    assert(RC_ISOK(tmp_rc));
    log_check.logging_paused = false;
    tmp_rc = pthread_mutex_unlock(&log_check.mutex);
    assert(RC_ISOK(tmp_rc));

    return rc;
}
