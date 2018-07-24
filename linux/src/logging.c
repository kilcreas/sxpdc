#include <util.h>
#include <logging.h>
#include <syslog.h>
#include <stdarg.h>

#ifdef TESTING
#include <pthread.h>
#include "../test/framework/inc/log_check.h"
#endif

#include "logging_helper.h"

static int log_loglevel_to_linux_level(enum log_level ll)
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

/**
 * @brief set the log level to log only messages with level higher or equal to
 *the level set
 *
 * @param loglevel level to set
 */
void log_setloglevel(enum log_level loglevel)
{
    int mask = 0;
    switch (loglevel) {
    case LOG_LEVEL_TRACE:
        mask |= LOG_MASK(LOG_INFO);
    /*fallthrough*/
    case LOG_LEVEL_DEBUG:
        mask |= LOG_MASK(LOG_DEBUG);
    /*fallthrough*/
    case LOG_LEVEL_ERROR:
        mask |= LOG_MASK(LOG_ERR);
    /*fallthrough*/
    case LOG_LEVEL_ALERT:
        mask |= LOG_MASK(LOG_ALERT);
    }
    setlogmask(mask);
}

const char *log_level_to_string(enum log_level l)
{
    switch (l) {
    case LOG_LEVEL_ALERT:
        return "ALERT";
    case LOG_LEVEL_ERROR:
        return "ERROR";
    case LOG_LEVEL_TRACE:
        return "TRACE";
    case LOG_LEVEL_DEBUG:
        return "DEBUG";
    }
    return "UNKNOWN";
}

int parse_log_level(enum log_level *loglevel, const char *parse_from)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, loglevel, parse_from);
    RC_CHECK(rc, out);
    if (!strcasecmp(parse_from, "alert")) {
        *loglevel = LOG_LEVEL_ALERT;
    } else if (!strcasecmp(parse_from, "error")) {
        *loglevel = LOG_LEVEL_ERROR;
    } else if (!strcasecmp(parse_from, "debug")) {
        *loglevel = LOG_LEVEL_DEBUG;
    } else if (!strcasecmp(parse_from, "trace")) {
        *loglevel = LOG_LEVEL_TRACE;
    } else {
        LOG_ERROR("Unrecognized log level option: %s", parse_from);
        rc = -1;
        goto out;
    }
out:
    return rc;
}

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
                ...)
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
    syslog(log_loglevel_to_linux_level(loglevel), "%s", buffer);

#ifdef TESTING
    log_check_analyze_log(buffer, loglevel, function_name, file_name, "%s",
                          buffer + written);
#endif

#ifdef ENABLE_LOG_PRINTING
#ifdef TESTING
    pthread_t tid = pthread_self();
    pid_t pid = getpid();
    time_t ltime = time(NULL);
    struct tm tm;
    localtime_r(&ltime, &tm);
    switch (loglevel) {
    case LOG_LEVEL_ALERT:
        fprintf(stderr, "[%lu:%lu]ALERT:%02d:%02d:%02d:%s\n",
                (long unsigned)pid, (long unsigned)tid, tm.tm_hour, tm.tm_min,
                tm.tm_sec, buffer);
        break;
    case LOG_LEVEL_ERROR:
        fprintf(stderr, "[%lu:%lu]ERROR:%02d:%02d:%02d:%s\n",
                (long unsigned)pid, (long unsigned)tid, tm.tm_hour, tm.tm_min,
                tm.tm_sec, buffer);
        break;
    case LOG_LEVEL_TRACE:
        fprintf(stderr, "[%lu:%lu]TRACE:%02d:%02d:%02d:%s\n",
                (long unsigned)pid, (long unsigned)tid, tm.tm_hour, tm.tm_min,
                tm.tm_sec, buffer);
        break;
    case LOG_LEVEL_DEBUG:
        fprintf(stderr, "[%lu:%lu]DEBUG:%02d:%02d:%02d:%s\n",
                (long unsigned)pid, (long unsigned)tid, tm.tm_hour, tm.tm_min,
                tm.tm_sec, buffer);
        break;
    }
#else
    static int have_pid = 0;
    static pid_t pid = 0;
    if (!have_pid) {
        have_pid = 1;
        pid = getpid();
    }
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
#endif
out:
    ;
}

void logging_open(void)
{
    openlog("sxpd", LOG_CONS | LOG_NDELAY | LOG_PID, LOG_DAEMON);
}

void logging_close(void)
{
    closelog();
}
