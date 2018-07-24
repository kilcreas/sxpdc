/*------------------------------------------------------------------
 * SXP daemon implementation - linux code
 *
 * March 2015, Klement Sekera
 *
 * Copyright (c) 2014-2015 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------*/

#include <inttypes.h>
#include <signal.h>
#include <sxpd.h>
#include <debug.h>
#include <util.h>
#include <rnd.h>
#include <strings.h>
#include <fcntl.h>
#include <logging.h>
#include <limits.h>
#include "logging_helper.h"

#ifdef ENABLE_GDBUS_INTERFACE
#include "gdbus_interface.h"
#endif

/* default configuration path */
#define CFG_FILE_PATH "/etc/sxpd.cfg"

/* default pid-file path */
#define PID_FILE_PATH "/tmp/sxpd.pid"

static int pid_file = 0;

DECL_DEBUG_V6_STATIC_BUFFER

/* if enabled, sigquit (ctrl-\) will cause debug print instead of coredump */
#define SIGQUIT_DEBUG (1)

#if SIGQUIT_DEBUG
static int sxpd_print_bindings(struct sxpd_ctx *ctx, enum ip_type type)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, ctx);
    RC_CHECK(rc, out);
    struct sxpd_bindings_iterator *bindings_iterator = NULL;
    size_t counter = 0;
    for (;;) {
        struct v4_v6_prefix prefix;
        memset(&prefix, 0, sizeof(prefix));
        uint16_t tag = 0;
        rc =
            sxpd_iterate_bindings(ctx, type, &bindings_iterator, prefix.ip.data,
                                  sizeof(prefix.ip.data), &prefix.len, &tag);
        RC_CHECK(rc, out);
        if (!bindings_iterator) {
            break;
        }
        if (V4 == type) {
            printf("V4 binding #%zu: " DEBUG_V4_FMT "/%" PRIu8 " = %" PRIu16
                   "\n",
                   counter, DEBUG_V4_PRINT(prefix.ip.v4), prefix.len, tag);
        } else {
            printf("V6 binding #%zu: " DEBUG_V6_FMT "/%" PRIu8 " = %" PRIu16
                   "\n",
                   counter, DEBUG_V6_PRINT(prefix.ip.v6), prefix.len, tag);
        }
        ++counter;
    }
out:
    return rc;
}

static const char *
outgoing_connection_state_string(enum sxpd_peer_out_conn_state state)
{
    switch (state) {
    case NONE:
        return "not connected";
    case WAITING_CONNECT:
        return "waiting for TCP connect to finish";
    case WILL_SEND_OPEN:
        return "going to send OPEN message";
    case WAITING_OPEN:
        return "waiting for OPEN message";
    case WILL_SEND_OPEN_RESP:
        return "going to send OPEN_RESP message";
    case WAITING_OPEN_RESP:
        return "waiting for OPEN_RESP message";
    case CONNECTED:
        return "connected";
    case ERROR_CONNECT:
        return "in connect error state";
    case CONNECT_RETRY_TIMER:
        return "waiting for retry timer to fire";
    }
    return "UNKNOWN";
}

static void
sigquit_handler(__attribute__((unused)) struct evmgr_sig_handler *handler,
                __attribute__((unused)) int signal, void *ctx)
{
    if (!ctx) {
        return;
    }
    printf("*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\n");
    printf("SIGQUIT caught, printing debugging information\n");
    int rc = 0;
    RC_CHECK(rc = sxpd_print_bindings(ctx, V4), out);
    RC_CHECK(rc = sxpd_print_bindings(ctx, V6), out);
    struct sxpd_peer_iterator *peer_iterator = NULL;
    struct sxpd_peer_info p;
    memset(&p, 0, sizeof(p));
    size_t counter = 0;
    for (;;) {
        rc = sxpd_iterate_peers(ctx, &peer_iterator, &p);
        RC_CHECK(rc, out);
        if (!peer_iterator) {
            break;
        }
        printf("peer #%zu: " DEBUG_V4_FMT ":%" PRIu16 "\n", counter,
               DEBUG_V4_PRINT(p.nbo_ip), ntohs(p.nbo_port));
        printf("\t%zu connection(s) active\n", p.connections_count);
        if (NONE == p.outgoing_connection_state && p.connections_count > 1) {
            printf("\tincoming connection is up\n");
        }
        printf("\toutgoing connection is %s\n",
               outgoing_connection_state_string(p.outgoing_connection_state));
        if (p.keepalive_timer_active) {
            printf("\tkeepalive timer is armed\n");
        }
        if (p.retry_timer_active) {
            printf("\tretry timer is armed\n");
        }
        if (p.hold_timer_active) {
            printf("\thold timer is armed\n");
        }
        if (p.delete_hold_down_timer_active) {
            printf("\tdelete hold-down timer is armed\n");
        }
        if (p.reconciliation_timer_active) {
            printf("\treconciliation timer is armed\n");
        }
        if (p.is_speaker) {
            printf("\tpeer has speaker role\n");
        }
        if (p.is_listener) {
            printf("\tpeer has listener role\n");
        }
        ++counter;
    }
    struct sxpd_info info;
    memset(&info, 0, sizeof(info));
    rc = sxpd_get_info(ctx, &info);
    RC_CHECK(rc, out);
    printf("sxpd bind address is " DEBUG_V4_FMT ", port is %" PRIu16
           ", default connection password is '%s'\n",
           DEBUG_V4_PRINT(info.nbo_bind_ip), ntohs(info.nbo_port),
           info.default_connection_password);
    printf("%zu configured peer(s)\n", info.peer_count);
    if (info.enabled) {
        printf("Daemon is enabled.\n");
    } else {
        printf("Daemon is NOT enabled.\n");
    }
    printf("*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*\n");
out:
    return;
}
#endif

static struct evmgr_sig_handler *signal_handler;

static void
signal_callback(__attribute__((unused)) struct evmgr_sig_handler *sig_handler,
                int signum, void *ctx)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, ctx);
    if (RC_ISOK(rc) && SIGINT == signum) {
        LOG_DEBUG("Caught SIGINT, shutting down");
        evmgr_dispatch_break(ctx);
    }
}

static int store_pid(const char *path)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, path);
    RC_CHECK(rc, out);
    do {
        pid_file = open(path, O_CREAT | O_RDWR, 0600);
        if (pid_file < 0) {
            if (EINTR == errno) {
                continue;
            }
            LOG_ERROR(
                "Couldn't open pid-file %s, check that the parent directory "
                "exists and that the permissions are correct, errno=%d:%s",
                path, errno, strerror(errno));
            rc = -1;
            goto out;
        }
    } while (0);
    LOG_TRACE("Opened pid-file %s", path);
    struct flock flock;
    memset(&flock, 0, sizeof(flock));
    flock.l_type = F_WRLCK;
    if ((-1) == fcntl(pid_file, F_SETLK, &flock)) {
        if (EACCES == errno || EAGAIN == errno) {
            LOG_ERROR("Couldn't obtain write lock on pid-file %s", path);
        } else {
            LOG_ERROR("Unexpected arror occured while obtaining write lock on "
                      "pid-file %s, errno=%d:%s",
                      path, errno, strerror(errno));
        }
        rc = -1;
        goto out;
    }
    LOG_DEBUG("Write-locked pid-file %s", path);

#define PID_BUFF_SIZE (1024)
    char pid_buff[PID_BUFF_SIZE] = { 0 };
    ssize_t bytes_read = 0;
    do {
        bytes_read = read(pid_file, pid_buff, PID_BUFF_SIZE);
        if (bytes_read < 0 && EINTR == errno) {
            continue;
        }
    } while (0);
    if (bytes_read > 0) {
        long previous_pid = 0;
        if (1 == sscanf(pid_buff, "%ld", &previous_pid)) {
            if (previous_pid <= 0 || previous_pid > INT_MAX) {
                LOG_ERROR(
                    "Found invalid pid %ld in pid-file %s, truncating pid-file",
                    previous_pid, path);
            } else {
                if (kill((int)previous_pid, 0)) {
                    if (ESRCH == errno) {
                        LOG_DEBUG("Found pid %ld, but no such process, "
                                  "truncating pid-file %s",
                                  previous_pid, path);
                    } else {
                        LOG_ERROR("Sending kill signal to pid %ld failed, "
                                  "cannot verify process existence, "
                                  "errno=%d:%s",
                                  previous_pid, errno, strerror(errno));
                        rc = -1;
                        goto out;
                    }
                } else {
                    LOG_ERROR("Found pid %ld of running process", previous_pid);
                    rc = -1;
                    goto out;
                }
                do {
                    if (ftruncate(pid_file, 0)) {
                        if (EINTR == errno) {
                            continue;
                        }
                        LOG_ERROR("Truncating pid-file %s failed, errno=%d:%s",
                                  path, errno, strerror(errno));
                        rc = -1;
                        goto out;
                    }
                } while (0);
            }
        } else {
        }
    } else if (bytes_read < 0) {
        LOG_ERROR("Cannot read from pid-file %s, errno=%d:%s", path, errno,
                  strerror(errno));
        rc = -1;
        goto out;
    } else {
        /* file is empty */
    }
    pid_t pid = getpid();
    int pid_length = snprintf(pid_buff, PID_BUFF_SIZE, "%ld", (long)pid);
    if (pid_length < 1 || PID_BUFF_SIZE == pid_length) {
        LOG_ERROR("Couldn't printf process pid %ld in buffer of length %d",
                  (long)pid, PID_BUFF_SIZE);
        rc = -1;
        goto out;
    }
    ssize_t chars_written = 0;
    do {
        chars_written = write(pid_file, pid_buff, strlen(pid_buff));
        if (chars_written < 0 && EINTR == chars_written) {
            do {
                if (ftruncate(pid_file, 0)) {
                    if (EINTR == errno) {
                        continue;
                    }
                    LOG_ERROR("Truncating pid-file %s failed, errno=%d:%s",
                              path, errno, strerror(errno));
                    rc = -1;
                    goto out;
                }
            } while (0);
            continue;
        }
    } while (0);
    if (pid_length != chars_written) {
        LOG_ALERT("Couldn't write pid into pid-file %s, errno=%d:%s", path,
                  errno, strerror(errno));
        rc = -1;
        goto out;
    }
    LOG_TRACE("Wrote pid %ld in pid-file %s", (long)pid, path);
    if (fsync(pid_file)) {
        LOG_ERROR("Couldn't fsync changes to pid-file %s, errno=%d:%s", path,
                  errno, strerror(errno));
        rc = -1;
        goto out;
    }
out:
    if (RC_ISNOTOK(rc) && pid_file) {
        close(pid_file);
        pid_file = 0;
    }
    return rc;
}

int main(int argc, char *argv[])
{
    int rc = 0;
    struct sxpd_ctx *ctx = NULL;
    struct evmgr_settings *es = NULL;
    struct cfg_ctx *cfg_ctx = NULL;
    struct evmgr *evmgr = NULL;
    enum log_level default_ll = LOG_LEVEL_ERROR;
#ifdef ENABLE_GDBUS_INTERFACE
    struct sxpd_gdbus_ctx *gdbus_ctx = NULL;
#endif
    random_init();
    logging_open();
    const char *file_path = CFG_FILE_PATH;
    const char *pid_path = PID_FILE_PATH;
    if (1 == argc) {
        LOG_DEBUG("No arguments provided, using default config file path %s"
                  ", default log-level %s and default pid-file storage %s",
                  file_path, log_level_to_string(default_ll), pid_path);
        log_setloglevel(default_ll);
    } else if (4 == argc && argv[1] && argv[2] && argv[3]) {
        pid_path = argv[3];
        file_path = argv[1];
        rc = parse_log_level(&default_ll, argv[2]);
        if (RC_ISNOTOK(rc)) {
            LOG_ERROR(
                "Invalid arguments provided, usage: sxpd "
                "[config_file_path] [alert|error|debug|trace] [pid_file_path]");
            goto out;
        }
        LOG_DEBUG("Using provided config file path %s, log-level %s and "
                  "pid-file storage %s",
                  file_path, log_level_to_string(default_ll), pid_path);
        log_setloglevel(default_ll);
    } else if (3 == argc && argv[1] && argv[2]) {
        file_path = argv[1];
        rc = parse_log_level(&default_ll, argv[2]);
        if (RC_ISNOTOK(rc)) {
            LOG_ERROR(
                "Invalid arguments provided, usage: sxpd "
                "[config_file_path] [alert|error|debug|trace] [pid_file_path]");
            goto out;
        }
        LOG_DEBUG("Using provided config file path %s, log-level %s and "
                  "default pid-file storage %s",
                  file_path, log_level_to_string(default_ll), pid_path);
        log_setloglevel(default_ll);
    } else if (2 == argc && argv[1]) {
        file_path = argv[1];
        LOG_DEBUG("Using provided config file path %s, default log-level %s "
                  "and default pid-file storage %s",
                  file_path, log_level_to_string(default_ll), pid_path);
        log_setloglevel(default_ll);
    } else {
        LOG_ERROR("Invalid arguments provided, usage: sxpd [config_file_path] "
                  "[alert|error|debug|trace] [pid_file_path]");
        rc = -1;
        goto out;
    }

    rc = store_pid(pid_path);
    if (RC_ISNOTOK(rc)) {
        LOG_ALERT("Cannot store process ID in pid-file %s - already running?",
                  pid_path);
        goto out;
    }

    /* create configuration context */
    rc = cfg_ctx_create(&cfg_ctx, file_path, &es);
    if (RC_ISOK(rc)) {
        LOG_TRACE("Create configuration context success");
    } else {
        LOG_ERROR("Create configuration context failed: %d", rc);
        goto out;
    }

    evmgr = evmgr_create(es);

    if (evmgr) {
        LOG_TRACE("Event mgr create success");
    } else {
        LOG_ERROR("Event mgr create failed");
        rc = -1;
        goto out;
    }

    ctx = sxpd_create(evmgr, es, default_ll);
    if (!ctx) {
        LOG_ERROR("Cannot allocate sxpd context");
        rc = -1;
        goto out;
    }

#if SIGQUIT_DEBUG
    if (RC_ISOK(rc)) {
        struct evmgr_sig_handler *handler = evmgr_sig_handler_create(
            evmgr, NULL, SIGQUIT, sigquit_handler, ctx);
        if (!handler) {
            LOG_ERROR("Cannot create SIGQUIT signal handler");
            rc = -1;
            goto out;
        }
    }
#endif

    signal_handler =
        evmgr_sig_handler_create(evmgr, NULL, SIGINT, signal_callback, evmgr);
    if (!signal_handler) {
        LOG_ERROR("Cannot register signal handler");
        rc = -1;
        goto out;
    }

    rc = sxpd_register_config(ctx, cfg_ctx);
    RC_CHECK(rc, out);

#ifdef ENABLE_GDBUS_INTERFACE
    rc = sxpd_gdbus_interface_init(&gdbus_ctx, ctx, evmgr);
    RC_CHECK(rc, out);
#endif

    rc = evmgr_dispatch(evmgr);
    RC_CHECK(rc, out);

#ifdef ENABLE_GDBUS_INTERFACE
    rc = sxpd_gdbus_interface_deinit(gdbus_ctx);
    RC_CHECK(rc, out);
#endif

out:
    sxpd_destroy(ctx);
    cfg_ctx_destroy(cfg_ctx);
    evmgr_destroy(evmgr);
    logging_close();
    if (pid_file) {
        close(pid_file);
        remove(pid_path);
    }
    return rc;
}
