#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#include <inttypes.h>
#include <sxpd.h>
#include <config.h>
#include <debug.h>
#include <radix.h>
#include <util.h>

#include <mem.h>
#include <config.h>
#include <util.h>

#include "../framework/inc/log_check.h"
#include "../framework/inc/topology.h"

#include "shared.c"

/* default configuration path */
#define CFG_FILE_PATH_DEFAULT "default.cfg"

#define WAIT_TIMEOUT 30
#define RETRY_TIME 4

/* test 6.5.1 - retry timer */

/* sxpd instances */
static struct topo_sxpd topo_sxpd[] = {
    TOPO_SXPD_INIT("simple topology sxpd A", CFG_FILE_PATH_DEFAULT),
};

#define SXPD_A (&topo_sxpd[0])

/* sxpd instances ip addresses */
static const char topo_sxpd_ip[][16] = { "127.0.0.1", "127.0.0.2" };

#define SXPD_A_IP topo_sxpd_ip[0]
#define SXPD_B_IP topo_sxpd_ip[1]

static struct topo_task_peer_chk sxpd_a_exp_peers[] = {
    TOPO_TASK_WAIT_FOR_PEER(SXPD_B_IP, 64000, false, false, true),
};

struct topo_task_peer_chk_ctx sxpd_a_exp_peer_ctx = TOPO_TASK_WAIT_FOR_PEERS(
    sxpd_a_exp_peers, sizeof(sxpd_a_exp_peers) / sizeof(*sxpd_a_exp_peers),
    true);

/* log checker rules */
static struct log_pattern log_pattern[] = {
    LOG_PATTERN_STATIC_INIT("expected trace logs about uint32 config add",
                            LOG_EXPECTED, LOG_LEVEL_TRACE, "sxpd.c",
                            "sxpd_cfg_add_uint32_setting", NULL),
    LOG_PATTERN_STATIC_INIT("expected trace logs about peer add", LOG_EXPECTED,
                            LOG_LEVEL_TRACE, "sxpd.c", "sxpd_cfg_add_peer",
                            NULL),
    LOG_PATTERN_STATIC_INIT("expected trace logs about peer config del",
                            LOG_EXPECTED, LOG_LEVEL_TRACE, "sxpd.c",
                            "sxpd_cfg_del_peer", NULL),

    LOG_PATTERN_STATIC_INIT(
        "optional error logs about rejecting incoming socket", LOG_OPTIONAL,
        LOG_LEVEL_ERROR, "sxpd.c", "sxpd_peer_connection_acceptable",
        "^(.*)(\\balready have enough connections\\b)(.*?)$"),
    LOG_PATTERN_STATIC_INIT(
        "optional error logs about connection reset by peer", LOG_OPTIONAL,
        LOG_LEVEL_ERROR, "evmgr.c", "evmgr_socket_read",
        "^(.*)(\\bfailed rc=104:Connection reset by peer\\b)(.*?)$"),
    LOG_PATTERN_STATIC_INIT(
        "optional error logs about connection refused", LOG_OPTIONAL,
        LOG_LEVEL_ERROR, "evmgr.c", "evmgr_socket_read",
        "^(.*)(\\bfailed rc=111:Connection refused\\b)(.*?)$"),
    LOG_PATTERN_STATIC_INIT(
        "optional error logs about peer config does not exist yet",
        LOG_OPTIONAL, LOG_LEVEL_ERROR, "sxpd.c",
        "sxpd_evmgr_global_accept_callback", "^(.*)(\\bUnknown peer\\b)(.*?)$"),
    LOG_PATTERN_STATIC_INIT(
        "optional error logs", LOG_OPTIONAL, LOG_LEVEL_ERROR, "evmgr.c",
        "evmgr_listener_md5_sig_del", "^(.*)(\\bCannot remove TCP-MD5-SIGN "
                                      "option for listener socket\\b)(.*?)$"),
    LOG_PATTERN_STATIC_INIT(
        "optional error logs", LOG_OPTIONAL, LOG_LEVEL_ERROR, "evmgr.c",
        "evmgr_socket_md5_sig_set", "^(.*)(\\bFailed to set TCP-MD5-SIGN "
                                    "socket option, errno=2:No such file or "
                                    "directory\\b)(.*?)$"),

    LOG_PATTERN_STATIC_INIT("unexpected trace logs about binding add",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "sxpd.c",
                            "sxpd_cfg_add_binding", NULL),
    LOG_PATTERN_STATIC_INIT("unexpected trace logs about uint32 config del",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "sxpd.c",
                            "sxpd_cfg_del_uint32_setting", NULL),
    LOG_PATTERN_STATIC_INIT("unexpected trace logs about str config del",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "sxpd.c",
                            "sxpd_cfg_del_str_setting", NULL),
    LOG_PATTERN_STATIC_INIT("unexpected trace logs about binding config del",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "sxpd.c",
                            "sxpd_cfg_del_binding", NULL),

    LOG_PATTERN_STATIC_INIT("unexpected any other error logs", LOG_UNEXPECTED,
                            LOG_LEVEL_ERROR, NULL, NULL, NULL),
};

static struct topo_task_log_check_set_patterns_ctx log_patterns_ctx =
    TOPO_TASK_LOG_CHECK_SET_PATTERNS(log_pattern, sizeof(log_pattern) /
                                                      sizeof(*log_pattern));

struct topo_task_retry_timer_verify_ctx {
    const char *bind_ip;
    uint16_t bind_port;
    size_t retry_timer_time;
    size_t repeat;
};

#define TOPO_TASK_RETRY_TIMER_VERIFY_CTX_INIT(bind_ip_, bind_port_,       \
                                              retry_timer_time_, repeat_) \
    {                                                                     \
        .bind_ip = bind_ip_, .bind_port = bind_port_,                     \
        .retry_timer_time = retry_timer_time_, .repeat = repeat_,         \
    }

int topo_task_retry_timer_verify_cb(struct topo_task *topo_task)
{
    int rc = 0;
    int tmp_rc = 0;
    struct timespec ts_start = { 0, 0 };
    struct timespec ts_end = { 0, 0 };
    struct timeval tv_timeout = { 0, 0 };
    int main_sock = -1;
    int cl_sock = -1;
    size_t i = 0;
    size_t retry_timer_time_75p = 0;
    size_t retry_time_actual = 0;
    struct topo_task_retry_timer_verify_ctx *ctx = NULL;
    fd_set fds;

    PARAM_NULL_CHECK(rc, topo_task, topo_task->task.main_exec.cb_ctx);
    RC_CHECK(rc, out);

    ctx = topo_task->task.main_exec.cb_ctx;

    retry_timer_time_75p = ctx->retry_timer_time * 0.75;

    main_sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if ((-1) == main_sock) {
        rc = -1;
        TOPO_TASK_ERROR(topo_task, "Failed to create main socket: %d", rc);
        goto out;
    }

    int optval = 1;
    if (0 != setsockopt(main_sock, SOL_SOCKET, SO_REUSEADDR, &optval,
                        sizeof(optval))) {
        LOG_DEBUG("Setting SO_REUSEADDR failed - ignoring");
    }

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_port = htons(ctx->bind_port);
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    inet_pton(AF_INET, ctx->bind_ip, &address.sin_addr);

    if (bind(main_sock, (struct sockaddr *)&address, sizeof(address))) {
        rc = -1;
        TOPO_TASK_ERROR(
            topo_task, "Failed to bind main socket fd %d to " DEBUG_SIN_FMT
                       ", errno=%d:%s",
            main_sock, DEBUG_SIN_PRINT(address), errno, strerror(errno));
        goto out;
    }

    rc = listen(main_sock, 1);
    if (RC_ISNOTOK(rc)) {
        TOPO_TASK_ERROR(topo_task,
                        "Listen on main socket fd %d failed: %d, errno=%d:%s",
                        main_sock, rc, errno, strerror(errno));
        goto out;
    }

    for (i = 0; i < ctx->repeat; ++i) {
        FD_ZERO(&fds);
        FD_SET(main_sock, &fds);
        tv_timeout.tv_sec = ctx->retry_timer_time + 3;
        tmp_rc = select(main_sock + 1, &fds, (fd_set *)NULL, (fd_set *)NULL,
                        &tv_timeout);
        if (0 == tmp_rc) {
            rc = -1;
            TOPO_TASK_ERROR(topo_task,
                            "Select on main socket fd %d timeout %ld seconds",
                            main_sock, tv_timeout.tv_sec);
            goto out;
        } else if (tmp_rc < 0) {
            rc = -1;
            TOPO_TASK_ERROR(topo_task, "Select on main socket fd %d error: %d, "
                                       "errno=%d:%s",
                            main_sock, rc, errno, strerror(errno));
            goto out;
        }

        cl_sock = accept(main_sock, NULL, NULL);
        if (-1 == cl_sock) {
            rc = -1;
            TOPO_TASK_ERROR(
                topo_task,
                "Accept on main socket fd %d failed: %d, errno=%d:%s",
                main_sock, cl_sock, errno, strerror(errno));
            goto out;
        } else {
            TOPO_TASK_TRACE(topo_task, "Accept new client fd %d", cl_sock);
        }

        if (i != 0) {
            rc = clock_gettime(CLOCK_REALTIME, &ts_end);
            if (RC_ISNOTOK(rc)) {
                TOPO_TASK_ERROR(topo_task, "get real time error: %d", rc);
                goto out;
            }
            retry_time_actual = ts_end.tv_sec - ts_start.tv_sec;
            if (retry_time_actual < retry_timer_time_75p) {
                TOPO_TASK_ERROR(topo_task,
                                "retry time %zu is less then minimum time: %zu",
                                retry_time_actual, retry_timer_time_75p);
                rc = -1;
                goto out;
            }

            if (retry_time_actual > ctx->retry_timer_time) {
                TOPO_TASK_ERROR(topo_task,
                                "retry time %zu is above maximum time: %zu",
                                retry_time_actual, ctx->retry_timer_time);
                rc = -1;
                goto out;
            }
        }

        rc = close(cl_sock);
        while (RC_ISNOTOK(rc) && (EINTR == errno)) {
            TOPO_TASK_TRACE(topo_task, "success: %d", rc);
            rc = close(cl_sock);
        }

        if (RC_ISNOTOK(rc)) {
            TOPO_TASK_ERROR(topo_task,
                            "Close client socket fd %d failed: %d, errno=%d:%s",
                            cl_sock, rc, errno, strerror(errno));
            goto out;
        } else {
            TOPO_TASK_TRACE(topo_task, "Closed client socket fd %d", cl_sock);
            cl_sock = -1;
        }

        rc = clock_gettime(CLOCK_REALTIME, &ts_start);
        if (RC_ISNOTOK(rc)) {
            TOPO_TASK_ERROR(topo_task, "get real time error: %d", rc);
            goto out;
        }
    }

    TOPO_TASK_TRACE(topo_task, "success: %d", rc);

out:
    if (cl_sock > -1) {
        int rc = close(cl_sock);
        while (RC_ISNOTOK(rc) && (EINTR == errno)) {
            TOPO_TASK_TRACE(topo_task, "success: %d", rc);
            rc = close(cl_sock);
        }
    }

    if (main_sock > -1) {
        TOPO_TASK_TRACE(topo_task, "success: %d", rc);
        int rc = close(main_sock);
        while (RC_ISNOTOK(rc) && (EINTR == errno)) {
            TOPO_TASK_TRACE(topo_task, "success: %d", rc);
            rc = close(main_sock);
        }
    }
    return rc;
}

struct topo_task_retry_timer_verify_ctx topo_task_retry_timer_verify_ctx =
    TOPO_TASK_RETRY_TIMER_VERIFY_CTX_INIT(SXPD_B_IP, 64000, RETRY_TIME, 3);

static struct topo_task topo_task[] = {
    TOPO_TASK_MAIN_EXEC_INIT("set log check patterns",
                             topo_task_log_check_set_patterns_cb,
                             &log_patterns_ctx),

    TOPO_TASK_NEW_SXPD_INIT("create sxpd instance A", SXPD_A),
    TOPO_TASK_RUN_SXPD_INIT("run sxpd instance A", SXPD_A),
    TOPO_TASK_UINT32_CFG_ADD_INIT("update sxpd A retry timer value", SXPD_A,
                                  UINT32_SETTING_RETRY_TIMER, RETRY_TIME),
    TOPO_TASK_UINT32_CFG_STR_ADD_INIT("configure sxpd instance A IP", SXPD_A,
                                      UINT32_SETTING_BIND_ADDRESS, SXPD_A_IP),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd instance A node id", SXPD_A,
                                  UINT32_SETTING_NODE_ID, 0xA),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd instance A enabled", SXPD_A,
                                  UINT32_SETTING_ENABLED, 1),

    TOPO_TASK_PEER_CFG_ADD_INIT("add peer listener B to instance A", SXPD_A,
                                SXPD_B_IP, 64000, NULL, PEER_LISTENER),
    TOPO_TASK_WAIT_FOR_INIT("A B sxpd are not connected", SXPD_A, WAIT_TIMEOUT,
                            topo_task_cb_wait_for_peers, &sxpd_a_exp_peer_ctx),

    TOPO_TASK_MAIN_EXEC_INIT("Run sxpd B and verify retry timer functionality",
                             topo_task_retry_timer_verify_cb,
                             &topo_task_retry_timer_verify_ctx),

    TOPO_TASK_PEER_CFG_DEL_INIT("del peer B from instance A", SXPD_A, SXPD_B_IP,
                                64000, NULL, PEER_LISTENER),

    TOPO_TASK_STOP_SXPD_INIT("stop sxpd instance A", SXPD_A),

    TOPO_TASK_MAIN_EXEC_INIT("run log checker", topo_task_log_check_run_cb,
                             NULL),
};

int main(void)
{
    int rc = 0;

    /* run topology tasks */
    rc = topo_run(topo_task, sizeof(topo_task) / sizeof(*topo_task));
    if (RC_ISOK(rc)) {
        LOG_TRACE("Topology test success: %d", rc);
    } else {
        LOG_ERROR("Topology test failed: %d", rc);
        RC_CHECK(rc, out);
    }

out:
    return rc;
}
