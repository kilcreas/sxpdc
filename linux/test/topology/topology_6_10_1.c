#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <fcntl.h>
#include <inttypes.h>

#include <sxp.h>
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
#define LISTENER_HOLD_TIME 900
#define BINDINGS_NUM 1000
#define RETRY_TIME 3

/* test 6.5.2 - keep alive message */

/* sxpd instances */
static struct topo_sxpd topo_sxpd[] = {
    TOPO_SXPD_INIT("simple topology sxpd A", CFG_FILE_PATH_DEFAULT),
};

#define SXPD_A (&topo_sxpd[0])

/* sxpd instances ip addresses */
static const char topo_sxpd_ip[][16] = { "127.0.0.1", "127.0.0.2" };

#define SXPD_A_IP topo_sxpd_ip[0]
#define SXPD_B_IP topo_sxpd_ip[1]

/* complex mega topology tasks */
#define ONE(description) 1
#define TASKS_NUM                                                             \
    (0 + ONE("set log check patterns") + ONE("create sxpd A") +               \
     ONE("run sxpd A") + ONE("configure sxpd A retry timer value") +          \
     ONE("configure sxpd A ip") + ONE("configure sxpd A node id") +           \
     ONE("configure sxpd A enabled") + ONE("add peer listener B to sxpd A") + \
     (ONE("configure sxpd A bindings") * BINDINGS_NUM) +                      \
     ONE("check message size limit") + ONE("del peer B from sxpd A") +        \
     ONE("stop sxpd A") + ONE("run log checker"))

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
    LOG_PATTERN_STATIC_INIT("expected trace logs about binding add",
                            LOG_EXPECTED, LOG_LEVEL_TRACE, "sxpd.c",
                            "sxpd_cfg_add_binding", NULL),

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

struct topo_task_msg_size_limit_verify_ctx {
    const char *bind_ip;
    uint16_t bind_port;
};

#define TOPO_TASK_MSG_SIZE_LIMIT_VERIFY_CTX_INIT(bind_ip_, bind_port_) \
    {                                                                  \
        .bind_ip = bind_ip_, .bind_port = bind_port_,                  \
    }

int socket_read(struct topo_task *topo_task, int socket, void *buffer,
                size_t buffer_size, size_t *bytes_read)
{
    int rc = 0;
    ssize_t bytes_read_ = 0;

    PARAM_NULL_CHECK(rc, topo_task, buffer, bytes_read);
    RC_CHECK(rc, out);

    *bytes_read = 0;

    do {
        bytes_read_ = read(socket, (char *)buffer + (*bytes_read),
                           buffer_size - (*bytes_read));
        while (-1 == bytes_read_ && EINTR == errno) {
            bytes_read_ = read(socket, (char *)buffer + (*bytes_read),
                               buffer_size - (*bytes_read));
        }

        if (0 == bytes_read_) {
            rc = 1;
            TOPO_TASK_ERROR(topo_task,
                            "Read from socket fd %d failed. End of file",
                            socket);
            goto out;
        } else if (-1 == bytes_read_ &&
                   (EAGAIN == errno || EWOULDBLOCK == errno)) {
            goto out;
        } else if (-1 == bytes_read_) {
            rc = -1;
            TOPO_TASK_ERROR(topo_task, "Read from socket fd %d failed rc=%d:%s",
                            socket, errno, strerror(errno));
            goto out;
        } else {
            TOPO_TASK_TRACE(topo_task, "Read %zu bytes from socket fd %d",
                            bytes_read_, socket);
            *bytes_read = (*bytes_read) + (size_t)bytes_read_;
        }
    } while (buffer_size != (*bytes_read));

out:
    return rc;
}

int socket_write(struct topo_task *topo_task, int socket, void *buffer,
                 size_t buffer_len)
{
    int rc = 0;
    ssize_t write_ret = 0;
    size_t bytes_written = 0;

    PARAM_NULL_CHECK(rc, topo_task, buffer);
    RC_CHECK(rc, out);

    TOPO_TASK_TRACE(topo_task, "%zu bytes are ready for write to socket fd %d",
                    buffer_len, socket);

    do {
        write_ret = write(socket, (char *)buffer + bytes_written,
                          buffer_len - bytes_written);
        while (-1 == write_ret && EINTR == errno) {
            write_ret = write(socket, (char *)buffer + bytes_written,
                              buffer_len - bytes_written);
        }

        if (-1 == write_ret && (EAGAIN == errno || EWOULDBLOCK == errno)) {
            continue;
        } else if (-1 == write_ret) {
            rc = -1;
            TOPO_TASK_ERROR(topo_task, "Write to socket fd %d failed rc=%d:%s",
                            socket, errno, strerror(errno));
            goto out;
        } else {
            TOPO_TASK_TRACE(topo_task, "Write %zu bytes to socket fd %d",
                            write_ret, socket);
            bytes_written = bytes_written + (size_t)write_ret;
        }
    } while (buffer_len != bytes_written);

out:
    return rc;
}

int socket_select_read(struct topo_task *topo_task, int socket_fd,
                       struct timeval *timeout)
{
    int rc = 0;
    int tmp_rc = 0;
    fd_set fds;

    PARAM_NULL_CHECK(rc, topo_task, timeout);

    FD_ZERO(&fds);
    FD_SET(socket_fd, &fds);
    tmp_rc =
        select(socket_fd + 1, &fds, (fd_set *)NULL, (fd_set *)NULL, timeout);
    if (0 == tmp_rc) {
        rc = 1;
        TOPO_TASK_TRACE(topo_task, "Select on socket fd %d timeout %ld seconds",
                        socket_fd, timeout->tv_sec);
        goto out;
    } else if (tmp_rc < 0) {
        rc = -1;
        TOPO_TASK_ERROR(topo_task, "Select on socket fd %d error: %d, errno="
                                   "%d:%s",
                        socket_fd, tmp_rc, errno, strerror(errno));
        goto out;
    }

out:
    return rc;
}

int topo_task_msg_size_limit_verify_cb(struct topo_task *topo_task)
{
    int rc = 0;
    struct timeval tv_timeout = { 0, 0 };
    int main_sock = -1;
    int cl_sock = -1;
    size_t i = 0;
    struct topo_task_msg_size_limit_verify_ctx *ctx = NULL;
#define BUFFER_SIZE (1024 * 4)
    uint8_t buffer[BUFFER_SIZE] = { 0 };
    size_t buffer_len = 0;
    size_t read_len = 0;
    struct sxp_msg *sxp_msg = (struct sxp_msg *)buffer;

    PARAM_NULL_CHECK(rc, topo_task, topo_task->task.main_exec.cb_ctx);
    RC_CHECK(rc, out);

    ctx = topo_task->task.main_exec.cb_ctx;

    /* create listening non-blocking socket */
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

    /* wait for client connect */
    tv_timeout.tv_sec = 3;
    tv_timeout.tv_usec = 0;
    rc = socket_select_read(topo_task, main_sock, &tv_timeout);
    RC_CHECK(rc, out);
    cl_sock = accept(main_sock, NULL, NULL);
    if (-1 == cl_sock) {
        rc = -1;
        TOPO_TASK_ERROR(topo_task,
                        "Accept on main socket fd %d failed: %d, errno=%d:%s",
                        main_sock, cl_sock, errno, strerror(errno));
        goto out;
    } else {
        TOPO_TASK_TRACE(topo_task, "Accept new client fd %d", cl_sock);
    }

    /* switch client socket to non-blocking mode */
    if ((-1) ==
        fcntl(cl_sock, F_SETFL, fcntl(cl_sock, F_GETFL, 0) | O_NONBLOCK)) {
        rc = -1;
        TOPO_TASK_ERROR(
            topo_task,
            "failed to switch socket fd %d to non_blocking mode, errno=%d:%s",
            cl_sock, errno, strerror(errno));
        goto out;
    }

    /* wait for recv open message from client */
    tv_timeout.tv_sec = 3;
    tv_timeout.tv_usec = 0;
    rc = socket_select_read(topo_task, cl_sock, &tv_timeout);
    RC_CHECK(rc, out);

    /* read hello message */
    rc = socket_read(topo_task, cl_sock, (void *)buffer, BUFFER_SIZE,
                     &buffer_len);
    if (RC_ISNOTOK(rc)) {
        rc = -1;
        TOPO_TASK_ERROR(topo_task, "socket fd %d read failed: %d", cl_sock, rc);
        goto out;
    }

    /* check hello message type and size */
    if (sizeof(struct sxp_msg) > buffer_len) {
        rc = -1;
        TOPO_TASK_ERROR(
            topo_task,
            "Received open message size %zu smaller than minimum size %zu",
            buffer_len, sizeof(struct sxp_msg));
        goto out;
    }

    if (ntohl(sxp_msg->length) != buffer_len) {
        rc = -1;
        TOPO_TASK_ERROR(topo_task, "Open message size %" PRIu32
                                   " not equal expected size %zu",
                        ntohl(sxp_msg->length), buffer_len);
        goto out;
    }

    if (ntohl(sxp_msg->type) != SXP_MSG_OPEN) {
        rc = -1;
        TOPO_TASK_ERROR(topo_task, "Received message type %" PRIu32
                                   " not equal expected type %" PRIu32,
                        ntohl(sxp_msg->type), SXP_MSG_OPEN);
        goto out;
    }

    /* create and send open resp message */
    memset(buffer, 0, BUFFER_SIZE);
    rc = sxp_create_open_resp(buffer, BUFFER_SIZE, 4, SXP_MODE_LISTENER, 0x0);
    RC_CHECK(rc, out);
    struct sxp_attribute *caps = NULL;
    RC_CHECK(rc = sxp_msg_add_capabilities((void *)buffer, BUFFER_SIZE, &caps),
             out);

    rc = sxp_capabilities_add_capability((void *)buffer, BUFFER_SIZE, caps,
                                         SXP_CAPABILITY_IPV4_UNICAST);
    RC_CHECK(rc, out);

    rc = sxp_capabilities_add_capability((void *)buffer, BUFFER_SIZE, caps,
                                         SXP_CAPABILITY_IPV6_UNICAST);
    RC_CHECK(rc, out);

    rc = sxp_capabilities_add_capability((void *)buffer, BUFFER_SIZE, caps,
                                         SXP_CAPABILITY_SUBNET_BINDINGS);
    RC_CHECK(rc, out);
    rc = sxp_msg_add_hold_time((void *)buffer, BUFFER_SIZE, LISTENER_HOLD_TIME,
                               KEEPALIVE_UNUSED);
    RC_CHECK(rc, out);

    enum sxp_error_code code = SXP_ERR_CODE_NONE;
    enum sxp_error_sub_code subcode = SXP_SUB_ERR_CODE_NONE;
    rc = sxp_msg_hton_swap((void *)buffer, &code, &subcode);
    if (sxp_isnotok(rc, code, subcode)) {
        TOPO_TASK_ERROR(topo_task, "%s",
                        "Swap message from host to network byte order failed");
        rc = -1;
        goto out;
    }

    rc = socket_write(topo_task, cl_sock, buffer, ntohl(sxp_msg->length));
    RC_CHECK(rc, out);

    buffer_len = 0;
    i = 0;

    /* recv message from client */
    do {
        tv_timeout.tv_sec = 10;
        tv_timeout.tv_usec = 0;
        rc = socket_select_read(topo_task, cl_sock, &tv_timeout);
        if (1 == rc) {
            if (0 == i) {
                rc = -1;
                TOPO_TASK_ERROR(topo_task,
                                "Read data from socket fd %d timeout", cl_sock);
            } else if (0 != buffer_len) {
                rc = -1;
                TOPO_TASK_ERROR(topo_task, "Socket fd %d read incomplete "
                                           "message from client. %zu bytes "
                                           "left in buffer. sxp msg length is "
                                           "%" PRIu32,
                                cl_sock, buffer_len, ntohl(sxp_msg->length));
            } else {
                rc = 0;
            }
            goto out;
        } else {
            RC_CHECK(rc, out);
        }

        /* read message */
        read_len = 0;
        rc = socket_read(topo_task, cl_sock, (void *)&buffer[buffer_len],
                         BUFFER_SIZE - buffer_len, &read_len);
        if (RC_ISNOTOK(rc)) {
            rc = -1;
            TOPO_TASK_ERROR(topo_task, "socket fd %d read failed: %d", cl_sock,
                            rc);
            goto out;
        }
        buffer_len = buffer_len + read_len;

        /* check message */
        while (sizeof(struct sxp_msg) <= buffer_len) {
            if (ntohl(sxp_msg->type) != SXP_MSG_UPDATE) {
                rc = -1;
                TOPO_TASK_ERROR(topo_task, "Received message #%zu type %" PRIu32
                                           " not equal expected type %" PRIu32,
                                i, ntohl(sxp_msg->type), SXP_MSG_UPDATE);
                goto out;
            }

            if (ntohl(sxp_msg->length) > BUFFER_SIZE) {
                rc = -1;
                TOPO_TASK_ERROR(topo_task,
                                "Message #%zu size %" PRIu32
                                " bigger than maximum buffer size %d",
                                i, ntohl(sxp_msg->length), BUFFER_SIZE);
                goto out;
            }

            if (ntohl(sxp_msg->length) <= buffer_len) {
                TOPO_TASK_TRACE(topo_task,
                                "Received update sxp msg length is %" PRIu32,
                                ntohl(sxp_msg->length));
                buffer_len = buffer_len - ntohl(sxp_msg->length);
                memmove(buffer, &buffer[ntohl(sxp_msg->length)], buffer_len);
                i++;
            } else {
                break;
            }
        }
    } while (1);

    TOPO_TASK_TRACE(topo_task, "success: %d", rc);

out:
    if (cl_sock > -1) {
        int rc = close(cl_sock);
        while (RC_ISNOTOK(rc) && (EINTR == errno)) {
            rc = close(cl_sock);
        }
    }

    if (main_sock > -1) {
        int rc = close(main_sock);
        while (RC_ISNOTOK(rc) && (EINTR == errno)) {
            rc = close(main_sock);
        }
    }
    return rc;
}

struct topo_task_msg_size_limit_verify_ctx topo_task_msg_size_limit_verify_ctx =
    TOPO_TASK_MSG_SIZE_LIMIT_VERIFY_CTX_INIT(SXPD_B_IP, 64000);

static struct topo_task topo_task[TASKS_NUM];

static char bindings_ip[BINDINGS_NUM][16];

void tasks_init(void);

int main(void)
{
    int rc = 0;

    tasks_init();

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

void tasks_init(void)
{
    size_t i = 0;
    size_t task_num = 0;

    uint8_t host_part_ip_a = 2;
    uint8_t host_part_ip_b = 0;

    for (i = 0; i < BINDINGS_NUM; ++i) {
        if (++host_part_ip_a > 254) {
            host_part_ip_b++;
            host_part_ip_a = 0;
        }
        sprintf(bindings_ip[i], "127.0.%" PRIu8 ".%" PRIu8, host_part_ip_b,
                host_part_ip_a);
    }

    topo_task[task_num++] = (struct topo_task)TOPO_TASK_MAIN_EXEC_INIT(
        "set log check patterns", topo_task_log_check_set_patterns_cb,
        &log_patterns_ctx);

    topo_task[task_num++] = (struct topo_task)TOPO_TASK_NEW_SXPD_INIT(
        "create sxpd instance A", SXPD_A);
    topo_task[task_num++] = (struct topo_task)TOPO_TASK_RUN_SXPD_INIT(
        "run sxpd instance A", SXPD_A);
    topo_task[task_num++] = (struct topo_task)TOPO_TASK_UINT32_CFG_ADD_INIT(
        "update sxpd A retry timer value", SXPD_A, UINT32_SETTING_RETRY_TIMER,
        RETRY_TIME);
    topo_task[task_num++] = (struct topo_task)TOPO_TASK_UINT32_CFG_STR_ADD_INIT(
        "configure sxpd instance A IP", SXPD_A, UINT32_SETTING_BIND_ADDRESS,
        SXPD_A_IP);
    topo_task[task_num++] = (struct topo_task)TOPO_TASK_UINT32_CFG_ADD_INIT(
        "configure sxpd instance A node id", SXPD_A, UINT32_SETTING_NODE_ID,
        0xA);
    topo_task[task_num++] = (struct topo_task)TOPO_TASK_UINT32_CFG_ADD_INIT(
        "configure sxpd instance A enabled", SXPD_A, UINT32_SETTING_ENABLED, 1);
    topo_task[task_num++] = (struct topo_task)TOPO_TASK_PEER_CFG_ADD_INIT(
        "add peer listener B to instance A", SXPD_A, SXPD_B_IP, 64000, NULL,
        PEER_LISTENER);

    /* add bindings */
    for (i = 0; i < BINDINGS_NUM; ++i) {
        topo_task[task_num++] =
            (struct topo_task)TOPO_TASK_BINDING_CFG_ADD_INIT(
                "add binding to speaker", SXPD_A, bindings_ip[i], 32,
                PREFIX_IPV4, 40);
    }

    topo_task[task_num++] = (struct topo_task)TOPO_TASK_MAIN_EXEC_INIT(
        "Run sxpd B and check message size limit",
        topo_task_msg_size_limit_verify_cb,
        &topo_task_msg_size_limit_verify_ctx);
    topo_task[task_num++] = (struct topo_task)TOPO_TASK_PEER_CFG_DEL_INIT(
        "del peer B from instance A", SXPD_A, SXPD_B_IP, 64000, NULL,
        PEER_LISTENER);
    topo_task[task_num++] = (struct topo_task)TOPO_TASK_STOP_SXPD_INIT(
        "stop sxpd instance A", SXPD_A);
    topo_task[task_num++] = (struct topo_task)TOPO_TASK_MAIN_EXEC_INIT(
        "run log checker", topo_task_log_check_run_cb, NULL);

    return;
}
