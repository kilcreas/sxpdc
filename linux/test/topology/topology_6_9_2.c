#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <bsd/stdlib.h>

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

/* Stress test 6.9.2 - complex mega topology */

/* sxpd instances num */
#define CMEGA_LISTENER_NUM 1
/* both per speakers */
#define CMEGA_B_PER_S 2
#define CMEGA_BINDINGS_PER_SPEAKER 1024
#define CMEGA_SPEAKER_NUM 1024
#define CMEGA_BOTH_NUM (CMEGA_SPEAKER_NUM * CMEGA_B_PER_S)
#define CMEGA_LISTENER_EXP_BIND_NUM \
    CMEGA_BINDINGS_PER_SPEAKER *CMEGA_SPEAKER_NUM

#define CMEGA_IPV4_STR_SIZE 16
#define CMEGA_IPV6_STR_SIZE 40

int cmega_bindings_propagate_sleep = 120;

/* sxpd instances */
static struct topo_sxpd cmega_listener_sxpd[CMEGA_LISTENER_NUM];
static struct topo_sxpd cmega_both_sxpd[CMEGA_BOTH_NUM];
static struct topo_sxpd cmega_speaker_sxpd[CMEGA_SPEAKER_NUM];

/* listener expected peer list */
static struct topo_task_peer_chk cmega_listener_exp_peers[CMEGA_BOTH_NUM];
static struct topo_task_peer_chk_ctx cmega_listener_exp_peer_ctx =
    TOPO_TASK_WAIT_FOR_PEERS(cmega_listener_exp_peers,
                             sizeof(cmega_listener_exp_peers) /
                                 sizeof(*cmega_listener_exp_peers),
                             false);

/* both expected peer list */
static struct topo_task_peer_chk cmega_both_exp_peers[CMEGA_BOTH_NUM][2];
static struct topo_task_peer_chk_ctx cmega_both_exp_peer_ctx[CMEGA_BOTH_NUM];

/* speaker expected peer list */
static struct topo_task_peer_chk cmega_speaker_exp_peers[CMEGA_SPEAKER_NUM][2];
static struct topo_task_peer_chk_ctx
    cmega_speaker_exp_peer_ctx[CMEGA_SPEAKER_NUM];

/* listener expected bindings */
struct topo_task_binding_chk
    cmega_listener_exp_bindings[CMEGA_LISTENER_EXP_BIND_NUM];
struct topo_task_binding_chk_ctx cmega_listener_exp_bind_ctx =
    TOPO_TASK_WAIT_FOR_BINDINGS(cmega_listener_exp_bindings,
                                CMEGA_LISTENER_EXP_BIND_NUM, false);

/* bindings ip addresses */
static char cmega_speaker_bindings_ip
    [CMEGA_SPEAKER_NUM][CMEGA_BINDINGS_PER_SPEAKER][CMEGA_IPV4_STR_SIZE];

/* ip addresses */
static char cmega_listener_ip[CMEGA_LISTENER_NUM][CMEGA_IPV4_STR_SIZE];
static char cmega_both_ip[CMEGA_BOTH_NUM][CMEGA_IPV4_STR_SIZE];
static char cmega_speaker_ip[CMEGA_SPEAKER_NUM][CMEGA_IPV4_STR_SIZE];

#define CMEGA_LISTENER (&cmega_listener_sxpd[0])
#define CMEGA_LISTENER_IP cmega_listener_ip[0]

/* complex mega topology tasks */
#define ONE(description) 1

#define CMEGA_LISTENER_TASK_NUM                                             \
    (0 + ONE("set log check patterns") + ONE("create listener instance") +  \
     ONE("run listener instance") + ONE("configure listener instance IP") + \
     ONE("configure listener instance node id") +                           \
     ONE("enable listener instance") +                                      \
     ONE("wait for listener peers connect") + ONE("Sleep") +                \
     ONE("check bindings") + ONE("log check run") +                         \
     ONE("stop listener instance"))

#define CMEGA_BOTH_TASK_NUM                                                 \
    (0 + ONE("create both instance") + ONE("run both instance") +           \
     ONE("configure both instance IP") +                                    \
     ONE("configure both instance node-id") + ONE("enable both instance") + \
     ONE("add both peer to listener instance") +                            \
     ONE("add listener peer to both instance") +                            \
     ONE("add speaker peer to both instance") +                             \
     ONE("add both peer to speaker instance") +                             \
     ONE("wait for both peers connect") + ONE("stop speaker instance"))

#define CMEGA_SPEAKER_TASK_NUM(bindings_per_speaker)                          \
    (0 + ONE("create speaker instance") + ONE("run speaker instance") +       \
     ONE("configure speaker instance IP") +                                   \
     ONE("configure speaker instance node-id") +                              \
     ONE("enable speaker instance") + ONE("wait for speaker peers connect") + \
     (ONE("add bindings") * bindings_per_speaker) +                           \
     ONE("stop speaker instance"))

#define CMEGA_TASK_NUM(both_num, speaker_num, bindings_per_speaker) \
    ((CMEGA_LISTENER_NUM * CMEGA_LISTENER_TASK_NUM) +               \
     (both_num * CMEGA_BOTH_TASK_NUM) +                             \
     (speaker_num * CMEGA_SPEAKER_TASK_NUM(bindings_per_speaker)))

static struct topo_task cmega_topo_task[CMEGA_TASK_NUM(
    CMEGA_BOTH_NUM, CMEGA_SPEAKER_NUM, CMEGA_BINDINGS_PER_SPEAKER)];

void cmega_init(void);

size_t cmega_bindings_per_speaker = CMEGA_BINDINGS_PER_SPEAKER;
size_t cmega_speaker_num = CMEGA_SPEAKER_NUM;
size_t cmega_both_num = CMEGA_BOTH_NUM;

int main(int argc, char *argv[])
{
    int rc = 0;
    const char *errstr = NULL;

    if (1 == argc) {
        LOG_DEBUG("No arguments provided, using default number of speakers %zu"
                  " and default number of bindings per speaker %zu",
                  cmega_speaker_num, cmega_bindings_per_speaker);
    } else if (3 == argc && argv[1] && argv[2]) {
        cmega_speaker_num = strtonum(argv[1], 1, CMEGA_SPEAKER_NUM, &errstr);
        if (NULL != errstr) {
            LOG_ERROR("Invalid [number of speakers] argument: %s", errstr);
            rc = -1;
            goto out;
        }

        cmega_bindings_per_speaker =
            strtonum(argv[2], 1, CMEGA_BINDINGS_PER_SPEAKER, &errstr);
        if (NULL != errstr) {
            LOG_ERROR("Invalid [number of bindings per speaker] argument: %s",
                      errstr);
            rc = -1;
            goto out;
        }

        cmega_both_num = cmega_speaker_num * CMEGA_B_PER_S;
        cmega_listener_exp_bind_ctx.bindings_num =
            cmega_bindings_per_speaker * cmega_speaker_num;
        cmega_listener_exp_peer_ctx.peers_num = cmega_both_num;
        LOG_DEBUG("Using specified arguments: number of speakers %zu and "
                  "number of bindings per speaker %zu",
                  cmega_speaker_num, cmega_bindings_per_speaker);
    } else {
        LOG_ERROR("Invalid arguments provided, usage: topology_6_9_2 "
                  "[number of speakers] [number of bindings per speaker]");
        rc = -1;
        goto out;
    }

    /* simple mega topology tasks initialization */
    cmega_init();

    /* run simple mega topology */
    rc = topo_run(cmega_topo_task,
                  CMEGA_TASK_NUM(cmega_both_num, cmega_speaker_num,
                                 cmega_bindings_per_speaker));
    if (RC_ISOK(rc)) {
        LOG_TRACE("Topology test success: %d", rc);
    } else {
        LOG_ERROR("Topology test failed: %d", rc);
        RC_CHECK(rc, out);
    }

out:
    return rc;
}

static struct log_pattern cmega_log_pattern[] = {
    LOG_PATTERN_STATIC_INIT("expected trace logs about uint32 config add",
                            LOG_EXPECTED, LOG_LEVEL_TRACE, "sxpd.c",
                            "sxpd_cfg_add_uint32_setting", NULL),
    LOG_PATTERN_STATIC_INIT("expected trace logs about peer add", LOG_EXPECTED,
                            LOG_LEVEL_TRACE, "sxpd.c", "sxpd_cfg_add_peer",
                            NULL),

    LOG_PATTERN_STATIC_INIT(
        "optional error logs about rejecting incoming socket", LOG_OPTIONAL,
        LOG_LEVEL_ERROR, "sxpd.c", "sxpd_peer_connection_acceptable",
        "^(.*)(\\balready have enough connections\\b)(.*?)$"),
    LOG_PATTERN_STATIC_INIT(
        "optional error logs about connection reset by peer", LOG_OPTIONAL,
        LOG_LEVEL_ERROR, "evmgr.c", "evmgr_socket_read",
        "^(.*)(\\bfailed rc=104:Connection reset by peer\\b)(.*?)$"),
    LOG_PATTERN_STATIC_INIT(
        "optional error logs about peer config does not exist yet",
        LOG_OPTIONAL, LOG_LEVEL_ERROR, "sxpd.c",
        "sxpd_evmgr_global_accept_callback", "^(.*)(\\bUnknown peer\\b)(.*?)$"),

    LOG_PATTERN_STATIC_INIT("unexpected trace logs about uint32 config del",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "sxpd.c",
                            "sxpd_cfg_del_uint32_setting", NULL),
    LOG_PATTERN_STATIC_INIT("unexpected trace logs about str config del",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "sxpd.c",
                            "sxpd_cfg_del_str_setting", NULL),
    LOG_PATTERN_STATIC_INIT("unexpected trace logs about peer config del",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "sxpd.c",
                            "sxpd_cfg_del_peer", NULL),
    LOG_PATTERN_STATIC_INIT("unexpected trace logs about binding config del",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "sxpd.c",
                            "sxpd_cfg_del_binding", NULL),

    LOG_PATTERN_STATIC_INIT("unexpected any other error logs", LOG_UNEXPECTED,
                            LOG_LEVEL_ERROR, NULL, NULL, NULL),
};

static struct topo_task_log_check_set_patterns_ctx cmega_log_patterns_ctx =
    TOPO_TASK_LOG_CHECK_SET_PATTERNS(cmega_log_pattern,
                                     sizeof(cmega_log_pattern) /
                                         sizeof(*cmega_log_pattern));

void cmega_init(void)
{
    size_t i = 0;
    size_t j = 0;
    size_t taskid = 0;
    uint8_t host_part_ip_a = 2;
    uint8_t host_part_ip_b = 0;
    uint32_t node_id = 2;

    uint8_t binding_part_ip_a = 2;
    uint8_t binding_part_ip_b = 0;
    uint8_t binding_part_ip_c = 0;

    LOG_TRACE("Initializing complex mega topology tasks...");

    /* initialize sxpd instance structures */
    for (i = 0; i < CMEGA_LISTENER_NUM; ++i) {
        cmega_listener_sxpd[i] = (struct topo_sxpd)TOPO_SXPD_INIT(
            "complex mega topology listener", CFG_FILE_PATH_DEFAULT);
    }

    for (i = 0; i < cmega_both_num; ++i) {
        cmega_both_sxpd[i] = (struct topo_sxpd)TOPO_SXPD_INIT(
            "complex mega topology both", CFG_FILE_PATH_DEFAULT);
    }

    for (i = 0; i < cmega_speaker_num; ++i) {
        cmega_speaker_sxpd[i] = (struct topo_sxpd)TOPO_SXPD_INIT(
            "complex mega topology speaker", CFG_FILE_PATH_DEFAULT);
    }

    /* generate ip addresses */
    strcpy(CMEGA_LISTENER_IP, "127.254.254.254");
    for (i = 0; i < cmega_both_num; ++i) {
        if (++host_part_ip_a > 254) {
            host_part_ip_b++;
            host_part_ip_a = 0;
        }
        sprintf(cmega_both_ip[i], "127.0.%" PRIu8 ".%" PRIu8, host_part_ip_b,
                host_part_ip_a);
    }
    for (i = 0; i < cmega_speaker_num; ++i) {
        if (++host_part_ip_a > 254) {
            host_part_ip_b++;
            host_part_ip_a = 0;
        }
        sprintf(cmega_speaker_ip[i], "127.0.%" PRIu8 ".%" PRIu8, host_part_ip_b,
                host_part_ip_a);

        /* bindings ip addresses */
        for (j = 0; j < cmega_bindings_per_speaker; ++j) {
            if (++binding_part_ip_a > 254) {
                binding_part_ip_a = 0;
                if (++binding_part_ip_b > 254) {
                    binding_part_ip_b = 0;
                    binding_part_ip_c++;
                }
            }
            sprintf(cmega_speaker_bindings_ip[i][j],
                    "127.%" PRIu8 ".%" PRIu8 ".%" PRIu8, binding_part_ip_c,
                    binding_part_ip_b, binding_part_ip_a);
        }
    }

    /* generate listener sxpd instance tasks */
    cmega_topo_task[taskid++] = (struct topo_task)TOPO_TASK_MAIN_EXEC_INIT(
        "set log check patterns", topo_task_log_check_set_patterns_cb,
        &cmega_log_patterns_ctx);

    cmega_topo_task[taskid++] = (struct topo_task)TOPO_TASK_NEW_SXPD_INIT(
        "create listener", CMEGA_LISTENER);

    cmega_topo_task[taskid++] = (struct topo_task)TOPO_TASK_RUN_SXPD_INIT(
        "run listener", CMEGA_LISTENER);

    cmega_topo_task[taskid++] =
        (struct topo_task)TOPO_TASK_UINT32_CFG_STR_ADD_INIT(
            "config listener IP", CMEGA_LISTENER, UINT32_SETTING_BIND_ADDRESS,
            CMEGA_LISTENER_IP);

    cmega_topo_task[taskid++] = (struct topo_task)TOPO_TASK_UINT32_CFG_ADD_INIT(
        "config listener node id", CMEGA_LISTENER, UINT32_SETTING_NODE_ID,
        0xAAAAAAAA);

    cmega_topo_task[taskid++] = (struct topo_task)TOPO_TASK_UINT32_CFG_ADD_INIT(
        "config listener enabled", CMEGA_LISTENER, UINT32_SETTING_ENABLED, 1);

    /* generate both sxpd instances tasks */
    for (i = 0; i < cmega_both_num; ++i) {

        cmega_topo_task[taskid++] = (struct topo_task)TOPO_TASK_NEW_SXPD_INIT(
            "create both", (&cmega_both_sxpd[i]));

        cmega_topo_task[taskid++] = (struct topo_task)TOPO_TASK_RUN_SXPD_INIT(
            "run both", (&cmega_both_sxpd[i]));

        cmega_topo_task[taskid++] =
            (struct topo_task)TOPO_TASK_UINT32_CFG_STR_ADD_INIT(
                "config both IP", (&cmega_both_sxpd[i]),
                UINT32_SETTING_BIND_ADDRESS, cmega_both_ip[i]);

        cmega_topo_task[taskid++] =
            (struct topo_task)TOPO_TASK_UINT32_CFG_ADD_INIT(
                "config both node id", (&cmega_both_sxpd[i]),
                UINT32_SETTING_NODE_ID, node_id++);

        cmega_topo_task[taskid++] =
            (struct topo_task)TOPO_TASK_UINT32_CFG_ADD_INIT(
                "config both enabled", (&cmega_both_sxpd[i]),
                UINT32_SETTING_ENABLED, 1);

        cmega_topo_task[taskid++] =
            (struct topo_task)TOPO_TASK_PEER_CFG_ADD_INIT(
                "add both peer to listener instance", CMEGA_LISTENER,
                cmega_both_ip[i], 64000, NULL, PEER_SPEAKER);

        cmega_topo_task[taskid++] =
            (struct topo_task)TOPO_TASK_PEER_CFG_ADD_INIT(
                "add listener peer to both instance", (&cmega_both_sxpd[i]),
                CMEGA_LISTENER_IP, 64000, NULL, PEER_LISTENER);

        cmega_listener_exp_peers[i] =
            (struct topo_task_peer_chk)TOPO_TASK_WAIT_FOR_PEER(
                cmega_both_ip[i], 64000, true, true, false);

        cmega_both_exp_peers[i][0] =
            (struct topo_task_peer_chk)TOPO_TASK_WAIT_FOR_PEER(
                CMEGA_LISTENER_IP, 64000, true, false, true);

        cmega_both_exp_peer_ctx[i] =
            (struct topo_task_peer_chk_ctx)TOPO_TASK_WAIT_FOR_PEERS(
                cmega_both_exp_peers[i], 1, false);
    }

    cmega_topo_task[taskid++] = (struct topo_task)TOPO_TASK_WAIT_FOR_INIT(
        "wait for listener peers", CMEGA_LISTENER, 30,
        topo_task_cb_wait_for_peers, &cmega_listener_exp_peer_ctx);

    /* generate speaker sxpd instances tasks */
    for (i = 0; i < cmega_speaker_num; ++i) {

        cmega_topo_task[taskid++] = (struct topo_task)TOPO_TASK_NEW_SXPD_INIT(
            "create speaker", (&cmega_speaker_sxpd[i]));

        cmega_topo_task[taskid++] = (struct topo_task)TOPO_TASK_RUN_SXPD_INIT(
            "run speaker", (&cmega_speaker_sxpd[i]));

        cmega_topo_task[taskid++] =
            (struct topo_task)TOPO_TASK_UINT32_CFG_STR_ADD_INIT(
                "config speaker IP", (&cmega_speaker_sxpd[i]),
                UINT32_SETTING_BIND_ADDRESS, cmega_speaker_ip[i]);

        cmega_topo_task[taskid++] =
            (struct topo_task)TOPO_TASK_UINT32_CFG_ADD_INIT(
                "config speaker node id", (&cmega_speaker_sxpd[i]),
                UINT32_SETTING_NODE_ID, node_id++);

        cmega_topo_task[taskid++] =
            (struct topo_task)TOPO_TASK_UINT32_CFG_ADD_INIT(
                "config speaker enabled", (&cmega_speaker_sxpd[i]),
                UINT32_SETTING_ENABLED, 1);

        for (j = 0; j < CMEGA_B_PER_S; ++j) {
            cmega_topo_task[taskid++] =
                (struct topo_task)TOPO_TASK_PEER_CFG_ADD_INIT(
                    "add speaker peer to both instance",
                    (&cmega_both_sxpd[(i * CMEGA_B_PER_S) + j]),
                    cmega_speaker_ip[i], 64000, NULL, PEER_SPEAKER);

            cmega_topo_task[taskid++] =
                (struct topo_task)TOPO_TASK_PEER_CFG_ADD_INIT(
                    "add both peer to speaker instance",
                    (&cmega_speaker_sxpd[i]),
                    cmega_both_ip[(i * CMEGA_B_PER_S) + j], 64000, NULL,
                    PEER_LISTENER);

            cmega_both_exp_peers[(i * CMEGA_B_PER_S) + j][1] =
                (struct topo_task_peer_chk)TOPO_TASK_WAIT_FOR_PEER(
                    cmega_speaker_ip[i], 64000, true, true, false);

            cmega_speaker_exp_peers[i][j] =
                (struct topo_task_peer_chk)TOPO_TASK_WAIT_FOR_PEER(
                    cmega_both_ip[(i * CMEGA_B_PER_S) + j], 64000, true, false,
                    true);

            cmega_topo_task[taskid++] =
                (struct topo_task)TOPO_TASK_WAIT_FOR_INIT(
                    "wait for both peers connect",
                    &cmega_both_sxpd[(i * CMEGA_B_PER_S) + j], 30,
                    topo_task_cb_wait_for_peers,
                    &cmega_both_exp_peer_ctx[(i * CMEGA_B_PER_S) + j]);
        }

        cmega_speaker_exp_peer_ctx[i] =
            (struct topo_task_peer_chk_ctx)TOPO_TASK_WAIT_FOR_PEERS(
                cmega_speaker_exp_peers[i], CMEGA_B_PER_S, false);

        cmega_topo_task[taskid++] = (struct topo_task)TOPO_TASK_WAIT_FOR_INIT(
            "wait for speaker peers connect", &cmega_speaker_sxpd[i], 30,
            topo_task_cb_wait_for_peers, &cmega_speaker_exp_peer_ctx[i]);
    }

    for (i = 0; i < cmega_speaker_num; ++i) {
        for (j = 0; j < cmega_bindings_per_speaker; ++j) {
            cmega_topo_task[taskid++] =
                (struct topo_task)TOPO_TASK_BINDING_CFG_ADD_INIT(
                    "add binding to speaker", &cmega_speaker_sxpd[i],
                    cmega_speaker_bindings_ip[i][j], 32, PREFIX_IPV4, 40);

            cmega_listener_exp_bindings[(i * cmega_bindings_per_speaker) + j] =
                (struct topo_task_binding_chk)TOPO_TASK_WAIT_FOR_BINDING(
                    cmega_speaker_bindings_ip[i][j], 32, PREFIX_IPV4, 40);
        }
    }

    cmega_topo_task[taskid++] = (struct topo_task)TOPO_TASK_MAIN_EXEC_INIT(
        "sleep for a while... bindings propagating...", topo_task_sleep_cb,
        &cmega_bindings_propagate_sleep);

    cmega_topo_task[taskid++] = (struct topo_task)TOPO_TASK_WAIT_FOR_INIT(
        "wait for all listener bindings", CMEGA_LISTENER, 20,
        topo_task_cb_wait_for_bindings, &cmega_listener_exp_bind_ctx);

    cmega_topo_task[taskid++] = (struct topo_task)TOPO_TASK_MAIN_EXEC_INIT(
        "run log checker", topo_task_log_check_run_cb, NULL);

    /* stop topology */
    for (i = 0; i < cmega_speaker_num; ++i) {
        cmega_topo_task[taskid++] = (struct topo_task)TOPO_TASK_PAUSE_SXPD_INIT(
            "stop speaker instance", (&cmega_speaker_sxpd[i]));
    }

    for (i = 0; i < cmega_both_num; ++i) {
        cmega_topo_task[taskid++] = (struct topo_task)TOPO_TASK_PAUSE_SXPD_INIT(
            "stop both instance", (&cmega_both_sxpd[i]));
    }

    cmega_topo_task[taskid++] = (struct topo_task)TOPO_TASK_PAUSE_SXPD_INIT(
        "stop listener instance", CMEGA_LISTENER);

    LOG_TRACE("Initializing complex mega topology tasks finished");
}
