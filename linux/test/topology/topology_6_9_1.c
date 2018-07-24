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

/* Stress test 6.9.1 */

#define WAIT_TIMEOUT 30

#define SMEGA_BOTH_NUM 10000

#define SMEGA_SXPD_NUM SMEGA_BOTH_NUM + 1

#define SMEGA_SXPD_LISTENER (&smega_topo_sxpd[smega_both_num])
#define SMEGA_SXPD_LISTENER_IP smega_topo_ip[SMEGA_BOTH_NUM]

/* expected peer list */
static struct topo_task_peer_chk smega_sxpd_exp_peers[SMEGA_BOTH_NUM];
static struct topo_task_peer_chk_ctx smega_sxpd_exp_peer_ctx =
    TOPO_TASK_WAIT_FOR_PEERS(
        smega_sxpd_exp_peers,
        sizeof(smega_sxpd_exp_peers) / sizeof(*smega_sxpd_exp_peers), false);

/* sxpd instances */
static struct topo_sxpd smega_topo_sxpd[SMEGA_SXPD_NUM];
/* sxpd instances ip addresses */
static char smega_topo_ip[SMEGA_SXPD_NUM][16];

/* simple mega topology tasks */
#define ONE(description) 1
#define SMEGA_SPEAKER_TASK_NUM                                          \
    (0 + ONE("create speaker instance") + ONE("run speaker instance") + \
     ONE("configure speaker instance IP") +                             \
     ONE("configure speaker instance node-id") +                        \
     ONE("enable speaker instance") +                                   \
     ONE("add listener peer to speaker instance") +                     \
     ONE("add speaker peer to listener instance") +                     \
     ONE("stop speaker instance"))

#define SMEGA_LISTENER_TASK_NUM                                             \
    (0 + ONE("set log check patterns") + ONE("create listener instance") +  \
     ONE("run listener instance") + ONE("configure listener instance IP") + \
     ONE("configure listener instance node id") +                           \
     ONE("enable listener instance") +                                      \
     ONE("wait for speaker and listener connect") + ONE("log check run") +  \
     ONE("stop listener instance"))

#define SMEGA_TASK_NUM(smega_both_num) \
    (smega_both_num * (SMEGA_SPEAKER_TASK_NUM)) + SMEGA_LISTENER_TASK_NUM

static struct topo_task smega_topo_task[SMEGA_TASK_NUM(SMEGA_BOTH_NUM)];

void smega_init(void);

size_t smega_both_num = SMEGA_BOTH_NUM;
size_t smega_sxpd_num = SMEGA_SXPD_NUM;

int main(int argc, char *argv[])
{
    int rc = 0;
    const char *errstr = NULL;

    if (1 == argc) {
        LOG_DEBUG("No arguments provided, using default number of speakers %zu",
                  smega_both_num);
    } else if (2 == argc && argv[1]) {
        smega_both_num = strtonum(argv[1], 1, SMEGA_BOTH_NUM, &errstr);
        if (NULL != errstr) {
            LOG_ERROR("Invalid [number of speakers] argument: %s", errstr);
            rc = -1;
            goto out;
        }
        smega_sxpd_exp_peer_ctx.peers_num = smega_both_num;
        smega_sxpd_num = smega_both_num + 1;
        LOG_DEBUG("Using specified argument: number of speakers %zu",
                  smega_both_num);
    } else {
        LOG_ERROR("Invalid arguments provided, usage: topology_6_9_1 "
                  "[number of speakers]");
        rc = -1;
        goto out;
    }

    /* simple mega topology tasks initialization */
    smega_init();

    /* run simple mega topology */
    rc = topo_run(smega_topo_task, SMEGA_TASK_NUM(smega_both_num));
    if (RC_ISOK(rc)) {
        LOG_TRACE("Topology test success: %d", rc);
    } else {
        LOG_ERROR("Topology test failed: %d", rc);
        RC_CHECK(rc, out);
    }

out:
    return rc;
}

static struct log_pattern smega_log_pattern[] = {
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

static struct topo_task_log_check_set_patterns_ctx smega_log_patterns_ctx =
    TOPO_TASK_LOG_CHECK_SET_PATTERNS(smega_log_pattern,
                                     sizeof(smega_log_pattern) /
                                         sizeof(*smega_log_pattern));

void smega_init(void)
{
    size_t i = 0;
    size_t taskid = 0;
    uint8_t host_part_ip_a = 2;
    uint8_t host_part_ip_b = 0;

    LOG_TRACE("Initializing simpe mega topology tasks...");

    /* initialize sxpd instance structures */
    for (i = 0; i < smega_sxpd_num; ++i) {
        smega_topo_sxpd[i] = (struct topo_sxpd)TOPO_SXPD_INIT(
            "simple mega topology speaker", CFG_FILE_PATH_DEFAULT);
    }

    smega_topo_sxpd[smega_both_num] = (struct topo_sxpd)TOPO_SXPD_INIT(
        "simple mega topology listener", CFG_FILE_PATH_DEFAULT);

    /* initialize sxpd instance task structures */
    smega_topo_task[taskid++] = (struct topo_task)TOPO_TASK_MAIN_EXEC_INIT(
        "set log check patterns", topo_task_log_check_set_patterns_cb,
        &smega_log_patterns_ctx);

    smega_topo_task[taskid++] = (struct topo_task)TOPO_TASK_NEW_SXPD_INIT(
        "create listener", SMEGA_SXPD_LISTENER);

    smega_topo_task[taskid++] = (struct topo_task)TOPO_TASK_RUN_SXPD_INIT(
        "run listener", SMEGA_SXPD_LISTENER);

    strcpy(SMEGA_SXPD_LISTENER_IP, "127.254.254.254");
    smega_topo_task[taskid++] =
        (struct topo_task)TOPO_TASK_UINT32_CFG_STR_ADD_INIT(
            "config listener IP", SMEGA_SXPD_LISTENER,
            UINT32_SETTING_BIND_ADDRESS, SMEGA_SXPD_LISTENER_IP);

    smega_topo_task[taskid++] = (struct topo_task)TOPO_TASK_UINT32_CFG_ADD_INIT(
        "config listener node id", SMEGA_SXPD_LISTENER, UINT32_SETTING_NODE_ID,
        0xAAAAAAAA);

    smega_topo_task[taskid++] = (struct topo_task)TOPO_TASK_UINT32_CFG_ADD_INIT(
        "config listener enabled", SMEGA_SXPD_LISTENER, UINT32_SETTING_ENABLED,
        1);

    for (i = 0; i < smega_both_num; ++i) {
        if (++host_part_ip_a > 254) {
            host_part_ip_b++;
            host_part_ip_a = 0;
        }

        smega_topo_task[taskid++] = (struct topo_task)TOPO_TASK_NEW_SXPD_INIT(
            "create speaker", (&smega_topo_sxpd[i]));

        smega_topo_task[taskid++] = (struct topo_task)TOPO_TASK_RUN_SXPD_INIT(
            "run speaker", (&smega_topo_sxpd[i]));

        sprintf(smega_topo_ip[i], "127.0.%" PRIu8 ".%" PRIu8, host_part_ip_b,
                host_part_ip_a);
        smega_topo_task[taskid++] =
            (struct topo_task)TOPO_TASK_UINT32_CFG_STR_ADD_INIT(
                "config speaker IP", (&smega_topo_sxpd[i]),
                UINT32_SETTING_BIND_ADDRESS, smega_topo_ip[i]);

        smega_sxpd_exp_peers[i] =
            (struct topo_task_peer_chk)TOPO_TASK_WAIT_FOR_PEER(
                smega_topo_ip[i], 64000, true, true, false);

        smega_topo_task[taskid++] =
            (struct topo_task)TOPO_TASK_UINT32_CFG_ADD_INIT(
                "config speaker node id", (&smega_topo_sxpd[i]),
                UINT32_SETTING_NODE_ID, 2 + i);

        smega_topo_task[taskid++] =
            (struct topo_task)TOPO_TASK_UINT32_CFG_ADD_INIT(
                "config speaker enabled", (&smega_topo_sxpd[i]),
                UINT32_SETTING_ENABLED, 1);

        smega_topo_task[taskid++] =
            (struct topo_task)TOPO_TASK_PEER_CFG_ADD_INIT(
                "add speaker peer to listener instance", SMEGA_SXPD_LISTENER,
                smega_topo_ip[i], 64000, NULL, PEER_SPEAKER);

        smega_topo_task[taskid++] =
            (struct topo_task)TOPO_TASK_PEER_CFG_ADD_INIT(
                "add listener peer to speaker instace", (&smega_topo_sxpd[i]),
                SMEGA_SXPD_LISTENER_IP, 64000, NULL, PEER_LISTENER);
    }

    smega_topo_task[taskid++] = (struct topo_task)TOPO_TASK_WAIT_FOR_INIT(
        "wait for listener and speakers connect", SMEGA_SXPD_LISTENER,
        WAIT_TIMEOUT, topo_task_cb_wait_for_peers, &smega_sxpd_exp_peer_ctx);

    smega_topo_task[taskid++] = (struct topo_task)TOPO_TASK_MAIN_EXEC_INIT(
        "run log checker", topo_task_log_check_run_cb, NULL);

    for (i = 0; i < smega_both_num; ++i) {
        smega_topo_task[taskid++] = (struct topo_task)TOPO_TASK_PAUSE_SXPD_INIT(
            "stop speaker instance", (&smega_topo_sxpd[i]));
    }

    smega_topo_task[taskid++] = (struct topo_task)TOPO_TASK_PAUSE_SXPD_INIT(
        "stop listener instance", SMEGA_SXPD_LISTENER);

    LOG_TRACE("Initializing simpe mega topology tasks finished");
}
