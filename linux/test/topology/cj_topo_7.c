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
#include "cj_shared.c"

/* default configuration path */
#define CFG_FILE_PATH_DEFAULT "cj_default.cfg"

/* c-java 7 - Linux vs Java SXP binding expansion */

static struct topo_task_wait_for_sync_ctx sync_ctx =
    TOPO_TASK_WAIT_FOR_SYNC(NULL);

/* sxpd instances */
static struct topo_sxpd topo_sxpd[] = {
    TOPO_SXPD_INIT("simple topology sxpd A", CFG_FILE_PATH_DEFAULT),
    TOPO_SXPDVX_INIT("simple topology sxpd B", CFG_FILE_PATH_DEFAULT, 1),
    TOPO_SXPD_INIT("dummy sxpd", CFG_FILE_PATH_DEFAULT),
};

#define SXPD_A (&topo_sxpd[0])
#define SXPD_DUMMY (&topo_sxpd[(sizeof(topo_sxpd) / sizeof(*topo_sxpd)) - 1])

/* sxpd instances ip addresses */
static const char topo_sxpd_ip[][16] = { "127.0.1.1" };

static const char java_topo_sxpd_ip[][16] = { "127.0.2.1", "127.0.2.2" };

#define SXPD_A_IP topo_sxpd_ip[0]

#define JAVA_SXPD_B_IP java_topo_sxpd_ip[1]

#define WAIT_TIMEOUT 60
#define PWD NULL
#define PORT 64999

/* expected SXPD A peer lists */
static struct topo_task_peer_chk sxpd_a_exp_peers[] = {
    TOPO_TASK_WAIT_FOR_PEER(JAVA_SXPD_B_IP, PORT, true, false, true),
};

struct topo_task_peer_chk_ctx sxpd_a_exp_peer_ctx =
    TOPO_TASK_WAIT_FOR_PEERS(sxpd_a_exp_peers, 1, false);

#define BINDING1_IPV4_IP "192.168.1.0"
#define BINDING1_IPV4_LEN 29
#define BINDING1_IPV4_SGT 29

#define BINDING2_IPV4_IP "192.168.1.0"
#define BINDING2_IPV4_LEN 30
#define BINDING2_IPV4_SGT 30

#define BINDING3_IPV4_IP "192.168.1.1"
#define BINDING3_IPV4_LEN 32
#define BINDING3_IPV4_SGT 32

/* log checker rules */
static struct log_pattern log_pattern[] = {
    LOG_PATTERN_STATIC_INIT("expected trace logs about uint32 config add",
                            LOG_EXPECTED, LOG_LEVEL_TRACE, "sxpd.c",
                            "sxpd_cfg_add_uint32_setting", NULL),
    LOG_PATTERN_STATIC_INIT("expected trace logs about peer add", LOG_EXPECTED,
                            LOG_LEVEL_TRACE, "sxpd.c", "sxpd_cfg_add_peer",
                            NULL),
    LOG_PATTERN_STATIC_INIT("expected trace logs about binding add",
                            LOG_EXPECTED, LOG_LEVEL_TRACE, "sxpd.c",
                            "sxpd_cfg_add_binding", NULL),
    LOG_PATTERN_STATIC_INIT("expected trace logs about binding config del",
                            LOG_EXPECTED, LOG_LEVEL_TRACE, "sxpd.c",
                            "sxpd_cfg_del_binding", NULL),

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
    LOG_PATTERN_STATIC_INIT(
        "optional error logs", LOG_OPTIONAL, LOG_LEVEL_ERROR, "evmgr.c",
        "evmgr_listener_md5_sig_del", "^(.*)(\\bCannot remove TCP-MD5-SIGN "
                                      "option for listener socket\\b)(.*?)$"),
    LOG_PATTERN_STATIC_INIT("optional error logs", LOG_OPTIONAL,
                            LOG_LEVEL_ERROR, "evmgr.c",
                            "evmgr_socket_md5_sig_set", NULL),
    LOG_PATTERN_STATIC_INIT("optional error logs", LOG_OPTIONAL,
                            LOG_LEVEL_ERROR, "sxpd.c", "sxpd_process_error_msg",
                            "^(.*)(\\bGot error reply from peer with "
                            "non-extended error code "
                            "1=VERSION-MISMATCH\\b)(.*?)$"),

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

int sleep_for_socket_cleanup = 1;
int sleep_time = 10;

static struct topo_task topo_task[] = {
    TOPO_TASK_MAIN_EXEC_INIT("set log check patterns",
                             topo_task_log_check_set_patterns_cb,
                             &log_patterns_ctx),
    TOPO_TASK_NEW_SXPD_INIT("create dummy sxpd instance", SXPD_DUMMY),
    TOPO_TASK_RUN_SXPD_INIT("run dummy sxpd instance", SXPD_DUMMY),
    TOPO_TASK_NEW_SXPD_INIT("create sxpd instance A", SXPD_A),
    TOPO_TASK_RUN_SXPD_INIT("run sxpd instance A", SXPD_A),
    TOPO_TASK_UINT32_CFG_STR_ADD_INIT("configure sxpd instance A IP", SXPD_A,
                                      UINT32_SETTING_BIND_ADDRESS, SXPD_A_IP),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd instance A node id", SXPD_A,
                                  UINT32_SETTING_NODE_ID, 0xA),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd A port", SXPD_A,
                                  UINT32_SETTING_PORT, PORT),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd instance A enabled", SXPD_A,
                                  UINT32_SETTING_ENABLED, 1),

    TOPO_TASK_BINDING_CFG_ADD_INIT("add V4 host binding to sxpd A", SXPD_A,
                                   BINDING1_IPV4_IP, BINDING1_IPV4_LEN,
                                   PREFIX_IPV4, BINDING1_IPV4_SGT),
    TOPO_TASK_BINDING_CFG_ADD_INIT("add V4 subnet binding to sxpd A", SXPD_A,
                                   BINDING2_IPV4_IP, BINDING2_IPV4_LEN,
                                   PREFIX_IPV4, BINDING2_IPV4_SGT),
    TOPO_TASK_BINDING_CFG_ADD_INIT("add V4 subnet binding to sxpd A", SXPD_A,
                                   BINDING3_IPV4_IP, BINDING3_IPV4_LEN,
                                   PREFIX_IPV4, BINDING3_IPV4_SGT),

    /* configure topology and test binding expansion */
    TOPO_TASK_WAIT_FOR_INIT("ready to start test part #1", SXPD_A, WAIT_TIMEOUT,
                            topo_task_wait_for_sync_cb, &sync_ctx),

    TOPO_TASK_PEER_CFG_ADD_INIT("add peer listener B to instance A", SXPD_A,
                                JAVA_SXPD_B_IP, PORT, PWD, PEER_LISTENER),

    TOPO_TASK_MAIN_EXEC_INIT("sleep before connect status check",
                             topo_task_sleep_cb, &sleep_time),

    TOPO_TASK_WAIT_FOR_INIT("wait for A peers connect", SXPD_A, WAIT_TIMEOUT,
                            topo_task_cb_wait_for_peers, &sxpd_a_exp_peer_ctx),

    TOPO_TASK_WAIT_FOR_INIT("synchronization - binding expansion success",
                            SXPD_DUMMY, WAIT_TIMEOUT,
                            topo_task_wait_for_sync_cb, &sync_ctx),

    TOPO_TASK_BINDING_CFG_DEL_INIT("del V4 host binding from sxpd A", SXPD_A,
                                   BINDING1_IPV4_IP, BINDING1_IPV4_LEN,
                                   PREFIX_IPV4, BINDING1_IPV4_SGT),
    TOPO_TASK_BINDING_CFG_DEL_INIT("del V4 subnet binding from sxpd A", SXPD_A,
                                   BINDING2_IPV4_IP, BINDING2_IPV4_LEN,
                                   PREFIX_IPV4, BINDING2_IPV4_SGT),
    TOPO_TASK_BINDING_CFG_DEL_INIT("del V4 subnet binding from sxpd A", SXPD_A,
                                   BINDING3_IPV4_IP, BINDING3_IPV4_LEN,
                                   PREFIX_IPV4, BINDING3_IPV4_SGT),

    TOPO_TASK_WAIT_FOR_INIT(
        "synchronization - expanded bindings delete success", SXPD_DUMMY,
        WAIT_TIMEOUT, topo_task_wait_for_sync_cb, &sync_ctx),

    /* test cleanup */
    TOPO_TASK_PAUSE_SXPD_INIT("pause sxpd A", SXPD_A),
    TOPO_TASK_MAIN_EXEC_INIT("run log checker", topo_task_log_check_run_cb,
                             NULL),
    TOPO_TASK_STOP_SXPD_INIT("stop sxpd A", SXPD_A),
    TOPO_TASK_WAIT_FOR_INIT("final synchronization", SXPD_DUMMY, WAIT_TIMEOUT,
                            topo_task_wait_for_sync_cb, &sync_ctx),
    TOPO_TASK_STOP_SXPD_INIT("stop dummy sxpd instance", SXPD_DUMMY),
};

int main(int argc, char *argv[])
{
    int rc = 0;

    if (2 == argc && argv[1]) {
        sync_ctx.file_path = argv[1];
        LOG_DEBUG("Using provided synchronization file path %s",
                  sync_ctx.file_path);
    } else {
        LOG_ERROR("Invalid arguments provided, usage: %s <sync_file_path>",
                  argv[0]);
        rc = -1;
        goto out;
    }

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
