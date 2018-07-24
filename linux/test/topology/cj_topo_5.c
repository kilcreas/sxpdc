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

/* c-java 5 - Linux vs Java SXP bindings conflict management */

static struct topo_task_wait_for_sync_ctx sync_ctx =
    TOPO_TASK_WAIT_FOR_SYNC(NULL);

/* sxpd instances */
static struct topo_sxpd topo_sxpd[] = {
    TOPO_SXPD_INIT("simple topology sxpd A", CFG_FILE_PATH_DEFAULT),
    TOPO_SXPD_INIT("simple topology sxpd B", CFG_FILE_PATH_DEFAULT),
    TOPO_SXPD_INIT("simple topology sxpd C", CFG_FILE_PATH_DEFAULT),
    TOPO_SXPD_INIT("simple topology sxpd D", CFG_FILE_PATH_DEFAULT),
    TOPO_SXPD_INIT("simple topology sxpd E", CFG_FILE_PATH_DEFAULT),
    TOPO_SXPD_INIT("dummy sxpd", CFG_FILE_PATH_DEFAULT),
};

#define SXPD_A (&topo_sxpd[0])
#define SXPD_B (&topo_sxpd[1])
#define SXPD_C (&topo_sxpd[2])
#define SXPD_D (&topo_sxpd[3])
#define SXPD_E (&topo_sxpd[4])
#define SXPD_DUMMY (&topo_sxpd[(sizeof(topo_sxpd) / sizeof(*topo_sxpd)) - 1])

/* sxpd instances ip addresses */
static const char topo_sxpd_ip[][16] = { "127.0.1.1", "127.0.1.2", "127.0.1.3",
                                         "127.0.1.4", "127.0.1.5" };

static const char java_topo_sxpd_ip[][16] = { "127.0.2.1", "127.0.2.2",
                                              "127.0.2.3", "127.0.2.4",
                                              "127.0.2.5" };

#define SXPD_A_IP topo_sxpd_ip[0]
#define SXPD_B_IP topo_sxpd_ip[1]
#define SXPD_C_IP topo_sxpd_ip[2]
#define SXPD_D_IP topo_sxpd_ip[3]
#define SXPD_E_IP topo_sxpd_ip[4]

#define JAVA_SXPD_A_IP java_topo_sxpd_ip[0]
#define JAVA_SXPD_B_IP java_topo_sxpd_ip[1]
#define JAVA_SXPD_C_IP java_topo_sxpd_ip[2]
#define JAVA_SXPD_D_IP java_topo_sxpd_ip[3]
#define JAVA_SXPD_E_IP java_topo_sxpd_ip[4]

#define WAIT_TIMEOUT 60
#define PWD NULL
#define PORT 64999

/* expected SXPD A peer lists */
static struct topo_task_peer_chk sxpd_a_exp_peers[] = {
    TOPO_TASK_WAIT_FOR_PEER(SXPD_B_IP, PORT, true, false, true),
};

struct topo_task_peer_chk_ctx sxpd_a_exp_peer_ctx =
    TOPO_TASK_WAIT_FOR_PEERS(sxpd_a_exp_peers, 1, false);

/* expected peer SXPD B peer lists */
struct topo_task_peer_chk sxpd_b_exp_peers[] = {
    TOPO_TASK_WAIT_FOR_PEER(SXPD_A_IP, PORT, true, true, false),
    TOPO_TASK_WAIT_FOR_PEER(JAVA_SXPD_C_IP, PORT, true, false, true),
};

struct topo_task_peer_chk_ctx sxpd_b_exp_peer_ctx =
    TOPO_TASK_WAIT_FOR_PEERS(sxpd_b_exp_peers, 2, false);

/* expected SXPD D peer lists */
static struct topo_task_peer_chk sxpd_d_exp_peers[] = {
    TOPO_TASK_WAIT_FOR_PEER(JAVA_SXPD_C_IP, PORT, true, true, false),
};

struct topo_task_peer_chk_ctx sxpd_d_exp_peer_ctx =
    TOPO_TASK_WAIT_FOR_PEERS(sxpd_d_exp_peers, 1, false);

/* expected SXPD E peer lists */
static struct topo_task_peer_chk sxpd_e_exp_peers[] = {
    TOPO_TASK_WAIT_FOR_PEER(JAVA_SXPD_C_IP, PORT, true, false, true),
};

struct topo_task_peer_chk_ctx sxpd_e_exp_peer_ctx =
    TOPO_TASK_WAIT_FOR_PEERS(sxpd_e_exp_peers, 1, false);

#define BINDING1_IPV4_IP "192.168.1.1"
#define BINDING1_IPV4_LEN 32
#define BINDING1_IPV4_SGT 40
#define BINDING1_IPV4_SGT2 41

#define BINDING2_IPV4_IP "192.168.2.0"
#define BINDING2_IPV4_LEN 24
#define BINDING2_IPV4_SGT 42
#define BINDING2_IPV4_SGT2 43

#define BINDING3_IPV6_IP "aaaa:eeee:abcf:eeee:0:0:0:0"
#define BINDING3_IPV6_LEN 128
#define BINDING3_IPV6_SGT 60
#define BINDING3_IPV6_SGT2 61

#define BINDING4_IPV6_IP "aaaa:eeee:abcf:eeed:0:0:0:0"
#define BINDING4_IPV6_LEN 64
#define BINDING4_IPV6_SGT 62
#define BINDING4_IPV6_SGT2 63

struct topo_task_binding_chk sxpd_exp_bindings[] = {
    TOPO_TASK_WAIT_FOR_BINDING(BINDING1_IPV4_IP, BINDING1_IPV4_LEN, PREFIX_IPV4,
                               BINDING1_IPV4_SGT),
    TOPO_TASK_WAIT_FOR_BINDING(BINDING2_IPV4_IP, BINDING2_IPV4_LEN, PREFIX_IPV4,
                               BINDING2_IPV4_SGT),
    TOPO_TASK_WAIT_FOR_BINDING(BINDING3_IPV6_IP, BINDING3_IPV6_LEN, PREFIX_IPV6,
                               BINDING3_IPV6_SGT),
    TOPO_TASK_WAIT_FOR_BINDING(BINDING4_IPV6_IP, BINDING4_IPV6_LEN, PREFIX_IPV6,
                               BINDING4_IPV6_SGT),
};

struct topo_task_binding_chk sxpd_exp_bindings2[] = {
    TOPO_TASK_WAIT_FOR_BINDING(BINDING1_IPV4_IP, BINDING1_IPV4_LEN, PREFIX_IPV4,
                               BINDING1_IPV4_SGT2),
    TOPO_TASK_WAIT_FOR_BINDING(BINDING2_IPV4_IP, BINDING2_IPV4_LEN, PREFIX_IPV4,
                               BINDING2_IPV4_SGT2),
    TOPO_TASK_WAIT_FOR_BINDING(BINDING3_IPV6_IP, BINDING3_IPV6_LEN, PREFIX_IPV6,
                               BINDING3_IPV6_SGT2),
    TOPO_TASK_WAIT_FOR_BINDING(BINDING4_IPV6_IP, BINDING4_IPV6_LEN, PREFIX_IPV6,
                               BINDING4_IPV6_SGT2),
};

struct topo_task_binding_chk_ctx sxpd_exp_bind_ctx =
    TOPO_TASK_WAIT_FOR_BINDINGS(
        sxpd_exp_bindings,
        sizeof(sxpd_exp_bindings) / sizeof(*sxpd_exp_bindings), false);

struct topo_task_binding_chk_ctx sxpd_exp_bind_ctx2 =
    TOPO_TASK_WAIT_FOR_BINDINGS(
        sxpd_exp_bindings2,
        sizeof(sxpd_exp_bindings2) / sizeof(*sxpd_exp_bindings2), true);

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
    TOPO_TASK_BINDING_CFG_ADD_INIT("add V6 host binding to sxpd A", SXPD_A,
                                   BINDING3_IPV6_IP, BINDING3_IPV6_LEN,
                                   PREFIX_IPV6, BINDING3_IPV6_SGT),
    TOPO_TASK_BINDING_CFG_ADD_INIT("add V6 subnet binding to sxpd A", SXPD_A,
                                   BINDING4_IPV6_IP, BINDING4_IPV6_LEN,
                                   PREFIX_IPV6, BINDING4_IPV6_SGT),

    TOPO_TASK_NEW_SXPD_INIT("create sxpd instance B", SXPD_B),
    TOPO_TASK_RUN_SXPD_INIT("run sxpd instance B", SXPD_B),
    TOPO_TASK_UINT32_CFG_STR_ADD_INIT("configure sxpd instance B IP", SXPD_B,
                                      UINT32_SETTING_BIND_ADDRESS, SXPD_B_IP),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd instance B node id", SXPD_B,
                                  UINT32_SETTING_NODE_ID, 0xB),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd B port", SXPD_B,
                                  UINT32_SETTING_PORT, PORT),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd instance B enabled", SXPD_B,
                                  UINT32_SETTING_ENABLED, 1),

    TOPO_TASK_NEW_SXPD_INIT("create sxpd instance C", SXPD_C),
    TOPO_TASK_RUN_SXPD_INIT("run sxpd instance C", SXPD_C),
    TOPO_TASK_UINT32_CFG_STR_ADD_INIT("configure sxpd instance C IP", SXPD_C,
                                      UINT32_SETTING_BIND_ADDRESS, SXPD_C_IP),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd instance C node id", SXPD_C,
                                  UINT32_SETTING_NODE_ID, 0xC),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd C port", SXPD_C,
                                  UINT32_SETTING_PORT, PORT),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd instance C enabled", SXPD_C,
                                  UINT32_SETTING_ENABLED, 1),

    TOPO_TASK_NEW_SXPD_INIT("create sxpd instance D", SXPD_D),
    TOPO_TASK_RUN_SXPD_INIT("run sxpd instance D", SXPD_D),
    TOPO_TASK_UINT32_CFG_STR_ADD_INIT("configure sxpd instance D IP", SXPD_D,
                                      UINT32_SETTING_BIND_ADDRESS, SXPD_D_IP),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd instance D node id", SXPD_D,
                                  UINT32_SETTING_NODE_ID, 0xD),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd D port", SXPD_D,
                                  UINT32_SETTING_PORT, PORT),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd instance D enabled", SXPD_D,
                                  UINT32_SETTING_ENABLED, 1),

    TOPO_TASK_NEW_SXPD_INIT("create sxpd instance E", SXPD_E),
    TOPO_TASK_RUN_SXPD_INIT("run sxpd instance E", SXPD_E),
    TOPO_TASK_UINT32_CFG_STR_ADD_INIT("configure sxpd instance E IP", SXPD_E,
                                      UINT32_SETTING_BIND_ADDRESS, SXPD_E_IP),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd instance E node id", SXPD_E,
                                  UINT32_SETTING_NODE_ID, 0xE),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd E port", SXPD_E,
                                  UINT32_SETTING_PORT, PORT),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd instance E enabled", SXPD_E,
                                  UINT32_SETTING_ENABLED, 1),

    TOPO_TASK_BINDING_CFG_ADD_INIT("add V4 host binding to sxpd A", SXPD_E,
                                   BINDING1_IPV4_IP, BINDING1_IPV4_LEN,
                                   PREFIX_IPV4, BINDING1_IPV4_SGT2),
    TOPO_TASK_BINDING_CFG_ADD_INIT("add V4 subnet binding to sxpd A", SXPD_E,
                                   BINDING2_IPV4_IP, BINDING2_IPV4_LEN,
                                   PREFIX_IPV4, BINDING2_IPV4_SGT2),
    TOPO_TASK_BINDING_CFG_ADD_INIT("add V6 host binding to sxpd A", SXPD_E,
                                   BINDING3_IPV6_IP, BINDING3_IPV6_LEN,
                                   PREFIX_IPV6, BINDING3_IPV6_SGT2),
    TOPO_TASK_BINDING_CFG_ADD_INIT("add V6 subnet binding to sxpd A", SXPD_E,
                                   BINDING4_IPV6_IP, BINDING4_IPV6_LEN,
                                   PREFIX_IPV6, BINDING4_IPV6_SGT2),

    /* configure topology and test bindings conflict management */
    TOPO_TASK_WAIT_FOR_INIT("ready to start test part #1", SXPD_DUMMY,
                            WAIT_TIMEOUT, topo_task_wait_for_sync_cb,
                            &sync_ctx),

    TOPO_TASK_PEER_CFG_ADD_INIT("add peer speaker B to instance C", SXPD_C,
                                JAVA_SXPD_B_IP, PORT, PWD, PEER_SPEAKER),
    TOPO_TASK_PEER_CFG_ADD_INIT("add peer speaker D to instance C", SXPD_C,
                                JAVA_SXPD_D_IP, PORT, PWD, PEER_LISTENER),
    TOPO_TASK_PEER_CFG_ADD_INIT("add peer listener E to instance C", SXPD_C,
                                JAVA_SXPD_E_IP, PORT, PWD, PEER_SPEAKER),

    TOPO_TASK_WAIT_FOR_INIT(
        "synchronization - bindings exported/re-exported/received", SXPD_DUMMY,
        WAIT_TIMEOUT, topo_task_wait_for_sync_cb, &sync_ctx),

    TOPO_TASK_PAUSE_SXPD_INIT("pause sxpd C", SXPD_C),

    TOPO_TASK_WAIT_FOR_INIT("ready to start test part #2", SXPD_DUMMY,
                            WAIT_TIMEOUT, topo_task_wait_for_sync_cb,
                            &sync_ctx),

    TOPO_TASK_PEER_CFG_ADD_INIT("add peer listener B to instance A", SXPD_A,
                                SXPD_B_IP, PORT, PWD, PEER_LISTENER),
    TOPO_TASK_PEER_CFG_ADD_INIT("add peer speaker A to instance B", SXPD_B,
                                SXPD_A_IP, PORT, PWD, PEER_SPEAKER),
    TOPO_TASK_PEER_CFG_ADD_INIT("add peer listener C to instance B", SXPD_B,
                                JAVA_SXPD_C_IP, PORT, PWD, PEER_LISTENER),
    TOPO_TASK_PEER_CFG_ADD_INIT("add peer speaker C to instance D", SXPD_D,
                                JAVA_SXPD_C_IP, PORT, PWD, PEER_SPEAKER),

    TOPO_TASK_MAIN_EXEC_INIT("sleep before connect status check",
                             topo_task_sleep_cb, &sleep_time),

    TOPO_TASK_WAIT_FOR_INIT("wait for A peers connect", SXPD_A, WAIT_TIMEOUT,
                            topo_task_cb_wait_for_peers, &sxpd_a_exp_peer_ctx),
    TOPO_TASK_WAIT_FOR_INIT("wait for B peers connect", SXPD_B, WAIT_TIMEOUT,
                            topo_task_cb_wait_for_peers, &sxpd_b_exp_peer_ctx),
    TOPO_TASK_WAIT_FOR_INIT("wait for D peers connect", SXPD_D, WAIT_TIMEOUT,
                            topo_task_cb_wait_for_peers, &sxpd_d_exp_peer_ctx),

    TOPO_TASK_WAIT_FOR_INIT("wait for binding re-exported from A to D", SXPD_D,
                            WAIT_TIMEOUT, topo_task_cb_wait_for_bindings,
                            &sxpd_exp_bind_ctx),

    TOPO_TASK_PEER_CFG_ADD_INIT("add peer listener C to instance E", SXPD_E,
                                JAVA_SXPD_C_IP, PORT, PWD, PEER_LISTENER),

    TOPO_TASK_WAIT_FOR_INIT(
        "synchronization - bindings exported/re-exported/received from A to D",
        SXPD_DUMMY, WAIT_TIMEOUT, topo_task_wait_for_sync_cb, &sync_ctx),

    TOPO_TASK_MAIN_EXEC_INIT("sleep before connect status check",
                             topo_task_sleep_cb, &sleep_time),

    TOPO_TASK_WAIT_FOR_INIT("wait for E peers connect", SXPD_E, WAIT_TIMEOUT,
                            topo_task_cb_wait_for_peers, &sxpd_e_exp_peer_ctx),

    TOPO_TASK_WAIT_FOR_INIT("wait for binding re-exported from E to D", SXPD_D,
                            WAIT_TIMEOUT, topo_task_cb_wait_for_bindings,
                            &sxpd_exp_bind_ctx2),

    TOPO_TASK_WAIT_FOR_INIT(
        "synchronization - bindings exported/re-exported/received", SXPD_DUMMY,
        WAIT_TIMEOUT, topo_task_wait_for_sync_cb, &sync_ctx),

    /* test cleanup */
    TOPO_TASK_PAUSE_SXPD_INIT("pause sxpd A", SXPD_A),
    TOPO_TASK_PAUSE_SXPD_INIT("pause sxpd B", SXPD_B),
    TOPO_TASK_PAUSE_SXPD_INIT("pause sxpd D", SXPD_D),
    TOPO_TASK_PAUSE_SXPD_INIT("pause sxpd E", SXPD_E),

    TOPO_TASK_WAIT_FOR_INIT("synchronization - cleanup", SXPD_DUMMY,
                            WAIT_TIMEOUT, topo_task_wait_for_sync_cb,
                            &sync_ctx),

    TOPO_TASK_MAIN_EXEC_INIT("run log checker", topo_task_log_check_run_cb,
                             NULL),
    TOPO_TASK_STOP_SXPD_INIT("stop sxpd A", SXPD_A),
    TOPO_TASK_STOP_SXPD_INIT("stop sxpd B", SXPD_B),
    TOPO_TASK_STOP_SXPD_INIT("stop sxpd C", SXPD_C),
    TOPO_TASK_STOP_SXPD_INIT("stop sxpd D", SXPD_D),
    TOPO_TASK_STOP_SXPD_INIT("stop sxpd E", SXPD_E),
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
