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

/* loop detection code coverage test */

/* sxpd instances */
static struct topo_sxpd topo_sxpd[] = {
    TOPO_SXPDVX_INIT("simple topology sxpd A", CFG_FILE_PATH_DEFAULT, 4),
    TOPO_SXPDVX_INIT("simple topology sxpd B", CFG_FILE_PATH_DEFAULT, 4),
    TOPO_SXPDVX_INIT("simple topology sxpd C", CFG_FILE_PATH_DEFAULT, 4),
};

#define SXPD_A (&topo_sxpd[0])
#define SXPD_B (&topo_sxpd[1])
#define SXPD_C (&topo_sxpd[2])

/* sxpd instances ip addresses */
static const char topo_sxpd_ip[][16] = {
    "127.0.0.1", "127.0.0.2", "127.0.0.3",
};

#define SXPD_A_IP topo_sxpd_ip[0]
#define SXPD_B_IP topo_sxpd_ip[1]
#define SXPD_C_IP topo_sxpd_ip[2]

/* expected peer SXPD A lists */
static struct topo_task_peer_chk sxpd_a_exp_peers[] = {
    TOPO_TASK_WAIT_FOR_PEER(SXPD_B_IP, 64000, true, true, true),
    TOPO_TASK_WAIT_FOR_PEER(SXPD_C_IP, 64000, true, true, true),
};

struct topo_task_peer_chk_ctx sxpd_a_exp_peer_ctx =
    TOPO_TASK_WAIT_FOR_PEERS(sxpd_a_exp_peers, 2, true);

/* expected peer SXPD B lists */
static struct topo_task_peer_chk sxpd_b_exp_peers[] = {
    TOPO_TASK_WAIT_FOR_PEER(SXPD_A_IP, 64000, true, true, true),
    TOPO_TASK_WAIT_FOR_PEER(SXPD_C_IP, 64000, true, true, true),
};

struct topo_task_peer_chk_ctx sxpd_b_exp_peer_ctx =
    TOPO_TASK_WAIT_FOR_PEERS(sxpd_b_exp_peers, 2, true);

/* expected peer SXPD C lists */
static struct topo_task_peer_chk sxpd_c_exp_peers[] = {
    TOPO_TASK_WAIT_FOR_PEER(SXPD_A_IP, 64000, true, true, true),
    TOPO_TASK_WAIT_FOR_PEER(SXPD_B_IP, 64000, true, true, true),
};

struct topo_task_peer_chk_ctx sxpd_c_exp_peer_ctx =
    TOPO_TASK_WAIT_FOR_PEERS(sxpd_c_exp_peers, 2, true);

/* expected bindings */
struct topo_task_binding_chk sxpd_exp_bindings[] = {
    TOPO_TASK_WAIT_FOR_BINDING("192.168.1.0", 32, PREFIX_IPV4, 40),
    TOPO_TASK_WAIT_FOR_BINDING("aaaa:eeee:abcf:aaaa:0:0:0:0", 128, PREFIX_IPV6,
                               41),
};

struct topo_task_binding_chk_ctx sxpd_exp_bind_ctx[] = {
    TOPO_TASK_WAIT_FOR_BINDINGS(
        sxpd_exp_bindings,
        sizeof(sxpd_exp_bindings) / sizeof(*sxpd_exp_bindings), false),
    TOPO_TASK_WAIT_FOR_BINDINGS(NULL, 0, false),
};

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
        "optional error logs about connection reset by peer", LOG_OPTIONAL,
        LOG_LEVEL_ERROR, "evmgr.c", "evmgr_write_wrapper",
        "^(.*)(\\bfailed, rc=104:Connection reset by peer\\b)(.*?)$"),
    LOG_PATTERN_STATIC_INIT(
        "optional error logs about peer config does not exist yet",
        LOG_OPTIONAL, LOG_LEVEL_ERROR, "sxpd.c",
        "sxpd_evmgr_global_accept_callback", "^(.*)(\\bUnknown peer\\b)(.*?)$"),
    LOG_PATTERN_STATIC_INIT(
        "optional error logs", LOG_OPTIONAL, LOG_LEVEL_ERROR, "evmgr.c",
        "evmgr_listener_md5_sig_del", "^(.*)(\\bCannot remove TCP-MD5-SIGN "
                                      "option for listener socket\\b)(.*?)$"),

    LOG_PATTERN_STATIC_INIT("unexpected trace logs about uint32 config del",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "sxpd.c",
                            "sxpd_cfg_del_uint32_setting", NULL),
    LOG_PATTERN_STATIC_INIT("unexpected trace logs about str config del",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "sxpd.c",
                            "sxpd_cfg_del_str_setting", NULL),
    LOG_PATTERN_STATIC_INIT("unexpected any other error logs", LOG_UNEXPECTED,
                            LOG_LEVEL_ERROR, NULL, NULL, NULL),
};

static struct topo_task_log_check_set_patterns_ctx log_patterns_ctx =
    TOPO_TASK_LOG_CHECK_SET_PATTERNS(log_pattern, sizeof(log_pattern) /
                                                      sizeof(*log_pattern));

static struct topo_task topo_task[] = {
    TOPO_TASK_MAIN_EXEC_INIT("set log check patterns",
                             topo_task_log_check_set_patterns_cb,
                             &log_patterns_ctx),

    TOPO_TASK_NEW_SXPD_INIT("create sxpd instance A", SXPD_A),
    TOPO_TASK_RUN_SXPD_INIT("run sxpd instance A", SXPD_A),
    TOPO_TASK_UINT32_CFG_STR_ADD_INIT("configure sxpd instance A IP", SXPD_A,
                                      UINT32_SETTING_BIND_ADDRESS, SXPD_A_IP),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd instance A node id", SXPD_A,
                                  UINT32_SETTING_NODE_ID, 0xA),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd instance A enabled", SXPD_A,
                                  UINT32_SETTING_ENABLED, 1),

    TOPO_TASK_NEW_SXPD_INIT("create sxpd instance B", SXPD_B),
    TOPO_TASK_RUN_SXPD_INIT("run sxpd instance B", SXPD_B),
    TOPO_TASK_UINT32_CFG_STR_ADD_INIT("configure sxpd instance B IP", SXPD_B,
                                      UINT32_SETTING_BIND_ADDRESS, SXPD_B_IP),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd instance B node id", SXPD_B,
                                  UINT32_SETTING_NODE_ID, 0xB),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd instance B enabled", SXPD_B,
                                  UINT32_SETTING_ENABLED, 1),

    TOPO_TASK_NEW_SXPD_INIT("create sxpd instance C", SXPD_C),
    TOPO_TASK_RUN_SXPD_INIT("run sxpd instance C", SXPD_C),
    TOPO_TASK_UINT32_CFG_STR_ADD_INIT("configure sxpd instance C IP", SXPD_C,
                                      UINT32_SETTING_BIND_ADDRESS, SXPD_C_IP),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd instance C node id", SXPD_C,
                                  UINT32_SETTING_NODE_ID, 0xC),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd instance C enabled", SXPD_C,
                                  UINT32_SETTING_ENABLED, 1),

    TOPO_TASK_PEER_CFG_ADD_INIT("add peer B to instance A", SXPD_A, SXPD_B_IP,
                                64000, "passwordAB", PEER_BOTH),
    TOPO_TASK_PEER_CFG_ADD_INIT("add peer A to instance B", SXPD_B, SXPD_A_IP,
                                64000, "passwordAB", PEER_BOTH),
    TOPO_TASK_PEER_CFG_ADD_INIT("add peer C to instance A", SXPD_A, SXPD_C_IP,
                                64000, "passwordAC", PEER_BOTH),
    TOPO_TASK_PEER_CFG_ADD_INIT("add peer A to instance C", SXPD_C, SXPD_A_IP,
                                64000, "passwordAC", PEER_BOTH),
    TOPO_TASK_PEER_CFG_ADD_INIT("add peer C to instance B", SXPD_B, SXPD_C_IP,
                                64000, "passwordBC", PEER_BOTH),
    TOPO_TASK_PEER_CFG_ADD_INIT("add peer B to instance C", SXPD_C, SXPD_B_IP,
                                64000, "passwordBC", PEER_BOTH),

    TOPO_TASK_WAIT_FOR_INIT("wait for sxpd A peers connect", SXPD_A,
                            WAIT_TIMEOUT, topo_task_cb_wait_for_peers,
                            &sxpd_a_exp_peer_ctx),
    TOPO_TASK_WAIT_FOR_INIT("wait for sxpd B peers connect", SXPD_B,
                            WAIT_TIMEOUT, topo_task_cb_wait_for_peers,
                            &sxpd_b_exp_peer_ctx),
    TOPO_TASK_WAIT_FOR_INIT("wait for sxpd C peers connect", SXPD_C,
                            WAIT_TIMEOUT, topo_task_cb_wait_for_peers,
                            &sxpd_c_exp_peer_ctx),

    TOPO_TASK_BINDING_CFG_ADD_INIT("add V4 binding to sxpd A", SXPD_A,
                                   "192.168.1.0", 32, PREFIX_IPV4, 40),
    TOPO_TASK_BINDING_CFG_ADD_INIT("add V6 binding to sxpd A", SXPD_A,
                                   "aaaa:eeee:abcf:aaaa:0:0:0:0", 128,
                                   PREFIX_IPV6, 41),

    TOPO_TASK_WAIT_FOR_INIT("wait for binding exchange", SXPD_B, WAIT_TIMEOUT,
                            topo_task_cb_wait_for_bindings,
                            &sxpd_exp_bind_ctx[0]),

    TOPO_TASK_BINDING_CFG_DEL_INIT("del V4 binding to sxpd A", SXPD_A,
                                   "192.168.1.0", 32, PREFIX_IPV4, 40),
    TOPO_TASK_BINDING_CFG_DEL_INIT("del V6 binding to sxpd A", SXPD_A,
                                   "aaaa:eeee:abcf:aaaa:0:0:0:0", 128,
                                   PREFIX_IPV6, 42),

    TOPO_TASK_WAIT_FOR_INIT("wait for binding del exchange", SXPD_B,
                            WAIT_TIMEOUT, topo_task_cb_wait_for_bindings,
                            &sxpd_exp_bind_ctx[1]),

    TOPO_TASK_PEER_CFG_DEL_INIT("del peer B to instance A", SXPD_A, SXPD_B_IP,
                                64000, "passwordAB", PEER_BOTH),
    TOPO_TASK_PEER_CFG_DEL_INIT("del peer A to instance B", SXPD_B, SXPD_A_IP,
                                64000, "passwordAB", PEER_BOTH),
    TOPO_TASK_PEER_CFG_DEL_INIT("del peer C to instance A", SXPD_A, SXPD_C_IP,
                                64000, "passwordAC", PEER_BOTH),
    TOPO_TASK_PEER_CFG_DEL_INIT("del peer A to instance C", SXPD_C, SXPD_A_IP,
                                64000, "passwordAC", PEER_BOTH),
    TOPO_TASK_PEER_CFG_DEL_INIT("del peer C to instance B", SXPD_B, SXPD_C_IP,
                                64000, "passwordBC", PEER_BOTH),
    TOPO_TASK_PEER_CFG_DEL_INIT("del peer B to instance C", SXPD_C, SXPD_B_IP,
                                64000, "passwordBC", PEER_BOTH),

    TOPO_TASK_STOP_SXPD_INIT("stop sxpd instance A", SXPD_A),
    TOPO_TASK_STOP_SXPD_INIT("stop sxpd instance B", SXPD_B),
    TOPO_TASK_STOP_SXPD_INIT("stop sxpd instance C", SXPD_C),

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
