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

#define WAIT_TIMEOUT 10
#define HOLD_DOWN_TIMER 120
#define SPEAKER_MIN_HOLD_TIME 3
#define LISTENER_MIN_HOLD_TIME 3
#define LISTENER_MAX_HOLD_TIME 4

/* test 6.5.4 - hold timer */

/* sxpd instances */
static struct topo_sxpd topo_sxpd[] = {
    TOPO_SXPD_INIT("simple topology sxpd A", CFG_FILE_PATH_DEFAULT),
    TOPO_SXPD_INIT("simple topology sxpd B", CFG_FILE_PATH_DEFAULT),
};

#define SXPD_A (&topo_sxpd[0])
#define SXPD_B (&topo_sxpd[1])

/* sxpd instances ip addresses */
static const char topo_sxpd_ip[][16] = {
    "127.0.0.1", "127.0.0.2",
};

#define SXPD_A_IP topo_sxpd_ip[0]
#define SXPD_B_IP topo_sxpd_ip[1]

/* expected SXPD A peer lists */
static struct topo_task_peer_chk sxpd_a_exp_peers[] = {
    TOPO_TASK_WAIT_FOR_PEER(SXPD_B_IP, 64000, true, false, true),
};

struct topo_task_peer_chk_ctx sxpd_a_exp_peer_ctx = TOPO_TASK_WAIT_FOR_PEERS(
    sxpd_a_exp_peers, sizeof(sxpd_a_exp_peers) / sizeof(*sxpd_a_exp_peers),
    true);

/* expected SXPD B peer lists */
struct topo_task_peer_chk sxpd_b_exp_peers[] = {
    TOPO_TASK_WAIT_FOR_PEER(SXPD_A_IP, 64000, true, true, false),
    TOPO_TASK_WAIT_FOR_PEER(SXPD_A_IP, 64000, false, true, false),
};

struct topo_task_peer_chk_ctx sxpd_b_exp_peer_ctx[] = {
    TOPO_TASK_WAIT_FOR_PEERS(&sxpd_b_exp_peers[0], 1, true),
    TOPO_TASK_WAIT_FOR_PEERS(&sxpd_b_exp_peers[1], 1, true),
};

/* expected bindings #1 */
struct topo_task_binding_chk sxpd_b_exp_bindings[] = {
    TOPO_TASK_WAIT_FOR_BINDING("192.168.1.0", 24, PREFIX_IPV4, 40),
    TOPO_TASK_WAIT_FOR_BINDING("aaaa:eeee:abcf:eeee:0:0:0:0", 128, PREFIX_IPV6,
                               41),
};

struct topo_task_binding_chk_ctx sxpd_b_exp_bind_ctx[] = {
    TOPO_TASK_WAIT_FOR_BINDINGS(
        sxpd_b_exp_bindings,
        sizeof(sxpd_b_exp_bindings) / sizeof(*sxpd_b_exp_bindings), true),
    TOPO_TASK_WAIT_FOR_BINDINGS(NULL, 0, true),
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

    LOG_PATTERN_STATIC_INIT("unexpected trace logs about binding config del",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "sxpd.c",
                            "sxpd_cfg_del_binding", NULL),
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

int sleep_before_hold_time_check = LISTENER_MIN_HOLD_TIME - 1;
int sleep_before_hold_down_time_check = HOLD_DOWN_TIMER - 1;

int sleep_for_socket_cleanup = 1;

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
    TOPO_TASK_UINT32_CFG_ADD_INIT(
        "configure sxpd instance A speaker min hold time", SXPD_A,
        UINT32_SETTING_SPEAKER_MIN_HOLD_TIME, SPEAKER_MIN_HOLD_TIME),
    TOPO_TASK_UINT32_CFG_ADD_INIT(
        "configure sxpd instance A listener min hold time", SXPD_A,
        UINT32_SETTING_LISTENER_MIN_HOLD_TIME, LISTENER_MIN_HOLD_TIME),
    TOPO_TASK_UINT32_CFG_ADD_INIT(
        "configure sxpd instance A listener max hold time", SXPD_A,
        UINT32_SETTING_LISTENER_MAX_HOLD_TIME, LISTENER_MAX_HOLD_TIME),

    TOPO_TASK_NEW_SXPD_INIT("create sxpd instance B", SXPD_B),
    TOPO_TASK_RUN_SXPD_INIT("run sxpd instance B", SXPD_B),
    TOPO_TASK_UINT32_CFG_STR_ADD_INIT("configure sxpd instance B IP", SXPD_B,
                                      UINT32_SETTING_BIND_ADDRESS, SXPD_B_IP),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd instance B node id", SXPD_B,
                                  UINT32_SETTING_NODE_ID, 0xB),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd instance B enabled", SXPD_B,
                                  UINT32_SETTING_ENABLED, 1),
    TOPO_TASK_UINT32_CFG_ADD_INIT(
        "configure sxpd instance B speaker min hold time", SXPD_B,
        UINT32_SETTING_SPEAKER_MIN_HOLD_TIME, SPEAKER_MIN_HOLD_TIME),
    TOPO_TASK_UINT32_CFG_ADD_INIT(
        "configure sxpd instance B listener min hold time", SXPD_B,
        UINT32_SETTING_LISTENER_MIN_HOLD_TIME, LISTENER_MIN_HOLD_TIME),
    TOPO_TASK_UINT32_CFG_ADD_INIT(
        "configure sxpd instance B listener max hold time", SXPD_B,
        UINT32_SETTING_LISTENER_MAX_HOLD_TIME, LISTENER_MAX_HOLD_TIME),

    TOPO_TASK_PEER_CFG_ADD_INIT("add peer listener B to instance A", SXPD_A,
                                SXPD_B_IP, 64000, NULL, PEER_LISTENER),
    TOPO_TASK_PEER_CFG_ADD_INIT("add peer speaker A to instance B", SXPD_B,
                                SXPD_A_IP, 64000, NULL, PEER_SPEAKER),

    TOPO_TASK_WAIT_FOR_INIT("wait for A peers connect", SXPD_A, WAIT_TIMEOUT,
                            topo_task_cb_wait_for_peers, &sxpd_a_exp_peer_ctx),
    TOPO_TASK_WAIT_FOR_INIT("wait for B peers connect", SXPD_B, WAIT_TIMEOUT,
                            topo_task_cb_wait_for_peers,
                            &sxpd_b_exp_peer_ctx[0]),

    TOPO_TASK_BINDING_CFG_ADD_INIT("add V4 binding to sxpd A", SXPD_A,
                                   "192.168.1.0", 24, PREFIX_IPV4, 40),
    TOPO_TASK_BINDING_CFG_ADD_INIT("add V6 binding to sxpd A", SXPD_A,
                                   "aaaa:eeee:abcf:eeee:0:0:0:0", 128,
                                   PREFIX_IPV6, 41),

    TOPO_TASK_WAIT_FOR_INIT("wait for binding exported from A to B", SXPD_B,
                            WAIT_TIMEOUT, topo_task_cb_wait_for_bindings,
                            &sxpd_b_exp_bind_ctx[0]),

    TOPO_TASK_PAUSE_SXPD_INIT("pause execution of sxpd A", SXPD_A),

    TOPO_TASK_MAIN_EXEC_INIT("sleep", topo_task_sleep_cb,
                             &sleep_before_hold_time_check),
    TOPO_TASK_WAIT_FOR_INIT("check if B peers still here", SXPD_B, 0,
                            topo_task_cb_wait_for_peers,
                            &sxpd_b_exp_peer_ctx[0]),
    TOPO_TASK_WAIT_FOR_INIT(
        "wait for B hold timer expires and tears down connection to A", SXPD_B,
        3, topo_task_cb_wait_for_peers, &sxpd_b_exp_peer_ctx[1]),

    TOPO_TASK_MAIN_EXEC_INIT("sleep", topo_task_sleep_cb,
                             &sleep_before_hold_down_time_check),
    TOPO_TASK_WAIT_FOR_INIT("check if B bindings still here", SXPD_B, 0,
                            topo_task_cb_wait_for_bindings,
                            &sxpd_b_exp_bind_ctx[0]),
    TOPO_TASK_WAIT_FOR_INIT(
        "wait for B hold-down timer expires and removes A bindinsgs", SXPD_B, 3,
        topo_task_cb_wait_for_bindings, &sxpd_b_exp_bind_ctx[1]),

    TOPO_TASK_PEER_CFG_DEL_INIT("del peer speaker A from instance B", SXPD_B,
                                SXPD_A_IP, 64000, NULL, PEER_SPEAKER),

    TOPO_TASK_MAIN_EXEC_INIT("sleep for socket cleanup", topo_task_sleep_cb,
                             &sleep_for_socket_cleanup),

    TOPO_TASK_STOP_SXPD_INIT("stop sxpd A", SXPD_A),
    TOPO_TASK_STOP_SXPD_INIT("stop sxpd B", SXPD_B),

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
