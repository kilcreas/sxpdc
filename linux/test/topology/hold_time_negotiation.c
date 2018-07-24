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

/* hold time negotiation test */

#define WAIT_TIMEOUT 1
#define WAIT_TIMEOUT3 3
#define PWD NULL
#define PORT 64000

/* sxpd instances */
static struct topo_sxpd topo_sxpd[] = {
    TOPO_SXPD_INIT("simple topology sxpd A", CFG_FILE_PATH_DEFAULT),
    TOPO_SXPD_INIT("simple topology sxpd B", CFG_FILE_PATH_DEFAULT),
};

#define SXPD_A (&topo_sxpd[0])
#define SXPD_B (&topo_sxpd[1])

/* sxpd instances ip addresses */
static const char topo_sxpd_ip[][16] = { "127.0.0.1", "127.0.0.2" };

#define SXPD_A_IP topo_sxpd_ip[0]
#define SXPD_B_IP topo_sxpd_ip[1]

/* expected peer SXPD A lists */
static struct topo_task_peer_chk sxpd_a_exp_peers[] = {
    TOPO_TASK_WAIT_FOR_PEER(SXPD_B_IP, PORT, true, true, false),
    TOPO_TASK_WAIT_FOR_PEER(SXPD_B_IP, PORT, true, true, true),
    TOPO_TASK_WAIT_FOR_PEER(SXPD_B_IP, PORT, false, true, false),
    TOPO_TASK_WAIT_FOR_PEER(SXPD_B_IP, PORT, false, true, true),
};

struct topo_task_peer_chk_ctx sxpd_a_exp_peer_ctx[] = {
    TOPO_TASK_WAIT_FOR_PEERS(&sxpd_a_exp_peers[0], 1, true),
    TOPO_TASK_WAIT_FOR_PEERS(&sxpd_a_exp_peers[1], 1, true),
    TOPO_TASK_WAIT_FOR_PEERS(&sxpd_a_exp_peers[2], 1, true),
    TOPO_TASK_WAIT_FOR_PEERS(&sxpd_a_exp_peers[3], 1, true),
};

#define B_SPEAKER_CONNECTED &sxpd_a_exp_peer_ctx[0]
#define B_BOTH_CONNECTED &sxpd_a_exp_peer_ctx[1]
#define B_SPEAKER_DISCONNECTED &sxpd_a_exp_peer_ctx[2]
#define B_BOTH_DISCONNECTED &sxpd_a_exp_peer_ctx[3]

/* expected peer SXPD B lists */
struct topo_task_peer_chk sxpd_b_exp_peers[] = {
    TOPO_TASK_WAIT_FOR_PEER(SXPD_A_IP, PORT, true, false, true),
    TOPO_TASK_WAIT_FOR_PEER(SXPD_A_IP, PORT, true, true, true),
    TOPO_TASK_WAIT_FOR_PEER(SXPD_A_IP, PORT, false, false, true),
    TOPO_TASK_WAIT_FOR_PEER(SXPD_A_IP, PORT, false, true, true),
};

struct topo_task_peer_chk_ctx sxpd_b_exp_peer_ctx[] = {
    TOPO_TASK_WAIT_FOR_PEERS(&sxpd_b_exp_peers[0], 1, true),
    TOPO_TASK_WAIT_FOR_PEERS(&sxpd_b_exp_peers[1], 1, true),
    TOPO_TASK_WAIT_FOR_PEERS(&sxpd_b_exp_peers[2], 1, true),
    TOPO_TASK_WAIT_FOR_PEERS(&sxpd_b_exp_peers[3], 1, true),
};

#define A_LISTENER_CONNECTED &sxpd_b_exp_peer_ctx[0]
#define A_BOTH_CONNECTED &sxpd_b_exp_peer_ctx[1]
#define A_LISTENER_DISCONNECTED &sxpd_b_exp_peer_ctx[2]
#define A_BOTH_DISCONNECTED &sxpd_b_exp_peer_ctx[3]

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
        "optional error logs about peer config does not exist yet",
        LOG_OPTIONAL, LOG_LEVEL_ERROR, "sxpd.c",
        "sxpd_evmgr_global_accept_callback", "^(.*)(\\bUnknown peer\\b)(.*?)$"),
    LOG_PATTERN_STATIC_INIT("optional error logs", LOG_OPTIONAL,
                            LOG_LEVEL_ERROR, "evmgr.c",
                            "evmgr_listener_md5_sig_del", NULL),
    LOG_PATTERN_STATIC_INIT("optional error logs", LOG_OPTIONAL,
                            LOG_LEVEL_ERROR, "evmgr.c",
                            "evmgr_socket_md5_sig_set", NULL),

    LOG_PATTERN_STATIC_INIT("unexpected trace logs about uint32 config del",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "sxpd.c",
                            "sxpd_cfg_del_uint32_setting", NULL),
    LOG_PATTERN_STATIC_INIT("unexpected trace logs about str config del",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "sxpd.c",
                            "sxpd_cfg_del_str_setting", NULL),
    LOG_PATTERN_STATIC_INIT("unexpected trace logs about binding add",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "sxpd.c",
                            "sxpd_cfg_add_binding", NULL),
    LOG_PATTERN_STATIC_INIT("unexpected trace logs about binding config del",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "sxpd.c",
                            "sxpd_cfg_del_binding", NULL),

    LOG_PATTERN_STATIC_INIT("unexpected any other error logs", LOG_UNEXPECTED,
                            LOG_LEVEL_ERROR, NULL, NULL, NULL),
};

/* log checker rules */
static struct log_pattern log_pattern2[] = {
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
        "optional error logs about peer config does not exist yet",
        LOG_OPTIONAL, LOG_LEVEL_ERROR, "sxpd.c",
        "sxpd_evmgr_global_accept_callback", "^(.*)(\\bUnknown peer\\b)(.*?)$"),
    LOG_PATTERN_STATIC_INIT("optional error logs", LOG_OPTIONAL,
                            LOG_LEVEL_ERROR, "evmgr.c",
                            "evmgr_listener_md5_sig_del", NULL),
    LOG_PATTERN_STATIC_INIT("optional error logs", LOG_OPTIONAL,
                            LOG_LEVEL_ERROR, "evmgr.c",
                            "evmgr_socket_md5_sig_set", NULL),
    LOG_PATTERN_STATIC_INIT("unacceptable hold time error reply", LOG_OPTIONAL,
                            LOG_LEVEL_ERROR, "sxpd.c", "sxpd_process_error_msg",
                            "^(.*)(\\bUNACCEPTABLE-HOLD-TIME\\b)(.*?)$"),
    LOG_PATTERN_STATIC_INIT("incompatible hold time value", LOG_OPTIONAL,
                            LOG_LEVEL_ERROR, "sxpd.c",
                            "sxpd_process_open_hold_time_attr", NULL),

    LOG_PATTERN_STATIC_INIT("unexpected trace logs about uint32 config del",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "sxpd.c",
                            "sxpd_cfg_del_uint32_setting", NULL),
    LOG_PATTERN_STATIC_INIT("unexpected trace logs about str config del",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "sxpd.c",
                            "sxpd_cfg_del_str_setting", NULL),
    LOG_PATTERN_STATIC_INIT("unexpected trace logs about binding add",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "sxpd.c",
                            "sxpd_cfg_add_binding", NULL),
    LOG_PATTERN_STATIC_INIT("unexpected trace logs about binding config del",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "sxpd.c",
                            "sxpd_cfg_del_binding", NULL),

    LOG_PATTERN_STATIC_INIT("unexpected any other error logs", LOG_UNEXPECTED,
                            LOG_LEVEL_ERROR, NULL, NULL, NULL),
};

static struct topo_task_log_check_set_patterns_ctx log_patterns_ctx =
    TOPO_TASK_LOG_CHECK_SET_PATTERNS(log_pattern, sizeof(log_pattern) /
                                                      sizeof(*log_pattern));

static struct topo_task_log_check_set_patterns_ctx log_patterns_ctx2 =
    TOPO_TASK_LOG_CHECK_SET_PATTERNS(log_pattern2, sizeof(log_pattern2) /
                                                       sizeof(*log_pattern2));

int sleep_time = WAIT_TIMEOUT;
int sleep_time3 = WAIT_TIMEOUT3;

static struct topo_task topo_task[] = {
    TOPO_TASK_MAIN_EXEC_INIT("set log check patterns",
                             topo_task_log_check_set_patterns_cb,
                             &log_patterns_ctx),

    TOPO_TASK_NEW_SXPD_INIT("create sxpd instance A", SXPD_A),
    TOPO_TASK_RUN_SXPD_INIT("run sxpd instance A", SXPD_A),
    TOPO_TASK_UINT32_CFG_STR_ADD_INIT("configure sxpd instance A IP", SXPD_A,
                                      UINT32_SETTING_BIND_ADDRESS, SXPD_A_IP),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd instance A node id 0xA",
                                  SXPD_A, UINT32_SETTING_NODE_ID, 0xA),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd instance A retry timer",
                                  SXPD_A, UINT32_SETTING_RETRY_TIMER, 120),
    TOPO_TASK_UINT32_CFG_ADD_INIT(
        "configure sxpd instance A reconciliation timer", SXPD_A,
        UINT32_SETTING_RECONCILIATION_TIMER, 80),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd instance A enabled", SXPD_A,
                                  UINT32_SETTING_ENABLED, 1),

    TOPO_TASK_NEW_SXPD_INIT("create sxpd instance B", SXPD_B),
    TOPO_TASK_RUN_SXPD_INIT("run sxpd instance B", SXPD_B),
    TOPO_TASK_UINT32_CFG_STR_ADD_INIT("configure sxpd instance B IP", SXPD_B,
                                      UINT32_SETTING_BIND_ADDRESS, SXPD_B_IP),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd instance B node id 0xB",
                                  SXPD_B, UINT32_SETTING_NODE_ID, 0xB),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd instance A retry timer",
                                  SXPD_B, UINT32_SETTING_RETRY_TIMER, 120),
    TOPO_TASK_UINT32_CFG_ADD_INIT(
        "configure sxpd instance A reconciliation timer", SXPD_B,
        UINT32_SETTING_RECONCILIATION_TIMER, 80),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd instance B enabled", SXPD_B,
                                  UINT32_SETTING_ENABLED, 1),

    /* configure listener-speaker topology with speaker hold-time in listener
     * hold-time range */
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd A listener minimum hold time",
                                  SXPD_A, UINT32_SETTING_LISTENER_MIN_HOLD_TIME,
                                  80),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd A listener maximum hold time",
                                  SXPD_A, UINT32_SETTING_LISTENER_MAX_HOLD_TIME,
                                  120),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd B speaker minimum hold time",
                                  SXPD_B, UINT32_SETTING_SPEAKER_MIN_HOLD_TIME,
                                  90),

    /* connection is initialized by instance A */
    TOPO_TASK_PEER_CFG_ADD_INIT("add peer listener A to instance B", SXPD_B,
                                SXPD_A_IP, PORT, PWD, PEER_LISTENER),
    TOPO_TASK_MAIN_EXEC_INIT("sleep before open msg send", topo_task_sleep_cb,
                             &sleep_time),
    TOPO_TASK_PEER_CFG_ADD_INIT("add peer speaker B to instance A", SXPD_A,
                                SXPD_B_IP, PORT, PWD, PEER_SPEAKER),

    TOPO_TASK_MAIN_EXEC_INIT("sleep before connect status check",
                             topo_task_sleep_cb, &sleep_time),
    TOPO_TASK_WAIT_FOR_INIT("wait for A B sxpd connect", SXPD_A, WAIT_TIMEOUT,
                            topo_task_cb_wait_for_peers, B_SPEAKER_CONNECTED),
    TOPO_TASK_WAIT_FOR_INIT("wait for B A sxpd connect", SXPD_B, WAIT_TIMEOUT,
                            topo_task_cb_wait_for_peers, A_LISTENER_CONNECTED),
    TOPO_TASK_PEER_CFG_DEL_INIT("del peer listener A from instance B", SXPD_B,
                                SXPD_A_IP, PORT, PWD, PEER_LISTENER),
    TOPO_TASK_PEER_CFG_DEL_INIT("del peer speaker B from instance A", SXPD_A,
                                SXPD_B_IP, PORT, PWD, PEER_SPEAKER),

    /* connection is initialized by instance B */
    TOPO_TASK_PEER_CFG_ADD_INIT("add peer speaker B to instance A", SXPD_A,
                                SXPD_B_IP, PORT, PWD, PEER_SPEAKER),
    TOPO_TASK_MAIN_EXEC_INIT("sleep before open msg send", topo_task_sleep_cb,
                             &sleep_time),
    TOPO_TASK_PEER_CFG_ADD_INIT("add peer listener A to instance B", SXPD_B,
                                SXPD_A_IP, PORT, PWD, PEER_LISTENER),

    TOPO_TASK_MAIN_EXEC_INIT("sleep before connect status check",
                             topo_task_sleep_cb, &sleep_time),
    TOPO_TASK_WAIT_FOR_INIT("wait for A B sxpd connect", SXPD_A, WAIT_TIMEOUT,
                            topo_task_cb_wait_for_peers, B_SPEAKER_CONNECTED),
    TOPO_TASK_WAIT_FOR_INIT("wait for B A sxpd connect", SXPD_B, WAIT_TIMEOUT,
                            topo_task_cb_wait_for_peers, A_LISTENER_CONNECTED),
    TOPO_TASK_PEER_CFG_DEL_INIT("del peer listener A from instance B", SXPD_B,
                                SXPD_A_IP, PORT, PWD, PEER_LISTENER),
    TOPO_TASK_PEER_CFG_DEL_INIT("del peer speaker B from instance A", SXPD_A,
                                SXPD_B_IP, PORT, PWD, PEER_SPEAKER),

    TOPO_TASK_MAIN_EXEC_INIT("run log checker", topo_task_log_check_run_cb,
                             NULL),

    /* reconfigure listener-speaker topology with speaker hold-time lower than
     * listener hold-time range */
    TOPO_TASK_MAIN_EXEC_INIT("set log check patterns",
                             topo_task_log_check_set_patterns_cb,
                             &log_patterns_ctx),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd A listener minimum hold time",
                                  SXPD_A, UINT32_SETTING_LISTENER_MIN_HOLD_TIME,
                                  80),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd A listener maximum hold time",
                                  SXPD_A, UINT32_SETTING_LISTENER_MAX_HOLD_TIME,
                                  120),
    TOPO_TASK_UINT32_CFG_ADD_INIT(
        "reconfigure sxpd B speaker minimum hold time", SXPD_B,
        UINT32_SETTING_SPEAKER_MIN_HOLD_TIME, 70),

    /* connection is initialized by instance A */
    TOPO_TASK_PEER_CFG_ADD_INIT("add peer listener A to instance B", SXPD_B,
                                SXPD_A_IP, PORT, PWD, PEER_LISTENER),
    TOPO_TASK_MAIN_EXEC_INIT("sleep before open msg send", topo_task_sleep_cb,
                             &sleep_time),
    TOPO_TASK_PEER_CFG_ADD_INIT("add peer speaker B to instance A", SXPD_A,
                                SXPD_B_IP, PORT, PWD, PEER_SPEAKER),

    TOPO_TASK_MAIN_EXEC_INIT("sleep before connect status check",
                             topo_task_sleep_cb, &sleep_time),
    TOPO_TASK_WAIT_FOR_INIT("wait for A B sxpd connect", SXPD_A, WAIT_TIMEOUT,
                            topo_task_cb_wait_for_peers, B_SPEAKER_CONNECTED),
    TOPO_TASK_WAIT_FOR_INIT("wait for B A sxpd connect", SXPD_B, WAIT_TIMEOUT,
                            topo_task_cb_wait_for_peers, A_LISTENER_CONNECTED),
    TOPO_TASK_PEER_CFG_DEL_INIT("del peer listener A from instance B", SXPD_B,
                                SXPD_A_IP, PORT, PWD, PEER_LISTENER),
    TOPO_TASK_PEER_CFG_DEL_INIT("del peer speaker B from instance A", SXPD_A,
                                SXPD_B_IP, PORT, PWD, PEER_SPEAKER),

    /* connection is initialized by instance B */
    TOPO_TASK_PEER_CFG_ADD_INIT("add peer speaker B to instance A", SXPD_A,
                                SXPD_B_IP, PORT, PWD, PEER_SPEAKER),
    TOPO_TASK_MAIN_EXEC_INIT("sleep before open msg send", topo_task_sleep_cb,
                             &sleep_time),
    TOPO_TASK_PEER_CFG_ADD_INIT("add peer listener A to instance B", SXPD_B,
                                SXPD_A_IP, PORT, PWD, PEER_LISTENER),

    TOPO_TASK_MAIN_EXEC_INIT("sleep before connect status check",
                             topo_task_sleep_cb, &sleep_time),
    TOPO_TASK_WAIT_FOR_INIT("wait for A B sxpd connect", SXPD_A, WAIT_TIMEOUT,
                            topo_task_cb_wait_for_peers, B_SPEAKER_CONNECTED),
    TOPO_TASK_WAIT_FOR_INIT("wait for B A sxpd connect", SXPD_B, WAIT_TIMEOUT,
                            topo_task_cb_wait_for_peers, A_LISTENER_CONNECTED),
    TOPO_TASK_PEER_CFG_DEL_INIT("del peer listener A from instance B", SXPD_B,
                                SXPD_A_IP, PORT, PWD, PEER_LISTENER),
    TOPO_TASK_PEER_CFG_DEL_INIT("del peer speaker B from instance A", SXPD_A,
                                SXPD_B_IP, PORT, PWD, PEER_SPEAKER),

    TOPO_TASK_MAIN_EXEC_INIT("run log checker", topo_task_log_check_run_cb,
                             NULL),

    /* reconfigure listener-speaker topology with incompatible speaker hold-time
     * greater than listener hold-time range */
    TOPO_TASK_MAIN_EXEC_INIT("set log check patterns",
                             topo_task_log_check_set_patterns_cb,
                             &log_patterns_ctx2),

    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd A listener minimum hold time",
                                  SXPD_A, UINT32_SETTING_LISTENER_MIN_HOLD_TIME,
                                  80),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd A listener maximum hold time",
                                  SXPD_A, UINT32_SETTING_LISTENER_MAX_HOLD_TIME,
                                  120),
    TOPO_TASK_UINT32_CFG_ADD_INIT(
        "reconfigure sxpd B speaker minimum hold time", SXPD_B,
        UINT32_SETTING_SPEAKER_MIN_HOLD_TIME, 130),

    /* connection is initialized by instance A */
    TOPO_TASK_PEER_CFG_ADD_INIT("add peer listener A to instance B", SXPD_B,
                                SXPD_A_IP, PORT, PWD, PEER_LISTENER),
    TOPO_TASK_MAIN_EXEC_INIT("sleep before open msg send", topo_task_sleep_cb,
                             &sleep_time),
    TOPO_TASK_PEER_CFG_ADD_INIT("add peer speaker B to instance A", SXPD_A,
                                SXPD_B_IP, PORT, PWD, PEER_SPEAKER),

    TOPO_TASK_MAIN_EXEC_INIT("sleep before connect status check",
                             topo_task_sleep_cb, &sleep_time),
    TOPO_TASK_WAIT_FOR_INIT("wait for A B sxpd connect", SXPD_A, WAIT_TIMEOUT,
                            topo_task_cb_wait_for_peers,
                            B_SPEAKER_DISCONNECTED),
    TOPO_TASK_WAIT_FOR_INIT("wait for B A sxpd connect", SXPD_B, WAIT_TIMEOUT,
                            topo_task_cb_wait_for_peers,
                            A_LISTENER_DISCONNECTED),
    TOPO_TASK_PEER_CFG_DEL_INIT("del peer listener A from instance B", SXPD_B,
                                SXPD_A_IP, PORT, PWD, PEER_LISTENER),
    TOPO_TASK_PEER_CFG_DEL_INIT("del peer speaker B from instance A", SXPD_A,
                                SXPD_B_IP, PORT, PWD, PEER_SPEAKER),

    /* connection is initialized by instance B */
    TOPO_TASK_PEER_CFG_ADD_INIT("add peer speaker B to instance A", SXPD_A,
                                SXPD_B_IP, PORT, PWD, PEER_SPEAKER),
    TOPO_TASK_MAIN_EXEC_INIT("sleep before open msg send", topo_task_sleep_cb,
                             &sleep_time),
    TOPO_TASK_PEER_CFG_ADD_INIT("add peer listener A to instance B", SXPD_B,
                                SXPD_A_IP, PORT, PWD, PEER_LISTENER),

    TOPO_TASK_MAIN_EXEC_INIT("sleep before connect status check",
                             topo_task_sleep_cb, &sleep_time),
    TOPO_TASK_WAIT_FOR_INIT("wait for A B sxpd connect", SXPD_A, WAIT_TIMEOUT,
                            topo_task_cb_wait_for_peers,
                            B_SPEAKER_DISCONNECTED),
    TOPO_TASK_WAIT_FOR_INIT("wait for B A sxpd connect", SXPD_B, WAIT_TIMEOUT,
                            topo_task_cb_wait_for_peers,
                            A_LISTENER_DISCONNECTED),
    TOPO_TASK_PEER_CFG_DEL_INIT("del peer listener A from instance B", SXPD_B,
                                SXPD_A_IP, PORT, PWD, PEER_LISTENER),
    TOPO_TASK_PEER_CFG_DEL_INIT("del peer speaker B from instance A", SXPD_A,
                                SXPD_B_IP, PORT, PWD, PEER_SPEAKER),

    TOPO_TASK_MAIN_EXEC_INIT("run log checker", topo_task_log_check_run_cb,
                             NULL),

    /* reconfigure listener-speaker topology with listener hold-time unused */
    TOPO_TASK_MAIN_EXEC_INIT("set log check patterns",
                             topo_task_log_check_set_patterns_cb,
                             &log_patterns_ctx),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd A listener minimum hold time",
                                  SXPD_A, UINT32_SETTING_LISTENER_MIN_HOLD_TIME,
                                  0xffff),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd A listener maximum hold time",
                                  SXPD_A, UINT32_SETTING_LISTENER_MAX_HOLD_TIME,
                                  0xffff),
    TOPO_TASK_UINT32_CFG_ADD_INIT(
        "reconfigure sxpd B speaker minimum hold time", SXPD_B,
        UINT32_SETTING_SPEAKER_MIN_HOLD_TIME, 70),

    /* connection is initialized by instance A */
    TOPO_TASK_PEER_CFG_ADD_INIT("add peer listener A to instance B", SXPD_B,
                                SXPD_A_IP, PORT, PWD, PEER_LISTENER),
    TOPO_TASK_MAIN_EXEC_INIT("sleep before open msg send", topo_task_sleep_cb,
                             &sleep_time),
    TOPO_TASK_PEER_CFG_ADD_INIT("add peer speaker B to instance A", SXPD_A,
                                SXPD_B_IP, PORT, PWD, PEER_SPEAKER),

    TOPO_TASK_MAIN_EXEC_INIT("sleep before connect status check",
                             topo_task_sleep_cb, &sleep_time),
    TOPO_TASK_WAIT_FOR_INIT("wait for A B sxpd connect", SXPD_A, WAIT_TIMEOUT,
                            topo_task_cb_wait_for_peers, B_SPEAKER_CONNECTED),
    TOPO_TASK_WAIT_FOR_INIT("wait for B A sxpd connect", SXPD_B, WAIT_TIMEOUT,
                            topo_task_cb_wait_for_peers, A_LISTENER_CONNECTED),
    TOPO_TASK_PEER_CFG_DEL_INIT("del peer listener A from instance B", SXPD_B,
                                SXPD_A_IP, PORT, PWD, PEER_LISTENER),
    TOPO_TASK_PEER_CFG_DEL_INIT("del peer speaker B from instance A", SXPD_A,
                                SXPD_B_IP, PORT, PWD, PEER_SPEAKER),

    /* connection is initialized by instance B */
    TOPO_TASK_PEER_CFG_ADD_INIT("add peer speaker B to instance A", SXPD_A,
                                SXPD_B_IP, PORT, PWD, PEER_SPEAKER),
    TOPO_TASK_MAIN_EXEC_INIT("sleep before open msg send", topo_task_sleep_cb,
                             &sleep_time),
    TOPO_TASK_PEER_CFG_ADD_INIT("add peer listener A to instance B", SXPD_B,
                                SXPD_A_IP, PORT, PWD, PEER_LISTENER),

    TOPO_TASK_MAIN_EXEC_INIT("sleep before connect status check",
                             topo_task_sleep_cb, &sleep_time),
    TOPO_TASK_WAIT_FOR_INIT("wait for A B sxpd connect", SXPD_A, WAIT_TIMEOUT,
                            topo_task_cb_wait_for_peers, B_SPEAKER_CONNECTED),
    TOPO_TASK_WAIT_FOR_INIT("wait for B A sxpd connect", SXPD_B, WAIT_TIMEOUT,
                            topo_task_cb_wait_for_peers, A_LISTENER_CONNECTED),
    TOPO_TASK_PEER_CFG_DEL_INIT("del peer listener A from instance B", SXPD_B,
                                SXPD_A_IP, PORT, PWD, PEER_LISTENER),
    TOPO_TASK_PEER_CFG_DEL_INIT("del peer speaker B from instance A", SXPD_A,
                                SXPD_B_IP, PORT, PWD, PEER_SPEAKER),
    TOPO_TASK_MAIN_EXEC_INIT("run log checker", topo_task_log_check_run_cb,
                             NULL),

    /* reconfigure listener-speaker topology with speaker hold-time unused */
    TOPO_TASK_MAIN_EXEC_INIT("set log check patterns",
                             topo_task_log_check_set_patterns_cb,
                             &log_patterns_ctx),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd A listener minimum hold time",
                                  SXPD_A, UINT32_SETTING_LISTENER_MIN_HOLD_TIME,
                                  80),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd A listener maximum hold time",
                                  SXPD_A, UINT32_SETTING_LISTENER_MAX_HOLD_TIME,
                                  120),
    TOPO_TASK_UINT32_CFG_ADD_INIT(
        "reconfigure sxpd B speaker minimum hold time", SXPD_B,
        UINT32_SETTING_SPEAKER_MIN_HOLD_TIME, 0xffff),

    /* connection is initialized by instance A */
    TOPO_TASK_PEER_CFG_ADD_INIT("add peer listener A to instance B", SXPD_B,
                                SXPD_A_IP, PORT, PWD, PEER_LISTENER),
    TOPO_TASK_MAIN_EXEC_INIT("sleep before open msg send", topo_task_sleep_cb,
                             &sleep_time),
    TOPO_TASK_PEER_CFG_ADD_INIT("add peer speaker B to instance A", SXPD_A,
                                SXPD_B_IP, PORT, PWD, PEER_SPEAKER),

    TOPO_TASK_MAIN_EXEC_INIT("sleep before connect status check",
                             topo_task_sleep_cb, &sleep_time),
    TOPO_TASK_WAIT_FOR_INIT("wait for A B sxpd connect", SXPD_A, WAIT_TIMEOUT,
                            topo_task_cb_wait_for_peers, B_SPEAKER_CONNECTED),
    TOPO_TASK_WAIT_FOR_INIT("wait for B A sxpd connect", SXPD_B, WAIT_TIMEOUT,
                            topo_task_cb_wait_for_peers, A_LISTENER_CONNECTED),
    TOPO_TASK_PEER_CFG_DEL_INIT("del peer listener A from instance B", SXPD_B,
                                SXPD_A_IP, PORT, PWD, PEER_LISTENER),
    TOPO_TASK_PEER_CFG_DEL_INIT("del peer speaker B from instance A", SXPD_A,
                                SXPD_B_IP, PORT, PWD, PEER_SPEAKER),

    /* connection is initialized by instance B */
    TOPO_TASK_PEER_CFG_ADD_INIT("add peer speaker B to instance A", SXPD_A,
                                SXPD_B_IP, PORT, PWD, PEER_SPEAKER),
    TOPO_TASK_MAIN_EXEC_INIT("sleep before open msg send", topo_task_sleep_cb,
                             &sleep_time),
    TOPO_TASK_PEER_CFG_ADD_INIT("add peer listener A to instance B", SXPD_B,
                                SXPD_A_IP, PORT, PWD, PEER_LISTENER),

    TOPO_TASK_MAIN_EXEC_INIT("sleep before connect status check",
                             topo_task_sleep_cb, &sleep_time),
    TOPO_TASK_WAIT_FOR_INIT("wait for A B sxpd connect", SXPD_A, WAIT_TIMEOUT,
                            topo_task_cb_wait_for_peers, B_SPEAKER_CONNECTED),
    TOPO_TASK_WAIT_FOR_INIT("wait for B A sxpd connect", SXPD_B, WAIT_TIMEOUT,
                            topo_task_cb_wait_for_peers, A_LISTENER_CONNECTED),
    TOPO_TASK_PEER_CFG_DEL_INIT("del peer listener A from instance B", SXPD_B,
                                SXPD_A_IP, PORT, PWD, PEER_LISTENER),
    TOPO_TASK_PEER_CFG_DEL_INIT("del peer speaker B from instance A", SXPD_A,
                                SXPD_B_IP, PORT, PWD, PEER_SPEAKER),

    TOPO_TASK_MAIN_EXEC_INIT("run log checker", topo_task_log_check_run_cb,
                             NULL),

    /* reconfigure both-both topology with speaker hold-time in listener
     * hold-time range */
    TOPO_TASK_MAIN_EXEC_INIT("set log check patterns",
                             topo_task_log_check_set_patterns_cb,
                             &log_patterns_ctx),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd A listener minimum hold time",
                                  SXPD_A, UINT32_SETTING_LISTENER_MIN_HOLD_TIME,
                                  81),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd A listener maximum hold time",
                                  SXPD_A, UINT32_SETTING_LISTENER_MAX_HOLD_TIME,
                                  121),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd A speaker minimum hold time",
                                  SXPD_A, UINT32_SETTING_SPEAKER_MIN_HOLD_TIME,
                                  91),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd B listener minimum hold time",
                                  SXPD_B, UINT32_SETTING_LISTENER_MIN_HOLD_TIME,
                                  82),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd B listener maximum hold time",
                                  SXPD_B, UINT32_SETTING_LISTENER_MAX_HOLD_TIME,
                                  122),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd B speaker minimum hold time",
                                  SXPD_B, UINT32_SETTING_SPEAKER_MIN_HOLD_TIME,
                                  92),

    /* connection is initialized by instance A */
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd instance A retry timer",
                                  SXPD_B, UINT32_SETTING_RETRY_TIMER, 1),
    TOPO_TASK_PEER_CFG_ADD_INIT("add peer both A to instance B", SXPD_B,
                                SXPD_A_IP, PORT, PWD, PEER_BOTH),
    TOPO_TASK_PEER_CFG_ADD_INIT("add peer both B to instance A", SXPD_A,
                                SXPD_B_IP, PORT, PWD, PEER_BOTH),

    TOPO_TASK_MAIN_EXEC_INIT("sleep before connect status check",
                             topo_task_sleep_cb, &sleep_time3),
    TOPO_TASK_WAIT_FOR_INIT("wait for A B sxpd connect 111", SXPD_A,
                            WAIT_TIMEOUT, topo_task_cb_wait_for_peers,
                            B_BOTH_CONNECTED),
    TOPO_TASK_WAIT_FOR_INIT("wait for B A sxpd connect", SXPD_B, WAIT_TIMEOUT,
                            topo_task_cb_wait_for_peers, A_BOTH_CONNECTED),
    TOPO_TASK_PEER_CFG_DEL_INIT("del peer both A from instance B", SXPD_B,
                                SXPD_A_IP, PORT, PWD, PEER_BOTH),
    TOPO_TASK_PEER_CFG_DEL_INIT("del peer both B from instance A", SXPD_A,
                                SXPD_B_IP, PORT, PWD, PEER_BOTH),

    TOPO_TASK_MAIN_EXEC_INIT("run log checker", topo_task_log_check_run_cb,
                             NULL),

    /* reconfigure both_both topology with speaker hold-time lower than
     * listener hold-time range */
    TOPO_TASK_MAIN_EXEC_INIT("set log check patterns",
                             topo_task_log_check_set_patterns_cb,
                             &log_patterns_ctx),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd A listener minimum hold time",
                                  SXPD_A, UINT32_SETTING_LISTENER_MIN_HOLD_TIME,
                                  81),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd A listener maximum hold time",
                                  SXPD_A, UINT32_SETTING_LISTENER_MAX_HOLD_TIME,
                                  121),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd A speaker minimum hold time",
                                  SXPD_A, UINT32_SETTING_SPEAKER_MIN_HOLD_TIME,
                                  71),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd B listener minimum hold time",
                                  SXPD_B, UINT32_SETTING_LISTENER_MIN_HOLD_TIME,
                                  82),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd B listener maximum hold time",
                                  SXPD_B, UINT32_SETTING_LISTENER_MAX_HOLD_TIME,
                                  122),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd B speaker minimum hold time",
                                  SXPD_B, UINT32_SETTING_SPEAKER_MIN_HOLD_TIME,
                                  72),

    /* connection is initialized by instance A */
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd instance A retry timer",
                                  SXPD_B, UINT32_SETTING_RETRY_TIMER, 1),
    TOPO_TASK_PEER_CFG_ADD_INIT("add peer both A to instance B", SXPD_B,
                                SXPD_A_IP, PORT, PWD, PEER_BOTH),
    TOPO_TASK_PEER_CFG_ADD_INIT("add peer both B to instance A", SXPD_A,
                                SXPD_B_IP, PORT, PWD, PEER_BOTH),

    TOPO_TASK_MAIN_EXEC_INIT("sleep before connect status check",
                             topo_task_sleep_cb, &sleep_time3),
    TOPO_TASK_WAIT_FOR_INIT("wait for A B sxpd connect 111", SXPD_A,
                            WAIT_TIMEOUT, topo_task_cb_wait_for_peers,
                            B_BOTH_CONNECTED),
    TOPO_TASK_WAIT_FOR_INIT("wait for B A sxpd connect", SXPD_B, WAIT_TIMEOUT,
                            topo_task_cb_wait_for_peers, A_BOTH_CONNECTED),
    TOPO_TASK_PEER_CFG_DEL_INIT("del peer both A from instance B", SXPD_B,
                                SXPD_A_IP, PORT, PWD, PEER_BOTH),
    TOPO_TASK_PEER_CFG_DEL_INIT("del peer both B from instance A", SXPD_A,
                                SXPD_B_IP, PORT, PWD, PEER_BOTH),

    TOPO_TASK_MAIN_EXEC_INIT("run log checker", topo_task_log_check_run_cb,
                             NULL),

    /* reconfigure both-both topology with incompatible speaker hold-time
     * greater than listener hold-time range */
    TOPO_TASK_MAIN_EXEC_INIT("set log check patterns",
                             topo_task_log_check_set_patterns_cb,
                             &log_patterns_ctx2),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd A listener minimum hold time",
                                  SXPD_A, UINT32_SETTING_LISTENER_MIN_HOLD_TIME,
                                  81),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd A listener maximum hold time",
                                  SXPD_A, UINT32_SETTING_LISTENER_MAX_HOLD_TIME,
                                  121),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd A speaker minimum hold time",
                                  SXPD_A, UINT32_SETTING_SPEAKER_MIN_HOLD_TIME,
                                  131),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd B listener minimum hold time",
                                  SXPD_B, UINT32_SETTING_LISTENER_MIN_HOLD_TIME,
                                  82),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd B listener maximum hold time",
                                  SXPD_B, UINT32_SETTING_LISTENER_MAX_HOLD_TIME,
                                  122),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd B speaker minimum hold time",
                                  SXPD_B, UINT32_SETTING_SPEAKER_MIN_HOLD_TIME,
                                  132),

    /* connection is initialized by instance A */
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd instance A retry timer",
                                  SXPD_B, UINT32_SETTING_RETRY_TIMER, 1),
    TOPO_TASK_PEER_CFG_ADD_INIT("add peer both A to instance B", SXPD_B,
                                SXPD_A_IP, PORT, PWD, PEER_BOTH),
    TOPO_TASK_PEER_CFG_ADD_INIT("add peer both B to instance A", SXPD_A,
                                SXPD_B_IP, PORT, PWD, PEER_BOTH),

    TOPO_TASK_MAIN_EXEC_INIT("sleep before connect status check",
                             topo_task_sleep_cb, &sleep_time3),
    TOPO_TASK_WAIT_FOR_INIT("wait for A B sxpd connect 111", SXPD_A,
                            WAIT_TIMEOUT, topo_task_cb_wait_for_peers,
                            B_BOTH_DISCONNECTED),
    TOPO_TASK_WAIT_FOR_INIT("wait for B A sxpd connect", SXPD_B, WAIT_TIMEOUT,
                            topo_task_cb_wait_for_peers, A_BOTH_DISCONNECTED),
    TOPO_TASK_PEER_CFG_DEL_INIT("del peer both A from instance B", SXPD_B,
                                SXPD_A_IP, PORT, PWD, PEER_BOTH),
    TOPO_TASK_PEER_CFG_DEL_INIT("del peer both B from instance A", SXPD_A,
                                SXPD_B_IP, PORT, PWD, PEER_BOTH),

    TOPO_TASK_MAIN_EXEC_INIT("run log checker", topo_task_log_check_run_cb,
                             NULL),

    /* reconfigure both-both topology with listener and speaker hold-time unused
     * */
    TOPO_TASK_MAIN_EXEC_INIT("set log check patterns",
                             topo_task_log_check_set_patterns_cb,
                             &log_patterns_ctx),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd A listener minimum hold time",
                                  SXPD_A, UINT32_SETTING_LISTENER_MIN_HOLD_TIME,
                                  81),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd A listener maximum hold time",
                                  SXPD_A, UINT32_SETTING_LISTENER_MAX_HOLD_TIME,
                                  121),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd A speaker minimum hold time",
                                  SXPD_A, UINT32_SETTING_SPEAKER_MIN_HOLD_TIME,
                                  91),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd B listener minimum hold time",
                                  SXPD_B, UINT32_SETTING_LISTENER_MIN_HOLD_TIME,
                                  0xffff),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd B listener maximum hold time",
                                  SXPD_B, UINT32_SETTING_LISTENER_MAX_HOLD_TIME,
                                  0xffff),
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd B speaker minimum hold time",
                                  SXPD_B, UINT32_SETTING_SPEAKER_MIN_HOLD_TIME,
                                  0xffff),

    /* connection is initialized by instance A */
    TOPO_TASK_UINT32_CFG_ADD_INIT("configure sxpd instance A retry timer",
                                  SXPD_B, UINT32_SETTING_RETRY_TIMER, 1),
    TOPO_TASK_PEER_CFG_ADD_INIT("add peer both A to instance B", SXPD_B,
                                SXPD_A_IP, PORT, PWD, PEER_BOTH),
    TOPO_TASK_PEER_CFG_ADD_INIT("add peer both B to instance A", SXPD_A,
                                SXPD_B_IP, PORT, PWD, PEER_BOTH),

    TOPO_TASK_MAIN_EXEC_INIT("sleep before connect status check",
                             topo_task_sleep_cb, &sleep_time3),
    TOPO_TASK_WAIT_FOR_INIT("wait for A B sxpd connect 111", SXPD_A,
                            WAIT_TIMEOUT, topo_task_cb_wait_for_peers,
                            B_BOTH_CONNECTED),
    TOPO_TASK_WAIT_FOR_INIT("wait for B A sxpd connect", SXPD_B, WAIT_TIMEOUT,
                            topo_task_cb_wait_for_peers, A_BOTH_CONNECTED),
    TOPO_TASK_PEER_CFG_DEL_INIT("del peer both A from instance B", SXPD_B,
                                SXPD_A_IP, PORT, PWD, PEER_BOTH),
    TOPO_TASK_PEER_CFG_DEL_INIT("del peer both B from instance A", SXPD_A,
                                SXPD_B_IP, PORT, PWD, PEER_BOTH),

    TOPO_TASK_MAIN_EXEC_INIT("run log checker", topo_task_log_check_run_cb,
                             NULL),

    /* destroy instances */
    TOPO_TASK_STOP_SXPD_INIT("stop sxpd instance A", SXPD_A),
    TOPO_TASK_STOP_SXPD_INIT("stop sxpd instance B", SXPD_B),
};

int main(void)
{
    int rc = 0;

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
