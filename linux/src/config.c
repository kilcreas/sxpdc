/*------------------------------------------------------------------
 * Configuration manager implementation
 *
 * November 2014, Jan Omasta
 *
 * Copyright (c) 2014-2015 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------*/

#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>
#include <libconfig.h>
#include <arpa/inet.h>
#include <sys/queue.h>
#include <signal.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <pthread.h>

#include "config.h"
#include "util.h"
#include "mem.h"
#include "sxp.h"
#include "logging.h"
#include "radix.h"

#include "config_validate.h"

#define CFG_RADIX_V4_MAXBITS 32
#define CFG_RADIX_V6_MAXBITS 128

#define CFG_GLOBAL_LOG_LEVEL "global.log_level"
#define CFG_GLOBAL_LOG_LEVEL_DEFAULT LOG_LEVEL_ERROR
#define CFG_GLOBAL_LOG_LEVEL_ALERT "alert"
#define CFG_GLOBAL_LOG_LEVEL_ERROR "error"
#define CFG_GLOBAL_LOG_LEVEL_TRACE "trace"
#define CFG_GLOBAL_LOG_LEVEL_DEBUG "debug"

#define CFG_GLOBAL_ENABLED "global.enabled"
#define CFG_GLOBAL_RETRY_TIMER "global.retry_timer"
#define CFG_GLOBAL_RETRY_TIMER_MIN 0
#define CFG_GLOBAL_RETRY_TIMER_MAX UINT16_MAX
#define CFG_GLOBAL_RECONCILIATION_TIMER "global.reconciliation_timer"
#define CFG_GLOBAL_RECONCILIATION_TIMER_MIN 0
#define CFG_GLOBAL_RECONCILIATION_TIMER_MAX UINT16_MAX
#define CFG_GLOBAL_LISTENER_HOLD_TIME_MIN "global.listener_min_hold_time"
#define CFG_GLOBAL_LISTENER_HOLD_TIME_MIN_MIN 0
#define CFG_GLOBAL_LISTENER_HOLD_TIME_MIN_MAX UINT16_MAX
#define CFG_GLOBAL_LISTENER_HOLD_TIME_MAX "global.listener_max_hold_time"
#define CFG_GLOBAL_LISTENER_HOLD_TIME_MAX_MIN 0
#define CFG_GLOBAL_LISTENER_HOLD_TIME_MAX_MAX UINT16_MAX
#define CFG_GLOBAL_SPEAKER_HOLD_TIME_MIN "global.speaker_min_hold_time"
#define CFG_GLOBAL_SPEAKER_HOLD_TIME_MIN_MIN 0
#define CFG_GLOBAL_SPEAKER_HOLD_TIME_MIN_MAX UINT16_MAX

#define CFG_GLOBAL_KEEPALIVE_TIMER "global.keepalive_timer"
#define CFG_GLOBAL_KEEPALIVE_TIMER_MIN 0
#define CFG_GLOBAL_KEEPALIVE_TIMER_MAX UINT16_MAX

#define CFG_GLOBAL_SUBNET_EXPANSION_LIMIT "global.subnet_expansion_limit"
#define CFG_GLOBAL_SUBNET_EXPANSION_LIMIT_MIN 0
#define CFG_GLOBAL_SUBNET_EXPANSION_LIMIT_MAX UINT16_MAX

#define CFG_GLOBAL_DEFAULT_CONNECTION_PASSWD "global.default_connection_passwd"
#define CFG_GLOBAL_BIND_IP_MAX_LEN 15
#define CFG_GLOBAL_BIND_IP "global.bind_ip"
#define CFG_GLOBAL_PORT_NUMBER "global.port_number"
#define CFG_GLOBAL_PORT_NUMBER_MIN 0
#define CFG_GLOBAL_PORT_NUMBER_MAX UINT16_MAX

#define CFG_GLOBAL_NODE_ID "global.node_id"
#define CFG_GLOBAL_NODE_ID_MIN 0
#define CFG_GLOBAL_NODE_ID_MAX UINT32_MAX

#define CFG_HIDDEN_STR "SECRET"

#define CFG_BINDINGS "bindings"
#define CFG_PEERS "peers"

#define CFG_PEER_CON_PASSWORD "connection_password"
#define CFG_PEER_IP_ADDRESS "ip_address"
#define CFG_PEER_PORT_NUMBER "port_number"
#define CFG_PEER_PORT_NUMBER_MIN 0
#define CFG_PEER_PORT_NUMBER_MAX UINT16_MAX
#define CFG_PEER_PORT_NUMBER_DEFAULT 64999
#define CFG_PEER_TYPE "peer_type"
#define CFG_PEER_TYPE_SPEAKER "speaker"
#define CFG_PEER_TYPE_LISTENER "listener"
#define CFG_PEER_TYPE_BOTH "both"

#define CFG_BINDING_IPV4_PREFIX "ipv4_prefix"
#define CFG_BINDING_IPV4_PREFIX_LENGTH "ipv4_prefix_length"
#define CFG_BINDING_IPV4_PREFIX_LENGTH_MIN 1
#define CFG_BINDING_IPV4_PREFIX_LENGTH_MAX 32
#define CFG_BINDING_IPV6_PREFIX "ipv6_prefix"
#define CFG_BINDING_IPV6_PREFIX_LENGTH "ipv6_prefix_length"
#define CFG_BINDING_IPV6_PREFIX_LENGTH_MIN 1
#define CFG_BINDING_IPV6_PREFIX_LENGTH_MAX 128
#define CFG_BINDING_SGT "sgt"
#define CFG_BINDING_SGT_MIN 2
#define CFG_BINDING_SGT_MAX UINT16_MAX

#define ERROR_SIZE 512

#define CFG_STR_CMP(str1, str2)            \
    (((NULL == str1) && (NULL == str2)) || \
     ((NULL != str1) && (NULL != str2) && (strcmp(str1, str2) == 0)))

#define TUPLE_CFG_PATTERN_TYPE_DEF(SELECT_FUNC) \
    SELECT_FUNC(CFG_IS_GROUP, "group")          \
    SELECT_FUNC(CFG_IS_LIST, "list")            \
    SELECT_FUNC(CFG_IS_BOOL, "bool")            \
    SELECT_FUNC(CFG_IS_NUM, "number")           \
    SELECT_FUNC(CFG_IS_STR, "string")

#define TUPLE_CFG_PATTERN_TYPE_ENUM(enumerator, str) enumerator,
#define TUPLE_CFG_PATTERN_TYPE_STR(enumerator, str) str,

enum cfg_pattern_type {
    TUPLE_CFG_PATTERN_TYPE_DEF(TUPLE_CFG_PATTERN_TYPE_ENUM) CFG_IS_LAST
};

enum cfg_value_pattern_type {
    VALUE_PATTERN_NUM_RANGE,
    VALUE_PATTERN_STR_LENGTH,
    VALUE_PATTERN_STR_ENUM,
    VALUE_PATTERN_IPV4,
    VALUE_PATTERN_IPV6,
    VALUE_PATTERN_NONE,
};

struct cfg_value_pattern_num_range {
    int64_t min;
    int64_t max;
};

struct cfg_value_pattern_str_length {
    size_t min;
    size_t max;
};

struct cfg_value_pattern_str_enum {
    const char **str_enum;
};

struct cfg_pattern_limit {
    enum cfg_value_pattern_type type;
    union {
        void *unused;
        struct cfg_value_pattern_num_range range;
        struct cfg_value_pattern_str_length str_length;
        struct cfg_value_pattern_str_enum str_enum;
    } l;
};

struct cfg_pattern;

typedef int (*pattern_check_cb)(struct cfg_ctx *ctx, const config_setting_t *cs,
                                struct cfg_pattern *pn, bool *failed);

/**
 * @brief configuration pattern used by configuration content validation
 */
struct cfg_pattern {
    const char *name;
    /* logging is using this description when configuration pattern represents
     * unnamed configuration element */
    const char *desc;
    enum cfg_pattern_type val_type;
    struct cfg_pattern *child;
    size_t child_num;
    struct cfg_pattern_limit limit;
    pattern_check_cb check_cb;
};

#define CFG_PATTERN_AGGREGATE(settin_name, setting_description,                \
                              setting_value_type, child_elemt, child_elem_num, \
                              cb)                                              \
    {                                                                          \
        .name = settin_name, .desc = setting_description,                      \
        .val_type = setting_value_type, .child = child_elemt,                  \
        .child_num = child_elem_num, .limit = {.type = VALUE_PATTERN_NONE,     \
                                               .l =                            \
                                                   {                           \
                                                    .unused = NULL,            \
                                                   } },                        \
        .check_cb = cb,                                                        \
    }

#define CFG_PATTERN_SCALAR(settin_name, setting_description,           \
                           setting_value_type)                         \
    {                                                                  \
        .name = settin_name, .desc = setting_description,              \
        .val_type = setting_value_type, .child = NULL, .child_num = 0, \
        .limit = {.type = VALUE_PATTERN_NONE,                          \
                  .l =                                                 \
                      {                                                \
                       .unused = NULL,                                 \
                      } },                                             \
        .check_cb = NULL,                                              \
    }

#define CFG_PATTERN_STR_ENUM(settin_name, setting_description, ...)         \
    {                                                                       \
        .name = settin_name, .desc = setting_description,                   \
        .val_type = CFG_IS_STR, .child = NULL, .child_num = 0,              \
        .limit =                                                            \
            {                                                               \
              .type = VALUE_PATTERN_STR_ENUM,                               \
              .l.str_enum.str_enum = (const char *[]){ __VA_ARGS__, NULL }, \
            },                                                              \
        .check_cb = NULL,                                                   \
    }

#define CFG_PATTERN_STR_LENGTH(settin_name, setting_description, min_len, \
                               max_len)                                   \
    {                                                                     \
        .name = settin_name, .desc = setting_description,                 \
        .val_type = CFG_IS_STR, .child = NULL, .child_num = 0,            \
        .limit = {.type = VALUE_PATTERN_STR_LENGTH,                       \
                  .l.str_length =                                         \
                      {                                                   \
                       .min = min_len, .max = max_len,                    \
                      } },                                                \
        .check_cb = NULL,                                                 \
    }

#define CFG_PATTERN_NUM_RANGE(settin_name, setting_description, min_val, \
                              max_val)                                   \
    {                                                                    \
        .name = settin_name, .desc = setting_description,                \
        .val_type = CFG_IS_NUM, .child = NULL, .child_num = 0,           \
        .limit = {.type = VALUE_PATTERN_NUM_RANGE,                       \
                  .l.range =                                             \
                      {                                                  \
                       .min = min_val, .max = max_val,                   \
                      } },                                               \
        .check_cb = NULL,                                                \
    }

#define CFG_PATTERN_IPV4(settin_name, setting_description)     \
    {                                                          \
        .name = settin_name, .desc = setting_description,      \
        .val_type = CFG_IS_STR, .child = NULL, .child_num = 0, \
        .limit = {.type = VALUE_PATTERN_IPV4,                  \
                  .l =                                         \
                      {                                        \
                       .unused = NULL,                         \
                      } },                                     \
        .check_cb = NULL,                                      \
    }

#define CFG_PATTERN_IPV6(settin_name, setting_description)     \
    {                                                          \
        .name = settin_name, .desc = setting_description,      \
        .val_type = CFG_IS_STR, .child = NULL, .child_num = 0, \
        .limit = {.type = VALUE_PATTERN_IPV6,                  \
                  .l =                                         \
                      {                                        \
                       .unused = NULL,                         \
                      } },                                     \
        .check_cb = NULL,                                      \
    }

static struct cfg_pattern cfg_pn_global[] = {
    CFG_PATTERN_NUM_RANGE("retry_timer", "", CFG_GLOBAL_RETRY_TIMER_MIN,
                          CFG_GLOBAL_RETRY_TIMER_MAX),
    CFG_PATTERN_NUM_RANGE("reconciliation_timer", "",
                          CFG_GLOBAL_RECONCILIATION_TIMER_MIN,
                          CFG_GLOBAL_RECONCILIATION_TIMER_MAX),
    CFG_PATTERN_NUM_RANGE("speaker_min_hold_time", "",
                          CFG_GLOBAL_SPEAKER_HOLD_TIME_MIN_MIN,
                          CFG_GLOBAL_SPEAKER_HOLD_TIME_MIN_MAX),
    CFG_PATTERN_NUM_RANGE("listener_min_hold_time", "",
                          CFG_GLOBAL_LISTENER_HOLD_TIME_MIN_MIN,
                          CFG_GLOBAL_LISTENER_HOLD_TIME_MIN_MAX),
    CFG_PATTERN_NUM_RANGE("listener_max_hold_time", "",
                          CFG_GLOBAL_LISTENER_HOLD_TIME_MAX_MIN,
                          CFG_GLOBAL_LISTENER_HOLD_TIME_MAX_MAX),
    CFG_PATTERN_NUM_RANGE("keepalive_timer", "", CFG_GLOBAL_KEEPALIVE_TIMER_MIN,
                          CFG_GLOBAL_KEEPALIVE_TIMER_MAX),
    CFG_PATTERN_NUM_RANGE("subnet_expansion_limit", "",
                          CFG_GLOBAL_SUBNET_EXPANSION_LIMIT_MIN,
                          CFG_GLOBAL_SUBNET_EXPANSION_LIMIT_MAX),
    CFG_PATTERN_STR_LENGTH("default_connection_passwd", "", 0,
                           CFG_PASSWORD_MAX_SIZE - 1),
    CFG_PATTERN_IPV4("bind_ip", ""),
    CFG_PATTERN_NUM_RANGE("port_number", "", CFG_GLOBAL_PORT_NUMBER_MIN,
                          CFG_GLOBAL_PORT_NUMBER_MAX),
    CFG_PATTERN_NUM_RANGE("node_id", "", CFG_GLOBAL_NODE_ID_MIN,
                          CFG_GLOBAL_NODE_ID_MAX),
    CFG_PATTERN_SCALAR("enabled", "", CFG_IS_BOOL),
    CFG_PATTERN_STR_ENUM("log_level", "", CFG_GLOBAL_LOG_LEVEL_ALERT,
                         CFG_GLOBAL_LOG_LEVEL_ERROR, CFG_GLOBAL_LOG_LEVEL_TRACE,
                         CFG_GLOBAL_LOG_LEVEL_DEBUG),
};

static struct cfg_pattern cfg_pn_binding[] = {
    CFG_PATTERN_IPV4(CFG_BINDING_IPV4_PREFIX, ""),
    CFG_PATTERN_NUM_RANGE(CFG_BINDING_IPV4_PREFIX_LENGTH, "",
                          CFG_BINDING_IPV4_PREFIX_LENGTH_MIN,
                          CFG_BINDING_IPV4_PREFIX_LENGTH_MAX),
    CFG_PATTERN_IPV6(CFG_BINDING_IPV6_PREFIX, ""),
    CFG_PATTERN_NUM_RANGE(CFG_BINDING_IPV6_PREFIX_LENGTH, "",
                          CFG_BINDING_IPV6_PREFIX_LENGTH_MIN,
                          CFG_BINDING_IPV6_PREFIX_LENGTH_MAX),
    CFG_PATTERN_NUM_RANGE(CFG_BINDING_SGT, "", CFG_BINDING_SGT_MIN,
                          CFG_BINDING_SGT_MAX),
};

static int cfg_validate_binding_cb(struct cfg_ctx *ctx,
                                   const config_setting_t *cs,
                                   struct cfg_pattern *pn, bool *failed);

static struct cfg_pattern cfg_pn_bindings[] = {
    CFG_PATTERN_AGGREGATE(NULL, "binding list item", CFG_IS_GROUP,
                          cfg_pn_binding,
                          sizeof(cfg_pn_binding) / sizeof(*cfg_pn_binding),
                          cfg_validate_binding_cb),
};

static struct cfg_pattern cfg_pn_peer[] = {
    CFG_PATTERN_IPV4(CFG_PEER_IP_ADDRESS, ""),
    CFG_PATTERN_NUM_RANGE(CFG_PEER_PORT_NUMBER, "", CFG_PEER_PORT_NUMBER_MIN,
                          CFG_PEER_PORT_NUMBER_MAX),
    CFG_PATTERN_STR_LENGTH(CFG_PEER_CON_PASSWORD, "", 0,
                           CFG_PASSWORD_MAX_SIZE - 1),
    CFG_PATTERN_STR_ENUM(CFG_PEER_TYPE, "", CFG_PEER_TYPE_SPEAKER,
                         CFG_PEER_TYPE_LISTENER, CFG_PEER_TYPE_BOTH),
};

static int cfg_validate_peer_cb(struct cfg_ctx *ctx, const config_setting_t *cs,
                                struct cfg_pattern *pn, bool *failed);

static struct cfg_pattern cfg_pn_peers[] = {
    CFG_PATTERN_AGGREGATE(NULL, "peer list item", CFG_IS_GROUP, cfg_pn_peer,
                          sizeof(cfg_pn_peer) / sizeof(*cfg_pn_peer),
                          cfg_validate_peer_cb),
};

static int cfg_validate_bindings_cb(struct cfg_ctx *ctx,
                                    const config_setting_t *cs,
                                    struct cfg_pattern *pn, bool *failed);

static int cfg_validate_peers_cb(struct cfg_ctx *ctx,
                                 const config_setting_t *cs,
                                 struct cfg_pattern *pn, bool *failed);

static struct cfg_pattern cfg_pn_root[] = {
    CFG_PATTERN_AGGREGATE("global", "", CFG_IS_GROUP, cfg_pn_global,
                          sizeof(cfg_pn_global) / sizeof(*cfg_pn_global), NULL),
    CFG_PATTERN_AGGREGATE("peers", "", CFG_IS_LIST, cfg_pn_peers,
                          sizeof(cfg_pn_peers) / sizeof(*cfg_pn_peers),
                          cfg_validate_peers_cb),
    CFG_PATTERN_AGGREGATE("bindings", "", CFG_IS_LIST, cfg_pn_bindings,
                          sizeof(cfg_pn_bindings) / sizeof(*cfg_pn_bindings),
                          cfg_validate_bindings_cb),
};

static struct cfg_pattern cfg_pn = CFG_PATTERN_AGGREGATE(
    NULL, "root of configuration", CFG_IS_GROUP, cfg_pn_root,
    sizeof(cfg_pn_root) / sizeof(*cfg_pn_root), NULL);

TAILQ_HEAD(tailq_peer_head_s, peer_item);

/**
 * event manager settings structure
 */
struct evmgr_settings {
    bool unused;
};

/**
 * @brief tailq item type
 */
typedef enum list_item_flag_e {
    LIST_ITEM_EXIST,
    LIST_ITEM_REMOVED,
    LIST_ITEM_ADDED,
} list_item_flag_t;

/**
 * @brief peer list item
 */
struct peer_item {
    TAILQ_ENTRY(peer_item) tailq_entries;
    list_item_flag_t flag;
    struct peer peer;
};

/**
 * @brief peer list with iterator
 */
struct peer_set {
    struct tailq_peer_head_s tailq_head; /* List head. */
};

/**
 * @brief binding list with iterator
 */
struct binding_item {
    list_item_flag_t flag;
    struct binding binding;
};

/**
 * @brief global settings structure
 */
struct global_settings {
    bool setting_is_set[UINT32_SETTING_LAST];
    bool str_setting_is_set[STR_SETTING_LAST];
    uint16_t retry_timer;
    uint16_t reconciliation_timer;
    uint16_t listener_min_hold_time;
    uint16_t listener_max_hold_time;
    uint16_t speaker_min_hold_time;
    uint16_t keepalive_timer;
    uint16_t subnet_expansion_counter;
    char default_connection_password[CFG_PASSWORD_MAX_SIZE];
    in_addr_t bind_address; /* network byte order */
    uint16_t port;          /* network byte order */
    uint32_t node_id;
    bool enabled;
    enum log_level log_level;
};

/**
 * @brief tailq item type
 */
enum cfg_reload_status_e {
    CFG_RELOAD_NOT_RUNNING,
    CFG_RELOAD_RUNNING,
    CFG_RELOAD_AGAIN,
};

struct cfg_ctx {
    const char *config_path;
    config_t cfg;
    bool global_settings_is_loaded;
    struct global_settings global_settings;
    struct radix_tree *v4binding_set;
    struct radix_tree *v6binding_set;
    struct peer_set peer_set;
    cfg_add_uint32_setting_callback add_uint_cb;
    cfg_del_uint32_setting_callback del_uint_cb;
    cfg_add_str_setting_callback add_str_cb;
    cfg_del_str_setting_callback del_str_cb;
    cfg_add_peer_callback add_peer_cb;
    cfg_del_peer_callback del_peer_cb;
    cfg_add_binding_callback add_binding_cb;
    cfg_del_binding_callback del_binding_cb;
    struct sxpd_ctx *sxpd_ctx;
    bool cfg_is_read;
    pthread_mutex_t cfg_reload_mutex;
    enum cfg_reload_status_e cfg_reload_status;
    pthread_t cfg_reload_thread;
    struct evmgr_timer *cfg_reload_timer;
};

#define PAIR_DEF_STR(enumerator, string) string,

/**
 * @brief string types of added/deleted uint32 setting
 */
static const char *uint32_setting_str[] = { TUPLE_UINT32_CFG_DEF(
    PAIR_DEF_STR) };

/**
 * @brief string types of added/deleted str setting
 */
static const char *str_setting_str[] = { TUPLE_STR_CFG_DEF(PAIR_DEF_STR) };

const char *cfg_get_uint32_setting_str(uint32_setting_type_t type)
{
    const char *ret = NULL;

    if (type < UINT32_SETTING_LAST) {
        ret = uint32_setting_str[type];
    }

    return ret;
}

const char *cfg_get_str_setting_str(str_setting_type_t type)
{
    const char *ret = NULL;

    if (type < STR_SETTING_LAST) {
        ret = str_setting_str[type];
    }

    return ret;
}

static int cfg_check_int64(const char *cfg_path, const int64_t *min_val,
                           const int64_t *max_val, const int64_t *cfg_val)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, cfg_path, cfg_val);

    if (RC_ISOK(rc)) {
        if ((NULL != min_val) && ((*min_val) > (*cfg_val))) {
            LOG_ERROR("Setting <%s> value <%" PRId64 "> out of minimum "
                      "<%" PRId64 ">",
                      cfg_path, *cfg_val, *min_val);
            rc = -1;
        } else if ((NULL != max_val) && ((*max_val) < (*cfg_val))) {
            LOG_ERROR("Setting <%s> value <%" PRId64 "> out of maximum "
                      "<%" PRId64 ">",
                      cfg_path, *cfg_val, *max_val);
            rc = -1;
        } else {
            LOG_TRACE("Setting <%s> loaded with value <%" PRId64 ">", cfg_path,
                      *cfg_val);
            rc = 1;
        }
    } else {
        rc = -1;
    }

    return rc;
}

static int cfg_get_bool(struct cfg_ctx *ctx, const char *cfg_path,
                        bool *cfg_val)
{
    int rc = 0;
    config_t *cfg = NULL;
    int tmp = 0;

    PARAM_NULL_CHECK(rc, ctx, cfg_path, cfg_val);

    if (RC_ISOK(rc)) {
        cfg = &ctx->cfg;

        if (CONFIG_TRUE != config_lookup_bool(cfg, cfg_path, &tmp)) {
            LOG_TRACE("Setting <%s> value not found", cfg_path);
            rc = 0;
        } else {
            *cfg_val = (bool)tmp;
            LOG_TRACE("Setting <%s> loaded with value <%d>", cfg_path, tmp);
            rc = 1;
        }
    } else {
        rc = -1;
    }

    return rc;
}

static int cfg_get_int64(struct cfg_ctx *ctx, const char *cfg_path,
                         const int64_t *min_val, const int64_t *max_val,
                         int64_t *cfg_val, int64_t *cfg_def)
{
    int rc = 0;
    config_t *cfg = NULL;
    long long int tmp_ll = 0;

    PARAM_NULL_CHECK(rc, ctx, cfg_path, cfg_val);

    if (RC_ISOK(rc)) {
        cfg = &ctx->cfg;

        if (CONFIG_TRUE != config_lookup_int64(cfg, cfg_path, &tmp_ll)) {
            if (NULL != cfg_def) {
                LOG_TRACE("Setting <%s> value not found, using default "
                          "<%" PRId64 ">",
                          cfg_path, *cfg_def);
                *cfg_val = *cfg_def;
                rc = 1;
            } else {
                LOG_TRACE("Setting <%s> value not found", cfg_path);
                rc = 0;
            }
        } else {
            if ((tmp_ll < INT64_MIN) || (tmp_ll > INT64_MAX)) {
                LOG_ERROR("Setting <%s> value is out of range "
                          "<%" PRId64 "...%" PRId64 ">",
                          cfg_path, INT64_MIN, INT64_MAX);
                rc = -1;
            } else {
                *cfg_val = (int64_t)tmp_ll;
                rc = cfg_check_int64(cfg_path, min_val, max_val, cfg_val);
            }
        }
    } else {
        rc = -1;
    }

    return rc;
}

static int cfg_check_str(const char *cfg_path, const size_t *min_len,
                         const size_t *max_len, const char **cfg_val,
                         bool secret)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, cfg_path, cfg_val);

    if (RC_ISOK(rc)) {
        if ((NULL != min_len) && ((*min_len) > strlen(*cfg_val))) {
            LOG_ERROR("Setting <%s> value <%s> out of minimum length <%zu>",
                      cfg_path, secret ? CFG_HIDDEN_STR : *cfg_val, *min_len);
            rc = -1;
        } else if ((NULL != max_len) && ((*max_len) < strlen(*cfg_val))) {
            LOG_ERROR("Setting <%s> value <%s> out of maximum length <%zu>",
                      cfg_path, secret ? CFG_HIDDEN_STR : *cfg_val, *max_len);
            rc = -1;
        } else {
            LOG_TRACE("Setting <%s> loaded with value <%s>", cfg_path,
                      secret ? CFG_HIDDEN_STR : *cfg_val);
            rc = 1;
        }
    } else {
        rc = -1;
    }

    return rc;
}

static int cfg_get_str(struct cfg_ctx *ctx, const char *cfg_path,
                       const size_t *min_len, const size_t *max_len,
                       const char **cfg_val, bool secret)
{
    int rc = 0;
    config_t *cfg = NULL;

    PARAM_NULL_CHECK(rc, ctx, cfg_path, cfg_val);

    if (RC_ISOK(rc)) {
        cfg = &ctx->cfg;

        if (CONFIG_TRUE != config_lookup_string(cfg, cfg_path, cfg_val)) {
            LOG_TRACE("Setting <%s> value not found", cfg_path);
            rc = 0;
        } else {
            rc = cfg_check_str(cfg_path, min_len, max_len, cfg_val, secret);
        }
    } else {
        rc = -1;
    }

    return rc;
}

static int cfg_get_global_bool(struct cfg_ctx *ctx, const char *cfg_path,
                               uint32_setting_type_t setting_type,
                               bool *cfg_val)
{
    int rc = 0;
    bool tmp_int = 0;
    bool *cfg_is_set = NULL;

    PARAM_NULL_CHECK(rc, ctx, cfg_path, cfg_val);

    if (RC_ISOK(rc)) {
        cfg_is_set = &ctx->global_settings.setting_is_set[setting_type];
        rc = cfg_get_bool(ctx, cfg_path, &tmp_int);
        if ((0 == rc) && (true == ctx->global_settings_is_loaded) &&
            (true == (*cfg_is_set))) {
            rc = ctx->del_uint_cb(ctx->sxpd_ctx, setting_type);
            (*cfg_is_set) = false;
            (*cfg_val) = 0;
        } else if (1 == rc) {
            if ((true == ctx->global_settings_is_loaded) &&
                (true == (*cfg_is_set)) && ((*cfg_val) != tmp_int)) {
                rc = ctx->add_uint_cb(ctx->sxpd_ctx, setting_type,
                                      (uint32_t)tmp_int);
                (*cfg_val) = tmp_int;
            } else if ((false == ctx->global_settings_is_loaded) ||
                       (false == (*cfg_is_set))) {
                rc = ctx->add_uint_cb(ctx->sxpd_ctx, setting_type,
                                      (uint32_t)tmp_int);
                (*cfg_is_set) = true;
                (*cfg_val) = tmp_int;
            }
        }
    }

    return rc;
}

static int cfg_get_global_int64(struct cfg_ctx *ctx, const char *cfg_path,
                                uint32_setting_type_t setting_type,
                                const int64_t *min_val, const int64_t *max_val,
                                int64_t *cfg_val, int64_t *cfg_def)
{
    int rc = 0;
    int64_t tmp_int = 0;
    bool *cfg_is_set = NULL;

    PARAM_NULL_CHECK(rc, ctx, cfg_path, cfg_val);

    if (RC_ISOK(rc)) {
        cfg_is_set = &ctx->global_settings.setting_is_set[setting_type];
        rc = cfg_get_int64(ctx, cfg_path, min_val, max_val, &tmp_int, cfg_def);
        if ((0 == rc) && (true == ctx->global_settings_is_loaded) &&
            (true == (*cfg_is_set))) {
            rc = ctx->del_uint_cb(ctx->sxpd_ctx, setting_type);
            (*cfg_is_set) = false;
            (*cfg_val) = 0;
        } else if (1 == rc) {
            if ((true == ctx->global_settings_is_loaded) &&
                (true == (*cfg_is_set)) && ((*cfg_val) != tmp_int)) {
                rc = ctx->add_uint_cb(ctx->sxpd_ctx, setting_type,
                                      (uint32_t)tmp_int);
                (*cfg_val) = tmp_int;
            } else if ((false == ctx->global_settings_is_loaded) ||
                       (false == (*cfg_is_set))) {
                rc = ctx->add_uint_cb(ctx->sxpd_ctx, setting_type,
                                      (uint32_t)tmp_int);
                (*cfg_is_set) = true;
                (*cfg_val) = tmp_int;
            }
        }
    }

    return rc;
}

static int cfg_get_global_port(struct cfg_ctx *ctx, const char *cfg_path,
                               uint32_setting_type_t setting_type,
                               const int64_t *min_val, const int64_t *max_val,
                               int64_t *cfg_val)
{
    int rc = 0;
    int64_t tmp_int = 0;
    bool *cfg_is_set = NULL;

    PARAM_NULL_CHECK(rc, ctx, cfg_path, cfg_val);

    if (RC_ISOK(rc)) {
        cfg_is_set = &ctx->global_settings.setting_is_set[setting_type];
        rc = cfg_get_int64(ctx, cfg_path, min_val, max_val, &tmp_int, NULL);
        if ((0 == rc) && (true == ctx->global_settings_is_loaded) &&
            (true == (*cfg_is_set))) {
            rc = ctx->del_uint_cb(ctx->sxpd_ctx, setting_type);
            (*cfg_is_set) = false;
            (*cfg_val) = 0;
        } else if (1 == rc) {
            if ((true == ctx->global_settings_is_loaded) &&
                (true == (*cfg_is_set)) && ((*cfg_val) != tmp_int)) {
                rc = ctx->add_uint_cb(ctx->sxpd_ctx, setting_type,
                                      htons((uint16_t)tmp_int));
                (*cfg_val) = tmp_int;
            } else if ((false == ctx->global_settings_is_loaded) ||
                       (false == (*cfg_is_set))) {
                rc = ctx->add_uint_cb(ctx->sxpd_ctx, setting_type,
                                      htons((uint16_t)tmp_int));
                (*cfg_is_set) = true;
                (*cfg_val) = tmp_int;
            }
        }
    }

    return rc;
}

static int cfg_get_global_str(struct cfg_ctx *ctx, const char *cfg_path,
                              str_setting_type_t setting_type,
                              const size_t *min_len, const size_t *max_len,
                              char *cfg_val, bool secret)
{
    int rc = 0;
    const char *tmp_str = 0;
    bool *cfg_is_set = NULL;

    PARAM_NULL_CHECK(rc, ctx, cfg_path, cfg_val);

    if (RC_ISOK(rc)) {
        cfg_is_set = &ctx->global_settings.str_setting_is_set[setting_type];
        rc = cfg_get_str(ctx, cfg_path, min_len, max_len, &tmp_str, secret);
        if ((0 == rc) && (true == ctx->global_settings_is_loaded) &&
            (true == (*cfg_is_set))) {
            rc = ctx->del_str_cb(ctx->sxpd_ctx, setting_type);
            (*cfg_is_set) = false;
            cfg_val[0] = '\0';
        } else if (1 == rc) {
            if ((true == ctx->global_settings_is_loaded) &&
                (true == (*cfg_is_set)) && (strcmp(cfg_val, tmp_str) != 0)) {
                rc = ctx->add_str_cb(ctx->sxpd_ctx, setting_type, tmp_str);
                strcpy(cfg_val, tmp_str);
            } else if ((false == ctx->global_settings_is_loaded) ||
                       (false == (*cfg_is_set))) {
                rc = ctx->add_str_cb(ctx->sxpd_ctx, setting_type, tmp_str);
                (*cfg_is_set) = true;
                strcpy(cfg_val, tmp_str);
            }
        }
    }

    return rc;
}

static int cfg_get_global_ip(struct cfg_ctx *ctx, const char *cfg_path,
                             uint32_setting_type_t setting_type,
                             in_addr_t *cfg_val)
{
    int rc = 0;
    const char *tmp_str = NULL;
    bool *cfg_is_set = NULL;
    const size_t min_len = 0;
    const size_t max_len = CFG_GLOBAL_BIND_IP_MAX_LEN;
    in_addr_t tmp_val;

    PARAM_NULL_CHECK(rc, ctx, cfg_path, cfg_val);

    if (RC_ISOK(rc)) {
        cfg_is_set = &ctx->global_settings.setting_is_set[setting_type];
        rc = cfg_get_str(ctx, cfg_path, &min_len, &max_len, &tmp_str, false);
        if ((0 == rc) && (true == ctx->global_settings_is_loaded) &&
            (true == (*cfg_is_set))) {
            rc = ctx->del_uint_cb(ctx->sxpd_ctx, setting_type);
            (*cfg_is_set) = false;
        } else if (1 == rc) {
            if (inet_pton(AF_INET, tmp_str, &tmp_val) != 1) {
                LOG_ERROR("Load setting <%s> failed with invalid IPv4 "
                          "address <%s>",
                          cfg_path, tmp_str);
                rc = -1;
            } else if ((true == ctx->global_settings_is_loaded) &&
                       (true == (*cfg_is_set)) && (*cfg_val != tmp_val)) {
                rc = ctx->add_uint_cb(ctx->sxpd_ctx, setting_type, tmp_val);
                *cfg_val = tmp_val;
            } else if ((false == ctx->global_settings_is_loaded) ||
                       (false == (*cfg_is_set))) {
                rc = ctx->add_uint_cb(ctx->sxpd_ctx, setting_type, tmp_val);
                (*cfg_is_set) = true;
                *cfg_val = tmp_val;
            }
        }
    }

    return rc;
}

static int cfg_get_global_log_level(struct cfg_ctx *ctx, const char *cfg_path,
                                    uint32_setting_type_t setting_type,
                                    enum log_level *cfg_val)
{
    int rc = 0;
    const char *tmp_str = NULL;
    bool *cfg_is_set = NULL;
    enum log_level tmp_val = LOG_LEVEL_ALERT;

    PARAM_NULL_CHECK(rc, ctx, cfg_path, cfg_val);

    if (RC_ISOK(rc)) {
        cfg_is_set = &ctx->global_settings.setting_is_set[setting_type];
        rc = cfg_get_str(ctx, cfg_path, NULL, NULL, &tmp_str, false);
        if ((0 == rc) && (true == ctx->global_settings_is_loaded) &&
            (true == (*cfg_is_set))) {
            rc = ctx->del_uint_cb(ctx->sxpd_ctx, setting_type);
            (*cfg_is_set) = false;
        } else if (1 == rc) {
            rc = parse_log_level(&tmp_val, tmp_str);
            if (RC_ISNOTOK(rc)) {
                LOG_ERROR("Load setting <%s> failed with invalid log level "
                          "value <%s>",
                          cfg_path, tmp_str);
                rc = -1;
            } else if ((true == ctx->global_settings_is_loaded) &&
                       (true == (*cfg_is_set)) && (*cfg_val != tmp_val)) {
                rc = ctx->add_uint_cb(ctx->sxpd_ctx, setting_type, tmp_val);
                *cfg_val = tmp_val;
            } else if ((false == ctx->global_settings_is_loaded) ||
                       (false == (*cfg_is_set))) {
                rc = ctx->add_uint_cb(ctx->sxpd_ctx, setting_type, tmp_val);
                (*cfg_is_set) = true;
                *cfg_val = tmp_val;
            }
        }
    }

    return rc;
}

static bool cfg_ipv4_is_loopback_net(uint32_t ip)
{
    if ((ip & 0xFF000000) == 0x7F000000) {
        return true;
    }

    return false;
}

static int cfg_get_default_node_id(uint32_t *default_node_id)
{
    int rc = 0;
    struct ifaddrs *ifaddr = NULL;
    struct ifaddrs *ifa = NULL;
    struct sockaddr_in *sock = NULL;
    uint32_t node_id_hi = 0;
    uint32_t node_id_tmp = 0;
    uint32_t node_id_nbo = 0;
    uint32_t node_id_loop_hi = 0;
    char ip[INET_ADDRSTRLEN];

    PARAM_NULL_CHECK(rc, default_node_id);

    if (RC_ISOK(rc)) {
        rc = getifaddrs(&ifaddr);
        if (RC_ISNOTOK(rc)) {
            LOG_ERROR("Failed to get network interfaces description: %d", rc);
        }
    }

    if (RC_ISOK(rc)) {
        /* walk trough interface list and find interface with highest
         * ipv4 address */
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == NULL) {
                continue;
            }

            if (ifa->ifa_addr->sa_family == AF_INET) {
                sock = (struct sockaddr_in *)ifa->ifa_addr;
                node_id_tmp = ntohl(sock->sin_addr.s_addr);
                if (cfg_ipv4_is_loopback_net(node_id_tmp)) {
                    if (node_id_tmp > node_id_loop_hi) {
                        node_id_loop_hi = node_id_tmp;
                    }
                } else if (node_id_tmp > node_id_hi) {
                    node_id_hi = node_id_tmp;
                }
            }
        }

        freeifaddrs(ifaddr);

        if (0 == node_id_hi) {
            node_id_hi = node_id_loop_hi;
        }
        *default_node_id = node_id_hi;

        /* TODO remove next lines */
        node_id_nbo = htonl(node_id_hi);
        inet_ntop(AF_INET, &node_id_nbo, ip, INET_ADDRSTRLEN);
        LOG_DEBUG("Get default node id <%u> from interface with highest ipv4 "
                  "address %s",
                  node_id_hi, ip);
    }

    return rc;
}

static int cfg_get_global(struct cfg_ctx *ctx)
{
    int rc = 0;
    bool tmp_bool = 0;
    int64_t tmp_int = 0;
    int64_t min = 0;
    int64_t max = 0;
    int64_t def = 0;
    uint32_t def32 = 0;
    size_t min_len = 0;
    size_t max_len = 0;

    PARAM_NULL_CHECK(rc, ctx);

    if (RC_ISOK(rc)) {
        rc = cfg_get_global_log_level(ctx, CFG_GLOBAL_LOG_LEVEL,
                                      UINT32_SETTING_LOG_LEVEL,
                                      &ctx->global_settings.log_level);
        if (1 == rc) {
            rc = 0;
        }
    }

    if (RC_ISOK(rc)) {
        min = CFG_GLOBAL_RETRY_TIMER_MIN;
        max = CFG_GLOBAL_RETRY_TIMER_MAX;
        tmp_int = ctx->global_settings.retry_timer;

        rc = cfg_get_global_int64(ctx, CFG_GLOBAL_RETRY_TIMER,
                                  UINT32_SETTING_RETRY_TIMER, &min, &max,
                                  &tmp_int, NULL);
        if ((0 == rc) || (1 == rc)) {
            rc = 0;
            ctx->global_settings.retry_timer = (uint16_t)tmp_int;
        }
    }

    if (RC_ISOK(rc)) {
        min = CFG_GLOBAL_RECONCILIATION_TIMER_MIN;
        max = CFG_GLOBAL_RECONCILIATION_TIMER_MAX;
        tmp_int = ctx->global_settings.reconciliation_timer;

        rc = cfg_get_global_int64(ctx, CFG_GLOBAL_RECONCILIATION_TIMER,
                                  UINT32_SETTING_RECONCILIATION_TIMER, &min,
                                  &max, &tmp_int, NULL);
        if ((0 == rc) || (1 == rc)) {
            rc = 0;
            ctx->global_settings.reconciliation_timer = (uint16_t)tmp_int;
        }
    }

    if (RC_ISOK(rc)) {
        min = CFG_GLOBAL_SPEAKER_HOLD_TIME_MIN_MIN;
        max = CFG_GLOBAL_SPEAKER_HOLD_TIME_MIN_MAX;
        tmp_int = ctx->global_settings.speaker_min_hold_time;

        rc = cfg_get_global_int64(ctx, CFG_GLOBAL_SPEAKER_HOLD_TIME_MIN,
                                  UINT32_SETTING_SPEAKER_MIN_HOLD_TIME, &min,
                                  &max, &tmp_int, NULL);
        if ((0 == rc) || (1 == rc)) {
            rc = 0;
            ctx->global_settings.speaker_min_hold_time = (uint16_t)tmp_int;
        }
    }

    if (RC_ISOK(rc)) {
        min = CFG_GLOBAL_LISTENER_HOLD_TIME_MIN_MIN;
        max = CFG_GLOBAL_LISTENER_HOLD_TIME_MIN_MAX;
        tmp_int = ctx->global_settings.listener_min_hold_time;

        rc = cfg_get_global_int64(ctx, CFG_GLOBAL_LISTENER_HOLD_TIME_MIN,
                                  UINT32_SETTING_LISTENER_MIN_HOLD_TIME, &min,
                                  &max, &tmp_int, NULL);
        if ((0 == rc) || (1 == rc)) {
            rc = 0;
            ctx->global_settings.listener_min_hold_time = (uint16_t)tmp_int;
        }
    }

    if (RC_ISOK(rc)) {
        /* hold timer maximum must be greater than hold timer minimum */
        if (ctx->global_settings.listener_min_hold_time == 0xffff) {
            min = CFG_GLOBAL_LISTENER_HOLD_TIME_MAX_MIN;
        } else {
            min = ctx->global_settings.listener_min_hold_time + 1;
        }
        max = CFG_GLOBAL_LISTENER_HOLD_TIME_MAX_MAX;
        tmp_int = ctx->global_settings.listener_max_hold_time;

        rc = cfg_get_global_int64(ctx, CFG_GLOBAL_LISTENER_HOLD_TIME_MAX,
                                  UINT32_SETTING_LISTENER_MAX_HOLD_TIME, &min,
                                  &max, &tmp_int, NULL);
        if ((0 == rc) || (1 == rc)) {
            rc = 0;
            ctx->global_settings.listener_max_hold_time = (uint16_t)tmp_int;
        }
    }

    if (RC_ISOK(rc)) {
        min = CFG_GLOBAL_KEEPALIVE_TIMER_MIN;
        max = CFG_GLOBAL_KEEPALIVE_TIMER_MAX;
        tmp_int = ctx->global_settings.keepalive_timer;

        rc = cfg_get_global_int64(ctx, CFG_GLOBAL_KEEPALIVE_TIMER,
                                  UINT32_SETTING_KEEPALIVE_TIMER, &min, &max,
                                  &tmp_int, NULL);
        if ((0 == rc) || (1 == rc)) {
            rc = 0;
            ctx->global_settings.keepalive_timer = (uint16_t)tmp_int;
        }
    }

    if (RC_ISOK(rc)) {
        min = CFG_GLOBAL_SUBNET_EXPANSION_LIMIT_MIN;
        max = CFG_GLOBAL_SUBNET_EXPANSION_LIMIT_MAX;
        tmp_int = ctx->global_settings.subnet_expansion_counter;

        rc = cfg_get_global_int64(ctx, CFG_GLOBAL_SUBNET_EXPANSION_LIMIT,
                                  UINT32_SETTING_SUBNET_EXPANSION_LIMIT, &min,
                                  &max, &tmp_int, NULL);
        if ((0 == rc) || (1 == rc)) {
            rc = 0;
            ctx->global_settings.subnet_expansion_counter = (uint16_t)tmp_int;
        }
    }

    if (RC_ISOK(rc)) {
        min_len = 0;
        max_len = CFG_PASSWORD_MAX_SIZE - 1;

        rc = cfg_get_global_str(
            ctx, CFG_GLOBAL_DEFAULT_CONNECTION_PASSWD, STR_SETTING_PASSWORD,
            &min_len, &max_len,
            ctx->global_settings.default_connection_password, 1);
        if ((0 == rc) || (1 == rc)) {
            rc = 0;
        }
    }

    if (RC_ISOK(rc)) {
        rc = cfg_get_global_ip(ctx, CFG_GLOBAL_BIND_IP,
                               UINT32_SETTING_BIND_ADDRESS,
                               &ctx->global_settings.bind_address);
        if ((0 == rc) || (1 == rc)) {
            rc = 0;
        }
    }

    if (RC_ISOK(rc)) {
        min = CFG_GLOBAL_PORT_NUMBER_MIN;
        max = CFG_GLOBAL_PORT_NUMBER_MAX;
        tmp_int = ctx->global_settings.port;

        rc = cfg_get_global_port(ctx, CFG_GLOBAL_PORT_NUMBER,
                                 UINT32_SETTING_PORT, &min, &max, &tmp_int);
        if ((0 == rc) || (1 == rc)) {
            rc = 0;
            ctx->global_settings.port = (uint16_t)tmp_int;
        }
    }

    if (RC_ISOK(rc)) {
        min = CFG_GLOBAL_NODE_ID_MIN;
        max = CFG_GLOBAL_NODE_ID_MAX;
        tmp_int = ctx->global_settings.node_id;

        rc = cfg_get_default_node_id(&def32);
        if (RC_ISOK(rc)) {
            def = def32;
        } else {
            LOG_TRACE("Failed to generate sxpd default node id: %d", rc);
        }
        rc = cfg_get_global_int64(ctx, CFG_GLOBAL_NODE_ID,
                                  UINT32_SETTING_NODE_ID, &min, &max, &tmp_int,
                                  &def);
        if ((0 == rc) || (1 == rc)) {
            rc = 0;
            ctx->global_settings.node_id = (uint32_t)tmp_int;
        }
    }

    if (RC_ISOK(rc)) {
        tmp_bool = ctx->global_settings.enabled;

        rc = cfg_get_global_bool(ctx, CFG_GLOBAL_ENABLED,
                                 UINT32_SETTING_ENABLED, &tmp_bool);
        if ((0 == rc) || (1 == rc)) {
            rc = 0;
            ctx->global_settings.enabled = tmp_bool;
        }
    }

    if (RC_ISOK(rc)) {
        ctx->global_settings_is_loaded = true;
    }

    return rc;
}

static int cfg_lookup_str(const config_setting_t *cfg, const char *cfg_path,
                          const size_t *min_len, const size_t *max_len,
                          const char **cfg_val, bool secret)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, cfg, cfg_path, cfg_val);

    if (RC_ISOK(rc)) {
        if (CONFIG_TRUE !=
            config_setting_lookup_string(cfg, cfg_path, cfg_val)) {
            LOG_TRACE("Setting <%s> value not found", cfg_path);
            rc = 0;
        } else {
            rc = cfg_check_str(cfg_path, min_len, max_len, cfg_val, secret);
        }
    } else {
        rc = -1;
    }

    return rc;
}

static int cfg_lookup_int(const config_setting_t *cfg, const char *cfg_path,
                          const int *min_val, const int *max_val, int *cfg_val)
{
    int rc = 0;
    int64_t min64 = 0;
    int64_t max64 = 0;
    int64_t *min64_p = NULL;
    int64_t *max64_p = NULL;
    int64_t val64 = 0;

    PARAM_NULL_CHECK(rc, cfg, cfg_path, cfg_val);

    if (RC_ISOK(rc)) {
        if (CONFIG_TRUE != config_setting_lookup_int(cfg, cfg_path, cfg_val)) {
            LOG_TRACE("Setting <%s> value not found", cfg_path);
            rc = 0;
        } else {
            if (min_val) {
                min64 = *min_val;
                min64_p = &min64;
            }

            if (max_val) {
                max64 = *max_val;
                max64_p = &max64;
            }
            val64 = *cfg_val;
            rc = cfg_check_int64(cfg_path, min64_p, max64_p, &val64);
        }
    } else {
        rc = -1;
    }

    return rc;
}

static bool cfg_peer_equal(const struct peer *peer1, const struct peer *peer2)
{
    int rc = 0;
    bool ret = false;

    PARAM_NULL_CHECK(rc, peer1, peer2);

    if (RC_ISOK(rc)) {

        if ((CFG_STR_CMP(peer1->connection_password,
                         peer2->connection_password)) &&
            (peer1->ip_address == peer2->ip_address) &&
            (peer1->peer_type == peer2->peer_type) &&
            (peer1->port == peer2->port)) {
            ret = true;
        }
    }

    return ret;
}

static bool cfg_binding_equal(const struct binding *binding1,
                              const struct binding *binding2)
{
    int rc = 0;
    bool ret = false;

    PARAM_NULL_CHECK(rc, binding1, binding2);

    if (RC_ISOK(rc)) {
        if (binding1->type == binding2->type) {
            if (PREFIX_IPV4 == binding1->type) {
                if (binding1->prefix.prefix_v4 == binding2->prefix.prefix_v4) {
                    if (binding1->prefix_length == binding2->prefix_length) {
                        if (binding1->source_group_tag ==
                            binding2->source_group_tag) {
                            ret = true;
                        }
                    }
                }
            } else if (PREFIX_IPV6 == binding1->type) {
                if (memcmp(binding1->prefix.prefix_v6,
                           binding2->prefix.prefix_v6,
                           sizeof(uint32_t) * 4) == 0) {
                    if (binding1->prefix_length == binding2->prefix_length) {
                        if (binding1->source_group_tag ==
                            binding2->source_group_tag) {
                            ret = true;
                        }
                    }
                }
            }
        }
    }

    return ret;
}

static const struct peer_item *cfg_find_peer(struct cfg_ctx *ctx,
                                             in_addr_t ip_address,
                                             bool port_is_set, uint16_t port)
{
    int rc = 0;
    const struct peer_item *peer = NULL;

    PARAM_NULL_CHECK(rc, ctx);

    if (RC_ISOK(rc)) {
        TAILQ_FOREACH(peer, &ctx->peer_set.tailq_head, tailq_entries)
        {
            if ((peer->peer.ip_address == ip_address) &&
                (((false == peer->peer.port_is_set) &&
                  (false == port_is_set ||
                   CFG_PEER_PORT_NUMBER_DEFAULT == port)) ||
                 (false == port &&
                  (CFG_PEER_PORT_NUMBER_DEFAULT == peer->peer.port)) ||
                 (peer->peer.port == port))) {
                return peer;
            }
        }
    }

    return NULL;
}

static struct radix_tree *cfg_get_binding_radix(struct cfg_ctx *ctx,
                                                enum prefix_type_e prefix_type)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, ctx);
    RC_CHECK(rc, out);

    if (PREFIX_IPV4 == prefix_type) {
        return ctx->v4binding_set;
    } else if (PREFIX_IPV6 == prefix_type) {
        return ctx->v6binding_set;
    }

    LOG_ERROR("Invalid prefix type %d", prefix_type);

out:
    return NULL;
}

static const char *cfg_get_prefix_type_str(enum prefix_type_e prefix_type)
{
    if (PREFIX_IPV4 == prefix_type) {
        return "V4";
    } else if (PREFIX_IPV6 == prefix_type) {
        return "V6";
    }

    LOG_ERROR("Invalid prefix type %d", prefix_type);

    return NULL;
}

static int cfg_find_binding(struct cfg_ctx *ctx, const struct binding *binding,
                            struct radix_node **radix_node,
                            struct binding_item **binding_item)
{
    int rc = 0;
    struct radix_node *radix_node_ = NULL;

    PARAM_NULL_CHECK(rc, ctx, binding, radix_node, binding_item);
    RC_CHECK(rc, out);

    rc = radix_search(cfg_get_binding_radix(ctx, binding->type),
                      (uint8_t *)binding->prefix.prefix_v6,
                      binding->prefix_length, &radix_node_);
    if (RC_ISNOTOK(rc)) {
        LOG_ERROR("find %s binding in radix failed: %d",
                  cfg_get_prefix_type_str(binding->type), rc);
        goto out;
    }

    if (NULL != radix_node_) {
        rc =
            radix_parse_node(radix_node_, NULL, 0, NULL, (void **)binding_item);
        if (RC_ISNOTOK(rc)) {
            LOG_ERROR("parse %s binding radix node failed: %d",
                      cfg_get_prefix_type_str(binding->type), rc);
            goto out;
        }
        *radix_node = radix_node_;
    }

out:
    return rc;
}

static int cfg_store_binding(struct cfg_ctx *ctx, struct binding_item *binding)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, ctx, binding);
    RC_CHECK(rc, out);

    rc = radix_store(cfg_get_binding_radix(ctx, binding->binding.type),
                     (uint8_t *)binding->binding.prefix.prefix_v6,
                     binding->binding.prefix_length, binding, NULL);
    if (RC_ISNOTOK(rc)) {
        LOG_ERROR("store %s binding in radix failed: %d",
                  cfg_get_prefix_type_str(binding->binding.type), rc);
        goto out;
    }

out:
    return rc;
}

static int cfg_get_peer(struct cfg_ctx *ctx, const config_setting_t *peer_cfg,
                        struct peer_item *peer)
{
    int rc = 0;
    const char *tmp_ip = NULL;
    const char *tmp_passwd = NULL;
    const char *tmp_peer_type = NULL;
    int port = 0;
    bool port_is_set = false;
    size_t max_len = 0;
    int min = 0;
    int max = 0;

    PARAM_NULL_CHECK(rc, ctx, peer_cfg, peer);
    RC_CHECK(rc, out);

    if (config_setting_is_group(peer_cfg) != CONFIG_TRUE) {
        LOG_ERROR(
            "Peer at file:line <%s:%u> error: Peer setting is not group item",
            ctx->config_path, config_setting_source_line(peer_cfg));
        rc = -1;
        goto out;
    }

    if (1 != cfg_lookup_str(peer_cfg, CFG_PEER_IP_ADDRESS, NULL, NULL, &tmp_ip,
                            false)) {
        LOG_ERROR("Peer at file:line <%s:%u> error: Load peer setting "
                  "<%s> failed",
                  ctx->config_path, config_setting_source_line(peer_cfg),
                  CFG_PEER_IP_ADDRESS);
        rc = -1;
        goto out;
    }

    min = CFG_PEER_PORT_NUMBER_MIN;
    max = CFG_PEER_PORT_NUMBER_MAX;
    rc = cfg_lookup_int(peer_cfg, CFG_PEER_PORT_NUMBER, &min, &max, &port);
    port_is_set = rc;
    if (-1 == rc) {
        LOG_ERROR("Peer at file:line <%s:%u> error: Load peer setting <%s> "
                  "failed",
                  ctx->config_path, config_setting_source_line(peer_cfg),
                  CFG_PEER_PORT_NUMBER);
        goto out;
    }

    if (1 != cfg_lookup_str(peer_cfg, CFG_PEER_TYPE, NULL, NULL, &tmp_peer_type,
                            false)) {
        LOG_ERROR("Peer at file:line <%s:%u> error: Load peer setting <%s> "
                  "failed",
                  ctx->config_path, config_setting_source_line(peer_cfg),
                  CFG_PEER_TYPE);
        rc = -1;
        goto out;
    }

    max_len = CFG_PASSWORD_MAX_SIZE;
    rc = cfg_lookup_str(peer_cfg, CFG_PEER_CON_PASSWORD, NULL, &max_len,
                        &tmp_passwd, true);
    if (-1 == rc) {
        LOG_ERROR("Peer at file:line <%s:%u> error: Load peer setting <%s> "
                  "failed",
                  ctx->config_path, config_setting_source_line(peer_cfg),
                  CFG_PEER_CON_PASSWORD);
        goto out;
    }

    /* fill peer item password */
    if (peer->peer.connection_password) {
        mem_free(peer->peer.connection_password);
        peer->peer.connection_password = NULL;
    }

    if (NULL == tmp_passwd) {
        peer->peer.connection_password = NULL;
    } else {
        peer->peer.connection_password = strdup(tmp_passwd);
        if (NULL == peer->peer.connection_password) {
            LOG_ERROR("Failed to duplicate connection password string");
            rc = -1;
            goto out;
        }
    }

    /* fill peer port number */
    peer->peer.port = htons((uint16_t)port);
    peer->peer.port_is_set = port_is_set;

    /* convert peer string IP to binary IP format */
    if (inet_pton(AF_INET, tmp_ip, &peer->peer.ip_address) != 1) {
        LOG_ERROR("Peer at file:line <%s:%u> error: Setting <%s> "
                  "value <%s> is not valid IPv4 address",
                  ctx->config_path, config_setting_source_line(peer_cfg),
                  CFG_PEER_IP_ADDRESS, tmp_ip);
        rc = -1;
        goto out;
    }

    /* fill peer type */
    if (strcasecmp(CFG_PEER_TYPE_SPEAKER, tmp_peer_type) == 0) {
        peer->peer.peer_type = PEER_SPEAKER;
    } else if (strcasecmp(CFG_PEER_TYPE_LISTENER, tmp_peer_type) == 0) {
        peer->peer.peer_type = PEER_LISTENER;
    } else if (strcasecmp(CFG_PEER_TYPE_BOTH, tmp_peer_type) == 0) {
        peer->peer.peer_type = PEER_BOTH;
    } else {
        LOG_ERROR("Peer at file:line <%s:%u> error: Setting <%s> "
                  "value <%s> is invalid",
                  ctx->config_path, config_setting_source_line(peer_cfg),
                  CFG_PEER_TYPE, tmp_peer_type);
        rc = -1;
        goto out;
    }
    rc = 0;

out:
    return rc;
}

static void free_peer(struct peer_item *peer)
{
    if (NULL != peer) {
        if (NULL != peer->peer.connection_password) {
            mem_free(peer->peer.connection_password);
        }
        mem_free(peer);
    }
}

static void free_binding(struct binding_item *binding)
{
    if (NULL != binding) {
        mem_free(binding);
    }
}

static int cfg_get_peers(struct cfg_ctx *ctx)
{
    int rc = 0;
    config_t *cfg = NULL;
    const config_setting_t *peers_cfg = NULL;
    const config_setting_t *peer_cfg = NULL;
    int peers_num = 0;
    int i = 0;
    struct peer_item *peer;
    struct peer_item *peer_tmp = NULL;

    PARAM_NULL_CHECK(rc, ctx);
    RC_CHECK(rc, out);

    cfg = &ctx->cfg;
    peers_cfg = config_lookup(cfg, CFG_PEERS);
    if (NULL == peers_cfg) {
        LOG_TRACE("Setting <%s> not found", CFG_PEERS);
        goto remove;
    }

    peers_num = config_setting_length(peers_cfg);
    if (0 == peers_num) {
        LOG_TRACE("<%s> setting list is empty", CFG_PEERS);
        goto remove;
    }

    peer = NULL;
    for (i = 0; i < peers_num; i++) {

        peer_cfg = config_setting_get_elem(peers_cfg, (unsigned)i);

        if (NULL == peer_cfg) {
            LOG_ERROR("failed to get item #%d from <%s> list setting", i,
                      CFG_PEERS);
            rc = -1;
            goto out;
        }

        if (config_setting_is_group(peer_cfg) != CONFIG_TRUE) {
            LOG_ERROR(
                "Peer #%d at file:line <%s:%u> error: Peer setting is not "
                "group item",
                i, ctx->config_path, config_setting_source_line(peer_cfg));
            rc = -1;
            goto out;
        }

        if (NULL == peer) {
            peer = mem_calloc(1, sizeof(*peer));
            if (NULL == peer) {
                rc = -1;
                goto out;
            }
        }

        rc = cfg_get_peer(ctx, peer_cfg, peer);
        if (RC_ISNOTOK(rc)) {
            LOG_ERROR("Peer #%d at file:line <%s:%u> error: Parse failed", i,
                      ctx->config_path, config_setting_source_line(peer_cfg));
            goto out;
        } else {
            LOG_DEBUG("Peer #%d at file:line <%s:%u> parse success", i,
                      ctx->config_path, config_setting_source_line(peer_cfg));
        }

        peer_tmp = (struct peer_item *)cfg_find_peer(ctx, peer->peer.ip_address,
                                                     peer->peer.port_is_set,
                                                     peer->peer.port);

        if ((NULL != peer_tmp) && ((LIST_ITEM_EXIST == peer_tmp->flag) ||
                                   (LIST_ITEM_ADDED == peer_tmp->flag))) {
            LOG_ERROR("Peer #%d at file:line <%s:%u> error: Peer is duplicated",
                      i, ctx->config_path,
                      config_setting_source_line(peer_cfg));
            rc = -1;
            goto out;
        }

        if ((NULL != peer_tmp) &&
            (cfg_peer_equal(&peer->peer, &peer_tmp->peer))) {
            peer_tmp->flag = LIST_ITEM_EXIST;
        } else {
            peer->flag = LIST_ITEM_ADDED;
            TAILQ_INSERT_TAIL(&ctx->peer_set.tailq_head, peer, tailq_entries);
            peer = NULL;
        }
    }

    if (NULL != peer) {
        free_peer(peer);
    }

remove:
    peer = TAILQ_FIRST(&ctx->peer_set.tailq_head);

    while (NULL != peer) {
        peer_tmp = peer;
        peer = TAILQ_NEXT(peer, tailq_entries);
        if (peer_tmp->flag == LIST_ITEM_ADDED) {
            rc = ctx->add_peer_cb(ctx->sxpd_ctx, &peer_tmp->peer);
            /* mark all added peers like going to be removed, on next
             * configuration reload*/
            peer_tmp->flag = LIST_ITEM_REMOVED;
        } else if (peer_tmp->flag == LIST_ITEM_REMOVED) {
            rc = ctx->del_peer_cb(ctx->sxpd_ctx, &peer_tmp->peer);
            TAILQ_REMOVE(&ctx->peer_set.tailq_head, peer_tmp, tailq_entries);
            free_peer(peer_tmp);
        } else {
            /* mark all added peers like going to be removed, on next
             * configuration reload*/
            peer_tmp->flag = LIST_ITEM_REMOVED;
        }
    }

out:
    return rc;
}

#ifdef ENABLE_STRICT_BINDING_CFG_CHECK
static int cfg_binding_strict_check(struct cfg_ctx *ctx,
                                    const config_setting_t *cs,
                                    struct binding_item *binding)
{
    int rc = 0;
    size_t i = 0;
    size_t j = 0;
    uint32_t netmask = 0;
    char ip[INET6_ADDRSTRLEN] = { '\0' };
    char exp_ip[INET6_ADDRSTRLEN] = { '\0' };

    PARAM_NULL_CHECK(rc, ctx, cs, binding);
    RC_CHECK(rc, out);

    if (PREFIX_IPV4 == binding->binding.type) {
        netmask =
            htonl((~(uint32_t)0) << (32 - binding->binding.prefix_length));

        if ((binding->binding.prefix.prefix_v4 & netmask) !=
            binding->binding.prefix.prefix_v4) {
            if (inet_ntop(AF_INET, &binding->binding.prefix.prefix_v4, ip,
                          INET_ADDRSTRLEN) == NULL) {
                LOG_ERROR(
                    "strict checker IPv4 address convert internal error ");
                rc = -1;
                goto out;
            }

            binding->binding.prefix.prefix_v4 &= netmask;
            if (inet_ntop(AF_INET, &binding->binding.prefix.prefix_v4, exp_ip,
                          INET_ADDRSTRLEN) == NULL) {
                LOG_ERROR(
                    "strict checker IPv4 address convert internal error ");
                rc = -1;
                goto out;
            }

            LOG_ERROR("Binding at file:line <%s:%u> error: Binding contains "
                      "invalid IPv4 prefix/length pair values <%s/%" PRIu8 ">. "
                      "Expected values are <%s/%" PRIu8 ">  ",
                      ctx->config_path, config_setting_source_line(cs), ip,
                      binding->binding.prefix_length, exp_ip,
                      binding->binding.prefix_length);
            rc = -1;
            goto out;
        }
    } else {
        if (binding->binding.prefix_length <= 32) {
            netmask =
                htonl((~(uint32_t)0) << (32 - binding->binding.prefix_length));
            i = 0;
        } else if (binding->binding.prefix_length <= 64) {
            netmask =
                htonl((~(uint32_t)0) << (64 - binding->binding.prefix_length));
            i = 1;
        } else if (binding->binding.prefix_length <= 96) {
            netmask =
                htonl((~(uint32_t)0) << (96 - binding->binding.prefix_length));
            i = 2;
        } else {
            netmask =
                htonl((~(uint32_t)0) << (128 - binding->binding.prefix_length));
            i = 3;
        }

        if ((binding->binding.prefix.prefix_v6[i] & netmask) !=
            binding->binding.prefix.prefix_v6[i]) {
            rc = -1;
        } else {
            for (j = i + 1; j < 4; ++j) {
                if ((binding->binding.prefix.prefix_v6[j] & ((uint32_t)0)) !=
                    binding->binding.prefix.prefix_v6[j]) {
                    rc = -1;
                    break;
                }
            }
        }

        if (RC_ISNOTOK(rc)) {
            if (inet_ntop(AF_INET6, binding->binding.prefix.prefix_v6, ip,
                          INET6_ADDRSTRLEN) == NULL) {
                LOG_ERROR(
                    "strict checker IPv6 address convert internal error ");
                rc = -1;
                goto out;
            }

            binding->binding.prefix.prefix_v6[i] &= netmask;
            for (j = i + 1; j < 4; ++j) {
                binding->binding.prefix.prefix_v6[j] &= ((uint32_t)0);
            }

            if (inet_ntop(AF_INET6, binding->binding.prefix.prefix_v6, exp_ip,
                          INET6_ADDRSTRLEN) == NULL) {
                LOG_ERROR(
                    "strict checker IPv6 address convert internal error ");
                rc = -1;
                goto out;
            }

            LOG_ERROR("Binding at file:line <%s:%u> error: Binding contains "
                      "invalid IPv6 prefix/length pair values <%s/%" PRIu8 ">. "
                      "Expected values are <%s/%" PRIu8 ">  ",
                      ctx->config_path, config_setting_source_line(cs), ip,
                      binding->binding.prefix_length, exp_ip,
                      binding->binding.prefix_length);
            rc = -1;
            goto out;
        }
    }

out:
    return rc;
}
#endif

static int cfg_get_binding(struct cfg_ctx *ctx,
                           const config_setting_t *binding_cfg,
                           struct binding_item *binding)
{
    int rc = 0;
    bool ipv4_prefix_length_is_set = false;
    const char *ipv4_prefix = NULL;
    int ipv4_prefix_length = 0;
    bool ipv6_prefix_length_is_set = false;
    const char *ipv6_prefix = NULL;
    int ipv6_prefix_length = 0;
    uint16_t sgt = 0;
    int cfg_ret = 0;
    int min = 0;
    int max = 0;
    int tmp = 0;

    PARAM_NULL_CHECK(rc, ctx, binding_cfg, binding);
    RC_CHECK(rc, out);

    if (config_setting_is_group(binding_cfg) != CONFIG_TRUE) {
        LOG_ERROR("Binding at file:line <%s:%u> error: Binding setting is not "
                  "group item",
                  ctx->config_path, config_setting_source_line(binding_cfg));
        rc = -1;
        goto out;
    }

    if (-1 == cfg_lookup_str(binding_cfg, CFG_BINDING_IPV4_PREFIX, NULL, NULL,
                             &ipv4_prefix, false)) {
        LOG_ERROR("Binding at file:line <%s:%u> error: Load binding setting "
                  "<%s> failed",
                  ctx->config_path, config_setting_source_line(binding_cfg),
                  CFG_BINDING_IPV4_PREFIX);
        rc = -1;
        goto out;
    }

    if (-1 == cfg_lookup_str(binding_cfg, CFG_BINDING_IPV6_PREFIX, NULL, NULL,
                             &ipv6_prefix, false)) {
        LOG_ERROR("Binding at file:line <%s:%u> error: Load binding setting "
                  "<%s> failed",
                  ctx->config_path, config_setting_source_line(binding_cfg),
                  CFG_BINDING_IPV6_PREFIX);
        rc = -1;
        goto out;
    }

    min = 0;
    max = UINT8_MAX;
    cfg_ret = cfg_lookup_int(binding_cfg, CFG_BINDING_IPV4_PREFIX_LENGTH, &min,
                             &max, &ipv4_prefix_length);
    ipv4_prefix_length_is_set = cfg_ret;
    if (-1 == cfg_ret) {
        LOG_ERROR("Binding at file:line <%s:%u> error: Load binding setting "
                  "<%s> failed",
                  ctx->config_path, config_setting_source_line(binding_cfg),
                  CFG_BINDING_IPV4_PREFIX_LENGTH);
        rc = -1;
        goto out;
    }

    min = 0;
    max = UINT8_MAX;
    cfg_ret = cfg_lookup_int(binding_cfg, CFG_BINDING_IPV6_PREFIX_LENGTH, &min,
                             &max, &ipv6_prefix_length);
    ipv6_prefix_length_is_set = cfg_ret;
    if (-1 == cfg_ret) {
        LOG_ERROR("Binding at file:line <%s:%u> error: Load binding setting "
                  "<%s> failed",
                  ctx->config_path, config_setting_source_line(binding_cfg),
                  CFG_BINDING_IPV6_PREFIX_LENGTH);
        rc = -1;
        goto out;
    }

    min = CFG_BINDING_SGT_MIN;
    max = CFG_BINDING_SGT_MAX;
    if (1 != cfg_lookup_int(binding_cfg, CFG_BINDING_SGT, &min, &max, &tmp)) {
        LOG_ERROR("Binding at file:line <%s:%u> error: Load binding setting "
                  "<%s> failed",
                  ctx->config_path, config_setting_source_line(binding_cfg),
                  CFG_BINDING_SGT);
        rc = -1;
        goto out;
    }

    sgt = (uint16_t)tmp;

    /* check of only one ip prefix type is set */
    if ((NULL != ipv4_prefix) && (NULL != ipv6_prefix)) {
        LOG_ERROR("Binding at file:line <%s:%u> error: Binding setting contain "
                  "both <%s> and <%s> settings",
                  ctx->config_path, config_setting_source_line(binding_cfg),
                  CFG_BINDING_IPV4_PREFIX, CFG_BINDING_IPV6_PREFIX);
        rc = -1;
        goto out;
    } else if ((NULL == ipv4_prefix) && (NULL == ipv6_prefix)) {
        LOG_ERROR("Binding at file:line <%s:%u> error: Binding setting does "
                  "not contain <%s> or <%s> setting",
                  ctx->config_path, config_setting_source_line(binding_cfg),
                  CFG_BINDING_IPV4_PREFIX, CFG_BINDING_IPV6_PREFIX);
        rc = -1;
        goto out;
    } else if ((true == ipv4_prefix_length_is_set) &&
               (true == ipv6_prefix_length_is_set)) {
        LOG_ERROR("Binding at file:line <%s:%u> error: Binding setting both "
                  "<%s> and <%s> settings",
                  ctx->config_path, config_setting_source_line(binding_cfg),
                  CFG_BINDING_IPV4_PREFIX_LENGTH,
                  CFG_BINDING_IPV6_PREFIX_LENGTH);
        rc = -1;
        goto out;
    } else if ((NULL != ipv4_prefix) && (false == ipv4_prefix_length_is_set)) {
        LOG_ERROR("Binding at file:line <%s:%u> error: Binding setting contain "
                  "<%s> but <%s> settings not found",
                  ctx->config_path, config_setting_source_line(binding_cfg),
                  CFG_BINDING_IPV4_PREFIX, CFG_BINDING_IPV4_PREFIX_LENGTH);
        rc = -1;
        goto out;
    } else if ((NULL != ipv6_prefix) && (false == ipv6_prefix_length_is_set)) {
        LOG_ERROR("Binding at file:line <%s:%u> error: Binding setting contain "
                  "<%s> but <%s> settings not found",
                  ctx->config_path, config_setting_source_line(binding_cfg),
                  CFG_BINDING_IPV6_PREFIX, CFG_BINDING_IPV6_PREFIX_LENGTH);
        rc = -1;
        goto out;
    }

    binding->binding.source_group_tag = sgt;
    if (NULL != ipv4_prefix) {
        binding->binding.type = PREFIX_IPV4;
        binding->binding.prefix_length = (uint8_t)ipv4_prefix_length;
        if (inet_pton(AF_INET, ipv4_prefix,
                      &binding->binding.prefix.prefix_v4) != 1) {
            LOG_ERROR("Binding at file:line <%s:%u> error: Binding setting "
                      "<%s> value <%s> is invalid",
                      ctx->config_path, config_setting_source_line(binding_cfg),
                      CFG_BINDING_IPV4_PREFIX, ipv4_prefix);
            rc = -1;
            goto out;
        }
    } else {
        binding->binding.type = PREFIX_IPV6;
        binding->binding.prefix_length = (uint8_t)ipv6_prefix_length;
        if (inet_pton(AF_INET6, ipv6_prefix,
                      &binding->binding.prefix.prefix_v6) != 1) {
            LOG_ERROR("Binding at file:line <%s:%u> error: Binding setting "
                      "<%s> value <%s> is invalid",
                      ctx->config_path, config_setting_source_line(binding_cfg),
                      CFG_BINDING_IPV6_PREFIX, ipv6_prefix);
            rc = -1;
            goto out;
        }
    }

#ifdef ENABLE_STRICT_BINDING_CFG_CHECK
    rc = cfg_binding_strict_check(ctx, binding_cfg, binding);
    if (RC_ISNOTOK(rc)) {
        LOG_ERROR("Binding at file:line <%s:%u> error: Binding IP/prefix "
                  "setting pair values are invalid",
                  ctx->config_path, config_setting_source_line(binding_cfg));
        goto out;
    }
#endif

out:
    return rc;
}

static int cfg_get_bindings_removing(struct cfg_ctx *ctx,
                                     enum prefix_type_e type)
{
    int rc = 0;
    struct radix_node *radix_node = NULL;
    struct radix_node *radix_node_next = NULL;
    struct binding_item *binding_tmp = NULL;

    PARAM_NULL_CHECK(rc, ctx);
    RC_CHECK(rc, out);

    rc = radix_iterate(cfg_get_binding_radix(ctx, type), radix_node,
                       &radix_node_next);
    if (RC_ISNOTOK(rc)) {
        LOG_ERROR("%s binding radix iteration failed: %d",
                  cfg_get_prefix_type_str(type), rc);
        goto out;
    }

    while (NULL != radix_node_next) {
        rc = radix_parse_node(radix_node_next, NULL, 0, NULL,
                              (void **)&binding_tmp);
        if (RC_ISNOTOK(rc)) {
            LOG_ERROR("%s binding radix node parse failed: %d",
                      cfg_get_prefix_type_str(type), rc);
            goto out;
        }
        assert(binding_tmp);

        radix_node = radix_node_next;
        rc = radix_iterate(cfg_get_binding_radix(ctx, type), radix_node,
                           &radix_node_next);
        if (RC_ISNOTOK(rc)) {
            LOG_ERROR("%s binding radix iteration failed: %d",
                      cfg_get_prefix_type_str(type), rc);
            goto out;
        }

        if (binding_tmp->flag == LIST_ITEM_REMOVED) {
            rc =
                radix_delete_node(cfg_get_binding_radix(ctx, type), radix_node);
            if (RC_ISNOTOK(rc)) {
                LOG_ERROR("%s binding radix node delete failed: %d",
                          cfg_get_prefix_type_str(type), rc);
                goto out;
            }

            rc = ctx->del_binding_cb(ctx->sxpd_ctx, &binding_tmp->binding);
            if (RC_ISNOTOK(rc)) {
                LOG_ERROR("sxpd %s binding radix node delete failed: %d",
                          cfg_get_prefix_type_str(type), rc);
                goto out;
            }

            free_binding(binding_tmp);
        } else {
            /* mark all added bindings like going to be removed, on next
             * configuration reload */
            binding_tmp->flag = LIST_ITEM_REMOVED;
        }
        binding_tmp = NULL;
    }

out:
    return rc;
}

static int cfg_get_bindings_fail_cleanup(struct cfg_ctx *ctx,
                                         enum prefix_type_e type)
{
    int rc = 0;
    struct radix_node *radix_node = NULL;
    struct radix_node *radix_node_next = NULL;
    struct binding_item *binding_tmp = NULL;

    PARAM_NULL_CHECK(rc, ctx);
    RC_CHECK(rc, out);

    radix_node = NULL;
    binding_tmp = NULL;

    rc = radix_iterate(cfg_get_binding_radix(ctx, type), radix_node,
                       &radix_node_next);
    if (RC_ISNOTOK(rc)) {
        LOG_ERROR("%s binding radix iteration failed: %d",
                  cfg_get_prefix_type_str(type), rc);
        goto out;
    }

    while (NULL != radix_node_next) {
        rc = radix_parse_node(radix_node_next, NULL, 0, NULL,
                              (void **)&binding_tmp);
        if (RC_ISNOTOK(rc)) {
            LOG_ERROR("%s binding radix node parse failed: %d",
                      cfg_get_prefix_type_str(type), rc);
            goto out;
        }
        assert(binding_tmp);

        radix_node = radix_node_next;
        rc = radix_iterate(cfg_get_binding_radix(ctx, type), radix_node,
                           &radix_node_next);
        if (RC_ISNOTOK(rc)) {
            LOG_ERROR("%s binding radix iteration failed: %d",
                      cfg_get_prefix_type_str(type), rc);
            goto out;
        }

        /* mark all added bindings like going to be removed, on next
         * configuration reload */
        binding_tmp->flag = LIST_ITEM_REMOVED;
        binding_tmp = NULL;
    }

out:
    return rc;
}

static int cfg_get_bindings(struct cfg_ctx *ctx)
{
    int rc = 0;
    config_t *cfg = NULL;
    const config_setting_t *bindings_cfg = NULL;
    const config_setting_t *binding_cfg = NULL;
    int bindings_num = 0;
    int i = 0;
    struct binding_item *binding = NULL;
    struct binding_item *binding_tmp = NULL;
    struct radix_node *radix_node = NULL;

    PARAM_NULL_CHECK(rc, ctx);
    RC_CHECK(rc, out);

    cfg = &ctx->cfg;
    bindings_cfg = config_lookup(cfg, CFG_BINDINGS);
    if (NULL == bindings_cfg) {
        LOG_TRACE("Setting <%s> not found", CFG_BINDINGS);
        goto remove;
    }

    bindings_num = config_setting_length(bindings_cfg);
    if (0 == bindings_num) {
        LOG_TRACE("<%s> setting list is empty", CFG_BINDINGS);
        goto remove;
    }

    binding = NULL;
    for (i = 0; i < bindings_num; i++) {

        binding_cfg = config_setting_get_elem(bindings_cfg, (unsigned)i);

        if (NULL == binding_cfg) {
            LOG_ERROR("failed to get item #%d from <%s> list setting", i,
                      CFG_BINDINGS);
            rc = -1;
            goto out;
        }

        if (config_setting_is_group(binding_cfg) != CONFIG_TRUE) {
            LOG_ERROR("Binding #%d at file:line <%s:%u> error: Binding setting "
                      "is not "
                      "group item",
                      i, ctx->config_path,
                      config_setting_source_line(binding_cfg));
            rc = -1;
            goto out;
        }

        if (NULL == binding) {
            binding = mem_calloc(1, sizeof(*binding));
            if (NULL == binding) {
                rc = -1;
                goto out;
            }
        }

        rc = cfg_get_binding(ctx, binding_cfg, binding);
        if (RC_ISNOTOK(rc)) {
            LOG_ERROR("%s binding #%d at file:line <%s:%u> error: Parse failed",
                      cfg_get_prefix_type_str(binding->binding.type), i,
                      ctx->config_path,
                      config_setting_source_line(binding_cfg));
            goto out;
        } else {
            LOG_DEBUG("%s binding #%d at file:line <%s:%u> parse success",
                      cfg_get_prefix_type_str(binding->binding.type), i,
                      ctx->config_path,
                      config_setting_source_line(binding_cfg));
        }

        rc =
            cfg_find_binding(ctx, &binding->binding, &radix_node, &binding_tmp);
        if (RC_ISNOTOK(rc)) {
            LOG_ERROR("find %s binding function failed: %d",
                      cfg_get_prefix_type_str(binding->binding.type), rc);
            goto out;
        }
        assert((radix_node && binding_tmp) || (!radix_node && !binding_tmp));

        if (NULL != binding_tmp) {
            if ((LIST_ITEM_EXIST == binding_tmp->flag) ||
                (LIST_ITEM_ADDED == binding_tmp->flag)) {
                LOG_ERROR(
                    "%s binding #%d at file:line <%s:%u> error: Binding is"
                    " duplicated",
                    cfg_get_prefix_type_str(binding->binding.type), i,
                    ctx->config_path, config_setting_source_line(binding_cfg));
                rc = -1;
                goto out;
            } else if (cfg_binding_equal(&binding->binding,
                                         &binding_tmp->binding)) {
                binding_tmp->flag = LIST_ITEM_EXIST;
            } else {
                binding->flag = LIST_ITEM_ADDED;
                rc = radix_node_set_value(radix_node, binding);
                if (RC_ISNOTOK(rc)) {
                    LOG_ERROR("store %s binding #%d in radix failed: %d",
                              cfg_get_prefix_type_str(binding->binding.type), i,
                              rc);
                    goto out;
                }
                rc = ctx->del_binding_cb(ctx->sxpd_ctx, &binding_tmp->binding);
                RC_CHECK(rc, out);
                free_binding(binding_tmp);
                rc = ctx->add_binding_cb(ctx->sxpd_ctx, &binding->binding);
                RC_CHECK(rc, out);
                binding = NULL;
            }
        } else {
            binding->flag = LIST_ITEM_ADDED;
            rc = cfg_store_binding(ctx, binding);
            if (RC_ISNOTOK(rc)) {
                LOG_ERROR("store %s binding #%d in radix failed: %d",
                          cfg_get_prefix_type_str(binding->binding.type), i,
                          rc);
                goto out;
            }
            ctx->add_binding_cb(ctx->sxpd_ctx, &binding->binding);
            binding = NULL;
        }
        binding_tmp = NULL;
        radix_node = NULL;
    }

remove:
    rc = cfg_get_bindings_removing(ctx, PREFIX_IPV4);
    if (RC_ISNOTOK(rc)) {
        LOG_ERROR("V4 bindings removing failed: %d", rc);
        goto out;
    }

    rc = cfg_get_bindings_removing(ctx, PREFIX_IPV6);
    if (RC_ISNOTOK(rc)) {
        LOG_ERROR("V6 bindings removing failed: %d", rc);
        goto out;
    }

    LOG_TRACE("Successfully loaded %d binding items", bindings_num);

out:
    if (RC_ISNOTOK(rc)) {
        rc = cfg_get_bindings_fail_cleanup(ctx, PREFIX_IPV4);
        assert(RC_ISOK(rc));
        rc = cfg_get_bindings_fail_cleanup(ctx, PREFIX_IPV6);
        assert(RC_ISOK(rc));
        rc = -1;
    }

    if (NULL != binding) {
        free_binding(binding);
    }

    return rc;
}

static const char *cfg_type_to_str(enum cfg_pattern_type type)
{
    const char *ret = NULL;
    static const char *cfg_type_str[] = { TUPLE_CFG_PATTERN_TYPE_DEF(
        TUPLE_CFG_PATTERN_TYPE_STR) };

    if (type < CFG_IS_LAST) {
        ret = cfg_type_str[type];
    }

    return ret;
}

/**
 * @brief get string type of configuration setting
 */
static const char *config_setting_str_type(const config_setting_t *cs)
{
    int rc = 0;
    const char *ret = NULL;

    PARAM_NULL_CHECK(rc, cs);
    RC_CHECK(rc, out);

    if ((config_setting_is_group(cs) == CONFIG_TRUE)) {
        ret = "group";
    } else if (config_setting_is_list(cs) == CONFIG_TRUE) {
        ret = "list";
    } else if (config_setting_is_number(cs) == CONFIG_TRUE) {
        ret = "number";
    } else if (cs->type == CONFIG_TYPE_BOOL) {
        ret = "bool";
    } else if (cs->type == CONFIG_TYPE_STRING) {
        ret = "string";
    }

out:
    return ret;
}

static bool cfg_pattern_match_setting_type(struct cfg_pattern *pn,
                                           const config_setting_t *cs)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, pn, cs);
    assert(RC_ISOK(rc));

    if ((pn->val_type == CFG_IS_GROUP) &&
        (config_setting_is_group(cs) == CONFIG_TRUE)) {
        return true;
    } else if ((pn->val_type == CFG_IS_LIST) &&
               (config_setting_is_list(cs) == CONFIG_TRUE)) {
        return true;
    } else if ((pn->val_type == CFG_IS_NUM) &&
               (config_setting_is_number(cs) == CONFIG_TRUE)) {
        return true;
    } else if ((pn->val_type == CFG_IS_BOOL) &&
               (cs->type == CONFIG_TYPE_BOOL)) {
        return true;
    } else if ((pn->val_type == CFG_IS_STR) &&
               (cs->type == CONFIG_TYPE_STRING)) {
        return true;
    }

    return false;
}

static bool cfg_pattern_match_setting(struct cfg_pattern *pp,
                                      const config_setting_t *cs)
{
    int rc = 0;
    const char *cs_name = NULL;

    PARAM_NULL_CHECK(rc, pp, cs);
    assert(RC_ISOK(rc));

    cs_name = config_setting_name(cs);

    if (cfg_pattern_match_setting_type(pp, cs) &&
        (((!cs_name) && (!pp->name)) ||
         ((cs_name) && (pp->name) && (strcmp(pp->name, cs_name) == 0)))) {
        return true;
    }

    return false;
}

static int cfg_validate_content_elem(struct cfg_ctx *ctx,
                                     const config_setting_t *cs,
                                     struct cfg_pattern *pn, bool *failed);

static int cfg_validate_content_elem_aggregate(struct cfg_ctx *ctx,
                                               const config_setting_t *cs,
                                               struct cfg_pattern *pn,
                                               bool *failed)
{
    int rc = 0;
    unsigned i = 0;
    size_t j = 0;
    unsigned cs_len = 0;
    const config_setting_t *cs_child = NULL;
    const char *cs_child_name = NULL;
    struct cfg_pattern *pn_child = NULL;

    PARAM_NULL_CHECK(rc, ctx, cs, pn, failed);
    RC_CHECK(rc, out);

    /* list all child elements and find matching patterns */
    int tmp = config_setting_length(cs);
    if (tmp < 0) {
        LOG_ERROR("Unexpected value %d of config setting length", tmp);
        rc = -1;
        goto out;
    }

    cs_len = (unsigned)tmp;
    for (i = 0; i < cs_len; ++i) {
        cs_child = config_setting_get_elem(cs, i);
        if (NULL == cs_child) {
            LOG_ERROR("failed to get #%d item from <%s> setting", i, pn->name);
            rc = -1;
            goto out;
        }

        cs_child_name = config_setting_name(cs_child);
        pn_child = NULL;
        for (j = 0; j < pn->child_num; ++j) {
            if (cfg_pattern_match_setting(&pn->child[j], cs_child)) {
                pn_child = &pn->child[j];
                rc = cfg_validate_content_elem(ctx, cs_child, pn_child, failed);
                RC_CHECK(rc, out);
                break;
            }
        }

        if (NULL == pn_child) {
            LOG_ERROR("configuration error in file <%s> at line <%u>: "
                      "configuration setting <%s> of type <%s> contains "
                      "unrecognized setting <%s> of type <%s>",
                      ctx->config_path, config_setting_source_line(cs_child),
                      pn->name ? pn->name : pn->desc,
                      cfg_type_to_str(pn->val_type), cs_child_name,
                      config_setting_str_type(cs_child));
            LOG_ERROR("expected settings are:");
            for (j = 0; j < pn->child_num; ++j) {
                LOG_ERROR("#%zu setting <%s> of type <%s> ", j,
                          pn->child[j].name,
                          cfg_type_to_str(pn->child[j].val_type));
            }

            *failed = 1;
        }
    }

out:
    return rc;
}

static int cfg_validate_content_elem_number(struct cfg_ctx *ctx,
                                            const config_setting_t *cs,
                                            struct cfg_pattern *pn,
                                            bool *failed)
{
    int rc = 0;
    int64_t num = 0;
    long long int tmp_ll = 0;

    PARAM_NULL_CHECK(rc, ctx, cs, pn, failed);
    RC_CHECK(rc, out);

    tmp_ll = config_setting_get_int64(cs);
    num = (int64_t)tmp_ll;
    if ((num < pn->limit.l.range.min) || (num > pn->limit.l.range.max)) {
        LOG_ERROR("configuration error in file <%s> at line <%u>: "
                  "configuration setting <%s> of type <%s> value "
                  "<%" PRId64 "> is out of range [%" PRId64 " ... %" PRId64 "]",
                  ctx->config_path, config_setting_source_line(cs),
                  pn->name ? pn->name : pn->desc, cfg_type_to_str(pn->val_type),
                  num, pn->limit.l.range.min, pn->limit.l.range.max);
        *failed = 1;
        goto out;
    }

out:
    return rc;
}

static int cfg_validate_content_elem_string(struct cfg_ctx *ctx,
                                            const config_setting_t *cs,
                                            struct cfg_pattern *pn,
                                            bool *failed)
{
    int rc = 0;
    int i = 0;
    const char *str = NULL;
    size_t str_len = 0;
    bool str_enum_match = false;
    uint32_t tmp_ip[4] = { 0, 0, 0, 0 };

    PARAM_NULL_CHECK(rc, ctx, cs, pn, failed);
    RC_CHECK(rc, out);

    str = config_setting_get_string(cs);
    assert(NULL != str);
    str_len = strlen(str);
    if (VALUE_PATTERN_STR_LENGTH == pn->limit.type) {
        if ((str_len < pn->limit.l.str_length.min) ||
            (str_len > pn->limit.l.str_length.max)) {
            LOG_ERROR("configuration error in file <%s> at line <%u>: "
                      "configuration setting <%s> of type <%s> value "
                      "<%s> length <%" PRId64 "> is out of range [%" PRId64
                      " ... %" PRId64 "]",
                      ctx->config_path, config_setting_source_line(cs),
                      pn->name ? pn->name : pn->desc,
                      cfg_type_to_str(pn->val_type), str, str_len,
                      pn->limit.l.str_length.min, pn->limit.l.str_length.max);
            *failed = 1;
            goto out;
        }

    } else if (VALUE_PATTERN_STR_ENUM == pn->limit.type) {
        str_enum_match = false;
        for (i = 0; pn->limit.l.str_enum.str_enum[i] != NULL; ++i) {
            if (strncmp(str, pn->limit.l.str_enum.str_enum[i], str_len + 1) ==
                0) {
                str_enum_match = true;
                break;
            }
        }

        if (false == str_enum_match) {
            LOG_ERROR("configuration error in file <%s> at line <%u>: "
                      "configuration setting <%s> of type <%s> value "
                      "<%s> is invalid.",
                      ctx->config_path, config_setting_source_line(cs),
                      pn->name ? pn->name : pn->desc,
                      cfg_type_to_str(pn->val_type), str);
            LOG_ERROR("Valid values are:");
            for (i = 0; pn->limit.l.str_enum.str_enum[i] != NULL; ++i) {
                LOG_ERROR("#%d <%s>", i, pn->limit.l.str_enum.str_enum[i]);
            }
            *failed = 1;
            goto out;
        }
    } else if (VALUE_PATTERN_IPV4 == pn->limit.type) {
        if (inet_pton(AF_INET, str, &tmp_ip) != 1) {
            LOG_ERROR("configuration error in file <%s> at line <%u>: "
                      "configuration setting <%s> of type <%s> value "
                      "<%s> is invalid IPv4 address",
                      ctx->config_path, config_setting_source_line(cs),
                      pn->name ? pn->name : pn->desc,
                      cfg_type_to_str(pn->val_type), str);
            *failed = 1;
            goto out;
        }
    } else if (VALUE_PATTERN_IPV6 == pn->limit.type) {
        if (inet_pton(AF_INET6, str, &tmp_ip) != 1) {
            LOG_ERROR("configuration error in file <%s> at line <%u>: "
                      "configuration setting <%s> of type <%s> value "
                      "<%s> is invalid IPv6 address",
                      ctx->config_path, config_setting_source_line(cs),
                      pn->name ? pn->name : pn->desc,
                      cfg_type_to_str(pn->val_type), str);
            *failed = 1;
            goto out;
        }
    }

out:
    return rc;
}

static int cfg_validate_content_elem(struct cfg_ctx *ctx,
                                     const config_setting_t *cs,
                                     struct cfg_pattern *pn, bool *failed)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, ctx, cs, pn, failed);
    RC_CHECK(rc, out);

    if ((CFG_IS_GROUP == pn->val_type) || (CFG_IS_LIST == pn->val_type)) {
        rc = cfg_validate_content_elem_aggregate(ctx, cs, pn, failed);
        RC_CHECK(rc, out);
    } else if ((CFG_IS_NUM == pn->val_type) &&
               (VALUE_PATTERN_NONE != pn->limit.type)) {
        rc = cfg_validate_content_elem_number(ctx, cs, pn, failed);
        RC_CHECK(rc, out);
    } else if ((CFG_IS_STR == pn->val_type) &&
               (VALUE_PATTERN_NONE != pn->limit.type)) {
        rc = cfg_validate_content_elem_string(ctx, cs, pn, failed);
        RC_CHECK(rc, out);
    }

    /* if previous checking of pattern not failed and custom check callback is
     * set, call it */
    if (NULL != pn->check_cb) {
        rc = pn->check_cb(ctx, cs, pn, failed);
        RC_CHECK(rc, out);
    }

out:
    return rc;
}

static int cfg_validate_binding_cb(struct cfg_ctx *ctx,
                                   const config_setting_t *cs,
                                   struct cfg_pattern *pn, bool *failed)
{
    int rc = 0;

    static struct binding_item binding = {
        .flag = LIST_ITEM_ADDED,
        .binding =
            {
             .type = PREFIX_IPV4,
             .prefix.prefix_v4 = 0,
             .prefix_length = 0,
             .source_group_tag = 0,
            },
    };

    struct binding_item *binding_tmp = NULL;
    struct radix_node *radix_node = NULL;

    PARAM_NULL_CHECK(rc, ctx, cs, pn, failed);
    RC_CHECK(rc, out);

    rc = cfg_get_binding(ctx, cs, &binding);
    if (RC_ISNOTOK(rc)) {
        LOG_ERROR("configuration error in file <%s> at line <%u>: "
                  "configuration setting <%s> of type <%s> is invalid",
                  ctx->config_path, config_setting_source_line(cs),
                  pn->name ? pn->name : pn->desc,
                  cfg_type_to_str(pn->val_type));
        rc = 0;
        *failed = 1;
        goto out;
    }

    rc = cfg_find_binding(ctx, &binding.binding, &radix_node, &binding_tmp);
    if (RC_ISNOTOK(rc)) {
        LOG_ERROR("find %s binding function failed: %d",
                  cfg_get_prefix_type_str(binding.binding.type), rc);
        goto out;
    }
    assert((radix_node && binding_tmp) || (!radix_node && !binding_tmp));

    if (NULL != binding_tmp) {
        if ((LIST_ITEM_EXIST == binding_tmp->flag) ||
            (LIST_ITEM_ADDED == binding_tmp->flag)) {
            LOG_ERROR("%s binding at file:line <%s:%u> error: Binding is"
                      " duplicated",
                      cfg_get_prefix_type_str(binding.binding.type),
                      ctx->config_path, config_setting_source_line(cs));
            *failed = 1;
            goto out;
        } else if (cfg_binding_equal(&binding.binding, &binding_tmp->binding)) {
            binding_tmp->flag = LIST_ITEM_EXIST;
        } else {
            binding_tmp->flag = LIST_ITEM_EXIST;
        }
    } else {
        rc = cfg_store_binding(ctx, &binding);
        if (RC_ISNOTOK(rc)) {
            LOG_ERROR("store %s binding in radix failed: %d",
                      cfg_get_prefix_type_str(binding.binding.type), rc);
            goto out;
        }
    }

out:
    return rc;
}

int cfg_validate_bindings_cleanup_cb(struct radix_node *node,
                                     __attribute__((unused)) void *ctx)
{
    int rc = 0;
    struct binding_item *binding_tmp = NULL;

    assert(node);

    /* binding value is in fact static variable so it must not be freed */
    rc = radix_parse_node(node, NULL, 0, NULL, (void **)&binding_tmp);
    assert(RC_ISOK(rc));
    assert(binding_tmp);

    if (LIST_ITEM_ADDED == binding_tmp->flag) {
        rc = 1;
    } else {
        binding_tmp->flag = LIST_ITEM_REMOVED;
    }

    return rc;
}

static int cfg_validate_bindings_cleanup(struct cfg_ctx *ctx,
                                         enum prefix_type_e type, bool *failed)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, ctx, failed);
    RC_CHECK(rc, out);

    rc = radix_delete_matching(cfg_get_binding_radix(ctx, type),
                               cfg_validate_bindings_cleanup_cb, NULL);
    if (RC_ISNOTOK(rc)) {
        LOG_ERROR("%s binding radix iteration failed: %d",
                  cfg_get_prefix_type_str(type), rc);
        goto out;
    }

out:
    return rc;
}

static int cfg_validate_bindings_cb(struct cfg_ctx *ctx,
                                    const config_setting_t *cs,
                                    struct cfg_pattern *pn, bool *failed)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, ctx, cs, pn, failed);
    RC_CHECK(rc, out);

    rc = cfg_validate_bindings_cleanup(ctx, PREFIX_IPV4, failed);
    if (RC_ISNOTOK(rc)) {
        LOG_ERROR("V4 bindings validate internal error: %d", rc);
        goto out;
    }

    rc = cfg_validate_bindings_cleanup(ctx, PREFIX_IPV6, failed);
    if (RC_ISNOTOK(rc)) {
        LOG_ERROR("V6 bindings validate internal error: %d", rc);
        goto out;
    }

out:
    return rc;
}

static int cfg_validate_peers_cb(struct cfg_ctx *ctx,
                                 const config_setting_t *cs,
                                 struct cfg_pattern *pn, bool *failed)
{
    int rc = 0;
    struct peer_item *peer;
    struct peer_item *peer_tmp = NULL;

    PARAM_NULL_CHECK(rc, ctx, cs, pn, failed);
    RC_CHECK(rc, out);

    peer = TAILQ_FIRST(&ctx->peer_set.tailq_head);

    while (NULL != peer) {
        peer_tmp = peer;
        peer = TAILQ_NEXT(peer, tailq_entries);
        if (peer_tmp->flag == LIST_ITEM_ADDED) {
            TAILQ_REMOVE(&ctx->peer_set.tailq_head, peer_tmp, tailq_entries);
            free_peer(peer_tmp);
        } else {
            /* mark all added peers like going to be removed, on next
             * configuration reload*/
            peer_tmp->flag = LIST_ITEM_REMOVED;
        }
    }

out:
    return rc;
}

static int cfg_validate_peer_cb(struct cfg_ctx *ctx, const config_setting_t *cs,
                                struct cfg_pattern *pn, bool *failed)
{
    int rc = 0;
    struct peer_item *peer = NULL;
    struct peer_item *peer_tmp = NULL;

    PARAM_NULL_CHECK(rc, ctx, cs, pn, failed);
    RC_CHECK(rc, out);

    peer = mem_calloc(1, sizeof(*peer));
    if (NULL == peer) {
        rc = -1;
        LOG_ERROR("Out of memory to create new peer item");
        goto out;
    }

    rc = cfg_get_peer(ctx, cs, peer);

    if (RC_ISNOTOK(rc)) {
        LOG_ERROR("configuration error in file <%s> at line <%u>: "
                  "configuration setting <%s> of type <%s> is invalid",
                  ctx->config_path, config_setting_source_line(cs),
                  pn->name ? pn->name : pn->desc,
                  cfg_type_to_str(pn->val_type));
        rc = 0;
        *failed = 1;
        goto out;
    }

    peer_tmp = (struct peer_item *)cfg_find_peer(
        ctx, peer->peer.ip_address, peer->peer.port_is_set, peer->peer.port);

    if ((NULL != peer_tmp) && ((LIST_ITEM_EXIST == peer_tmp->flag) ||
                               (LIST_ITEM_ADDED == peer_tmp->flag))) {
        LOG_ERROR("Peer at file:line <%s:%u> error: Peer is duplicated",
                  ctx->config_path, config_setting_source_line(cs));
        *failed = true;
        goto out;
    } else if ((NULL != peer_tmp) &&
               (cfg_peer_equal(&peer->peer, &peer_tmp->peer))) {
        peer_tmp->flag = LIST_ITEM_EXIST;
    } else {
        peer->flag = LIST_ITEM_ADDED;
        TAILQ_INSERT_TAIL(&ctx->peer_set.tailq_head, peer, tailq_entries);
        peer = NULL;
    }
out:

    if (NULL != peer) {
        free_peer(peer);
        peer = NULL;
    }
    return rc;
}

/**
 * @brief validate configuration file content
 *
 * @param ctx configuration context
 * @return 0 on configuration validation success, 1 on configuration validation
 *           syntax error, -1 on internal error
 */
static int cfg_validate_content(struct cfg_ctx *ctx)
{
    int rc = 0;
    const config_t *cfg = NULL;
    const config_setting_t *root = NULL;
    bool failed = false;

    PARAM_NULL_CHECK(rc, ctx);
    RC_CHECK(rc, out);

    cfg = &ctx->cfg;
    root = config_root_setting(cfg);
    if (config_setting_is_root(root) != CONFIG_TRUE) {
        LOG_ERROR("internal error: configuration setting root is not group");
        rc = -1;
        goto out;
    }

    rc = cfg_validate_content_elem(ctx, root, &cfg_pn, &failed);
    if (RC_ISNOTOK(rc)) {
        LOG_ERROR("Configuration content validation internal error: %d", rc);
        goto out;
    }

    if (true == failed) {
        LOG_ERROR("configuration content validation error: %d", rc);
        rc = 1;
        goto out;
    }

out:
    return rc;
}

static int cfg_reload_test(struct cfg_ctx *ctx)
{
    int rc = 0;
    config_t *cfg = NULL;
    char error_str[ERROR_SIZE];

    PARAM_NULL_CHECK(rc, ctx, ctx->config_path);
    RC_CHECK(rc, out);

    if (true == ctx->cfg_is_read) {
        LOG_ERROR("Libconfig configuration already loaded internal error");
        assert(0);
    }

    rc = cfg_validate(ctx->config_path, error_str, ERROR_SIZE);
    if (RC_ISNOTOK(rc)) {
        if (1 == rc) {
            LOG_ALERT("Configuration syntax error: %d: %s", rc, error_str);
            rc = -1;
        } else {
            LOG_ERROR("Configuration validation error: %d", rc);
        }
        goto out;
    }
    LOG_TRACE("Configuration validation success: %d", rc);

    /* read configuration file */
    cfg = &ctx->cfg;
    config_init(cfg);
    if (CONFIG_TRUE != config_read_file(cfg, ctx->config_path)) {
        LOG_ERROR("Configuration <%s> read failed: %s:%d: '%s'",
                  ctx->config_path, config_error_file(cfg),
                  config_error_line(cfg), config_error_text(cfg));
        config_destroy(cfg);
        rc = -1;
        goto out;
    }
    ctx->cfg_is_read = true;

    rc = cfg_validate_content(ctx);
    if (RC_ISNOTOK(rc)) {
        if (1 == rc) {
            LOG_ALERT("Configuration content validation error: %d", rc);
            rc = -1;
        } else {
            LOG_ERROR("Configuration content validation internal error: %d",
                      rc);
        }
        goto out;
    }
    LOG_TRACE("Configuration content validation success: %d", rc);

out:
    if (RC_ISNOTOK(rc)) {
        if (NULL != ctx) {
            if (true == ctx->cfg_is_read) {
                ctx->cfg_is_read = false;
                config_destroy(cfg);
            }
        }
    }

    return rc;
}

static int cfg_reload_real(struct cfg_ctx *ctx)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, ctx, ctx->config_path);
    RC_CHECK(rc, out);

    if (false == ctx->cfg_is_read) {
        LOG_ERROR("Libconfig configuration not loaded internal error");
        assert(0);
    }

    rc = cfg_get_global(ctx);
    if (RC_ISNOTOK(rc)) {
        LOG_ERROR("Get global configuration failed: %d", rc);
        goto out;
    }
    LOG_TRACE("Get global configuration success: %d", rc);

    rc = cfg_get_peers(ctx);
    if (RC_ISNOTOK(rc)) {
        LOG_ERROR("Get peers configuration failed: %d", rc);
        goto out;
    }
    LOG_TRACE("Get peers configuration success: %d", rc);

    rc = cfg_get_bindings(ctx);
    if (RC_ISNOTOK(rc)) {
        LOG_ERROR("Get bindings configuration failed: %d", rc);
        goto out;
    }
    LOG_TRACE("Get bindings configuration success: %d", rc);

    if (RC_ISOK(rc)) {
        LOG_TRACE("Configuration <%s> read success", ctx->config_path);
    }

out:
    if (NULL != ctx) {
        if (true == ctx->cfg_is_read) {
            ctx->cfg_is_read = false;
            config_destroy(&ctx->cfg);
        }
    }

    return rc;
}

static int cfg_reload(struct cfg_ctx *ctx)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, ctx, ctx->config_path);
    RC_CHECK(rc, out);

    rc = cfg_reload_test(ctx);
    RC_CHECK(rc, out);

    rc = cfg_reload_real(ctx);
    RC_CHECK(rc, out);

out:
    if (NULL != ctx) {
        if (true == ctx->cfg_is_read) {
            config_destroy(&ctx->cfg);
        }
    }

    return rc;
}

static void cfg_reload_real_cb(struct evmgr_timer *timer, void *cfg_ctx)
{
    int rc = 0;
    struct cfg_ctx *ctx = NULL;

    PARAM_NULL_CHECK(rc, timer, cfg_ctx);
    RC_CHECK(rc, out);

    ctx = cfg_ctx;

    rc = pthread_mutex_lock(&ctx->cfg_reload_mutex);
    if (RC_ISNOTOK(rc)) {
        LOG_ERROR("cfg reload handler mutex lock failed: %d", rc);
        assert(0);
    }

    if (ctx->cfg_reload_status == CFG_RELOAD_AGAIN) {
        ctx->cfg_reload_status = CFG_RELOAD_NOT_RUNNING;
        kill(getpid(), SIGHUP);
    } else {
        ctx->cfg_reload_status = CFG_RELOAD_NOT_RUNNING;

        rc = cfg_reload_real(ctx);
        if (RC_ISNOTOK(rc)) {
            LOG_ERROR("Configuration reload failed: %d", rc);
        }
    }

    rc = pthread_mutex_unlock(&ctx->cfg_reload_mutex);
    if (RC_ISNOTOK(rc)) {
        LOG_ERROR("cfg reload handler mutex unlock failed: %d", rc);
        assert(0);
    }
out:
    return;
}

static void *cfg_reload_test_thread(void *cfg_ctx)
{
    int rc = 0;
    int tmp_rc = 0;
    struct cfg_ctx *ctx = NULL;

    assert(cfg_ctx);
    ctx = cfg_ctx;

    LOG_DEBUG("asynchronous configuration reload started");

test_again:
    rc = cfg_reload_test(ctx);

    tmp_rc = pthread_mutex_lock(&ctx->cfg_reload_mutex);
    if (RC_ISNOTOK(tmp_rc)) {
        LOG_ERROR("cfg reload handler mutex lock failed: %d", tmp_rc);
        assert(0);
    }

    if (ctx->cfg_reload_status == CFG_RELOAD_AGAIN) {
        ctx->cfg_reload_status = CFG_RELOAD_RUNNING;
        tmp_rc = pthread_mutex_unlock(&ctx->cfg_reload_mutex);
        if (RC_ISNOTOK(tmp_rc)) {
            LOG_ERROR("cfg reload handler mutex unlock failed: %d", tmp_rc);
            assert(0);
        }
        if (true == ctx->cfg_is_read) {
            ctx->cfg_is_read = false;
            config_destroy(&ctx->cfg);
        }
        goto test_again;
    } else if (RC_ISNOTOK(rc)) {
        ctx->cfg_reload_status = CFG_RELOAD_NOT_RUNNING;
        LOG_ERROR("Asynchronous configuration validation failed: %d", rc);
        tmp_rc = pthread_mutex_unlock(&ctx->cfg_reload_mutex);
        if (RC_ISNOTOK(tmp_rc)) {
            LOG_ERROR("cfg reload handler mutex unlock failed: %d", tmp_rc);
            assert(0);
        }
        goto out;
    }

    tmp_rc = pthread_mutex_unlock(&ctx->cfg_reload_mutex);
    if (RC_ISNOTOK(tmp_rc)) {
        LOG_ERROR("cfg reload handler mutex unlock failed: %d", tmp_rc);
        assert(0);
    }

    rc = evmgr_timer_arm(ctx->cfg_reload_timer);
    if (RC_ISNOTOK(rc)) {
        LOG_ERROR("Asynchronous configuration validation timer arm failed: %d",
                  rc);
        assert(0);
    }

out:
    LOG_DEBUG("asynchronous configuration reload finished");
    pthread_exit(NULL);
}

static struct evmgr_sig_handler *signal_handler = NULL;

void cfg_ctx_destroy(struct cfg_ctx *ctx)
{
    config_t *cfg = NULL;
    struct peer_item *peer_prev = NULL;
    struct peer_item *peer_next = NULL;

    /* unregister previously registered SIGHUP */
    if (signal_handler) {
        evmgr_sig_handler_destroy(signal_handler);
        signal_handler = NULL;
    }

    if (ctx) {
        cfg = &ctx->cfg;
        config_destroy(cfg);

        radix_destroy(ctx->v4binding_set, mem_free);
        radix_destroy(ctx->v6binding_set, mem_free);

        TAILQ_FOREACH(peer_next, &ctx->peer_set.tailq_head, tailq_entries)
        {
            free_peer(peer_prev);
            peer_prev = peer_next;
        }
        free_peer(peer_prev);

        ctx->cfg_is_read = false;
        pthread_mutex_destroy(&ctx->cfg_reload_mutex);
        ctx->cfg_reload_status = CFG_RELOAD_NOT_RUNNING;
        if (NULL != ctx->cfg_reload_timer) {
            evmgr_timer_disarm(ctx->cfg_reload_timer);
            evmgr_timer_destroy(ctx->cfg_reload_timer);
            ctx->cfg_reload_timer = NULL;
        }

        mem_free(ctx);
    }

    return;
}

int cfg_ctx_create(struct cfg_ctx **ctx, const char *cfg_string,
                   struct evmgr_settings **evmgr_settings)
{
    int rc = 0;
    struct cfg_ctx *ctx_ = NULL;
    struct evmgr_settings *evmgr_settings_ = NULL;

    PARAM_NULL_CHECK(rc, ctx, cfg_string, evmgr_settings);
    RC_CHECK(rc, out);

    ctx_ = mem_calloc(1, sizeof(*ctx_));
    if (NULL == ctx_) {
        LOG_ERROR("Configuration context allocation failed");
        rc = -1;
        goto out;
    }

    evmgr_settings_ = mem_calloc(1, sizeof(*evmgr_settings_));
    if (NULL == evmgr_settings_) {
        LOG_ERROR("Event manager settings allocation failed");
        rc = -1;
        goto out;
    }

    ctx_->v4binding_set = radix_create(CFG_RADIX_V4_MAXBITS);
    if (NULL == ctx_->v4binding_set) {
        LOG_ERROR("v4 binding radix tree create failed");
        rc = -1;
        goto out;
    }

    ctx_->v6binding_set = radix_create(CFG_RADIX_V6_MAXBITS);
    if (NULL == ctx_->v6binding_set) {
        LOG_ERROR("v6 binding radix tree create failed");
        rc = -1;
        goto out;
    }

    ctx_->cfg_is_read = false;
    pthread_mutex_init(&ctx_->cfg_reload_mutex, NULL);
    ctx_->cfg_reload_status = CFG_RELOAD_NOT_RUNNING;
    ctx_->cfg_reload_timer = NULL;

    /* process configuration parameter */
    ctx_->config_path = cfg_string;

    /* init config lists */
    TAILQ_INIT(&ctx_->peer_set.tailq_head);

    /* fill configuration context callbacks */
    ctx_->add_uint_cb = NULL;
    ctx_->del_uint_cb = NULL;
    ctx_->add_str_cb = NULL;
    ctx_->del_str_cb = NULL;
    ctx_->add_peer_cb = NULL;
    ctx_->del_peer_cb = NULL;
    ctx_->add_binding_cb = NULL;
    ctx_->del_binding_cb = NULL;
    ctx_->global_settings_is_loaded = false;

    *ctx = ctx_;
    *evmgr_settings = evmgr_settings_;

out:

    if (RC_ISNOTOK(rc)) {
        if (NULL != ctx_) {
            if (NULL != ctx_->v4binding_set) {
                mem_free(ctx_->v4binding_set);
            }

            if (NULL != ctx_->v6binding_set) {
                mem_free(ctx_->v6binding_set);
            }
            mem_free(ctx_);
        }

        if (NULL != evmgr_settings_) {
            mem_free(evmgr_settings_);
        }
    }

    return rc;
}

static void cfg_signal_callback(
    __attribute__((unused)) struct evmgr_sig_handler *sig_handler, int signum,
    void *cfg_ctx)
{
    int rc = 0;
    int mutex_rc = 0;
    struct cfg_ctx *ctx = NULL;

    PARAM_NULL_CHECK(rc, cfg_ctx);
    RC_CHECK(rc, out);

    if (SIGHUP == signum) {
        LOG_DEBUG("Caught SIGHUP, reloading configuration");
        ctx = cfg_ctx;

        mutex_rc = pthread_mutex_lock(&ctx->cfg_reload_mutex);
        if (RC_ISNOTOK(mutex_rc)) {
            LOG_ERROR("cfg reload handler mutex lock failed: %d", mutex_rc);
            assert(0);
        }

        if (ctx->cfg_reload_status == CFG_RELOAD_NOT_RUNNING) {
            rc = pthread_create(&ctx->cfg_reload_thread, NULL,
                                cfg_reload_test_thread, ctx);
            if (RC_ISNOTOK(rc)) {
                LOG_ERROR("cfg reload thread start failed: %d", rc);
            } else {
                ctx->cfg_reload_status = CFG_RELOAD_RUNNING;
            }
        } else {
            ctx->cfg_reload_status = CFG_RELOAD_AGAIN;
        }

        mutex_rc = pthread_mutex_unlock(&ctx->cfg_reload_mutex);
        if (RC_ISNOTOK(mutex_rc)) {
            LOG_ERROR("cfg reload handler mutex unlock failed: %d", mutex_rc);
            assert(0);
        }
    }

out:
    return;
}

int cfg_register_callbacks(struct cfg_ctx *ctx, struct evmgr *evmgr,
                           struct sxpd_ctx *sxpd_ctx,
                           cfg_add_uint32_setting_callback add_uint_cb,
                           cfg_del_uint32_setting_callback del_uint_cb,
                           cfg_add_str_setting_callback add_str_cb,
                           cfg_del_str_setting_callback del_str_cb,
                           cfg_add_peer_callback add_peer_cb,
                           cfg_del_peer_callback del_peer_cb,
                           cfg_add_binding_callback add_binding_cb,
                           cfg_del_binding_callback del_binding_cb)
{
    int rc = 0;
    struct timeval tv = {.tv_sec = 0, .tv_usec = 0 };

    PARAM_NULL_CHECK(rc, ctx, add_uint_cb, del_uint_cb, add_str_cb, del_str_cb,
                     add_peer_cb, del_peer_cb, add_binding_cb, del_binding_cb);
    RC_CHECK(rc, out);

    /* fill configuration context callbacks */
    ctx->add_uint_cb = add_uint_cb;
    ctx->del_uint_cb = del_uint_cb;
    ctx->add_str_cb = add_str_cb;
    ctx->del_str_cb = del_str_cb;
    ctx->add_peer_cb = add_peer_cb;
    ctx->del_peer_cb = del_peer_cb;
    ctx->add_binding_cb = add_binding_cb;
    ctx->del_binding_cb = del_binding_cb;
    ctx->global_settings_is_loaded = false;
    ctx->sxpd_ctx = sxpd_ctx;

    /* load settings */
    rc = cfg_reload(ctx);
    if (RC_ISNOTOK(rc)) {
        LOG_ERROR("Load configuration failed: %d", rc);
        goto out;
    }

    /* create configuration reload timer used after asynchronous thread
     * configuration validating */
    ctx->cfg_reload_timer =
        evmgr_timer_create(evmgr, NULL, &tv, false, cfg_reload_real_cb, ctx);
    if (NULL == ctx->cfg_reload_timer) {
        LOG_ERROR("Create configuration reload timer failed");
        rc = -1;
        goto out;
    }

    /* unregister previously registered SIGHUP */
    if (signal_handler) {
        evmgr_sig_handler_destroy(signal_handler);
        signal_handler = NULL;
    }

    /* register reload setting event */
    signal_handler =
        evmgr_sig_handler_create(evmgr, NULL, SIGHUP, cfg_signal_callback, ctx);
    if (!signal_handler) {
        LOG_ERROR("Cannot register signal handler");
        rc = ENOMEM;
    }

out:
    return rc;
}
