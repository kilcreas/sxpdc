/*------------------------------------------------------------------
 * topology testing framework API
 *
 * May 2015, Jan Omasta
 *
 * Copyright (c) 2014-2015 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------*/

#ifndef TOPOLOGY_H_
#define TOPOLOGY_H_

#include <stdint.h>
#include <sys/queue.h>
#include <evmgr.h>
#include <regex.h>
#include <config.h>

/**
 * @brief task types and description tuples
 */
#define TUPLE_TOPO_TASK(SELECT_FUNC)                                   \
    SELECT_FUNC(TOPO_TASK_NEW_SXPD, "create new sxpd")                 \
    SELECT_FUNC(TOPO_TASK_RUN_SXPD, "run sxpd")                        \
    SELECT_FUNC(TOPO_TASK_PAUSE_SXPD, "pause sxpd")                    \
    SELECT_FUNC(TOPO_TASK_STOP_SXPD, "stop sxpd")                      \
    SELECT_FUNC(TOPO_TASK_KILL_SXPD, "kill sxpd")                      \
    SELECT_FUNC(TOPO_TASK_WAIT_FOR, "wait for event")                  \
    SELECT_FUNC(TOPO_TASK_EXEC, "exec callback in sxpd thread")        \
    SELECT_FUNC(TOPO_TASK_MAIN_EXEC, "exec callback in main thread")   \
    SELECT_FUNC(TOPO_TASK_UINT32_CFG, "uint32 configuration update")   \
    SELECT_FUNC(TOPO_TASK_STR_CFG, "str configuration update")         \
    SELECT_FUNC(TOPO_TASK_BINDING_CFG, "binding configuration update") \
    SELECT_FUNC(                                                       \
        TOPO_TASK_PEER_CFG,                                            \
        "peer configuration update") /*    SELECT_FUNC(TOPO_TASK_, "") */

#define TUPLE_TOPO_TASK_ENUM(enum_, desc_) enum_,

/**
 * @brief one topology sxpd instance
 */
struct topo_sxpd {
    const char *desc;
    const char *cfg_path;
    struct sxpd_ctx *sxpd_ctx;
    int version;
    struct evmgr_timer *nop_retry_timer;
    struct topo_sxpd_priv *topo_sxpd_priv; /* private fw sxpd data */
};

/**
 * @brief sxpd instance initializer
 */
#define TOPO_SXPD_INIT(desc_, cfg_path_)                                      \
    {                                                                         \
        .desc = desc_, .cfg_path = cfg_path_, .sxpd_ctx = NULL, .version = 4, \
        .nop_retry_timer = NULL, .topo_sxpd_priv = NULL,                      \
    }

/**
 * @brief sxpd version X instance initializer
 */
#define TOPO_SXPDVX_INIT(desc_, cfg_path_, version_)                          \
    {                                                                         \
        .desc = desc_, .cfg_path = cfg_path_, .sxpd_ctx = NULL,               \
        .version = version_, .nop_retry_timer = NULL, .topo_sxpd_priv = NULL, \
    }

struct topo_task;

typedef int (*topo_task_cb)(struct topo_task *topo_task);

enum topo_task_wait_status {
    TOPO_TASK_WAIT,
    TOPO_TASK_WAIT_DONE,
};

struct topo_task_wait {
    struct timespec timeout;
    struct timespec elapsed;
    bool timeouted;
    enum topo_task_wait_status wait_status;
    uint32_t sleep_time;
    topo_task_cb cb;
    void *wait_cb_ctx;
};

struct topo_task_main_exec {
    topo_task_cb cb;
    void *cb_ctx;
};

struct topo_task_exec {
    topo_task_cb cb;
    void *cb_ctx;
};

struct topo_task_uint32_cfg {
    bool cfg_add;
    uint32_setting_type_t type;
    uint32_t value;
    const char *str_value;
};

struct topo_task_str_cfg {
    bool cfg_add;
    str_setting_type_t type;
    const char *value;
};

struct topo_task_peer_cfg {
    bool cfg_add;
    const char *ip;
    uint16_t port;
    struct peer peer;
};

struct topo_task_binding_cfg {
    bool cfg_add;
    const char *prefix;
    struct binding binding;
};

/**
 * @brief topology task type
 */
enum topo_task_type { TUPLE_TOPO_TASK(TUPLE_TOPO_TASK_ENUM) };

struct topo_task {
    const char *desc; /*!< task description */
    struct topo_sxpd *topo_sxpd;
    enum topo_task_type type;
    union {
        struct topo_task_uint32_cfg uint32_cfg;
        struct topo_task_str_cfg str_cfg;
        struct topo_task_peer_cfg peer_cfg;
        struct topo_task_binding_cfg binding_cfg;
        struct topo_task_wait wait;
        struct topo_task_exec exec;
        struct topo_task_main_exec main_exec;
    } task;
    struct topo_task_priv *topo_task_priv;
    size_t id;
};

#define TOPO_TASK_FMT "Topology task #%zu <%s> <%s>: "
#define TOPO_TASK_ARG(topo_task) \
    (topo_task)->id, topo_task_type_to_str((topo_task)->type), (topo_task)->desc

#define TOPO_TASK_ALERT(topo_task, fmt, ...)                                   \
    do {                                                                       \
        LOG_ALERT(TOPO_TASK_FMT fmt, TOPO_TASK_ARG(topo_task), ##__VA_ARGS__); \
    } while (0)

#define TOPO_TASK_ERROR(topo_task, fmt, ...)                                   \
    do {                                                                       \
        LOG_ERROR(TOPO_TASK_FMT fmt, TOPO_TASK_ARG(topo_task), ##__VA_ARGS__); \
    } while (0)

#define TOPO_TASK_TRACE(topo_task, fmt, ...)                                   \
    do {                                                                       \
        LOG_TRACE(TOPO_TASK_FMT fmt, TOPO_TASK_ARG(topo_task), ##__VA_ARGS__); \
    } while (0)

/**
 * @brief initializes task used to create new sxpd instance
 */
#define TOPO_TASK_NEW_SXPD_INIT(desc_, topo_sxpd_)                          \
    {                                                                       \
        .desc = desc_, .topo_sxpd = topo_sxpd_, .type = TOPO_TASK_NEW_SXPD, \
        .topo_task_priv = NULL, .id = 0,                                    \
    }

/**
 * @brief initializes task used to start paused or newly created sxpd instance
 */
#define TOPO_TASK_RUN_SXPD_INIT(desc_, topo_sxpd_)                          \
    {                                                                       \
        .desc = desc_, .topo_sxpd = topo_sxpd_, .type = TOPO_TASK_RUN_SXPD, \
        .topo_task_priv = NULL, .id = 0,                                    \
    }

/**
 * @brief initializes task used to pause sxpd instance
 */
#define TOPO_TASK_PAUSE_SXPD_INIT(desc_, topo_sxpd_)                          \
    {                                                                         \
        .desc = desc_, .topo_sxpd = topo_sxpd_, .type = TOPO_TASK_PAUSE_SXPD, \
        .topo_task_priv = NULL, .id = 0,                                      \
    }

/**
 * @brief initializes task used to gracefully stop sxpd instance
 */
#define TOPO_TASK_STOP_SXPD_INIT(desc_, topo_sxpd_)                          \
    {                                                                        \
        .desc = desc_, .topo_sxpd = topo_sxpd_, .type = TOPO_TASK_STOP_SXPD, \
        .topo_task_priv = NULL, .id = 0,                                     \
    }

/**
 * @brief initializes task used to kill sxpd instance
 */
#define TOPO_TASK_KILL_SXPD_INIT(desc_, topo_sxpd_)                          \
    {                                                                        \
        .desc = desc_, .topo_sxpd = topo_sxpd_, .type = TOPO_TASK_KILL_SXPD, \
        .topo_task_priv = NULL, .id = 0,                                     \
    }

/**
 * @brief initializes task used to exec callback in sxpd instance
 */
#define TOPO_TASK_EXEC_INIT(desc_, topo_sxpd_, cb_, cb_ctx_)            \
    {                                                                   \
        .desc = desc_, .topo_sxpd = topo_sxpd_, .type = TOPO_TASK_EXEC, \
        .topo_task_priv = NULL, .id = 0, .task.exec = {                 \
            .cb = cb_, .cb_ctx = (void *)cb_ctx_,                       \
        }                                                               \
    }

/**
 * @brief initializes task used to add uin32 value to configuration
 */
#define TOPO_TASK_UINT32_CFG_ADD_INIT(desc_, topo_sxpd_, type_, value_)       \
    {                                                                         \
        .desc = desc_, .topo_sxpd = topo_sxpd_, .type = TOPO_TASK_UINT32_CFG, \
        .topo_task_priv = NULL, .id = 0, .task.uint32_cfg = {                 \
            .cfg_add = true,                                                  \
            .type = type_,                                                    \
            .value = value_,                                                  \
            .str_value = NULL,                                                \
        },                                                                    \
    }

/**
 * @brief initializes task used to add uint32 value to configuration
 */
#define TOPO_TASK_UINT32_CFG_STR_ADD_INIT(desc_, topo_sxpd_, type_,           \
                                          str_value_)                         \
    {                                                                         \
        .desc = desc_, .topo_sxpd = topo_sxpd_, .type = TOPO_TASK_UINT32_CFG, \
        .topo_task_priv = NULL, .id = 0, .task.uint32_cfg = {                 \
            .cfg_add = true,                                                  \
            .type = type_,                                                    \
            .value = 0,                                                       \
            .str_value = str_value_,                                          \
        },                                                                    \
    }

/**
 * @brief initializes task used to del uint32 value from configuration
 */
#define TOPO_TASK_UINT32_CFG_DEL_INIT(desc_, topo_sxpd_, type_)               \
    {                                                                         \
        .desc = desc_, .topo_sxpd = topo_sxpd_, .type = TOPO_TASK_UINT32_CFG, \
        .topo_task_priv = NULL, .id = 0, .task.uint32_cfg = {                 \
            .cfg_add = false, .type = type_, .value = 0, .str_value = NULL,   \
        },                                                                    \
    }

/**
 * @brief initializes task used to add string value to configuration
 */
#define TOPO_TASK_STR_CFG_ADD_INIT(desc_, topo_sxpd_, type_, value_)       \
    {                                                                      \
        .desc = desc_, .topo_sxpd = topo_sxpd_, .type = TOPO_TASK_STR_CFG, \
        .topo_task_priv = NULL, .id = 0, .task.str_cfg = {                 \
            .cfg_add = true, .type = type_, .value = value_,               \
        },                                                                 \
    }

/**
 * @brief initializes task used to delete string value from configuration
 */
#define TOPO_TASK_STR_CFG_DEL_INIT(desc_, topo_sxpd_, type_)               \
    {                                                                      \
        .desc = desc_, .topo_sxpd = topo_sxpd_, .type = TOPO_TASK_STR_CFG, \
        .topo_task_priv = NULL, .id = 0, .task.str_cfg = {                 \
            .cfg_add = false, .type = type_, .value = 0,                   \
        },                                                                 \
    }

/**
 * @brief initializes task used to add peer to configuration
 */
#define TOPO_TASK_PEER_CFG_ADD_INIT(desc_, topo_sxpd_, ip_, port_, pass_,   \
                                    type_)                                  \
    {                                                                       \
        .desc = desc_, .topo_sxpd = topo_sxpd_, .type = TOPO_TASK_PEER_CFG, \
        .topo_task_priv = NULL, .id = 0,                                    \
        .task.peer_cfg = {.cfg_add = true,                                  \
                          .ip = ip_,                                        \
                          .port = port_,                                    \
                          .peer = {                                         \
                              .ip_address = 0,                              \
                              .port_is_set = true,                          \
                              .port = 0,                                    \
                              .connection_password = (char *)pass_,         \
                              .peer_type = type_,                           \
                          } },                                              \
    }

/**
 * @brief initializes task used to delete peer from configuration
 */
#define TOPO_TASK_PEER_CFG_DEL_INIT(desc_, topo_sxpd_, ip_, port_, pass_,   \
                                    type_)                                  \
    {                                                                       \
        .desc = desc_, .topo_sxpd = topo_sxpd_, .type = TOPO_TASK_PEER_CFG, \
        .topo_task_priv = NULL, .id = 0,                                    \
        .task.peer_cfg = {.cfg_add = false,                                 \
                          .ip = ip_,                                        \
                          .port = port_,                                    \
                          .peer = {                                         \
                              .ip_address = 0,                              \
                              .port_is_set = true,                          \
                              .port = 0,                                    \
                              .connection_password = (char *)pass_,         \
                              .peer_type = type_,                           \
                          } },                                              \
    }

/**
 * @brief initializes task used to add binding to configuration
 */
#define TOPO_TASK_BINDING_CFG_ADD_INIT(desc_, topo_sxpd_, prefix_,             \
                                       prefix_length_, prefix_type_,           \
                                       source_group_tag_)                      \
    {                                                                          \
        .desc = desc_, .topo_sxpd = topo_sxpd_, .type = TOPO_TASK_BINDING_CFG, \
        .topo_task_priv = NULL, .id = 0, .task.binding_cfg = {                 \
            .cfg_add = true,                                                   \
            .prefix = prefix_,                                                 \
            .binding =                                                         \
                {                                                              \
                 .type = prefix_type_,                                         \
                 .prefix.prefix_v4 = 0,                                        \
                 .prefix_length = prefix_length_,                              \
                 .source_group_tag = source_group_tag_,                        \
                },                                                             \
        },                                                                     \
    }

/**
 * @brief initializes task used to delete binding from configuration
 */
#define TOPO_TASK_BINDING_CFG_DEL_INIT(desc_, topo_sxpd_, prefix_,             \
                                       prefix_length_, prefix_type_,           \
                                       source_group_tag_)                      \
    {                                                                          \
        .desc = desc_, .topo_sxpd = topo_sxpd_, .type = TOPO_TASK_BINDING_CFG, \
        .topo_task_priv = NULL, .id = 0, .task.binding_cfg = {                 \
            .cfg_add = false,                                                  \
            .prefix = prefix_,                                                 \
            .binding =                                                         \
                {                                                              \
                 .type = prefix_type_,                                         \
                 .prefix.prefix_v4 = 0,                                        \
                 .prefix_length = prefix_length_,                              \
                 .source_group_tag = source_group_tag_,                        \
                },                                                             \
        },                                                                     \
    }

/**
 * @brief initializes task used to wait for event
 */
#define TOPO_TASK_WAIT_FOR_INIT(desc_, topo_sxpd_, timeout_sec_, cb_,       \
                                wait_cb_ctx_)                               \
    {                                                                       \
        .desc = desc_, .topo_sxpd = topo_sxpd_, .type = TOPO_TASK_WAIT_FOR, \
        .topo_task_priv = NULL, .id = 0, .task.wait = {                     \
            .timeout =                                                      \
                {                                                           \
                 .tv_sec = timeout_sec_, .tv_nsec = 0,                      \
                },                                                          \
            .elapsed =                                                      \
                {                                                           \
                 .tv_sec = 0, .tv_nsec = 0,                                 \
                },                                                          \
            .timeouted = false,                                             \
            .wait_status = TOPO_TASK_WAIT,                                  \
            .sleep_time = 0,                                                \
            .cb = cb_,                                                      \
            .wait_cb_ctx = (void *)wait_cb_ctx_,                            \
        }                                                                   \
    }

/**
 * @brief initializes task used to execute callback in main thread
 */
#define TOPO_TASK_MAIN_EXEC_INIT(desc_, cb_, cb_ctx_)                  \
    {                                                                  \
        .desc = desc_, .topo_sxpd = NULL, .type = TOPO_TASK_MAIN_EXEC, \
        .topo_task_priv = NULL, .id = 0, .task.main_exec = {           \
            .cb = cb_, .cb_ctx = (void *)cb_ctx_,                      \
        }                                                              \
    }

const char *topo_task_type_to_str(enum topo_task_type type);

/**
 * @brief run topology tasks one by one.
 *
 * @param tasks array of tasks
 * @param tasks_num number of tasks in array
 *
 * @return 0 on success, other on error
 */
int topo_run(struct topo_task *tasks, size_t tasks_num);

#endif /* TOPOLOGY_H_ */
