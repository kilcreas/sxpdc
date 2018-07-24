/*------------------------------------------------------------------
 * Configuration manager API
 *
 * November 2014, Jan Omasta
 *
 * Copyright (c) 2014-2015 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------*/

#ifndef CONFIG_H_
#define CONFIG_H_

#include <stdint.h>
#include <sys/queue.h>
#include <evmgr.h>

/**
 * @defgroup config Configuration manager
 * @htmlinclude configuration_manager.html
 * @addtogroup config
 * @{
 */

/**
 * @brief maximum tcp-md5 signing password length
 */
#define CFG_PASSWORD_MAX_SIZE 81

/**
 * @brief implementation-specific configuration context
 */
struct cfg_ctx;

struct sxpd_ctx;

/**
 * @brief peer type
 */
enum peer_type {
    PEER_SPEAKER,  /*!< peer which acts like speaker */
    PEER_LISTENER, /*!< peer which acts like listener */
    PEER_BOTH,     /*!< peer which acts like speaker as well as listener */
};

/**
 * @brief peer configuration info
 */
struct peer {
    in_addr_t ip_address; /*!< peer's ip address in network byte order */
    bool port_is_set;     /*!< whether the port is set to meaningful value */
    uint16_t port;        /*!< peer's port in network byte order */
    char *connection_password; /*!< connection password */
    enum peer_type peer_type;  /*!< the type of the peer */
};

/**
 * @brief type of ip prefix
 */
enum prefix_type_e {
    PREFIX_IPV4, /*!< IPV4 */
    PREFIX_IPV6, /*!< IPV6 */
};

/**
 * @brief configured binding
 */
struct binding {
    enum prefix_type_e type;
    union {
        uint32_t prefix_v4;
        uint32_t prefix_v6[4];
    } prefix;
    uint8_t prefix_length;
    uint16_t source_group_tag;
};

#define TUPLE_STR_CFG_DEF(SELECT_FUNC) \
    SELECT_FUNC(STR_SETTING_PASSWORD, "default password")

#define TUPLE_CFG_SELECT_ENUM(enumerator, string) enumerator,

typedef enum str_seting_type_e {
    TUPLE_STR_CFG_DEF(TUPLE_CFG_SELECT_ENUM)
        STR_SETTING_LAST, /* place holder */
} str_setting_type_t;

/**
 * @brief callback called when string configuration is added
 *
 * @param ctx sxpd context
 * @param type setting type
 * @param value setting value
 */
typedef int (*cfg_add_str_setting_callback)(struct sxpd_ctx *ctx,
                                            str_setting_type_t type,
                                            const char *value);

/**
 * @brief callback called when string configuration is deleted
 *
 * @param ctx sxpd context
 * @param type setting type
 */
typedef int (*cfg_del_str_setting_callback)(struct sxpd_ctx *ctx,
                                            str_setting_type_t type);

#define TUPLE_UINT32_CFG_DEF(SELECT_FUNC)                                      \
    SELECT_FUNC(UINT32_SETTING_LOG_LEVEL, "log_level")                         \
    SELECT_FUNC(UINT32_SETTING_RETRY_TIMER, "retry timer")                     \
    SELECT_FUNC(UINT32_SETTING_RECONCILIATION_TIMER, "reconciliation timer")   \
    SELECT_FUNC(UINT32_SETTING_LISTENER_MIN_HOLD_TIME,                         \
                "listener min hold time")                                      \
    SELECT_FUNC(UINT32_SETTING_LISTENER_MAX_HOLD_TIME,                         \
                "listener max hold time")                                      \
    SELECT_FUNC(UINT32_SETTING_SPEAKER_MIN_HOLD_TIME, "speaker min hold time") \
    SELECT_FUNC(UINT32_SETTING_KEEPALIVE_TIMER, "keep alive timer")            \
    SELECT_FUNC(UINT32_SETTING_SUBNET_EXPANSION_LIMIT,                         \
                "subnet expansion limit")                                      \
    SELECT_FUNC(UINT32_SETTING_BIND_ADDRESS, "bind address")                   \
    SELECT_FUNC(UINT32_SETTING_PORT, "port")                                   \
    SELECT_FUNC(UINT32_SETTING_NODE_ID, "node id")                             \
    SELECT_FUNC(UINT32_SETTING_ENABLED, "enabled")

typedef enum uin32_setting_type_e {
    TUPLE_UINT32_CFG_DEF(TUPLE_CFG_SELECT_ENUM) UINT32_SETTING_LAST
} uint32_setting_type_t;

/**
 * @brief return pretty print of setting name
 *
 * @param type type to print
 *
 * @return string suitable for printing
 */
const char *cfg_get_uint32_setting_str(uint32_setting_type_t type);

/**
 * @brief return pretty print of setting name
 *
 * @param type type to print
 *
 * @return string suitable for printing
 */
const char *cfg_get_str_setting_str(str_setting_type_t type);

/**
 * @brief callback called when uint32_t configuration is added
 *
 * @param ctx sxpd context
 * @param type setting type
 * @param value setting value
 */
typedef int (*cfg_add_uint32_setting_callback)(struct sxpd_ctx *ctx,
                                               uint32_setting_type_t type,
                                               uint32_t value);

/**
 * @brief callback called when uint32_t configuration is deleted
 *
 * @param ctx sxpd context
 * @param type string setting type
 */
typedef int (*cfg_del_uint32_setting_callback)(struct sxpd_ctx *ctx,
                                               uint32_setting_type_t type);

/**
 * @brief callback called when peer configuration is added
 *
 * @param ctx sxpd context
 * @param peer added peer setting
 */
typedef int (*cfg_add_peer_callback)(struct sxpd_ctx *ctx,
                                     const struct peer *peer);

/**
 * @brief callback called when peer configuration is deleted
 *
 * @param ctx sxpd context
 * @param peer deleted peer setting
 */
typedef int (*cfg_del_peer_callback)(struct sxpd_ctx *ctx,
                                     const struct peer *peer);

/**
 * @brief callback called when binding configuration is added
 *
 * @param ctx sxpd context
 * @param binding added binding setting
 */
typedef int (*cfg_add_binding_callback)(struct sxpd_ctx *ctx,
                                        const struct binding *binding);

/**
 * @brief callback called when binding configuration is deleted
 *
 * @param ctx sxpd context
 * @param binding deleted binding setting
 */
typedef int (*cfg_del_binding_callback)(struct sxpd_ctx *ctx,
                                        const struct binding *binding);

/**
 * @brief create configuration context
 *
 * @param[out] ctx configuration context
 * @param cfg_string configuration string i.e. file path
 * @param[out] evmgr_settings event manager settings
 * @return returns 0 on success, -1 on error
 */
int cfg_ctx_create(struct cfg_ctx **ctx, const char *cfg_string,
                   struct evmgr_settings **evmgr_settings);

/**
 * @brief register configuration callbacks
 *
 * @param ctx configuration context
 * @param evmgr event manager
 * @param sxpd_ctx callback context
 * @param add_uint_cb callback called when uint32_t configuration is added
 * @param del_uint_cb callback called when uint32_t configuration is deleted
 * @param add_str_cb callback called when string configuration is added
 * @param del_str_cb callback called when string configuration is deleted
 * @param add_peer_cb callback called when peer configuration is added
 * @param del_peer_cb callback called when peer configuration is deleted
 * @param add_binding_cb callback called when binding configuration is added
 * @param del_binding_cb callback called when binding configuration is deleted
 * @return returns 0 on success, -1 on error
 */
int cfg_register_callbacks(struct cfg_ctx *ctx, struct evmgr *evmgr,
                           struct sxpd_ctx *sxpd_ctx,
                           cfg_add_uint32_setting_callback add_uint_cb,
                           cfg_del_uint32_setting_callback del_uint_cb,
                           cfg_add_str_setting_callback add_str_cb,
                           cfg_del_str_setting_callback del_str_cb,
                           cfg_add_peer_callback add_peer_cb,
                           cfg_del_peer_callback del_peer_cb,
                           cfg_add_binding_callback add_binding_cb,
                           cfg_del_binding_callback del_binding_cb);
/**
 * @brief destroy configuration context
 *
 * @param ctx sxpd context
 */
void cfg_ctx_destroy(struct cfg_ctx *ctx);

/** @} */

#endif /* CONFIG_H_ */
