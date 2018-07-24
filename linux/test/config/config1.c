#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <inttypes.h>
#include <math.h>
#include <arpa/inet.h>
#include <signal.h>
#include <unistd.h>

#include <sxpd.h>
#include <sxp.h>
#include <mem.h>
#include <config.h>
#include <util.h>

#include "../framework/inc/log_check.h"

/* default configuration path */
#define CFG_FILE_PATH1 "config1.cfg"

static char cfg_file_path[100];

DECL_DEBUG_V6_STATIC_BUFFER

/**
 * @brief loaded and expected settings structure
 */
struct test_settings {
    bool is_set_uint32_val[UINT32_SETTING_LAST];
    uint32_t uint32_val[UINT32_SETTING_LAST];
    bool is_set_str_val[STR_SETTING_LAST];
    char default_connection_password[CFG_PASSWORD_MAX_SIZE];
};

/**
 * @brief called and expected to called setting callbacks
 */
struct test_settings_cb_calls {
    bool add_uint32_setting_call[UINT32_SETTING_LAST];
    bool del_uint32_setting_call[UINT32_SETTING_LAST];
    bool add_str_setting_call[STR_SETTING_LAST];
    bool del_str_setting_call[STR_SETTING_LAST];
};

/**
 * @brief item is expected to be added or deleted from list
 */
enum exp_flag {
    EXP_ADD,
    EXP_DEL,
};

/**
 * @brief expected peer configuration updates
 */
struct test_peer_exp_upt {
    bool exist;
    enum exp_flag flag;
    bool checked;
    struct peer peer;
};

/**
 * @brief expected binding configuration updates
 */
struct test_binding_exp_upt {
    bool exist;
    enum exp_flag flag;
    bool checked;
    struct binding binding;
};

/**
 * @brief per config reload structure
 */
struct test_cfg_reload {
    const char *description;
    struct log_pattern *log_pattern;
    size_t log_pattern_num;
};

static struct log_pattern log_pattern_1[] = {
    LOG_PATTERN_STATIC_INIT("expected trace logs about uint32 config add",
                            LOG_EXPECTED, LOG_LEVEL_TRACE, "config1.c",
                            "cfg_add_uint32_setting_cb", NULL),
    LOG_PATTERN_STATIC_INIT("expected trace logs about str config add",
                            LOG_EXPECTED, LOG_LEVEL_TRACE, "config1.c",
                            "cfg_add_str_setting_cb", NULL),
    LOG_PATTERN_STATIC_INIT("expected trace logs about peer add", LOG_EXPECTED,
                            LOG_LEVEL_TRACE, "config1.c", "cfg_add_peer_cb",
                            NULL),
    LOG_PATTERN_STATIC_INIT("expected trace logs about binding add",
                            LOG_EXPECTED, LOG_LEVEL_TRACE, "config1.c",
                            "cfg_add_binding_cb", NULL),

    LOG_PATTERN_STATIC_INIT("unexpected trace logs about uint32 config del",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "config1.c",
                            "cfg_del_uint32_setting_cb", NULL),
    LOG_PATTERN_STATIC_INIT("unexpected trace logs about str config del",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "config1.c",
                            "cfg_del_str_setting_cb", NULL),
    LOG_PATTERN_STATIC_INIT("unexpected trace logs about peer config del",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "config1.c",
                            "cfg_del_peer_cb", NULL),
    LOG_PATTERN_STATIC_INIT("unexpected trace logs about binding config del",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "config1.c",
                            "cfg_del_binding_cb", NULL),

    LOG_PATTERN_STATIC_INIT("unexpected any error logs", LOG_UNEXPECTED,
                            LOG_LEVEL_ERROR, NULL, NULL, NULL),
};

static struct log_pattern log_pattern_2[] = {
    LOG_PATTERN_STATIC_INIT("unexpected trace logs about uint32 config add",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "config1.c",
                            "cfg_add_uint32_setting_cb", NULL),
    LOG_PATTERN_STATIC_INIT("unexpected trace logs about str config add",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "config1.c",
                            "cfg_add_str_setting_cb", NULL),
    LOG_PATTERN_STATIC_INIT("unexpected trace logs about peer add",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "config1.c",
                            "cfg_add_peer_cb", NULL),
    LOG_PATTERN_STATIC_INIT("unexpected trace logs about binding add",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "config1.c",
                            "cfg_add_binding_cb", NULL),

    LOG_PATTERN_STATIC_INIT("unexpected trace logs about uint32 config del",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "config1.c",
                            "cfg_del_uint32_setting_cb", NULL),
    LOG_PATTERN_STATIC_INIT("unexpected trace logs about str config del",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "config1.c",
                            "cfg_del_str_setting_cb", NULL),
    LOG_PATTERN_STATIC_INIT("unexpected trace logs about peer config del",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "config1.c",
                            "cfg_del_peer_cb", NULL),
    LOG_PATTERN_STATIC_INIT("unexpected trace logs about binding config del",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "config1.c",
                            "cfg_del_binding_cb", NULL),

    LOG_PATTERN_STATIC_INIT("unexpected any error logs", LOG_UNEXPECTED,
                            LOG_LEVEL_ERROR, NULL, NULL, NULL),
};

static struct log_pattern log_pattern_3[] = {
    LOG_PATTERN_STATIC_INIT("expected trace logs about uint32 config add",
                            LOG_EXPECTED, LOG_LEVEL_TRACE, "config1.c",
                            "cfg_add_uint32_setting_cb", NULL),
    LOG_PATTERN_STATIC_INIT("expected trace logs about str config add",
                            LOG_EXPECTED, LOG_LEVEL_TRACE, "config1.c",
                            "cfg_add_str_setting_cb", NULL),
    LOG_PATTERN_STATIC_INIT("expected trace logs about peer add", LOG_EXPECTED,
                            LOG_LEVEL_TRACE, "config1.c", "cfg_add_peer_cb",
                            NULL),
    LOG_PATTERN_STATIC_INIT("expected trace logs about binding add",
                            LOG_EXPECTED, LOG_LEVEL_TRACE, "config1.c",
                            "cfg_add_binding_cb", NULL),
    LOG_PATTERN_STATIC_INIT("expected trace logs about peer del", LOG_EXPECTED,
                            LOG_LEVEL_TRACE, "config1.c", "cfg_del_peer_cb",
                            NULL),
    LOG_PATTERN_STATIC_INIT("expected trace logs about binding del",
                            LOG_EXPECTED, LOG_LEVEL_TRACE, "config1.c",
                            "cfg_del_binding_cb", NULL),

    LOG_PATTERN_STATIC_INIT("unexpected trace logs about uint32 config del",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "config1.c",
                            "cfg_del_uint32_setting_cb", NULL),
    LOG_PATTERN_STATIC_INIT("unexpected trace logs about str config del",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "config1.c",
                            "cfg_del_str_setting_cb", NULL),

    LOG_PATTERN_STATIC_INIT("unexpected any error logs", LOG_UNEXPECTED,
                            LOG_LEVEL_ERROR, NULL, NULL, NULL),
};

static struct log_pattern log_pattern_4[] = {
    LOG_PATTERN_STATIC_INIT("unexpected trace logs about uint32 config add",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "config1.c",
                            "cfg_add_uint32_setting_cb", NULL),
    LOG_PATTERN_STATIC_INIT("unexpected trace logs about str config add",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "config1.c",
                            "cfg_add_str_setting_cb", NULL),
    LOG_PATTERN_STATIC_INIT("unexpected trace logs about peer add",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "config1.c",
                            "cfg_add_peer_cb", NULL),
    LOG_PATTERN_STATIC_INIT("unexpected trace logs about binding add",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "config1.c",
                            "cfg_add_binding_cb", NULL),

    LOG_PATTERN_STATIC_INIT("unexpected trace logs about uint32 config del",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "config1.c",
                            "cfg_del_uint32_setting_cb", NULL),
    LOG_PATTERN_STATIC_INIT("unexpected trace logs about str config del",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "config1.c",
                            "cfg_del_str_setting_cb", NULL),
    LOG_PATTERN_STATIC_INIT("unexpected trace logs about peer config del",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "config1.c",
                            "cfg_del_peer_cb", NULL),
    LOG_PATTERN_STATIC_INIT("unexpected trace logs about binding config del",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "config1.c",
                            "cfg_del_binding_cb", NULL),

    LOG_PATTERN_STATIC_INIT("expected error logs", LOG_EXPECTED,
                            LOG_LEVEL_ERROR, NULL, NULL, NULL),
    LOG_PATTERN_STATIC_INIT("expected alert log", LOG_EXPECTED, LOG_LEVEL_ALERT,
                            NULL, NULL, NULL),
};

static struct log_pattern log_pattern_5[] = {
    LOG_PATTERN_STATIC_INIT("unexpected trace logs about uint32 config add",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "config1.c",
                            "cfg_add_uint32_setting_cb", NULL),
    LOG_PATTERN_STATIC_INIT("unexpected trace logs about str config add",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "config1.c",
                            "cfg_add_str_setting_cb", NULL),
    LOG_PATTERN_STATIC_INIT("unexpected trace logs about peer add",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "config1.c",
                            "cfg_add_peer_cb", NULL),
    LOG_PATTERN_STATIC_INIT("unexpected trace logs about binding add",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "config1.c",
                            "cfg_add_binding_cb", NULL),

    LOG_PATTERN_STATIC_INIT("unexpected trace logs about uint32 config del",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "config1.c",
                            "cfg_del_uint32_setting_cb", NULL),
    LOG_PATTERN_STATIC_INIT("unexpected trace logs about str config del",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "config1.c",
                            "cfg_del_str_setting_cb", NULL),
    LOG_PATTERN_STATIC_INIT("unexpected trace logs about peer config del",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "config1.c",
                            "cfg_del_peer_cb", NULL),
    LOG_PATTERN_STATIC_INIT("unexpected trace logs about binding config del",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "config1.c",
                            "cfg_del_binding_cb", NULL),

    LOG_PATTERN_STATIC_INIT("unexpected any error logs", LOG_UNEXPECTED,
                            LOG_LEVEL_ERROR, NULL, NULL, NULL),
};

static struct log_pattern log_pattern_6[] = {
    LOG_PATTERN_STATIC_INIT(
        "expected trace logs about uint32 <log_level> config add", LOG_EXPECTED,
        LOG_LEVEL_TRACE, "config1.c", "cfg_add_uint32_setting_cb",
        "^(.*)(\\blog_level\\b)(.*?)$"),
    LOG_PATTERN_STATIC_INIT("expected trace logs about peer add", LOG_EXPECTED,
                            LOG_LEVEL_TRACE, "config1.c", "cfg_add_peer_cb",
                            NULL),
    LOG_PATTERN_STATIC_INIT("expected trace logs about binding add",
                            LOG_EXPECTED, LOG_LEVEL_TRACE, "config1.c",
                            "cfg_add_binding_cb", NULL),
    LOG_PATTERN_STATIC_INIT("expected trace logs about peer config del",
                            LOG_EXPECTED, LOG_LEVEL_TRACE, "config1.c",
                            "cfg_del_peer_cb", NULL),
    LOG_PATTERN_STATIC_INIT("expected trace logs about binding config del",
                            LOG_EXPECTED, LOG_LEVEL_TRACE, "config1.c",
                            "cfg_del_binding_cb", NULL),

    LOG_PATTERN_STATIC_INIT("unexpected trace logs about str config add",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "config1.c",
                            "cfg_add_str_setting_cb", NULL),
    LOG_PATTERN_STATIC_INIT("unexpected trace logs about uint32 config del",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "config1.c",
                            "cfg_del_uint32_setting_cb", NULL),
    LOG_PATTERN_STATIC_INIT("unexpected trace logs about str config del",
                            LOG_UNEXPECTED, LOG_LEVEL_TRACE, "config1.c",
                            "cfg_del_str_setting_cb", NULL),

    LOG_PATTERN_STATIC_INIT("unexpected any error logs", LOG_UNEXPECTED,
                            LOG_LEVEL_ERROR, NULL, NULL, NULL),
};

static struct test_cfg_reload cfg_reload[] = {
    {
     .description = "Valid configuration file config1.cfg",
     .log_pattern = log_pattern_1,
     .log_pattern_num = sizeof(log_pattern_1) / sizeof(*log_pattern_1),
    },
    {
     .description = "Valid configuration file config1.cfg again. Test is "
                    "expecting no config updates",
     .log_pattern = log_pattern_2,
     .log_pattern_num = sizeof(log_pattern_2) / sizeof(*log_pattern_2),
    },
    {
     .description = "Updated valid configuration file config2.cfg. Test is "
                    "expecting every item of config to be updated",
     .log_pattern = log_pattern_3,
     .log_pattern_num = sizeof(log_pattern_3) / sizeof(*log_pattern_3),
    },
    {
     .description = "Updated and also invalid configuration file config3.cfg. "
                    "Test is expecting no config updates and error "
                    "messages to be logged",
     .log_pattern = log_pattern_4,
     .log_pattern_num = sizeof(log_pattern_4) / sizeof(*log_pattern_4),
    },
    {
     .description = "Valid configuration file config4.cfg. No difference "
                    "between config2.cfg. Test is expecting no config updates",
     .log_pattern = log_pattern_5,
     .log_pattern_num = sizeof(log_pattern_5) / sizeof(*log_pattern_5),
    },
    {
     .description = "Valid configuration file config5.cfg. Test is expecting "
                    "some specific config updates",
     .log_pattern = log_pattern_6,
     .log_pattern_num = sizeof(log_pattern_6) / sizeof(*log_pattern_6),
    },
    {
     .description = "Invalid configuration file config6.cfg. Syntax error. "
                    "Missing comma",
     .log_pattern = log_pattern_4,
     .log_pattern_num = sizeof(log_pattern_4) / sizeof(*log_pattern_4),
    },
    {
     .description = "Invalid configuration file config7.cfg. Syntax error. "
                    "Assign character '=' replaced by character '-'",
     .log_pattern = log_pattern_4,
     .log_pattern_num = sizeof(log_pattern_4) / sizeof(*log_pattern_4),
    },
    {
     .description = "Invalid configuration file config8.cfg. Syntax error. "
                    "Assign character '=' is duplicated",
     .log_pattern = log_pattern_4,
     .log_pattern_num = sizeof(log_pattern_4) / sizeof(*log_pattern_4),
    },
};

/* number of configuration reloads */
#define CFG_RELOAD_NUM sizeof(cfg_reload) / sizeof(*cfg_reload) /* 6 */
#define MAX_PEER_CB 9
#define MAX_BINDING_CB 7

/* configuration reload number */
static size_t cfg_reload_actual = 0;

#define TUPLE_UINT32_CFG_IS_NOT_SET(enumerator, string) \
    .is_set_uint32_val[enumerator] = false,
#define TUPLE_STR_CFG_IS_NOT_SET(enumerator, string) \
    .is_set_str_val[enumerator] = false,

/* loaded global configuration settings */
static struct test_settings settings = { TUPLE_UINT32_CFG_DEF(
    TUPLE_UINT32_CFG_IS_NOT_SET) TUPLE_STR_CFG_DEF(TUPLE_STR_CFG_IS_NOT_SET) };

static struct test_binding_exp_upt
    binding_exp_upt[CFG_RELOAD_NUM][MAX_BINDING_CB] = {
        { {.exist = true,
           .flag = EXP_ADD,
           .checked = false,
           .binding =
               {
                .type = PREFIX_IPV4,
                .prefix.prefix_v4 = 16885952,
                .prefix_length = 32,
                .source_group_tag = 45,
               } },
          {.exist = true,
           .flag = EXP_ADD,
           .checked = false,
           .binding =
               {
                .type = PREFIX_IPV6,
                .prefix.prefix_v6 = { 2917008160, 2907566014, 1174414080,
                                      113408 },
                .prefix_length = 127,
                .source_group_tag = 46,
               } },
          {
           .exist = true,
           .flag = EXP_ADD,
           .checked = false,
           .binding =
               {
                .type = PREFIX_IPV6,
                .prefix.prefix_v6 = { 2917008416, 2907566014, 1174414080,
                                      16890624 },
                .prefix_length = 128,
                .source_group_tag = 47,
               },
          },
          {
           .exist = false,
          } },
        { {
           .exist = false,
        } },
        { {
           .exist = true,
           .flag = EXP_DEL,
           .checked = false,
           .binding =
               {
                .type = PREFIX_IPV4,
                .prefix.prefix_v4 = 16885952,
                .prefix_length = 32,
                .source_group_tag = 45,
               },
          },
          {
           .exist = true,
           .flag = EXP_DEL,
           .checked = false,
           .binding =
               {
                .type = PREFIX_IPV6,
                .prefix.prefix_v6 = { 2917008160, 2907566014, 1174414080,
                                      113408 },
                .prefix_length = 127,
                .source_group_tag = 46,
               },
          },
          {
           .exist = true,
           .flag = EXP_DEL,
           .checked = false,
           .binding =
               {
                .type = PREFIX_IPV6,
                .prefix.prefix_v6 = { 2917008416, 2907566014, 1174414080,
                                      16890624 },
                .prefix_length = 128,
                .source_group_tag = 47,
               },
          },
          {
           .exist = true,
           .flag = EXP_ADD,
           .checked = false,
           .binding =
               {
                .type = PREFIX_IPV4,
                .prefix.prefix_v4 = 33663168,
                .prefix_length = 32,
                .source_group_tag = 45,
               },
          },
          {
           .exist = true,
           .flag = EXP_ADD,
           .checked = false,
           .binding =
               {
                .type = PREFIX_IPV6,
                .prefix.prefix_v6 = { 2917008160, 2907566014, 1174414080,
                                      113408 },
                .prefix_length = 128,
                .source_group_tag = 46,
               },
          },
          {
           .exist = true,
           .flag = EXP_ADD,
           .checked = false,
           .binding =
               {
                .type = PREFIX_IPV6,
                .prefix.prefix_v6 = { 2917008416, 2907566014, 1174414080,
                                      16890624 },
                .prefix_length = 128,
                .source_group_tag = 48,
               },
          },
          {
           .exist = false,
          } },
        { {
           /* updated and also invalid configuration file, so no config update
              callbacks should be called */
           .exist = false,
        } },
        { {
           /* valid configuration file, no difference between config2.cfg */
           .exist = false,
        } },
        {
         {.exist = true, /* 192.168.1.1/32:45 */
          .flag = EXP_ADD,
          .checked = false,
          .binding =
              {
               .type = PREFIX_IPV4,
               .prefix.prefix_v4 = 16885952,
               .prefix_length = 32,
               .source_group_tag = 45,
              } },
         {
          /* 2003:dead:beef:4dad:23:46:bb:100/128:48 */
          .exist = true,
          .flag = EXP_DEL,
          .checked = false,
          .binding =
              {
               .type = PREFIX_IPV6,
               .prefix.prefix_v6 = { 2917008160, 2907566014, 1174414080,
                                     113408 },
               .prefix_length = 128,
               .source_group_tag = 46,
              },
         },
         {
          .exist = false,
         },
        },
        { {
           /* invalid configuration file. Syntax error.
            * Missing comma ',' character in peers settings. */
           .exist = false,
        } },
        { {
           /* invalid configuration file. Syntax error.
            * Assign character '=' replaced by character '-' */
           .exist = false,
        } },
        { {
           /* invalid configuration file. Syntax error.
            * Assign character '=' is duplicated */
           .exist = false,
        } },
    };

static struct test_peer_exp_upt
    peer_exp_upt[CFG_RELOAD_NUM]
                [MAX_PEER_CB] = {
                    { {
                       .exist = true,
                       .flag = EXP_ADD,
                       .checked = false,
                       .peer =
                           {
                            .ip_address = 16885952,
                            .port_is_set = true,
                            .port = 506,
                            .connection_password = (char *)"192.168.1.1:64001",
                            .peer_type = PEER_SPEAKER,
                           },
                      },
                      {
                       .exist = true,
                       .flag = EXP_ADD,
                       .checked = false,
                       .peer =
                           {
                            .ip_address = 33663168,
                            .port_is_set = true,
                            .port = 762,
                            .connection_password = (char *)"password",
                            .peer_type = PEER_LISTENER,
                           },
                      },
                      {
                       .exist = true,
                       .flag = EXP_ADD,
                       .checked = false,
                       .peer =
                           {
                            .ip_address = 50440384,
                            .port_is_set = true,
                            .port = 762,
                            .connection_password = (char *)"password",
                            .peer_type = PEER_BOTH,
                           },
                      },
                      {
                       .exist = true,
                       .flag = EXP_ADD,
                       .checked = false,
                       .peer =
                           {
                            .ip_address = 83994816,
                            .port_is_set = true,
                            .port = 762,
                            .connection_password = (char *)"password",
                            .peer_type = PEER_SPEAKER,
                           },
                      },
                      {
                       .exist = false,
                      } },
                    { {
                       .exist = false,
                    } },
                    { {
                       .exist = true,
                       .flag = EXP_DEL,
                       .checked = false,
                       .peer =
                           {
                            .ip_address = 16885952,
                            .port_is_set = true,
                            .port = 506,
                            .connection_password = (char *)"192.168.1.1:64001",
                            .peer_type = PEER_SPEAKER,
                           },
                      },
                      {
                       .exist = true,
                       .flag = EXP_DEL,
                       .checked = false,
                       .peer =
                           {
                            .ip_address = 33663168,
                            .port_is_set = true,
                            .port = 762,
                            .connection_password = (char *)"password",
                            .peer_type = PEER_LISTENER,
                           },
                      },
                      {
                       .exist = true,
                       .flag = EXP_DEL,
                       .checked = false,
                       .peer =
                           {
                            .ip_address = 50440384,
                            .port_is_set = true,
                            .port = 762,
                            .connection_password = (char *)"password",
                            .peer_type = PEER_BOTH,
                           },
                      },
                      {
                       .exist = true,
                       .flag = EXP_ADD,
                       .checked = false,
                       .peer =
                           {
                            .ip_address = 67217600,
                            .port_is_set = true,
                            .port = 506,
                            .connection_password = (char *)"secret",
                            .peer_type = PEER_SPEAKER,
                           },
                      },
                      {
                       .exist = true,
                       .flag = EXP_ADD,
                       .checked = false,
                       .peer =
                           {
                            .ip_address = 33663168,
                            .port_is_set = true,
                            .port = 1018,
                            .connection_password = (char *)"password",
                            .peer_type = PEER_LISTENER,
                           },
                      },
                      {
                       .exist = true,
                       .flag = EXP_ADD,
                       .checked = false,
                       .peer =
                           {
                            .ip_address = 50440384,
                            .port_is_set = true,
                            .port = 762,
                            .connection_password = (char *)"password",
                            .peer_type = PEER_SPEAKER,
                           },
                      },
                      {
                       .exist = false,
                      } },
                    { {
                       .exist = false,
                    } },
                    { {
                       .exist = false,
                    } },
                    {
                     {
                      .exist = true,
                      .flag = EXP_ADD,
                      .checked = false,
                      .peer =
                          {
                           .ip_address = 16885952,
                           .port_is_set = true,
                           .port = 506,
                           .connection_password = (char *)"192.168.1.1:64001",
                           .peer_type = PEER_SPEAKER,
                          },
                     },
                     {
                      .exist = true,
                      .flag = EXP_DEL,
                      .checked = false,
                      .peer =
                          {
                           .ip_address = 83994816,
                           .port_is_set = true,
                           .port = 762,
                           .connection_password = (char *)"password",
                           .peer_type = PEER_SPEAKER,
                          },
                     },
                    },
                    { {
                       /* invalid configuration file. Syntax error.
                        * Missing comma ',' character in peers settings. */
                       .exist = false,
                    } },
                    { {
                       /* invalid configuration file. Syntax error.
                        * Assign character '=' replaced by character '-' */
                       .exist = false,
                    } },
                    { {
                       /* invalid configuration file. Syntax error.
                        * Assign character '=' is duplicated */
                       .exist = false,
                    } },
                };

static struct test_settings_cb_calls settings_cb_calls;

static struct test_settings_cb_calls exp_cb_calls[] = {
    {
     .add_uint32_setting_call[UINT32_SETTING_LOG_LEVEL] = true,
     .add_uint32_setting_call[UINT32_SETTING_ENABLED] = true,
     .add_uint32_setting_call[UINT32_SETTING_RETRY_TIMER] = true,
     .add_uint32_setting_call[UINT32_SETTING_RECONCILIATION_TIMER] = true,
     .add_uint32_setting_call[UINT32_SETTING_SPEAKER_MIN_HOLD_TIME] = true,
     .add_uint32_setting_call[UINT32_SETTING_LISTENER_MIN_HOLD_TIME] = true,
     .add_uint32_setting_call[UINT32_SETTING_LISTENER_MAX_HOLD_TIME] = true,
     .add_uint32_setting_call[UINT32_SETTING_KEEPALIVE_TIMER] = true,
     .add_uint32_setting_call[UINT32_SETTING_SUBNET_EXPANSION_LIMIT] = true,
     .add_uint32_setting_call[UINT32_SETTING_BIND_ADDRESS] = true,
     .add_uint32_setting_call[UINT32_SETTING_PORT] = true,
     .add_uint32_setting_call[UINT32_SETTING_NODE_ID] = true,
     .del_uint32_setting_call[UINT32_SETTING_LOG_LEVEL] = false,
     .del_uint32_setting_call[UINT32_SETTING_ENABLED] = false,
     .del_uint32_setting_call[UINT32_SETTING_RETRY_TIMER] = false,
     .del_uint32_setting_call[UINT32_SETTING_RECONCILIATION_TIMER] = false,
     .del_uint32_setting_call[UINT32_SETTING_SPEAKER_MIN_HOLD_TIME] = false,
     .del_uint32_setting_call[UINT32_SETTING_LISTENER_MIN_HOLD_TIME] = false,
     .del_uint32_setting_call[UINT32_SETTING_LISTENER_MAX_HOLD_TIME] = false,
     .del_uint32_setting_call[UINT32_SETTING_KEEPALIVE_TIMER] = false,
     .del_uint32_setting_call[UINT32_SETTING_SUBNET_EXPANSION_LIMIT] = false,
     .del_uint32_setting_call[UINT32_SETTING_BIND_ADDRESS] = false,
     .del_uint32_setting_call[UINT32_SETTING_PORT] = false,
     .del_uint32_setting_call[UINT32_SETTING_NODE_ID] = false,
     .add_str_setting_call[STR_SETTING_PASSWORD] = true,
     .del_str_setting_call[STR_SETTING_PASSWORD] = false,
    },
    {
     .add_uint32_setting_call[UINT32_SETTING_LOG_LEVEL] = false,
     .add_uint32_setting_call[UINT32_SETTING_ENABLED] = false,
     .add_uint32_setting_call[UINT32_SETTING_RETRY_TIMER] = false,
     .add_uint32_setting_call[UINT32_SETTING_RECONCILIATION_TIMER] = false,
     .add_uint32_setting_call[UINT32_SETTING_SPEAKER_MIN_HOLD_TIME] = false,
     .add_uint32_setting_call[UINT32_SETTING_LISTENER_MIN_HOLD_TIME] = false,
     .add_uint32_setting_call[UINT32_SETTING_LISTENER_MAX_HOLD_TIME] = false,
     .add_uint32_setting_call[UINT32_SETTING_KEEPALIVE_TIMER] = false,
     .add_uint32_setting_call[UINT32_SETTING_SUBNET_EXPANSION_LIMIT] = false,
     .add_uint32_setting_call[UINT32_SETTING_BIND_ADDRESS] = false,
     .add_uint32_setting_call[UINT32_SETTING_PORT] = false,
     .add_uint32_setting_call[UINT32_SETTING_NODE_ID] = false,
     .del_uint32_setting_call[UINT32_SETTING_LOG_LEVEL] = false,
     .del_uint32_setting_call[UINT32_SETTING_ENABLED] = false,
     .del_uint32_setting_call[UINT32_SETTING_RETRY_TIMER] = false,
     .del_uint32_setting_call[UINT32_SETTING_RECONCILIATION_TIMER] = false,
     .del_uint32_setting_call[UINT32_SETTING_SPEAKER_MIN_HOLD_TIME] = false,
     .del_uint32_setting_call[UINT32_SETTING_LISTENER_MIN_HOLD_TIME] = false,
     .del_uint32_setting_call[UINT32_SETTING_LISTENER_MAX_HOLD_TIME] = false,
     .del_uint32_setting_call[UINT32_SETTING_KEEPALIVE_TIMER] = false,
     .del_uint32_setting_call[UINT32_SETTING_SUBNET_EXPANSION_LIMIT] = false,
     .del_uint32_setting_call[UINT32_SETTING_BIND_ADDRESS] = false,
     .del_uint32_setting_call[UINT32_SETTING_PORT] = false,
     .del_uint32_setting_call[UINT32_SETTING_NODE_ID] = false,
     .add_str_setting_call[STR_SETTING_PASSWORD] = false,
     .del_str_setting_call[STR_SETTING_PASSWORD] = false,
    },
    {
     .add_uint32_setting_call[UINT32_SETTING_LOG_LEVEL] = true,
     .add_uint32_setting_call[UINT32_SETTING_ENABLED] = true,
     .add_uint32_setting_call[UINT32_SETTING_RETRY_TIMER] = true,
     .add_uint32_setting_call[UINT32_SETTING_RECONCILIATION_TIMER] = true,
     .add_uint32_setting_call[UINT32_SETTING_SPEAKER_MIN_HOLD_TIME] = true,
     .add_uint32_setting_call[UINT32_SETTING_LISTENER_MIN_HOLD_TIME] = true,
     .add_uint32_setting_call[UINT32_SETTING_LISTENER_MAX_HOLD_TIME] = true,
     .add_uint32_setting_call[UINT32_SETTING_KEEPALIVE_TIMER] = true,
     .add_uint32_setting_call[UINT32_SETTING_SUBNET_EXPANSION_LIMIT] = true,
     .add_uint32_setting_call[UINT32_SETTING_BIND_ADDRESS] = true,
     .add_uint32_setting_call[UINT32_SETTING_PORT] = true,
     .add_uint32_setting_call[UINT32_SETTING_NODE_ID] = true,
     .del_uint32_setting_call[UINT32_SETTING_LOG_LEVEL] = false,
     .del_uint32_setting_call[UINT32_SETTING_ENABLED] = false,
     .del_uint32_setting_call[UINT32_SETTING_RETRY_TIMER] = false,
     .del_uint32_setting_call[UINT32_SETTING_RECONCILIATION_TIMER] = false,
     .del_uint32_setting_call[UINT32_SETTING_SPEAKER_MIN_HOLD_TIME] = false,
     .del_uint32_setting_call[UINT32_SETTING_LISTENER_MIN_HOLD_TIME] = false,
     .del_uint32_setting_call[UINT32_SETTING_LISTENER_MAX_HOLD_TIME] = false,
     .del_uint32_setting_call[UINT32_SETTING_KEEPALIVE_TIMER] = false,
     .del_uint32_setting_call[UINT32_SETTING_SUBNET_EXPANSION_LIMIT] = false,
     .del_uint32_setting_call[UINT32_SETTING_BIND_ADDRESS] = false,
     .del_uint32_setting_call[UINT32_SETTING_PORT] = false,
     .del_uint32_setting_call[UINT32_SETTING_NODE_ID] = false,
     .add_str_setting_call[STR_SETTING_PASSWORD] = true,
     .del_str_setting_call[STR_SETTING_PASSWORD] = false,
    },
    {
     .add_uint32_setting_call[UINT32_SETTING_LOG_LEVEL] = false,
     .add_uint32_setting_call[UINT32_SETTING_ENABLED] = false,
     .add_uint32_setting_call[UINT32_SETTING_RETRY_TIMER] = false,
     .add_uint32_setting_call[UINT32_SETTING_RECONCILIATION_TIMER] = false,
     .add_uint32_setting_call[UINT32_SETTING_SPEAKER_MIN_HOLD_TIME] = false,
     .add_uint32_setting_call[UINT32_SETTING_LISTENER_MIN_HOLD_TIME] = false,
     .add_uint32_setting_call[UINT32_SETTING_LISTENER_MAX_HOLD_TIME] = false,
     .add_uint32_setting_call[UINT32_SETTING_KEEPALIVE_TIMER] = false,
     .add_uint32_setting_call[UINT32_SETTING_SUBNET_EXPANSION_LIMIT] = false,
     .add_uint32_setting_call[UINT32_SETTING_BIND_ADDRESS] = false,
     .add_uint32_setting_call[UINT32_SETTING_PORT] = false,
     .add_uint32_setting_call[UINT32_SETTING_NODE_ID] = false,
     .del_uint32_setting_call[UINT32_SETTING_LOG_LEVEL] = false,
     .del_uint32_setting_call[UINT32_SETTING_ENABLED] = false,
     .del_uint32_setting_call[UINT32_SETTING_RETRY_TIMER] = false,
     .del_uint32_setting_call[UINT32_SETTING_RECONCILIATION_TIMER] = false,
     .del_uint32_setting_call[UINT32_SETTING_SPEAKER_MIN_HOLD_TIME] = false,
     .del_uint32_setting_call[UINT32_SETTING_LISTENER_MIN_HOLD_TIME] = false,
     .del_uint32_setting_call[UINT32_SETTING_LISTENER_MAX_HOLD_TIME] = false,
     .del_uint32_setting_call[UINT32_SETTING_KEEPALIVE_TIMER] = false,
     .del_uint32_setting_call[UINT32_SETTING_SUBNET_EXPANSION_LIMIT] = false,
     .del_uint32_setting_call[UINT32_SETTING_BIND_ADDRESS] = false,
     .del_uint32_setting_call[UINT32_SETTING_PORT] = false,
     .del_uint32_setting_call[UINT32_SETTING_NODE_ID] = false,
     .add_str_setting_call[STR_SETTING_PASSWORD] = false,
     .del_str_setting_call[STR_SETTING_PASSWORD] = false,
    },
    {
     .add_uint32_setting_call[UINT32_SETTING_LOG_LEVEL] = false,
     .add_uint32_setting_call[UINT32_SETTING_ENABLED] = false,
     .add_uint32_setting_call[UINT32_SETTING_RETRY_TIMER] = false,
     .add_uint32_setting_call[UINT32_SETTING_RECONCILIATION_TIMER] = false,
     .add_uint32_setting_call[UINT32_SETTING_SPEAKER_MIN_HOLD_TIME] = false,
     .add_uint32_setting_call[UINT32_SETTING_LISTENER_MIN_HOLD_TIME] = false,
     .add_uint32_setting_call[UINT32_SETTING_LISTENER_MAX_HOLD_TIME] = false,
     .add_uint32_setting_call[UINT32_SETTING_KEEPALIVE_TIMER] = false,
     .add_uint32_setting_call[UINT32_SETTING_SUBNET_EXPANSION_LIMIT] = false,
     .add_uint32_setting_call[UINT32_SETTING_BIND_ADDRESS] = false,
     .add_uint32_setting_call[UINT32_SETTING_PORT] = false,
     .add_uint32_setting_call[UINT32_SETTING_NODE_ID] = false,
     .del_uint32_setting_call[UINT32_SETTING_LOG_LEVEL] = false,
     .del_uint32_setting_call[UINT32_SETTING_ENABLED] = false,
     .del_uint32_setting_call[UINT32_SETTING_RETRY_TIMER] = false,
     .del_uint32_setting_call[UINT32_SETTING_RECONCILIATION_TIMER] = false,
     .del_uint32_setting_call[UINT32_SETTING_SPEAKER_MIN_HOLD_TIME] = false,
     .del_uint32_setting_call[UINT32_SETTING_LISTENER_MIN_HOLD_TIME] = false,
     .del_uint32_setting_call[UINT32_SETTING_LISTENER_MAX_HOLD_TIME] = false,
     .del_uint32_setting_call[UINT32_SETTING_KEEPALIVE_TIMER] = false,
     .del_uint32_setting_call[UINT32_SETTING_SUBNET_EXPANSION_LIMIT] = false,
     .del_uint32_setting_call[UINT32_SETTING_BIND_ADDRESS] = false,
     .del_uint32_setting_call[UINT32_SETTING_PORT] = false,
     .del_uint32_setting_call[UINT32_SETTING_NODE_ID] = false,
     .add_str_setting_call[STR_SETTING_PASSWORD] = false,
     .del_str_setting_call[STR_SETTING_PASSWORD] = false,
    },
    {
     .add_uint32_setting_call[UINT32_SETTING_LOG_LEVEL] = true,
     .add_uint32_setting_call[UINT32_SETTING_ENABLED] = false,
     .add_uint32_setting_call[UINT32_SETTING_RETRY_TIMER] = false,
     .add_uint32_setting_call[UINT32_SETTING_RECONCILIATION_TIMER] = false,
     .add_uint32_setting_call[UINT32_SETTING_SPEAKER_MIN_HOLD_TIME] = false,
     .add_uint32_setting_call[UINT32_SETTING_LISTENER_MIN_HOLD_TIME] = false,
     .add_uint32_setting_call[UINT32_SETTING_LISTENER_MAX_HOLD_TIME] = false,
     .add_uint32_setting_call[UINT32_SETTING_KEEPALIVE_TIMER] = false,
     .add_uint32_setting_call[UINT32_SETTING_SUBNET_EXPANSION_LIMIT] = false,
     .add_uint32_setting_call[UINT32_SETTING_BIND_ADDRESS] = false,
     .add_uint32_setting_call[UINT32_SETTING_PORT] = false,
     .add_uint32_setting_call[UINT32_SETTING_NODE_ID] = false,
     .del_uint32_setting_call[UINT32_SETTING_LOG_LEVEL] = false,
     .del_uint32_setting_call[UINT32_SETTING_ENABLED] = false,
     .del_uint32_setting_call[UINT32_SETTING_RETRY_TIMER] = false,
     .del_uint32_setting_call[UINT32_SETTING_RECONCILIATION_TIMER] = false,
     .del_uint32_setting_call[UINT32_SETTING_SPEAKER_MIN_HOLD_TIME] = false,
     .del_uint32_setting_call[UINT32_SETTING_LISTENER_MIN_HOLD_TIME] = false,
     .del_uint32_setting_call[UINT32_SETTING_LISTENER_MAX_HOLD_TIME] = false,
     .del_uint32_setting_call[UINT32_SETTING_KEEPALIVE_TIMER] = false,
     .del_uint32_setting_call[UINT32_SETTING_SUBNET_EXPANSION_LIMIT] = false,
     .del_uint32_setting_call[UINT32_SETTING_BIND_ADDRESS] = false,
     .del_uint32_setting_call[UINT32_SETTING_PORT] = false,
     .del_uint32_setting_call[UINT32_SETTING_NODE_ID] = false,
     .add_str_setting_call[STR_SETTING_PASSWORD] = false,
     .del_str_setting_call[STR_SETTING_PASSWORD] = false,
    },
    {
     .add_uint32_setting_call[UINT32_SETTING_LOG_LEVEL] = false,
     .add_uint32_setting_call[UINT32_SETTING_ENABLED] = false,
     .add_uint32_setting_call[UINT32_SETTING_RETRY_TIMER] = false,
     .add_uint32_setting_call[UINT32_SETTING_RECONCILIATION_TIMER] = false,
     .add_uint32_setting_call[UINT32_SETTING_SPEAKER_MIN_HOLD_TIME] = false,
     .add_uint32_setting_call[UINT32_SETTING_LISTENER_MIN_HOLD_TIME] = false,
     .add_uint32_setting_call[UINT32_SETTING_LISTENER_MAX_HOLD_TIME] = false,
     .add_uint32_setting_call[UINT32_SETTING_KEEPALIVE_TIMER] = false,
     .add_uint32_setting_call[UINT32_SETTING_SUBNET_EXPANSION_LIMIT] = false,
     .add_uint32_setting_call[UINT32_SETTING_BIND_ADDRESS] = false,
     .add_uint32_setting_call[UINT32_SETTING_PORT] = false,
     .add_uint32_setting_call[UINT32_SETTING_NODE_ID] = false,
     .del_uint32_setting_call[UINT32_SETTING_LOG_LEVEL] = false,
     .del_uint32_setting_call[UINT32_SETTING_ENABLED] = false,
     .del_uint32_setting_call[UINT32_SETTING_RETRY_TIMER] = false,
     .del_uint32_setting_call[UINT32_SETTING_RECONCILIATION_TIMER] = false,
     .del_uint32_setting_call[UINT32_SETTING_SPEAKER_MIN_HOLD_TIME] = false,
     .del_uint32_setting_call[UINT32_SETTING_LISTENER_MIN_HOLD_TIME] = false,
     .del_uint32_setting_call[UINT32_SETTING_LISTENER_MAX_HOLD_TIME] = false,
     .del_uint32_setting_call[UINT32_SETTING_KEEPALIVE_TIMER] = false,
     .del_uint32_setting_call[UINT32_SETTING_SUBNET_EXPANSION_LIMIT] = false,
     .del_uint32_setting_call[UINT32_SETTING_BIND_ADDRESS] = false,
     .del_uint32_setting_call[UINT32_SETTING_PORT] = false,
     .del_uint32_setting_call[UINT32_SETTING_NODE_ID] = false,
     .add_str_setting_call[STR_SETTING_PASSWORD] = false,
     .del_str_setting_call[STR_SETTING_PASSWORD] = false,
    },
    {
     .add_uint32_setting_call[UINT32_SETTING_LOG_LEVEL] = false,
     .add_uint32_setting_call[UINT32_SETTING_ENABLED] = false,
     .add_uint32_setting_call[UINT32_SETTING_RETRY_TIMER] = false,
     .add_uint32_setting_call[UINT32_SETTING_RECONCILIATION_TIMER] = false,
     .add_uint32_setting_call[UINT32_SETTING_SPEAKER_MIN_HOLD_TIME] = false,
     .add_uint32_setting_call[UINT32_SETTING_LISTENER_MIN_HOLD_TIME] = false,
     .add_uint32_setting_call[UINT32_SETTING_LISTENER_MAX_HOLD_TIME] = false,
     .add_uint32_setting_call[UINT32_SETTING_KEEPALIVE_TIMER] = false,
     .add_uint32_setting_call[UINT32_SETTING_SUBNET_EXPANSION_LIMIT] = false,
     .add_uint32_setting_call[UINT32_SETTING_BIND_ADDRESS] = false,
     .add_uint32_setting_call[UINT32_SETTING_PORT] = false,
     .add_uint32_setting_call[UINT32_SETTING_NODE_ID] = false,
     .del_uint32_setting_call[UINT32_SETTING_LOG_LEVEL] = false,
     .del_uint32_setting_call[UINT32_SETTING_ENABLED] = false,
     .del_uint32_setting_call[UINT32_SETTING_RETRY_TIMER] = false,
     .del_uint32_setting_call[UINT32_SETTING_RECONCILIATION_TIMER] = false,
     .del_uint32_setting_call[UINT32_SETTING_SPEAKER_MIN_HOLD_TIME] = false,
     .del_uint32_setting_call[UINT32_SETTING_LISTENER_MIN_HOLD_TIME] = false,
     .del_uint32_setting_call[UINT32_SETTING_LISTENER_MAX_HOLD_TIME] = false,
     .del_uint32_setting_call[UINT32_SETTING_KEEPALIVE_TIMER] = false,
     .del_uint32_setting_call[UINT32_SETTING_SUBNET_EXPANSION_LIMIT] = false,
     .del_uint32_setting_call[UINT32_SETTING_BIND_ADDRESS] = false,
     .del_uint32_setting_call[UINT32_SETTING_PORT] = false,
     .del_uint32_setting_call[UINT32_SETTING_NODE_ID] = false,
     .add_str_setting_call[STR_SETTING_PASSWORD] = false,
     .del_str_setting_call[STR_SETTING_PASSWORD] = false,
    },
    {
     .add_uint32_setting_call[UINT32_SETTING_LOG_LEVEL] = false,
     .add_uint32_setting_call[UINT32_SETTING_ENABLED] = false,
     .add_uint32_setting_call[UINT32_SETTING_RETRY_TIMER] = false,
     .add_uint32_setting_call[UINT32_SETTING_RECONCILIATION_TIMER] = false,
     .add_uint32_setting_call[UINT32_SETTING_SPEAKER_MIN_HOLD_TIME] = false,
     .add_uint32_setting_call[UINT32_SETTING_LISTENER_MIN_HOLD_TIME] = false,
     .add_uint32_setting_call[UINT32_SETTING_LISTENER_MAX_HOLD_TIME] = false,
     .add_uint32_setting_call[UINT32_SETTING_KEEPALIVE_TIMER] = false,
     .add_uint32_setting_call[UINT32_SETTING_SUBNET_EXPANSION_LIMIT] = false,
     .add_uint32_setting_call[UINT32_SETTING_BIND_ADDRESS] = false,
     .add_uint32_setting_call[UINT32_SETTING_PORT] = false,
     .add_uint32_setting_call[UINT32_SETTING_NODE_ID] = false,
     .del_uint32_setting_call[UINT32_SETTING_LOG_LEVEL] = false,
     .del_uint32_setting_call[UINT32_SETTING_ENABLED] = false,
     .del_uint32_setting_call[UINT32_SETTING_RETRY_TIMER] = false,
     .del_uint32_setting_call[UINT32_SETTING_RECONCILIATION_TIMER] = false,
     .del_uint32_setting_call[UINT32_SETTING_SPEAKER_MIN_HOLD_TIME] = false,
     .del_uint32_setting_call[UINT32_SETTING_LISTENER_MIN_HOLD_TIME] = false,
     .del_uint32_setting_call[UINT32_SETTING_LISTENER_MAX_HOLD_TIME] = false,
     .del_uint32_setting_call[UINT32_SETTING_KEEPALIVE_TIMER] = false,
     .del_uint32_setting_call[UINT32_SETTING_SUBNET_EXPANSION_LIMIT] = false,
     .del_uint32_setting_call[UINT32_SETTING_BIND_ADDRESS] = false,
     .del_uint32_setting_call[UINT32_SETTING_PORT] = false,
     .del_uint32_setting_call[UINT32_SETTING_NODE_ID] = false,
     .add_str_setting_call[STR_SETTING_PASSWORD] = false,
     .del_str_setting_call[STR_SETTING_PASSWORD] = false,
    },
};

static struct test_settings exp_settings[] = {
    {
     .is_set_uint32_val[UINT32_SETTING_LOG_LEVEL] = true,
     .uint32_val[UINT32_SETTING_LOG_LEVEL] = LOG_LEVEL_ALERT,
     .is_set_uint32_val[UINT32_SETTING_ENABLED] = true,
     .uint32_val[UINT32_SETTING_ENABLED] = true,
     .is_set_uint32_val[UINT32_SETTING_RETRY_TIMER] = true,
     .uint32_val[UINT32_SETTING_RETRY_TIMER] = 5,
     .is_set_uint32_val[UINT32_SETTING_RECONCILIATION_TIMER] = true,
     .uint32_val[UINT32_SETTING_RECONCILIATION_TIMER] = 80,
     .is_set_uint32_val[UINT32_SETTING_SPEAKER_MIN_HOLD_TIME] = true,
     .uint32_val[UINT32_SETTING_SPEAKER_MIN_HOLD_TIME] = 90,
     .is_set_uint32_val[UINT32_SETTING_LISTENER_MIN_HOLD_TIME] = true,
     .uint32_val[UINT32_SETTING_LISTENER_MIN_HOLD_TIME] = 80,
     .is_set_uint32_val[UINT32_SETTING_LISTENER_MAX_HOLD_TIME] = true,
     .uint32_val[UINT32_SETTING_LISTENER_MAX_HOLD_TIME] = 120,
     .is_set_uint32_val[UINT32_SETTING_KEEPALIVE_TIMER] = true,
     .uint32_val[UINT32_SETTING_KEEPALIVE_TIMER] = 60,
     .is_set_uint32_val[UINT32_SETTING_SUBNET_EXPANSION_LIMIT] = true,
     .uint32_val[UINT32_SETTING_SUBNET_EXPANSION_LIMIT] = 50,
     .is_set_uint32_val[UINT32_SETTING_BIND_ADDRESS] = true,
     .uint32_val[UINT32_SETTING_BIND_ADDRESS] = 43200, /* network byte order */
     .is_set_uint32_val[UINT32_SETTING_PORT] = true,
     .uint32_val[UINT32_SETTING_PORT] = 250, /* network byte order */
     .is_set_uint32_val[UINT32_SETTING_NODE_ID] = true,
     .uint32_val[UINT32_SETTING_NODE_ID] = 0x00112233,
     .is_set_str_val[STR_SETTING_PASSWORD] = true,
     .default_connection_password = { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' },
    },
    {
     .is_set_uint32_val[UINT32_SETTING_LOG_LEVEL] = true,
     .uint32_val[UINT32_SETTING_LOG_LEVEL] = LOG_LEVEL_ALERT,
     .is_set_uint32_val[UINT32_SETTING_ENABLED] = true,
     .uint32_val[UINT32_SETTING_ENABLED] = true,
     .is_set_uint32_val[UINT32_SETTING_RETRY_TIMER] = true,
     .uint32_val[UINT32_SETTING_RETRY_TIMER] = 5,
     .is_set_uint32_val[UINT32_SETTING_RECONCILIATION_TIMER] = true,
     .uint32_val[UINT32_SETTING_RECONCILIATION_TIMER] = 80,
     .is_set_uint32_val[UINT32_SETTING_SPEAKER_MIN_HOLD_TIME] = true,
     .uint32_val[UINT32_SETTING_SPEAKER_MIN_HOLD_TIME] = 90,
     .is_set_uint32_val[UINT32_SETTING_LISTENER_MIN_HOLD_TIME] = true,
     .uint32_val[UINT32_SETTING_LISTENER_MIN_HOLD_TIME] = 80,
     .is_set_uint32_val[UINT32_SETTING_LISTENER_MAX_HOLD_TIME] = true,
     .uint32_val[UINT32_SETTING_LISTENER_MAX_HOLD_TIME] = 120,
     .is_set_uint32_val[UINT32_SETTING_KEEPALIVE_TIMER] = true,
     .uint32_val[UINT32_SETTING_KEEPALIVE_TIMER] = 60,
     .is_set_uint32_val[UINT32_SETTING_SUBNET_EXPANSION_LIMIT] = true,
     .uint32_val[UINT32_SETTING_SUBNET_EXPANSION_LIMIT] = 50,
     .is_set_uint32_val[UINT32_SETTING_BIND_ADDRESS] = true,
     .uint32_val[UINT32_SETTING_BIND_ADDRESS] = 43200, /* network byte order */
     .is_set_uint32_val[UINT32_SETTING_PORT] = true,
     .uint32_val[UINT32_SETTING_PORT] = 250, /* network byte order */
     .is_set_uint32_val[UINT32_SETTING_NODE_ID] = true,
     .uint32_val[UINT32_SETTING_NODE_ID] = 0x00112233,
     .is_set_str_val[STR_SETTING_PASSWORD] = true,
     .default_connection_password = { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' },
    },
    {
     .is_set_uint32_val[UINT32_SETTING_LOG_LEVEL] = true,
     .uint32_val[UINT32_SETTING_LOG_LEVEL] = LOG_LEVEL_ERROR,
     .is_set_uint32_val[UINT32_SETTING_ENABLED] = true,
     .uint32_val[UINT32_SETTING_ENABLED] = false,
     .is_set_uint32_val[UINT32_SETTING_RETRY_TIMER] = true,
     .uint32_val[UINT32_SETTING_RETRY_TIMER] = 6,
     .is_set_uint32_val[UINT32_SETTING_RECONCILIATION_TIMER] = true,
     .uint32_val[UINT32_SETTING_RECONCILIATION_TIMER] = 81,
     .is_set_uint32_val[UINT32_SETTING_SPEAKER_MIN_HOLD_TIME] = true,
     .uint32_val[UINT32_SETTING_SPEAKER_MIN_HOLD_TIME] = 91,
     .is_set_uint32_val[UINT32_SETTING_LISTENER_MIN_HOLD_TIME] = true,
     .uint32_val[UINT32_SETTING_LISTENER_MIN_HOLD_TIME] = 82,
     .is_set_uint32_val[UINT32_SETTING_LISTENER_MAX_HOLD_TIME] = true,
     .uint32_val[UINT32_SETTING_LISTENER_MAX_HOLD_TIME] = 121,
     .is_set_uint32_val[UINT32_SETTING_KEEPALIVE_TIMER] = true,
     .uint32_val[UINT32_SETTING_KEEPALIVE_TIMER] = 61,
     .is_set_uint32_val[UINT32_SETTING_SUBNET_EXPANSION_LIMIT] = true,
     .uint32_val[UINT32_SETTING_SUBNET_EXPANSION_LIMIT] = 51,
     .is_set_uint32_val[UINT32_SETTING_BIND_ADDRESS] = true,
     .uint32_val[UINT32_SETTING_BIND_ADDRESS] =
         16820416, /* network byte order */
     .is_set_uint32_val[UINT32_SETTING_PORT] = true,
     .uint32_val[UINT32_SETTING_PORT] = 506, /* network byte order */
     .is_set_uint32_val[UINT32_SETTING_NODE_ID] = true,
     .uint32_val[UINT32_SETTING_NODE_ID] = 0x00112234,
     .is_set_str_val[STR_SETTING_PASSWORD] = true,
     .default_connection_password = { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
                                      '2' },
    },
    {
     .is_set_uint32_val[UINT32_SETTING_LOG_LEVEL] = true,
     .uint32_val[UINT32_SETTING_LOG_LEVEL] = LOG_LEVEL_ERROR,
     .is_set_uint32_val[UINT32_SETTING_ENABLED] = true,
     .uint32_val[UINT32_SETTING_ENABLED] = false,
     .is_set_uint32_val[UINT32_SETTING_RETRY_TIMER] = true,
     .uint32_val[UINT32_SETTING_RETRY_TIMER] = 6,
     .is_set_uint32_val[UINT32_SETTING_RECONCILIATION_TIMER] = true,
     .uint32_val[UINT32_SETTING_RECONCILIATION_TIMER] = 81,
     .is_set_uint32_val[UINT32_SETTING_SPEAKER_MIN_HOLD_TIME] = true,
     .uint32_val[UINT32_SETTING_SPEAKER_MIN_HOLD_TIME] = 91,
     .is_set_uint32_val[UINT32_SETTING_LISTENER_MIN_HOLD_TIME] = true,
     .uint32_val[UINT32_SETTING_LISTENER_MIN_HOLD_TIME] = 82,
     .is_set_uint32_val[UINT32_SETTING_LISTENER_MAX_HOLD_TIME] = true,
     .uint32_val[UINT32_SETTING_LISTENER_MAX_HOLD_TIME] = 121,
     .is_set_uint32_val[UINT32_SETTING_KEEPALIVE_TIMER] = true,
     .uint32_val[UINT32_SETTING_KEEPALIVE_TIMER] = 61,
     .is_set_uint32_val[UINT32_SETTING_SUBNET_EXPANSION_LIMIT] = true,
     .uint32_val[UINT32_SETTING_SUBNET_EXPANSION_LIMIT] = 51,
     .is_set_uint32_val[UINT32_SETTING_BIND_ADDRESS] = true,
     .uint32_val[UINT32_SETTING_BIND_ADDRESS] =
         16820416, /* network byte order */
     .is_set_uint32_val[UINT32_SETTING_PORT] = true,
     .uint32_val[UINT32_SETTING_PORT] = 506, /* network byte order */
     .is_set_uint32_val[UINT32_SETTING_NODE_ID] = true,
     .uint32_val[UINT32_SETTING_NODE_ID] = 0x00112234,
     .is_set_str_val[STR_SETTING_PASSWORD] = true,
     .default_connection_password = { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
                                      '2' },
    },
    {
     .is_set_uint32_val[UINT32_SETTING_LOG_LEVEL] = true,
     .uint32_val[UINT32_SETTING_LOG_LEVEL] = LOG_LEVEL_ERROR,
     .is_set_uint32_val[UINT32_SETTING_ENABLED] = true,
     .uint32_val[UINT32_SETTING_ENABLED] = false,
     .is_set_uint32_val[UINT32_SETTING_RETRY_TIMER] = true,
     .uint32_val[UINT32_SETTING_RETRY_TIMER] = 6,
     .is_set_uint32_val[UINT32_SETTING_RECONCILIATION_TIMER] = true,
     .uint32_val[UINT32_SETTING_RECONCILIATION_TIMER] = 81,
     .is_set_uint32_val[UINT32_SETTING_SPEAKER_MIN_HOLD_TIME] = true,
     .uint32_val[UINT32_SETTING_SPEAKER_MIN_HOLD_TIME] = 91,
     .is_set_uint32_val[UINT32_SETTING_LISTENER_MIN_HOLD_TIME] = true,
     .uint32_val[UINT32_SETTING_LISTENER_MIN_HOLD_TIME] = 82,
     .is_set_uint32_val[UINT32_SETTING_LISTENER_MAX_HOLD_TIME] = true,
     .uint32_val[UINT32_SETTING_LISTENER_MAX_HOLD_TIME] = 121,
     .is_set_uint32_val[UINT32_SETTING_KEEPALIVE_TIMER] = true,
     .uint32_val[UINT32_SETTING_KEEPALIVE_TIMER] = 61,
     .is_set_uint32_val[UINT32_SETTING_SUBNET_EXPANSION_LIMIT] = true,
     .uint32_val[UINT32_SETTING_SUBNET_EXPANSION_LIMIT] = 51,
     .is_set_uint32_val[UINT32_SETTING_BIND_ADDRESS] = true,
     .uint32_val[UINT32_SETTING_BIND_ADDRESS] =
         16820416, /* network byte order */
     .is_set_uint32_val[UINT32_SETTING_PORT] = true,
     .uint32_val[UINT32_SETTING_PORT] = 506, /* network byte order */
     .is_set_uint32_val[UINT32_SETTING_NODE_ID] = true,
     .uint32_val[UINT32_SETTING_NODE_ID] = 0x00112234,
     .is_set_str_val[STR_SETTING_PASSWORD] = true,
     .default_connection_password = { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
                                      '2' },
    },
    {
     .is_set_uint32_val[UINT32_SETTING_LOG_LEVEL] = true,
     .uint32_val[UINT32_SETTING_LOG_LEVEL] = LOG_LEVEL_DEBUG,
     .is_set_uint32_val[UINT32_SETTING_ENABLED] = true,
     .uint32_val[UINT32_SETTING_ENABLED] = false,
     .is_set_uint32_val[UINT32_SETTING_RETRY_TIMER] = true,
     .uint32_val[UINT32_SETTING_RETRY_TIMER] = 6,
     .is_set_uint32_val[UINT32_SETTING_RECONCILIATION_TIMER] = true,
     .uint32_val[UINT32_SETTING_RECONCILIATION_TIMER] = 81,
     .is_set_uint32_val[UINT32_SETTING_SPEAKER_MIN_HOLD_TIME] = true,
     .uint32_val[UINT32_SETTING_SPEAKER_MIN_HOLD_TIME] = 91,
     .is_set_uint32_val[UINT32_SETTING_LISTENER_MIN_HOLD_TIME] = true,
     .uint32_val[UINT32_SETTING_LISTENER_MIN_HOLD_TIME] = 82,
     .is_set_uint32_val[UINT32_SETTING_LISTENER_MAX_HOLD_TIME] = true,
     .uint32_val[UINT32_SETTING_LISTENER_MAX_HOLD_TIME] = 121,
     .is_set_uint32_val[UINT32_SETTING_KEEPALIVE_TIMER] = true,
     .uint32_val[UINT32_SETTING_KEEPALIVE_TIMER] = 61,
     .is_set_uint32_val[UINT32_SETTING_SUBNET_EXPANSION_LIMIT] = true,
     .uint32_val[UINT32_SETTING_SUBNET_EXPANSION_LIMIT] = 51,
     .is_set_uint32_val[UINT32_SETTING_BIND_ADDRESS] = true,
     .uint32_val[UINT32_SETTING_BIND_ADDRESS] =
         16820416, /* network byte order */
     .is_set_uint32_val[UINT32_SETTING_PORT] = true,
     .uint32_val[UINT32_SETTING_PORT] = 506, /* network byte order */
     .is_set_uint32_val[UINT32_SETTING_NODE_ID] = true,
     .uint32_val[UINT32_SETTING_NODE_ID] = 0x00112234,
     .is_set_str_val[STR_SETTING_PASSWORD] = true,
     .default_connection_password = { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
                                      '2' },
    },
    {
     .is_set_uint32_val[UINT32_SETTING_LOG_LEVEL] = true,
     .uint32_val[UINT32_SETTING_LOG_LEVEL] = LOG_LEVEL_DEBUG,
     .is_set_uint32_val[UINT32_SETTING_ENABLED] = true,
     .uint32_val[UINT32_SETTING_ENABLED] = false,
     .is_set_uint32_val[UINT32_SETTING_RETRY_TIMER] = true,
     .uint32_val[UINT32_SETTING_RETRY_TIMER] = 6,
     .is_set_uint32_val[UINT32_SETTING_RECONCILIATION_TIMER] = true,
     .uint32_val[UINT32_SETTING_RECONCILIATION_TIMER] = 81,
     .is_set_uint32_val[UINT32_SETTING_SPEAKER_MIN_HOLD_TIME] = true,
     .uint32_val[UINT32_SETTING_SPEAKER_MIN_HOLD_TIME] = 91,
     .is_set_uint32_val[UINT32_SETTING_LISTENER_MIN_HOLD_TIME] = true,
     .uint32_val[UINT32_SETTING_LISTENER_MIN_HOLD_TIME] = 82,
     .is_set_uint32_val[UINT32_SETTING_LISTENER_MAX_HOLD_TIME] = true,
     .uint32_val[UINT32_SETTING_LISTENER_MAX_HOLD_TIME] = 121,
     .is_set_uint32_val[UINT32_SETTING_KEEPALIVE_TIMER] = true,
     .uint32_val[UINT32_SETTING_KEEPALIVE_TIMER] = 61,
     .is_set_uint32_val[UINT32_SETTING_SUBNET_EXPANSION_LIMIT] = true,
     .uint32_val[UINT32_SETTING_SUBNET_EXPANSION_LIMIT] = 51,
     .is_set_uint32_val[UINT32_SETTING_BIND_ADDRESS] = true,
     .uint32_val[UINT32_SETTING_BIND_ADDRESS] =
         16820416, /* network byte order */
     .is_set_uint32_val[UINT32_SETTING_PORT] = true,
     .uint32_val[UINT32_SETTING_PORT] = 506, /* network byte order */
     .is_set_uint32_val[UINT32_SETTING_NODE_ID] = true,
     .uint32_val[UINT32_SETTING_NODE_ID] = 0x00112234,
     .is_set_str_val[STR_SETTING_PASSWORD] = true,
     .default_connection_password = { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
                                      '2' },
    },
    {
     .is_set_uint32_val[UINT32_SETTING_LOG_LEVEL] = true,
     .uint32_val[UINT32_SETTING_LOG_LEVEL] = LOG_LEVEL_DEBUG,
     .is_set_uint32_val[UINT32_SETTING_ENABLED] = true,
     .uint32_val[UINT32_SETTING_ENABLED] = false,
     .is_set_uint32_val[UINT32_SETTING_RETRY_TIMER] = true,
     .uint32_val[UINT32_SETTING_RETRY_TIMER] = 6,
     .is_set_uint32_val[UINT32_SETTING_RECONCILIATION_TIMER] = true,
     .uint32_val[UINT32_SETTING_RECONCILIATION_TIMER] = 81,
     .is_set_uint32_val[UINT32_SETTING_SPEAKER_MIN_HOLD_TIME] = true,
     .uint32_val[UINT32_SETTING_SPEAKER_MIN_HOLD_TIME] = 91,
     .is_set_uint32_val[UINT32_SETTING_LISTENER_MIN_HOLD_TIME] = true,
     .uint32_val[UINT32_SETTING_LISTENER_MIN_HOLD_TIME] = 82,
     .is_set_uint32_val[UINT32_SETTING_LISTENER_MAX_HOLD_TIME] = true,
     .uint32_val[UINT32_SETTING_LISTENER_MAX_HOLD_TIME] = 121,
     .is_set_uint32_val[UINT32_SETTING_KEEPALIVE_TIMER] = true,
     .uint32_val[UINT32_SETTING_KEEPALIVE_TIMER] = 61,
     .is_set_uint32_val[UINT32_SETTING_SUBNET_EXPANSION_LIMIT] = true,
     .uint32_val[UINT32_SETTING_SUBNET_EXPANSION_LIMIT] = 51,
     .is_set_uint32_val[UINT32_SETTING_BIND_ADDRESS] = true,
     .uint32_val[UINT32_SETTING_BIND_ADDRESS] =
         16820416, /* network byte order */
     .is_set_uint32_val[UINT32_SETTING_PORT] = true,
     .uint32_val[UINT32_SETTING_PORT] = 506, /* network byte order */
     .is_set_uint32_val[UINT32_SETTING_NODE_ID] = true,
     .uint32_val[UINT32_SETTING_NODE_ID] = 0x00112234,
     .is_set_str_val[STR_SETTING_PASSWORD] = true,
     .default_connection_password = { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
                                      '2' },
    },
    {
     .is_set_uint32_val[UINT32_SETTING_LOG_LEVEL] = true,
     .uint32_val[UINT32_SETTING_LOG_LEVEL] = LOG_LEVEL_DEBUG,
     .is_set_uint32_val[UINT32_SETTING_ENABLED] = true,
     .uint32_val[UINT32_SETTING_ENABLED] = false,
     .is_set_uint32_val[UINT32_SETTING_RETRY_TIMER] = true,
     .uint32_val[UINT32_SETTING_RETRY_TIMER] = 6,
     .is_set_uint32_val[UINT32_SETTING_RECONCILIATION_TIMER] = true,
     .uint32_val[UINT32_SETTING_RECONCILIATION_TIMER] = 81,
     .is_set_uint32_val[UINT32_SETTING_SPEAKER_MIN_HOLD_TIME] = true,
     .uint32_val[UINT32_SETTING_SPEAKER_MIN_HOLD_TIME] = 91,
     .is_set_uint32_val[UINT32_SETTING_LISTENER_MIN_HOLD_TIME] = true,
     .uint32_val[UINT32_SETTING_LISTENER_MIN_HOLD_TIME] = 82,
     .is_set_uint32_val[UINT32_SETTING_LISTENER_MAX_HOLD_TIME] = true,
     .uint32_val[UINT32_SETTING_LISTENER_MAX_HOLD_TIME] = 121,
     .is_set_uint32_val[UINT32_SETTING_KEEPALIVE_TIMER] = true,
     .uint32_val[UINT32_SETTING_KEEPALIVE_TIMER] = 61,
     .is_set_uint32_val[UINT32_SETTING_SUBNET_EXPANSION_LIMIT] = true,
     .uint32_val[UINT32_SETTING_SUBNET_EXPANSION_LIMIT] = 51,
     .is_set_uint32_val[UINT32_SETTING_BIND_ADDRESS] = true,
     .uint32_val[UINT32_SETTING_BIND_ADDRESS] =
         16820416, /* network byte order */
     .is_set_uint32_val[UINT32_SETTING_PORT] = true,
     .uint32_val[UINT32_SETTING_PORT] = 506, /* network byte order */
     .is_set_uint32_val[UINT32_SETTING_NODE_ID] = true,
     .uint32_val[UINT32_SETTING_NODE_ID] = 0x00112234,
     .is_set_str_val[STR_SETTING_PASSWORD] = true,
     .default_connection_password = { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
                                      '2' },
    },
};

#define RESET_CB_CALL_ADD_UINT32(enumerator, string) \
    cb_calls->add_uint32_setting_call[enumerator] = false;
#define RESET_CB_CALL_DEL_UINT32(enumerator, string) \
    cb_calls->del_uint32_setting_call[enumerator] = false;
#define RESET_CB_CALL_ADD_STR(enumerator, string) \
    cb_calls->add_str_setting_call[enumerator] = false;
#define RESET_CB_CALL_DEL_STR(enumerator, string) \
    cb_calls->del_str_setting_call[enumerator] = false;

/**
 * @brief resets global configuration callback calls
 * @param cb_calls callback calls structure to be reseted
 */
static void reset_cb_calls(struct test_settings_cb_calls *cb_calls)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, cb_calls);

    if (RC_ISOK(rc)) {
        TUPLE_UINT32_CFG_DEF(RESET_CB_CALL_ADD_UINT32);
        TUPLE_UINT32_CFG_DEF(RESET_CB_CALL_DEL_UINT32);
        TUPLE_STR_CFG_DEF(RESET_CB_CALL_ADD_STR);
        TUPLE_STR_CFG_DEF(RESET_CB_CALL_DEL_STR);
    }
}

static int
cfg_add_str_setting_cb(__attribute__((unused)) struct sxpd_ctx *cb_ctx,
                       str_setting_type_t type, const char *value)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, value);
    RC_CHECK(rc, out);

    if (type >= STR_SETTING_LAST) {
        LOG_ERROR("Add string setting callback received invalid setting "
                  "type <%d>",
                  type);
        rc = -1;
        goto out;
    }

    settings.is_set_str_val[type] = true;
    switch (type) {
    case STR_SETTING_PASSWORD:
        strncpy(settings.default_connection_password, value,
                CFG_PASSWORD_MAX_SIZE);
        break;
    default:
        LOG_ERROR("Add string setting callback received invalid "
                  "setting type <%d>",
                  type);
        rc = -1;
        goto out;
    }

    settings_cb_calls.add_str_setting_call[type] = true;
    LOG_TRACE("added string setting #%d <%s> value: %s", type,
              cfg_get_str_setting_str(type), value);

out:
    return rc;
}

static int
cfg_del_str_setting_cb(__attribute__((unused)) struct sxpd_ctx *cb_ctx,
                       str_setting_type_t type)
{
    int rc = 0;

    if (type >= STR_SETTING_LAST) {
        LOG_ERROR("Del string setting callback received invalid setting "
                  "type <%d>",
                  type);
        rc = -1;
        goto out;
    }

    settings.is_set_str_val[type] = false;
    switch (type) {
    case STR_SETTING_PASSWORD:
        settings.default_connection_password[0] = '\0';
        break;
    default:
        LOG_ERROR("Del string setting callback received invalid "
                  "setting type #%d",
                  type);
        rc = -1;
        goto out;
    }

    settings_cb_calls.del_str_setting_call[type] = true;
    LOG_TRACE("deleted string setting #%d <%s>", type,
              cfg_get_str_setting_str(type));

out:
    return rc;
}

static int
cfg_add_uint32_setting_cb(__attribute__((unused)) struct sxpd_ctx *ctx,
                          uint32_setting_type_t type, uint32_t value)
{
    int rc = 0;

    if (type >= UINT32_SETTING_LAST) {
        LOG_ERROR("Add uint32 setting callback received invalid setting "
                  "type <%d>",
                  type);
        rc = -1;
        goto out;
    }

    settings.is_set_uint32_val[type] = true;
    settings.uint32_val[type] = value;
    settings_cb_calls.add_uint32_setting_call[type] = true;

    LOG_TRACE("added uint32 setting #%d <%s> value: %" PRIu32, type,
              cfg_get_uint32_setting_str(type), value);

out:
    return rc;
}

static int
cfg_del_uint32_setting_cb(__attribute__((unused)) struct sxpd_ctx *cb_ctx,
                          uint32_setting_type_t type)
{
    int rc = 0;

    if (type >= UINT32_SETTING_LAST) {
        LOG_ERROR("Del uint32 setting callback received invalid setting "
                  "type <%d>",
                  type);
        rc = -1;
        goto out;
    }

    settings.is_set_uint32_val[type] = false;
    settings.uint32_val[type] = 0;

    settings_cb_calls.del_uint32_setting_call[type] = true;

    LOG_TRACE("deleted uint32 setting #%d <%s>", type,
              cfg_get_uint32_setting_str(type));

out:
    return rc;
}

static struct test_peer_exp_upt *cfg_find_exp_peer(const struct peer *peer)
{
    int rc = 0;
    struct test_peer_exp_upt *peer_exp = NULL;
    size_t i = 0;

    PARAM_NULL_CHECK(rc, peer);

    if (RC_ISOK(rc)) {
        for (i = 0; i < MAX_PEER_CB &&
                        peer_exp_upt[cfg_reload_actual][i].exist == true;
             i++) {

            peer_exp = &peer_exp_upt[cfg_reload_actual][i];

            if ((peer_exp->peer.peer_type == peer->peer_type) &&
                (peer_exp->peer.ip_address == peer->ip_address) &&
                (peer_exp->peer.port_is_set == peer->port_is_set) &&
                (peer_exp->peer.port == peer->port) &&
                (((peer_exp->peer.connection_password == NULL) &&
                  (peer->connection_password == NULL)) ||
                 ((peer_exp->peer.connection_password != NULL) &&
                  (peer->connection_password != NULL) &&
                  (strcmp(peer_exp->peer.connection_password,
                          peer->connection_password) == 0)))) {
                break;
            } else {
                peer_exp = NULL;
            }
        }
    }

    if (RC_ISOK(rc)) {
        if (peer_exp != NULL) {
            LOG_TRACE("Expected peer: %" PRIu32 ":%" PRIu16 " found",
                      peer->ip_address, peer->port);
        } else {
            LOG_ERROR("Expected peer: %" PRIu32 ":%" PRIu16 " not found",
                      peer->ip_address, peer->port);
        }
    }

    return peer_exp;
}

static struct test_binding_exp_upt *
cfg_find_exp_binding(const struct binding *binding)
{
    int rc = 0;
    struct test_binding_exp_upt *binding_exp = NULL;
    size_t i = 0;

    PARAM_NULL_CHECK(rc, binding);

    if (RC_ISOK(rc)) {
        for (i = 0; i < MAX_PEER_CB &&
                        binding_exp_upt[cfg_reload_actual][i].exist == true;
             i++) {

            binding_exp = &binding_exp_upt[cfg_reload_actual][i];

            if ((binding_exp->binding.source_group_tag ==
                 binding->source_group_tag) &&
                (binding_exp->binding.prefix_length ==
                 binding->prefix_length) &&
                (binding_exp->binding.type == binding->type) &&
                (memcmp(&binding_exp->binding.prefix.prefix_v4,
                        &binding->prefix.prefix_v4,
                        binding->type == PREFIX_IPV4
                            ? sizeof(uint32_t)
                            : sizeof(uint32_t) * 4) == 0)) {
                break;
            } else {
                binding_exp = NULL;
            }
        }
    }

    if (RC_ISOK(rc)) {
        if (binding_exp != NULL) {
            LOG_TRACE("Expected binding with sgt: %" PRIu16 " found",
                      binding->source_group_tag);
        } else {
            LOG_ERROR("Expected binding with sgt: %" PRIu16 " not found",
                      binding->source_group_tag);
        }
    }

    return binding_exp;
}

static int cfg_add_peer_cb(__attribute__((unused)) struct sxpd_ctx *cb_ctx,
                           const struct peer *peer)
{
    int rc = 0;
    struct test_peer_exp_upt *peer_exp = NULL;

    PARAM_NULL_CHECK(rc, peer);

    if (RC_ISOK(rc)) {
        LOG_TRACE("added peer: %" PRIu32 ":%" PRIu16, peer->ip_address,
                  peer->port);
    }

    if (RC_ISOK(rc)) {
        peer_exp = cfg_find_exp_peer(peer);
        if (peer_exp != NULL) {
            if (peer_exp->flag == EXP_ADD) {
                if (peer_exp->checked == false) {
                    peer_exp->checked = true;
                } else {
                    LOG_ERROR("This peer was already called in add callback");
                    rc = EINVAL;
                }
            } else {
                LOG_ERROR("This peer should not be called in add callback");
                rc = EINVAL;
            }
        } else {
            LOG_ERROR("This peer not found in expected peer list");
            rc = EINVAL;
        }
    }

    assert(RC_ISOK(rc));
    return rc;
}

static int cfg_del_peer_cb(__attribute__((unused)) struct sxpd_ctx *cb_ctx,
                           const struct peer *peer)
{
    int rc = 0;
    struct test_peer_exp_upt *peer_exp = NULL;

    PARAM_NULL_CHECK(rc, peer);

    if (RC_ISOK(rc)) {
        LOG_TRACE("deleted peer: %" PRIu32 ":%" PRIu16, peer->ip_address,
                  peer->port);
    }

    if (RC_ISOK(rc)) {
        peer_exp = cfg_find_exp_peer(peer);
        if (peer_exp != NULL) {
            if (peer_exp->flag == EXP_DEL) {
                if (peer_exp->checked == false) {
                    peer_exp->checked = true;
                } else {
                    LOG_ERROR("This peer was already called in del callback");
                    rc = EINVAL;
                }
            } else {
                LOG_ERROR("This peer should not be called in del callback");
                rc = EINVAL;
            }
        } else {
            LOG_ERROR("This peer not found in expected peer list");
            rc = EINVAL;
        }
    }

    assert(RC_ISOK(rc));
    return rc;
}

static int cfg_add_binding_cb(__attribute__((unused)) struct sxpd_ctx *cb_ctx,
                              const struct binding *binding)
{
    int rc = 0;
    struct test_binding_exp_upt *binding_exp = NULL;

    PARAM_NULL_CHECK(rc, binding);

    if (RC_ISOK(rc)) {
        if (binding->type == PREFIX_IPV4) {
            LOG_TRACE("added binding: <sgt,address/legth>: <%" PRIu32
                      "," DEBUG_V4_FMT "/%" PRIu8 "> binary IPv4: <%" PRIu32
                      ">",
                      binding->source_group_tag,
                      DEBUG_V4_PRINT(binding->prefix.prefix_v4),
                      binding->prefix_length, binding->prefix.prefix_v4);
        } else {
            LOG_TRACE("added binding: <sgt,address/lentg>: <%" PRIu32
                      "," DEBUG_V6_FMT "/%" PRIu8 "> binary IPv6: <%" PRIu32
                      ".%" PRIu32 ".%" PRIu32 ".%" PRIu32 ">",
                      binding->source_group_tag,
                      DEBUG_V6_PRINT(binding->prefix.prefix_v6),
                      binding->prefix_length, binding->prefix.prefix_v6[0],
                      binding->prefix.prefix_v6[1],
                      binding->prefix.prefix_v6[2],
                      binding->prefix.prefix_v6[3]);
        }
    }

    if (RC_ISOK(rc)) {
        binding_exp = cfg_find_exp_binding(binding);
        if (binding_exp != NULL) {
            if (binding_exp->flag == EXP_ADD) {
                if (binding_exp->checked == false) {
                    binding_exp->checked = true;
                } else {
                    LOG_ERROR(
                        "This binding was already called in add callback");
                    rc = EINVAL;
                }
            } else {
                LOG_ERROR("This binding should not be called in add callback");
                rc = EINVAL;
            }
        } else {
            LOG_ERROR("This binding not found in expected binding list");
            rc = EINVAL;
        }
    }

    assert(RC_ISOK(rc));
    return rc;
}

static int cfg_del_binding_cb(__attribute__((unused)) struct sxpd_ctx *cb_ctx,
                              const struct binding *binding)
{
    int rc = 0;
    struct test_binding_exp_upt *binding_exp = NULL;

    PARAM_NULL_CHECK(rc, binding);

    if (RC_ISOK(rc)) {
        if (binding->type == PREFIX_IPV4) {
            LOG_TRACE("deleted binding: <sgt,address>: <%" PRIu32
                      "," DEBUG_V4_FMT "/%" PRIu8 " binary IPv4: <%" PRIu32 ">",
                      binding->source_group_tag,
                      DEBUG_V4_PRINT(binding->prefix.prefix_v4),
                      binding->prefix_length, binding->prefix.prefix_v4);
        } else {
            LOG_TRACE("deleted binding: <sgt,address>: <%" PRIu32
                      "," DEBUG_V6_FMT "/%" PRIu8 "> binary IPv6: <%" PRIu32
                      ".%" PRIu32 ".%" PRIu32 ".%" PRIu32 ">",
                      binding->source_group_tag,
                      DEBUG_V6_PRINT(binding->prefix.prefix_v6),
                      binding->prefix_length, binding->prefix.prefix_v6[0],
                      binding->prefix.prefix_v6[1],
                      binding->prefix.prefix_v6[2],
                      binding->prefix.prefix_v6[3]);
        }
    }

    if (RC_ISOK(rc)) {
        binding_exp = cfg_find_exp_binding(binding);
        if (binding_exp != NULL) {
            if (binding_exp->flag == EXP_DEL) {
                if (binding_exp->checked == false) {
                    binding_exp->checked = true;
                } else {
                    LOG_ERROR(
                        "This binding was already called in del callback");
                    rc = EINVAL;
                }
            } else {
                LOG_ERROR("This binding should not be called in del callback");
                rc = EINVAL;
            }
        } else {
            LOG_ERROR("This binding not found in expected binding list");
            rc = EINVAL;
        }
    }

    assert(RC_ISOK(rc));
    return rc;
}

static int sxp_check_global_config_cb_calls(
    struct test_settings_cb_calls *cb_calls,
    struct test_settings_cb_calls *expected_cb_calls)
{
    int rc = 0;
    int i = 0;

    PARAM_NULL_CHECK(rc, cb_calls, expected_cb_calls);

    if (RC_ISOK(rc)) {
        for (i = 0; i < UINT32_SETTING_LAST; i++) {
            if (cb_calls->add_uint32_setting_call[i] !=
                expected_cb_calls->add_uint32_setting_call[i]) {
                LOG_ERROR("Unexpected global uint32 setting #%d <%s> add "
                          "callback state."
                          " State: <%s>, expected state: <%s>",
                          i, cfg_get_uint32_setting_str(i),
                          cb_calls->add_uint32_setting_call[i] == true
                              ? "called"
                              : "not called",
                          expected_cb_calls->add_uint32_setting_call[i] == true
                              ? "called"
                              : "not called");
                rc = EINVAL;
            }
        }

        for (i = 0; i < UINT32_SETTING_LAST; i++) {
            if (cb_calls->del_uint32_setting_call[i] !=
                expected_cb_calls->del_uint32_setting_call[i]) {
                LOG_ERROR("Unexpected global uint32 setting #%d <%s> del "
                          "callback state."
                          " State: <%s> expected state: <%s>",
                          i, cfg_get_uint32_setting_str(i),
                          cb_calls->del_uint32_setting_call[i] == true
                              ? "called"
                              : "not called",
                          expected_cb_calls->del_uint32_setting_call[i] == true
                              ? "called"
                              : "not called");
                rc = EINVAL;
            }
        }

        for (i = 0; i < STR_SETTING_LAST; i++) {
            if (cb_calls->add_str_setting_call[i] !=
                expected_cb_calls->add_str_setting_call[i]) {
                LOG_ERROR(
                    "Unexpected global str setting #%d <%s> add callback state."
                    " State: <%s>, expected state: <%s>",
                    i, cfg_get_str_setting_str(i),
                    cb_calls->add_str_setting_call[i] == true ? "called"
                                                              : "not called",
                    expected_cb_calls->add_str_setting_call[i] == true
                        ? "called"
                        : "not called");
                rc = EINVAL;
            }
        }

        for (i = 0; i < STR_SETTING_LAST; i++) {
            if (cb_calls->del_str_setting_call[i] !=
                expected_cb_calls->del_str_setting_call[i]) {
                LOG_ERROR(
                    "Unexpected global str setting #%d <%s> del callback state."
                    " State: <%s> expected state: <%s>",
                    i, cfg_get_str_setting_str(i),
                    cb_calls->del_str_setting_call[i] == true ? "called"
                                                              : "not called",
                    expected_cb_calls->del_str_setting_call[i] == true
                        ? "called"
                        : "not called");
                rc = EINVAL;
            }
        }
    }

    return rc;
}

static int
sxp_check_global_config(struct test_settings *global_settings,
                        struct test_settings *expected_global_settings)
{
    int rc = 0;
    int i = 0;

    PARAM_NULL_CHECK(rc, global_settings, expected_global_settings);

    if (RC_ISOK(rc)) {
        for (i = 0; i < UINT32_SETTING_LAST; i++) {
            if (global_settings->is_set_uint32_val[i] !=
                expected_global_settings->is_set_uint32_val[i]) {
                LOG_ERROR("Unexpected global uint32 setting #%d <%s> 'is set'."
                          "Setting: %d expected setting: %d",
                          i, cfg_get_uint32_setting_str(i),
                          global_settings->is_set_uint32_val[i],
                          expected_global_settings->is_set_uint32_val[i]);
                rc = EINVAL;
            } else if ((global_settings->is_set_uint32_val[i] == true) &&
                       (global_settings->uint32_val[i] !=
                        expected_global_settings->uint32_val[i])) {
                LOG_ERROR("Unexpected global uint32 setting #%d <%s> value %d."
                          "Expected setting is %d",
                          i, cfg_get_uint32_setting_str(i),
                          global_settings->uint32_val[i],
                          expected_global_settings->uint32_val[i]);
                rc = EINVAL;
            } else {
                /* nothing to do here */
            }
        }

        for (i = 0; i < STR_SETTING_LAST; i++) {
            if (global_settings->is_set_str_val[i] !=
                expected_global_settings->is_set_str_val[i]) {
                LOG_ERROR("Unexpected global setting 'is set' on string type"
                          "#%d <%s>. setting:%d expected setting: %d",
                          i, cfg_get_str_setting_str(i),
                          global_settings->is_set_str_val[i],
                          expected_global_settings->is_set_str_val[i]);
                rc = EINVAL;
            } else if (global_settings->is_set_str_val[i] == true) {
                switch (i) {
                case STR_SETTING_PASSWORD:
                    if (strncmp(global_settings->default_connection_password,
                                expected_global_settings
                                    ->default_connection_password,
                                CFG_PASSWORD_MAX_SIZE) != 0) {
                        LOG_ERROR(
                            "Unexpected global setting 'is set' on str type"
                            "#%d <%s>. setting:<%s> not match expected "
                            "setting: "
                            "<%s>",
                            i, cfg_get_str_setting_str(i),
                            global_settings->default_connection_password,
                            expected_global_settings
                                ->default_connection_password);
                        rc = EINVAL;
                    }
                    break;
                default:
                    LOG_TRACE("Del string setting callback received invalid "
                              "setting type #%d",
                              i);
                    rc = EINVAL;
                    break;
                }
            }
        }
    }

    return rc;
}

static int sxp_check_peers(const struct test_peer_exp_upt *peer_exp_upt)
{
    int rc = 0;
    const struct test_peer_exp_upt *peer_exp = NULL;
    size_t i = 0;

    PARAM_NULL_CHECK(rc, peer_exp_upt);

    if (RC_ISOK(rc)) {
        for (i = 0; i < MAX_PEER_CB && peer_exp_upt[i].exist == true; i++) {
            peer_exp = &peer_exp_upt[i];

            if (peer_exp->checked == false) {
                LOG_ERROR("Peer configuration do not hit peer: %" PRIu16,
                          peer_exp->peer.ip_address);
                rc = -1;
            }
        }
    }

    return rc;
}

static int
sxp_check_bindings(const struct test_binding_exp_upt *binding_exp_upt)
{
    int rc = 0;
    const struct test_binding_exp_upt *binding_exp = NULL;
    size_t i = 0;

    PARAM_NULL_CHECK(rc, binding_exp_upt);

    if (RC_ISOK(rc)) {
        for (i = 0; i < MAX_BINDING_CB && binding_exp_upt[i].exist == true;
             i++) {
            binding_exp = &binding_exp_upt[i];

            if (binding_exp->checked == false) {
                LOG_ERROR(
                    "Binding configuration do not hit %s binding with sgt: "
                    "%" PRIu16,
                    binding_exp->flag == EXP_ADD ? "ADD" : "DEL",
                    binding_exp->binding.source_group_tag);
                rc = -1;
            }
        }
    }

    return rc;
}

static int sxp_check_config(struct test_settings_cb_calls *cb_calls,
                            struct test_settings_cb_calls *expected_cb_calls,
                            struct test_settings *global_settings,
                            struct test_settings *expected_global_settings,
                            struct test_peer_exp_upt *peer_exp_upt,
                            struct test_binding_exp_upt *binding_exp_upt)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, cb_calls, expected_cb_calls, global_settings,
                     expected_global_settings, peer_exp_upt, binding_exp_upt);

    if (RC_ISOK(rc)) {
        rc = sxp_check_global_config_cb_calls(cb_calls, expected_cb_calls);
        if (RC_ISOK(rc)) {
            LOG_TRACE("Check global configuration callback calls success");
        } else {
            LOG_ERROR("Check global configuration callback calls failed: %d",
                      rc);
        }
    }

    if (RC_ISOK(rc)) {
        rc = sxp_check_global_config(global_settings, expected_global_settings);
        if (RC_ISOK(rc)) {
            LOG_TRACE("Check global configuration success");
        } else {
            LOG_ERROR("Check global configuration failed: %d", rc);
        }
    }

    if (RC_ISOK(rc)) {
        rc = sxp_check_peers(peer_exp_upt);
        if (RC_ISOK(rc)) {
            LOG_TRACE("Check peer configuration success");
        } else {
            LOG_ERROR("Check peer configuration failed: %d", rc);
        }
    }

    if (RC_ISOK(rc)) {
        rc = sxp_check_bindings(binding_exp_upt);
        if (RC_ISOK(rc)) {
            LOG_TRACE("Check binding configuration success");
        } else {
            LOG_ERROR("Check binding configuration failed: %d", rc);
        }
    }

    if (RC_ISOK(rc)) {
        rc = log_check_run();
        if (RC_ISOK(rc)) {
            LOG_TRACE("Check log records success");
        } else {
            LOG_ERROR("Check log records failed: %d", rc);
        }
    }

    return rc;
}

static int test_load_config(struct cfg_ctx *cfg_ctx, struct evmgr *evmgr)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, cfg_ctx, evmgr);

    if (RC_ISOK(rc)) {
        reset_cb_calls(&settings_cb_calls);
    }

    if (RC_ISOK(rc)) {
        rc = log_check_set_patterns(
            cfg_reload[cfg_reload_actual].log_pattern,
            cfg_reload[cfg_reload_actual].log_pattern_num);
        if (RC_ISNOTOK(rc)) {
            LOG_ERROR("Log check patterns set failed: %d", rc);
        }
    }

    LOG_TRACE("Test #%zu <%s>", cfg_reload_actual,
              cfg_reload[cfg_reload_actual].description);
    /* register callbacks and load configuration */
    if (RC_ISOK(rc)) {
        rc = cfg_register_callbacks(
            cfg_ctx, evmgr, NULL, cfg_add_uint32_setting_cb,
            cfg_del_uint32_setting_cb, cfg_add_str_setting_cb,
            cfg_del_str_setting_cb, cfg_add_peer_cb, cfg_del_peer_cb,
            cfg_add_binding_cb, cfg_del_binding_cb);
        if (RC_ISOK(rc)) {
            LOG_TRACE("Register callbacks and load configuration success");
        } else {
            LOG_ERROR("Register callbacks and load configuration failed: %d",
                      rc);
        }
    }

    /* check loaded configuration */
    if (RC_ISOK(rc)) {
        rc = sxp_check_config(
            &settings_cb_calls, &exp_cb_calls[cfg_reload_actual], &settings,
            &exp_settings[cfg_reload_actual], peer_exp_upt[cfg_reload_actual],
            binding_exp_upt[cfg_reload_actual]);
        if (RC_ISOK(rc)) {
            LOG_TRACE("Check loaded configuration #%zu success",
                      cfg_reload_actual);
        } else {
            LOG_ERROR("Check loaded configuration #%zu failed: %d",
                      cfg_reload_actual, rc);
        }
    }

    return rc;
}

static int config_check()
{
    int rc = 0;

    if (cfg_reload_actual < CFG_RELOAD_NUM) {
        /* check reloaded configuration */
        rc = sxp_check_config(
            &settings_cb_calls, &exp_cb_calls[cfg_reload_actual], &settings,
            &exp_settings[cfg_reload_actual], peer_exp_upt[cfg_reload_actual],
            binding_exp_upt[cfg_reload_actual]);
        if (RC_ISOK(rc)) {
            LOG_TRACE("Check reloaded configuration #%zu success",
                      cfg_reload_actual);
        } else {
            LOG_ERROR("Check reloaded configuration #%zu failed: %d",
                      cfg_reload_actual, rc);
        }
    }

    return rc;
}

static void config_check_callback(struct evmgr_timer *timer, void *ctx)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, timer, ctx);
    RC_CHECK(rc, out);

    LOG_TRACE("config check timer fires");
    rc = config_check();
    if (RC_ISOK(rc)) {
        LOG_TRACE("config check success");
    } else {
        LOG_ERROR("config check failed: %d", rc);
        goto out;
    }

    /* schedule next configuration reload and check or dispatch break */
    cfg_reload_actual++;
    if (cfg_reload_actual < CFG_RELOAD_NUM) {
        reset_cb_calls(&settings_cb_calls);

        rc = log_check_set_patterns(
            cfg_reload[cfg_reload_actual].log_pattern,
            cfg_reload[cfg_reload_actual].log_pattern_num);
        if (RC_ISNOTOK(rc)) {
            LOG_ERROR("failed to set new log check patterns: %d", rc);
            goto out;
        }

        LOG_TRACE("\n\n\n\n"); /* newline between configuration reload */
        LOG_TRACE("Test #%zu <%s>", cfg_reload_actual,
                  cfg_reload[cfg_reload_actual].description);
        /* reload configuration with new configuration file */
        snprintf(cfg_file_path, sizeof(cfg_file_path), "%s%zu%s", "config",
                 cfg_reload_actual, ".cfg");

        kill(getpid(), SIGHUP);
        rc = evmgr_timer_arm(timer);
        if (RC_ISNOTOK(rc)) {
            LOG_ERROR("Cannot arm retry timer!");
            goto out;
        }
    } else {
        evmgr_timer_destroy(timer);
        rc = evmgr_dispatch_break(ctx);
        if (RC_ISNOTOK(rc)) {
            LOG_ERROR("Dispatch break failed: %d", rc);
            goto out;
        }
    }

out:
    assert(RC_ISOK(rc));
}

static int test_schedule_config_check(struct evmgr *evmgr,
                                      struct timeval *retry_timeout)
{
    int rc = 0;
    struct evmgr_timer *retry_timer = NULL;

    PARAM_NULL_CHECK(rc, evmgr, retry_timeout);

    if (RC_ISOK(rc)) {
        retry_timer = evmgr_timer_create(evmgr, NULL, retry_timeout, false,
                                         config_check_callback, evmgr);
        if (!retry_timer) {
            LOG_ERROR("Cannot create retry timer!");
            rc = ENOMEM;
        }
    }

    if (RC_ISOK(rc)) {
        rc = evmgr_timer_arm(retry_timer);
        if (RC_ISNOTOK(rc)) {
            LOG_ERROR("Cannot arm retry timer!");
        }
    }

    return rc;
}

int main(void)
{
    int rc = 0;
    struct cfg_ctx *cfg_ctx = NULL;
    struct evmgr *evmgr = NULL;
    struct evmgr_settings *es = NULL;

    /* reset configuration reload number */
    cfg_reload_actual = 0;

    /* set configuration file path */
    snprintf(cfg_file_path, sizeof(cfg_file_path), CFG_FILE_PATH1);

    evmgr = evmgr_create(es);
    if (!evmgr) {
        LOG_ERROR("Cannot create event manager");
        rc = -1;
    }

    /* create configuration context */
    if (RC_ISOK(rc)) {
        rc = cfg_ctx_create(&cfg_ctx, cfg_file_path, &es);
        if (RC_ISOK(rc)) {
            LOG_TRACE("Create configuration success");
        } else {
            LOG_ERROR("Create configuration failed: %d", rc);
        }
    }

    /* reload SXP configuration multiple times with updated configuration file
     */
    if (RC_ISOK(rc)) {
        rc = test_load_config(cfg_ctx, evmgr);
        if (RC_ISOK(rc)) {
            LOG_TRACE("Load configuration success");
        } else {
            LOG_ERROR("Load configuration failed: %d", rc);
        }
    }

    /* schedule configuration reload and configuration check */
    if (RC_ISOK(rc)) {
        cfg_reload_actual++;
        reset_cb_calls(&settings_cb_calls);
        LOG_TRACE("\n\n\n\n"); /* newline between configuration reload */

        LOG_TRACE("Test #%zu <%s>", cfg_reload_actual,
                  cfg_reload[cfg_reload_actual].description);
        /* reload configuration with new configuration file */
        snprintf(cfg_file_path, sizeof(cfg_file_path), "%s%zu%s", "config",
                 cfg_reload_actual, ".cfg");
        kill(getpid(), SIGHUP);
        struct timeval retry_timeout = {.tv_sec = 0, .tv_usec = 200000 };
        rc = test_schedule_config_check(evmgr, &retry_timeout);
        if (RC_ISOK(rc)) {
            LOG_TRACE("Schedule configuration check success");
        } else {
            LOG_ERROR("Schedule configuration check failed: %d", rc);
        }
    }

    /* start everything up */
    if (RC_ISOK(rc)) {
        rc = evmgr_dispatch(evmgr);
    }

    if (RC_ISOK(rc)) {
        cfg_ctx_destroy(cfg_ctx);
        evmgr_destroy(evmgr);
        mem_free(es);
    }

    return rc;
}
