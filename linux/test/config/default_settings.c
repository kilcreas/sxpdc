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

#include "../../../src/sxpd_internal.h"

#include "../framework/inc/log_check.h"

/* default configuration path */
#define CFG_FILE_PATH "default_settings.cfg"

#define UINT32_SETTING_RETRY_TIMER_DEFAULT 120
#define UINT32_SETTING_RECONCILIATION_TIMER_DEFAULT 120
#define UINT32_SETTING_LISTENER_MIN_HOLD_TIME_DEFAULT 90
#define UINT32_SETTING_LISTENER_MAX_HOLD_TIME_DEFAULT 180
#define UINT32_SETTING_SPEAKER_MIN_HOLD_TIME_DEFAULT 120
#define UINT32_SETTING_SUBNET_EXPANSION_LIMIT_DEFAULT 0
#define UINT32_SETTING_KEEPALIVE_TIMER_DEFAULT KEEPALIVE_UNUSED
#define UINT32_SETTING_PORT_DEFAULT 64999
#define UINT32_SETTING_ENABLED_DEFAULT false

static struct log_pattern log_pattern[] = {

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

static void test_schedule_dispatch_break_cb(struct evmgr_timer *timer,
                                            void *ctx)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, timer, ctx);
    RC_CHECK(rc, out);

    LOG_TRACE("dispatch break timer fires");

    evmgr_timer_destroy(timer);

    rc = evmgr_dispatch_break(ctx);
    if (RC_ISNOTOK(rc)) {
        LOG_ERROR("Dispatch break failed: %d", rc);
        goto out;
    }

out:
    assert(RC_ISOK(rc));
}

static int test_schedule_dispatch_break(struct evmgr *evmgr,
                                        struct timeval *retry_timeout)
{
    int rc = 0;
    struct evmgr_timer *retry_timer = NULL;

    PARAM_NULL_CHECK(rc, evmgr, retry_timeout);

    if (RC_ISOK(rc)) {
        retry_timer =
            evmgr_timer_create(evmgr, NULL, retry_timeout, false,
                               test_schedule_dispatch_break_cb, evmgr);
        if (!retry_timer) {
            LOG_ERROR("Cannot create dispatch break timer!");
            rc = ENOMEM;
        }
    }

    if (RC_ISOK(rc)) {
        rc = evmgr_timer_arm(retry_timer);
        if (RC_ISNOTOK(rc)) {
            LOG_ERROR("Cannot arm dispatch timer!");
        }
    }

    return rc;
}

static int test_setup_defaults_check(struct sxpd_ctx *ctx)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, ctx);
    RC_CHECK(rc, out);

    if (UINT32_SETTING_RETRY_TIMER_DEFAULT != ctx->retry_timeout.tv_sec) {
        LOG_ERROR("Retry timer value %lu do not match default value %d",
                  ctx->retry_timeout.tv_sec,
                  UINT32_SETTING_RETRY_TIMER_DEFAULT);
        rc = -1;
        goto out;
    }

    if (UINT32_SETTING_RECONCILIATION_TIMER_DEFAULT !=
        ctx->reconciliation_timeout.tv_sec) {
        LOG_ERROR(
            "Reconciliation timer value %lu do not match default value %d",
            ctx->reconciliation_timeout.tv_sec,
            UINT32_SETTING_RECONCILIATION_TIMER_DEFAULT);
        rc = -1;
        goto out;
    }

    if (UINT32_SETTING_SPEAKER_MIN_HOLD_TIME_DEFAULT !=
        ctx->speaker_min_hold_time) {
        LOG_ERROR("Speaker minimum hold time value %" PRIu16
                  " do not match default value %d",
                  ctx->speaker_min_hold_time,
                  UINT32_SETTING_SPEAKER_MIN_HOLD_TIME_DEFAULT);
        rc = -1;
        goto out;
    }

    if (UINT32_SETTING_LISTENER_MIN_HOLD_TIME_DEFAULT !=
        ctx->listener_min_hold_time) {
        LOG_ERROR("Listener minimum hold time value %" PRIu16
                  " do not match default value %d",
                  ctx->listener_min_hold_time,
                  UINT32_SETTING_LISTENER_MIN_HOLD_TIME_DEFAULT);
        rc = -1;
        goto out;
    }

    if (UINT32_SETTING_LISTENER_MAX_HOLD_TIME_DEFAULT !=
        ctx->listener_max_hold_time) {
        LOG_ERROR("Listener maximum hold time value %" PRIu16
                  " do not match default value %d",
                  ctx->listener_max_hold_time,
                  UINT32_SETTING_LISTENER_MAX_HOLD_TIME_DEFAULT);
        rc = -1;
        goto out;
    }

    if (UINT32_SETTING_KEEPALIVE_TIMER_DEFAULT !=
        ctx->keepalive_timeout.tv_sec) {
        LOG_ERROR("Keep alive timer value %ld do not match default value %d",
                  ctx->keepalive_timeout.tv_sec,
                  UINT32_SETTING_KEEPALIVE_TIMER_DEFAULT);
        rc = -1;
        goto out;
    }

    if (UINT32_SETTING_SUBNET_EXPANSION_LIMIT_DEFAULT !=
        ctx->sub_expand_limit) {
        LOG_ERROR("Subnet expansion value %zu do not match default value %d",
                  ctx->sub_expand_limit,
                  UINT32_SETTING_SUBNET_EXPANSION_LIMIT_DEFAULT);
        rc = -1;
        goto out;
    }

    if ('\0' != ctx->default_connection_password[0]) {
        LOG_ERROR(
            "Connection password value '%s' do not match default value '%s'",
            ctx->default_connection_password, "");
        rc = -1;
        goto out;
    }

    if (INADDR_ANY != ntohl(ctx->nbo_bind_ip)) {
        LOG_ERROR("Bind IP address value '" DEBUG_V4_FMT
                  "' do not match default value '" DEBUG_V4_FMT "'",
                  DEBUG_V4_PRINT(ctx->nbo_bind_ip),
                  DEBUG_V4_PRINT(htonl(INADDR_ANY)));
        rc = -1;
        goto out;
    }

    if (UINT32_SETTING_PORT_DEFAULT != ntohs(ctx->nbo_port)) {
        LOG_ERROR("Port number value '%" PRIu16
                  "' do not match default value '%" PRIu16 "'",
                  ntohs(ctx->nbo_port), UINT32_SETTING_PORT_DEFAULT);
        rc = -1;
        goto out;
    }

    if (UINT32_SETTING_ENABLED_DEFAULT != ctx->enabled) {
        LOG_ERROR("Enabled value '%d' do not match default value '%d'",
                  ctx->enabled, UINT32_SETTING_ENABLED_DEFAULT);
        rc = -1;
        goto out;
    }

    LOG_TRACE("Default setting check success: %d", rc);

out:
    return rc;
}

int main(void)
{
    int rc = 0;
    struct cfg_ctx *cfg_ctx = NULL;
    struct evmgr *evmgr = NULL;
    struct evmgr_settings *es = NULL;
    struct sxpd_ctx *sxpd_ctx = NULL;
    /* set configuration file path */
    struct timeval retry_timeout = {.tv_sec = 0, .tv_usec = 100000 };
    enum log_level default_ll = LOG_LEVEL_ERROR;

    /* set log check patterns */
    rc = log_check_set_patterns(log_pattern,
                                sizeof(log_pattern) / sizeof(*log_pattern));
    if (RC_ISNOTOK(rc)) {
        LOG_ERROR("Set log check patterns failed: %d", rc);
        goto out;
    }

    /* create configuration context */
    rc = cfg_ctx_create(&cfg_ctx, CFG_FILE_PATH, &es);
    if (RC_ISOK(rc)) {
        LOG_TRACE("Create configuration success");
    } else {
        LOG_ERROR("Create configuration failed: %d", rc);
        goto out;
    }

    /* create event manager */
    evmgr = evmgr_create(es);
    if (!evmgr) {
        LOG_ERROR("Cannot create event manager");
        rc = -1;
        goto out;
    }

    rc = test_schedule_dispatch_break(evmgr, &retry_timeout);
    if (RC_ISOK(rc)) {
        LOG_TRACE("Schedule dispatch success");
    } else {
        LOG_ERROR("Schedule dispatch failed: %d", rc);
        goto out;
    }

    sxpd_ctx = sxpd_create(evmgr, es, default_ll);
    if (!sxpd_ctx) {
        LOG_ERROR("Cannot allocate sxpd context");
        rc = -1;
        goto out;
    }

    /* start everything up */
    rc = evmgr_dispatch(evmgr);
    RC_CHECK(rc, out);

    rc = test_setup_defaults_check(sxpd_ctx);
    RC_CHECK(rc, out);

    rc = log_check_run();
    RC_CHECK(rc, out);

out:
    sxpd_destroy(sxpd_ctx);
    cfg_ctx_destroy(cfg_ctx);
    evmgr_destroy(evmgr);
    mem_free(es);

    return rc;
}
