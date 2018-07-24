#include <util.h>
#include <logging.h>
#include <syslog.h>
#include <stdarg.h>
#include <sys/queue.h>
#include <pthread.h>

#include <sxpd.h>
#include <sxp.h>
#include <mem.h>
#include <config.h>
#include <util.h>

#include "../inc/topology.h"
#include "../inc/log_check.h"
#include "../../../../src/sxpd_internal.h"

#define TOPO_TASK_WAIT_MAX_SLEEP_TIME 3000000

#pragma GCC diagnostic ignored "-Wunused-but-set-variable"

struct topo_ctx {
    pthread_cond_t cond;
    pthread_mutex_t mutex;
};

/**
 * @brief status of one instance od sxpd topology
 */
enum topo_sxpd_status {
    TOPO_SXPD_INSTANCE_STOPPED, //!< TOPO_SXPD_INSTALCE_STOPPED
    TOPO_SXPD_INSTANCE_STARTED, //!< TOPO_SXPD_INSTALCE_STARTED
    TOPO_SXPD_INSTANCE_PAUSED,  //!< TOPO_SXPD_INSTANCE_PAUSED
};

struct topo_sxpd_priv {
    pthread_t pthread;
    enum topo_sxpd_status status;
    struct cfg_ctx *cfg_ctx;
    struct evmgr *evmgr;
    struct evmgr_settings *es;
};

struct topo_task_priv {
    struct topo_ctx *topo_ctx;
};

#define TUPLE_TOPO_TASK_DESC(enum_, desc_) desc_,

static const char *topo_task_type_str[] = { TUPLE_TOPO_TASK(
    TUPLE_TOPO_TASK_DESC) };

const char *topo_task_type_to_str(enum topo_task_type type)
{
    const char *ret = NULL;

    if (type < (sizeof(topo_task_type_str) / (sizeof(*topo_task_type_str)))) {
        ret = topo_task_type_str[type];
    }

    return ret;
}

struct topo_hnd_ctx {
    const char *error;
    struct topo_task *topo_task;
    topo_task_cb sxpd_cb;
};

#define TOPO_SXPD_ERROR_INTERNAL "internal error"
#define TOPO_CTX_COND_TIMEOUT 6

static void topo_task_schedule_handling_sxpd_cb(struct evmgr_timer *timer,
                                                void *ctx_)
{
    int rc = 0;
    int tmp_rc = 0;
    struct topo_hnd_ctx *ctx = ctx_;
    size_t i = 0;

    PARAM_NULL_CHECK(rc, timer, ctx, ctx->sxpd_cb, ctx->topo_task,
                     ctx->topo_task->topo_task_priv,
                     ctx->topo_task->topo_task_priv->topo_ctx);
    RC_CHECK(rc, out);

    rc = evmgr_timer_disarm(timer);
    RC_CHECK(rc, out);
    evmgr_timer_destroy(timer);

    i = ctx->topo_task->id;

    tmp_rc =
        pthread_mutex_lock(&ctx->topo_task->topo_task_priv->topo_ctx->mutex);
    if (RC_ISNOTOK(tmp_rc)) {
        TOPO_TASK_ERROR(ctx->topo_task, "sxpd handler mutex lock failed: %d",
                        tmp_rc);
        assert(0);
    }

    rc = ctx->sxpd_cb(ctx->topo_task);
    if (RC_ISNOTOK(rc)) {
        ctx->error = TOPO_SXPD_ERROR_INTERNAL;
        TOPO_TASK_ERROR(ctx->topo_task, "sxpd handler failed: %d", rc);
    }

    tmp_rc =
        pthread_cond_signal(&ctx->topo_task->topo_task_priv->topo_ctx->cond);
    if (RC_ISNOTOK(tmp_rc)) {
        TOPO_TASK_ERROR(ctx->topo_task,
                        "sxpd handler condition signal failed: %d", tmp_rc);
        assert(0);
    }

    if (RC_ISOK(rc)) {
        LOG_TRACE("Topology task #%zu: sxpd handler success: %d", i, rc);
    }

    tmp_rc =
        pthread_mutex_unlock(&ctx->topo_task->topo_task_priv->topo_ctx->mutex);
    if (RC_ISNOTOK(tmp_rc)) {
        LOG_ERROR("Topology task #%zu: sxpd handler mutex unlock failed: %d", i,
                  tmp_rc);
        assert(0);
    }

out:
    return;
}

static int sxpd_gdbus_schedule_handling_sxpd(struct topo_hnd_ctx *cb_ctx)
{
    int rc = 0;
    struct evmgr_timer *retry_timer = NULL;
    struct timeval retry_timeout = {.tv_sec = 0, .tv_usec = 0 };

    PARAM_NULL_CHECK(rc, cb_ctx, cb_ctx->sxpd_cb, cb_ctx->topo_task,
                     cb_ctx->topo_task->topo_sxpd,
                     cb_ctx->topo_task->topo_sxpd->topo_sxpd_priv,
                     cb_ctx->topo_task->topo_sxpd->topo_sxpd_priv->evmgr);
    RC_CHECK(rc, out);

    retry_timer = evmgr_timer_create(
        cb_ctx->topo_task->topo_sxpd->topo_sxpd_priv->evmgr, NULL,
        &retry_timeout, false, topo_task_schedule_handling_sxpd_cb, cb_ctx);
    if (!retry_timer) {
        TOPO_TASK_ERROR(cb_ctx->topo_task, "%s",
                        "sxpd scheduler timer create failed");
        rc = -1;
        goto out;
    }

    rc = evmgr_timer_arm(retry_timer);
    if (RC_ISNOTOK(rc)) {
        TOPO_TASK_ERROR(cb_ctx->topo_task,
                        "sxpd scheduler failed to arm timer: %d", rc);
        goto out;
    }

out:
    return rc;
}

static int topo_task_schedule_handling_sync(struct topo_hnd_ctx *cb_ctx)
{
    int rc = 0;
    int tmp = 0;

    PARAM_NULL_CHECK(rc, cb_ctx, cb_ctx->sxpd_cb, cb_ctx->topo_task,
                     cb_ctx->topo_task->topo_task_priv,
                     cb_ctx->topo_task->topo_task_priv->topo_ctx);
    RC_CHECK(rc, out);

    rc =
        pthread_mutex_lock(&cb_ctx->topo_task->topo_task_priv->topo_ctx->mutex);
    if (RC_ISNOTOK(rc)) {
        TOPO_TASK_ERROR(cb_ctx->topo_task, "Mutex lock failed: %d", rc);
        goto out;
    }

    rc = sxpd_gdbus_schedule_handling_sxpd(cb_ctx);
    if (RC_ISNOTOK(rc)) {
        tmp = pthread_mutex_unlock(
            &cb_ctx->topo_task->topo_task_priv->topo_ctx->mutex);
        assert(RC_ISOK(tmp));
        TOPO_TASK_ERROR(cb_ctx->topo_task, "schedule sxpd handler failed: %d",
                        rc);
        goto out;
    }

    rc = pthread_cond_wait(&cb_ctx->topo_task->topo_task_priv->topo_ctx->cond,
                           &cb_ctx->topo_task->topo_task_priv->topo_ctx->mutex);
    if (RC_ISNOTOK(rc)) {
        tmp = pthread_mutex_unlock(
            &cb_ctx->topo_task->topo_task_priv->topo_ctx->mutex);
        assert(RC_ISOK(tmp));
        TOPO_TASK_ERROR(cb_ctx->topo_task, "Condition wait failed: %d", rc);
        goto out;
    }

    tmp = pthread_mutex_unlock(
        &cb_ctx->topo_task->topo_task_priv->topo_ctx->mutex);
    assert(RC_ISOK(tmp));
    if (NULL != cb_ctx->error) {
        TOPO_TASK_ERROR(cb_ctx->topo_task, "sxpd handler failed: %s",
                        cb_ctx->error);
        rc = -1;
        goto out;
    }

out:
    return rc;
}

static int topo_task_schedule_handling(topo_task_cb sxpd_cb,
                                       topo_task_cb main_cb,
                                       struct topo_task *topo_task)
{
    int rc = 0;
    struct topo_hnd_ctx cb_ctx = {
        .error = NULL, .sxpd_cb = sxpd_cb, .topo_task = topo_task,
    };

    PARAM_NULL_CHECK(rc, sxpd_cb, topo_task);
    RC_CHECK(rc, out);

    rc = topo_task_schedule_handling_sync(&cb_ctx);
    if (RC_ISNOTOK(rc)) {
        TOPO_TASK_ERROR(topo_task, "sxpd handler failed: %d", rc);
        goto out;
    }

    if (main_cb) {
        rc = main_cb(topo_task);
        if (RC_ISNOTOK(rc)) {
            TOPO_TASK_ERROR(topo_task, "main handler failed: %d", rc);
            goto out;
        }
    }

    TOPO_TASK_TRACE(topo_task, "task handler success: %d", rc);

out:
    return rc;
}

int topo_task_wait_for_sxpd_cb(struct topo_task *topo_task)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, topo_task, topo_task->topo_sxpd,
                     topo_task->topo_sxpd->topo_sxpd_priv,
                     topo_task->topo_sxpd->sxpd_ctx, topo_task->task.wait.cb);
    RC_CHECK(rc, out);

    rc = topo_task->task.wait.cb(topo_task);
    if (RC_ISNOTOK(rc)) {
        TOPO_TASK_ERROR(topo_task, "wait for callback failed: %d", rc);
        goto out;
    }

out:
    return rc;
}

static int topo_task_wait_for(struct topo_task *topo_task)
{
    int rc = 0;
    struct timespec ts_start = { 0, 0 };
    struct timespec ts_actual = { 0, 0 };

    PARAM_NULL_CHECK(rc, topo_task, topo_task->desc, topo_task->topo_sxpd,
                     topo_task->topo_sxpd->topo_sxpd_priv,
                     topo_task->topo_sxpd->topo_sxpd_priv->evmgr,
                     topo_task->topo_task_priv,
                     topo_task->topo_task_priv->topo_ctx);
    RC_CHECK(rc, out);

    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    /* wait for sxpd instance event/error/timeout */
    do {
        rc = topo_task_schedule_handling(topo_task_wait_for_sxpd_cb, NULL,
                                         topo_task);
        if (RC_ISNOTOK(rc)) {
            TOPO_TASK_ERROR(topo_task, "wait for event failed: %d", rc);
            goto out;
        }

        if (topo_task->task.wait.wait_status == TOPO_TASK_WAIT) {
            clock_gettime(CLOCK_MONOTONIC, &ts_actual);
            topo_task->task.wait.elapsed.tv_sec =
                ts_actual.tv_sec - ts_start.tv_sec;
            if ((ts_actual.tv_sec - ts_start.tv_sec) >=
                topo_task->task.wait.timeout.tv_sec) {
                topo_task->task.wait.timeouted = true;
                topo_task_schedule_handling(topo_task_wait_for_sxpd_cb, NULL,
                                            topo_task);
                rc = -1;
                TOPO_TASK_ERROR(topo_task, "wait for event timeout: %zu sec",
                                topo_task->task.wait.timeout.tv_sec);
                goto out;
            } else {
                usleep(topo_task->task.wait.sleep_time);
                if (topo_task->task.wait.sleep_time <
                    TOPO_TASK_WAIT_MAX_SLEEP_TIME) {
                    topo_task->task.wait.sleep_time += 50000;
                }
            }
        }
    } while (topo_task->task.wait.wait_status == TOPO_TASK_WAIT);

    TOPO_TASK_TRACE(topo_task, "wait for event success: %d", rc);

out:
    return rc;
}

int topo_task_update_binding_cfg_sxpd_cb(struct topo_task *topo_task)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, topo_task, topo_task->topo_sxpd,
                     topo_task->topo_sxpd->topo_sxpd_priv,
                     topo_task->topo_sxpd->sxpd_ctx, topo_task);
    RC_CHECK(rc, out);

    if (PREFIX_IPV4 == topo_task->task.binding_cfg.binding.type) {
        if (inet_pton(AF_INET, topo_task->task.binding_cfg.prefix,
                      &topo_task->task.binding_cfg.binding.prefix.prefix_v4) !=
            1) {
            TOPO_TASK_ERROR(topo_task,
                            "binding V4 prefix string value <%s> is invalid",
                            topo_task->task.binding_cfg.prefix);
            rc = -1;
            goto out;
        }
    } else {
        if (inet_pton(AF_INET6, topo_task->task.binding_cfg.prefix,
                      topo_task->task.binding_cfg.binding.prefix.prefix_v6) !=
            1) {
            TOPO_TASK_ERROR(topo_task,
                            "binding V6 prefix string value <%s> is invalid",
                            topo_task->task.binding_cfg.prefix);
            rc = -1;
            goto out;
        }
    }

    if (topo_task->task.binding_cfg.cfg_add) {
        rc = sxpd_cfg_add_binding(topo_task->topo_sxpd->sxpd_ctx,
                                  &topo_task->task.binding_cfg.binding);
        if (RC_ISOK(rc)) {
            TOPO_TASK_TRACE(topo_task, "binding config add success: %d", rc);
        } else {
            TOPO_TASK_ERROR(topo_task, "binding config add failed: %d", rc);
            goto out;
        }
    } else {
        rc = sxpd_cfg_del_binding(topo_task->topo_sxpd->sxpd_ctx,
                                  &topo_task->task.binding_cfg.binding);
        if (RC_ISOK(rc)) {
            TOPO_TASK_TRACE(topo_task, "binding config del success: %d", rc);
        } else {
            TOPO_TASK_ERROR(topo_task, "binding config del failed: %d", rc);
            goto out;
        }
    }

out:
    return rc;
}

static int topo_task_update_binding_cfg(struct topo_task *topo_task)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, topo_task, topo_task->desc, topo_task->topo_sxpd,
                     topo_task->topo_sxpd->topo_sxpd_priv,
                     topo_task->topo_sxpd->topo_sxpd_priv->evmgr,
                     topo_task->topo_task_priv,
                     topo_task->topo_task_priv->topo_ctx);
    RC_CHECK(rc, out);

    /* update sxpd instance binding config */
    rc = topo_task_schedule_handling(topo_task_update_binding_cfg_sxpd_cb, NULL,
                                     topo_task);
    if (RC_ISOK(rc)) {
        TOPO_TASK_TRACE(topo_task, "binding config update success: %d", rc);
    } else {
        TOPO_TASK_ERROR(topo_task, "binding config update failed: %d", rc);
        goto out;
    }

out:
    return rc;
}

static int topo_task_exec(struct topo_task *topo_task)
{
    int rc = 0;

    PARAM_NULL_CHECK(
        rc, topo_task, topo_task->desc, topo_task->topo_sxpd,
        topo_task->topo_sxpd->topo_sxpd_priv,
        topo_task->topo_sxpd->topo_sxpd_priv->evmgr, topo_task->topo_task_priv,
        topo_task->topo_task_priv->topo_ctx, topo_task->task.exec.cb);
    RC_CHECK(rc, out);

    /* update sxpd instance binding config */
    rc = topo_task_schedule_handling(topo_task->task.exec.cb, NULL, topo_task);
    if (RC_ISOK(rc)) {
        TOPO_TASK_TRACE(topo_task, "custom sxpd callback execution success: %d",
                        rc);
    } else {
        TOPO_TASK_ERROR(topo_task, "custom sxpd callback execution failed: %d",
                        rc);
        goto out;
    }

out:
    return rc;
}

int topo_task_update_peer_cfg_sxpd_cb(struct topo_task *topo_task)
{
    int rc = 0;
    in_addr_t in_addr;

    PARAM_NULL_CHECK(rc, topo_task, topo_task->topo_sxpd,
                     topo_task->topo_sxpd->topo_sxpd_priv,
                     topo_task->topo_sxpd->sxpd_ctx, topo_task);
    RC_CHECK(rc, out);

    if (inet_pton(AF_INET, topo_task->task.peer_cfg.ip, &in_addr) != 1) {
        TOPO_TASK_ERROR(topo_task, "peer IP string value <%s> is invalid",
                        topo_task->task.peer_cfg.ip);
        rc = -1;
        goto out;
    }

    topo_task->task.peer_cfg.peer.ip_address = in_addr;
    topo_task->task.peer_cfg.peer.port =
        htons((uint16_t)topo_task->task.peer_cfg.port);

    if (topo_task->task.peer_cfg.cfg_add) {
        rc = sxpd_cfg_add_peer(topo_task->topo_sxpd->sxpd_ctx,
                               &topo_task->task.peer_cfg.peer);
        if (RC_ISOK(rc)) {
            TOPO_TASK_TRACE(topo_task, "peer config add success: %d", rc);
        } else {
            TOPO_TASK_ERROR(topo_task, "peer config add failed: %d", rc);
            goto out;
        }
    } else {
        rc = sxpd_cfg_del_peer(topo_task->topo_sxpd->sxpd_ctx,
                               &topo_task->task.peer_cfg.peer);
        if (RC_ISOK(rc)) {
            TOPO_TASK_TRACE(topo_task, "peer config del success: %d", rc);
        } else {
            TOPO_TASK_ERROR(topo_task, "peer config del failed: %d", rc);
            goto out;
        }
    }

out:
    return rc;
}

static int topo_task_update_peer_cfg(struct topo_task *topo_task)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, topo_task, topo_task->desc, topo_task->topo_sxpd,
                     topo_task->topo_sxpd->topo_sxpd_priv,
                     topo_task->topo_sxpd->topo_sxpd_priv->evmgr,
                     topo_task->topo_task_priv,
                     topo_task->topo_task_priv->topo_ctx);
    RC_CHECK(rc, out);

    /* update sxpd instance peer config */
    rc = topo_task_schedule_handling(topo_task_update_peer_cfg_sxpd_cb, NULL,
                                     topo_task);
    if (RC_ISOK(rc)) {
        TOPO_TASK_TRACE(topo_task, "peer config update success: %d", rc);
    } else {
        TOPO_TASK_ERROR(topo_task, "peer config update failed: %d", rc);
        goto out;
    }

out:
    return rc;
}

int topo_task_del_str_cfg_sxpd_cb(struct topo_task *topo_task)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, topo_task, topo_task->topo_sxpd,
                     topo_task->topo_sxpd->topo_sxpd_priv,
                     topo_task->topo_sxpd->sxpd_ctx, topo_task);
    RC_CHECK(rc, out);

    rc = sxpd_cfg_del_str_setting(topo_task->topo_sxpd->sxpd_ctx,
                                  topo_task->task.str_cfg.type);
    if (RC_ISOK(rc)) {
        TOPO_TASK_TRACE(topo_task, "<%s> config del success: %d",
                        cfg_get_str_setting_str(topo_task->task.str_cfg.type),
                        rc);
    } else {
        TOPO_TASK_ERROR(topo_task, "<%s> config del failed: %d",
                        cfg_get_str_setting_str(topo_task->task.str_cfg.type),
                        rc);
        goto out;
    }

out:
    return rc;
}

static int topo_task_del_str_cfg(struct topo_task *topo_task)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, topo_task, topo_task->desc, topo_task->topo_sxpd,
                     topo_task->topo_sxpd->topo_sxpd_priv,
                     topo_task->topo_sxpd->topo_sxpd_priv->evmgr,
                     topo_task->topo_task_priv,
                     topo_task->topo_task_priv->topo_ctx);
    RC_CHECK(rc, out);

    /* remove config from sxpd instance */
    rc = topo_task_schedule_handling(topo_task_del_str_cfg_sxpd_cb, NULL,
                                     topo_task);
    if (RC_ISOK(rc)) {
        TOPO_TASK_TRACE(topo_task, "sxpd instance config del success: %d", rc);
    } else {
        TOPO_TASK_ERROR(topo_task, "sxpd instance config del failed: %d", rc);
        goto out;
    }

out:
    return rc;
}

int topo_task_add_str_cfg_sxpd_cb(struct topo_task *topo_task)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, topo_task, topo_task->topo_sxpd,
                     topo_task->topo_sxpd->topo_sxpd_priv,
                     topo_task->topo_sxpd->sxpd_ctx, topo_task);
    RC_CHECK(rc, out);

    rc = sxpd_cfg_add_str_setting(topo_task->topo_sxpd->sxpd_ctx,
                                  topo_task->task.str_cfg.type,
                                  topo_task->task.str_cfg.value);
    if (RC_ISOK(rc)) {
        TOPO_TASK_TRACE(topo_task, "<%s> config add success: %d",
                        cfg_get_str_setting_str(topo_task->task.str_cfg.type),
                        rc);
    } else {
        TOPO_TASK_ERROR(topo_task, "<%s> config add failed: %d",
                        cfg_get_str_setting_str(topo_task->task.str_cfg.type),
                        rc);
        goto out;
    }

out:
    return rc;
}

static int topo_task_add_str_cfg(struct topo_task *topo_task)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, topo_task, topo_task->desc, topo_task->topo_sxpd,
                     topo_task->topo_sxpd->topo_sxpd_priv,
                     topo_task->topo_sxpd->topo_sxpd_priv->evmgr,
                     topo_task->topo_task_priv,
                     topo_task->topo_task_priv->topo_ctx);
    RC_CHECK(rc, out);

    /* add config to sxpd instance */
    rc = topo_task_schedule_handling(topo_task_add_str_cfg_sxpd_cb, NULL,
                                     topo_task);
    if (RC_ISOK(rc)) {
        TOPO_TASK_TRACE(topo_task, "sxpd instance config add success: %d", rc);
    } else {
        TOPO_TASK_ERROR(topo_task, "sxpd instance config add failed: %d", rc);
        goto out;
    }

out:
    return rc;
}

int topo_task_del_uint32_cfg_sxpd_cb(struct topo_task *topo_task)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, topo_task, topo_task->topo_sxpd,
                     topo_task->topo_sxpd->topo_sxpd_priv,
                     topo_task->topo_sxpd->sxpd_ctx, topo_task);
    RC_CHECK(rc, out);

    rc = sxpd_cfg_del_uint32_setting(topo_task->topo_sxpd->sxpd_ctx,
                                     topo_task->task.uint32_cfg.type);
    if (RC_ISOK(rc)) {
        TOPO_TASK_TRACE(
            topo_task, "<%s> config del success: %d",
            cfg_get_uint32_setting_str(topo_task->task.uint32_cfg.type), rc);
    } else {
        TOPO_TASK_ERROR(
            topo_task, "<%s> config del failed: %d",
            cfg_get_uint32_setting_str(topo_task->task.uint32_cfg.type), rc);
        goto out;
    }

out:
    return rc;
}

static int topo_task_del_uint32_cfg(struct topo_task *topo_task)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, topo_task, topo_task->desc, topo_task->topo_sxpd,
                     topo_task->topo_sxpd->topo_sxpd_priv,
                     topo_task->topo_sxpd->topo_sxpd_priv->evmgr,
                     topo_task->topo_task_priv,
                     topo_task->topo_task_priv->topo_ctx);
    RC_CHECK(rc, out);

    /* remove config from sxpd instance */
    rc = topo_task_schedule_handling(topo_task_del_uint32_cfg_sxpd_cb, NULL,
                                     topo_task);
    if (RC_ISOK(rc)) {
        TOPO_TASK_TRACE(topo_task, "sxpd instance config del success: %d", rc);
    } else {
        TOPO_TASK_ERROR(topo_task, "sxpd instance config del failed: %d", rc);
        goto out;
    }

out:
    return rc;
}

int topo_task_add_uint32_cfg_sxpd_cb(struct topo_task *topo_task)
{
    int rc = 0;
    enum log_level log_level = LOG_LEVEL_ALERT;
    in_addr_t in_addr;

    PARAM_NULL_CHECK(rc, topo_task, topo_task->topo_sxpd,
                     topo_task->topo_sxpd->topo_sxpd_priv,
                     topo_task->topo_sxpd->sxpd_ctx, topo_task);
    RC_CHECK(rc, out);

    if (UINT32_SETTING_LOG_LEVEL == topo_task->task.uint32_cfg.type) {
        if (NULL == topo_task->task.uint32_cfg.str_value) {
            TOPO_TASK_ERROR(
                topo_task, "<%s> string value is not set",
                cfg_get_uint32_setting_str(topo_task->task.uint32_cfg.type));
            rc = -1;
            goto out;
        }

        rc = parse_log_level(&log_level, topo_task->task.uint32_cfg.str_value);
        if (RC_ISNOTOK(rc)) {
            TOPO_TASK_ERROR(
                topo_task, "<%s> string value <%s> is invalid",
                cfg_get_uint32_setting_str(topo_task->task.uint32_cfg.type),
                topo_task->task.uint32_cfg.str_value);
            goto out;
        }
        topo_task->task.uint32_cfg.value = log_level;
    } else if (UINT32_SETTING_BIND_ADDRESS == topo_task->task.uint32_cfg.type) {
        if (NULL == topo_task->task.uint32_cfg.str_value) {
            TOPO_TASK_ERROR(
                topo_task, "<%s> string value is not set",
                cfg_get_uint32_setting_str(topo_task->task.uint32_cfg.type));
            rc = -1;
            goto out;
        }

        if (inet_pton(AF_INET, topo_task->task.uint32_cfg.str_value,
                      &in_addr) != 1) {
            TOPO_TASK_ERROR(
                topo_task, "<%s> string value <%s> is invalid",
                cfg_get_uint32_setting_str(topo_task->task.uint32_cfg.type),
                topo_task->task.uint32_cfg.str_value);
            rc = -1;
            goto out;
        }
        topo_task->task.uint32_cfg.value = in_addr;
    } else if (UINT32_SETTING_PORT == topo_task->task.uint32_cfg.type) {
        topo_task->task.uint32_cfg.value =
            htons((uint16_t)topo_task->task.uint32_cfg.value);
    }

    rc = sxpd_cfg_add_uint32_setting(topo_task->topo_sxpd->sxpd_ctx,
                                     topo_task->task.uint32_cfg.type,
                                     topo_task->task.uint32_cfg.value);
    if (RC_ISOK(rc)) {
        TOPO_TASK_TRACE(
            topo_task, "<%s> config add success: %d",
            cfg_get_uint32_setting_str(topo_task->task.uint32_cfg.type), rc);
    } else {
        TOPO_TASK_ERROR(
            topo_task, "<%s> config add failed: %d",
            cfg_get_uint32_setting_str(topo_task->task.uint32_cfg.type), rc);
        goto out;
    }

out:
    return rc;
}

static int topo_task_add_uint32_cfg(struct topo_task *topo_task)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, topo_task, topo_task->desc, topo_task->topo_sxpd,
                     topo_task->topo_sxpd->topo_sxpd_priv,
                     topo_task->topo_sxpd->topo_sxpd_priv->evmgr,
                     topo_task->topo_task_priv,
                     topo_task->topo_task_priv->topo_ctx);
    RC_CHECK(rc, out);

    /* add config to sxpd instance */
    rc = topo_task_schedule_handling(topo_task_add_uint32_cfg_sxpd_cb, NULL,
                                     topo_task);
    if (RC_ISOK(rc)) {
        TOPO_TASK_TRACE(topo_task, "sxpd instance config add success: %d", rc);
    } else {
        TOPO_TASK_ERROR(topo_task, "sxpd instance config add failed: %d", rc);
        goto out;
    }

out:
    return rc;
}

int topo_task_pause_sxpd_sxpd_cb(struct topo_task *topo_task)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, topo_task);
    RC_CHECK(rc, out);

    rc = evmgr_dispatch_break(topo_task->topo_sxpd->topo_sxpd_priv->evmgr);
    if (RC_ISOK(rc)) {
        TOPO_TASK_TRACE(topo_task, "topology evmgr dispatch break success: %d",
                        rc);
    } else {
        TOPO_TASK_ERROR(topo_task, "topology evmgr dispatch break failed: %d",
                        rc);
    }

out:
    return rc;
}

static int topo_task_pause_sxpd(struct topo_task *topo_task)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, topo_task, topo_task->desc, topo_task->topo_sxpd,
                     topo_task->topo_sxpd->topo_sxpd_priv,
                     topo_task->topo_sxpd->topo_sxpd_priv->evmgr,
                     topo_task->topo_task_priv,
                     topo_task->topo_task_priv->topo_ctx);
    RC_CHECK(rc, out);

    /* stop sxpd thread */
    rc = topo_task_schedule_handling(topo_task_pause_sxpd_sxpd_cb, NULL,
                                     topo_task);
    if (RC_ISOK(rc)) {
        TOPO_TASK_TRACE(topo_task, "sxpd instance dispatch break success: %d",
                        rc);
    } else {
        TOPO_TASK_ERROR(topo_task, "sxpd instance dispatch break failed: %d",
                        rc);
        goto out;
    }

    /* wait for thread to finish */
    rc = pthread_join(topo_task->topo_sxpd->topo_sxpd_priv->pthread, NULL);
    if (RC_ISOK(rc)) {
        TOPO_TASK_TRACE(topo_task, "sxpd instance pause success: %d", rc);
    } else {
        TOPO_TASK_ERROR(topo_task, "sxpd instance pause failed: %d", rc);
        goto out;
    }

    topo_task->topo_sxpd->topo_sxpd_priv->status = TOPO_SXPD_INSTANCE_PAUSED;

out:
    return rc;
}

static int topo_task_stop_sxpd(struct topo_task *topo_task)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, topo_task, topo_task->desc, topo_task->topo_sxpd,
                     topo_task->topo_sxpd->topo_sxpd_priv,
                     topo_task->topo_sxpd->topo_sxpd_priv->evmgr,
                     topo_task->topo_task_priv,
                     topo_task->topo_task_priv->topo_ctx);
    RC_CHECK(rc, out);

    /* pause sxpd instance first */
    if (TOPO_SXPD_INSTANCE_STARTED ==
        topo_task->topo_sxpd->topo_sxpd_priv->status) {
        rc = topo_task_pause_sxpd(topo_task);
        RC_CHECK(rc, out);
    }

    if (TOPO_SXPD_INSTANCE_PAUSED !=
        topo_task->topo_sxpd->topo_sxpd_priv->status) {
        rc = -1;
        TOPO_TASK_ERROR(topo_task, "sxpd instance is not paused error: %d", rc);
        goto out;
    }

    topo_task->topo_sxpd->topo_sxpd_priv->status = TOPO_SXPD_INSTANCE_STOPPED;

    evmgr_timer_destroy(topo_task->topo_sxpd->nop_retry_timer);
    topo_task->topo_sxpd->nop_retry_timer = NULL;

    cfg_ctx_destroy(topo_task->topo_sxpd->topo_sxpd_priv->cfg_ctx);
    topo_task->topo_sxpd->topo_sxpd_priv->cfg_ctx = NULL;

    sxpd_destroy(topo_task->topo_sxpd->sxpd_ctx);
    topo_task->topo_sxpd->sxpd_ctx = NULL;

    evmgr_destroy(topo_task->topo_sxpd->topo_sxpd_priv->evmgr);
    topo_task->topo_sxpd->topo_sxpd_priv->evmgr = NULL;

    if (topo_task->topo_sxpd->topo_sxpd_priv->es) {
        mem_free(topo_task->topo_sxpd->topo_sxpd_priv->es);
        topo_task->topo_sxpd->topo_sxpd_priv->es = NULL;
    }

    mem_free(topo_task->topo_sxpd->topo_sxpd_priv);
    topo_task->topo_sxpd->topo_sxpd_priv = NULL;

out:
    return rc;
}

static void *topo_task_sxpd_thread(void *topo_task_)
{
    int rc = 0;
    struct topo_task *topo_task = NULL;

    assert(topo_task_);
    topo_task = topo_task_;

    TOPO_TASK_TRACE(topo_task, "%s",
                    "Sxpd instance thread start in progress...");

    /* dispatch evmgr of sxpd instance in concurrent thread */
    rc = evmgr_dispatch(topo_task->topo_sxpd->topo_sxpd_priv->evmgr);
    if (RC_ISNOTOK(rc)) {
        TOPO_TASK_ERROR(topo_task, "evmgr dispatch failed: %d", rc);
        assert(0);
    }

    pthread_exit(NULL);
}

int topo_task_run_sxpd_sxpd_cb(struct topo_task *topo_task)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, topo_task);
    RC_CHECK(rc, out);

out:
    return rc;
}

static int topo_task_run_sxpd(struct topo_task *topo_task)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, topo_task, topo_task->desc, topo_task->topo_sxpd,
                     topo_task->topo_sxpd->topo_sxpd_priv,
                     topo_task->topo_sxpd->topo_sxpd_priv->evmgr,
                     topo_task->topo_sxpd->cfg_path, topo_task->topo_task_priv,
                     topo_task->topo_task_priv->topo_ctx);
    RC_CHECK(rc, out);

    /* run sxpd instance in parallel thread */
    rc = pthread_create(&topo_task->topo_sxpd->topo_sxpd_priv->pthread, NULL,
                        topo_task_sxpd_thread, topo_task);
    if (RC_ISNOTOK(rc)) {
        TOPO_TASK_ERROR(topo_task, "Sxpd instance thread start failed: %d", rc);
        goto out;
    }

    /* check if is sxpd instance already started */
    rc = topo_task_schedule_handling(topo_task_run_sxpd_sxpd_cb, NULL,
                                     topo_task);
    if (RC_ISOK(rc)) {
        TOPO_TASK_TRACE(topo_task, "sxpd instance start success: %d", rc);
    } else {
        TOPO_TASK_ERROR(topo_task, "sxpd instance start failed: %d", rc);
        goto out;
    }

    topo_task->topo_sxpd->topo_sxpd_priv->status = TOPO_SXPD_INSTANCE_STARTED;

out:
    return rc;
}

static int topo_task_main_exec(struct topo_task *topo_task)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, topo_task, topo_task->desc, topo_task->topo_task_priv,
                     topo_task->topo_task_priv->topo_ctx,
                     topo_task->task.main_exec.cb);
    RC_CHECK(rc, out);

    rc = topo_task->task.main_exec.cb(topo_task);
    if (RC_ISOK(rc)) {
        TOPO_TASK_TRACE(
            topo_task, "main thread executing custom task callback success: %d",
            rc);
    } else {
        TOPO_TASK_ERROR(topo_task,
                        "main thread executing custom task callback failed: %d",
                        rc);
        goto out;
    }

out:
    return rc;
}

static void topo_task_new_sxpd_nop_handler(struct evmgr_timer *timer,
                                           __attribute__((unused)) void *ctx_)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, timer);
    assert(RC_ISOK(rc));

    return;
}

static int topo_task_new_sxpd_setup_nop_handler(struct topo_task *topo_task)
{
    int rc = 0;
    struct evmgr_timer *retry_timer = NULL;
    struct timeval retry_timeout = {.tv_sec = 43200, .tv_usec = 0 };

    PARAM_NULL_CHECK(rc, topo_task, topo_task->desc, topo_task->topo_sxpd,
                     topo_task->topo_sxpd->topo_sxpd_priv,
                     topo_task->topo_sxpd->topo_sxpd_priv->evmgr);
    RC_CHECK(rc, out);

    retry_timer = evmgr_timer_create(
        topo_task->topo_sxpd->topo_sxpd_priv->evmgr, NULL, &retry_timeout, true,
        topo_task_new_sxpd_nop_handler, NULL);
    if (!retry_timer) {
        TOPO_TASK_ERROR(topo_task, "%s", "sxpd timer create failed");
        rc = -1;
        goto out;
    }

    rc = evmgr_timer_arm(retry_timer);
    if (RC_ISNOTOK(rc)) {
        TOPO_TASK_ERROR(topo_task, "sxpd timer arm failed: %d", rc);
        goto out;
    }

    topo_task->topo_sxpd->nop_retry_timer = retry_timer;
out:
    return rc;
}

static int topo_task_new_sxpd(struct topo_task *topo_task)
{
    int rc = 0;
    struct topo_sxpd_priv *topo_sxpd_priv = NULL;

    PARAM_NULL_CHECK(rc, topo_task, topo_task->desc, topo_task->topo_sxpd,
                     topo_task->topo_sxpd->cfg_path, topo_task->topo_task_priv,
                     topo_task->topo_task_priv->topo_ctx);
    RC_CHECK(rc, out);

    assert(!topo_task->topo_sxpd->topo_sxpd_priv);

    topo_task->topo_sxpd->topo_sxpd_priv =
        mem_calloc(1, sizeof(*topo_task->topo_sxpd->topo_sxpd_priv));
    if (!topo_task->topo_task_priv) {
        TOPO_TASK_ERROR(topo_task, "%s",
                        "Out of memory to create internal data");
        rc = -1;
        goto out;
    }
    topo_sxpd_priv = topo_task->topo_sxpd->topo_sxpd_priv;

    /* create configuration context */
    rc = cfg_ctx_create(&topo_sxpd_priv->cfg_ctx,
                        topo_task->topo_sxpd->cfg_path, &topo_sxpd_priv->es);
    if (RC_ISOK(rc)) {
        TOPO_TASK_TRACE(topo_task, "Configuration context create success: %d",
                        rc);
    } else {
        TOPO_TASK_ERROR(topo_task, "Configuration context create failed: %d",
                        rc);
        goto out;
    }

    topo_sxpd_priv->evmgr = evmgr_create(topo_sxpd_priv->es);
    if (topo_sxpd_priv->evmgr) {
        TOPO_TASK_TRACE(topo_task, "Event mgr create success: %p",
                        (void *)topo_sxpd_priv->evmgr);
    } else {
        TOPO_TASK_ERROR(topo_task, "Event mgr create failed: %p",
                        (void *)topo_sxpd_priv->evmgr);
        rc = -1;
        goto out;
    }

    topo_task->topo_sxpd->sxpd_ctx =
        sxpd_create(topo_sxpd_priv->evmgr, topo_sxpd_priv->es, LOG_LEVEL_ERROR);
    if (topo_task->topo_sxpd->sxpd_ctx) {
        TOPO_TASK_TRACE(topo_task, "Sxpd context create success: %p",
                        (void *)topo_task->topo_sxpd->sxpd_ctx);
    } else {
        TOPO_TASK_ERROR(topo_task, "Sxpd context create failed: %p",
                        (void *)topo_task->topo_sxpd->sxpd_ctx);
        rc = -1;
        goto out;
    }

    topo_task->topo_sxpd->sxpd_ctx->version = topo_task->topo_sxpd->version;

    rc = topo_task_new_sxpd_setup_nop_handler(topo_task);
    if (RC_ISOK(rc)) {
        TOPO_TASK_TRACE(topo_task, "Sxpd setup nop handler success: %d", rc);
    } else {
        TOPO_TASK_ERROR(topo_task, "Sxpd setup nop handler failed: %d", rc);
        goto out;
    }

    rc = sxpd_register_config(topo_task->topo_sxpd->sxpd_ctx,
                              topo_sxpd_priv->cfg_ctx);
    RC_CHECK(rc, out);

out:
    if (RC_ISNOTOK(rc) && topo_sxpd_priv) {
        if (topo_sxpd_priv->es) {
            mem_free(topo_sxpd_priv->es);
            topo_sxpd_priv->es = NULL;
        }
        sxpd_destroy(topo_task->topo_sxpd->sxpd_ctx);
        topo_task->topo_sxpd->topo_sxpd_priv = NULL;
        cfg_ctx_destroy(topo_sxpd_priv->cfg_ctx);
        evmgr_destroy(topo_sxpd_priv->evmgr);

        mem_free(topo_sxpd_priv);
        topo_sxpd_priv = NULL;
    }
    return rc;
}

static struct topo_ctx topo_ctx = {.mutex = PTHREAD_MUTEX_INITIALIZER,
                                   .cond = PTHREAD_COND_INITIALIZER };

int topo_run(struct topo_task *tasks, size_t tasks_num)
{
    int rc = 0;
    size_t i = 0;
    size_t j = 0;
    struct topo_task *topo_task = NULL;
    log_setloglevel(LOG_LEVEL_ERROR);

    PARAM_NULL_CHECK(rc, tasks);
    RC_CHECK(rc, out);

    /* process all tasks */
    for (i = 0; i < tasks_num; ++i) {

        topo_task = &tasks[i];

        assert(!topo_task->topo_task_priv);

        /* create topology task internal data */
        topo_task->topo_task_priv =
            mem_calloc(1, sizeof(*topo_task->topo_task_priv));
        if (!topo_task->topo_task_priv) {
            LOG_ERROR(TOPO_TASK_FMT "Out of memory to create internal data", i,
                      topo_task_type_to_str((topo_task)->type),
                      (topo_task)->desc);
            rc = -1;
            goto out;
        }

        /* fill topology task internal data */
        topo_task->id = i;
        topo_task->topo_task_priv->topo_ctx = &topo_ctx;

        TOPO_TASK_TRACE(topo_task, "%s", "starting");
        switch (topo_task->type) {
        case TOPO_TASK_NEW_SXPD:
            rc = topo_task_new_sxpd(topo_task);
            break;
        case TOPO_TASK_RUN_SXPD:
            rc = topo_task_run_sxpd(topo_task);
            break;
        case TOPO_TASK_PAUSE_SXPD:
            rc = topo_task_pause_sxpd(topo_task);
            break;
        case TOPO_TASK_STOP_SXPD:
            rc = topo_task_stop_sxpd(topo_task);
            break;
        case TOPO_TASK_UINT32_CFG:
            if (topo_task->task.uint32_cfg.cfg_add) {
                rc = topo_task_add_uint32_cfg(topo_task);
            } else {
                rc = topo_task_del_uint32_cfg(topo_task);
            }
            break;
        case TOPO_TASK_STR_CFG:
            if (topo_task->task.str_cfg.cfg_add) {
                rc = topo_task_add_str_cfg(topo_task);
            } else {
                rc = topo_task_del_str_cfg(topo_task);
            }
            break;
        case TOPO_TASK_PEER_CFG:
            rc = topo_task_update_peer_cfg(topo_task);
            break;
        case TOPO_TASK_BINDING_CFG:
            rc = topo_task_update_binding_cfg(topo_task);
            break;
        case TOPO_TASK_WAIT_FOR:
            rc = topo_task_wait_for(topo_task);
            break;
        case TOPO_TASK_EXEC:
            rc = topo_task_exec(topo_task);
            break;
        case TOPO_TASK_MAIN_EXEC:
            rc = topo_task_main_exec(topo_task);
            break;
        default:
            TOPO_TASK_ERROR(topo_task, "task type <%d> is invalid",
                            topo_task->type);
            rc = -1;
            break;
        }

        if (RC_ISOK(rc)) {
            TOPO_TASK_TRACE(topo_task, "success: %d", rc);
        } else {
            TOPO_TASK_ERROR(topo_task, "failed: %d", rc);
            break;
        }
    }

    /* destroy tasks internal data */
    for (j = 0; j < i; ++j) {
        topo_task = &tasks[j];
        if (topo_task->topo_task_priv) {
            mem_free(topo_task->topo_task_priv);
            topo_task->topo_task_priv = NULL;
        }
    }
out:
    return rc;
}
