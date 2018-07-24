
#include <stdbool.h>
#include <gio/gio.h>

#include <sxpd.h>
#include <debug.h>
#include <util.h>
#include <evmgr.h>
#include <config.h>

#include "gdbus_interface_gen.h"
#include "gdbus_interface.h"

#define SXPD_GDBUS_OWN_NAME "com.cisco.sxpd"
#define SXPD_GDBUS_INTERFACE_PATH "/com/cisco/sxpd"
#define SXPD_GDBUS_MAX_SENDER_ID_SIZE NAME_MAX
#define SXPD_GDBUS_MAX_ITER_NUM 10
#define SXPD_GDBUS_ITER_TIMEOUT 300 /* 300 seconds = 5 minutes */
#define SXPD_GDBUS_ITER_CLEAN_TIMEOUT 30

#define SXPD_GDBUS_ERROR_INTERNAL "gdbus internal error"
#define SXPD_GDBUS_ERROR_MAX_CLIENTS \
    "gdbus maximum number of clients has been reached"
#define SXPD_GDBUS_ERROR_INVALID_BINDING_TYPE "invalid binding type"
#define SXPD_GDBUS_ERROR_ITER "iterator does not exist"
#define SXPD_GDBUS_COND_TIMEOUT 6

struct sxpd_gdbus_res_v4_v6_data {
    bool iter_end;
    uint16_t tag;
    struct v4_v6_prefix prefix;
};

struct sxpd_gdbus_res_peer_data {
    bool iter_end;
    struct sxpd_peer_info p;
};

struct sxpd_gdbus_info {
    struct sxpd_info sxpd_info;
    char default_password[CFG_PASSWORD_MAX_SIZE];
};

struct sxpd_gdbus_iter {
    bool in_use;
    char sender_id[SXPD_GDBUS_MAX_SENDER_ID_SIZE];
    struct timespec last_usage;
    void *sxpd_iterator;
};

struct sxpd_gdbus_ctx {
    struct sxpd_ctx *sxpd_ctx;
    struct evmgr *evmgr;
    GMainLoop *loop;
    pthread_t thread;
    pthread_cond_t cond;
    pthread_mutex_t mutex;
    guint gdbus_identifier;
    guint timeout_identifier;
    struct sxpd_gdbus_iter v4_iter[SXPD_GDBUS_MAX_ITER_NUM];
    struct sxpd_gdbus_iter v6_iter[SXPD_GDBUS_MAX_ITER_NUM];
    struct sxpd_gdbus_iter peer_iter[SXPD_GDBUS_MAX_ITER_NUM];
};

struct sxpd_gdbus_hnd_ctx;

typedef int (*sxpd_gdbus_hnd_cb)(Sxpd *object,
                                 GDBusMethodInvocation *invocation,
                                 struct sxpd_gdbus_hnd_ctx *cb_ctx);

typedef int (*sxpd_gdbus_hnd_sxpd_cb)(struct sxpd_gdbus_hnd_ctx *cb_ctx);

struct sxpd_gdbus_hnd_ctx {
    sxpd_gdbus_hnd_sxpd_cb hnd_sxpd_cb;
    struct sxpd_gdbus_ctx *gdbus_ctx;
    char sender_id[SXPD_GDBUS_MAX_SENDER_ID_SIZE];
    const char *gdbus_error;
    size_t iter_id;
    uint8_t binding_type;
    union {
        /* iterator id response */
        size_t iter_id_res;
        /* v6 binding data response */
        struct sxpd_gdbus_res_v4_v6_data v4v6;
        /* peer data response */
        struct sxpd_gdbus_res_peer_data peer;
        /* sxpd informations response */
        struct sxpd_gdbus_info sxpd_info;
    } res_data;
};

static int sxpd_gdbus_ctx_new(struct sxpd_gdbus_ctx **gdbus_ctx,
                              struct sxpd_ctx *sxpd_ctx, struct evmgr *evmgr)
{
    int rc = 0;
    struct sxpd_gdbus_ctx *ctx = NULL;

    PARAM_NULL_CHECK(rc, gdbus_ctx);
    RC_CHECK(rc, out);

    ctx = mem_calloc(1, sizeof(*ctx));
    if (NULL == (ctx)) {
        LOG_ERROR("gdbus context memory allocation failed");
        rc = -1;
        goto out;
    }

    ctx->sxpd_ctx = sxpd_ctx;
    ctx->evmgr = evmgr;
    pthread_cond_init(&ctx->cond, NULL);
    pthread_mutex_init(&ctx->mutex, NULL);

    ctx->loop = g_main_loop_new(NULL, FALSE);
    if (NULL == ctx->loop) {
        LOG_ERROR("GMainLoop new failed");
        rc = -1;
        goto out;
    }

    *gdbus_ctx = ctx;
out:
    return rc;
}

static int sxpd_gdbus_interface_loop_quit(struct sxpd_gdbus_ctx *gdbus_ctx)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, gdbus_ctx);
    RC_CHECK(rc, out);

    if (NULL != gdbus_ctx->loop) {
        if (g_main_loop_is_running(gdbus_ctx->loop)) {
            g_main_loop_quit(gdbus_ctx->loop);
            LOG_TRACE("gdbus interface main loop quit called");
        }
        g_main_loop_unref(gdbus_ctx->loop);
        gdbus_ctx->loop = NULL;
    }
out:
    return rc;
}

static int sxpd_gdbus_ctx_destroy(struct sxpd_gdbus_ctx *gdbus_ctx)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, gdbus_ctx);
    RC_CHECK(rc, out);

    sxpd_gdbus_interface_loop_quit(gdbus_ctx);

    pthread_mutex_destroy(&gdbus_ctx->mutex);
    pthread_cond_destroy(&gdbus_ctx->cond);
    mem_free(gdbus_ctx);

out:
    return rc;
}

static int sxpd_gdbus_iter_new(struct sxpd_gdbus_iter *iter_list,
                               const char *sender_id, size_t *iter_id)
{
    int rc = 0;
    size_t i = 0;
    struct sxpd_gdbus_iter *iter = NULL;

    PARAM_NULL_CHECK(rc, iter_list, sender_id, iter_id);
    RC_CHECK(rc, out);

    if (strnlen(sender_id, SXPD_GDBUS_MAX_SENDER_ID_SIZE) >=
        SXPD_GDBUS_MAX_SENDER_ID_SIZE) {
        LOG_ERROR("Sender id is out of maximum length");
        rc = -1;
        goto out;
    }

    for (i = 0; i < SXPD_GDBUS_MAX_ITER_NUM; ++i) {
        if (false == iter_list[i].in_use) {
            iter = &iter_list[i];
            iter->in_use = true;
            clock_gettime(CLOCK_MONOTONIC, &iter->last_usage);
            strncpy(iter->sender_id, sender_id, SXPD_GDBUS_MAX_SENDER_ID_SIZE);
            iter->sxpd_iterator = NULL;
            break;
        }
    }

    if (NULL != iter) {
        *iter_id = i;
    } else {
        rc = -1;
        LOG_ERROR("internal maximum error");
    }

out:
    return rc;
}

static int sxpd_gdbus_iter_finish(struct sxpd_gdbus_iter *iter_list,
                                  const char *sender_id, size_t iter_id,
                                  void **sxpd_iterator)
{
    int rc = 0;
    struct sxpd_gdbus_iter *iter = NULL;

    PARAM_NULL_CHECK(rc, iter_list);
    RC_CHECK(rc, out);

    if ((NULL != sender_id) &&
        (strnlen(sender_id, SXPD_GDBUS_MAX_SENDER_ID_SIZE) >=
         SXPD_GDBUS_MAX_SENDER_ID_SIZE)) {
        LOG_ERROR("Sender id is out of maximum length");
        rc = -1;
        goto out;
    }

    if (iter_id >= SXPD_GDBUS_MAX_ITER_NUM) {
        LOG_ERROR("iterator id is out of range");
        rc = -1;
        goto out;
    }

    if (false == iter_list[iter_id].in_use) {
        LOG_ERROR("iterator is not active");
        rc = -1;
        goto out;
    }

    iter = &iter_list[iter_id];
    if ((NULL != sender_id) && (strncmp(iter->sender_id, sender_id,
                                        SXPD_GDBUS_MAX_SENDER_ID_SIZE) != 0)) {
        LOG_ERROR("iterator does not match sender");
        rc = -1;
        goto out;
    }

    iter->in_use = false;
    if (NULL != sxpd_iterator) {
        *sxpd_iterator = iter->sxpd_iterator;
    }
    iter->sxpd_iterator = NULL;

out:
    return rc;
}

static int sxpd_gdbus_iter_get(struct sxpd_gdbus_iter *iter_list,
                               const char *sender_id, size_t iter_id,
                               struct sxpd_gdbus_iter **iter)
{
    int rc = 0;
    struct sxpd_gdbus_iter *iter_tmp = NULL;

    PARAM_NULL_CHECK(rc, iter_list);
    RC_CHECK(rc, out);

    if ((NULL != sender_id) &&
        (strnlen(sender_id, SXPD_GDBUS_MAX_SENDER_ID_SIZE) >=
         SXPD_GDBUS_MAX_SENDER_ID_SIZE)) {
        LOG_ERROR("Sender id is out of maximum length");
        rc = -1;
        goto out;
    }

    if (iter_id >= SXPD_GDBUS_MAX_ITER_NUM) {
        LOG_ERROR("iterator id is out of range");
        rc = -1;
        goto out;
    }

    if (false == iter_list[iter_id].in_use) {
        LOG_ERROR("iterator is not active");
        rc = -1;
        goto out;
    }

    iter_tmp = &iter_list[iter_id];
    if ((NULL != sender_id) && (strncmp(iter_tmp->sender_id, sender_id,
                                        SXPD_GDBUS_MAX_SENDER_ID_SIZE) != 0)) {
        LOG_ERROR("iterator does not match sender");
        rc = -1;
        goto out;
    }

    clock_gettime(CLOCK_MONOTONIC, &iter_tmp->last_usage);
    *iter = iter_tmp;

out:
    return rc;
}

static bool sxpd_gdbus_iter_timeouted(struct sxpd_gdbus_iter *iter)
{
    int rc = 0;
    bool ret = false;
    struct timespec ts = { 0, 0 };

    PARAM_NULL_CHECK(rc, iter);
    RC_CHECK(rc, out);

    clock_gettime(CLOCK_MONOTONIC, &ts);
    if (true == iter->in_use) {
        if ((ts.tv_sec - iter->last_usage.tv_sec) >= SXPD_GDBUS_ITER_TIMEOUT) {
            ret = true;
        }
    }

out:
    return ret;
}

static void sxpd_gdbus_schedule_handling_sxpd_cb(struct evmgr_timer *timer,
                                                 void *ctx_)
{
    int rc = 0;
    int tmp_rc = 0;
    struct sxpd_gdbus_hnd_ctx *ctx;

    PARAM_NULL_CHECK(rc, timer, ctx_);
    RC_CHECK(rc, out);

    rc = evmgr_timer_disarm(timer);
    RC_CHECK(rc, out);
    evmgr_timer_destroy(timer);

    ctx = ctx_;

    LOG_TRACE("sxpd handler fires");

    tmp_rc = pthread_mutex_lock(&ctx->gdbus_ctx->mutex);
    if (RC_ISNOTOK(tmp_rc)) {
        LOG_ERROR("sxpd handler mutex lock failed: %d", tmp_rc);
        assert(0);
    }

    rc = ctx->hnd_sxpd_cb(ctx);
    if (RC_ISNOTOK(rc)) {
        if (NULL == ctx->gdbus_error) {
            ctx->gdbus_error = SXPD_GDBUS_ERROR_INTERNAL;
        }
        LOG_ERROR("sxpd handler failed: %d", rc);
    }

    tmp_rc = pthread_cond_signal(&ctx->gdbus_ctx->cond);
    if (RC_ISNOTOK(tmp_rc)) {
        LOG_ERROR("sxpd handler condition signal failed: %d", tmp_rc);
        assert(0);
    }

    tmp_rc = pthread_mutex_unlock(&ctx->gdbus_ctx->mutex);
    if (RC_ISNOTOK(tmp_rc)) {
        LOG_ERROR("sxpd handler mutex unlock failed: %d", tmp_rc);
        assert(0);
    }

    if (RC_ISOK(rc)) {
        LOG_TRACE("sxpd handler success");
    }

out:
    return;
}

static int sxpd_gdbus_schedule_handling_sxpd(struct sxpd_gdbus_hnd_ctx *cb_ctx)
{
    int rc = 0;
    struct evmgr_timer *retry_timer = NULL;
    struct timeval retry_timeout = {.tv_sec = 0, .tv_usec = 0 };

    PARAM_NULL_CHECK(rc, cb_ctx, cb_ctx->gdbus_ctx, cb_ctx->hnd_sxpd_cb);

    if (RC_ISOK(rc)) {
        retry_timer = evmgr_timer_create(
            cb_ctx->gdbus_ctx->evmgr, NULL, &retry_timeout, false,
            sxpd_gdbus_schedule_handling_sxpd_cb, cb_ctx);
        if (!retry_timer) {
            LOG_ERROR("sxpd gdbus scheduler timer create failed");
            rc = ENOMEM;
        }
    }

    if (RC_ISOK(rc)) {
        rc = evmgr_timer_arm(retry_timer);
        if (RC_ISNOTOK(rc)) {
            LOG_ERROR("sxpd handle scheduler cannot arm timer failed");
        }
    }

    return rc;
}

static int sxpd_gdbus_schedule_handling_sync(struct sxpd_gdbus_ctx *gdbus_ctx,
                                             sxpd_gdbus_hnd_sxpd_cb sxpd_cb,
                                             struct sxpd_gdbus_hnd_ctx *cb_ctx)
{
    int rc = 0;
    struct timespec ts = { 0, 0 };
    int tmp = 0;

    PARAM_NULL_CHECK(rc, gdbus_ctx, sxpd_cb, cb_ctx);
    RC_CHECK(rc, out);

    cb_ctx->gdbus_ctx = gdbus_ctx;
    cb_ctx->hnd_sxpd_cb = sxpd_cb;

    rc = pthread_mutex_lock(&gdbus_ctx->mutex);
    if (RC_ISNOTOK(rc)) {
        LOG_ERROR("Mutex lock failed: %d", rc);
        goto out;
    }

    rc = sxpd_gdbus_schedule_handling_sxpd(cb_ctx);
    if (RC_ISNOTOK(rc)) {
        tmp = pthread_mutex_unlock(&gdbus_ctx->mutex);
        assert(RC_ISOK(tmp));
        LOG_ERROR("schedule sxpd handler failed: %d", rc);
        goto out;
    }

    tmp = clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec = ts.tv_sec + SXPD_GDBUS_COND_TIMEOUT;
    assert(RC_ISOK(tmp));

    rc = pthread_cond_timedwait(&gdbus_ctx->cond, &gdbus_ctx->mutex, &ts);
    if (RC_ISNOTOK(rc)) {
        tmp = pthread_mutex_unlock(&gdbus_ctx->mutex);
        assert(RC_ISOK(tmp));
        LOG_ERROR("Condition wait failed: %d", rc);
        goto out;
    }

    tmp = pthread_mutex_unlock(&gdbus_ctx->mutex);
    assert(RC_ISOK(tmp));
    if (NULL != cb_ctx->gdbus_error) {
        LOG_ERROR("sxpd handler failed: %s", cb_ctx->gdbus_error);
        rc = -1;
        goto out;
    }

out:
    return rc;
}

static int sxpd_gdbus_schedule_handling(Sxpd *object,
                                        GDBusMethodInvocation *invocation,
                                        struct sxpd_gdbus_ctx *gdbus_ctx,
                                        sxpd_gdbus_hnd_sxpd_cb sxpd_cb,
                                        sxpd_gdbus_hnd_cb gdbus_cb,
                                        struct sxpd_gdbus_hnd_ctx *cb_ctx)
{
    int rc = 0;
    const char *sender_id = NULL;

    PARAM_NULL_CHECK(rc, object, invocation, gdbus_ctx, sxpd_cb, gdbus_cb,
                     cb_ctx);
    RC_CHECK(rc, out);

    cb_ctx->gdbus_ctx = gdbus_ctx;
    cb_ctx->hnd_sxpd_cb = sxpd_cb;

    sender_id = g_dbus_method_invocation_get_sender(invocation);
    if (NULL == sender_id) {
        LOG_ERROR("failed to get sender id");
        rc = -1;
        goto out;
    }

    if (strnlen(sender_id, SXPD_GDBUS_MAX_SENDER_ID_SIZE) >=
        SXPD_GDBUS_MAX_SENDER_ID_SIZE) {
        LOG_ERROR("sender id is out of maximum length");
        rc = -1;
        goto out;
    }

    strncpy(cb_ctx->sender_id, sender_id, SXPD_GDBUS_MAX_SENDER_ID_SIZE);

    rc = sxpd_gdbus_schedule_handling_sync(gdbus_ctx, sxpd_cb, cb_ctx);
    if (RC_ISNOTOK(rc)) {
        LOG_TRACE("sxpd handler failed: %d", rc);
        goto out;
    }

    rc = gdbus_cb(object, invocation, cb_ctx);
    if (RC_ISNOTOK(rc)) {
        LOG_ERROR("handling sxpd answer by gdbus callback failed: %d", rc);
        goto out;
    }

    LOG_TRACE("gdbus handler success");

out:
    if (RC_ISNOTOK(rc)) {
        if ((NULL != cb_ctx) && (NULL != invocation)) {
            if (NULL == cb_ctx->gdbus_error) {
                cb_ctx->gdbus_error = SXPD_GDBUS_ERROR_INTERNAL;
            }
            g_dbus_method_invocation_return_error(invocation, G_IO_ERROR,
                                                  G_IO_ERROR_DBUS_ERROR,
                                                  cb_ctx->gdbus_error);
        } else {
            g_dbus_method_invocation_return_error(invocation, G_IO_ERROR,
                                                  G_IO_ERROR_DBUS_ERROR,
                                                  SXPD_GDBUS_ERROR_INTERNAL);
        }
    }
    return rc;
}

static int on_handle_binding_iterate_gdbus(Sxpd *object,
                                           GDBusMethodInvocation *invocation,
                                           struct sxpd_gdbus_hnd_ctx *ctx)
{
    int rc = 0;
    uint32_t data[4] = { 0, 0, 0, 0 };
    GVariant *gv = NULL;

    PARAM_NULL_CHECK(rc, object, invocation, ctx);
    RC_CHECK(rc, out);

    if (false == ctx->res_data.v4v6.iter_end) {
        gv = g_variant_new_fixed_array(G_VARIANT_TYPE_UINT32,
                                       ctx->res_data.v4v6.prefix.ip.data, 4,
                                       sizeof(guint32));
        if (NULL == gv) {
            LOG_ERROR("create new fixed array gvariant failed");
            ctx->gdbus_error = SXPD_GDBUS_ERROR_INTERNAL;
            goto out;
        }
        if (ctx->binding_type == V4) {
            sxpd_complete_binding_iterate(object, invocation, gv,
                                          ctx->res_data.v4v6.prefix.len,
                                          ctx->res_data.v4v6.tag);
        } else {
            sxpd_complete_binding_iterate(object, invocation, gv,
                                          ctx->res_data.v4v6.prefix.len,
                                          ctx->res_data.v4v6.tag);
        }
    } else {
        gv = g_variant_new_fixed_array(G_VARIANT_TYPE_UINT32, data, 4,
                                       sizeof(guint32));
        if (NULL == gv) {
            LOG_ERROR("create new fixed array gvariant failed");
            ctx->gdbus_error = SXPD_GDBUS_ERROR_INTERNAL;
            goto out;
        }
        sxpd_complete_binding_iterate(object, invocation, gv, 0, 0);
    }

out:
    return rc;
}

static int on_handle_binding_iterate_sxpd(struct sxpd_gdbus_hnd_ctx *ctx)
{
    int rc = 0;
    struct sxpd_gdbus_iter *iter = NULL;

    PARAM_NULL_CHECK(rc, ctx, ctx->gdbus_ctx);
    RC_CHECK(rc, out);

    if (ctx->binding_type == V4) {
        rc = sxpd_gdbus_iter_get(ctx->gdbus_ctx->v4_iter, ctx->sender_id,
                                 ctx->iter_id, &iter);
        if (RC_ISNOTOK(rc)) {
            ctx->gdbus_error = SXPD_GDBUS_ERROR_ITER;
            LOG_ERROR("Failed to finish V4 binding iterator: %d", rc);
            goto out;
        }
    } else if (ctx->binding_type == V6) {
        rc = sxpd_gdbus_iter_get(ctx->gdbus_ctx->v6_iter, ctx->sender_id,
                                 ctx->iter_id, &iter);
        if (RC_ISNOTOK(rc)) {
            ctx->gdbus_error = SXPD_GDBUS_ERROR_ITER;
            LOG_ERROR("Failed to finish V6 binding iterator: %d", rc);
            goto out;
        }
    } else {
        ctx->gdbus_error = SXPD_GDBUS_ERROR_INVALID_BINDING_TYPE;
        LOG_ERROR("binding type %d is invalid", ctx->binding_type);
        rc = -1;
        goto out;
    }

    rc = sxpd_iterate_bindings(
        ctx->gdbus_ctx->sxpd_ctx, ctx->binding_type,
        (struct sxpd_bindings_iterator **)&iter->sxpd_iterator,
        ctx->res_data.v4v6.prefix.ip.data,
        sizeof(ctx->res_data.v4v6.prefix.ip.data),
        &ctx->res_data.v4v6.prefix.len, &ctx->res_data.v4v6.tag);

    if (RC_ISNOTOK(rc)) {
        ctx->gdbus_error = SXPD_GDBUS_ERROR_INTERNAL;
        LOG_ERROR("binding iterate failed: %d", rc);
        goto out;
    }

    if (NULL != iter->sxpd_iterator) {
        ctx->res_data.v4v6.iter_end = false;
    } else {
        ctx->res_data.v4v6.iter_end = true;
    }

out:
    return rc;
}

static gboolean on_handle_binding_iterate(Sxpd *object,
                                          GDBusMethodInvocation *invocation,
                                          guint arg_type, guint arg_id,
                                          gpointer *user_data)
{
    int rc = 0;
    struct sxpd_gdbus_hnd_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));

    PARAM_NULL_CHECK(rc, user_data);
    RC_CHECK(rc, out);

    ctx.binding_type = arg_type;
    ctx.iter_id = arg_id;

    rc = sxpd_gdbus_schedule_handling(
        object, invocation, (struct sxpd_gdbus_ctx *)user_data,
        on_handle_binding_iterate_sxpd, on_handle_binding_iterate_gdbus, &ctx);
    if (RC_ISOK(rc)) {
        LOG_TRACE("handle binding-iterate success");
    } else {
        LOG_ERROR("handle binding-iterate failed: %d", rc);
    }
out:
    return true;
}

static int
on_handle_binding_iterator_finish_gdbus(Sxpd *object,
                                        GDBusMethodInvocation *invocation,
                                        struct sxpd_gdbus_hnd_ctx *ctx)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, object, invocation, ctx);
    RC_CHECK(rc, out);

    sxpd_complete_binding_iterator_finish(object, invocation);

out:
    return rc;
}

static int
on_handle_binding_iterator_finish_sxpd(struct sxpd_gdbus_hnd_ctx *ctx)
{
    int rc = 0;
    void *sxpd_iter = NULL;

    PARAM_NULL_CHECK(rc, ctx, ctx->gdbus_ctx);
    RC_CHECK(rc, out);

    if (ctx->iter_id >= SXPD_GDBUS_MAX_ITER_NUM) {
        ctx->gdbus_error = SXPD_GDBUS_ERROR_ITER;
        LOG_ERROR("iterator id is out of range");
        rc = -1;
        goto out;
    }

    if (ctx->binding_type == V4) {
        rc = sxpd_gdbus_iter_finish(ctx->gdbus_ctx->v4_iter, ctx->sender_id,
                                    ctx->iter_id, &sxpd_iter);
        if (RC_ISNOTOK(rc)) {
            ctx->gdbus_error = SXPD_GDBUS_ERROR_ITER;
            LOG_ERROR("Failed to finish V4 binding iterator: %d", rc);
            goto out;
        }
    } else if (ctx->binding_type == V6) {
        rc = sxpd_gdbus_iter_finish(ctx->gdbus_ctx->v6_iter, ctx->sender_id,
                                    ctx->iter_id, &sxpd_iter);
        if (RC_ISNOTOK(rc)) {
            ctx->gdbus_error = SXPD_GDBUS_ERROR_ITER;
            LOG_ERROR("Failed to finish V6 binding iterator: %d", rc);
            goto out;
        }
    } else {
        ctx->gdbus_error = SXPD_GDBUS_ERROR_INVALID_BINDING_TYPE;
        LOG_ERROR("binding type %d is invalid", ctx->binding_type);
        rc = -1;
        goto out;
    }

    if (NULL != sxpd_iter) {
        sxpd_iterate_bindings_finish(
            ctx->gdbus_ctx->sxpd_ctx,
            (struct sxpd_bindings_iterator *)sxpd_iter);
        sxpd_iter = NULL;
    }

out:
    return rc;
}

static gboolean on_handle_binding_iterator_finish(
    Sxpd *object, GDBusMethodInvocation *invocation, guint arg_type,
    guint arg_id, gpointer *user_data)
{
    int rc = 0;
    struct sxpd_gdbus_hnd_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));

    PARAM_NULL_CHECK(rc, user_data);
    RC_CHECK(rc, out);

    ctx.binding_type = arg_type;
    ctx.iter_id = arg_id;

    rc = sxpd_gdbus_schedule_handling(
        object, invocation, (struct sxpd_gdbus_ctx *)user_data,
        on_handle_binding_iterator_finish_sxpd,
        on_handle_binding_iterator_finish_gdbus, &ctx);
    if (RC_ISOK(rc)) {
        LOG_TRACE("handle binding-iterator-finish success");
    } else {
        LOG_ERROR("handle binding-iterator-finish failed: %d", rc);
    }
out:
    return true;
}

static int
on_handle_binding_iterator_new_gdbus(Sxpd *object,
                                     GDBusMethodInvocation *invocation,
                                     struct sxpd_gdbus_hnd_ctx *ctx)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, object, invocation, ctx);
    RC_CHECK(rc, out);

    sxpd_complete_binding_iterator_new(object, invocation,
                                       ctx->res_data.iter_id_res);

out:
    return rc;
}

static int on_handle_binding_iterator_new_sxpd(struct sxpd_gdbus_hnd_ctx *ctx)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, ctx, ctx->gdbus_ctx);
    RC_CHECK(rc, out);

    if (ctx->binding_type == V4) {
        rc = sxpd_gdbus_iter_new(ctx->gdbus_ctx->v4_iter, ctx->sender_id,
                                 &ctx->res_data.iter_id_res);
        if (RC_ISNOTOK(rc)) {
            ctx->gdbus_error = SXPD_GDBUS_ERROR_MAX_CLIENTS;
            LOG_ERROR("Failed to create new V4 binding iterator: %d", rc);
            goto out;
        }
    } else if (ctx->binding_type == V6) {
        rc = sxpd_gdbus_iter_new(ctx->gdbus_ctx->v6_iter, ctx->sender_id,
                                 &ctx->res_data.iter_id_res);
        if (RC_ISNOTOK(rc)) {
            ctx->gdbus_error = SXPD_GDBUS_ERROR_MAX_CLIENTS;
            LOG_ERROR("Failed to create new V6 binding iterator: %d", rc);
            goto out;
        }
    } else {
        ctx->gdbus_error = SXPD_GDBUS_ERROR_INVALID_BINDING_TYPE;
        LOG_ERROR("binding type %d is invalid", ctx->binding_type);
        rc = -1;
        goto out;
    }

out:
    return rc;
}

static gboolean
on_handle_binding_iterator_new(Sxpd *object, GDBusMethodInvocation *invocation,
                               guint arg_type, gpointer *user_data)
{
    int rc = 0;
    struct sxpd_gdbus_hnd_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));

    PARAM_NULL_CHECK(rc, user_data);
    RC_CHECK(rc, out);

    ctx.binding_type = arg_type;

    rc = sxpd_gdbus_schedule_handling(
        object, invocation, (struct sxpd_gdbus_ctx *)user_data,
        on_handle_binding_iterator_new_sxpd,
        on_handle_binding_iterator_new_gdbus, &ctx);
    if (RC_ISOK(rc)) {
        LOG_TRACE("handle binding-iterator-new success");
    } else {
        LOG_ERROR("handle binding-iterator-new failed: %d", rc);
    }
out:
    return true;
}

static int on_handle_peer_iterate_gdbus(Sxpd *object,
                                        GDBusMethodInvocation *invocation,
                                        struct sxpd_gdbus_hnd_ctx *ctx)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, object, invocation, ctx);
    RC_CHECK(rc, out);

    if (false == ctx->res_data.peer.iter_end) {
        sxpd_complete_peer_iterate(
            object, invocation, ctx->res_data.peer.p.nbo_ip,
            ctx->res_data.peer.p.nbo_port,
            ctx->res_data.peer.p.connections_count,
            ctx->res_data.peer.p.retry_timer_active,
            ctx->res_data.peer.p.delete_hold_down_timer_active,
            ctx->res_data.peer.p.reconciliation_timer_active,
            ctx->res_data.peer.p.keepalive_timer_active,
            ctx->res_data.peer.p.hold_timer_active);
    } else {
        sxpd_complete_peer_iterate(object, invocation, 0, 0, 0, 0, 0, 0, 0, 0);
    }

out:
    return rc;
}

static int on_handle_peer_iterate_sxpd(struct sxpd_gdbus_hnd_ctx *ctx)
{
    int rc = 0;
    struct sxpd_gdbus_iter *iter = NULL;

    PARAM_NULL_CHECK(rc, ctx, ctx->gdbus_ctx);
    RC_CHECK(rc, out);

    rc = sxpd_gdbus_iter_get(ctx->gdbus_ctx->peer_iter, ctx->sender_id,
                             ctx->iter_id, &iter);
    if (RC_ISNOTOK(rc)) {
        ctx->gdbus_error = SXPD_GDBUS_ERROR_ITER;
        LOG_ERROR("Failed to get peer iterator: %d", rc);
        goto out;
    }

    rc = sxpd_iterate_peers(ctx->gdbus_ctx->sxpd_ctx,
                            (struct sxpd_peer_iterator **)&iter->sxpd_iterator,
                            &ctx->res_data.peer.p);
    if (RC_ISNOTOK(rc)) {
        ctx->gdbus_error = SXPD_GDBUS_ERROR_INTERNAL;
        LOG_ERROR("peers iterate failed: %d", rc);
        goto out;
    }

    if (NULL != iter->sxpd_iterator) {
        ctx->res_data.peer.iter_end = false;
    } else {
        ctx->res_data.peer.iter_end = true;
    }

out:
    return rc;
}

static gboolean on_handle_peer_iterate(Sxpd *object,
                                       GDBusMethodInvocation *invocation,
                                       guint arg_id, gpointer *user_data)
{
    int rc = 0;
    struct sxpd_gdbus_hnd_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));

    PARAM_NULL_CHECK(rc, user_data);
    RC_CHECK(rc, out);

    ctx.iter_id = arg_id;

    rc = sxpd_gdbus_schedule_handling(
        object, invocation, (struct sxpd_gdbus_ctx *)user_data,
        on_handle_peer_iterate_sxpd, on_handle_peer_iterate_gdbus, &ctx);
    if (RC_ISOK(rc)) {
        LOG_TRACE("handle peer-iterator-finish success");
    } else {
        LOG_ERROR("handle peer-iterator-finish failed: %d", rc);
    }
out:
    return true;
}

static int
on_handle_peer_iterator_finish_gdbus(Sxpd *object,
                                     GDBusMethodInvocation *invocation,
                                     struct sxpd_gdbus_hnd_ctx *ctx)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, object, invocation, ctx);
    RC_CHECK(rc, out);

    sxpd_complete_peer_iterator_finish(object, invocation);

out:
    return rc;
}

static int on_handle_peer_iterator_finish_sxpd(struct sxpd_gdbus_hnd_ctx *ctx)
{
    int rc = 0;
    void *sxpd_iter = NULL;

    PARAM_NULL_CHECK(rc, ctx, ctx->gdbus_ctx);
    RC_CHECK(rc, out);

    rc = sxpd_gdbus_iter_finish(ctx->gdbus_ctx->peer_iter, ctx->sender_id,
                                ctx->iter_id, &sxpd_iter);
    if (RC_ISNOTOK(rc)) {
        ctx->gdbus_error = SXPD_GDBUS_ERROR_ITER;
        LOG_ERROR("Failed to finish peer iterator: %d", rc);
        goto out;
    }

    if (NULL != sxpd_iter) {
        sxpd_iterate_peers_finish(ctx->gdbus_ctx->sxpd_ctx,
                                  (struct sxpd_peer_iterator *)sxpd_iter);
        sxpd_iter = NULL;
    }

out:
    return rc;
}

static gboolean
on_handle_peer_iterator_finish(Sxpd *object, GDBusMethodInvocation *invocation,
                               guint arg_id, gpointer *user_data)
{
    int rc = 0;
    struct sxpd_gdbus_hnd_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));

    PARAM_NULL_CHECK(rc, user_data);
    RC_CHECK(rc, out);

    ctx.iter_id = arg_id;

    rc = sxpd_gdbus_schedule_handling(
        object, invocation, (struct sxpd_gdbus_ctx *)user_data,
        on_handle_peer_iterator_finish_sxpd,
        on_handle_peer_iterator_finish_gdbus, &ctx);
    if (RC_ISOK(rc)) {
        LOG_TRACE("handle peer-iterator-finish success");
    } else {
        LOG_ERROR("handle peer-iterator-finish failed: %d", rc);
    }
out:
    return true;
}

static int on_handle_peer_iterator_new_gdbus(Sxpd *object,
                                             GDBusMethodInvocation *invocation,
                                             struct sxpd_gdbus_hnd_ctx *ctx)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, object, invocation, ctx);
    RC_CHECK(rc, out);

    sxpd_complete_peer_iterator_new(object, invocation,
                                    ctx->res_data.iter_id_res);

out:
    return rc;
}

static int on_handle_peer_iterator_new_sxpd(struct sxpd_gdbus_hnd_ctx *ctx)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, ctx, ctx->gdbus_ctx);
    RC_CHECK(rc, out);

    rc = sxpd_gdbus_iter_new(ctx->gdbus_ctx->peer_iter, ctx->sender_id,
                             &ctx->res_data.iter_id_res);
    if (RC_ISNOTOK(rc)) {
        ctx->gdbus_error = SXPD_GDBUS_ERROR_MAX_CLIENTS;
        LOG_ERROR("Failed to create new peer iterator: %d", rc);
        goto out;
    }

out:
    return rc;
}

static gboolean on_handle_peer_iterator_new(Sxpd *object,
                                            GDBusMethodInvocation *invocation,
                                            gpointer *user_data)
{
    int rc = 0;
    struct sxpd_gdbus_hnd_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));

    PARAM_NULL_CHECK(rc, user_data);
    RC_CHECK(rc, out);

    rc = sxpd_gdbus_schedule_handling(object, invocation,
                                      (struct sxpd_gdbus_ctx *)user_data,
                                      on_handle_peer_iterator_new_sxpd,
                                      on_handle_peer_iterator_new_gdbus, &ctx);
    if (RC_ISOK(rc)) {
        LOG_TRACE("handle peer-iterator-new success");
    } else {
        LOG_ERROR("handle peer-iterator-new failed: %d", rc);
    }
out:
    return true;
}

static int on_handle_sxpd_info_gdbus(Sxpd *object,
                                     GDBusMethodInvocation *invocation,
                                     struct sxpd_gdbus_hnd_ctx *ctx)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, object, invocation, ctx);
    RC_CHECK(rc, out);

    sxpd_complete_sxpd_info(
        object, invocation, ctx->res_data.sxpd_info.sxpd_info.nbo_bind_ip,
        ctx->res_data.sxpd_info.sxpd_info.nbo_port,
        ctx->res_data.sxpd_info.default_password,
        ctx->res_data.sxpd_info.sxpd_info.peer_count,
        ctx->res_data.sxpd_info.sxpd_info.expanded_entry_count,
        ctx->res_data.sxpd_info.sxpd_info.enabled);

out:
    return rc;
}

static int on_handle_sxpd_info_sxpd(struct sxpd_gdbus_hnd_ctx *ctx)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, ctx, ctx->gdbus_ctx, ctx->gdbus_ctx->sxpd_ctx);
    RC_CHECK(rc, out);

    rc = sxpd_get_info(ctx->gdbus_ctx->sxpd_ctx,
                       &ctx->res_data.sxpd_info.sxpd_info);
    if (RC_ISNOTOK(rc)) {
        ctx->gdbus_error = SXPD_GDBUS_ERROR_MAX_CLIENTS;
        LOG_ERROR("Failed to create new peer iterator: %d", rc);
        goto out;
    }

    if (NULL == ctx->res_data.sxpd_info.sxpd_info.default_connection_password) {
        ctx->res_data.sxpd_info.default_password[0] = '\0';
    } else if (strnlen(ctx->res_data.sxpd_info.sxpd_info
                           .default_connection_password,
                       CFG_PASSWORD_MAX_SIZE) < CFG_PASSWORD_MAX_SIZE) {
        strncpy(ctx->res_data.sxpd_info.default_password,
                ctx->res_data.sxpd_info.sxpd_info.default_connection_password,
                CFG_PASSWORD_MAX_SIZE);
    } else {
        ctx->gdbus_error = SXPD_GDBUS_ERROR_INTERNAL;
        LOG_ERROR("Invalid sxpd default connection password");
        rc = -1;
        goto out;
    }

out:
    return rc;
}

static gboolean on_handle_sxpd_info(Sxpd *object,
                                    GDBusMethodInvocation *invocation,
                                    gpointer *user_data)
{
    int rc = 0;
    struct sxpd_gdbus_hnd_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));

    PARAM_NULL_CHECK(rc, user_data);
    RC_CHECK(rc, out);

    rc = sxpd_gdbus_schedule_handling(
        object, invocation, (struct sxpd_gdbus_ctx *)user_data,
        on_handle_sxpd_info_sxpd, on_handle_sxpd_info_gdbus, &ctx);
    if (RC_ISOK(rc)) {
        LOG_TRACE("handle sxpd-info success");
    } else {
        LOG_ERROR("handle sxpd-info failed: %d", rc);
    }
out:
    return true;
}

static void on_name_acquired(GDBusConnection *connection, const gchar *name,
                             gpointer user_data)
{
    int rc = 0;
    Sxpd *skeleton = NULL;
    gulong grc = 0;

    PARAM_NULL_CHECK(rc, connection, name, user_data);
    assert(RC_ISOK(rc));

    LOG_TRACE("gdbus name '%s' acquired", name);

    skeleton = sxpd_skeleton_new();

    grc = g_signal_connect(skeleton, "handle-sxpd-info",
                           G_CALLBACK(on_handle_sxpd_info), user_data);
    assert(grc > 0);

    grc = g_signal_connect(skeleton, "handle-binding-iterate",
                           G_CALLBACK(on_handle_binding_iterate), user_data);
    assert(grc > 0);

    grc = g_signal_connect(skeleton, "handle-binding-iterator-finish",
                           G_CALLBACK(on_handle_binding_iterator_finish),
                           user_data);
    assert(grc > 0);

    grc =
        g_signal_connect(skeleton, "handle-binding-iterator-new",
                         G_CALLBACK(on_handle_binding_iterator_new), user_data);
    assert(grc > 0);

    grc = g_signal_connect(skeleton, "handle-peer-iterate",
                           G_CALLBACK(on_handle_peer_iterate), user_data);
    assert(grc > 0);

    grc =
        g_signal_connect(skeleton, "handle-peer-iterator-finish",
                         G_CALLBACK(on_handle_peer_iterator_finish), user_data);
    assert(grc > 0);

    grc = g_signal_connect(skeleton, "handle-peer-iterator-new",
                           G_CALLBACK(on_handle_peer_iterator_new), user_data);
    assert(grc > 0);

    assert(g_dbus_interface_skeleton_export(
               G_DBUS_INTERFACE_SKELETON(skeleton), connection,
               SXPD_GDBUS_INTERFACE_PATH, NULL) == true);

    return;
}

static void on_bus_acquired(GDBusConnection *connection, const gchar *name,
                            gpointer user_data)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, connection, name, user_data);
    RC_CHECK(rc, out);

    LOG_TRACE("gdbus bus acquired");

out:
    return;
}

static void on_name_lost(GDBusConnection *connection, const gchar *name,
                         gpointer user_data)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, connection, name, user_data);
    RC_CHECK(rc, out);

    LOG_ERROR("gdbus connection name '%s' lost", name);

out:
    return;
}

static void on_user_data_destroy(gpointer user_data)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, user_data);
    RC_CHECK(rc, out);

    LOG_TRACE("gdbus user data destroy callback fires");

out:
    return;
}

static void *sxpd_gdbus_main_loop_thread(void *gdbus_ctx)
{
    struct sxpd_gdbus_ctx *ctx = NULL;

    assert(gdbus_ctx);
    ctx = gdbus_ctx;

    LOG_TRACE("gdbus interface main loop started");
    g_main_loop_run(ctx->loop);
    LOG_TRACE("gdbus interface main loop stopped");

    pthread_exit(NULL);
}

static int sxpd_gdbus_iter_clean_cb_sxpd(struct sxpd_gdbus_hnd_ctx *cb_ctx)
{
    int rc = 0;
    struct sxpd_ctx *sxpd_ctx = NULL;
    struct sxpd_gdbus_ctx *gdbus_ctx = NULL;
    size_t i = 0;
    struct sxpd_gdbus_iter *iter = NULL;
    void *sxpd_iter = NULL;

    PARAM_NULL_CHECK(rc, cb_ctx, cb_ctx->gdbus_ctx,
                     cb_ctx->gdbus_ctx->sxpd_ctx);
    RC_CHECK(rc, out);
    gdbus_ctx = cb_ctx->gdbus_ctx;
    sxpd_ctx = cb_ctx->gdbus_ctx->sxpd_ctx;

    for (i = 0; i < SXPD_GDBUS_MAX_ITER_NUM; ++i) {
        iter = &gdbus_ctx->peer_iter[i];
        if (true == sxpd_gdbus_iter_timeouted(iter)) {
            LOG_TRACE("gdbus interface peer iterator #%zu %p timeout %u sec", i,
                      (void *)iter, SXPD_GDBUS_ITER_TIMEOUT);

            rc = sxpd_gdbus_iter_finish(gdbus_ctx->peer_iter, NULL, i,
                                        &sxpd_iter);
            if (RC_ISNOTOK(rc)) {
                LOG_ERROR("failed to finish gdbus sxpd peer iterator: %p",
                          iter->sxpd_iterator);
                goto out;
            }

            if (NULL != sxpd_iter) {
                sxpd_iterate_peers_finish(
                    sxpd_ctx, (struct sxpd_peer_iterator *)sxpd_iter);
                sxpd_iter = NULL;
            }
        }

        iter = &gdbus_ctx->v4_iter[i];
        if (true == sxpd_gdbus_iter_timeouted(iter)) {
            LOG_TRACE(
                "gdbus interface v4 binding iterator #%zu %p timeout %u sec", i,
                (void *)iter, SXPD_GDBUS_ITER_TIMEOUT);

            rc =
                sxpd_gdbus_iter_finish(gdbus_ctx->v4_iter, NULL, i, &sxpd_iter);
            if (RC_ISNOTOK(rc)) {
                LOG_ERROR("failed to finish gdbus sxpd v4 binding iterator: %p",
                          iter->sxpd_iterator);
                goto out;
            }

            if (NULL != sxpd_iter) {
                sxpd_iterate_bindings_finish(
                    sxpd_ctx, (struct sxpd_bindings_iterator *)sxpd_iter);
                sxpd_iter = NULL;
            }
        }

        iter = &gdbus_ctx->v6_iter[i];
        if (true == sxpd_gdbus_iter_timeouted(iter)) {
            LOG_TRACE(
                "gdbus interface v6 binding iterator #%zu %p timeout %u sec", i,
                (void *)iter, SXPD_GDBUS_ITER_TIMEOUT);

            rc =
                sxpd_gdbus_iter_finish(gdbus_ctx->v6_iter, NULL, i, &sxpd_iter);
            if (RC_ISNOTOK(rc)) {
                LOG_ERROR("failed to finish gdbus sxpd v6 binding iterator: %p",
                          iter->sxpd_iterator);
                goto out;
            }

            if (NULL != sxpd_iter) {
                sxpd_iterate_bindings_finish(
                    sxpd_ctx, (struct sxpd_bindings_iterator *)sxpd_iter);
                sxpd_iter = NULL;
            }
        }
    }

out:
    return rc;
}

static gboolean sxpd_gdbus_iter_clean_cb(gpointer user_data)
{
    int rc = 0;
    struct sxpd_gdbus_ctx *ctx = NULL;
    struct sxpd_gdbus_hnd_ctx hnd;

    PARAM_NULL_CHECK(rc, user_data);
    assert(RC_ISOK(rc));

    ctx = (struct sxpd_gdbus_ctx *)user_data;
    memset(&hnd, 0, sizeof(hnd));

    rc = sxpd_gdbus_schedule_handling_sync(ctx, sxpd_gdbus_iter_clean_cb_sxpd,
                                           &hnd);
    if (RC_ISOK(rc)) {
        LOG_TRACE("handle 'iterator timeout cleaner' success");
    } else {
        LOG_ERROR("handle 'iterator timeout cleaner' failed: %d", rc);
        assert(0);
    }

    return TRUE;
}

int sxpd_gdbus_interface_init(struct sxpd_gdbus_ctx **gdbus_ctx,
                              struct sxpd_ctx *sxpd_ctx, struct evmgr *evmgr)
{
    int rc = 0;
    struct sxpd_gdbus_ctx *ctx = NULL;

    PARAM_NULL_CHECK(rc, gdbus_ctx, sxpd_ctx, evmgr);
    RC_CHECK(rc, out);

    rc = sxpd_gdbus_ctx_new(&ctx, sxpd_ctx, evmgr);
    if (RC_ISNOTOK(rc)) {
        LOG_ERROR("gdbus interface context create failed: %d", rc);
        goto out;
    }

    ctx->gdbus_identifier = g_bus_own_name(
        G_BUS_TYPE_SYSTEM, SXPD_GDBUS_OWN_NAME, G_BUS_NAME_OWNER_FLAGS_NONE,
        on_bus_acquired, on_name_acquired, on_name_lost, ctx,
        on_user_data_destroy);
    if (0 == ctx->gdbus_identifier) {
        LOG_ERROR("gdbus interface own dbus name '%s' failed",
                  SXPD_GDBUS_OWN_NAME);
        rc = -1;
        goto out;
    }

    rc = pthread_create(&ctx->thread, NULL, sxpd_gdbus_main_loop_thread, ctx);
    if (RC_ISNOTOK(rc)) {
        LOG_ERROR("gdbus interface main loop start failed: %d", rc);
        rc = -1;
        goto out;
    }

    /* schedule iterator cleaner function */
    ctx->timeout_identifier = g_timeout_add_seconds(
        SXPD_GDBUS_ITER_CLEAN_TIMEOUT, sxpd_gdbus_iter_clean_cb, ctx);
    if (0 == ctx->timeout_identifier) {
        LOG_ERROR("gdbus 'iterator timeout cleaner' callback add failed");
        rc = -1;
        goto out;
    }

out:
    if (RC_ISOK(rc)) {
        LOG_TRACE("gdbus interface initialization success");
        *gdbus_ctx = ctx;
    } else {
        if (NULL != gdbus_ctx) {
            *gdbus_ctx = NULL;
        }
        if (NULL != ctx) {
            sxpd_gdbus_ctx_destroy(ctx);
        }
    }

    return rc;
}

int sxpd_gdbus_interface_deinit(struct sxpd_gdbus_ctx *gdbus_ctx)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, gdbus_ctx);
    RC_CHECK(rc, out);

    if (0 != gdbus_ctx->gdbus_identifier) {
        g_bus_unown_name(gdbus_ctx->gdbus_identifier);
    }

    rc = sxpd_gdbus_interface_loop_quit(gdbus_ctx);
    if (RC_ISNOTOK(rc)) {
        LOG_ERROR("gdbus interface main loop quit call failed");
        goto out;
    }

    LOG_TRACE("waiting for gdbus interface main loop exit");

    rc = pthread_join(gdbus_ctx->thread, NULL);
    if (RC_ISNOTOK(rc)) {
        LOG_ERROR("gdbus interface main loop exit failed");
        goto out;
    }

    LOG_TRACE("gdbus interface main loop exit success");

    rc = sxpd_gdbus_ctx_destroy(gdbus_ctx);
    if (RC_ISNOTOK(rc)) {
        LOG_ERROR("failed to destroy gdbus interface context: %d", rc);
        goto out;
    }

out:
    return rc;
}
