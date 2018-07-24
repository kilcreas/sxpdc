#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#include <sys/wait.h>

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

DECL_DEBUG_V6_STATIC_BUFFER

struct topo_task_binding_chk_ctx {
    struct topo_task_binding_chk *bindings;
    size_t bindings_num;
    bool exact_match;
    bool unexpected_binding_found;
    bool preprocess_done;
    struct radix_tree *bindings_v4;
    struct radix_tree *bindings_v6;
};

struct topo_task_binding_chk {
    const char *prefix;
    struct binding binding;
    bool found;
};

#define TOPO_TASK_WAIT_FOR_BINDING(prefix_, prefix_length_, prefix_type_, \
                                   sgt_)                                  \
    {                                                                     \
        .prefix = prefix_, .binding =                                     \
                               {                                          \
                                 .type = prefix_type_,                    \
                                 .prefix.prefix_v4 = 0,                   \
                                 .prefix_length = prefix_length_,         \
                                 .source_group_tag = sgt_,                \
                               },                                         \
        .found = false,                                                   \
    }

#define TOPO_TASK_WAIT_FOR_BINDINGS(bindings_, bindings_num_, exact_match_) \
    {                                                                       \
        .bindings = bindings_, .bindings_num = bindings_num_,               \
        .exact_match = exact_match_, .unexpected_binding_found = false,     \
        .preprocess_done = false,                                           \
    }

struct topo_task_peer_chk_ctx {
    struct topo_task_peer_chk *peers;
    size_t peers_num;
    bool exact_match;
    bool unexpected_peer_found;
    bool preprocess_done;
};

struct topo_task_peer_chk {
    const char *ip;
    uint16_t port;
    struct sxpd_peer_info peer;
    bool found;
};

#define TOPO_TASK_WAIT_FOR_PEER(ip_, port_, conn_active_, is_speaker_, \
                                is_listener_)                          \
    {                                                                  \
        .ip = (const char *)ip_, .port = port_,                        \
        .peer =                                                        \
            {                                                          \
              .nbo_ip = 0,                                             \
              .nbo_port = 0,                                           \
              .connections_count =                                     \
                  (is_speaker_ + is_listener_) * conn_active_,         \
              .outgoing_connection_state = NONE,                       \
              .retry_timer_active = false,                             \
              .delete_hold_down_timer_active = false,                  \
              .reconciliation_timer_active = false,                    \
              .keepalive_timer_active = true,                          \
              .hold_timer_active = false,                              \
              .is_speaker = is_speaker_,                               \
              .is_listener = is_listener_,                             \
            },                                                         \
        .found = false,                                                \
    }

#define TOPO_TASK_WAIT_FOR_PEERS(peers_, peers_num_, exact_match_)             \
    {                                                                          \
        .peers = (struct topo_task_peer_chk *)peers_, .peers_num = peers_num_, \
        .exact_match = exact_match_, .unexpected_peer_found = false,           \
        .preprocess_done = false,                                              \
    }

static int topo_task_cb_wait_for_check_binding(struct topo_task *topo_task,
                                               struct binding *binding)
{
    int rc = 0;
    struct topo_task_binding_chk_ctx *bindings_ctx = NULL;
    struct topo_task_binding_chk *binding_tmp = NULL;
    struct radix_tree *radix = NULL;
    struct radix_node *radix_node = NULL;

    PARAM_NULL_CHECK(rc, topo_task, binding);
    RC_CHECK(rc, out);

    bindings_ctx =
        (struct topo_task_binding_chk_ctx *)topo_task->task.wait.wait_cb_ctx;

    if (PREFIX_IPV4 == binding->type) {
        radix = bindings_ctx->bindings_v4;
    } else {
        radix = bindings_ctx->bindings_v6;
    }

    rc = radix_search(radix, (uint8_t *)binding->prefix.prefix_v6,
                      binding->prefix_length, &radix_node);
    if (RC_ISNOTOK(rc)) {
        TOPO_TASK_ERROR(topo_task, "radix search failed: %d", rc);
        goto out;
    }

    if (!radix_node) {
        if (bindings_ctx->exact_match) {
            if (true == topo_task->task.wait.timeouted) {
                if (PREFIX_IPV4 == binding->type) {
                    TOPO_TASK_ERROR(topo_task,
                                    "unexpected V4 binding <%" PRIu16
                                    "," DEBUG_V4_FMT "/%" PRIu8 "> found",
                                    binding->source_group_tag,
                                    DEBUG_V4_PRINT(binding->prefix.prefix_v4),
                                    binding->prefix_length);
                } else {
                    TOPO_TASK_ERROR(topo_task,
                                    "unexpected V6 binding <%" PRIu16
                                    "," DEBUG_V6_FMT "/%" PRIu8 "> found",
                                    binding->source_group_tag,
                                    DEBUG_V6_PRINT(binding->prefix.prefix_v6),
                                    binding->prefix_length);
                }
            }
            bindings_ctx->unexpected_binding_found = true;
        }
        goto out;
    }

    rc = radix_parse_node(radix_node, NULL, 0, NULL, (void **)&binding_tmp);
    if (RC_ISNOTOK(rc)) {
        TOPO_TASK_ERROR(topo_task, "radix parse node failed: %d", rc);
        goto out;
    }

    if (binding_tmp->binding.source_group_tag != binding->source_group_tag) {
        if (bindings_ctx->exact_match) {
            if (true == topo_task->task.wait.timeouted) {
                if (PREFIX_IPV4 == binding->type) {
                    TOPO_TASK_ERROR(topo_task,
                                    "unexpected V4 binding <%" PRIu16
                                    "," DEBUG_V4_FMT "/%" PRIu8 "> found",
                                    binding->source_group_tag,
                                    DEBUG_V4_PRINT(binding->prefix.prefix_v4),
                                    binding->prefix_length);
                } else {
                    TOPO_TASK_ERROR(topo_task,
                                    "unexpected V6 binding <%" PRIu16
                                    "," DEBUG_V6_FMT "/%" PRIu8 "> found",
                                    binding->source_group_tag,
                                    DEBUG_V6_PRINT(binding->prefix.prefix_v6),
                                    binding->prefix_length);
                }
            }
            bindings_ctx->unexpected_binding_found = true;
        }
        goto out;
    }

    binding_tmp->found = true;

out:
    return rc;
}

static int topo_task_cb_wait_for_list_bindings(struct topo_task *topo_task,
                                               enum ip_type type)
{
    int rc = 0;
    struct sxpd_bindings_iterator *bindings_iterator = NULL;
    struct topo_task_binding_chk_ctx *bindings_ctx = NULL;
    struct sxpd_ctx *ctx = NULL;
    struct binding binding;
    memset(&binding, 0, sizeof(binding));
    binding.type = type;
    size_t i = 0;

    PARAM_NULL_CHECK(rc, topo_task, topo_task->topo_sxpd,
                     topo_task->topo_sxpd->sxpd_ctx);
    RC_CHECK(rc, out);

    bindings_ctx =
        (struct topo_task_binding_chk_ctx *)topo_task->task.wait.wait_cb_ctx;
    ctx = topo_task->topo_sxpd->sxpd_ctx;

    for (;;) {
        rc = sxpd_iterate_bindings(
            ctx, type, &bindings_iterator, (uint8_t *)binding.prefix.prefix_v6,
            sizeof(binding.prefix.prefix_v6), &binding.prefix_length,
            &binding.source_group_tag);
        RC_CHECK(rc, out);
        if (!bindings_iterator) {
            break;
        }

        rc = topo_task_cb_wait_for_check_binding(topo_task, &binding);
        RC_CHECK(rc, out);

        if (bindings_ctx->exact_match) {
            if (bindings_ctx->unexpected_binding_found &&
                !topo_task->task.wait.timeouted) {
                sxpd_iterate_bindings_finish(ctx, bindings_iterator);
                break;
            }
        }
        i++;
    }

out:
    return rc;
}

int topo_task_cb_wait_for_bindings(struct topo_task *topo_task)
{
    int rc = 0;
    struct topo_task_binding_chk_ctx *bindings_ctx = NULL;
    struct topo_task_binding_chk *bindings = NULL;
    struct topo_task_binding_chk *binding = NULL;
    size_t bindings_num = 0;
    size_t i = 0;
    bool bindings_missing = false;

    PARAM_NULL_CHECK(rc, topo_task);
    RC_CHECK(rc, out);

    bindings_ctx =
        (struct topo_task_binding_chk_ctx *)topo_task->task.wait.wait_cb_ctx;
    bindings_ctx->unexpected_binding_found = false;
    bindings = bindings_ctx->bindings;
    bindings_num = bindings_ctx->bindings_num;

    /* convert IPv4/6 strings to NBO */
    if (false == bindings_ctx->preprocess_done) {

        bindings_ctx->bindings_v4 = radix_create(32);
        if (!bindings_ctx->bindings_v4) {
            rc = -1;
            TOPO_TASK_ERROR(topo_task,
                            "Cannot allocate v4 bindings radix tree: %d", rc);
            goto out;
        }

        bindings_ctx->bindings_v6 = radix_create(128);
        if (!bindings_ctx->bindings_v6) {
            rc = -1;
            TOPO_TASK_ERROR(topo_task,
                            "Cannot allocate v6 bindings radix tree: %d", rc);
            goto out;
        }

        for (i = 0; i < bindings_num; ++i) {
            binding = &bindings[i];
            if (PREFIX_IPV4 == binding->binding.type) {
                if (inet_pton(AF_INET, binding->prefix,
                              &binding->binding.prefix.prefix_v4) != 1) {
                    TOPO_TASK_ERROR(
                        topo_task,
                        "binding V4 prefix string value <%s> is invalid",
                        binding->prefix);
                    rc = -1;
                    goto out;
                }

                rc = radix_store(bindings_ctx->bindings_v4,
                                 (uint8_t *)&binding->binding.prefix.prefix_v4,
                                 binding->binding.prefix_length, binding, NULL);
                if (RC_ISNOTOK(rc)) {
                    TOPO_TASK_ERROR(
                        topo_task,
                        "binding V4 prefix <%s> radix store failed: %d",
                        binding->prefix, rc);
                    goto out;
                }
            } else {
                if (inet_pton(AF_INET6, binding->prefix,
                              binding->binding.prefix.prefix_v6) != 1) {
                    TOPO_TASK_ERROR(
                        topo_task,
                        "binding V6 prefix string value <%s> is invalid",
                        binding->prefix);
                    rc = -1;
                    goto out;
                }

                rc = radix_store(bindings_ctx->bindings_v6,
                                 (uint8_t *)binding->binding.prefix.prefix_v6,
                                 binding->binding.prefix_length, binding, NULL);
                if (RC_ISNOTOK(rc)) {
                    TOPO_TASK_ERROR(
                        topo_task,
                        "binding V6 prefix <%s> radix store failed: %d",
                        binding->prefix, rc);
                    goto out;
                }
            }
            binding->found = false;
        }
        bindings_ctx->preprocess_done = true;
    } else {
        for (i = 0; i < bindings_num; ++i) {
            binding = &bindings[i];
            binding->found = false;
        }
    }

    /* list v4 bindings and find expected matching ones */
    rc = topo_task_cb_wait_for_list_bindings(topo_task, V4);
    RC_CHECK(rc, out);

    /* list v6 bindings and find expected matching ones */
    rc = topo_task_cb_wait_for_list_bindings(topo_task, V6);
    RC_CHECK(rc, out);

    for (i = 0; i < bindings_num; ++i) {
        binding = &bindings[i];
        if (false == binding->found) {
            if (true == topo_task->task.wait.timeouted) {
                TOPO_TASK_ERROR(topo_task, "Expected binding <%" PRIu16
                                           ",%s/%" PRIu8 "> not found",
                                binding->binding.source_group_tag,
                                binding->prefix,
                                binding->binding.prefix_length);
            }
            bindings_missing = true;
        }
    }

    if (bindings_missing == true) {
        goto out;
    }

    if (false == bindings_ctx->exact_match ||
        false == bindings_ctx->unexpected_binding_found) {
        topo_task->task.wait.wait_status = TOPO_TASK_WAIT_DONE;
    }

out:
    return rc;
}

static int topo_task_cb_wait_for_check_peer(struct topo_task *topo_task,
                                            struct sxpd_peer_info *peer,
                                            size_t peer_num)
{
    int rc = 0;
    size_t i = 0;
    struct topo_task_peer_chk_ctx *peers_ctx = NULL;
    struct topo_task_peer_chk *peers = NULL;
    struct topo_task_peer_chk *peer_tmp = NULL;
    size_t peers_num = 0;

    PARAM_NULL_CHECK(rc, topo_task, peer);
    RC_CHECK(rc, out);

    peers_ctx =
        (struct topo_task_peer_chk_ctx *)topo_task->task.wait.wait_cb_ctx;
    peers = peers_ctx->peers;
    peers_num = peers_ctx->peers_num;

    for (i = 0; i < peers_num; ++i) {
        peer_tmp = &peers[i];
        if (peer_tmp->peer.nbo_ip == peer->nbo_ip &&
            peer_tmp->peer.nbo_port == peer->nbo_port &&
            peer_tmp->peer.is_listener == peer->is_listener &&
            peer_tmp->peer.is_speaker == peer->is_speaker) {

            if (peer_tmp->peer.connections_count == peer->connections_count) {
                peer_tmp->found = true;
            }
            goto out;
        }
    }

    if (peers_ctx->exact_match) {
        if (true == topo_task->task.wait.timeouted) {
            TOPO_TASK_ERROR(
                topo_task, "Unexpected peer  #%zu <" DEBUG_V4_FMT ":%" PRIu16
                           "> with <%zu> connections is listener <%d> is "
                           "speaker <%d> found\n",
                peer_num, DEBUG_V4_PRINT(peer->nbo_ip), ntohs(peer->nbo_port),
                peer->connections_count, peer->is_listener, peer->is_speaker);
        }
        peers_ctx->unexpected_peer_found = true;
        goto out;
    }

out:
    return rc;
}

static int topo_task_cb_wait_for_list_peers(struct topo_task *topo_task)
{
    int rc = 0;
    struct sxpd_peer_iterator *peers_iterator = NULL;
    struct topo_task_peer_chk_ctx *peers_ctx = NULL;
    struct sxpd_ctx *ctx = NULL;
    struct sxpd_peer_info peer;
    memset(&peer, 0, sizeof(peer));
    size_t i = 0;

    PARAM_NULL_CHECK(rc, topo_task, topo_task->topo_sxpd,
                     topo_task->topo_sxpd->sxpd_ctx);
    RC_CHECK(rc, out);

    peers_ctx =
        (struct topo_task_peer_chk_ctx *)topo_task->task.wait.wait_cb_ctx;
    ctx = topo_task->topo_sxpd->sxpd_ctx;

    for (;;) {
        rc = sxpd_iterate_peers(ctx, &peers_iterator, &peer);
        RC_CHECK(rc, out);
        if (!peers_iterator) {
            break;
        }

        rc = topo_task_cb_wait_for_check_peer(topo_task, &peer, i);
        RC_CHECK(rc, out);

        if (peers_ctx->exact_match) {
            if (peers_ctx->unexpected_peer_found) {
                sxpd_iterate_peers_finish(ctx, peers_iterator);
                break;
            }
        }
        i++;
    }

out:
    return rc;
}

int topo_task_cb_wait_for_peers(struct topo_task *topo_task)
{
    int rc = 0;
    struct topo_task_peer_chk_ctx *peers_ctx = NULL;
    struct topo_task_peer_chk *peers = NULL;
    struct topo_task_peer_chk *peer = NULL;
    size_t peers_num = 0;
    size_t i = 0;

    PARAM_NULL_CHECK(rc, topo_task);
    RC_CHECK(rc, out);

    peers_ctx =
        (struct topo_task_peer_chk_ctx *)topo_task->task.wait.wait_cb_ctx;
    peers_ctx->unexpected_peer_found = false;
    peers = peers_ctx->peers;
    peers_num = peers_ctx->peers_num;

    /* convert peer string to NBO */
    if (false == peers_ctx->preprocess_done) {
        for (i = 0; i < peers_num; ++i) {
            peer = &peers[i];
            if (inet_pton(AF_INET, peer->ip, &peer->peer.nbo_ip) != 1) {
                TOPO_TASK_ERROR(
                    topo_task,
                    "peer #%zu V4 prefix string value <%s> is invalid", i,
                    peer->ip);
                rc = -1;
                goto out;
            }
            peer->peer.nbo_port = htons(peer->port);
            peer->found = false;
        }
        peers_ctx->preprocess_done = true;
    } else {
        for (i = 0; i < peers_num; ++i) {
            peer = &peers[i];
            peer->found = false;
        }
    }

    /* list peers and find expected matching ones */
    rc = topo_task_cb_wait_for_list_peers(topo_task);
    RC_CHECK(rc, out);

    for (i = 0; i < peers_num; ++i) {
        peer = &peers[i];
        if (false == peer->found) {
            if (true == topo_task->task.wait.timeouted) {
                TOPO_TASK_TRACE(topo_task, "Expected peer #%zu <" DEBUG_V4_FMT
                                           ":%" PRIu16 "> not found\n",
                                i, DEBUG_V4_PRINT(peer->peer.nbo_ip),
                                ntohs(peer->peer.nbo_port));
            }
            goto out;
        }
    }

    if (false == peers_ctx->exact_match ||
        false == peers_ctx->unexpected_peer_found) {
        topo_task->task.wait.wait_status = TOPO_TASK_WAIT_DONE;
    }
out:
    return rc;
}

#define TOPO_TASK_LOG_CHECK_SET_PATTERNS(pattern_, pattern_num_) \
    {                                                            \
        .pattern = pattern_, .pattern_num = pattern_num_,        \
    }

struct topo_task_log_check_set_patterns_ctx {
    struct log_pattern *pattern;
    size_t pattern_num;
};

int topo_task_log_check_set_patterns_cb(struct topo_task *topo_task)
{
    int rc = 0;
    struct topo_task_log_check_set_patterns_ctx *ctx =
        (struct topo_task_log_check_set_patterns_ctx *)
            topo_task->task.main_exec.cb_ctx;
    ;

    PARAM_NULL_CHECK(rc, topo_task, ctx, ctx->pattern);
    RC_CHECK(rc, out);

    rc = log_check_set_patterns(ctx->pattern, ctx->pattern_num);
    if (RC_ISOK(rc)) {
        TOPO_TASK_TRACE(topo_task, "set log check pattern success: %d", rc);
    } else {
        TOPO_TASK_ERROR(topo_task, "set log check pattern failed: %d", rc);
        goto out;
    }

out:
    return rc;
}

#define TOPO_TASK_FORK_CTX_INIT(topo_task_)                             \
    {                                                                   \
        .topo_task = topo_task_,                                        \
        .task_num = sizeof(topo_task_) / sizeof(*topo_task_), .pid = 0, \
    }

struct topo_task_fork_ctx {
    struct topo_task *topo_task;
    size_t task_num;
    pid_t pid;
};

int topo_task_wait_child_cb(struct topo_task *topo_task)
{
    int rc = 0;
    pid_t pid = 0;
    int status = 0;
    struct topo_task_fork_ctx *fork_ctx = NULL;

    PARAM_NULL_CHECK(rc, topo_task, topo_task->task.main_exec.cb_ctx);
    RC_CHECK(rc, out);

    fork_ctx = topo_task->task.main_exec.cb_ctx;

    /* send signal used to notify child to exit process */
    rc = kill(fork_ctx->pid, SIGUSR1);
    if (RC_ISNOTOK(rc)) {
        TOPO_TASK_ERROR(topo_task, "Send signal to child process %d failed: %d",
                        fork_ctx->pid, rc);
        goto out;
    }

    /* wait for child status change */
    do {
        pid = waitpid(fork_ctx->pid, &status, 0);
        if (pid < 0) {
            rc = -1;
            TOPO_TASK_ERROR(
                topo_task,
                "Wait for child process %d exit failed: %d errno: %d",
                fork_ctx->pid, rc, errno);
            goto out;
        }
    } while (!WIFEXITED(status));

    fork_ctx->pid = 0;

    /* check child return value */
    if (0 != WEXITSTATUS(status)) {
        rc = -1;
        TOPO_TASK_ERROR(topo_task,
                        "Forked process exit status is not success %d",
                        WEXITSTATUS(status));
        goto out;
    }

out:
    return rc;
}

void topo_task_kill_all_childs(void)
{
    signal(SIGQUIT, SIG_IGN);
    kill(-1 * getpid(), SIGQUIT);

    return;
}

static bool sig_usr1_called = false;

static void sig_usr1_cb(__attribute__((unused)) int sig)
{
    sig_usr1_called = true;
}

int topo_task_fork_cb(struct topo_task *topo_task)
{
    int rc = 0;
    struct topo_task_fork_ctx *fork_ctx = NULL;

    PARAM_NULL_CHECK(rc, topo_task, topo_task->task.main_exec.cb_ctx);
    RC_CHECK(rc, out);

    fork_ctx = topo_task->task.main_exec.cb_ctx;

    if (0 != fork_ctx->pid) {
        rc = -1;
        TOPO_TASK_ERROR(topo_task,
                        "fork process context already in use by child: %d", rc);
        goto out;
    }

    fork_ctx->pid = fork();
    if (0 == fork_ctx->pid) {
        /* register signal used to notify child to exit process */
        signal(SIGUSR1, sig_usr1_cb);

        log_check_ctx_reinit();

        /* let child process do tasks */
        rc = topo_run(fork_ctx->topo_task, fork_ctx->task_num);
        if (RC_ISNOTOK(rc)) {
            TOPO_TASK_ERROR(topo_task, "Forked process tasks failed: %d", rc);
        }

        /* wait for signal from parent */
        if (false == sig_usr1_called) {
            pause();
        }

        exit(rc);
    } else if (-1 == fork_ctx->pid) {
        rc = -1;
        TOPO_TASK_ERROR(topo_task, "Fork process failed: %d", rc);
        goto out;
    }

out:
    return rc;
}

int topo_task_log_check_run_cb(struct topo_task *topo_task)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, topo_task);
    RC_CHECK(rc, out);

    rc = log_check_run();
    if (RC_ISOK(rc)) {
        TOPO_TASK_TRACE(topo_task, "log check run success: %d", rc);
    } else {
        TOPO_TASK_ERROR(topo_task, "log check run failed: %d", rc);
        goto out;
    }

out:
    return rc;
}

int topo_task_exit_cb(struct topo_task *topo_task)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, topo_task);
    RC_CHECK(rc, out);

    exit(0);

out:
    return rc;
}

int topo_task_sleep_cb(struct topo_task *topo_task)
{
    int rc = 0;
    int *sleep_time = NULL;
    PARAM_NULL_CHECK(rc, topo_task, topo_task->task.main_exec.cb_ctx);
    RC_CHECK(rc, out);

    sleep_time = (int *)topo_task->task.main_exec.cb_ctx;

    TOPO_TASK_TRACE(topo_task, "sleeping for %d seconds", *sleep_time);
    sleep(*sleep_time);
    TOPO_TASK_TRACE(topo_task, "sleeping for %d seconds done", *sleep_time);

out:
    return rc;
}
