/*------------------------------------------------------------------
 * Event manager implementation - linux code
 *
 * November 2014, Klement Sekera
 *
 * Copyright (c) 2014-2015 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------*/

#include <linux/tcp.h>
#include <unistd.h>
#include <inttypes.h>
#include <limits.h>
#include <sys/uio.h>

#include <event2/event.h>
#include <event2/listener.h>

#if defined(ENABLE_GDBUS_INTERFACE) || defined(TESTING)
#include <event2/event-config.h>
#include <event2/thread.h>
#endif

#include "debug.h"
#include "util.h"
#include "mem.h"
#include "evmgr.h"

#define EVMGR_TRACE_BYTES (1)

#define MAX_BUFFER_COUNT (16)

#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-parameter"

static struct timeval write_timeout = { 60, 0 };

struct evmgr_buffer {
    size_t data_size;
    size_t offset;
    struct evmgr_buffer *next;
    char data[1]; /* buffer is always allocated to contain data of data_size */
};

/**
 * event manager settings structure
 */
struct evmgr_settings {
    bool unused;
};

/**
 * event manager context
 */
struct evmgr {
    struct event_base *base;
    bool stop_flag;
};

/**
 * @brief event manager socket
 */
struct evmgr_socket {
    struct evmgr *evmgr;
    struct event *read_event;
    struct event *write_event;
    struct event *event_event;
    int16_t event_flags;
    evutil_socket_t fd;
    socket_readable_callback read_callback;
    socket_writeable_callback write_callback;
    socket_event_callback event_callback;
    void *callback_ctx;
    size_t pending_bytes;
    size_t buffer_count;
    struct evmgr_buffer *first;
    struct evmgr_buffer *last;
    bool connected;
};

/**
 * @brief event manager timer
 */
struct evmgr_timer {
    struct event *event;
    struct timeval timeout;
    evmgr_timer_callback callback;
    void *callback_ctx;
};

/**
 * @brief event manager listener
 */
struct evmgr_listener {
    struct evmgr *evmgr;
    struct evmgr_socket *socket;
    evmgr_accept_callback accept_callback;
    evmgr_error_callback error_callback;
    void *callback_ctx;
    struct evconnlistener *listener;
};

/**
 * @brief event manager signal handler
 */
struct evmgr_sig_handler {
    struct event *event;
    evmgr_signal_callback callback;
    void *callback_ctx;
};

/**
 * @brief create new event manager context
 *
 * @return event manager context or NULL if no memory
 */
struct evmgr *
evmgr_create(__attribute__((unused)) struct evmgr_settings *settings)
{
#if defined(ENABLE_GDBUS_INTERFACE) || defined(TESTING)
    int rc = 0;
    rc = evthread_use_pthreads();
    assert(RC_ISOK(rc));
#endif

    struct evmgr *e = mem_calloc(1, sizeof(*e));

    if (e) {
        e->base = event_base_new();
        if (e->base) {
            if (-1 == event_base_priority_init(e->base, 2)) {
                LOG_ERROR("Cannot init event priorities");
                event_base_free(e->base);
                e->base = NULL;
            }
        }
        if (!e->base) {
            mem_free(e);
            e = NULL;
        }
    }

    return e;
}

/**
 * @brief free event manager context
 *
 * @param evmgr event manager context to free
 */
void evmgr_destroy(struct evmgr *evmgr)
{
    if (evmgr) {
        event_base_free(evmgr->base);
        mem_free(evmgr);
    }
}

/**
 * @brief enter dispatch loop - process events until evmgr_dispatch_break is
 * not called
 *
 * @param evmgr event manager context
 *
 * @return returns 0 if dispatch finished due to evmgr_dispatch_break or -1 if
 * error occurs
 */
int evmgr_dispatch(struct evmgr *evmgr)
{
    int rc = 0;
    if (!evmgr) {
        LOG_ERROR("Invalid NULL event manager context");
        rc = -1;
    } else if (!evmgr->base) {
        LOG_ERROR("Event base is NULL");
        rc = -1;
    } else {
        evmgr->stop_flag = false;
        while (!evmgr->stop_flag) {
            if ((-1) == event_base_loop(evmgr->base, 0)) {
                rc = -1;
                break;
            }
        }
    }

    return rc;
}

/**
 * @brief break dispatch loop of event manager
 *
 * @param evmgr event manager context
 */
int evmgr_dispatch_break(struct evmgr *evmgr)
{
    int rc = -1;

    if (evmgr) {
        evmgr->stop_flag = true;
        rc = event_base_loopbreak(evmgr->base);
    }

    return rc;
}

static void evmgr_timer_callback_wrapper(__attribute__((unused))
                                         evutil_socket_t sock,
                                         __attribute__((unused)) short flags,
                                         void *ctx)
{
    struct evmgr_timer *t = ctx;

    if (t) {
        LOG_TRACE("Fire %p timer", (void *)t);
        t->callback(t, t->callback_ctx);
    }
}

/**
 * @brief create a new timer and associate it with evmgr context
 *
 * @param evmgr event manager context to associate the event with
 * @param settings platform-sepcific settings affecting timer creation
 * @param timeout pointer to timeval structure
 * @param persist if false, then the timer will fire only once (but can be
 * re-armed), otherwise it persists
 * @param callback callback called when event triggers
 * @param callback_ctx context passed to callback
 *
 * @return pointer to event context or NULL if error (memory, unsupported, etc.)
 */
struct evmgr_timer *
evmgr_timer_create(struct evmgr *evmgr,
                   __attribute__((unused)) struct evmgr_settings *settings,
                   struct timeval *timeout, bool persist,
                   evmgr_timer_callback callback, void *callback_ctx)
{
    struct evmgr_timer *t = NULL;

    /* NULL checks first */
    if (evmgr && timeout && callback) {
        t = mem_calloc(1, sizeof(*t));
    }

    /* create event */
    if (t) {
        short what = EV_TIMEOUT;
        if (persist) {
            what |= EV_PERSIST;
        }

        t->event =
            event_new(evmgr->base, 0, what, evmgr_timer_callback_wrapper, t);
        if (!t->event) {
            mem_free(t);
            t = NULL;
        } else {
            t->callback = callback;
            t->callback_ctx = callback_ctx;
            t->timeout = *timeout;
            LOG_TRACE("Create %p timer[%ld, %ld]", (void *)t,
                      (long)t->timeout.tv_sec, (long)t->timeout.tv_usec);
        }
    }

    return t;
}

/**
 * @brief arm timer - start countdown
 *
 * @param timer timer to arm
 *
 * @return 0 if success, -1 on error
 */
int evmgr_timer_arm(struct evmgr_timer *timer)
{
    int rc = 0;

    if (!timer) {
        rc = -1;
    }

    if (!rc) {
        LOG_TRACE("Arm %p timer[%ld, %ld]", (void *)timer,
                  (long)timer->timeout.tv_sec, (long)timer->timeout.tv_usec);
        if (timer->timeout.tv_sec || timer->timeout.tv_usec) {
            rc = event_add(timer->event, &timer->timeout);
        } else {
            event_active(timer->event, 0, 0);
        }
    }

    return rc;
}

/**
 * @brief disarm timer - stop countdown
 *
 * @param timer timer to disarm
 *
 * @return 0 if success, -1 on error
 */
int evmgr_timer_disarm(struct evmgr_timer *timer)
{
    int rc = 0;

    if (!timer) {
        rc = -1;
    }

    if (!rc) {
        LOG_TRACE("Disarm %p timer[%ld, %ld]", (void *)timer,
                  (long)timer->timeout.tv_sec, (long)timer->timeout.tv_usec);
        rc = event_del(timer->event);
    }

    return rc;
}

/**
 * @brief disassociate timer from event manager and free memory
 *
 * @param timer timer to destroy
 */
void evmgr_timer_destroy(struct evmgr_timer *timer)
{
    if (timer) {
        LOG_TRACE("Destroy %p timer[%ld, %ld]", (void *)timer,
                  (long)timer->timeout.tv_sec, (long)timer->timeout.tv_usec);
        event_free(timer->event);
        mem_free(timer);
    }
}

static void evmgr_signal_callback_wrapper(evutil_socket_t fd,
                                          __attribute__((unused)) short what,
                                          void *arg)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, arg);
    struct evmgr_sig_handler *sh = arg;
    if (RC_ISOK(rc)) {
        sh->callback(sh, fd, sh->callback_ctx);
    } else {
        LOG_ERROR("Signal handler called with NULL arg");
    }
}

/**
 * @brief create a signal handler
 *
 * @param evmgr event manager context
 * @param settings platform-sepcific settings affecting handler creation
 * @param signum signal to handle
 * @param callback function to call when signal is caught
 * @param callback_ctx context passed to callback function
 *
 * @return signal handler context or NULL if error occurred
 */
struct evmgr_sig_handler *evmgr_sig_handler_create(
    struct evmgr *evmgr,
    __attribute__((unused)) struct evmgr_settings *settings, int signum,
    evmgr_signal_callback callback, void *callback_ctx)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, evmgr, callback);
    struct evmgr_sig_handler *sh = NULL;
    RC_CHECK(rc, out);
    sh = mem_calloc(1, sizeof(*sh));
    if (!sh) {
        LOG_ERROR("Cannot allocate memory for signal handler");
        goto out;
    }

    sh->callback = callback;
    sh->callback_ctx = callback_ctx;
    sh->event = event_new(evmgr->base, signum, EV_SIGNAL | EV_PERSIST,
                          evmgr_signal_callback_wrapper, sh);
    if (!sh->event) {
        LOG_ERROR("Cannot create event for signal handler");
        evmgr_sig_handler_destroy(sh);
        sh = NULL;
        goto out;
    }

    rc = event_add(sh->event, NULL);
    if (rc) {
        LOG_ERROR("Cannot add event for signal handler");
        evmgr_sig_handler_destroy(sh);
        sh = NULL;
    }
out:
    return sh;
}

/**
 * @brief stop handling signal and free memory
 *
 * @param sig_handler signal handler context
 */
void evmgr_sig_handler_destroy(struct evmgr_sig_handler *sig_handler)
{
    if (sig_handler) {
        event_free(sig_handler->event);
        mem_free(sig_handler);
    }
}

static int evmgr_socket_md5_sig_set(int sock, struct sockaddr_in *sa,
                                    const void *key, uint16_t key_len)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, sa);
    if ((NULL == key) && (0 != key_len)) {
        rc = -1;
    }
    RC_CHECK(rc, out);

    struct tcp_md5sig md5sig;
    /* sanity check password - buffer sizes, length, NULL */
    if (key_len > EVMGR_TCP_MD5_MAX_PWD_LEN) {
        LOG_ERROR("Key length %" PRIu16 " exceeds max key length %zu", key_len,
                  (size_t)EVMGR_TCP_MD5_MAX_PWD_LEN);
        rc = -1;
        goto out;
    }

    if (key_len > TCP_MD5SIG_MAXKEYLEN) {
        LOG_ERROR("Key length %" PRIu16 " exceeds max key length %zu", key_len,
                  (size_t)TCP_MD5SIG_MAXKEYLEN);
        rc = -1;
        goto out;
    } else if (key_len > sizeof(md5sig.tcpm_key)) {
        LOG_ERROR("Key length %" PRIu16 " exceeds native buffer limit %zu",
                  key_len, sizeof(md5sig.tcpm_key));
        rc = -1;
        goto out;
    }

    /* sanity check struct sizes */
    if (sizeof(*sa) > sizeof(md5sig.tcpm_addr)) {
        LOG_ERROR("Size of native address is smaller then size of "
                  "address!");
        rc = -1;
        goto out;
    }

    memset(&md5sig, 0, sizeof(struct tcp_md5sig));
    md5sig.tcpm_keylen = key_len;
    if (key_len) {
        memcpy(md5sig.tcpm_key, key, key_len);
    }
    md5sig.tcpm_addr.ss_family = AF_INET;
    memcpy(&md5sig.tcpm_addr, sa, sizeof(*sa));
    /* set the IP-key combo for the socket */
    if ((-1) ==
        setsockopt(sock, IPPROTO_TCP, TCP_MD5SIG, &md5sig, sizeof(md5sig))) {
        LOG_ERROR("Failed to set TCP-MD5-SIGN socket option, errno=%d:%s",
                  errno, strerror(errno));
        rc = -1;
        goto out;
    } else {
        LOG_TRACE("Set TCP-MD5-SIGN <%s> for fd %d", (char *)key, sock);
    }
out:
    return rc;
}

static void evmgr_event_wrapper(__attribute__((unused)) evutil_socket_t s,
                                __attribute__((unused)) short flags, void *ctx)
{
    int rc = 0;
    struct evmgr_socket *socket = ctx;
    PARAM_NULL_CHECK(rc, ctx);
    RC_CHECK(rc, out);
    if (socket->event_callback) {
        LOG_DEBUG("Trigger event on socket %p, fd %d", (void *)socket,
                  socket->fd);
        socket->event_callback(socket, socket->event_flags,
                               socket->callback_ctx);
    } else {
        LOG_ERROR("Missed event with flags %" PRId16
                  " due to missing event callback on socket %p, fd %d",
                  socket->event_flags, (void *)socket, socket->fd);
    }
out:
    ;
}

static void evmgr_listener_accept_callback_wrapper(
    __attribute__((unused)) struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *addr, int len, void *ctx)
{
    int rc = 0;
    struct evmgr_socket *s = NULL;

    PARAM_NULL_CHECK(rc, ctx);
    RC_CHECK(rc, out);
    LOG_DEBUG("Incoming connection fd %d on listener %p", fd, ctx);
    if ((len < 0) || (len != sizeof(struct sockaddr_in))) {
        LOG_ERROR("Size of sockaddr arg (%d) does not match size of "
                  "sockaddr_in(%zu)",
                  len, sizeof(struct sockaddr_in));
        rc = -1;
        goto out;
    }
    if (AF_INET != addr->sa_family) {
        LOG_ERROR("Unsupported family %d", addr->sa_family);
        rc = -1;
        goto out;
    }

    struct evmgr_listener *l = ctx;
    s = mem_calloc(1, sizeof(*s));
    if (s) {
        s->event_event =
            event_new(l->evmgr->base, 0, 0, evmgr_event_wrapper, s);
        if (!s->event_event) {
            LOG_ERROR("Cannot create event event");
            rc = -1;
            goto out;
        } else {
            if (-1 == event_add(s->event_event, NULL)) {
                LOG_ERROR("Cannot add event for event reporting");
                rc = -1;
                goto out;
            }
            if (-1 == event_priority_set(s->event_event, 0)) {
                LOG_ERROR("Cannot set priority for event event");
                rc = -1;
                goto out;
            }
        }
        s->fd = fd;
        s->connected = true;
        s->evmgr = l->evmgr;
        LOG_TRACE("New connection socket %p, fd %d", (void *)s, s->fd);
        l->accept_callback(l, s, (struct sockaddr_in *)(void *)addr,
                           l->callback_ctx);
    } else {
        LOG_ERROR("Cannot allocate evmgr_socket");
        rc = -1;
    }
out:
    if (RC_ISNOTOK(rc)) {
        evmgr_socket_destroy(s);
    }
}

static void evmgr_listener_error_callback_wrapper(
    __attribute__((unused)) struct evconnlistener *listener, void *ctx)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, ctx);
    RC_CHECK(rc, out);
    struct evmgr_listener *l = ctx;
    l->error_callback(l, l->callback_ctx);
out:
    ;
}

int evmgr_md5sig_test(void)
{
    int rc = 0;
    int fd = 0;

    struct address_md5_pwd_pair pwd_pair;
    const char *test_password = "testing password";

    memset(&pwd_pair, 0, sizeof(pwd_pair));
    pwd_pair.sin.sin_family = AF_INET;
    pwd_pair.sin.sin_port = htons(9000);
    pwd_pair.sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    strncpy(pwd_pair.password, test_password, EVMGR_TCP_MD5_MAX_PWD_LEN);
    pwd_pair.password_len =
        (uint16_t)strnlen(test_password, EVMGR_TCP_MD5_MAX_PWD_LEN);

    /* create non-blocking socket */
    fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if ((-1) == fd) {
        LOG_ERROR("Failed to create socket, errno=%d:%s", errno,
                  strerror(errno));
        rc = -1;
    }

    /* try to enable md5 signing on TCP socket */
    if (RC_ISOK(rc)) {
        rc = evmgr_socket_md5_sig_set(fd, &pwd_pair.sin, pwd_pair.password,
                                      pwd_pair.password_len);
        if (RC_ISNOTOK(rc)) {
            LOG_ERROR("Cannot set TCP-MD5-SIGN option for fd %d", fd);
        } else {
            LOG_TRACE("Successfully set TCP-MD5-SIGN option for fd %d", fd);
        }
    }

    /* close socket */
    if ((-1) != fd) {
        int rc_close = close(fd);
        while (RC_ISNOTOK(rc_close) && (EINTR == errno)) {
            rc_close = close(fd);
        }

        if (RC_ISNOTOK(rc_close)) {
            LOG_ERROR("Cannot close fd %d, errno=%d:%s", fd, errno,
                      strerror(errno));
            rc = -1;
        }
    }

    return rc;
}

int evmgr_listener_md5_sig_add(struct evmgr_listener *listener,
                               const char *default_pwd,
                               struct address_md5_pwd_pair *pwd_pair)
{

    int rc = 0;
    const char *pwd = NULL;
    uint16_t pwd_len = 0;

    PARAM_NULL_CHECK(rc, listener, listener->socket, default_pwd, pwd_pair);

    if (RC_ISOK(rc)) {
        if (0 != pwd_pair->password_len) {
            pwd = pwd_pair->password;
            pwd_len = pwd_pair->password_len;
        } else {
            pwd = default_pwd;
            pwd_len = (uint16_t)strnlen(default_pwd, EVMGR_TCP_MD5_MAX_PWD_LEN);
        }

        if (pwd_len != 0) {
            rc = evmgr_socket_md5_sig_set(listener->socket->fd, &pwd_pair->sin,
                                          pwd, pwd_len);
            if (RC_ISNOTOK(rc)) {
                LOG_ERROR("Cannot add TCP-MD5-SIGN option for listener socket "
                          "%p, fd %d",
                          (void *)listener->socket, listener->socket->fd);
            } else {
                LOG_TRACE(
                    "Added TCP-MD5-SIGN option for listener socket %p, fd %d",
                    (void *)listener->socket, listener->socket->fd);
            }
        }
    }

    return rc;
}

int evmgr_listener_md5_sig_del(struct evmgr_listener *listener,
                               struct address_md5_pwd_pair *pwd_pair)
{

    int rc = 0;

    PARAM_NULL_CHECK(rc, listener, listener->socket, pwd_pair);

    if (RC_ISOK(rc)) {

        rc = evmgr_socket_md5_sig_set(listener->socket->fd, &pwd_pair->sin,
                                      NULL, 0);
        if (RC_ISNOTOK(rc)) {
            LOG_ERROR("Cannot remove TCP-MD5-SIGN option for listener socket "
                      "%p, fd %d",
                      (void *)listener->socket, listener->socket->fd);
        } else {
            LOG_TRACE(
                "Removed TCP-MD5-SIGN option for listener socket %p, fd %d",
                (void *)listener->socket, listener->socket->fd);
        }
    }

    return rc;
}

/**
 * @brief create socket and listen for incoming TCP connections, calling
 * specified callback once a connection is accepted
 *
 * @param evmgr event manager context to associate listener with
 * @param settings platform-sepcific settings affecting listener creation
 * @param address address to listen on
 * @param accept_callback function invoked when connection is accepted
 * @param error_callback function invoked when error occurs
 * @param callback_ctx context pointer passed to the callback function
 *
 * @return listener object or NULL if error
 */
struct evmgr_listener *
evmgr_listener_create(struct evmgr *evmgr, struct evmgr_settings *settings,
                      const struct sockaddr_in *address,
                      evmgr_accept_callback accept_callback,
                      evmgr_error_callback error_callback, void *callback_ctx)
{
    int rc = 0;
    struct evmgr_listener *l = NULL;

    PARAM_NULL_CHECK(rc, evmgr, address, accept_callback, error_callback);
    RC_CHECK(rc, out);
    struct evmgr_socket *socket = NULL;
    socket = evmgr_socket_create(evmgr, settings);
    if (!socket) {
        rc = -1;
        goto out;
    }

    int optval = 1;
    if (0 != (rc = setsockopt(socket->fd, SOL_SOCKET, SO_REUSEADDR, &optval,
                              sizeof(optval)))) {
        LOG_DEBUG("Setting SO_REUSEADDR failed - ignoring");
        rc = 0;
    }

    if (bind(socket->fd, (struct sockaddr *)address, sizeof(*address))) {
        LOG_ERROR("Failed to bind socket %p, fd %d to " DEBUG_SIN_FMT
                  ", errno=%d:%s",
                  (void *)socket, socket->fd, DEBUG_SIN_PRINT(*address), errno,
                  strerror(errno));
        rc = -1;
        goto out;
    }

    l = mem_calloc(1, sizeof(*l));
    if (!l) {
        LOG_ERROR("Cannot allocate memory for evmgr listener");
        evmgr_socket_destroy(socket);
        rc = -1;
        goto out;
    }

    struct evconnlistener *el = NULL;
    l->evmgr = evmgr;
    l->socket = socket;
    l->accept_callback = accept_callback;
    l->error_callback = error_callback;
    l->callback_ctx = callback_ctx;
    LOG_DEBUG("Create evconnlistener for socket %p, fd %d", (void *)socket,
              socket->fd);
    el = evconnlistener_new(evmgr->base, evmgr_listener_accept_callback_wrapper,
                            l, LEV_OPT_REUSEABLE, -1, socket->fd);
    if (!el) {
        LOG_ERROR("Failed to create evconnlistener");
        rc = -1;
        goto out;
    }

    l->listener = el;
    evconnlistener_set_error_cb(el, evmgr_listener_error_callback_wrapper);

out:
    if (RC_ISOK(rc)) {
        LOG_DEBUG("Created listener %p for socket %p, fd %d, " DEBUG_SIN_FMT,
                  (void *)l, (void *)l->socket, l->socket->fd,
                  DEBUG_SIN_PRINT(*address));
    } else {
        evmgr_listener_destroy(l);
        l = NULL;
    }
    return l;
}

/**
 * @brief destroy listener
 *
 * @param listener listener to destroy
 */
void evmgr_listener_destroy(struct evmgr_listener *listener)
{
    if (listener) {
        LOG_DEBUG("Destroy listener %p for socket %p, fd %d", (void *)listener,
                  (void *)listener->socket, listener->socket->fd);
        evconnlistener_free(listener->listener);
        listener->listener = NULL;
        evmgr_socket_destroy(listener->socket);
        mem_free(listener);
    }
}

/**
 * @brief create new socket (for connecting to address)
 *
 * @param evmgr event manager context
 * @param settings platform-sepcific settings affecting socket creation
 *
 * @return socket pointer or NULL if error
 */
struct evmgr_socket *
evmgr_socket_create(struct evmgr *evmgr,
                    __attribute__((unused)) struct evmgr_settings *settings)
{
    int rc = 0;
    struct evmgr_socket *s = NULL;
    PARAM_NULL_CHECK(rc, evmgr);
    RC_CHECK(rc, out);
    int fd = 0;
    /* create non-blocking socket */
    fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if ((-1) == fd) {
        LOG_ERROR("Failed to create socket");
        goto out;
    }

    s = mem_calloc(1, sizeof(*s));
    if (s) {
        s->event_event = event_new(evmgr->base, 0, 0, evmgr_event_wrapper, s);
        if (!s->event_event) {
            LOG_ERROR("Cannot create event event");
            rc = -1;
            goto out;
        } else {
            if (-1 == event_add(s->event_event, NULL)) {
                LOG_ERROR("Cannot add event for event reporting");
                rc = -1;
                goto out;
            }
            if (-1 == event_priority_set(s->event_event, 0)) {
                LOG_ERROR("Cannot set priority for event event");
                rc = -1;
                goto out;
            }
        }
        s->connected = false;
        s->fd = fd;
        s->evmgr = evmgr;
        LOG_DEBUG("Create socket %p, fd %d", (void *)s, fd);
    } else {
        LOG_ERROR("Failed to allocate evmgr_socket");
        rc = -1;
        goto out;
    }
out:
    if (RC_ISNOTOK(rc)) {
        evmgr_socket_destroy(s);
        s = NULL;
    }
    return s;
}

static void evmgr_socket_report_event(struct evmgr_socket *s,
                                      int16_t event_bits)
{
    if (!s) {
        LOG_ERROR("Internal error, report event with NULL socket");
        return;
    }
    s->event_flags = event_bits;
    event_active(s->event_event, 0, 0);
}

static void evmgr_read_wrapper(__attribute__((unused)) evutil_socket_t socket,
                               __attribute__((unused)) short flags, void *ctx)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, ctx);
    if (RC_ISOK(rc)) {
        struct evmgr_socket *s = ctx;
        LOG_DEBUG("Socket %p, fd %d is readable", (void *)s, s->fd);
        s->read_callback(s, s->callback_ctx);
    }
}

static void evmgr_write_wrapper(__attribute__((unused)) evutil_socket_t socket,
                                short flags, void *ctx)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, ctx);
    RC_CHECK(rc, out);
    struct iovec vec[MAX_BUFFER_COUNT];
    struct evmgr_socket *s = ctx;
    LOG_DEBUG("Socket %p, fd %d is writable", (void *)s, s->fd);
    if (flags & EV_TIMEOUT) {
        LOG_DEBUG("Timeout flag is set on socket %p, fd %d", (void *)s, s->fd);
        evmgr_socket_report_event(s, EVMGR_SOCK_EVENT_TIMEOUT |
                                         EVMGR_SOCK_EVENT_WRITING);
        goto out;
    }
    if (!s->buffer_count) {
        /* no data pending, invoke write callback, if any */
        if (s->write_callback) {
            s->write_callback(s, s->callback_ctx);
        } else if (s->write_event &&
                   event_pending(s->write_event, EV_WRITE, NULL)) {
            /* no data and no callback - disable write event */
            LOG_TRACE("Disable write event on socket %p, fd %d", (void *)s,
                      s->fd);
            rc = event_del(s->write_event);
            if (RC_ISNOTOK(rc)) {
                LOG_ERROR("Cannot disable write event on socket %p, fd %d",
                          (void *)s, s->fd);
                evmgr_socket_report_event(s, EVMGR_SOCK_EVENT_ERROR |
                                                 EVMGR_SOCK_EVENT_WRITING);
            }
        }
        return;
    }
    memset(&vec, 0, sizeof(vec));
    int i = 0;
    struct evmgr_buffer *buff = s->first;
    while (buff && i < MAX_BUFFER_COUNT) {
        vec[i].iov_base = buff->data + buff->offset;
        vec[i].iov_len = buff->data_size - buff->offset;
        ++i;
        buff = buff->next;
    }
    ssize_t bytes_written = writev(s->fd, vec, i);
    while (-1 == bytes_written && EINTR == errno) {
        bytes_written = writev(s->fd, vec, i);
    }
    if (-1 == bytes_written) {
        LOG_ERROR("Write to socket %p, fd %d failed, rc=%d:%s", ctx, s->fd,
                  errno, strerror(errno));
        evmgr_socket_report_event(s, EVMGR_SOCK_EVENT_ERROR |
                                         EVMGR_SOCK_EVENT_WRITING);
        goto out;
    }
    LOG_TRACE("Wrote %zd bytes to socket %p, fd %d", bytes_written, (void *)s,
              s->fd);
    s->pending_bytes -= (size_t)bytes_written;
    buff = s->first;
    while (bytes_written) {
        if (buff->data_size - buff->offset <= (size_t)bytes_written) {
            /* this buffer is completely drained */
            struct evmgr_buffer *tmp = buff;
#if EVMGR_TRACE_BYTES
            LOG_TRACE("--- Data chunk dump start (%zu bytes) ---",
                      buff->data_size - buff->offset);
            LOG_TRACE_BYTES(buff->data + buff->offset,
                            buff->data_size - buff->offset);
            LOG_TRACE("--- Data chunk dump end (%zu bytes) ---",
                      buff->data_size - buff->offset);
#endif
            bytes_written -= (buff->data_size - buff->offset);
            buff = buff->next;
            mem_free(tmp);
            --s->buffer_count;
        } else {
            /* partially drained - move offset */
            LOG_TRACE("Wrote data chunk to socket %p, fd %d", (void *)s, s->fd);
            LOG_TRACE_BYTES(buff->data + buff->offset, bytes_written);
            buff->offset += (size_t)bytes_written;
            break;
        }
    }
    s->first = buff;
    if (!s->first) {
        s->last = NULL;
    }

out:
    ;
}

static int evmgr_socket_create_events(struct evmgr_socket *socket)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, socket);
    RC_CHECK(rc, out);
    if (!socket->read_callback && socket->read_event) {
        LOG_TRACE("Destroy read event from socket %p, fd %d", (void *)socket,
                  socket->fd);
        rc = event_del(socket->read_event);
        if (RC_ISNOTOK(rc)) {
            LOG_ERROR("event_del() failed for socket %p, fd %d", (void *)socket,
                      socket->fd);
            goto out;
        }
        event_free(socket->read_event);
        socket->read_event = NULL;
    }

    if (socket->read_callback && !socket->read_event && socket->connected) {
        LOG_TRACE("Create read event for socket %p, fd %d", (void *)socket,
                  socket->fd);
        socket->read_event =
            event_new(socket->evmgr->base, socket->fd,
                      EV_READ | EV_PERSIST | EV_ET, evmgr_read_wrapper, socket);
        if (!socket->read_event) {
            LOG_ERROR("Cannot create read event for socket %p, fd %d",
                      (void *)socket, socket->fd);
            rc = -1;
            goto out;
        }
        rc = event_add(socket->read_event, NULL);
        if (RC_ISNOTOK(rc)) {
            LOG_ERROR("Cannot add event for socket %p, fd %d", (void *)socket,
                      socket->fd);
            rc = -1;
            goto out;
        }
    }
    if ((socket->write_callback || socket->buffer_count) &&
        !socket->write_event && socket->connected) {
        LOG_TRACE("Create write event for socket %p, fd %d", (void *)socket,
                  socket->fd);
        socket->write_event = event_new(socket->evmgr->base, socket->fd,
                                        EV_WRITE | EV_PERSIST | EV_TIMEOUT,
                                        evmgr_write_wrapper, socket);
        if (!socket->write_event) {
            LOG_ERROR("Cannot create write event for socket %p, fd %d",
                      (void *)socket, socket->fd);
            rc = -1;
            goto out;
        }
        rc = event_add(socket->write_event, &write_timeout);
        if (RC_ISNOTOK(rc)) {
            LOG_ERROR("Cannot add event for socket %p, fd %d", (void *)socket,
                      socket->fd);
            rc = -1;
            goto out;
        }
    }
    if (socket->write_event &&
        !event_pending(socket->write_event, EV_WRITE, NULL) &&
        (socket->write_event || socket->buffer_count)) {
        LOG_TRACE("Enable write event for socket %p, fd %d", (void *)socket,
                  socket->fd);
        rc = event_add(socket->write_event, &write_timeout);
        if (RC_ISNOTOK(rc)) {
            LOG_ERROR("Cannot add write event for socket %p, fd %d",
                      (void *)socket, socket->fd);
        }
    }
out:
    return rc;
}

static void evmgr_connected_wrapper(__attribute__((unused)) evutil_socket_t s,
                                    short flags, void *ctx)
{
    int rc = 0;
    struct evmgr_socket *socket = ctx;
    PARAM_NULL_CHECK(rc, ctx);
    RC_CHECK(rc, out);
    LOG_DEBUG("Socket %p, fd %d is writable(connected?)", (void *)socket,
              socket->fd);
    event_free(socket->write_event);
    socket->write_event = NULL;
    if (flags & EV_TIMEOUT) {
        LOG_DEBUG("Timeout flag is set on socket %p, fd %d", (void *)socket,
                  socket->fd);
        evmgr_socket_report_event(socket, EVMGR_SOCK_EVENT_CONNECTED |
                                              EVMGR_SOCK_EVENT_TIMEOUT);
        goto out;
    }
    socket->connected = true;
    rc = evmgr_socket_create_events(socket);
    RC_CHECK(rc, out);
    evmgr_socket_report_event(socket, EVMGR_SOCK_EVENT_CONNECTED);
out:
    if (RC_ISNOTOK(rc)) {
        evmgr_socket_report_event(socket, EVMGR_SOCK_EVENT_CONNECTED |
                                              EVMGR_SOCK_EVENT_ERROR);
    }
}

/**
 * @brief start connecting socket to given address
 *
 * @param socket socket to connect
 * @param src_address address to connect from (may be NULL)
 * @param dst_address address to connect to (optionally containing MD5 key)
 * @param read_callback callback invoked when data are ready to be read
 * @param write_callback callback invoked when socket writable
 * @param event_callback callback invoked if some event occurs (e.g. EOF)
 * @param callback_ctx context passed to callback functions
 *
 * @return 0 on success, -1 otherwise
 */
int evmgr_socket_connect(struct evmgr_socket *socket,
                         struct sockaddr_in *src_address,
                         struct address_md5_pwd_pair *dst_address,
                         socket_readable_callback read_callback,
                         socket_writeable_callback write_callback,
                         socket_event_callback event_callback,
                         void *callback_ctx)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, socket, dst_address, event_callback);
    RC_CHECK(rc, out);
    if (socket->connected) {
        LOG_ERROR("Socket %p, fd %d is already connected", (void *)socket,
                  socket->fd);
        rc = -1;
        goto out;
    }
    if (src_address) {
        rc = bind(socket->fd, (struct sockaddr *)src_address,
                  sizeof(*src_address));
        if (rc) {
            LOG_ERROR("Cannot bind socket %p, fd %d to " DEBUG_SIN_FMT
                      ", errno=%d:%s",
                      (void *)socket, socket->fd, DEBUG_SIN_PRINT(*src_address),
                      errno, strerror(errno));
            rc = -1;
            goto out;
        } else {
            LOG_TRACE("Bound socket %p, fd %d to " DEBUG_SIN_FMT,
                      (void *)socket, socket->fd,
                      DEBUG_SIN_PRINT(*src_address));
        }
    }

    socket->read_callback = read_callback;
    socket->write_callback = write_callback;
    socket->event_callback = event_callback;
    socket->callback_ctx = callback_ctx;

    if (dst_address->password_len) {
        rc = evmgr_socket_md5_sig_set(socket->fd, &dst_address->sin,
                                      dst_address->password,
                                      dst_address->password_len);
        RC_CHECK(rc, out);
    }

    rc = connect(socket->fd, (struct sockaddr *)&dst_address->sin,
                 sizeof(dst_address->sin));
    if (rc) {
        if (EINPROGRESS == errno || EINTR == errno) {
            rc = 0;
        } else {
            LOG_ERROR("Cannot connect socket %p, fd %d, rc=%d:%s",
                      (void *)socket, socket->fd, errno, strerror(errno));
            rc = -1;
            goto out;
        }
    }

    LOG_TRACE("Connect socket %p, fd %d to " DEBUG_SIN_FMT, (void *)socket,
              socket->fd, DEBUG_SIN_PRINT(dst_address->sin));
    if (write_callback) {
        socket->write_event = event_new(socket->evmgr->base, socket->fd,
                                        EV_WRITE | EV_PERSIST | EV_TIMEOUT,
                                        evmgr_connected_wrapper, socket);
        if (!socket->write_event) {
            LOG_ERROR("Cannot create write event for socket %p, fd %d",
                      (void *)socket, socket->fd);
            rc = -1;
            goto out;
        }
        rc = event_add(socket->write_event, &write_timeout);
        if (RC_ISNOTOK(rc)) {
            LOG_ERROR("Cannot add event for socket %p, fd %d", (void *)socket,
                      socket->fd);
            rc = -1;
            goto out;
        }
    }
out:
    return rc;
}

/**
 * @brief register socket for reading/writing or clear registration (if all
 * callbacks NULL)
 *
 * @param socket socket to register
 * @param read_callback callback called once data are ready to be read
 * @param write_callback callback called if data can be written
 * @param event_callback callback called if an event occurs (such as EOF)
 * @param callback_ctx context passed to callback functions
 *
 * @return 0 on success, -1 otherwise
 */
int evmgr_socket_cb_register(struct evmgr_socket *socket,
                             socket_readable_callback read_callback,
                             socket_writeable_callback write_callback,
                             socket_event_callback event_callback,
                             void *callback_ctx)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, socket);
    RC_CHECK(rc, out);
    LOG_TRACE("setting callbacks for socket %p, fd %d, read[%s], "
              "write[%s], event[%s]",
              (void *)socket, socket->fd, read_callback ? "*" : "",
              write_callback ? "*" : "", event_callback ? "*" : "");

    socket->read_callback = read_callback;
    socket->write_callback = write_callback;
    socket->event_callback = event_callback;
    socket->callback_ctx = callback_ctx;
    rc = evmgr_socket_create_events(socket);
out:
    return rc;
}

/**
 * @brief write data to socket
 *
 * @param socket target socket
 * @param data data to be written
 * @param data_size size of the data
 *
 * @return 0 on success, -1 otherwise
 */
int evmgr_socket_write(struct evmgr_socket *socket, const void *data,
                       size_t data_size)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, socket, data);
    RC_CHECK(rc, out);

    if (socket->pending_bytes + data_size > SSIZE_MAX) {
        LOG_ERROR("Cannot write more data to socket, currently stored bytes "
                  "%zu plus new bytes %zu would exceed SSIZE_MAX(%zu)",
                  socket->pending_bytes, data_size, SSIZE_MAX);
        rc = -1;
        goto out;
    }

    if (socket->buffer_count >= MAX_BUFFER_COUNT) {
        LOG_ERROR("Cannot write more data to socket, buffer count is already "
                  "at max %zu",
                  socket->buffer_count);
        rc = -1;
        goto out;
    }

    struct evmgr_buffer *buff =
        mem_malloc(sizeof(struct evmgr_buffer) + data_size);
    if (!buff) {
        LOG_ERROR("Cannot allocate data buffer");
        rc = -1;
        goto out;
    }

    memcpy(&buff->data, data, data_size);
    buff->data_size = data_size;
    buff->offset = 0;
    buff->next = NULL;

    if (!socket->first) {
        socket->first = buff;
    } else {
        socket->last->next = buff;
    }
    socket->last = buff;
    ++socket->buffer_count;
    socket->pending_bytes += data_size;
    LOG_TRACE("Enqueued buffer for writing to socket containing %zu bytes (%zu "
              "bytes total pending)",
              data_size, socket->pending_bytes);
    rc = evmgr_socket_create_events(socket);
out:
    return rc;
}

/**
 * @brief read data from socket
 *
 * @param socket source socket
 * @param buffer buffer for storing the data
 * @param buffer_size size of the buffer
 *
 * @return actual size read from socket
 */
size_t evmgr_socket_read(struct evmgr_socket *socket, void *buffer,
                         size_t buffer_size)
{
    int rc = 0;
    ssize_t bytes_read = 0;

    PARAM_NULL_CHECK(rc, socket, buffer);
    RC_CHECK(rc, out);
    bytes_read = read(socket->fd, buffer, buffer_size);
    while (-1 == bytes_read && EINTR == errno) {
        bytes_read = read(socket->fd, buffer, buffer_size);
    }
    if (0 == bytes_read) {
        /* EOF */
        evmgr_socket_report_event(socket, EVMGR_SOCK_EVENT_READING |
                                              EVMGR_SOCK_EVENT_EOF);
    } else if (-1 == bytes_read) {
        bytes_read = 0;
        if (EAGAIN != errno) {
            LOG_ERROR("Read from socket %p, fd %d failed rc=%d:%s",
                      (void *)socket, socket->fd, errno, strerror(errno));
            evmgr_socket_report_event(socket, EVMGR_SOCK_EVENT_READING |
                                                  EVMGR_SOCK_EVENT_ERROR);
        }
    } else {
        LOG_TRACE("Read %zu bytes from socket %p, fd %d", bytes_read,
                  (void *)socket, socket->fd);
#if EVMGR_TRACE_BYTES
        LOG_TRACE_BYTES(buffer, bytes_read);
#endif
    }
out:
    return (size_t)bytes_read;
}

/**
 * @brief destroy a socket
 *
 * @param socket socket to destroy
 */
void evmgr_socket_destroy(struct evmgr_socket *socket)
{
    if (socket) {
        LOG_DEBUG("Destroy socket %p, fd %d", (void *)socket, socket->fd);
        if (socket->event_event) {
            if (event_del(socket->event_event)) {
                LOG_ERROR("event_del() failed for socket %p, fd %d",
                          (void *)socket, socket->fd);
            }
            event_free(socket->event_event);
        }
        if (socket->read_event) {
            if (event_del(socket->read_event)) {
                LOG_ERROR("event_del() failed for socket %p, fd %d",
                          (void *)socket, socket->fd);
            }
            event_free(socket->read_event);
        }
        if (socket->write_event) {
            if (event_del(socket->write_event)) {
                LOG_ERROR("event_del() failed for socket %p, fd %d",
                          (void *)socket, socket->fd);
            }
            event_free(socket->write_event);
        }

        int rc = close(socket->fd);
        while (RC_ISNOTOK(rc) && (EINTR == errno)) {
            rc = close(socket->fd);
        }

        if (RC_ISNOTOK(rc)) {
            LOG_ERROR("Cannot close fd %d, errno=%d:%s", socket->fd, errno,
                      strerror(errno));
        }
        struct evmgr_buffer *previous = socket->first;
        struct evmgr_buffer *next = NULL;
        while (previous) {
            next = previous->next;
            mem_free(previous);
            previous = next;
        }
        mem_free(socket);
    }
}
