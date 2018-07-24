#include <stdio.h>
#include <signal.h>
#include <arpa/inet.h>
#include "debug.h"
#include "sxp.h"

#define PORT (9000)

static bool test_passed = false;

static const char *str = "hello, world!";
static struct evmgr_socket *c = NULL;

static void read_callback(struct evmgr_socket *socket, void *ctx)
{
    LOG_DEBUG("read_callback called socket=%p", (void *)socket);
    char buffer[4096] = { 0 };
    size_t read = evmgr_socket_read(socket, buffer, sizeof(buffer));
    LOG_DEBUG("read %zu bytes from socket: %s", read, buffer);
    if (read) {
        if (!strcmp(buffer, str)) {
            LOG_DEBUG("strings match!");
            test_passed = true;
        } else {
            LOG_ERROR("strings don't match!");
        }

        evmgr_dispatch_break(ctx);
    }
}

static void write_callback(struct evmgr_socket *socket,
                           __attribute__((unused)) void *ctx)
{
    static int cnt = 1;

    LOG_DEBUG("write_callback called socket=%p", (void *)socket);
    if (cnt) {
        int rc = evmgr_socket_write(socket, str, strlen(str));
        if (!rc) {
            LOG_DEBUG("wrote to socket %p: %s", (void *)socket, str);
        } else {
            LOG_ERROR("write to socket %p failed!", (void *)socket);
        }
    }

    --cnt;
}

static void event_callback(struct evmgr_socket *socket, int16_t events,
                           void *ctx)
{
    LOG_DEBUG("event_callback called socket=%p", (void *)socket);
    bool stop = true;
    if (events & EVMGR_SOCK_EVENT_EOF) {
        LOG_DEBUG("EOF is set");
    }

    if (events & EVMGR_SOCK_EVENT_READING) {
        LOG_DEBUG("READING is set");
    }

    if (events & EVMGR_SOCK_EVENT_WRITING) {
        LOG_DEBUG("WRITING is set");
    }

    if (events & EVMGR_SOCK_EVENT_ERROR) {
        LOG_DEBUG("ERROR is set");
    }

    if (events & EVMGR_SOCK_EVENT_CONNECTED) {
        LOG_DEBUG("CONNECTED is set");
        evmgr_socket_cb_register(socket, read_callback, write_callback,
                                 event_callback, ctx);
        stop = false;
    }

    if (events & EVMGR_SOCK_EVENT_TIMEOUT) {
        LOG_DEBUG("TIMEOUT is set");
    }

    if (stop) {
        evmgr_dispatch_break(ctx);
    }
}

static void accept_callback(struct evmgr_listener *listener,
                            struct evmgr_socket *socket,
                            struct sockaddr_in *address, void *ctx)
{
    LOG_DEBUG("accept_callback called listener=%p, socket=%p, addr=%p, ctx=%p",
              (void *)listener, (void *)socket, (void *)address, (void *)ctx);
    c = socket;
    evmgr_socket_cb_register(socket, read_callback, write_callback,
                             event_callback, ctx);
}

static void error_callback(struct evmgr_listener *listener, void *ctx)
{
    LOG_DEBUG("error_callback called listener=%p, ctx=%p", (void *)listener,
              (void *)ctx);
    evmgr_dispatch_break(ctx);
}

static void connect_callback(struct evmgr_socket *socket, int16_t events,
                             void *ctx)
{
    LOG_DEBUG("connect_callback called socket=%p, bits=0x%x!", (void *)socket,
              events);
    bool stop = true;
    if (events & EVMGR_SOCK_EVENT_EOF) {
        LOG_DEBUG("EOF is set");
    }

    if (events & EVMGR_SOCK_EVENT_READING) {
        LOG_DEBUG("READING is set");
    }

    if (events & EVMGR_SOCK_EVENT_WRITING) {
        LOG_DEBUG("WRITING is set");
    }

    if (events & EVMGR_SOCK_EVENT_ERROR) {
        LOG_DEBUG("ERROR is set");
    }

    if (events & EVMGR_SOCK_EVENT_CONNECTED) {
        LOG_DEBUG("CONNECTED is set");
        evmgr_socket_cb_register(socket, read_callback, write_callback,
                                 event_callback, ctx);
        stop = false;
    }

    if (events & EVMGR_SOCK_EVENT_TIMEOUT) {
        LOG_DEBUG("TIMEOUT is set");
    }

    if (stop) {
        evmgr_dispatch_break(ctx);
    }
}

int main(void)
{
    struct evmgr *evmgr = evmgr_create(NULL);
    if (NULL == evmgr) {
        LOG_ERROR("cannot initialize event manager!");
        return -1;
    }

    struct sockaddr_in in;
    memset(&in, 0, sizeof(in));
    in.sin_family = AF_INET;
    in.sin_port = htons(PORT);
    in.sin_addr.s_addr = htonl(INADDR_ANY);
    inet_pton(AF_INET, "127.0.0.2", &in.sin_addr);
    struct evmgr_listener *l = evmgr_listener_create(
        evmgr, NULL, &in, accept_callback, error_callback, &evmgr);
    if (!l) {
        LOG_ERROR("emvgr_listener_create failed!");
        return -1;
    }

    struct evmgr_socket *s = evmgr_socket_create(evmgr, NULL);
    if (!s) {
        LOG_ERROR("evmgr_socket_create failed!");
        return -1;
    }

    struct address_md5_pwd_pair am5;
    memset(&am5, 0, sizeof(am5));
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(PORT);
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    inet_pton(AF_INET, "127.0.0.2", &sin.sin_addr);

    am5.sin = sin;
    if (evmgr_socket_connect(s, NULL, &am5, read_callback, write_callback,
                             connect_callback, evmgr)) {
        LOG_ERROR("evmgr_socket_connect failed!");
        return -1;
    }

    if (evmgr_dispatch(evmgr)) {
        LOG_ERROR("evmgr dispatch failed!");
        return -1;
    }

    evmgr_socket_destroy(s);
    evmgr_socket_destroy(c);
    evmgr_listener_destroy(l);
    evmgr_destroy(evmgr);

    if (test_passed) {
        LOG_DEBUG("test passed!");
        return 0;
    } else {
        LOG_ERROR("test failed!");
        return -1;
    }
}
