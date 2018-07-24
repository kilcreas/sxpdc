/*------------------------------------------------------------------
 * Event manager API
 *
 * November 2014, Klement Sekera
 *
 * Copyright (c) 2014-2015 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------*/

#ifndef EVMGR_H
#define EVMGR_H

#ifdef EVMGR_H
/* avoid warning for unused guard macro */
#endif

#include <sys/time.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

/**
 * @defgroup evmgr Event manager
 * @htmlinclude event_manager.html
 * @addtogroup evmgr
 * @{
 */

/**
 * @brief implementation-specific event manager settings structure
 */
struct evmgr_settings;

/**
 * @brief implementation-specific event manager context
 */
struct evmgr;

/**
 * @brief implementation-specific event manager socket
 */
struct evmgr_socket;

/**
 * @brief implementation-specific event manager timer
 */
struct evmgr_timer;

/**
 * @brief implementation-specific event manager listener
 */
struct evmgr_listener;

/**
 * @brief implementation-specific event manager signal handler
 */
struct evmgr_sig_handler;

/**
 * @brief the maximum length of password used for TCP MD5 signing
 */
#define EVMGR_TCP_MD5_MAX_PWD_LEN (80)

/**
 * @brief mapping of address and password used for TCP MD5 signing,
 * if password_len == 0, it means there is no password for this address
 */
struct address_md5_pwd_pair {
    struct sockaddr_in sin;
    char password[EVMGR_TCP_MD5_MAX_PWD_LEN + 1];
    uint16_t password_len;
};

/**
 * @brief test if TCP md5 signing is available
 *
 * @return 0 on success, -1 on error
 */
int evmgr_md5sig_test(void);

/**
 * @brief create new event manager context
 * @param settings implementation-specific settings affecting timer creation
 *
 * @return event manager context or NULL if no memory
 */
struct evmgr *evmgr_create(struct evmgr_settings *settings);

/**
 * @brief free event manager context
 *
 * @param evmgr event manager context to free
 */
void evmgr_destroy(struct evmgr *evmgr);

/**
 * @brief enter dispatch loop - process events until evmgr_dispatch_break is
 * not called
 *
 * @param evmgr event manager context
 *
 * @return returns 0 if dispatch finished due to evmgr_dispatch_break or -1 if
 * error occurs
 */
int evmgr_dispatch(struct evmgr *evmgr);

/**
 * @brief break dispatch loop of event manager
 * @param evmgr event manager context
 *
 * @return 0 if success, -1 on error
 */
int evmgr_dispatch_break(struct evmgr *evmgr);

/**
 * @brief callback called when timer fires
 */
typedef void (*evmgr_timer_callback)(struct evmgr_timer *timer,
                                     void *callback_ctx);

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
struct evmgr_timer *evmgr_timer_create(struct evmgr *evmgr,
                                       struct evmgr_settings *settings,
                                       struct timeval *timeout, bool persist,
                                       evmgr_timer_callback callback,
                                       void *callback_ctx);

/**
 * @brief arm timer - start countdown
 *
 * @param timer timer to arm
 *
 * @return 0 if success, -1 on error
 */
int evmgr_timer_arm(struct evmgr_timer *timer);

/**
 * @brief disarm timer - stop countdown
 *
 * @param timer timer to disarm
 *
 * @return 0 if success, -1 on error
 */
int evmgr_timer_disarm(struct evmgr_timer *timer);

/**
 * @brief disassociate timer from event manager and free memory
 *
 * @param timer timer to destroy
 */
void evmgr_timer_destroy(struct evmgr_timer *timer);

/**
 * @brief callback called when signal is caught
 */
typedef void (*evmgr_signal_callback)(struct evmgr_sig_handler *sig_handler,
                                      int signum, void *callback_ctx);

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
struct evmgr_sig_handler *
evmgr_sig_handler_create(struct evmgr *evmgr, struct evmgr_settings *settings,
                         int signum, evmgr_signal_callback callback,
                         void *callback_ctx);

/**
 * @brief stop handling signal and free memory
 *
 * @param sig_handler signal handler context
 */
void evmgr_sig_handler_destroy(struct evmgr_sig_handler *sig_handler);

/**
 * @brief callback called when a new connection on listener has been accepted
 */
typedef void (*evmgr_accept_callback)(struct evmgr_listener *listener,
                                      struct evmgr_socket *socket,
                                      struct sockaddr_in *address,
                                      void *callback_ctx);

/**
 * @brief callback called when error occurs on listener
 */
typedef void (*evmgr_error_callback)(struct evmgr_listener *listener,
                                     void *callback_ctx);

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
                      evmgr_error_callback error_callback, void *callback_ctx);

/**
 * @brief set TCP md5 signature for specific client
 *
 * @param listener listener socket
 * @param default_pwd default connection password
 * @param pwd_pair password and client socket pair. if password length is 0
 *        default password connection password will be used
 *
 * @return 0 on success, -1 on error
 */
int evmgr_listener_md5_sig_add(struct evmgr_listener *listener,
                               const char *default_pwd,
                               struct address_md5_pwd_pair *pwd_pair);

/**
 * @brief remove TCP md5 signature for specific client
 *
 * @param listener listener socket
 * @param pwd_pair password and client socket pair
 *
 * @return 0 on success, -1 on error
 */
int evmgr_listener_md5_sig_del(struct evmgr_listener *listener,
                               struct address_md5_pwd_pair *pwd_pair);

/** event while reading */
#define EVMGR_SOCK_EVENT_READING 0x01
/** event while writing */
#define EVMGR_SOCK_EVENT_WRITING 0x02
/** end of file event */
#define EVMGR_SOCK_EVENT_EOF 0x10
/** error event */
#define EVMGR_SOCK_EVENT_ERROR 0x20
/** connection timeout event */
#define EVMGR_SOCK_EVENT_TIMEOUT 0x40
/** connection established event */
#define EVMGR_SOCK_EVENT_CONNECTED 0x80

/**
 * @brief destroy listener
 *
 * @param listener listener to destroy
 */
void evmgr_listener_destroy(struct evmgr_listener *listener);

/**
 * @brief callback called when event occurs on a socket
 */
typedef void (*socket_event_callback)(struct evmgr_socket *socket,
                                      int16_t event_bits, void *callback_ctx);

/**
 * @brief callback called when socket contains some data to be read
 */
typedef void (*socket_readable_callback)(struct evmgr_socket *socket,
                                         void *callback_ctx);

/**
 * @brief callback called when socket is able to accept more data
 */
typedef void (*socket_writeable_callback)(struct evmgr_socket *socket,
                                          void *callback_ctx);

/**
 * @brief create new socket (for connecting to address)
 *
 * @param evmgr event manager context
 * @param settings platform-sepcific settings affecting socket creation
 *
 * @return socket pointer or NULL if error
 */
struct evmgr_socket *evmgr_socket_create(struct evmgr *evmgr,
                                         struct evmgr_settings *settings);

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
                         void *callback_ctx);

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
                             void *callback_ctx);

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
                       size_t data_size);

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
                         size_t buffer_size);

/**
 * @brief destroy a socket
 *
 * @param socket socket to destroy
 */
void evmgr_socket_destroy(struct evmgr_socket *socket);

/** @} */

#endif
