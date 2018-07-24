/*------------------------------------------------------------------
 * @file
 * SXP daemon API
 *
 * November 2014, Klement Sekera
 *
 * Copyright (c) 2014-2015 by cisco Systems, Inc.
 * All rights reserved.
 *
 *------------------------------------------------------------------*/
#ifndef SXPD_H
#define SXPD_H

#ifndef SXPD_H
/* avoid unused macro warning */
#endif

#include <stdint.h>
#include <stddef.h>
#include <config.h>
#include <logging.h>

struct sxpd_ctx;

/*! @mainpage SXP Documentation
 *
 * @details SXPD is source group tag exchange protocol daemon which is
 * responsible for keeping track and distributing SGT-IP bindings.\n
 *
 * <hr/>
 * @section content Table of content
 *  - @ref maingoal
 *  - @ref maindesign
 *  - @ref mainstructure
 *   - @ref mainpdm
 *    - @ref mainevm
 *    - @ref mainmem
 *    - @ref maincfgm
 *    - @ref maintmst
 *    - @ref mainrng
 *    - @ref mainlogging
 *    - @ref maindbus
 *    - @ref mainsxpdmain
 *   - @ref mainpim
 *    - @ref mainsxpd
 *    - @ref mainsxp
 *    - @ref mainradix
 *  - @ref mainsystemflow
 *   - @ref mainevents
 *   - @ref maininitialization
 *    - @ref maininitialization
 *    - @ref mainretrytimer
 *    - @ref mainkeepalivetimer
 *    - @ref mainholdtimer
 *    - @ref mainreconciliationtimer
 *    - @ref maindeleteholddowntimer
 *   - @ref mainconfigurationevents
 *    - @ref mainparameterchanges
 *    - @ref mainpeerchange
 *    - @ref mainbindingchange
 *   - @ref mainsocketevents
 *    - @ref mainnewconnection
 *    - @ref mainwrite
 *    - @ref mainread
 *    - @ref mainerror
 *   - @ref mainsignals
 *  - @ref maindatastructures
 *   - @ref mainsxpctx
 *   - @ref mainpeerctx
 *
 * <hr/>
 *
 * @section maingoal 1 Problem definition
 * @details Goal is to implement SXP daemon in C. Daemon is responsible for
 * keeping track and distribution of IP-SGT bindings.
 *
 * @section maindesign 2 Design considerations
 * @details The implementation runs under Linux with easy portability to other
 * operating systems. Due to this, code is separated into platform-dependent and
 * platform-independent code with the goal of having as much functionality as
 * possible in the platform independent code.\n
 *
 * @section mainstructure 3 Functional Structure
 *
 * @startuml
 * package "SXP daemon block diagram" {
 *  component [logging] as log
 *  component "sxpd library" as sxpdlib {
 *   component [SXP protocol parser] as sxp
 *  }
 *  component "event manager" as evmgr {
 *   component [socket management]
 *   component [timers]
 *   component [signal handler]
 *  }
 *  component "configuration manager" as cfgmgr
 *  database "bindings database" as db {
 *   component [radix IPv4 tree] as ipv4radix
 *   component [radix IPv6 tree] as ipv6radix
 *  }
 * }
 * sxpdlib --> evmgr
 * db --> sxpdlib
 * cfgmgr --> sxpdlib
 * evmgr --> network
 * @enduml
 *
 * @startuml
 * package "Linux SXP daemon modules" {
 *  component "event manager" as evmgr {
 *   component [library libevent2]
 *   component [socket management]
 *   component [timers]
 *   component [signal handler]
 *  }
 *  component "configuration manager" as cfgmgr {
 *   component [library libconfig]
 *   component [configuration validator]
 *  }
 *  component "gdbus interface" as gdbus {
 *   component [libgio library]
 *  }
 * }
 * database "configuration file" as cfgfile
 * interface "dbus"
 * cfgmgr --> cfgfile
 * gdbus --> dbus
 * @enduml
 *
 * @subsection mainpdm 3.1 Platform-dependent modules
 *
 * @subsubsection mainevm 3.1.1 Event manager
 * @htmlinclude event_manager.html
 * @link evmgr read more...@endlink
 *
 * @subsubsection mainmem 3.1.2 Memory management
 * @htmlinclude memory_management.html
 * @link mem read more...@endlink
 *
 * @subsubsection maincfgm 3.1.3 Configuration manager
 * @htmlinclude configuration_manager.html
 * @link config read more...@endlink
 *
 * @subsubsection maintmst 3.1.4 Timestamp generator
 * @htmlinclude timestamp_generator.html
 * @link tstamp read more...@endlink
 *
 * @subsubsection mainrng 3.1.5 Random number generator
 * @htmlinclude random_number_generator.html
 * @link rnd read more...@endlink
 *
 * @subsubsection mainlogging 3.1.6 Logging
 * @htmlinclude logging.html
 * @link logging read more...@endlink
 *
 * @subsubsection maindbus 3.1.7 DBUS interface
 * @htmlinclude dbus_interface.html
 *
 * @subsubsection mainsxpdmain 3.1.8 SXPD main setup code
 * @htmlinclude sxpd_main_setup.html
 *
 * @subsection mainpim 3.2 Platform-independent modules
 * @details Platform-independent modules cover the core daemon functionality,
 * SXP protocol parser and radix tree implementation.
 *
 * @subsubsection mainsxpd 3.2.1 SXP daemon core logic
 * @htmlinclude sxp_daemon.html
 * @link sxpd read more...@endlink
 *
 * @subsubsection mainsxp 3.2.2 SXP protocol parser
 * @htmlinclude sxp_protocol_parser.html
 * @link sxp read more...@endlink
 *
 * @subsubsection mainradix 3.2.3 Radix tree
 * @htmlinclude radix_tree.html
 * @link radix read more...@endlink
 *
 * @section mainsystemflow 4 System flow
 *
 * @subsection mainevents 4.1 Events
 * @details The SXP daemon is event based – events include timer events,
 * configuration events, socket events and signals.
 *
 * @subsection maininitialization 4.2 Initialization
 * @details Initialization code is responsible for setting up the daemon.
 * It creates an event manager instance, registers configuration management
 * and then enters event loop.
 *
 * @subsection maintimerevents 4.3 Timer events
 *
 * @subsubsection mainretrytimer 4.3.1 Connection retry timer
 * @details This timer is setup for each peer whenever a failure occurs while
 * doing any operation regarding that peer which results in tearing down the
 * connection. Timer is canceled if a connection if brought up which results
 * in having enough connections to that peer.
 *
 * @subsubsection mainkeepalivetimer 4.3.2 Keep-alive timer
 * @details Timer is setup/active in case the keep-alive mechanism is
 * negotiated for peers which are listeners. When it expires, a keep-alive
 * message is sent to the peer and the timer is re-armed. The timer is also
 * re-armed after an update message has been sent to the peer.
 *
 * @subsubsection mainholdtimer 4.3.3 Hold timer
 * @details This timer is setup if keep-alive mechanism is negotiated for peers
 * which are speakers. If hold timer expires, sxp daemon assumes the connection
 * failed, tears down the appropriate socket and starts the delete hold-down
 * timer.
 *
 * @subsubsection mainreconciliationtimer 4.3.4 Reconciliation timer
 * @details This timer is started when a speaker peer reconnects. At this time,
 * a reconciliation timestamp is saved and when the timer fires, all bindings
 * from this peer are traversed. Any binding with timestamp older than the
 * reconciliation timestamp is removed. (That means all bindings which were not
 * advertised during the reconciliation timer).
 *
 * @subsubsection maindeleteholddowntimer 4.3.5 Delete hold-down timer
 * @details This timer is started when a connection to speaker peer is lost.
 * When the timer expires, all bindings from this peer are deleted. The timer
 * is cancelled when the peer reconnects
 *
 * @subsection mainconfigurationevents 4.4 Configuration events
 * @details Configuration events include configuration parameter change, peer
 * change and binding change.
 *
 * @subsubsection mainparameterchanges 4.4.1 Parameter changes
 * @details The parameters are:
 *  -# Log level (string)
 *  -# Default connection password (string)
 *  -# Retry timer value in seconds
 *  -# Reconciliation timer value in seconds
 *  -# Speaker hold timer minimum value in seconds
 *  -# Listener hold timer minimum in seconds
 *  -# Listener hold timer maximum in seconds
 *  -# Keep alive timer timeout in seconds
 *  -# Subnet expansion counter limit
 *  -# Bind address (address where the daemon binds to for listening)
 *  -# Listening port
 *  -# Node id for sxp daemon instance
 *  -# Enable – global setting which says whether the daemon is enabled or
 *disable
 *
 * @subsubsection mainpeerchange 4.4.2 Peer change
 * @details Peers can be added, modified and removed. When a peer is added,
 * an empty bindings database is created for it and connection attempt is
 * started. When a peer is removed, all connections to the peer are torn down
 * and all bindings from this peer are removed from the master bindings
 * database.
 *
 * @subsubsection mainbindingchange 4.4.3 Binding change
 * @details Bindings can be added or deleted. When a binding is added, it is
 * added to the local bindings database and propagated to the master bindings
 * database. When its removed, it is removed from both these databases.
 *
 * @subsection mainsocketevents 4.5 Socket events
 *
 * @subsubsection mainnewconnection 4.5.1 New connection
 * @details When a new connection is received, peer database is searched for
 * the source ip to see if the peer is recognized. If not, then connection
 * is closed, otherwise if the connection is needed (or the peers ip address
 * is higher) then the connection is kept. This might cause existing
 * connection (outgoing connection) to be torn down.
 *
 * @subsubsection mainwrite 4.5.2 Write
 * @details This event is utilized for error cases to detect whether an error
 * message was written to the socket, if yes, then the connection is closed.
 *
 * @subsubsection mainread 4.5.3 Read
 * @details When a read event occurs, data are read into local buffer and if
 * there is enough data to contain SXP message header, then this is parsed and
 * if enough data are received so that a complete message is in the buffer,
 * then that message is parsed. This is repeated multiple times if more
 * messages are in the buffer.
 *
 * @subsubsection mainerror 4.5.4 Error
 * @details This indicates that the other side closed the socket or some error
 * occurred. The affected socket is destroyed and retry timer is scheduled if
 * needed.
 *
 * @subsection mainsignals 4.6 Signals
 * @details Signal events are only used for debugging and/or platform specific
 * handling. On Linux, SIGHUP causes the configuration management to reload
 * the configuration file and call the appropriate callbacks for any changes
 * detected. Also SIGQUIT causes the daemon to print debugging info to the
 * standard output.
 *
 * @section maindatastructures 5 Data Structures
 *
 * @subsection mainsxpctx 5.1 SXP daemon context
 * @details The SXP daemon context holds the run-time state of the SXP daemon.
 *
 * @subsection mainpeerctx 5.2 SXP peer
 * @details This structure holds the run-time state of sxp peer.
 */

/**
 * @defgroup sxpd SXP daemon
 * @htmlinclude sxp_daemon.html
 * @addtogroup sxpd
 * @{
 */

/**
 * @brief create sxpd context
 *
 * @param evmgr event manager context to use
 * @param evmgr_settings event manager settings passed to event manager when
 * invoking event manager API calls
 * @param default_loglevel default log level
 *
 * @return context pointer on success, NULL on error
 */
struct sxpd_ctx *sxpd_create(struct evmgr *evmgr,
                             struct evmgr_settings *evmgr_settings,
                             enum log_level default_loglevel);

/**
 * @brief register configuration callbacks
 *
 * @param ctx sxpd context
 * @param cfg_ctx configuration context
 *
 * @return 0 on success, -1 on error
 */
int sxpd_register_config(struct sxpd_ctx *ctx, struct cfg_ctx *cfg_ctx);

/**
 * @brief destroy sxpd context and free resources
 *
 * @param ctx context to destroy
 */
void sxpd_destroy(struct sxpd_ctx *ctx);

enum ip_type { V4, V6 };

/**
 * @brief search the master bindings database for best match for given prefix
 *and return the corresponding tag
 *
 * @param[in] ctx sxpd context
 * @param[in] ip_type type - V4 or V6
 * @param[in] prefix prefix bits
 * @param[in] length length of the prefix
 * @param[out] tag set to corresponding tag, if found
 * @param[out] found set to true if found, otherwise false
 *
 * @return 0 on success, -1 on error
 */
int sxpd_search_best(struct sxpd_ctx *ctx, enum ip_type ip_type,
                     uint8_t *prefix, uint8_t length, uint16_t *tag,
                     bool *found);

/**
 * @brief opaque sxpd bindings iterator
 */
struct sxpd_bindings_iterator;

/**
 * @brief start or continue iterating the bindings database
 *
 * this function iterates the master bindings database
 * start the iteration by providing pointer to context set to NULL
 * when sxpd_iterate_bindings finishes, if *context is NULL, then there are
 * no more bindings available, if *context is non-NULL, then a binding was
 * was stored in buffer, length, tag
 *
 * there is NO guarantee on the consistency of the results if there are changes
 * in the bindings set while iterating, some bindings which are present COULD be
 * skipped if the bindings set is changed during the iteration
 *
 * @param ctx sxpd context
 * @param ip_type V4 for IPv4 bindings, V6 for IPv6
 * @param context pointer to iterator, allocated by sxpd_iterate_bindings
 * @param buffer buffer to store the prefix bits
 * @param buffer_size size of the buffer
 * @param length the number of prefix bits the prefix has
 * @param tag the associated source group tag
 *
 * @return 0 on success, -1 on error
 */
int sxpd_iterate_bindings(struct sxpd_ctx *ctx, enum ip_type ip_type,
                          struct sxpd_bindings_iterator **context,
                          uint8_t *buffer, size_t buffer_size, uint8_t *length,
                          uint16_t *tag);

/**
 * @brief stop iterating bindings and free iterator
 *
 * @param ctx sxpd context
 * @param iterator iterator returned by sxpd_iterate_bindings
 */
void sxpd_iterate_bindings_finish(struct sxpd_ctx *ctx,
                                  struct sxpd_bindings_iterator *iterator);

/**
 * @brief opaque sxpd peers iterator
 */
struct sxpd_peer_iterator;

/**
 * @brief sxpd peer outgoing connection state
 */
enum sxpd_peer_out_conn_state {
    NONE,                /*!< no connection */
    WAITING_CONNECT,     /*!< waiting for TCP connect to finish */
    WILL_SEND_OPEN,      /*!< need to send OPEN message */
    WAITING_OPEN,        /*!< waiting for OPEN message */
    WILL_SEND_OPEN_RESP, /*!< need to send OPEN_RESP message */
    WAITING_OPEN_RESP,   /*!< waiting for OPEN_RESP message */
    CONNECTED,           /*!< connected */
    ERROR_CONNECT,       /*!< error while connecting */
    CONNECT_RETRY_TIMER, /*!< outgoing connection retry timer running */
};

#define SXPD_PEER_STATE_ENUMERATOR(F)                            \
    F(NONE) F(WAITING_CONNECT) F(WILL_SEND_OPEN) F(WAITING_OPEN) \
        F(WILL_SEND_OPEN_RESP) F(WAITING_OPEN_RESP) F(CONNECTED) \
            F(ERROR_CONNECT) F(CONNECT_RETRY_TIMER)

#ifdef SXPD_PEER_STATE_ENUMERATOR
/* prevent unused macro warning */
#endif

/**
 * @brief structure describing peer
 */
struct sxpd_peer_info {
    uint32_t nbo_ip;          /*!< IP address */
    uint16_t nbo_port;        /*!< port */
    size_t connections_count; /*!< how many connections are active with this
                                 peer */
    enum sxpd_peer_out_conn_state
        outgoing_connection_state;      /*!< outgoing connection state */
    bool retry_timer_active;            /*!< retry timer armed ? */
    bool delete_hold_down_timer_active; /*!< delete hold down timer armed ? */
    bool reconciliation_timer_active;   /*!< reconciliation timer armed ? */
    bool keepalive_timer_active;        /*!< keepalive timer armed ? */
    bool hold_timer_active;             /*!< hold timer armed ? */
    bool is_speaker;  /*!< does this peer have speaker role ? */
    bool is_listener; /*!< does this peer have listener role ? */
};

/**
 * @brief start or continue iterating the peers
 *
 * this function iterates the peers
 * start the iteration by providing pointer to context set to NULL
 * when sxpd_iterate_peers finishes, if *context is NULL, then there are no more
 * peers available, otherwise peer info is filled in peer
 *
 * there is NO guarantee on the consistency of the results if there are changes
 * in the peer set while iterating peers, some peers MIGHT be skipped and a peer
 * COULD be returned twice if the peer set is reconfigured during iteration,
 * client should use the peer->nbo_ip/peer->port as the unique identifier
 * of the peer
 *
 * @param ctx sxpd context
 * @param context pointer to iterator, allocated by sxpd_iterate_peers
 * @param peer peer info
 *
 * @return 0 on success, -1 on error
 */
int sxpd_iterate_peers(struct sxpd_ctx *ctx,
                       struct sxpd_peer_iterator **context,
                       struct sxpd_peer_info *peer);

/**
 * @brief stop iterating peers and free iterator
 *
 * @param ctx sxpd context
 * @param iterator iterator returned by sxpd_iterate_peers
 */
void sxpd_iterate_peers_finish(struct sxpd_ctx *ctx,
                               struct sxpd_peer_iterator *iterator);

/**
 * @brief sxpd status
 */
struct sxpd_info {
    uint32_t nbo_bind_ip; /*!< IP to which sxpd is bound to */
    uint16_t nbo_port;    /*!< port used by sxpd */
    const char *default_connection_password; /*!< default connection password */
    size_t peer_count;                       /*!< number of peers configured */
    size_t expanded_entry_count; /*!< number of expanded host entries */
    bool enabled;                /*!< daemon enabled ? */
};

/**
 * @brief get sxpd runtime information
 *
 * @param ctx sxpd context
 * @param info sxpd info
 *
 * @return 0 on success, -1 on error
 */
int sxpd_get_info(struct sxpd_ctx *ctx, struct sxpd_info *info);

/**
 * @brief add string type configuration option to sxpd
 *
 * @param ctx sxpd context
 * @param type type of setting
 * @param value value of setting
 *
 * @return 0 on success, -1 on error
 */
int sxpd_cfg_add_str_setting(struct sxpd_ctx *ctx, str_setting_type_t type,
                             const char *value);

/**
 * @brief withdraw string setting from sxpd
 *
 * @param ctx sxpd context
 * @param type type of setting
 *
 * @return 0 on success, -1 on error
 */
int sxpd_cfg_del_str_setting(struct sxpd_ctx *ctx, str_setting_type_t type);

/**
 * @brief add uint32 type configuration option to sxpd
 *
 * @param ctx sxpd context
 * @param type type of setting
 * @param value value of setting
 *
 * @return 0 on success, -1 on error
 */
int sxpd_cfg_add_uint32_setting(struct sxpd_ctx *ctx,
                                uint32_setting_type_t type, uint32_t value);

/**
 * @brief withdraw uint32 setting from sxpd
 *
 * @param ctx sxpd context
 * @param type type of setting
 *
 * @return 0 on success, -1 on error
 */
int sxpd_cfg_del_uint32_setting(struct sxpd_ctx *ctx,
                                uint32_setting_type_t type);
/**
 * @brief add new peer to sxpd
 *
 * @param ctx sxpd context
 * @param peer peer info
 *
 * @return 0 on success, -1 on error
 */
int sxpd_cfg_add_peer(struct sxpd_ctx *ctx, const struct peer *peer);

/**
 * @brief remove peer from sxpd
 *
 * @param ctx sxpd context
 * @param peer peer info
 *
 * @return 0 on success, -1 on error
 */
int sxpd_cfg_del_peer(struct sxpd_ctx *ctx, const struct peer *peer);

/**
 * @brief add binding to sxpd
 *
 * @param ctx sxpd context
 * @param binding binding info
 *
 * @return 0 on success, -1 on error
 */
int sxpd_cfg_add_binding(struct sxpd_ctx *ctx, const struct binding *binding);

/**
 * @brief remove binding from sxpd
 *
 * @param ctx sxpd context
 * @param binding binding info
 *
 * @return 0 on success, -1 on error
 */
int sxpd_cfg_del_binding(struct sxpd_ctx *ctx, const struct binding *binding);

/** @} */

#endif
