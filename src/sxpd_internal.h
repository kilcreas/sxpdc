#ifndef SXPD_INTERNAL_H
#define SXPD_INTERNAL_H

#ifndef SXPD_INTERNAL_H
/* avoid unused macro warning */
#endif

#include <stdbool.h>
#include <evmgr.h>
#include <config.h>
#include <logging.h>

/**
 * @addtogroup sxpd
 * @{
 */

/**
 * structure representing an array of bits, bits are allocated when set and bits
 * which would be in part of array not allocated yet are considered to be set to
 * zero
 */
struct sxpd_mask {
    uint32_t *elems;   /**< holds the bits */
    size_t elem_count; /**< how many elems allocated */
    size_t bits_set;   /**< how many bits set currently */
};

/**
 * peer sequence array with reference count
 */
struct sxpd_peer_sequence {
    uint32_t *node_ids;    /**< node ids in the peer sequence */
    size_t node_ids_count; /**< number of node ids in the seqeuence */
    size_t refcount;       /**< reference count */
};

/**
 * represents binding contributed by peer
 */
struct sxpd_binding {
    /* peer sequence */
    struct sxpd_peer_sequence *peer_sequence;
    /* next binding with the same peer sequence */
    struct sxpd_binding *same_peer_seq_next;
    /* the binding list which contains this binding */
    struct sxpd_binding_list *binding_list;
    /* when this binding was registered */
    struct timestamp *timestamp;
    /* source group tag */
    uint16_t tag;
};

/**
 * represents expanded host entry
 */
struct sxpd_expansion_track_entry {
    /* binding list from which this host entry is chosen (to get peer sequence,
     * sgt, etc. from) */
    struct sxpd_binding_list *bl;
    /* length of the prefix of the binding list */
    uint8_t prefix_len;
    /* mask for single entries indicating whether peer is up to date regarding
     * this entry - peer's expansion index tells which bit is for which peer */
    struct sxpd_mask mask;
    /* radix node in the expanded entries radix tree */
    struct radix_node *node;
    /* used for temporary binding entries in linked list */
    struct sxpd_expansion_track_entry *next;
};

/**
 * represents contributing bindings in master binding database
 *
 * if binding list has count == 0, it means that all contributing bindings
 * were deleted and the deletes are being propagated to listeners - once all are
 * propagated (mask is set to all-ones), then the binding list gets removed
 */
struct sxpd_binding_list {
    /* radix node corresponding to this binding list */
    struct radix_node *radix_node;
    /* pointer to next binding list - used for temporary linking binding lists
     * to update e.g. bit mask after a message has been sent to a client */
    struct sxpd_binding_list *next;
    /* array of contributing bindings */
    struct sxpd_binding **bindings;
    /* number of elements in bindings array */
    size_t count;
    /* any iterators associated with this binding list (linked list) */
    struct sxpd_bindings_iterator *iterator;
    /* peer distribution mask */
    struct sxpd_mask mask;
    /* used for temporary marking elements as processed */
    bool mark : 1;
    /* flag indicating whether this prefix is being expanded to peers which
     * don't have subnet bindings capability */
    bool expanding : 1;
};

/**
 * @brief sxp context
 */
struct sxpd_ctx {
    /* event manager context */
    struct evmgr *evmgr;
    /* event manager settings */
    struct evmgr_settings *evmgr_settings;
    /* event manager listener for sxpd port */
    struct evmgr_listener *listener;
    /* number of configured peers */
    size_t peer_count;
    /* array of peers */
    struct sxpd_peer **peers;
    /* number of listeners in listeners array */
    size_t listener_count;
    /* number of listeners connected */
    size_t connected_listener_count;
    /* array of peers which act like listeners */
    struct sxpd_peer **listeners;
    /* the number of entries in expanding_listeners */
    size_t expanding_listener_count;
    /* array for tracking the listeners which don't have support for subnets */
    struct sxpd_peer **expanding_listeners;
    /* whether the instance is enabled or not */
    bool enabled;
    /* TCP md5 signing support */
    bool md5sig;
    /* number of peers with password set (not using default password) */
    size_t md5sig_peers;
    /* default connection password */
    char default_connection_password[CFG_PASSWORD_MAX_SIZE];
    /* keepalive timeout */
    struct timeval keepalive_timeout;
    /* reconciliation timeout */
    struct timeval reconciliation_timeout;
    /* retry timeout value */
    struct timeval retry_timeout;
    /* source address used when connecting to peers */
    struct sockaddr_in src_address;
    /* node id in network byte order */
    uint32_t node_id;
    /* linked list containing unused buffers */
    struct sxpd_buffer_wrapper *buffer_pool;
    /* ipv4 bindings local database (holds struct sxpd_binding*) */
    struct radix_tree *bindings_v4;
    /* ipv4 bindings master database (holds struct sxpd_binding_list*) */
    struct radix_tree *master_bindings_v4;
    /* ipv4 bindings local database (holds struct sxpd_binding*) */
    struct radix_tree *bindings_v6;
    /* ipv4 bindings master database (holds struct sxpd_binding_list*) */
    struct radix_tree *master_bindings_v6;
    /* ipv4 bindings which are being expanded to host entries (holds struct
     * sxpd_binding_list* shared with master_bindings_v4) */
    struct radix_tree *expand_bindings_v4;
    /* expanded host entries (holds struct sxpd_expansion_track_entry*) */
    struct radix_tree *expand_entries_v4;
    /* number of expanded host entries */
    size_t expanded_entry_count;
    /* dummy peer sequence for tracking old peers which do not provide it */
    struct sxpd_peer_sequence *v1_peer_sequence;
    /* helper variable tracking whether a setting is set or default is used */
    bool uint32_setting_is_set[UINT32_SETTING_LAST];
    /* helper variable tracking whether a setting is set or default is used */
    bool str_setting_is_set[STR_SETTING_LAST];
    /* subnet expansion limit */
    size_t sub_expand_limit;
    /* address to bind to */
    in_addr_t nbo_bind_ip;
    /* desired minimum hold-time in listener role */
    uint16_t listener_min_hold_time;
    /* desired maximum hold-time in listener role */
    uint16_t listener_max_hold_time;
    /* minimum acceptable hold-time in speaker role */
    uint16_t speaker_min_hold_time;
    /* bind port */
    uint16_t nbo_port;
    /* default log level */
    enum log_level default_log_level;
#ifdef TESTING
    int version;
#endif
};

/** @} */

#endif
