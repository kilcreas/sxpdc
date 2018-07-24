/*------------------------------------------------------------------
 * SXP daemon implementation
 *
 * November 2014, Klement Sekera
 *
 * Copyright (c) 2014-2015 by cisco Systems, Inc.
 * All rights reserved.
 *
 *------------------------------------------------------------------*/

#include <stddef.h>
#include <string.h>
#include <inttypes.h>
#include <math.h>
#include <arpa/inet.h>
#include <signal.h>
#include <unistd.h>
#include <rnd.h>

#include <sxpd.h>
#include <sxp.h>
#include <mem.h>
#include <config.h>
#include <util.h>
#include <radix.h>
#include <timestamp.h>
#include <logging.h>

#include "sxpd_internal.h"

/**
 * @addtogroup sxpd
 * @{
 *
 * @section gump generic update message processing
 * @startuml
 * actor "speaker" as speaker
 * participant "event manager" as evmgr
 * participant "sxpd peer" as peer
 * participant "sxp library" as sxplib
 * database "peer ipv4 bindings database" as peerdb4
 * database "peer ipv6 bindings database" as peerdb6
 * speaker->evmgr: update message
 * evmgr->peer: update message in network byte order
 * peer->sxplib: swap message from network to host byte order\
 * (sxp_msg_ntoh_swap)
 * sxplib-->peer: message in host byte order
 * peer->peer: validate update message (attributes, peer-sequence,\
 * peer's sxp version, etc..)
 * alt invalid message
 *  peer->sxplib: create error message
 *  sxplib-->peer: error message in host byte order
 *  peer->sxplib: swap error message from host to network byte order\
 *  (sxp_msg_hton_swap)
 *  sxplib-->peer: error message in network byte order
 *  peer->evmgr: write error message to socket (evmgr_socket_write)
 *  evmgr->speaker: error message
 * else valid message - peer is v1/v2 peer (update message validation ensured\
 * that only v1/v2 attributes are present)
 *  loop while message not parsed completely
 *   peer->sxplib: get next attribute (sxp_parse_msg)
 *   sxplib-->peer: attribute pointer
 *   alt add-ipv4 attribute
 *    peer->sxplib: parse add-ipv4 attribute (sxp_parse_add_ipv4)
 *    sxplib-->peer: prefix, source group tag, optionally prefix-length\
 *    (if present)
 *    peer->peerdb4: add prefix to peer database (sxpd_peer_add_prefix)
 *   else add-ipv6 attribute
 *    peer->sxplib: parse add-ipv6 attribute (sxp_parse_add_ipv6)
 *    sxplib-->peer: prefix, source group tag, optionally prefix-length\
 *    (if present)
 *    peer->peerdb6: add prefix to peer database (sxpd_peer_add_prefix)
 *   else del-ipv4 attribute
 *    peer->sxplib: parse del-ipv4 attribute (sxp_parse_del_ipv4)
 *    sxplib-->peer: prefix, source group tag, optionally prefix-length\
 *    (if present)
 *    peer->peerdb4: delete prefix from peer database (sxpd_peer_del_prefix)
 *   else del-ipv6 attribute
 *    peer->sxplib: parse del-ipv6 attribute (sxp_parse_del_ipv6)
 *    sxplib-->peer: prefix, source group tag, optionally prefix-length\
 *    (if present)
 *    peer->peerdb6: delete prefix from peer database (sxpd_peer_del_prefix)
 *   end
 *  end
 * else valid message - peer is non-v1/v2 peer (update message validation\
 * ensured that no v1/v2 attributes are present)
 *  peer->peer: clear loop-detected flag (local variable)
 *  loop while message not parsed completely
 *   peer->sxplib: get next attribute (sxp_parse_msg)
 *   sxplib-->peer: attribute pointer
 *   alt peer-sequence attribute
 *    peer->peer: clear loop-detected flag
 *    peer->sxplib: parse peer sequence (sxp_parse_peer_sequence)
 *    sxplib-->peer: array of node-ids
 *    peer->peer: check for sxpd node id (loop detection)
 *    alt loop detected
 *     peer->peer: set loop-detected flag
 *    else no loop
 *     peer->peer: remember peer-sequence for later use
 *    end
 *   else source group tag attribute
 *    alt loop-detected flag set
 *     peer->peer: ignore source group tag attribute
 *    else loop-detected flag not set
 *     peer->sxplib: get source group tag (sxp_attr_sgt_get_sgt)
 *     sxplib-->peer: source group tag
 *     peer->peer: remember source group tag for later use
 *    end
 *   else ipv4-add-prefix attribute
 *    alt loop-detected flag set
 *     peer->peer: ignore source group tag attribute
 *    else loop-detected flag not set
 *     loop for each prefix present in ipv4-add-prefix prefix list
 *      peer->sxplib: get next prefix from prefix list (sxp_parse_prefix_list)
 *      sxplib-->peer: next prefix
 *      peer->peerdb4: add prefix to peer database (sxpd_peer_add_prefix)
 *     end
 *    end
 *   else ipv6-add-prefix attribute
 *    alt loop-detected flag set
 *     peer->peer: ignore source group tag attribute
 *    else loop-detected flag not set
 *     loop for each prefix present in ipv6-add-prefix prefix list
 *      peer->sxplib: get next prefix from prefix list (sxp_parse_prefix_list)
 *      sxplib-->peer: next prefix
 *      peer->peerdb6: add prefix to peer database (sxpd_peer_add_prefix)
 *     end
 *    end
 *   else ipv4-del-prefix attribute
 *    alt loop-detected flag set
 *     peer->peer: ignore source group tag attribute
 *    else loop-detected flag not set
 *     loop for each prefix present in ipv4-del-prefix prefix list
 *      peer->sxplib: get next prefix from prefix list (sxp_parse_prefix_list)
 *      sxplib-->peer: next prefix
 *      peer->peerdb4: del prefix from peer database (sxpd_peer_del_prefix)
 *     end
 *    end
 *   else ipv6-del-prefix attribute
 *    alt loop-detected flag set
 *     peer->peer: ignore source group tag attribute
 *    else loop-detected flag not set
 *     loop for each prefix present in ipv6-del-prefix prefix list
 *      peer->sxplib: get next prefix from prefix list (sxp_parse_prefix_list)
 *      sxplib-->peer: next prefix
 *      peer->peerdb6: del prefix from peer database (sxpd_peer_del_prefix)
 *     end
 *    end
 *   end
 *  end
 * end
 * @enduml
 *
 * @section ddd data dependency diagram
 * @startuml
 * object "SXP daemon context\n(struct sxpd_context)" as sxpd_context
 * object "Array of all peers\n(struct sxpd_peer *)" as peers
 * object "Array of listeners\n(struct sxpd_peer *)" as listeners
 * object "Array of listeners which handle host-only entries\
 * \n(struct sxpd_peer *)" as expanding_listeners
 * object "SXP peer\n(struct sxpd_peer)" as sxpd_peer
 * object "Peer's IPv4 bindings database\n(struct radix_tree)" as ldb4
 * object "Peer's IPv6 bindings database\n(struct radix_tree)" as ldb6
 * object "Peer-provided IPv4-SGT binding\n(struct sxpd_binding)" as b4
 * object "Peer-provided IPv6-SGT binding\n(struct sxpd_binding)" as b6
 * object "Locally configured IPv4 bindings database\n(struct radix_tree)" as \
 * cdb4
 * object "Locally configured IPv4 binding\n(struct sxpd_binding)" as cb4
 * object "Locally configured IPv6 bindings database\n(struct radix_tree)" as \
 * cdb6
 * object "Locally configured IPv6 binding\n(struct sxpd_binding)" as cb6
 * object "Master IPv4 bindings database\n(struct radix_tree)" as mdb4
 * object "Master IPv6 bindings database\n(struct radix_tree)" as mdb6
 * object "Expanding IPv4 bindings database\n(struct radix_tree)" as ebdb
 * object "Expanded IPv4 hosts entries database\n(struct radix_tree)" as ehdb
 * object "IPv4-SGT binding list\n(struct sxpd_binding_list)" as bl4
 * object "IPv6-SGT binding list\n(struct sxpd_binding_list)" as bl6
 * object "Peer distribution mask\n(struct sxpd_mask)" as bl4m
 * object "Peer distribution mask\n(struct sxpd_mask)" as bl6m
 * object "Expansion track entry\n(struct sxpd_expansion_track_entry)" as et
 * object "Expansion track entry mask\n(struct sxpd_mask)" as etm
 * object "Event manager\n(struct evmgr)" as evmgr
 * object "Peer sequence\n(struct sxpd_peer_sequence)" as peer_sequence

 * sxpd_context "1" o-- "1" peers
 * sxpd_context "1" o-- "1" listeners
 * sxpd_context "1" o-- "1" expanding_listeners
 * sxpd_context "1" o-- "1" evmgr
 * sxpd_context "1" o-- "1" cdb4
 * sxpd_context "1" o-- "1" cdb6
 * sxpd_context "1" o-- "1" mdb4
 * sxpd_context "1" o-- "1" mdb6
 * sxpd_context "1" o-- "1" ldb4
 * sxpd_context "1" o-- "1" ldb6
 * sxpd_context "1" o-- "1" ebdb
 * sxpd_context "1" o-- "1" ehdb
 * peers "1" o-- "0..*" sxpd_peer
 * listeners "1" o-- "0..*" sxpd_peer
 * expanding_listeners "1" o-- "0..*" sxpd_peer
 * sxpd_peer "1" o-- "1" ldb4
 * sxpd_peer "1" o-- "1" ldb6
 * ldb4 "1" o-- "0..*" b4
 * ldb6 "1" o-- "0..*" b6
 * mdb4 "1" o-- "0..*" bl4
 * mdb6 "1" o-- "0..*" bl6
 * bl4 "1" o-- "0..*" b4
 * bl4 "1" o-- "1" bl4m
 * bl6 "1" o-- "0..*" b6
 * bl6 "1" o-- "1" bl6m
 * peer_sequence "1" o-- "1..n" b4
 * peer_sequence "1" o-- "1..n" b6
 * ebdb "1" o-- "0..*" bl4
 * ehdb "1" o-- "0..*" et
 * et "1" o-- "1" bl4
 * et "1" o-- "1" etm
 * cdb4 "1" o-- "0..n" cb4
 * cdb6 "1" o-- "0..n" cb6
 * bl4 "1" o-- "0..n" cb4
 * bl6 "1" o-- "0..n" cb6
 * @enduml
 */

DECL_DEBUG_V6_STATIC_BUFFER

#define RADIX_V4_MAXBITS 32
#define RADIX_V6_MAXBITS 128

#define UINT32_SETTING_RETRY_TIMER_DEFAULT 120
#define UINT32_SETTING_RECONCILIATION_TIMER_DEFAULT 120
#define UINT32_SETTING_SPEAKER_MIN_HOLD_TIME_DEFAULT 120
#define UINT32_SETTING_LISTENER_MIN_HOLD_TIME_DEFAULT 90
#define UINT32_SETTING_LISTENER_MAX_HOLD_TIME_DEFAULT 180
#define UINT32_SETTING_KEEPALIVE_TIMER_DEFAULT KEEPALIVE_UNUSED
#define UINT32_SETTING_SUBNET_EXPANSION_LIMIT_DEFAULT 0
#define UINT32_SETTING_PORT_DEFAULT 64999
#define UINT32_SETTING_ENABLED_DEFAULT false

/**
 * stop writing more data if this much data exceeded in single write event
 */
#define WRITE_CHUNK_SIZE (64 * 1024)

static inline const char *
sxpd_peer_outgoing_state_string(enum sxpd_peer_out_conn_state s)
{
#define HELPER(x) \
    case x:       \
        return #x;
    switch (s) {
        SXPD_PEER_STATE_ENUMERATOR(HELPER)
    }

#undef HELPER
    return "UNKNOWN";
}

struct sxpd_peer {
    /* parent sxpd context */
    struct sxpd_ctx *sxpd_ctx;
    /* peer address/port and md5 signing key pair */
    struct address_md5_pwd_pair pwd_pair;
    /* connection to the speaker */
    struct evmgr_socket *speaker;
    /* connection from the listener */
    struct evmgr_socket *listener;
    /* outgoing (initiated by sxpd) connection */
    struct evmgr_socket *outgoing;
    /* buffer for storing incoming data */
    struct sxpd_buffer *outgoing_in_buffer;
    /* outgoing (initiated by sxpd) connection state */
    enum sxpd_peer_out_conn_state outgoing_state;
    /* incoming (initiated by peer) connection */
    struct evmgr_socket *incoming;
    /* buffer for storing incoming data */
    struct sxpd_buffer *incoming_in_buffer;
    /* outgoing connection retry timer */
    struct evmgr_timer *retry_timer;
    /* negotiated hold time for listener peer (in seconds) */
    uint16_t listener_hold_time;
    /* negotiated hold time for speaker peer (in seconds) */
    uint16_t speaker_hold_time;
    /* keep-alive timer */
    struct evmgr_timer *keepalive_timer;
    /* hold timer */
    struct evmgr_timer *hold_timer;
    /* timestamp when the reconciliation timer was started */
    struct timestamp *reconciliation_timestamp;
    /* reconciliation timer */
    struct evmgr_timer *reconciliation_timer;
    /* delete hold down timer */
    struct evmgr_timer *delete_hold_down_timer;
    /* type of the peer */
    enum peer_type type;
    /* protocol version negotiated */
    uint32_t version;
    /* peer node id - in network byte order */
    uint32_t nbo_node_id;
    /* specifies the bit position which corresponds to this peer in bit masks,
     * this has a meaning only for peers which act like listeners */
    size_t listener_bit_pos;
    /* v4 bindings */
    struct radix_tree *bindings_v4;
    /* v6 bindings */
    struct radix_tree *bindings_v6;
    /* index into expansion track array */
    size_t expansion_index;
    /* peer flags */
    struct {
        /* flag set if OPEN message on in_conn was already processed */
        bool incoming_negotiation_done : 1;
        /* flag indicating ipv4 capability */
        bool ipv4 : 1;
        /* flag indicating ipv6 capability */
        bool ipv6 : 1;
        /* flag indicating subnet bindings capability */
        bool sub_bind : 1;
        /* flag indicating that the peer understands peer sequence attribute */
        bool handles_peer_seq : 1;
        /* flag indicating that the peer understands sxp v4 attributes
         * ipv4/6-add/del-prefix */
        bool handles_sxp_v4_attributes;
        /* flag indicating that subnet bindings should be sent to the peer even
         * though peer doesn't have the subnet bindings capability */
        bool always_export_subnets;
    } flags;
};

static const char *
sxpd_peer_outgoing_state_short_string(enum sxpd_peer_out_conn_state s)
{
    switch (s) {
    case NONE:
        return "--";
    case WAITING_CONNECT:
        return "WC";
    case WILL_SEND_OPEN:
        return "SO";
    case WAITING_OPEN:
        return "WO";
    case WILL_SEND_OPEN_RESP:
        return "SR";
    case CONNECTED:
        return "UP";
    case WAITING_OPEN_RESP:
        return "WR";
    case ERROR_CONNECT:
        return "ER";
    case CONNECT_RETRY_TIMER:
        return "RT";
    }
    return "UNKNOWN";
}

static const char *sxp_peer_type_string(enum peer_type type)
{
    switch (type) {
    case PEER_SPEAKER:
        return "SPEAKER";
    case PEER_LISTENER:
        return "LISTENER";
    case PEER_BOTH:
        return "BOTH";
    }
    return "UNKNOWN";
}

#define SXPD_PEER_PRINT_FMT DEBUG_SIN_FMT "[%c][O%s][I%s]: "

#define SXPD_PEER_PRINT(x)                                                  \
    DEBUG_SIN_PRINT((x)->pwd_pair.sin),                                     \
        (PEER_LISTENER == x->type ? 'L'                                     \
                                  : (PEER_SPEAKER == x->type ? 'S' : 'B')), \
        sxpd_peer_outgoing_state_short_string(x->outgoing_state),           \
        x->incoming ? x->flags.incoming_negotiation_done ? "UP" : "WO" : "--"

#define PLOG_TRACE_FMT(peer, fmt, ...)                                \
    LOG_TRACE("Peer " SXPD_PEER_PRINT_FMT fmt, SXPD_PEER_PRINT(peer), \
              __VA_ARGS__)
#define PLOG_DEBUG_FMT(peer, fmt, ...)                                \
    LOG_DEBUG("Peer " SXPD_PEER_PRINT_FMT fmt, SXPD_PEER_PRINT(peer), \
              __VA_ARGS__)
#define PLOG_ERROR_FMT(peer, fmt, ...)                                \
    LOG_ERROR("Peer " SXPD_PEER_PRINT_FMT fmt, SXPD_PEER_PRINT(peer), \
              __VA_ARGS__)

#define PLOG_TRACE_MSG(peer, msg) \
    LOG_TRACE("Peer " SXPD_PEER_PRINT_FMT msg, SXPD_PEER_PRINT(peer))
#define PLOG_DEBUG_MSG(peer, msg) \
    LOG_DEBUG("Peer " SXPD_PEER_PRINT_FMT msg, SXPD_PEER_PRINT(peer))
#define PLOG_ERROR_MSG(peer, msg) \
    LOG_ERROR("Peer " SXPD_PEER_PRINT_FMT msg, SXPD_PEER_PRINT(peer))

#define PEER_CHANGE_OUT_CONN_STATE(peer, new_state)                           \
    do {                                                                      \
        peer->outgoing_state = new_state;                                     \
        PLOG_TRACE_FMT(peer, "Change outgoing connection state[%s->%s]",      \
                       sxpd_peer_outgoing_state_string(peer->outgoing_state), \
                       sxpd_peer_outgoing_state_string(new_state));           \
    } while (0)

#define PLOG_UNEXPECTED_OUT_CONN_STATE(peer, event)                       \
    PLOG_ERROR_FMT(peer, "Unexpected OUT connection state %s while %s",   \
                   sxpd_peer_outgoing_state_string(peer->outgoing_state), \
                   event)

struct sxpd_binding_list;

static struct sxpd_peer *sxpd_find_peer(struct sxpd_ctx *ctx,
                                        struct sockaddr_in *sin);

static int sxpd_setup_listener(struct sxpd_ctx *ctx);

static int sxpd_connect_all_peers(struct sxpd_ctx *ctx);

static void sxpd_disconnect_peer(struct sxpd_peer *peer);

static int sxpd_peer_export_bindings(struct sxpd_peer *peer);

static size_t sxpd_peer_connections_active(struct sxpd_peer *peer);

static size_t sxpd_peer_connections_connected(struct sxpd_peer *peer);

static size_t sxpd_peer_connections_needed(struct sxpd_peer *peer);

static int sxpd_schedule_connect_retry(struct sxpd_peer *peer);

static void sxpd_destroy_binding_list(struct sxpd_binding_list *bl);

static void
sxpd_destroy_expansion_track_entry(struct sxpd_expansion_track_entry *e);

static int sxpd_disable(struct sxpd_ctx *ctx);

static int sxpd_expand_bindings(struct sxpd_ctx *ctx);

static int sxpd_expand_binding(struct sxpd_ctx *ctx,
                               const struct v4_v6_prefix *prefix,
                               struct sxpd_binding_list *bl);

static int sxpd_iterate_bindings_internal(struct sxpd_bindings_iterator *i);

static void sxpd_peer_read_callback(struct evmgr_socket *socket, void *ctx);

static void sxpd_peer_write_callback(struct evmgr_socket *socket, void *ctx);

static void sxpd_peer_event_callback(struct evmgr_socket *socket,
                                     int16_t events, void *ctx);
static bool sxpd_str_is_empty(const char *str)
{
    assert(str);
    if ('\0' == str[0]) {
        return true;
    }
    return false;
}

static bool sxpd_is_enabled(struct sxpd_ctx *sxpd_ctx)
{
    assert(sxpd_ctx);
    if (sxpd_ctx->uint32_setting_is_set[UINT32_SETTING_ENABLED] &&
        sxpd_ctx->enabled) {
        return true;
    }
    return false;
}

static bool sxpd_node_id_is_set(struct sxpd_ctx *sxpd_ctx)
{
    assert(sxpd_ctx);
    if (sxpd_ctx->uint32_setting_is_set[UINT32_SETTING_NODE_ID]) {
        return true;
    }
    return false;
}

static bool sxpd_pwd_is_empty(struct sxpd_ctx *sxpd_ctx)
{
    assert(sxpd_ctx);
    if (sxpd_str_is_empty(sxpd_ctx->default_connection_password)) {
        return true;
    }
    return false;
}

static bool sxpd_peer_pwd_is_empty(struct sxpd_peer *sxpd_peer)
{
    assert(sxpd_peer);
    if (0 == sxpd_peer->pwd_pair.password_len) {
        return true;
    }
    return false;
}

static bool sxpd_md5sig(struct sxpd_ctx *sxpd_ctx)
{
    assert(sxpd_ctx);
    if (sxpd_ctx->md5sig) {
        return true;
    }
    return false;
}

static bool sxpd_md5sig_ok(struct sxpd_ctx *sxpd_ctx)
{
    assert(sxpd_ctx);
    if (sxpd_md5sig(sxpd_ctx) ||
        ((0 == sxpd_ctx->md5sig_peers) && sxpd_pwd_is_empty(sxpd_ctx))) {
        return true;
    }
    return false;
}

static bool sxpd_is_listener(struct sxpd_peer *peer)
{
    if (peer) {
        switch (peer->type) {
        case PEER_SPEAKER:
            return false;
        case PEER_LISTENER:
            return true;
        case PEER_BOTH:
            return true;
        }
    }
    return false;
}

static struct sxpd_peer_sequence *sxpd_alloc_peer_sequence()
{
    struct sxpd_peer_sequence *ps = mem_calloc(1, sizeof(*ps));
    if (ps) {
        ps->refcount = 1;
    }
    return ps;
}

static void sxpd_destroy_peer_sequence(struct sxpd_peer_sequence *ps)
{
    if (ps) {
        --ps->refcount;
        if (!ps->refcount) {
            mem_free(ps->node_ids);
            mem_free(ps);
        }
    }
}

static void sxpd_destroy_binding(struct sxpd_binding *b)
{
    if (b) {
        LOG_TRACE("Destroy binding %p", (void *)b);
        sxpd_destroy_peer_sequence(b->peer_sequence);
        destroy_timestamp(b->timestamp);
        mem_free(b);
    }
}

static bool sxp_msg_type_known(enum sxp_msg_type e)
{
    switch (e) {
#define HELPER(x) \
    case x:       \
        return true;
        SXP_MSG_TYPE_ENUMERATOR(HELPER)
#undef HELPER
    }

    return false;
}

static const size_t mask_elem_size_bits =
    8 * sizeof(*((struct sxpd_mask *)0)->elems);

/**
 * @brief clear all bits in a mask
 *
 * @param mask mask to operate on
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_mask_clear(struct sxpd_mask *mask)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, mask);
    RC_CHECK(rc, out);
    memset(mask->elems, 0, mask->elem_count * sizeof(mask->elems[0]));
    mask->bits_set = 0;
out:
    return rc;
}

static int sxpd_mask_get(struct sxpd_mask *mask, size_t bit, unsigned *value);

/**
 * @brief set a bit at position to value
 *
 * @param mask mask to change
 * @param bit bit to set
 * @param value value to set the bit to
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_mask_set(struct sxpd_mask *mask, size_t bit, unsigned value)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, mask);
    RC_CHECK(rc, out);
    size_t elems_needed = bit / mask_elem_size_bits + 1;
    if (mask->elem_count < elems_needed) {
        /* resize the mask to accomodate the bit set */
        uint32_t *tmp = NULL;
        if (mask->elems) {
            tmp = mem_realloc(mask->elems, elems_needed * sizeof(*tmp));
            if (tmp) {
                memset(tmp + mask->elem_count, 0,
                       (elems_needed - mask->elem_count) * sizeof(*tmp));
            }
        } else {
            tmp = mem_calloc(elems_needed, sizeof(*tmp));
        }
        if (!tmp) {
            LOG_ERROR("Cannot (re)allocate mask elements");
            rc = -1;
        }
        mask->elems = tmp;
        ++mask->elem_count;
    }
    RC_CHECK(rc, out);
    size_t elem_pos = bit / mask_elem_size_bits;
    if (bit > mask_elem_size_bits && bit % mask_elem_size_bits) {
        ++elem_pos;
    }
    unsigned previous = 0;
    /* get the previous value so that we can update the bits_set property */
    rc = sxpd_mask_get(mask, bit, &previous);
    RC_CHECK(rc, out);
    mask->bits_set += value - previous;
    if (value) {
        mask->elems[elem_pos] |= 1 << bit % mask_elem_size_bits;
    } else {
        mask->elems[elem_pos] &= ~(1 << bit % mask_elem_size_bits);
    }
out:
    return rc;
}

/**
 * @brief get the value of bit at position
 *
 * @param mask mask to get bit from
 * @param bit position of the bit
 * @param value where to store the value of the bit
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_mask_get(struct sxpd_mask *mask, size_t bit, unsigned *value)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, mask, value);
    RC_CHECK(rc, out);
    size_t elem_pos = bit / mask_elem_size_bits;
    if (bit > mask_elem_size_bits && bit % mask_elem_size_bits) {
        ++elem_pos;
    }
    if (elem_pos >= mask->elem_count) {
        /* if the bit is not stored, it means its not set */
        *value = 0;
    } else {
        if (mask->elems[elem_pos] & (1 << bit % mask_elem_size_bits)) {
            *value = 1;
        } else {
            *value = 0;
        }
    }
out:
    return rc;
}

/** size of buffer handed out by sxpd_buffer_get function */
#define SXPD_BUFFER_SIZE (SXP_MAX_MSG_LENGTH)

/**
 * struct used for temporary storage of sxp messages
 */
struct sxpd_buffer {
    union {
        /** memory for storing data */
        uint8_t data[SXPD_BUFFER_SIZE];
        /** convenience access for data as sxp_msg */
        struct sxp_msg msg;
    } u;

    /** actual size of data stored in data */
    size_t size;
};

/**
 * buffer wrapper struct to store unused buffers in linked list
 */
struct sxpd_buffer_wrapper {
    /** next buffer in the linked list */
    struct sxpd_buffer_wrapper *next;
    struct sxpd_buffer data;
};

/**
 * @brief get an unused buffer or allocate a new buffer
 *
 * @param ctx sxpd context to operate on
 *
 * @return buffer pointer or NULL if cannot allocate
 */
static struct sxpd_buffer *sxpd_allocate_buffer(struct sxpd_ctx *ctx)
{
    int rc = 0;

    struct sxpd_buffer *result = 0;

    PARAM_NULL_CHECK(rc, ctx);
    if (RC_ISOK(rc)) {
        if (ctx->buffer_pool) {
            struct sxpd_buffer_wrapper *tmp = ctx->buffer_pool;
            ctx->buffer_pool = ctx->buffer_pool->next;
            tmp->next = NULL;
            memset(&tmp->data, 0, sizeof(tmp->data));
            result = &tmp->data;
        } else {
            struct sxpd_buffer_wrapper *tmp = mem_calloc(1, sizeof(*tmp));
            result = &tmp->data;
        }
    }

    return result;
}

/**
 * @brief return buffer to buffer pool after usage
 *
 * @param ctx sxpd context to operate on
 * @param data buffer pointer to return
 */
static void sxpd_release_buffer(struct sxpd_ctx *ctx, struct sxpd_buffer *data)
{
    if (data) {
        struct sxpd_buffer_wrapper *wrapper =
            (struct sxpd_buffer_wrapper *)((char *)data -
                                           offsetof(struct sxpd_buffer_wrapper,
                                                    data));
        if (ctx) {
            wrapper->next = ctx->buffer_pool;
            ctx->buffer_pool = wrapper;
        } else {
            mem_free(wrapper);
        }
    }
}

static int sxpd_uncontribute_binding(struct sxpd_ctx *ctx, enum ip_type type,
                                     struct sxpd_binding *b,
                                     const struct v4_v6_prefix *prefix,
                                     bool *binding_was_selected);

static int sxpd_export_bindings(struct sxpd_ctx *ctx);

/**
 * @brief swap the message to network byte order and send it to sxp peer
 *
 * @param peer peer to send the message to
 * @param socket socket to send the message on
 * @param buff buffer containing the message
 * @param write_failed flag set if the message couldn't be set due to socket
 *buffer being full
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_send_msg(struct sxpd_peer *peer, struct evmgr_socket *socket,
                         struct sxpd_buffer *buff, bool *write_failed)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, buff, peer, socket, write_failed);
    RC_CHECK(rc, out);
    PLOG_TRACE_FMT(peer, "Sending %s message",
                   sxp_msg_type_string(buff->u.msg.type));
    enum sxp_error_code code = SXP_ERR_CODE_NONE;
    enum sxp_error_sub_code subcode = SXP_SUB_ERR_CODE_NONE;
    RC_CHECK(rc = sxp_hbo_pretty_print_msg(&buff->u.msg, &code, &subcode), out);
    if (sxp_isnotok(rc, code, subcode)) {
        rc = -1;
        goto out;
    }
    RC_CHECK(rc = sxp_msg_hton_swap(&buff->u.msg, &code, &subcode), out);
    if (sxp_isnotok(rc, code, subcode)) {
        rc = -1;
        goto out;
    }
    if (RC_ISNOTOK(evmgr_socket_write(socket, buff->u.data, buff->size))) {
        PLOG_DEBUG_FMT(peer, "Could not send message %s",
                       sxp_msg_type_string(ntohl(buff->u.msg.type)));
        *write_failed = true;
    }
out:
    return rc;
}

/**
 * create and send an error message to peer, the error message format/content is
 *based on the peer's advertised sxp version
 *
 * @param peer peer to send the message to
 * @param socket socket to send the message on
 * @param err_attr attribute which caused the error (may be NULL)
 * @param error error code to put in the message
 * @param sub_error error sub-code to put in the message
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_send_error(struct sxpd_peer *peer, struct evmgr_socket *socket,
                           struct sxp_attribute *err_attr,
                           enum sxp_error_code error,
                           enum sxp_error_sub_code sub_error)
{
    int rc = 0;
    struct sxpd_buffer buff;
    memset(&buff, 0, sizeof(buff));
    PARAM_NULL_CHECK(rc, peer, socket);
    RC_CHECK(rc, out);
    if (!error && !sub_error) {
        PLOG_ERROR_MSG(
            peer, "Internal error, sending error without error or sub-error");
        rc = -1;
    }
    RC_CHECK(rc, out);
    if (peer->version <= 2) {
        rc = sxp_create_error_basic(buff.u.data, sizeof(buff.u.data),
                                    SXP_NON_EXT_ERR_CODE_MESSAGE_PARSE_ERROR);
    } else {
        rc = sxp_create_error_extended(buff.u.data, sizeof(buff.u.data), error,
                                       sub_error, err_attr);
    }
    RC_CHECK(rc, out);
    buff.size = buff.u.msg.length;
    bool write_failed = false;
    rc = sxpd_send_msg(peer, socket, &buff, &write_failed);
    if (RC_ISOK(rc) && write_failed) {
        rc = -1;
    }
out:
    return rc;
}

static int sxpd_connect_peer(struct sxpd_peer *peer);

/**
 * @brief create OPEN message
 *
 * @param peer peer to create the message for
 * @param buffer buffer to hold the message
 * @param size space available in buffer
 *
 * @return 0 on success, -1 on error
 */
static int sxpd_create_open_msg(struct sxpd_peer *peer, void *buffer,
                                size_t size)
{
    int rc = 0;
    uint16_t min_hold_time = KEEPALIVE_UNUSED;
    uint16_t max_hold_time = KEEPALIVE_UNUSED;
    PARAM_NULL_CHECK(rc, peer, buffer);
    RC_CHECK(rc, out);

    enum sxp_mode mode = SXP_MODE_SPEAKER;
    switch (peer->type) {
    case PEER_SPEAKER:
        /* if the other end is speaker, then we're the listener */
        mode = SXP_MODE_LISTENER;
        min_hold_time = peer->sxpd_ctx->listener_min_hold_time;
        max_hold_time = peer->sxpd_ctx->listener_max_hold_time;
        break;

    case PEER_BOTH:
        /* if the mode is both, then listener side initiates connection */
        mode = SXP_MODE_LISTENER;
        min_hold_time = peer->sxpd_ctx->listener_min_hold_time;
        max_hold_time = peer->sxpd_ctx->listener_max_hold_time;
        break;

    case PEER_LISTENER:
        /* if the other end is listener, then we're the speaker */
        mode = SXP_MODE_SPEAKER;
        min_hold_time = peer->sxpd_ctx->speaker_min_hold_time;
        break;
    }

/* rfc draft says that Node-ID has to be included only by the speaker */
#ifdef TESTING
    if (2 < peer->sxpd_ctx->version && SXP_MODE_SPEAKER == mode) {
#else
    if (SXP_MODE_SPEAKER == mode) {
#endif
        rc = sxp_create_open_v4(buffer, size, mode, peer->sxpd_ctx->node_id);

    } else {
        rc = sxp_create_open_v4(buffer, size, mode, 0);
#ifdef TESTING
        if (RC_ISOK(rc) && 2 >= peer->sxpd_ctx->version) {
            ((uint32_t *)(buffer))[2] = (peer->sxpd_ctx->version);
            goto out;
        }
#endif
    }
    RC_CHECK(rc, out);

    if (SXP_MODE_LISTENER == mode) {
        struct sxp_attribute *caps = NULL;
        RC_CHECK(rc = sxp_msg_add_capabilities(buffer, size, &caps), out);

        rc = sxp_capabilities_add_capability(buffer, size, caps,
                                             SXP_CAPABILITY_IPV4_UNICAST);
        RC_CHECK(rc, out);

        rc = sxp_capabilities_add_capability(buffer, size, caps,
                                             SXP_CAPABILITY_IPV6_UNICAST);
        RC_CHECK(rc, out);

        rc = sxp_capabilities_add_capability(buffer, size, caps,
                                             SXP_CAPABILITY_SUBNET_BINDINGS);
        RC_CHECK(rc, out);
    }

    if (KEEPALIVE_UNUSED != min_hold_time) {
        rc = sxp_msg_add_hold_time(buffer, size, min_hold_time, max_hold_time);
    }
out:
    return rc;
}

/**
 * @brief create OPEN_RESP message
 *
 * @param peer peer to create the message for
 * @param buffer buffer to hold the message
 * @param size space available in buffer
 */
static int sxpd_create_open_resp_msg(struct sxpd_peer *peer, void *buffer,
                                     size_t size)
{
    int rc = 0;
    uint16_t min_hold_time = KEEPALIVE_UNUSED;
    uint16_t max_hold_time = KEEPALIVE_UNUSED;
    PARAM_NULL_CHECK(rc, peer, buffer);
    RC_CHECK(rc, out);
    enum sxp_mode mode = SXP_MODE_SPEAKER;
    switch (peer->type) {
    case PEER_SPEAKER:
        /* if the other end is speaker, then we're the listener */
        mode = SXP_MODE_LISTENER;
        min_hold_time = peer->sxpd_ctx->listener_min_hold_time;
        max_hold_time = peer->sxpd_ctx->listener_max_hold_time;
        PLOG_TRACE_FMT(peer, "Including minimum hold-time value %" PRIu16,
                       min_hold_time);
        if (KEEPALIVE_UNUSED != max_hold_time) {
            PLOG_TRACE_FMT(peer, "Including maximum hold-time value %" PRIu16,
                           max_hold_time);
        }
        break;

    case PEER_BOTH:
        /* if the mode is both, then listener side initiates connection,
         * so when answering, we're the speaker */
        mode = SXP_MODE_SPEAKER;
        min_hold_time = peer->sxpd_ctx->speaker_min_hold_time;
        PLOG_TRACE_FMT(peer, "Including minimum hold-time value %" PRIu16,
                       min_hold_time);
        break;

    case PEER_LISTENER:
        /* if the other end is listener, then we're the speaker */
        mode = SXP_MODE_SPEAKER;
        min_hold_time = peer->sxpd_ctx->speaker_min_hold_time;
        PLOG_TRACE_FMT(peer, "Including minimum hold-time value %" PRIu16,
                       min_hold_time);
        break;
    }
#ifdef TESTING
    if (1 == peer->sxpd_ctx->version) {
        rc = sxp_create_open_resp(buffer, size, 1, mode, 0);
        goto out;
    } else if (2 == peer->sxpd_ctx->version) {
        rc = sxp_create_open_resp(buffer, size, 2, mode, 0);
        goto out;
    } else
#endif
        if (peer->version > 2 && SXP_MODE_SPEAKER == mode) {
        rc = sxp_create_open_resp(buffer, size, peer->version, mode,
                                  peer->sxpd_ctx->node_id);
    } else {
        rc = sxp_create_open_resp(buffer, size, peer->version, mode, 0);
    }
    RC_CHECK(rc, out);

    if (peer->version < 3) {
        goto out;
    }

    if (SXP_MODE_LISTENER == mode) {
        struct sxp_attribute *caps = NULL;
        RC_CHECK(rc = sxp_msg_add_capabilities(buffer, size, &caps), out);

        rc = sxp_capabilities_add_capability(buffer, size, caps,
                                             SXP_CAPABILITY_IPV4_UNICAST);
        RC_CHECK(rc, out);

        rc = sxp_capabilities_add_capability(buffer, size, caps,
                                             SXP_CAPABILITY_IPV6_UNICAST);
        RC_CHECK(rc, out);

        rc = sxp_capabilities_add_capability(buffer, size, caps,
                                             SXP_CAPABILITY_SUBNET_BINDINGS);
        RC_CHECK(rc, out);
    }
    rc = sxp_msg_add_hold_time(buffer, size, min_hold_time, max_hold_time);
    RC_CHECK(rc, out);

out:
    return rc;
}

/**
 * @brief create and send open message to peer
 *
 * @param peer peer to send the message to
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_send_open(struct sxpd_peer *peer)
{
    int rc = 0;
    struct sxpd_buffer buff;
    memset(&buff, 0, sizeof(buff));
    PARAM_NULL_CHECK(rc, peer);
    RC_CHECK(rc, out);
    if (!peer->outgoing) {
        PLOG_ERROR_MSG(
            peer, "Attempt to send OPEN message without outgoing connection");
        rc = -1;
    }
    RC_CHECK(rc, out);
    rc = sxpd_create_open_msg(peer, buff.u.data, sizeof(buff.u.data));
    RC_CHECK(rc, out);

    buff.size = buff.u.msg.length;
    bool write_failed = false;
    rc = sxpd_send_msg(peer, peer->outgoing, &buff, &write_failed);
    if (RC_ISOK(rc) && write_failed) {
        rc = -1;
    }

    if (RC_ISOK(rc)) {
        PEER_CHANGE_OUT_CONN_STATE(peer, WAITING_OPEN_RESP);
    } else {
        PEER_CHANGE_OUT_CONN_STATE(peer, ERROR_CONNECT);
    }
out:
    return rc;
}

/**
 * @brief called in the event when listener gets disconnected
 *
 * function
 * -# removes the listener from expanding listeners list (if applicable)
 * -# flags all IPv4 and IPv6 bindings as not advertised to this listener
 * -# decreases the connected listener count
 *
 * @param peer listener which is disconnected
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_listener_disconnected(struct sxpd_peer *peer)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, peer);
    RC_CHECK(rc, out);
    if (!peer->flags.sub_bind) {
        peer->sxpd_ctx->expanding_listeners[peer->expansion_index] = NULL;
    }
    struct radix_node *node = NULL;
    for (;;) {
        rc = radix_iterate(peer->sxpd_ctx->master_bindings_v4, node, &node);
        RC_CHECK(rc, out);
        if (!node) {
            break;
        }
        struct sxpd_binding_list *b = NULL;
        void *value = NULL;
        RC_CHECK(rc = radix_parse_node(node, NULL, 0, NULL, &value), out);
        b = value;
        RC_CHECK(rc = sxpd_mask_set(&b->mask, peer->listener_bit_pos, 0), out);
    }
    node = NULL;
    for (;;) {
        rc = radix_iterate(peer->sxpd_ctx->master_bindings_v6, node, &node);
        RC_CHECK(rc, out);
        if (!node) {
            break;
        }
        struct sxpd_binding_list *b = NULL;
        void *value = NULL;
        RC_CHECK(rc = radix_parse_node(node, NULL, 0, NULL, &value), out);
        b = value;
        RC_CHECK(rc = sxpd_mask_set(&b->mask, peer->listener_bit_pos, 0), out);
    }
    --peer->sxpd_ctx->connected_listener_count;
out:
    return rc;
}

/**
 * @brief helper function for deleting all bindings, frees the binding and
 *signals to the radix tree to remove it from the tree
 *
 * @param node radix node
 * @param ctx unused parameter
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_delete_all_bindings_helper(struct radix_node *node,
                                           __attribute__((unused)) void *ctx)
{
    void *value = NULL;
    if (RC_ISOK(radix_parse_node(node, NULL, 0, NULL, &value))) {
        sxpd_destroy_binding(value);
    }
    return 1;
}

/**
 * @brief delete all bindings from a peer of given type
 *
 * @param[in] peer peer to remove all bindings from
 * @param[in] type ipv4 or ipv6
 * @param[out] need_export flag set to true, if an export is needed to keep
 *other peers up to date
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_peer_delete_all_bindings(struct sxpd_peer *peer,
                                         enum ip_type type, bool *need_export)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, peer, need_export);
    RC_CHECK(rc, out);
    struct radix_node *node = NULL;
    struct radix_tree *tree = NULL;
    if (V4 == type) {
        PLOG_TRACE_MSG(peer, "Deleting all v4 bindings");
        tree = peer->bindings_v4;
    } else {
        PLOG_TRACE_MSG(peer, "Deleting all v6 bindings");
        tree = peer->bindings_v6;
    }
    *need_export = false;
    for (;;) {
        RC_CHECK(rc = radix_iterate(tree, node, &node), out);
        if (!node) {
            break;
        }
        struct v4_v6_prefix prefix = { 0, { { 0 } } };
        void *v = NULL;
        rc = radix_parse_node(node, prefix.ip.data, sizeof(prefix.ip.data),
                              &prefix.len, &v);
        RC_CHECK(rc, out);
        struct sxpd_binding *b = v;
        bool binding_was_selected = true;
        rc = sxpd_uncontribute_binding(peer->sxpd_ctx, type, b, &prefix,
                                       &binding_was_selected);
        RC_CHECK(rc, out);
        if (binding_was_selected) {
            *need_export = true;
        }
    }
    rc = radix_delete_matching(tree, sxpd_delete_all_bindings_helper, NULL);
out:
    return rc;
}

/**
 * @brief callback called when delete-hold-down timer expires
 *
 * @startuml
 * participant "event manager" as evmgr
 * participant "sxp daemon" as sxpd
 * participant "peer" as peer
 * database "peer v4 bindings database" as peerdb4
 * database "master v4 bindings database" as masterdb4
 * database "peer v6 bindings database" as peerdb6
 * database "master v6 bindings database" as masterdb6
 * evmgr->sxpd: delete-hold-down timer expired (sxpd_delete_hold_down_callback)
 * sxpd->peer: delete all v4 bindings (sxpd_peer_delete_all_bindings)
 * loop for each v4 binding
 * peer->masterdb4: uncontribute binding (sxpd_uncontribute_binding)
 * masterdb4->peer: response indicating whether the binding was selected
 * end
 * peer->peerdb4: delete all v4 bindings
 * sxpd->peer: delete all v6 bindings (sxpd_peer_delete_all_bindings)
 * loop for each v6 binding
 * peer->masterdb6: uncontribute binding (sxpd_uncontribute_binding)
 * masterdb6->peer: response indicating whether the binding was selected
 * end
 * peer->peerdb6: delete all v6 bindings
 * alt if some bindings were selected
 * peer->sxpd: export bindings (sxpd_export_bindings)
 * end
 *
 * @enduml
 *
 * @param timer expired timer
 * @param ctx context supplied when setting up the timer
 */
static void sxpd_delete_hold_down_callback(struct evmgr_timer *timer, void *ctx)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, timer, ctx);
    RC_CHECK(rc, out);
    struct sxpd_peer *peer = ctx;
    PLOG_TRACE_MSG(peer, "Delete hold down timer fires");
    bool need_export_v4 = false;
    bool need_export_v6 = false;
    rc = sxpd_peer_delete_all_bindings(peer, V4, &need_export_v4);
    if (RC_ISOK(rc)) {
        rc = sxpd_peer_delete_all_bindings(peer, V6, &need_export_v6);
    }
    if (RC_ISNOTOK(rc)) {
        PLOG_ERROR_MSG(peer, "Deleting all bindings failed");
    } else if (need_export_v4 || need_export_v6) {
        rc = sxpd_export_bindings(peer->sxpd_ctx);
        if (RC_ISNOTOK(rc)) {
            PLOG_ERROR_MSG(peer, "Exporting bindings failed");
        }
    }
out:
    return;
}

/**
 * @brief setup and start delete hold down timer for given peer
 *
 * @param peer peer to set the timer for
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_peer_setup_delete_hold_down_timer(struct sxpd_peer *peer)
{
    static struct timeval delete_hold_down_time = {.tv_sec = 120,
                                                   .tv_usec = 0 };

    PLOG_TRACE_MSG(peer, "Setting up hold down timer");
    int rc = 0;

    PARAM_NULL_CHECK(rc, peer);
    RC_CHECK(rc, out);

    if (!peer->delete_hold_down_timer) {
        peer->delete_hold_down_timer = evmgr_timer_create(
            peer->sxpd_ctx->evmgr, peer->sxpd_ctx->evmgr_settings,
            &delete_hold_down_time, false, sxpd_delete_hold_down_callback,
            peer);
        if (!peer->delete_hold_down_timer) {
            PLOG_ERROR_MSG(peer, "Cannot create delete hold down timer!");
            rc = -1;
            goto out;
        }
    }

    rc = evmgr_timer_arm(peer->delete_hold_down_timer);
out:
    return rc;
}

/**
 * @brief called when a speaker is disconnected
 *
 * @param peer speaker which is disconnected
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_speaker_disconnected(struct sxpd_peer *peer)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, peer);
    RC_CHECK(rc, out);
    RC_CHECK(rc = sxpd_peer_setup_delete_hold_down_timer(peer), out);
    if (peer->reconciliation_timer) {
        PLOG_TRACE_MSG(peer, "Cancel reconciliation timer");
        evmgr_timer_destroy(peer->reconciliation_timer);
        peer->reconciliation_timer = NULL;
    }
    RC_CHECK(rc = sxpd_export_bindings(peer->sxpd_ctx), out);
out:
    return rc;
}

/**
 * @brief remove socket from peer structure and trigger events based on the
 *removal
 * function removes all references to a given socket from a given peer
 *structure, freeing any buffers if applicable and based on whether the socket
 *is speaker/listener socket, triggers the appropriate 'disconnected' events
 *
 * @param peer peer to remove the socket from
 * @param socket socket to remove
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_clear_peer_sockets(struct sxpd_peer *peer,
                                   struct evmgr_socket *socket)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, peer, socket);
    RC_CHECK(rc, out);
    bool match = false;
    bool speaker_disconnected = false;
    bool listener_disconnected = false;
    const char *str1 = "";
    const char *str2 = "";
    const char *str3 = "";
    const char *str4 = "";

    if (socket == peer->incoming) {
        str3 = "[incoming]";
        match = true;
        peer->incoming = NULL;
        peer->flags.incoming_negotiation_done = false;
        sxpd_release_buffer(peer->sxpd_ctx, peer->incoming_in_buffer);
        peer->incoming_in_buffer = NULL;
    }

    if (socket == peer->outgoing) {
        str4 = "[outgoing]";
        match = true;
        peer->outgoing = NULL;
        sxpd_release_buffer(peer->sxpd_ctx, peer->outgoing_in_buffer);
        peer->outgoing_in_buffer = NULL;
        PEER_CHANGE_OUT_CONN_STATE(peer, NONE);
    }

    if (socket == peer->speaker) {
        str1 = "[speaker]";
        match = true;
        peer->speaker = NULL;
        evmgr_timer_destroy(peer->hold_timer);
        peer->hold_timer = NULL;
        speaker_disconnected = true;
    }

    if (socket == peer->listener) {
        str2 = "[listener]";
        match = true;
        peer->listener = NULL;
        evmgr_timer_destroy(peer->keepalive_timer);
        peer->keepalive_timer = NULL;
        listener_disconnected = true;
    }

    if (match) {
        PLOG_TRACE_FMT(peer, "Disconnect %s%s%s%s connection socket %p", str1,
                       str2, str3, str4, (void *)socket);
    }
    if (speaker_disconnected) {
        RC_CHECK(rc = sxpd_speaker_disconnected(peer), out);
    }
    if (listener_disconnected) {
        RC_CHECK(rc = sxpd_listener_disconnected(peer), out);
    }

out:
    return rc;
}

/**
 * @brief destroy socket once all data has been flushed and socket is writable
 * again
 */
static void sxpd_socket_disconnect_writeable_cb(struct evmgr_socket *socket,
                                                void __attribute__((unused)) *
                                                    callback_ctx)
{
    LOG_DEBUG("Socket %p marked for disconnect is writable - destroy socket",
              (void *)socket);
    evmgr_socket_destroy(socket);
}

/**
 * @brief event on socket marked for disconnecting - destroy the socket if its
 * an error, otherwise ignore
 */
static void
sxpd_socket_disconnect_event_cb(struct evmgr_socket *socket, int16_t event_bits,
                                void __attribute__((unused)) * callback_ctx)
{
    bool is_error = false;
    const char *eof = "";
    if (event_bits & EVMGR_SOCK_EVENT_EOF) {
        eof = " EOF";
        is_error = true;
    }

    const char *read = "";
    if (event_bits & EVMGR_SOCK_EVENT_READING) {
        read = " READ";
    }

    const char *write = "";
    if (event_bits & EVMGR_SOCK_EVENT_WRITING) {
        write = " WRITE";
    }

    const char *error = "";
    if (event_bits & EVMGR_SOCK_EVENT_ERROR) {
        error = " ERROR";
        is_error = true;
    }

    const char *conn = "";
    if (event_bits & EVMGR_SOCK_EVENT_CONNECTED) {
        conn = " CONNECTED";
    }

    const char *timeout = "";
    if (event_bits & EVMGR_SOCK_EVENT_TIMEOUT) {
        timeout = " TIMEOUT";
        is_error = true;
    }

    LOG_DEBUG("Event on socket %p marked for disconnecting:%s%s%s%s%s%s",
              (void *)socket, read, write, eof, conn, error, timeout);

    if (is_error) {
        evmgr_socket_destroy(socket);
    }
}

/**
 * @brief disconnect peer's socket
 *
 * @param peer peer to disconnect the socket from
 * @param socket socket to disconnect
 * @param immediate_disconnect if true, the socket is destroyed right away,
 *otherwise the socket destruction is deferred until all data has been flushed
 *to the socket
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_disconnect_peer_socket(struct sxpd_peer *peer,
                                       struct evmgr_socket *socket,
                                       bool immediate_disconnect)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, peer, socket);
    RC_CHECK(rc, out);
    rc = sxpd_clear_peer_sockets(peer, socket);
    if (immediate_disconnect) {
        evmgr_socket_destroy(socket);
        socket = NULL;
    } else {
        /* deferred destroy - wait until socket is writable */
        rc = evmgr_socket_cb_register(socket, NULL,
                                      sxpd_socket_disconnect_writeable_cb,
                                      sxpd_socket_disconnect_event_cb, NULL);
    }
out:
    if (RC_ISNOTOK(rc)) {
        /* in case of failure just destroy the socket */
        evmgr_socket_destroy(socket);
    }
    return rc;
}

/**
 * @brief return the number of active connections for peer
 *
 * @param peer peer to operate on
 *
 * @return number of connections
 */
static size_t sxpd_peer_connections_active(struct sxpd_peer *peer)
{
    if (peer) {
        if (peer->incoming) {
            if (peer->outgoing && peer->incoming != peer->outgoing) {
                return 2;
            } else {
                return 1;
            }
        } else if (peer->outgoing) {
            return 1;
        }
    }

    return 0;
}

/**
 * @brief return the number of connections that are connected and OPEN/OPEN_RESP
 * negotiation is done
 *
 * @param peer peer to operate on
 *
 * @return number of connections
 */
static size_t sxpd_peer_connections_connected(struct sxpd_peer *peer)
{
    if (peer) {
        if (peer->incoming) {
            if (peer->outgoing && peer->outgoing_state == CONNECTED &&
                peer->incoming != peer->outgoing) {
                return 2;
            } else {
                return 1;
            }
        } else if (peer->outgoing && peer->outgoing_state == CONNECTED) {
            return 1;
        }
    }

    return 0;
}

/**
 * @brief return the number of connections that should be up during normal
 *circumstances
 *
 * @param peer peer to operate on
 *
 * @return number of connections
 */
static size_t sxpd_peer_connections_needed(struct sxpd_peer *peer)
{
    if (peer) {
        if (PEER_BOTH == peer->type) {
            return 2;
        } else {
            return 1;
        }
    }

    return 0;
}

/**
 * @brief retry timer callback
 *
 * @startuml
 * participant "event manager" as evmgr
 * participant "sxp daemon" as sxpd
 * participant "peer" as peer
 * evmgr->sxpd: retry-timer expired (sxpd_retry_timer_callback)
 * sxpd->peer: check the number of connections needed
 * alt need more connections
 * sxpd->peer: connect peer (sxpd_connect_peer)
 * end
 * @enduml
 *
 * @param timer timer which expired
 * @param ctx context supplied when creating the timer
 */
static void sxpd_retry_timer_callback(struct evmgr_timer *timer, void *ctx)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, timer, ctx);
    struct sxpd_peer *peer = ctx;
    RC_CHECK(rc, out);
    PLOG_TRACE_MSG(peer, "Retry timer fires");
    if (CONNECT_RETRY_TIMER == peer->outgoing_state) {
        if (sxpd_peer_connections_needed(peer) >
            sxpd_peer_connections_active(peer)) {
            rc = sxpd_connect_peer(peer);
            if (RC_ISNOTOK(rc)) {
                PLOG_ERROR_MSG(peer, "Connecting peer failed");
            }
        } else {
            PLOG_DEBUG_FMT(
                peer, "Not connecting peer, %zu active connection(s) is enough",
                sxpd_peer_connections_active(peer));
            PEER_CHANGE_OUT_CONN_STATE(peer, NONE);
        }
    } else {
        PLOG_ERROR_MSG(peer, "Unexpected timer event");
    }
out:
    return;
}

/**
 * @brief schedule and arm a retry timer
 *
 * @param peer peer to schedule the retry for
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_schedule_connect_retry(struct sxpd_peer *peer)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, peer);
    RC_CHECK(rc, out);

    if (!peer->retry_timer) {
        peer->retry_timer = evmgr_timer_create(
            peer->sxpd_ctx->evmgr, peer->sxpd_ctx->evmgr_settings,
            &peer->sxpd_ctx->retry_timeout, false, sxpd_retry_timer_callback,
            peer);
        if (!peer->retry_timer) {
            PLOG_ERROR_MSG(peer, "Cannot create retry timer!");
            rc = -1;
            goto out;
        }
    }

    rc = evmgr_timer_arm(peer->retry_timer);
    PEER_CHANGE_OUT_CONN_STATE(peer, CONNECT_RETRY_TIMER);

out:
    return rc;
}

/**
 * @brief disconnect socket for given peer in case of error
 *
 * @param peer peer to disconnect socket for
 * @param socket socket to disconnect
 * @param immediate_disconnect if true, the socket is destroyed right away,
 *otherwise the socket destruction is deferred until all data has been flushed
 *to the socket
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_error_disconnect_peer(struct sxpd_peer *peer,
                                      struct evmgr_socket *socket,
                                      bool immediate_disconnect)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, peer, socket);
    RC_CHECK(rc, out);
    bool outgoing_disconnected = false;
    if (socket == peer->outgoing) {
        outgoing_disconnected = true;
    }
    rc = sxpd_disconnect_peer_socket(peer, socket, immediate_disconnect);
    RC_CHECK(rc, out);
    if ((outgoing_disconnected || !peer->outgoing) &&
        (sxpd_peer_connections_active(peer) <
         sxpd_peer_connections_needed(peer))) {
        /* if disconnecting outgoing connection due to an error, or if there is
         * no outgoing connection and another connection is needed, then
         * schedule a retry timer */
        RC_CHECK(rc = sxpd_schedule_connect_retry(peer), out);
    }
out:
    return rc;
}

/**
 * @brief create and send purge all message to peer
 *
 * @param peer peer to send the message to
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_send_purge_all(struct sxpd_peer *peer)
{
    int rc = 0;
    struct sxpd_buffer buffer;
    enum sxp_error_code code = SXP_ERR_CODE_NONE;
    enum sxp_error_sub_code subcode = SXP_SUB_ERR_CODE_NONE;
    memset(&buffer, 0, sizeof(buffer));
    PARAM_NULL_CHECK(rc, peer);
    if (RC_ISOK(rc)) {
        rc = sxp_create_purge_all(buffer.u.data, sizeof(buffer.u.data));
    }
    if (RC_ISOK(rc)) {
        buffer.size = buffer.u.msg.length;
        rc = sxp_hbo_pretty_print_msg(&buffer.u.msg, &code, &subcode);
    }
    if (sxp_isok(rc, code, subcode)) {
        rc = sxp_msg_hton_swap(&buffer.u.msg, &code, &subcode);
    }
    if (sxp_isok(rc, code, subcode)) {
        rc = evmgr_socket_write(peer->listener, buffer.u.data, buffer.size);
    }
    if (sxp_isnotok(rc, code, subcode)) {
        rc = sxpd_error_disconnect_peer(peer, peer->listener, false);
    }
    return rc;
}

/**
 * @brief create and send keep-alive message to peer
 *
 * @param peer peer to send the message to
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_send_keepalive(struct sxpd_peer *peer)
{
    int rc = 0;
    struct sxpd_buffer buffer;
    memset(&buffer, 0, sizeof(buffer));
    PARAM_NULL_CHECK(rc, peer);
    RC_CHECK(rc, out);
    RC_CHECK(rc = sxp_create_keepalive(buffer.u.data, sizeof(buffer.u.data)),
             out);
    buffer.size = buffer.u.msg.length;
    bool write_failed = false;
    rc = sxpd_send_msg(peer, peer->listener, &buffer, &write_failed);
    RC_CHECK(rc, out);
    if (write_failed) {
        rc = sxpd_error_disconnect_peer(peer, peer->listener, false);
    }
out:
    return rc;
}

static int sxpd_peer_setup_keepalive_timer(struct sxpd_peer *peer);

/**
 * @brief keep-alive timer callback
 *
 * @startuml
 * participant "event manager" as evmgr
 * participant "sxp daemon" as sxpd
 * participant "sxpd peer" as speer
 * actor "peer" as apeer
 * evmgr->sxpd: keep-alive timer expired (sxpd_keepalive_timer_callback)
 * sxpd->speer: send keep-alive message (sxpd_send_keepalive)
 * speer->evmgr: write keep-alive to socket (evmgr_socket_write)
 * alt sending data failed
 *   speer->speer: disconnect peer (sxpd_error_disconnect_peer)
 *   speer->evmgr: disconnect socket
 *   alt outgoing socket disconnect and another connection is needed
 *     speer->speer: schedule retry timer (sxpd_schedule_connect_retry)
 *     speer->evmgr: create retry timer (evmgr_timer_create)
 *     speer->evmgr: arm retry timer (evmgr_timer_arm)
 *   end
 * else sending data succeeded
 *   evmgr->apeer: keep-alive message
 *   sxpd->speer: setup keep-alive timer (sxpd_peer_setup_keepalive_timer)
 *   speer->speer: calculate keep-alive value based on listener-hold-time\n\
 *   with random jitter (75%-100% * 1/3 * listener-hold-time)
 *   speer->evmgr: create keep-alive timer (evmgr_timer_create)
 *   speer->evmgr: arm keep-alive timer (evmgr_timer_arm)
 * end
 * @enduml
 *
 * @param timer expired timer
 * @param ctx context supplied when creating the timer
 */
static void sxpd_keepalive_timer_callback(struct evmgr_timer *timer, void *ctx)
{
    if (!ctx) {
        LOG_ERROR("Got keep-alive timer callback with NULL ctx - disarming");
        evmgr_timer_disarm(timer);
        return;
    }
    struct sxpd_peer *peer = ctx;
    PLOG_TRACE_MSG(peer, "Keep-alive timer fires");
    int rc = 0;
    rc = sxpd_send_keepalive(peer);
    if (RC_ISOK(rc)) {
        rc = sxpd_peer_setup_keepalive_timer(peer);
        if (RC_ISNOTOK(rc)) {
            PLOG_ERROR_MSG(peer, "Keep-alive timer setup failed");
        }
    }
}

/**
 * @brief callback called when hold timer expired
 */
static void sxpd_hold_timer_callback(struct evmgr_timer *timer, void *ctx)
{
    if (!ctx) {
        LOG_ERROR("Got hold timer callback with NULL ctx - disarming");
        evmgr_timer_disarm(timer);
        return;
    }
    struct sxpd_peer *peer = ctx;
    PLOG_TRACE_MSG(peer, "Hold timer fires");
    /* FIXME replace with the correct error code/subcode once these are known */
    int rc = sxpd_send_error(peer, peer->speaker, NULL, SXP_ERR_CODE_NONE,
                             SXP_SUB_ERR_CODE_UNACCEPTABLE_HOLD_TIME);
    if (RC_ISOK(rc)) {
        rc = sxpd_error_disconnect_peer(peer, peer->speaker, false);
        if (RC_ISNOTOK(rc)) {
            PLOG_ERROR_MSG(peer, "Disconnecting peer socket failed");
        }
    }
}

/**
 * @brief setup and arm keep-alive timer if needed
 *
 * @param peer peer to set the timer for
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_peer_setup_keepalive_timer(struct sxpd_peer *peer)
{
    int rc = 0;
    time_t seconds = 0;
    PARAM_NULL_CHECK(rc, peer);
    RC_CHECK(rc, out);
    if ((!peer->listener_hold_time ||
         KEEPALIVE_UNUSED == peer->listener_hold_time) &&
        (peer->sxpd_ctx->keepalive_timeout.tv_sec == KEEPALIVE_UNUSED)) {
        PLOG_TRACE_MSG(
            peer,
            "Not setting up keep-alive timer, keep-alive mechanism unused");
        goto out;
    }
    PLOG_TRACE_MSG(peer, "Setting up keep-alive timer");
    evmgr_timer_destroy(peer->keepalive_timer);
    peer->keepalive_timer = NULL;
    if (peer->sxpd_ctx->keepalive_timeout.tv_sec == KEEPALIVE_UNUSED) {
        seconds =
            (time_t)(((peer->listener_hold_time / (double)3) / (double)4) *
                     (3 + random_get() / (double)random_max));
        if (seconds < 1) {
            seconds = 1;
        }
    } else {
        seconds = peer->sxpd_ctx->keepalive_timeout.tv_sec;
    }

    struct timeval t = {.tv_sec = seconds, .tv_usec = 0 };
    peer->keepalive_timer = evmgr_timer_create(
        peer->sxpd_ctx->evmgr, peer->sxpd_ctx->evmgr_settings, &t, false,
        sxpd_keepalive_timer_callback, peer);
    if (NULL == peer->keepalive_timer) {
        PLOG_ERROR_MSG(peer, "Cannot create keep-alive timer");
        rc = -1;
    } else {
        rc = evmgr_timer_arm(peer->keepalive_timer);
        if (RC_ISNOTOK(rc)) {
            PLOG_ERROR_MSG(peer, "Cannot arm keep-alive timer");
        }
    }
out:
    return rc;
}

/**
 * @brief set all expansion track entries for a peer to zero
 *
 * @param peer peer to operate on
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_peer_reset_expansion(struct sxpd_peer *peer)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, peer);
    RC_CHECK(rc, out);
    struct radix_node *node = NULL;
    for (;;) {
        rc = radix_iterate(peer->sxpd_ctx->expand_entries_v4, node, &node);
        RC_CHECK(rc, out);
        if (!node) {
            break;
        }
        void *value = NULL;
        RC_CHECK(rc = radix_parse_node(node, NULL, 0, NULL, &value), out);
        struct sxpd_expansion_track_entry *et = value;
        RC_CHECK(rc = sxpd_mask_set(&et->mask, peer->expansion_index, 0), out);
    }
out:
    return rc;
}

/**
 * @brief called when listener is connected
 *
 * function
 * -# cancels retry timer if not needed anymore
 * -# sets up keep-alive timer if used
 * -# if the peer does not support subnet bindings, puts this peer into the
 *array
 *of listeners which require expanded bindings
 * -# sets callbacks for listener socket
 *
 * @param peer listener which got connected
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_listener_connected(struct sxpd_peer *peer)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, peer);
    RC_CHECK(rc, out);
    PLOG_TRACE_MSG(peer, "Listener connected");
    if (sxpd_peer_connections_needed(peer) <=
        sxpd_peer_connections_active(peer)) {
        LOG_TRACE("Cancel retry timer, %zu connection(s) is enough.",
                  sxpd_peer_connections_active(peer));
        evmgr_timer_destroy(peer->retry_timer);
        peer->retry_timer = NULL;
    }
    RC_CHECK(rc = sxpd_peer_setup_keepalive_timer(peer), out);
    if (!peer->flags.sub_bind) {
        bool have_expansion_index = false;
        size_t i = 0;
        for (i = 0; i < peer->sxpd_ctx->expanding_listener_count; ++i) {
            if (!peer->sxpd_ctx->expanding_listeners[i]) {
                PLOG_DEBUG_FMT(peer, "Reuse index %zu for expansion tracking",
                               i);
                peer->sxpd_ctx->expanding_listeners[i] = peer;
                peer->expansion_index = i;
                have_expansion_index = true;
                break;
            }
        }
        if (!have_expansion_index) {
            struct sxpd_peer **tmp = NULL;
            if (peer->sxpd_ctx->expanding_listeners) {
                tmp = mem_realloc(
                    peer->sxpd_ctx->expanding_listeners,
                    sizeof(*tmp) *
                        (peer->sxpd_ctx->expanding_listener_count + 1));
            } else {
                tmp = mem_calloc(1, sizeof(*tmp));
            }
            if (!tmp) {
                PLOG_ERROR_MSG(peer,
                               "Cannot (re)allocate expanding_listeners array");
                rc = -1;
                goto out;
            }
            peer->sxpd_ctx->expanding_listeners = tmp;
            peer->sxpd_ctx->expanding_listeners
                [peer->sxpd_ctx->expanding_listener_count] = peer;
            peer->expansion_index = peer->sxpd_ctx->expanding_listener_count;
            PLOG_DEBUG_FMT(peer, "Allocate index %zu for expansion tracking",
                           i);
            ++peer->sxpd_ctx->expanding_listener_count;
        }
        RC_CHECK(rc = sxpd_peer_reset_expansion(peer), out);
        RC_CHECK(rc = sxpd_expand_bindings(peer->sxpd_ctx), out);
    }
    ++peer->sxpd_ctx->connected_listener_count;
    rc = evmgr_socket_cb_register(peer->listener, sxpd_peer_read_callback,
                                  sxpd_peer_write_callback,
                                  sxpd_peer_event_callback, peer);
out:
    return rc;
}

/**
 * @brief create and arm hold timer for peer
 *
 * @param peer peer to setup the hold timer for
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_peer_setup_hold_timer(struct sxpd_peer *peer)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, peer);
    RC_CHECK(rc, out);
    PLOG_TRACE_MSG(peer, "Setting up hold timer");
    evmgr_timer_destroy(peer->hold_timer);
    peer->hold_timer = NULL;
    struct timeval t = { 0, 0 };
    if (PEER_SPEAKER == peer->type) {
        t.tv_sec = peer->speaker_hold_time;
    } else {
        t.tv_sec = peer->listener_hold_time;
    }
    if (!t.tv_sec) {
        LOG_ERROR(
            "Internal error, attempt to setup hold-timer with zero timeout");
        rc = -1;
        goto out;
    }
    peer->hold_timer = evmgr_timer_create(
        peer->sxpd_ctx->evmgr, peer->sxpd_ctx->evmgr_settings, &t, false,
        sxpd_hold_timer_callback, peer);
    if (NULL == peer->hold_timer) {
        PLOG_ERROR_MSG(peer, "Cannot create hold timer");
        rc = -1;
    } else {
        rc = evmgr_timer_arm(peer->hold_timer);
        if (RC_ISNOTOK(rc)) {
            PLOG_ERROR_MSG(peer, "Cannot arm hold timer");
        }
    }
out:
    return rc;
}

/**
 * @brief helper structure to pass peer and ip type when single void* context is
 * available
 */
struct binding_expire_helper {
    struct sxpd_peer *peer;
    enum ip_type type;
};

/**
 * @brief compare binding timestamp with reconciliation timestamp and return 1
 *if binding is expired
 *
 * @param node radix node which holds the binding
 * @param ctx context holding helper structure (peer, ip type)
 *
 * @return 1 if binding is expired, 0 if not
 */
static int sxpd_binding_is_expired(struct radix_node *node, void *ctx)
{
    if (!node || !ctx) {
        return 1;
    }
    struct v4_v6_prefix prefix = { 0, { { 0 } } };
    void *v = NULL;
    struct binding_expire_helper *helper = ctx;
    int rc = 0;
    rc = radix_parse_node(node, prefix.ip.data, sizeof(prefix.ip.data),
                          &prefix.len, &v);
    RC_CHECK(rc, error);
    struct sxpd_binding *b = v;
    int result = 0;
    rc = timestamp_cmp(b->timestamp, helper->peer->reconciliation_timestamp,
                       &result);
    if (RC_ISNOTOK(rc)) {
        PLOG_ERROR_FMT(helper->peer,
                       "Cannot compare reconciliation timestamp for binding %p",
                       (void *)b);
        /* something is wrong with this binding, throw it away */
        return 1;
    }
    if (result < 0) {
        if (V6 == helper->type) {
            PLOG_DEBUG_FMT(helper->peer,
                           "Deleting expired v6 binding " DEBUG_V6_FMT
                           "/%" PRIu8,
                           DEBUG_V6_PRINT(prefix.ip.v6), prefix.len);
        } else {
            PLOG_DEBUG_FMT(helper->peer,
                           "Deleting expired v4 binding " DEBUG_V4_FMT
                           "/%" PRIu8,
                           DEBUG_V4_PRINT(prefix.ip.v4), prefix.len);
        }
        bool binding_was_selected = false;
        rc = sxpd_uncontribute_binding(helper->peer->sxpd_ctx, helper->type, b,
                                       &prefix, &binding_was_selected);
        RC_CHECK(rc, error);
        sxpd_destroy_binding(b);

        return 1;
    }
error:
    return 0;
}

/**
 * @brief reconciliation timer callback
 *
 * @startuml
 * participant "event manager" as evmgr
 * participant "sxp daemon" as sxpd
 * participant "sxpd peer" as peer
 * database "v4 peer bindings database" as db4
 * database "v6 peer bindings database" as db6
 * database "v4 master bindings database" as mdb4
 * database "v6 master bindings database" as mdb6
 * evmgr->peer: reconciliation timer expired \
 * (sxpd_reconciliation_timer_callback)
 * peer->db4: delete expired bindings (radix_delete_matching)
 * loop for each binding
 * db4->db4: compare binding received timestamp vs reconciliation timestamp
 * alt binding is too old (expired)
 * db4->mdb4: uncontribute binding (sxpd_uncontribute_binding)
 * db4->db4: delete binding
 * end
 * end
 * peer->db6: delete expired bindings (radix_delete_matching)
 * loop for each binding
 * db6->db6: compare binding received timestamp vs reconciliation timestamp
 * alt binding is too old (expired)
 * db6->mdb6: uncontribute binding (sxpd_uncontribute_binding)
 * db6->db6: delete binding
 * end
 * end
 * peer->sxpd: export binding updates (sxpd_export_bindings)
 * @enduml
 *
 * @param timer expired timer
 * @param ctx context supplied when creating timer
 */
static void sxpd_reconciliation_timer_callback(struct evmgr_timer *timer,
                                               void *ctx)
{
    if (!ctx) {
        LOG_ERROR(
            "Got reconciliation timer callback with NULL ctx - disarming");
        evmgr_timer_disarm(timer);
        return;
    }
    struct sxpd_peer *peer = ctx;
    PLOG_TRACE_MSG(peer, "Reconciliation timer fires");
    struct binding_expire_helper helper = {.peer = peer, .type = V4 };
    PLOG_DEBUG_MSG(peer, "Removing expired v4 bindings");
    int rc = radix_delete_matching(peer->bindings_v4, sxpd_binding_is_expired,
                                   &helper);
    if (RC_ISOK(rc)) {
        helper.type = V6;
        PLOG_DEBUG_MSG(peer, "Removing expired v6 bindings");
        rc = radix_delete_matching(peer->bindings_v6, sxpd_binding_is_expired,
                                   &helper);
    }
    if (RC_ISOK(rc)) {
        PLOG_DEBUG_MSG(peer, "Removed all expired bindings");
        rc = sxpd_export_bindings(peer->sxpd_ctx);
        if (RC_ISNOTOK(rc)) {
            PLOG_ERROR_MSG(peer, "Bindings export failed");
        }
    } else {
        LOG_ERROR("Cannot delete expired bindings");
    }
}

/**
 * @brief create and arm reconciliation timer plus store current timestamp in
 *the peer as reconciliation timestamp
 *
 * @param peer peer to setup timer for
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_peer_setup_reconciliation_timer(struct sxpd_peer *peer)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, peer);
    RC_CHECK(rc, out);
    PLOG_TRACE_MSG(peer, "Setting up reconciliation timer");
    struct timestamp *stamp = get_timestamp();
    if (!stamp) {
        LOG_ERROR("Cannot get timestamp");
        rc = -1;
        goto out;
    }
    destroy_timestamp(peer->reconciliation_timestamp);
    peer->reconciliation_timestamp = stamp;
    evmgr_timer_destroy(peer->reconciliation_timer);
    peer->reconciliation_timer = evmgr_timer_create(
        peer->sxpd_ctx->evmgr, peer->sxpd_ctx->evmgr_settings,
        &peer->sxpd_ctx->reconciliation_timeout, false,
        sxpd_reconciliation_timer_callback, peer);
    if (!peer->reconciliation_timer) {
        PLOG_ERROR_MSG(peer, "Cannot create reconciliation timer");
        rc = -1;
    } else {
        rc = evmgr_timer_arm(peer->reconciliation_timer);
        if (RC_ISNOTOK(rc)) {
            PLOG_ERROR_MSG(peer, "Cannot arm reconciliation timer");
        }
    }
out:
    return rc;
}

/**
 * @brief called when speaker is connected
 *
 * -# cancels retry timer if not needed anymore
 * -# sets up hold timer if used
 * -# cancels delete hold-down-timer if used and sets up reconcitiliation timer
 *
 * @param peer speaker which is now connected
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_speaker_connected(struct sxpd_peer *peer)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, peer);
    RC_CHECK(rc, out);
    PLOG_TRACE_MSG(peer, "Speaker connected");
    if (sxpd_peer_connections_needed(peer) <=
        sxpd_peer_connections_active(peer)) {
        LOG_TRACE("Cancel retry timer, %zu connection(s) is enough.",
                  sxpd_peer_connections_active(peer));
        evmgr_timer_destroy(peer->retry_timer);
        peer->retry_timer = NULL;
    }
    if ((PEER_LISTENER != peer->type &&
         KEEPALIVE_UNUSED != peer->speaker_hold_time) ||
        (KEEPALIVE_UNUSED != peer->listener_hold_time)) {
        RC_CHECK(rc = sxpd_peer_setup_hold_timer(peer), out);
    } else {
        PLOG_TRACE_MSG(
            peer, "Not setting up hold timer - keep-alive mechanism is unused");
    }
    if (peer->delete_hold_down_timer) {
        PLOG_TRACE_MSG(peer, "Cancel hold down timer");
        RC_CHECK(rc = evmgr_timer_disarm(peer->delete_hold_down_timer), out);
        evmgr_timer_destroy(peer->delete_hold_down_timer);
        peer->delete_hold_down_timer = NULL;
        rc = sxpd_peer_setup_reconciliation_timer(peer);
    }
out:
    return rc;
}

/**
 * @brief create and send OPEN_RESP message to peer
 *
 * @param peer peer to send the message to
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_send_open_resp(struct sxpd_peer *peer)
{
    int rc = 0;
    struct sxpd_buffer buff;
    memset(&buff, 0, sizeof(buff));

    PARAM_NULL_CHECK(rc, peer);
    if (RC_ISOK(rc) && !peer->incoming) {
        PLOG_ERROR_MSG(
            peer,
            "Attempt to send OPEN_RESP message without incoming connection");
        rc = -1;
    }

    if (RC_ISOK(rc)) {
        rc = sxpd_create_open_resp_msg(peer, buff.u.data, sizeof(buff.u.data));
    }

    if (RC_ISOK(rc)) {
        buff.size = buff.u.msg.length;
        PLOG_TRACE_FMT(peer, "Sending %s message",
                       sxp_msg_type_string(buff.u.msg.type));
        enum sxp_error_code tmp_code = SXP_ERR_CODE_NONE;
        enum sxp_error_sub_code tmp_subcode = SXP_SUB_ERR_CODE_NONE;
        rc = sxp_hbo_pretty_print_msg(&buff.u.msg, &tmp_code, &tmp_subcode);
        if (sxp_isok(rc, tmp_code, tmp_subcode)) {
            rc = sxp_msg_hton_swap(&buff.u.msg, &tmp_code, &tmp_subcode);
        }
        if (sxp_isnotok(rc, tmp_code, tmp_subcode)) {
            rc = -1;
        }
    }
    if (RC_ISOK(rc)) {
        rc = evmgr_socket_write(peer->incoming, buff.u.data, buff.size);
    }

    if (RC_ISOK(rc)) {
        peer->flags.incoming_negotiation_done = true;
    }

    return rc;
}

/**
 * @brief create an update message in buffer and add del-prefix attribute if
 *peer handles v4 attributes
 *
 * @param peer peer which should receive this message
 * @param buffer buffer to store the message in
 * @param type ipv4 or ipv6
 * @param[out] prefix_list prefix-list attribute pointer if created
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_init_delete_update_msg(struct sxpd_peer *peer,
                                       struct sxpd_buffer *buffer,
                                       enum ip_type type,
                                       struct sxp_attribute **prefix_list)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, peer, buffer, prefix_list);
    RC_CHECK(rc, out);
    memset(buffer, 0, sizeof(*buffer));
    rc = sxp_create_update(buffer->u.data, sizeof(buffer->u.data));
    RC_CHECK(rc, out);
    if (peer->flags.handles_sxp_v4_attributes) {
        if (V6 == type) {
            rc = sxp_msg_add_ipv6_del_prefix(&buffer->u.msg,
                                             sizeof(buffer->u.data),
                                             prefix_list, !peer->flags.ipv6);
        } else {
            rc = sxp_msg_add_ipv4_del_prefix(&buffer->u.msg,
                                             sizeof(buffer->u.data),
                                             prefix_list, !peer->flags.ipv4);
        }
    }
out:
    return rc;
}

/**
 * @brief update masks for binding lists in a linked temporary list - set the
 *bit representing listener to given value
 *
 * @param peer listener whose bit is to be modified
 * @param first first binding list in the temporary list
 * @param mask_value bit value to set
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_update_binding_list_masks(struct sxpd_peer *peer,
                                          struct sxpd_binding_list *first,
                                          unsigned mask_value)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, peer, first);
    RC_CHECK(rc, out);
    while (first) {
        rc = sxpd_mask_set(&first->mask, peer->listener_bit_pos, mask_value);
        RC_CHECK(rc, out);
        PLOG_TRACE_FMT(peer, "Mark binding list %p as processed",
                       (void *)first);
        first->mark = false;
        first = first->next;
    }
out:
    return rc;
}

/**
 * @brief send update message to peer and update binding list masks if write to
 *socket succeeded
 *
 * @param peer peer to which the message is sent
 * @param buffer buffer containing the update message
 * @param elems_in_msg first member of temporary linked list containing binding
 *lists which are present in the update message (linked via 'next' member)
 * @param mask_value value to set the mask bits to
 * @param[out] write_failed flag set to true if write failed and message was not
 *sent
 * @param[in,out] bytes_written number of bytes written to socket in this write
 *event, updated by this function, no more than WRITE_CHUNK_SIZE bytes will be
 *written
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_send_binding_list_update(struct sxpd_peer *peer,
                                         struct sxpd_buffer *buffer,
                                         struct sxpd_binding_list *elems_in_msg,
                                         unsigned mask_value,
                                         bool *write_failed,
                                         size_t *bytes_written)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, peer, buffer, elems_in_msg, write_failed,
                     bytes_written);
    RC_CHECK(rc, out);
    buffer->size = buffer->u.msg.length;
    rc = sxpd_send_msg(peer, peer->listener, buffer, write_failed);
    RC_CHECK(rc, out);
    if (!*write_failed) {
        *bytes_written += buffer->size;
        rc = sxpd_update_binding_list_masks(peer, elems_in_msg, mask_value);
    }
out:
    return rc;
}

/**
 * @brief continue walking radix tree in search for next binding list which is
 *being deleted but not advertised yet to peer via delete message
 *
 * @param peer peer for which to find the binding list
 * @param type ipv4 or ipv4
 * @param[in,out] ctx radix node holding the last radix node checked, updated by
 *this function after a next candidate is found
 * @param[out] bl binding list which being deleted but not advertised yet
 * @param[out] buffer buffer for storing prefix bits of the network prefix
 * @param[out] buffer_size size of the buffer (in bytes)
 * @param[out] prefix_len length of the network prefix (in bits)
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_peer_find_next_deleting_binding_list(
    struct sxpd_peer *peer, enum ip_type type, struct radix_node **ctx,
    struct sxpd_binding_list **bl, uint8_t *buffer, size_t buffer_size,
    uint8_t *prefix_len)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, peer, ctx, bl, buffer, prefix_len);
    RC_CHECK(rc, out);
    struct radix_node *next = NULL;
    for (;;) {
        if (V6 == type) {
            rc = radix_iterate(peer->sxpd_ctx->master_bindings_v6, *ctx, &next);
        } else {
            rc = radix_iterate(peer->sxpd_ctx->master_bindings_v4, *ctx, &next);
        }
        RC_CHECK(rc, out);
        *ctx = next;
        if (!next) {
            /* no more nodes */
            *bl = NULL;
            goto out;
        }
        void *v = NULL;
        rc = radix_parse_node(next, buffer, buffer_size, prefix_len, &v);
        RC_CHECK(rc, out);
        *bl = v;
        if ((*bl)->count) {
            /* this binding list is not being deleted */
            continue;
        }
        unsigned value = 0;
        rc = sxpd_mask_get(&(*bl)->mask, peer->listener_bit_pos, &value);
        RC_CHECK(rc, out);
        if (value) {
            /* already sent to peer in delete message */
            continue;
        }
        /* have next binding list */
        break;
    }
out:
    return rc;
}

/**
 * @brief calculate required size in bytes for a delete entry for given peer
 *
 * @param peer peer to calculate the value for
 * @param type ipv4 or ipv6
 * @param prefix_len length of prefix in bits
 * @param[out] entry_size how many bytes would a delete entry for this
 *peer/prefix length take in update message
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_calc_del_entry_size(struct sxpd_peer *peer, enum ip_type type,
                                    uint8_t prefix_len, uint32_t *entry_size)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, peer, entry_size);
    RC_CHECK(rc, out);
    if (peer->flags.handles_sxp_v4_attributes) {
        *entry_size = sxp_calc_prefix_size(prefix_len);
    } else if (V4 == type) {
        *entry_size = sxp_calc_del_ipv4_size(prefix_len);
    } else {
        *entry_size = sxp_calc_del_ipv6_size(prefix_len);
    }
out:
    return rc;
}

/**
 * @brief add delete prefix entry to update message
 *
 * @param peer peer for which to construct the message
 * @param type ipv4 or ipv6
 * @param buffer buffer holding the update message
 * @param prefix_list prefix list attribute to which the delete entry is added
 * @param prefix network prefix to add
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_update_msg_add_del_entry(struct sxpd_peer *peer,
                                         enum ip_type type,
                                         struct sxpd_buffer *buffer,
                                         struct sxp_attribute *prefix_list,
                                         struct v4_v6_prefix *prefix)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, peer, buffer, prefix);
    RC_CHECK(rc, out);
    if (peer->flags.handles_sxp_v4_attributes) {
        PARAM_NULL_CHECK(rc, prefix_list);
        RC_CHECK(rc, out);
        rc = sxp_prefix_list_add_prefix(&buffer->u.msg, sizeof(buffer->u.data),
                                        prefix_list, prefix->len,
                                        prefix->ip.data);
    } else if (V4 == type) {
        rc = sxp_msg_add_del_ipv4(&buffer->u.msg, sizeof(buffer->u.data),
                                  prefix->len, prefix->ip.data);
    } else {
        rc = sxp_msg_add_del_ipv6(&buffer->u.msg, sizeof(buffer->u.data),
                                  prefix->len, prefix->ip.data);
    }
out:
    return rc;
}

/**
 * @brief return true if prefix of given type and length is host entry
 */
static bool sxpd_prefix_length_is_host(enum ip_type type, uint8_t len)
{
    switch (type) {
    case V4:
        if (8 * sizeof(((struct v4_v6_prefix *)0)->ip.v4) == len) {
            return true;
        } else {
            return false;
        }
    case V6:
        if (8 * sizeof(((struct v4_v6_prefix *)0)->ip.v6) == len) {
            return true;
        } else {
            return false;
        }
    }
    return false;
}

/**
 * @brief destroy binding lists and free memory if no longer needed
 * function takes a list of binding lists (linked via 'next' property) and
 *checks for each of them checks if the binding list can be destroyed, if yes,
 *then the binding list is destroyed and deleted from the master database
 * binding list can be destroyed if there is no listener connected or if the
 *connected listener count is the same as the number of bits set in the mask
 *(this means all listeners are notified of deletion)
 *
 * @param ctx sxpd context to operate on
 * @param type ipv4 or ipv6
 * @param elems_in_msg pointer to first binding list in the list of binding
 *lists
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_prune_binding_lists(struct sxpd_ctx *ctx, enum ip_type type,
                                    struct sxpd_binding_list *elems_in_msg)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, ctx, elems_in_msg);
    RC_CHECK(rc, out);
    struct sxpd_binding_list *previous = NULL;
    struct radix_tree *tree = NULL;
    switch (type) {
    case V4:
        tree = ctx->master_bindings_v4;
        break;
    case V6:
        tree = ctx->master_bindings_v6;
        break;
    }
    previous = elems_in_msg;
    elems_in_msg = elems_in_msg->next;
    while (elems_in_msg) {
        if ((!ctx->connected_listener_count) ||
            (ctx->connected_listener_count == previous->mask.bits_set)) {
            RC_CHECK(rc = radix_delete_node(tree, previous->radix_node), out);
            sxpd_destroy_binding_list(previous);
        }
        previous = elems_in_msg;
        elems_in_msg = elems_in_msg->next;
    }
    if (previous) {
        if ((!ctx->connected_listener_count) ||
            (ctx->connected_listener_count == previous->mask.bits_set)) {
            RC_CHECK(rc = radix_delete_node(tree, previous->radix_node), out);
            sxpd_destroy_binding_list(previous);
        }
    }
out:
    return rc;
}

/**
 * @brief create and send update message(s) containing deleted prefixes
 *
 * @param peer peer to send the update message to
 * @param type ipv4 or ipv6
 * @param[out] write_failed set to true if the message could not be written to
 *socket
 * @param[in,out] bytes_written number of bytes written to socket in this write
 *event, updated by this function, no more than WRITE_CHUNK_SIZE bytes will be
 *written
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_peer_export_delete_updates(struct sxpd_peer *peer,
                                           enum ip_type type,
                                           bool *write_failed,
                                           size_t *bytes_written)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, peer, write_failed, bytes_written);
    RC_CHECK(rc, out);
    bool need_send = false;
    struct sxpd_buffer buffer;
    struct sxp_attribute *prefix_list = NULL;
    struct sxpd_binding_list *elems_in_msg = NULL;
    rc = sxpd_init_delete_update_msg(peer, &buffer, type, &prefix_list);
    RC_CHECK(rc, out);
    struct radix_node *find_ctx = NULL;
    for (;;) {
        struct v4_v6_prefix prefix = { 0, { { 0 } } };
        struct sxpd_binding_list *bl = NULL;
        rc = sxpd_peer_find_next_deleting_binding_list(
            peer, type, &find_ctx, &bl, prefix.ip.data, sizeof(prefix.ip.data),
            &prefix.len);
        RC_CHECK(rc, out);
        if (!bl) {
            break;
        }
        if (!sxpd_prefix_length_is_host(type, prefix.len) &&
            !peer->flags.sub_bind && !peer->flags.always_export_subnets) {
            continue;
        }
        uint32_t binding_size = 0;
        rc = sxpd_calc_del_entry_size(peer, type, prefix.len, &binding_size);
        RC_CHECK(rc, out);
        if (buffer.u.msg.length + binding_size > SXP_MAX_MSG_LENGTH) {
            rc = sxpd_send_binding_list_update(peer, &buffer, elems_in_msg, 1,
                                               write_failed, bytes_written);
            if (RC_ISNOTOK(rc) || *write_failed) {
                goto out;
            }
            rc = sxpd_prune_binding_lists(peer->sxpd_ctx, type, elems_in_msg);
            RC_CHECK(rc, out);
            if (*bytes_written >= WRITE_CHUNK_SIZE) {
                goto out;
            }
            rc = sxpd_init_delete_update_msg(peer, &buffer, type, &prefix_list);
            RC_CHECK(rc, out);
            elems_in_msg = NULL;
        }
        if (V6 == type) {
            PLOG_TRACE_FMT(peer, "Add binding " DEBUG_V6_FMT "/%" PRIu8
                                 " to delete msg",
                           DEBUG_V6_PRINT(prefix.ip.data), prefix.len);
        } else {
            PLOG_TRACE_FMT(peer, "Add binding " DEBUG_V4_FMT "/%" PRIu8
                                 " to delete msg",
                           DEBUG_V4_PRINT(prefix.ip.v4), prefix.len);
        }
        rc = sxpd_update_msg_add_del_entry(peer, type, &buffer, prefix_list,
                                           &prefix);
        RC_CHECK(rc, out);
        need_send = true;
        bl->next = elems_in_msg;
        elems_in_msg = bl;
    }
    if (need_send) {
        rc = sxpd_send_binding_list_update(peer, &buffer, elems_in_msg, 1,
                                           write_failed, bytes_written);
        RC_CHECK(rc, out);
        rc = sxpd_prune_binding_lists(peer->sxpd_ctx, type, elems_in_msg);
        RC_CHECK(rc, out);
    }
out:
    return rc;
}

/**
 * @brief find next binding list to be export to peer in update message via
 *add-prefix-like attribute
 *
 * @param peer peer to which the update message is being sent
 * @param type ipv4 or ipv6
 * @param ctx context pointer holding address of radix node which contained last
 *binding list added to the update message
 * @param previous previous binding added to the update message
 * @param[out] bl next binding list to be added to the update message or NULL if
 *no more binding lists
 * @param[out] buffer buffer for storing network prefix bits of the binding list
 *found
 * @param buffer_size size of buffer (in bytes)
 * @param[out] prefix_len length of network prefix (in bits)
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_peer_find_next_binding_list_for_export(
    struct sxpd_peer *peer, enum ip_type type, struct radix_node **ctx,
    const struct sxpd_binding *previous, struct sxpd_binding_list **bl,
    uint8_t *buffer, size_t buffer_size, uint8_t *prefix_len)

{
    int rc = 0;
    PARAM_NULL_CHECK(rc, peer, ctx, bl, prefix_len);
    RC_CHECK(rc, out);
    struct radix_node *next = NULL;
    struct sxpd_binding *same_peer_seq_candidate = NULL;
    if (previous) {
        same_peer_seq_candidate = previous->same_peer_seq_next;
    }
    for (;;) {
        /* if possible, pick the next unexported binding with the same peer
         * sequence */
        if (same_peer_seq_candidate) {
            if (!same_peer_seq_candidate->binding_list ||
                same_peer_seq_candidate->binding_list->bindings[0] !=
                    same_peer_seq_candidate) {
                same_peer_seq_candidate =
                    same_peer_seq_candidate->same_peer_seq_next;
                continue;
            }
            *bl = same_peer_seq_candidate->binding_list;
        } else {
            /* continue iterating the radix tree */
            if (V6 == type) {
                rc = radix_iterate(peer->sxpd_ctx->master_bindings_v6, *ctx,
                                   &next);
            } else {
                rc = radix_iterate(peer->sxpd_ctx->master_bindings_v4, *ctx,
                                   &next);
            }
            RC_CHECK(rc, out);
            *ctx = next;
            if (!next) {
                /* no more nodes */
                *bl = NULL;
                goto out;
            }
            void *v = NULL;
            rc = radix_parse_node(next, buffer, buffer_size, prefix_len, &v);
            RC_CHECK(rc, out);
            *bl = v;
        }
        if (!(*bl)->count /* list is being deleted */ ||
            (*bl)->mark /* or marked as already processed */ ||
            (!peer->flags.sub_bind /* or peer does not support subnets */ &&
             (*bl)->expanding) /* binding list is being expanded */) {
            if (same_peer_seq_candidate) {
                same_peer_seq_candidate =
                    same_peer_seq_candidate->same_peer_seq_next;
            }
            continue;
        }
        unsigned value = 0;
        rc = sxpd_mask_get(&(*bl)->mask, peer->listener_bit_pos, &value);
        RC_CHECK(rc, out);
        if (value) {
            if (same_peer_seq_candidate) {
                same_peer_seq_candidate =
                    same_peer_seq_candidate->same_peer_seq_next;
            }
            /* already sent */
            continue;
        }
        /* have next binding list */
        break;
    }
out:
    return rc;
}

/**
 * @brief calculate number of bytes required for add entry in sxp message
 *
 * function calculates the number of bytes required for adding a new "add"
 *entry, considering the possible re-use of tag and peer-sequence attributes
 *
 * @param peer peer to which this update message is being sent
 * @param type ipv4 or ipv6
 * @param prefix network prefix for which to compute the size
 * @param b binding for wich to compute the size
 * @param[in,out] peer_sequence peer sequence added to previous entry or NULL if
 *none
 * @param[in,out] tag tag added to previous entry or 0 if none
 * @param[in,out] prefix_list prefix-list attribute to which to add the entry
 * @param[out] entry_size number of bytes required to hold the attribute
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_calc_add_entry_size(
    struct sxpd_peer *peer, enum ip_type type, struct v4_v6_prefix *prefix,
    struct sxpd_binding *b, struct sxpd_peer_sequence **peer_sequence,
    uint16_t *tag, struct sxp_attribute **prefix_list, size_t *entry_size)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, peer, prefix, b, peer_sequence, tag, prefix_list,
                     entry_size);
    RC_CHECK(rc, out);
    if (peer->flags.handles_sxp_v4_attributes) {
        *entry_size = sxp_calc_prefix_size(8 * sizeof(uint32_t));
        uint32_t req_count = 1;
#ifdef UPDATE_MSG_ATTR_INHERITANCE
        if (peer->flags.handles_peer_seq &&
            (!*peer_sequence || b->peer_sequence != *peer_sequence)) {
#else
        if (peer->flags.handles_peer_seq) {
#endif
            /* need to add peer sequence */
            if (b->peer_sequence &&
                b->peer_sequence != peer->sxpd_ctx->v1_peer_sequence) {
                req_count += b->peer_sequence->node_ids_count;
            }
            *entry_size += sxp_calc_peer_sequence_size(req_count);
            *peer_sequence = NULL;
            *prefix_list = NULL;
        }
#ifdef UPDATE_MSG_ATTR_INHERITANCE
        if (b->tag != *tag) {
#endif
            *entry_size += sxp_calc_sgt_size();
            *tag = 0;
            *prefix_list = NULL;
#ifdef UPDATE_MSG_ATTR_INHERITANCE
        }
#endif

        if (!*prefix_list) {
            if (V4 == type) {
                *entry_size += sxp_calc_ipv4_add_prefix_size();
            } else {
                *entry_size += sxp_calc_ipv6_add_prefix_size();
            }
        }
    } else if (V4 == type) {
        *entry_size = sxp_calc_add_ipv4_size(prefix->len);
    } else {
        *entry_size = sxp_calc_add_ipv6_size(prefix->len);
    }
out:
    return rc;
}

/**
 * @brief add 'add' entry to update message
 *
 * @param peer peer for which the update message is being created
 * @param type ipv4 or ipv6
 * @param buffer buffer holding the update message
 * @param prefix network prefix to add to update message
 * @param b binding to add to update message
 * @param[in,out] peer_sequence peer sequence attribute already in the message,
 *if NULL, and one was added by this functions, its address will be stored here
 * @param[in,out] tag value of last tag stored in the message for
 *inheritance/re-use purposes, updated if changed by this function
 * @param[in,out] prefix_list prefix list attribute to which this entry is being
 *added, if NULL, this function will create one and store the address here
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_update_msg_add_add_entry(
    struct sxpd_peer *peer, enum ip_type type, struct sxpd_buffer *buffer,
    struct v4_v6_prefix *prefix, struct sxpd_binding *b,
    struct sxpd_peer_sequence **peer_sequence, uint16_t *tag,
    struct sxp_attribute **prefix_list)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, peer, buffer, prefix, b, peer_sequence, prefix_list);
    RC_CHECK(rc, out);
    if (peer->flags.handles_sxp_v4_attributes) {
        bool optional_flag = false;
        if (V4 == type) {
            optional_flag = !peer->flags.ipv4;
        } else {
            optional_flag = !peer->flags.ipv6;
        }
        if (peer->flags.handles_peer_seq && !*peer_sequence) {
            uint32_t req_count = 1;
            if (b->peer_sequence) {
                req_count += b->peer_sequence->node_ids_count;
            }
            uint32_t *sxp_id_arr = NULL;
            rc = sxp_msg_add_peer_sequence(&buffer->u.msg,
                                           sizeof(buffer->u.data), req_count,
                                           &sxp_id_arr, optional_flag);
            RC_CHECK(rc, out);
            size_t i = 0;
            sxp_id_arr[0] = peer->sxpd_ctx->node_id;
            if (b->peer_sequence) {
                for (i = 0; i < b->peer_sequence->node_ids_count; ++i) {
                    sxp_id_arr[i + 1] = b->peer_sequence->node_ids[i];
                }
            }
            *peer_sequence = b->peer_sequence;
        }
#ifdef UPDATE_MSG_ATTR_INHERITANCE
        if (*tag != b->tag) {
#endif
            rc = sxp_msg_add_sgt(&buffer->u.msg, sizeof(buffer->u.data), b->tag,
                                 optional_flag);
            RC_CHECK(rc, out);
            *tag = b->tag;
#ifdef UPDATE_MSG_ATTR_INHERITANCE
        }
#endif
        if (!*prefix_list) {
            if (V4 == type) {
                rc = sxp_msg_add_ipv4_add_prefix(&buffer->u.msg,
                                                 sizeof(buffer->u.data),
                                                 prefix_list, optional_flag);
            } else {
                rc = sxp_msg_add_ipv6_add_prefix(&buffer->u.msg,
                                                 sizeof(buffer->u.data),
                                                 prefix_list, optional_flag);
            }
            RC_CHECK(rc, out);
        }
        rc = sxp_prefix_list_add_prefix(&buffer->u.msg, sizeof(buffer->u.data),
                                        *prefix_list, prefix->len,
                                        prefix->ip.data);
    } else if (V4 == type) {
        rc = sxp_msg_add_add_ipv4(&buffer->u.msg, sizeof(buffer->u.data),
                                  b->tag, prefix->len, prefix->ip.data);
    } else {
        rc = sxp_msg_add_add_ipv6(&buffer->u.msg, sizeof(buffer->u.data),
                                  b->tag, prefix->len, prefix->ip.data);
    }
out:
    return rc;
}

/**
 * @brief export 'add' updates to peer
 *
 * @param peer peer to export add updates to
 * @param type ipv4 or ipv6
 * @param[out] write_failed flag set to true if a write to socket failed
 * @param[in,out] bytes_written number of bytes written to socket (updated while
 *writing more data), no more than WRITE_CHUNK_SIZE will be written
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_peer_export_add_updates(struct sxpd_peer *peer,
                                        enum ip_type type, bool *write_failed,
                                        size_t *bytes_written)
{
    int rc = 0;
    struct sxpd_binding_list *elems_in_msg = NULL;
    bool need_send = false;
    struct sxpd_buffer buffer;
    struct sxpd_binding *previous = NULL;
    struct sxpd_peer_sequence *peer_sequence = NULL;
    struct radix_node *find_ctx = NULL;
    uint16_t tag = 0; /* tag value 0 is invalid and serves as "not set" */
    struct sxp_attribute *prefix_list = NULL;
    memset(&buffer, 0, sizeof(buffer));
    PARAM_NULL_CHECK(rc, peer, write_failed, bytes_written);
    RC_CHECK(rc, out);
    RC_CHECK(rc = sxp_create_update(buffer.u.data, sizeof(buffer.u.data)), out);
    for (;;) {
        struct v4_v6_prefix prefix = { 0, { { 0 } } };
        struct sxpd_binding_list *bl = NULL;
        rc = sxpd_peer_find_next_binding_list_for_export(
            peer, type, &find_ctx, previous, &bl, prefix.ip.data,
            sizeof(prefix.ip.data), &prefix.len);
        RC_CHECK(rc, out);
        if (!bl) {
            break;
        }
        if (!sxpd_prefix_length_is_host(type, prefix.len) &&
            !peer->flags.sub_bind && !peer->flags.always_export_subnets) {
            continue;
        }
        struct sxpd_binding *b = bl->bindings[0];
        size_t req_size = 0;
        rc = sxpd_calc_add_entry_size(peer, type, &prefix, b, &peer_sequence,
                                      &tag, &prefix_list, &req_size);
        if (buffer.u.msg.length + req_size > SXP_MAX_MSG_LENGTH) {
            /* data does not fit into message - send the message out now and
             * create a new message*/
            rc = sxpd_send_binding_list_update(peer, &buffer, elems_in_msg, 1,
                                               write_failed, bytes_written);
            if (RC_ISNOTOK(rc) || *write_failed ||
                *bytes_written >= WRITE_CHUNK_SIZE) {
                goto out;
            }
            elems_in_msg = NULL;
            previous = NULL;
            tag = 0;
            prefix_list = NULL;
            rc = sxp_create_update(buffer.u.data, sizeof(buffer.u.data));
            RC_CHECK(rc, out);
        }
        if (V6 == type) {
            PLOG_TRACE_FMT(peer, "Add binding " DEBUG_V6_FMT "/%" PRIu8
                                 " to update msg",
                           DEBUG_V6_PRINT(prefix.ip.v6), prefix.len);
        } else {
            PLOG_TRACE_FMT(peer, "Add binding " DEBUG_V4_FMT "/%" PRIu8
                                 " to update msg",
                           DEBUG_V4_PRINT(prefix.ip.v4), prefix.len);
        }
        RC_CHECK(rc, out);
        rc = sxpd_update_msg_add_add_entry(peer, type, &buffer, &prefix, b,
                                           &peer_sequence, &tag, &prefix_list);
        RC_CHECK(rc, out);
        bl->mark = true;
        need_send = true;
        bl->next = elems_in_msg;
        elems_in_msg = bl;
        previous = b;
    }
    if (need_send) {
        rc = sxpd_send_binding_list_update(peer, &buffer, elems_in_msg, 1,
                                           write_failed, bytes_written);
    }
out:
    if (RC_ISOK(rc) && *write_failed) {
        PLOG_DEBUG_MSG(peer, "Write failed - will export bindings later");
        while (elems_in_msg) {
            elems_in_msg->mark = false;
            elems_in_msg = elems_in_msg->next;
        }
    }
    return rc;
}

/**
 * @brief send expanded entries to peer which cannot handle subnets
 *
 * @param peer peer to send the entries to
 * @param buffer buffer holding the update message
 * @param elems_in_msg linked list (via 'next') of expansion track entries
 *present in the update message
 * @param[out] write_failed flag set to true if write failed to socket
 * @param[in,out] bytes_written number of bytes written to socket (updated while
 *writing more data), no more than WRITE_CHUNK_SIZE will be written
 *
 * @return 0 if success, -1 if error
 */
static int
sxpd_send_expanded_entries(struct sxpd_peer *peer, struct sxpd_buffer *buffer,
                           struct sxpd_expansion_track_entry *elems_in_msg,
                           bool *write_failed, size_t *bytes_written)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, peer, buffer, elems_in_msg, write_failed,
                     bytes_written);
    RC_CHECK(rc, out);
    buffer->size = buffer->u.msg.length;
    rc = sxpd_send_msg(peer, peer->listener, buffer, write_failed);
    if (RC_ISNOTOK(rc) || *write_failed) {
        goto out;
    }
    *bytes_written += buffer->size;
    const size_t before = peer->sxpd_ctx->expanded_entry_count;
    while (elems_in_msg) {
        rc = sxpd_mask_set(&elems_in_msg->mask, peer->expansion_index, 1);
        RC_CHECK(rc, out);
        struct sxpd_expansion_track_entry *previous = elems_in_msg;
        elems_in_msg = elems_in_msg->next;
        /* if deleting, check if the total set bits is equal to listener count,
         * if yes, then all listeners are up to date */
        if (!previous->bl &&
            peer->sxpd_ctx->listener_count == previous->mask.bits_set) {
            rc = radix_delete_node(peer->sxpd_ctx->expand_entries_v4,
                                   previous->node);
            RC_CHECK(rc, out);
            sxpd_destroy_expansion_track_entry(previous);
            --peer->sxpd_ctx->expanded_entry_count;
        }
    }
    if (peer->sxpd_ctx->expanded_entry_count < before) {
        LOG_TRACE(
            "Try expanding more bindings after freeing %zu expansion entries",
            before - peer->sxpd_ctx->expanded_entry_count);
        RC_CHECK(rc = sxpd_expand_bindings(peer->sxpd_ctx), out);
        rc = sxpd_export_bindings(peer->sxpd_ctx);
    }
out:
    return rc;
}

/**
 * @brief find next expansion track entry to be exported to peer
 *
 * @param peer peer to which the entries are exported
 * @param node radix node of previous entry added to the update message
 * @param[out] entry expansion track to add to update message or NULL if no more
 *entries
 * @param[out] host network host entry corresponding to the expansion track
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_peer_find_next_expanded_entry_for_export(
    struct sxpd_peer *peer, struct radix_node **node,
    struct sxpd_expansion_track_entry **entry, struct v4_v6_prefix *host)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, peer, node, entry, host);
    RC_CHECK(rc, out);
    *entry = NULL;
    for (;;) {
        rc = radix_iterate(peer->sxpd_ctx->expand_entries_v4, *node, node);
        RC_CHECK(rc, out);
        if (!*node) {
            break;
        }
        void *value = NULL;
        rc = radix_parse_node(*node, host->ip.data, sizeof(host->ip.data),
                              &host->len, &value);
        RC_CHECK(rc, out);
        struct sxpd_expansion_track_entry *e = value;
        unsigned bit = 0;
        rc = sxpd_mask_get(&e->mask, peer->expansion_index, &bit);
        RC_CHECK(rc, out);
        if (!bit) {
            *entry = e;
            break;
        }
    }
out:
    return rc;
}

/**
 * @brief find next expanded entry which is being deleted for exporting to peer
 *
 * @param peer peer to which the entries are being exported
 * @param node radix node of previous entry added to the update message
 *
 * @param[out] entry expansion track to add to update message or NULL if no more
 *entries
 * @param[out] host network host entry corresponding to the expansion track
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_peer_find_next_deleting_expanded_entry(
    struct sxpd_peer *peer, struct radix_node **node,
    struct sxpd_expansion_track_entry **entry, struct v4_v6_prefix *host)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, peer, node, entry, host);
    RC_CHECK(rc, out);
    struct radix_node *next = NULL;
    for (;;) {
        rc = radix_iterate(peer->sxpd_ctx->expand_entries_v4, *node, &next);
        RC_CHECK(rc, out);
        *node = next;
        if (!next) {
            /* no more nodes */
            *entry = NULL;
            goto out;
        }
        void *v = NULL;
        rc = radix_parse_node(next, host->ip.data, sizeof(host->ip.data),
                              &host->len, &v);
        RC_CHECK(rc, out);
        *entry = v;
        if ((*entry)->bl) {
            /* this entry is not being deleted */
            continue;
        }
        unsigned value = 0;
        rc = sxpd_mask_get(&(*entry)->mask, peer->expansion_index, &value);
        RC_CHECK(rc, out);
        if (value) {
            /* already deleted */
            continue;
        }
        /* have next binding list */
        break;
    }
out:
    return rc;
}

/**
 * @brief export delete host updates to peer
 *
 * @param peer peer to which the deletes are exported
 * @param[out] write_failed flag set to true if write failed to socket
 * @param[in,out] bytes_written number of bytes written to socket (updated while
 *writing more data), no more than WRITE_CHUNK_SIZE will be written
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_peer_export_delete_host_updates(struct sxpd_peer *peer,
                                                bool *write_failed,
                                                size_t *bytes_written)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, peer, write_failed, bytes_written);
    RC_CHECK(rc, out);
    bool need_send = false;
    struct sxpd_buffer buffer;
    struct sxp_attribute *prefix_list = NULL;
    struct sxpd_expansion_track_entry *elems_in_msg = NULL;
    rc = sxpd_init_delete_update_msg(peer, &buffer, V4, &prefix_list);
    RC_CHECK(rc, out);
    struct radix_node *find_ctx = NULL;
    for (;;) {
        struct v4_v6_prefix host = { 0, { { 0 } } };
        struct sxpd_expansion_track_entry *e = NULL;
        rc = sxpd_peer_find_next_deleting_expanded_entry(peer, &find_ctx, &e,
                                                         &host);
        RC_CHECK(rc, out);
        if (!e) {
            break;
        }
        const uint32_t binding_size = sxp_calc_prefix_size(host.len);
        if (buffer.u.msg.length + binding_size > SXP_MAX_MSG_LENGTH) {
            rc = sxpd_send_expanded_entries(peer, &buffer, elems_in_msg,
                                            write_failed, bytes_written);
            if (RC_ISNOTOK(rc) || *write_failed ||
                *bytes_written >= WRITE_CHUNK_SIZE) {
                goto out;
            }
            rc = sxpd_init_delete_update_msg(peer, &buffer, V4, &prefix_list);
            RC_CHECK(rc, out);
            elems_in_msg = NULL;
        }
        PLOG_TRACE_FMT(peer, "Add expansion track %p " DEBUG_V4_FMT
                             "/32 to delete msg",
                       (void *)e, DEBUG_V4_PRINT(host.ip.v4));
        rc = sxpd_update_msg_add_del_entry(peer, V4, &buffer, prefix_list,
                                           &host);
        RC_CHECK(rc, out);
        need_send = true;
        e->next = elems_in_msg;
        elems_in_msg = e;
    }
    if (need_send) {
        rc = sxpd_send_expanded_entries(peer, &buffer, elems_in_msg,
                                        write_failed, bytes_written);
    }
out:
    return rc;
}

/**
 * @brief export add host updates to peer
 *
 * @param peer peer to which the updates should be exported
 * @param[out] write_failed flag set to true if write to socket failed
 * @param[in,out] bytes_written number of bytes written to socket (updated while
 *writing more data), no more than WRITE_CHUNK_SIZE will be written
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_peer_export_add_host_updates(struct sxpd_peer *peer,
                                             bool *write_failed,
                                             size_t *bytes_written)
{
    int rc = 0;
    struct sxpd_expansion_track_entry *elems_in_msg = NULL;
    PARAM_NULL_CHECK(rc, peer, write_failed, bytes_written);
    RC_CHECK(rc, out);
    bool need_send = false;
    uint16_t tag = 0; /* tag value 0 is invalid and serves as "not set" */
    struct sxp_attribute *prefix_list = NULL;
    struct sxpd_buffer buffer;
    struct sxpd_peer_sequence *peer_sequence = NULL;
    struct radix_node *node = NULL;
    struct sxpd_expansion_track_entry *e = NULL;
    memset(&buffer, 0, sizeof(buffer));
    PARAM_NULL_CHECK(rc, peer);
    RC_CHECK(rc, out);
    RC_CHECK(rc = sxp_create_update(buffer.u.data, sizeof(buffer.u.data)), out);
    for (;;) {
        struct v4_v6_prefix host = { 0, { { 0 } } };
        rc = sxpd_peer_find_next_expanded_entry_for_export(peer, &node, &e,
                                                           &host);
        RC_CHECK(rc, out);
        if (!e) {
            break;
        }
        size_t req_size = 0;
        struct sxpd_binding *b = e->bl->bindings[0];
        rc = sxpd_calc_add_entry_size(peer, V4, &host, b, &peer_sequence, &tag,
                                      &prefix_list, &req_size);
        RC_CHECK(rc, out);
        if (buffer.u.msg.length + req_size > SXP_MAX_MSG_LENGTH) {
            /* data does not fit into message - send the message out now and
             * create a new message*/
            rc = sxpd_send_expanded_entries(peer, &buffer, elems_in_msg,
                                            write_failed, bytes_written);
            if (RC_ISNOTOK(rc) || *write_failed ||
                *bytes_written >= WRITE_CHUNK_SIZE) {
                goto out;
            }
            peer_sequence = NULL;
            tag = 0;
            prefix_list = NULL;
            rc = sxp_create_update(buffer.u.data, sizeof(buffer.u.data));
            RC_CHECK(rc, out);
        }
        PLOG_TRACE_FMT(peer, "Add expansion track %p " DEBUG_V4_FMT "/%" PRIu8
                             " to update msg",
                       (void *)e, DEBUG_V4_PRINT(host.ip.v4), host.len);
        rc = sxpd_update_msg_add_add_entry(peer, V4, &buffer, &host, b,
                                           &peer_sequence, &tag, &prefix_list);
        RC_CHECK(rc, out);
        need_send = true;
        e->next = elems_in_msg;
        elems_in_msg = e;
    }
    if (need_send) {
        rc = sxpd_send_expanded_entries(peer, &buffer, elems_in_msg,
                                        write_failed, bytes_written);
    }
out:
    if (RC_ISOK(rc) && *write_failed) {
        PLOG_DEBUG_MSG(peer, "Write failed - will export bindings later");
    }
    return rc;
}

/**
 * @brief export binding updates to peer
 *
 * @param peer peer to which to export the bindings
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_peer_export_bindings(struct sxpd_peer *peer)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, peer);
    RC_CHECK(rc, out);
    size_t bytes_written = 0;
    bool write_failed = false;
    if (peer->flags.ipv4 || 4 == peer->version) {
        PLOG_TRACE_FMT(peer,
                       "Exporting IPv4 delete updates to v%" PRIu32 " peer",
                       peer->version);
        rc = sxpd_peer_export_delete_updates(peer, V4, &write_failed,
                                             &bytes_written);
        RC_CHECK(rc, out);
    }
    if ((peer->flags.ipv6 || 4 == peer->version) && !write_failed &&
        bytes_written < WRITE_CHUNK_SIZE) {
        PLOG_TRACE_FMT(peer,
                       "Exporting IPv6 delete updates to v%" PRIu32 " peer",
                       peer->version);
        rc = sxpd_peer_export_delete_updates(peer, V6, &write_failed,
                                             &bytes_written);
        RC_CHECK(rc, out);
    }
    if ((peer->flags.ipv4 || 4 == peer->version) && !write_failed &&
        bytes_written < WRITE_CHUNK_SIZE) {
        PLOG_TRACE_FMT(peer, "Exporting IPv4 add updates to v%" PRIu32 " peer",
                       peer->version);
        rc = sxpd_peer_export_add_updates(peer, V4, &write_failed,
                                          &bytes_written);
        RC_CHECK(rc, out);
    }
    if ((peer->flags.ipv6 || 4 == peer->version) && !write_failed &&
        bytes_written < WRITE_CHUNK_SIZE) {
        PLOG_TRACE_FMT(peer, "Exporting IPv6 add updates to v%" PRIu32 " peer",
                       peer->version);
        rc = sxpd_peer_export_add_updates(peer, V6, &write_failed,
                                          &bytes_written);
        RC_CHECK(rc, out);
    }
    if ((peer->flags.ipv4 || 4 == peer->version) && !peer->flags.sub_bind &&
        !write_failed && bytes_written < WRITE_CHUNK_SIZE) {
        PLOG_TRACE_FMT(peer, "Exporting IPv4 delete host updates to v%" PRIu32
                             " peer",
                       peer->version);
        rc = sxpd_peer_export_delete_host_updates(peer, &write_failed,
                                                  &bytes_written);
        RC_CHECK(rc, out);
    }
    if ((peer->flags.ipv4 || 4 == peer->version) && !peer->flags.sub_bind &&
        !write_failed && bytes_written < WRITE_CHUNK_SIZE) {
        PLOG_TRACE_FMT(peer,
                       "Exporting IPv4 add host updates to v%" PRIu32 " peer",
                       peer->version);
        rc = sxpd_peer_export_add_host_updates(peer, &write_failed,
                                               &bytes_written);
        RC_CHECK(rc, out);
    }
    if (write_failed) {
        LOG_DEBUG("Write failed - waiting for socket to become writable again");
    } else if (!bytes_written || bytes_written < WRITE_CHUNK_SIZE) {
        LOG_DEBUG("No more data to write - disable writeable callback (%zu "
                  "bytes written)",
                  bytes_written);
        rc = evmgr_socket_cb_register(peer->listener, sxpd_peer_read_callback,
                                      NULL, sxpd_peer_event_callback, peer);
    }
out:
    return rc;
}

/**
 * @brief destroy expansion track entry and free memory
 */
static void
sxpd_destroy_expansion_track_entry(struct sxpd_expansion_track_entry *e)
{
    if (e) {
        LOG_TRACE("Destroy expansion track %p", (void *)e);
        mem_free(e->mask.elems);
        mem_free(e);
    }
}

/**
 * @brief expand more bindings if possible and export bindings
 *
 * @param ctx sxpd context to operate on
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_expand_bindings(struct sxpd_ctx *ctx)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, ctx);
    RC_CHECK(rc, out);
    struct radix_node *node = NULL;
    size_t before = ctx->expanded_entry_count;
    while (ctx->sub_expand_limit > ctx->expanded_entry_count) {
        rc = radix_iterate(ctx->master_bindings_v4, node, &node);
        RC_CHECK(rc, out);
        if (!node) {
            break;
        }
        void *value = NULL;
        struct v4_v6_prefix prefix = { 0, { { 0 } } };
        rc = radix_parse_node(node, prefix.ip.data, sizeof(prefix.ip.data),
                              &prefix.len, &value);
        RC_CHECK(rc, out);
        struct sxpd_binding_list *bl = value;
        if (bl->expanding) {
            continue;
        }
        RC_CHECK(rc = sxpd_expand_binding(ctx, &prefix, bl), out);
    }
    if (before != ctx->expanded_entry_count) {
        rc = sxpd_export_bindings(ctx);
    }
out:
    return rc;
}

/**
 * @brief walk the peers and enable write callbacks for all peers which have
 *listener role on theirs listener sockets
 *
 * @param ctx sxpd context to operate on
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_export_bindings(struct sxpd_ctx *ctx)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, ctx);
    RC_CHECK(rc, out);
    size_t i = 0;
    for (i = 0; i < ctx->listener_count; ++i) {
        struct sxpd_peer *peer = ctx->listeners[i];
        if (!peer->listener) {
            continue;
        }
        rc = evmgr_socket_cb_register(peer->listener, sxpd_peer_read_callback,
                                      sxpd_peer_write_callback,
                                      sxpd_peer_event_callback, peer);
        RC_CHECK(rc, out);
    }
out:
    return rc;
}

/**
 * @brief callback called when socket is writable
 *
 * @param socket socket which is writable
 * @param ctx context passed to callback register function - struct sxpd_peer *
 *
 * @startuml
 * actor "peer" as apeer
 * participant "event manager" as evmgr
 * participant "sxpd peer" as peer
 * evmgr->peer: socket is writable
 * alt socket is outgoing socket and open message not sent yet
 *  peer->evmgr: send open message to peer (sxpd_send_open)
 *  evmgr->apeer: open message
 * else socket is outgoing socket and waiting for open/open_resp message
 *  peer->evmgr: unregister write callback (evmgr_socket_cb_register)
 * end
 * alt socket is connection to listener
 *   peer->peer: export bindings (sxpd_peer_export_bindings)
 *   peer->evmgr: send update message to peer
 *   evmgr->apeer: update message
 * else socket is connection to speaker
 *   peer->evmgr: unregister write callback (evmgr_socket_cb_register)
 * end
 * @enduml
 *
 */
static void sxpd_peer_write_callback(struct evmgr_socket *socket, void *ctx)
{
    int rc = 0;
    struct sxpd_peer *peer = ctx;

    PARAM_NULL_CHECK(rc, socket, ctx);
    if (RC_ISOK(rc)) {
        if (socket == peer->outgoing) {
            if (WILL_SEND_OPEN == peer->outgoing_state) {
                rc = sxpd_send_open(peer);
                if (RC_ISNOTOK(rc)) {
                    rc = sxpd_error_disconnect_peer(peer, socket, false);
                    if (RC_ISNOTOK(rc)) {
                        PLOG_ERROR_MSG(peer,
                                       "Disconnecting peer socket failed");
                    }
                }
            } else if (WAITING_OPEN_RESP == peer->outgoing_state ||
                       WAITING_OPEN == peer->outgoing_state) {
                /* unregister write callback, until OPEN_RESP comes back */
                rc = evmgr_socket_cb_register(socket, sxpd_peer_read_callback,
                                              NULL, sxpd_peer_event_callback,
                                              peer);
            }
        } else if (socket != peer->incoming) {
            PLOG_ERROR_FMT(peer, "Unknown socket %p is writable",
                           (void *)socket);
            rc = sxpd_error_disconnect_peer(peer, socket, true);
            if (RC_ISNOTOK(rc)) {
                PLOG_ERROR_MSG(peer, "Disconnecting peer socket failed");
            }
        }
    }
    if (RC_ISOK(rc)) {
        if (socket == peer->listener) {
            rc = sxpd_peer_export_bindings(peer);
            if (RC_ISNOTOK(rc)) {
                PLOG_ERROR_MSG(peer, "Exporting bindings failed");
            }
        } else if (socket == peer->speaker) {
            /* unregister write callback, we do not care if connection to
             * speaker is writable */
            rc = evmgr_socket_cb_register(socket, sxpd_peer_read_callback, NULL,
                                          sxpd_peer_event_callback, peer);
            if (RC_ISNOTOK(rc)) {
                PLOG_ERROR_MSG(peer, "Register peer socket callback failed");
            }
        }
    }
}

/**
 * @brief socket event callback
 *
 * @startuml
 * participant "event manager" as evmgr
 * participant "sxpd peer" as peer
 * evmgr->peer: event on socket
 * alt eof/timeout/error
 *  peer->peer: disconnect peer (sxpd_disconnect_peer_socket)
 *  peer->evmgr: close socket (evmgr_socket_destroy)
 * else connected
 *  alt waiting for connect
 *   peer->peer: change state to "will send open message"
 *  else not waiting for connect
 *   peer->peer: disconnect peer (sxpd_disconnect_peer_socket)
 *   peer->evmgr: close socket (evmgr_socket_destroy)
 *  end
 * else other event
 *  peer->peer: success (event ignored)
 * end
 * @enduml
 *
 * @param socket socket on which the event occurred
 * @param events bit flags specifying the events on the socket
 * @param ctx context supplied when registering callback
 */
static void sxpd_peer_event_callback(struct evmgr_socket *socket,
                                     int16_t events, void *ctx)
{
    int rc = 0;
    struct sxpd_peer *peer = ctx;

    PARAM_NULL_CHECK(rc, socket, ctx);
    bool is_error = false;
    bool is_connected = false;
    if (RC_ISOK(rc)) {
        const char *eof = "";
        if (events & EVMGR_SOCK_EVENT_EOF) {
            eof = " EOF";
            is_error = true;
        }

        const char *read = "";
        if (events & EVMGR_SOCK_EVENT_READING) {
            read = " READ";
        }

        const char *write = "";
        if (events & EVMGR_SOCK_EVENT_WRITING) {
            write = " WRITE";
        }

        const char *error = "";
        if (events & EVMGR_SOCK_EVENT_ERROR) {
            error = " ERROR";
            is_error = true;
        }

        const char *conn = "";
        if (events & EVMGR_SOCK_EVENT_CONNECTED) {
            conn = " CONNECTED";
            is_connected = true;
        }

        const char *timeout = "";
        if (events & EVMGR_SOCK_EVENT_TIMEOUT) {
            timeout = " TIMEOUT";
            is_error = true;
        }

        PLOG_DEBUG_FMT(peer, "Event:%s%s%s%s%s%s@%p", read, write, eof, conn,
                       error, timeout, (void *)socket);
    }

    if (RC_ISOK(rc)) {
        if (is_error) {
            rc = sxpd_error_disconnect_peer(peer, socket, true);
        } else if (is_connected) {
            if (socket == peer->outgoing) {
                if (peer->outgoing_state == WAITING_CONNECT) {
                    PLOG_TRACE_MSG(peer, "TCP connected, will send OPEN");
                    PEER_CHANGE_OUT_CONN_STATE(peer, WILL_SEND_OPEN);
                } else {
                    PLOG_ERROR_MSG(peer, "Unexpected connect event");
                    PEER_CHANGE_OUT_CONN_STATE(peer, ERROR_CONNECT);
                    rc = -1;
                }
            } else {
                PLOG_ERROR_FMT(peer, "Connect event on unknown socket %p, "
                                     "outgoing socket %p",
                               (void *)socket, (void *)peer->outgoing);
                rc = -1;
            }
        }
    }

    if (RC_ISNOTOK(rc)) {
        rc = sxpd_disconnect_peer_socket(peer, socket, true);
        if (RC_ISNOTOK(rc)) {
            PLOG_ERROR_MSG(peer, "Disconnecting peer socket failed");
        }
    }
}

/**
 * @brief process node id attribute and store it in peer structure
 *
 * @param peer peer which sent the message containing the attribute
 * @param attr node-id sxp attribute
 * @param[out] code error code found during parsing of the attribute
 * @param[out] subcode error sub-code found during parsing of the attribute
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_process_node_id_attr(struct sxpd_peer *peer,
                                     struct sxp_attribute *attr,
                                     enum sxp_error_code *code,
                                     enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, peer, attr, code, subcode);
    if (RC_ISOK(rc)) {
        uint32_t node_id = 0;
        rc = sxp_attr_node_id_get_node_id(attr, &node_id);
        if (RC_ISOK(rc)) {
            if (node_id) {
                peer->nbo_node_id = node_id;
                PLOG_DEBUG_FMT(peer, "%s is %" PRIu32,
                               sxp_attr_type_string(SXP_ATTR_TYPE_NODE_ID),
                               node_id);
            } else {
                PLOG_ERROR_FMT(peer, "%s %" PRIu32 " is invalid",
                               sxp_attr_type_string(SXP_ATTR_TYPE_NODE_ID),
                               node_id);
                *code = SXP_ERR_CODE_OPEN;
                *subcode = SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE;
            }
        }
    }
    return rc;
}

/**
 * @brief process capabilities attribute and set corresponding peer flags
 *
 * @param peer peer which sent the message containing the attribute
 * @param attr node-id sxp attribute
 * @param[out] code error code found during parsing of the attribute
 * @param[out] subcode error sub-code found during parsing of the attribute
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_process_capabilities_attr(struct sxpd_peer *peer,
                                          struct sxp_attribute *attr,
                                          enum sxp_error_code *code,
                                          enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    struct sxp_capability *cap = NULL;
    PARAM_NULL_CHECK(rc, peer, attr, code, subcode);
    while (sxp_isok(rc, *code, *subcode)) {
        rc = sxp_parse_capabilities(attr, cap, &cap, code, subcode);
        if (sxp_isnotok(rc, *code, *subcode)) {
            break;
        }
        if (!cap) {
            break;
        }
        enum sxp_capability_code cap_code = SXP_CAPABILITY_IPV4_UNICAST;
        rc = sxp_capability_get_code(cap, &cap_code);
        if (RC_ISNOTOK(rc)) {
            break;
        }
        uint8_t length = 0;
        rc = sxp_capability_get_length(cap, &length);
        if (RC_ISNOTOK(rc)) {
            break;
        }
        if (length) {
            PLOG_ERROR_FMT(peer,
                           "Non-zero length(%" PRIu8 ") for %s capability!",
                           length, sxp_capability_code_string(cap_code));
            *code = SXP_ERR_CODE_OPEN;
            *subcode = SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE;
        } else {
            switch (cap_code) {
            case SXP_CAPABILITY_IPV4_UNICAST:
                peer->flags.ipv4 = true;
                break;
            case SXP_CAPABILITY_IPV6_UNICAST:
                peer->flags.ipv6 = true;
                break;
            case SXP_CAPABILITY_SUBNET_BINDINGS:
                peer->flags.sub_bind = true;
                break;
            }
            PLOG_TRACE_FMT(peer, "Peer has %s capability",
                           sxp_capability_code_string(cap_code));
        }
    }
    return rc;
}

/**
 * @brief process hold time attribute found in OPEN message and store the values
 *in peer structure if applicable
 *
 * @param peer peer from which the OPEN message was received
 * @param attr hold time attribute to process
 * @param[out] code error code found during processing
 * @param[out] subcode error sub-code found during processing
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_process_open_hold_time_attr(struct sxpd_peer *peer,
                                            struct sxp_attribute *attr,
                                            enum sxp_error_code *code,
                                            enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    uint16_t min_val = 0;
    uint16_t max_val = 0;
    bool has_max_val = false;
    PARAM_NULL_CHECK(rc, peer, attr, code, subcode);
    RC_CHECK(rc, out);
    rc = sxp_attr_hold_time_get_val(attr, &min_val, &max_val, &has_max_val,
                                    code, subcode);
    if (sxp_isnotok(rc, *code, *subcode)) {
        goto out;
    }
    PLOG_TRACE_FMT(peer, "Found minimum hold-time %" PRIu16, min_val);
    if (has_max_val) {
        PLOG_TRACE_FMT(peer, "Found maximum hold-time %" PRIu16, max_val);
    }
    if (has_max_val) {
        if (PEER_SPEAKER == peer->type) {
            PLOG_ERROR_MSG(
                peer,
                "Hold-time attribute from speaker with maximum hold-time");
            *code = SXP_ERR_CODE_OPEN;
            *subcode = SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE;
            goto out;
            PLOG_DEBUG_MSG(peer, "Ignoring maximum hold-time from speaker");
        }
    } else if (PEER_SPEAKER != peer->type && min_val != KEEPALIVE_UNUSED) {
        PLOG_ERROR_FMT(peer,
                       "Hold-time attribute from %s without maximum hold-time",
                       sxp_peer_type_string(peer->type));
        *code = SXP_ERR_CODE_OPEN;
        *subcode = SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE;
        goto out;
    }
    if (PEER_SPEAKER != peer->type) {
        if (KEEPALIVE_UNUSED == peer->sxpd_ctx->speaker_min_hold_time) {
            PLOG_DEBUG_MSG(peer, "Ignoring hold-time attribute from peer,"
                                 " because keep-alive mechanism is unused");
            peer->listener_hold_time = KEEPALIVE_UNUSED;
        } else if (KEEPALIVE_UNUSED == min_val) {
            PLOG_TRACE_MSG(peer,
                           "Listener indicates keep-alive mechanism is unused");
            peer->listener_hold_time = KEEPALIVE_UNUSED;
        } else if (min_val > 0 && min_val < HOLD_TIME_MINIMUM_MINIMUM) {
            PLOG_ERROR_FMT(peer, "Minimum hold-time value %" PRIu16
                                 " below minimum allowed value %d",
                           min_val, HOLD_TIME_MINIMUM_MINIMUM);
            *code = SXP_ERR_CODE_OPEN;
            *subcode = SXP_SUB_ERR_CODE_UNACCEPTABLE_HOLD_TIME;
        } else if (max_val < peer->sxpd_ctx->speaker_min_hold_time) {
            PLOG_ERROR_FMT(
                peer,
                "Maximum hold-time value %" PRIu16
                " smaller than minimum configured speaker hold-time %" PRIu16,
                max_val, peer->sxpd_ctx->speaker_min_hold_time);
            *code = SXP_ERR_CODE_OPEN;
            *subcode = SXP_SUB_ERR_CODE_UNACCEPTABLE_HOLD_TIME;
        } else {
            if (peer->sxpd_ctx->speaker_min_hold_time < min_val) {
                PLOG_TRACE_FMT(
                    peer, "Configured speaker minimum hold-time %" PRIu16
                          " is smaller than listener provided value %" PRIu16,
                    peer->sxpd_ctx->speaker_min_hold_time, min_val);
                peer->listener_hold_time = min_val;
            } else if (peer->sxpd_ctx->speaker_min_hold_time == min_val) {
                PLOG_TRACE_FMT(peer,
                               "Configured speaker minimum hold-time %" PRIu16
                               " match listener provided value %" PRIu16,
                               peer->sxpd_ctx->speaker_min_hold_time, min_val);
                peer->listener_hold_time =
                    peer->sxpd_ctx->speaker_min_hold_time;
            } else {
                PLOG_TRACE_FMT(
                    peer, "Configured speaker minimum hold-time %" PRIu16
                          " is higher than listener provided value %" PRIu16,
                    peer->sxpd_ctx->speaker_min_hold_time, min_val);
                peer->listener_hold_time =
                    peer->sxpd_ctx->speaker_min_hold_time;
            }
            PLOG_TRACE_FMT(peer,
                           "Negotiated listener hold-time value of %" PRIu16
                           " seconds",
                           peer->listener_hold_time);
        }
    } else {
        if (KEEPALIVE_UNUSED == peer->sxpd_ctx->listener_min_hold_time) {
            PLOG_DEBUG_MSG(peer, "Ignoring hold-time attribute from peer,"
                                 " because keep-alive mechanism is unused");
            peer->speaker_hold_time = KEEPALIVE_UNUSED;
        } else if (KEEPALIVE_UNUSED == min_val) {
            PLOG_TRACE_MSG(peer,
                           "Speaker indicates keep-alive mechanism is unused");
            peer->speaker_hold_time = KEEPALIVE_UNUSED;
        } else if (min_val > 0 && min_val < HOLD_TIME_MINIMUM_MINIMUM) {
            PLOG_ERROR_FMT(peer, "Minimum hold-time value %" PRIu16
                                 " smaller then minimum allowed value %d",
                           min_val, HOLD_TIME_MINIMUM_MINIMUM);
            *code = SXP_ERR_CODE_OPEN;
            *subcode = SXP_SUB_ERR_CODE_UNACCEPTABLE_HOLD_TIME;
        } else if (min_val > peer->sxpd_ctx->listener_max_hold_time) {
            PLOG_ERROR_FMT(peer, "Minimum hold-time value %" PRIu16
                                 " is greater than maximum configured listener "
                                 "hold-time %" PRIu16,
                           min_val, peer->sxpd_ctx->speaker_min_hold_time);
            *code = SXP_ERR_CODE_OPEN;
            *subcode = SXP_SUB_ERR_CODE_UNACCEPTABLE_HOLD_TIME;
        } else {
            if (peer->sxpd_ctx->listener_min_hold_time < min_val) {
                PLOG_TRACE_FMT(peer,
                               "Configured listener minimum hold-time %" PRIu16
                               " is lower then speaker provided value %" PRIu16,
                               peer->sxpd_ctx->speaker_min_hold_time, min_val);
                peer->speaker_hold_time = min_val;
            } else {
                PLOG_TRACE_FMT(
                    peer, "Configured listener minimum hold-time %" PRIu16
                          " is higher than speaker provided value %" PRIu16,
                    peer->sxpd_ctx->speaker_min_hold_time, min_val);
                peer->speaker_hold_time =
                    peer->sxpd_ctx->listener_min_hold_time;
            }
            PLOG_TRACE_FMT(peer,
                           "Negotiated speaker hold-time value of %" PRIu16
                           " seconds",
                           peer->speaker_hold_time);
        }
    }
out:
    return rc;
}

/**
 * @brief validate and process attribute found in OPEN message
 *
 * @param peer peer from which the open message came
 * @param msg the message
 * @param attr attribute to process
 * @param[out] code error code found during processing
 * @param[out] subcode error sub-code found during processing
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_process_open_attr(struct sxpd_peer *peer, struct sxp_msg *msg,
                                  struct sxp_attribute *attr,
                                  enum sxp_error_code *code,
                                  enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    enum sxp_attr_type type = SXP_ATTR_TYPE_NODE_ID;
    PARAM_NULL_CHECK(rc, peer, msg, attr, code, subcode);
    if (RC_ISOK(rc)) {
        rc = sxp_attr_get_type(attr, &type);
    }
    if (RC_ISOK(rc)) {
        PLOG_TRACE_FMT(peer, "Processing %s attribute",
                       sxp_attr_type_string(type));
        switch (type) {
        case SXP_ATTR_TYPE_NODE_ID:
            if (peer->version < 3) {
                PLOG_ERROR_FMT(
                    peer, "Unexpected attribute %s in %s message from v%" PRIu32
                          " peer",
                    sxp_attr_type_string(type), sxp_msg_type_string(msg->type),
                    peer->version);
                rc = -1;
            } else {
                rc = sxpd_process_node_id_attr(peer, attr, code, subcode);
            }
            break;
        case SXP_ATTR_TYPE_CAPABILITIES:
            if (peer->version < 3) {
                PLOG_ERROR_FMT(
                    peer, "Unexpected attribute %s in %s message from v%" PRIu32
                          " peer",
                    sxp_attr_type_string(type), sxp_msg_type_string(msg->type),
                    peer->version);
                rc = -1;
            } else {
                rc = sxpd_process_capabilities_attr(peer, attr, code, subcode);
            }

            break;
        case SXP_ATTR_TYPE_HOLD_TIME:
            if (peer->version < 3) {
                PLOG_ERROR_FMT(
                    peer, "Unexpected attribute %s in %s message from v%" PRIu32
                          " peer",
                    sxp_attr_type_string(type), sxp_msg_type_string(msg->type),
                    peer->version);
                rc = -1;
            } else {
                rc =
                    sxpd_process_open_hold_time_attr(peer, attr, code, subcode);
            }
            break;
        case SXP_ATTR_TYPE_ADD_IPV4:
        /*fallthrough*/
        case SXP_ATTR_TYPE_ADD_IPV6:
        /*fallthrough*/
        case SXP_ATTR_TYPE_DEL_IPV4:
        /*fallthrough*/
        case SXP_ATTR_TYPE_DEL_IPV6:
        /*fallthrough*/
        case SXP_ATTR_TYPE_IPV4_ADD_PREFIX:
        /*fallthrough*/
        case SXP_ATTR_TYPE_IPV4_DEL_PREFIX:
        /*fallthrough*/
        case SXP_ATTR_TYPE_IPV6_ADD_PREFIX:
        /*fallthrough*/
        case SXP_ATTR_TYPE_IPV6_DEL_PREFIX:
        /*fallthrough*/
        case SXP_ATTR_TYPE_PEER_SEQUENCE:
        /*fallthrough*/
        case SXP_ATTR_TYPE_SGT:
            PLOG_ERROR_FMT(peer, "Unexpected attribute %s in %s message",
                           sxp_attr_type_string(type),
                           sxp_msg_type_string(msg->type));
            break;
        }
    }
    return rc;
}

/**
 * @brief set default flags and capabilities based on peer's version
 *
 * @param peer peer to set defaults for
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_setup_default_capabilities(struct sxpd_peer *peer)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, peer);
    RC_CHECK(rc, out);
    if (4 == peer->version) {
        peer->flags.handles_peer_seq = true;
        peer->flags.handles_sxp_v4_attributes = true;
        peer->flags.always_export_subnets = false;
    } else if (3 == peer->version) {
        peer->flags.ipv4 = true;
        peer->flags.ipv6 = true;
        peer->flags.sub_bind = true;
        peer->flags.handles_sxp_v4_attributes = false;
        peer->flags.always_export_subnets = false;
        PLOG_TRACE_FMT(
            peer, "Setting default capabilities for v3 peer: %s %s %s",
            sxp_capability_code_string(SXP_CAPABILITY_IPV4_UNICAST),
            sxp_capability_code_string(SXP_CAPABILITY_IPV6_UNICAST),
            sxp_capability_code_string(SXP_CAPABILITY_SUBNET_BINDINGS));
    } else if (2 == peer->version) {
        peer->flags.ipv4 = true;
        peer->flags.ipv6 = true;
        peer->flags.sub_bind = false;
        peer->flags.handles_sxp_v4_attributes = false;
        peer->flags.always_export_subnets = false;
        PLOG_TRACE_FMT(peer, "Setting default capabilities for v2 peer: %s %s",
                       sxp_capability_code_string(SXP_CAPABILITY_IPV4_UNICAST),
                       sxp_capability_code_string(SXP_CAPABILITY_IPV6_UNICAST));
    } else if (1 == peer->version) {
        peer->flags.ipv4 = true;
        peer->flags.ipv6 = false;
        peer->flags.sub_bind = false;
        peer->flags.always_export_subnets = false;
        peer->flags.handles_sxp_v4_attributes = false;
        PLOG_TRACE_FMT(peer, "Setting default capabilities for v1 peer: %s",
                       sxp_capability_code_string(SXP_CAPABILITY_IPV4_UNICAST));
    }
out:
    return rc;
}

/**
 * @brief process OPEN message from peer
 *
 * @param peer peer who sent the OPEN message
 * @param socket socket on which the message was received
 * @param msg message received
 * @param[out] code error code found during processing
 * @param[out] subcode error sub-code found during processing
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_process_open_msg(struct sxpd_peer *peer,
                                 struct evmgr_socket *socket,
                                 struct sxp_msg *msg, enum sxp_error_code *code,
                                 enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    uint32_t version = 0;
    bool have_node_id = false;
    bool have_capabilities = false;
    PARAM_NULL_CHECK(rc, peer, socket, msg, code, subcode);
    RC_CHECK(rc, out);
    if (peer->incoming != socket) {
        PLOG_ERROR_FMT(
            peer,
            "Unexpected OPEN message - socket %p is not incoming socket %p",
            (void *)socket, (void *)peer->incoming);
        *code = SXP_ERR_CODE_OPEN;
        goto out;
    } else if (peer->flags.incoming_negotiation_done) {
        PLOG_ERROR_FMT(peer, "Negotiation already done, %s msg unexpected",
                       sxp_msg_type_string(msg->type));
        *code = SXP_ERR_CODE_OPEN;
        goto out;
    } else {
        RC_CHECK(rc = sxp_open_get_version(msg, &version), out);
        if (4 < version) {
            PLOG_ERROR_FMT(peer, "Unsupported protocol version %" PRIu32,
                           version);
            *code = SXP_ERR_CODE_OPEN;
            goto out;
        }
    }
    peer->listener_hold_time = KEEPALIVE_UNUSED;
    peer->speaker_hold_time = KEEPALIVE_UNUSED;
    PLOG_TRACE_FMT(peer, "Processing %s message - version is %" PRIu32,
                   sxp_msg_type_string(msg->type), version);
    peer->version = version;
    RC_CHECK(rc = sxpd_setup_default_capabilities(peer), out);
    enum sxp_mode mode = SXP_MODE_SPEAKER;
    RC_CHECK(rc = sxp_open_get_mode(msg, &mode), out);
    if ((peer->type != PEER_SPEAKER && SXP_MODE_LISTENER != mode) ||
        (peer->type == PEER_SPEAKER && SXP_MODE_SPEAKER != mode)) {
        PLOG_ERROR_FMT(peer, "Unexpected mode %s in %s message from %s peer",
                       sxp_mode_string(mode), sxp_msg_type_string(msg->type),
                       sxp_peer_type_string(peer->type));
        *code = SXP_ERR_CODE_OPEN;
        goto out;
    }

    struct sxp_attribute *attr = NULL;
    while (sxp_isok(rc, *code, *subcode)) {
        rc = sxp_parse_msg(msg, attr, &attr, code, subcode);
        if (sxp_isnotok(rc, *code, *subcode)) {
            goto out;
        }
        if (!attr) {
            break;
        }
        enum sxp_attr_type type;
        RC_CHECK(rc = sxp_attr_get_type(attr, &type), out);
        if (SXP_ATTR_TYPE_NODE_ID == type) {
            have_node_id = true;
        } else if (SXP_ATTR_TYPE_CAPABILITIES == type) {
            have_capabilities = true;
        }
        rc = sxpd_process_open_attr(peer, msg, attr, code, subcode);
    }

    if (4 == peer->version) {
        if (peer->type == PEER_SPEAKER && !have_node_id) {
            PLOG_ERROR_FMT(peer, "Missing node-id attribute in %s message",
                           sxp_msg_type_string(msg->type));
            *code = SXP_ERR_CODE_OPEN;
            *subcode = SXP_SUB_ERR_CODE_MISSING_WELL_KNOWN_ATTRIBUTE;
            goto out;
        } else if (peer->type != PEER_SPEAKER && have_node_id) {
            PLOG_ERROR_FMT(peer, "Unexpected node-id attribute in %s message",
                           sxp_msg_type_string(msg->type));
            *code = SXP_ERR_CODE_OPEN;
            *subcode = SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE;
            goto out;
        } else if (!have_capabilities && peer->type != PEER_SPEAKER) {
            PLOG_ERROR_FMT(peer, "Missing capabilities attribute in %s message",
                           sxp_msg_type_string(msg->type));
            *code = SXP_ERR_CODE_OPEN;
            *subcode = SXP_SUB_ERR_CODE_MISSING_WELL_KNOWN_ATTRIBUTE;
            goto out;
        }
    }

    if (sxp_isok(rc, *code, *subcode)) {
        rc = sxpd_send_open_resp(peer);
        if (RC_ISOK(rc)) {
            if (PEER_SPEAKER == peer->type) {
                peer->speaker = socket;
                rc = sxpd_speaker_connected(peer);
            } else {
                /* if the config is both, then the listener initiates the
                 * connection and sends OPEN message, so the other side is
                 * listener here */
                peer->listener = socket;
                rc = sxpd_listener_connected(peer);
            }
        } else {
            PLOG_ERROR_MSG(peer,
                           "Could not send OPEN_RESP message - disconnect");
            rc = sxpd_disconnect_peer_socket(peer, socket, true);
        }
    }
out:
    return rc;
}

/**
 * @brief process hold time attribute found in OPEN_RESP message and store the
 *values in peer structure if applicable
 *
 * @param peer peer from which the OPEN_RESP message was received
 * @param attr hold time attribute to process
 * @param[out] code error code found during processing
 * @param[out] subcode error sub-code found during processing
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_process_open_resp_hold_time_attr(
    struct sxpd_peer *peer, struct sxp_attribute *attr,
    enum sxp_error_code *code, enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    uint16_t min_val = 0;
    uint16_t max_val = 0;
    bool has_max_val = false;
    PARAM_NULL_CHECK(rc, peer, attr, code, subcode);
    RC_CHECK(rc, out);
    rc = sxp_attr_hold_time_get_val(attr, &min_val, &max_val, &has_max_val,
                                    code, subcode);
    if (sxp_isnotok(rc, *code, *subcode)) {
        goto out;
    }
    PLOG_TRACE_FMT(peer, "Found minimum hold-time %" PRIu16, min_val);
    if (has_max_val) {
        PLOG_TRACE_FMT(peer, "Found maximum hold-time %" PRIu16, max_val);
    }

    if (PEER_LISTENER == peer->type) {
        if (KEEPALIVE_UNUSED == peer->sxpd_ctx->speaker_min_hold_time) {
            PLOG_DEBUG_MSG(peer, "Ignoring hold-time attribute from peer,"
                                 " because keep-alive mechanism is unused");
        } else if (KEEPALIVE_UNUSED == min_val) {
            PLOG_TRACE_MSG(peer,
                           "Listener indicates keep-alive mechanism is unused");
            peer->listener_hold_time = KEEPALIVE_UNUSED;
        } else if (min_val > 0 && min_val < HOLD_TIME_MINIMUM_MINIMUM) {
            PLOG_ERROR_FMT(peer, "Minimum hold-time value %" PRIu16
                                 " below minimum allowed value %d",
                           min_val, HOLD_TIME_MINIMUM_MINIMUM);
            *code = SXP_ERR_CODE_OPEN;
            *subcode = SXP_SUB_ERR_CODE_UNACCEPTABLE_HOLD_TIME;
        } else if (has_max_val &&
                   max_val < peer->sxpd_ctx->speaker_min_hold_time) {
            PLOG_ERROR_FMT(
                peer,
                "Maximum hold-time value %" PRIu16
                " smaller than minimum configured speaker hold-time %" PRIu16,
                max_val, peer->sxpd_ctx->speaker_min_hold_time);
            *code = SXP_ERR_CODE_OPEN;
            *subcode = SXP_SUB_ERR_CODE_UNACCEPTABLE_HOLD_TIME;
        } else {
            if (min_val < peer->sxpd_ctx->speaker_min_hold_time) {
                PLOG_TRACE_FMT(peer, "Minimum hold-time value %" PRIu16
                                     " smaller than minimum configured speaker "
                                     "hold-time %" PRIu16,
                               min_val, peer->sxpd_ctx->speaker_min_hold_time);
                peer->listener_hold_time =
                    peer->sxpd_ctx->speaker_min_hold_time;
            } else if (min_val > peer->sxpd_ctx->speaker_min_hold_time) {
                PLOG_TRACE_FMT(peer, "Minimum hold-time value %" PRIu16
                                     " greater than minimum configured speaker "
                                     "hold-time %" PRIu16,
                               min_val, peer->sxpd_ctx->speaker_min_hold_time);
                peer->listener_hold_time = min_val;
            } else {
                PLOG_TRACE_FMT(
                    peer,
                    "Minimum hold-time value %" PRIu16
                    " equal minimum configured speaker hold-time %" PRIu16,
                    min_val, peer->sxpd_ctx->speaker_min_hold_time);
                peer->listener_hold_time = min_val;
            }
            PLOG_TRACE_FMT(peer,
                           "Negotiated listener hold-time value of %" PRIu16
                           " seconds",
                           peer->listener_hold_time);
        }
    } else {
        if (has_max_val) {
            PLOG_ERROR_FMT(peer,
                           "Hold-time attribute with maximum hold-time in "
                           "%s message ",
                           sxp_msg_type_string(SXP_MSG_OPEN_RESP));
            *code = SXP_ERR_CODE_OPEN;
            *subcode = SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE;
            goto out;
        } else if (KEEPALIVE_UNUSED == peer->sxpd_ctx->listener_min_hold_time) {
            PLOG_DEBUG_MSG(peer, "Ignoring hold-time attribute from peer,"
                                 " because keep-alive mechanism is unused");
            peer->speaker_hold_time = KEEPALIVE_UNUSED;
        } else if (KEEPALIVE_UNUSED == min_val) {
            PLOG_TRACE_MSG(peer,
                           "Speaker indicates keep-alive mechanism is unused");
            peer->speaker_hold_time = KEEPALIVE_UNUSED;
        } else if (min_val > 0 && min_val < HOLD_TIME_MINIMUM_MINIMUM) {
            PLOG_ERROR_FMT(peer, "Minimum hold-time value %" PRIu16
                                 " smaller then minimum allowed value %d",
                           min_val, HOLD_TIME_MINIMUM_MINIMUM);
            *code = SXP_ERR_CODE_OPEN;
            *subcode = SXP_SUB_ERR_CODE_UNACCEPTABLE_HOLD_TIME;
        } else if (min_val > peer->sxpd_ctx->listener_max_hold_time) {
            PLOG_ERROR_FMT(
                peer,
                "Minimum hold-time value %" PRIu16
                " is greater than configured listener hold-time range <%" PRIu16
                ", %" PRIu16 ">",
                min_val, peer->sxpd_ctx->listener_min_hold_time,
                peer->sxpd_ctx->listener_max_hold_time);
            *code = SXP_ERR_CODE_OPEN;
            *subcode = SXP_SUB_ERR_CODE_UNACCEPTABLE_HOLD_TIME;
        } else if (min_val < peer->sxpd_ctx->listener_min_hold_time) {
            PLOG_TRACE_FMT(
                peer,
                "Minimum hold-time value %" PRIu16
                " is smaller than configured listener hold-time range <%" PRIu16
                ", %" PRIu16 ">",
                min_val, peer->sxpd_ctx->listener_min_hold_time,
                peer->sxpd_ctx->listener_max_hold_time);
            peer->speaker_hold_time = peer->sxpd_ctx->listener_min_hold_time;
            PLOG_TRACE_FMT(peer,
                           "Negotiated speaker hold-time value of %" PRIu16
                           " seconds",
                           peer->speaker_hold_time);
        } else {
            PLOG_TRACE_FMT(
                peer, "Minimum hold-time value %" PRIu16
                      " is in configured listener hold-time range <%" PRIu16
                      ", %" PRIu16 ">",
                min_val, peer->sxpd_ctx->listener_min_hold_time,
                peer->sxpd_ctx->listener_max_hold_time);
            peer->speaker_hold_time = min_val;
            PLOG_TRACE_FMT(peer,
                           "Negotiated speaker hold-time value of %" PRIu16
                           " seconds",
                           peer->speaker_hold_time);
        }
    }
out:
    return rc;
}

/**
 * @brief validate and process attribute found in OPEN_RESP message
 *
 * @param peer peer from which the open message came
 * @param msg the message
 * @param attr attribute to process
 * @param[out] code error code found during processing
 * @param[out] subcode error sub-code found during processing
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_process_open_resp_attr(struct sxpd_peer *peer,
                                       struct sxp_msg *msg,
                                       struct sxp_attribute *attr,
                                       enum sxp_error_code *code,
                                       enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    enum sxp_attr_type type = SXP_ATTR_TYPE_NODE_ID;
    PARAM_NULL_CHECK(rc, peer, msg, attr, code, subcode);
    if (RC_ISOK(rc)) {
        rc = sxp_attr_get_type(attr, &type);
    }
    if (RC_ISOK(rc)) {
        PLOG_TRACE_FMT(peer, "Processing %s attribute",
                       sxp_attr_type_string(type));
        switch (type) {
        case SXP_ATTR_TYPE_NODE_ID:
            if (peer->version < 3) {
                PLOG_ERROR_FMT(
                    peer, "Unexpected attribute %s in %s message from v%" PRIu32
                          " peer",
                    sxp_attr_type_string(type), sxp_msg_type_string(msg->type),
                    peer->version);
                rc = -1;
            } else {
                rc = sxpd_process_node_id_attr(peer, attr, code, subcode);
            }
            break;
        case SXP_ATTR_TYPE_CAPABILITIES:
            if (peer->version < 3) {
                PLOG_ERROR_FMT(
                    peer, "Unexpected attribute %s in %s message from v%" PRIu32
                          " peer",
                    sxp_attr_type_string(type), sxp_msg_type_string(msg->type),
                    peer->version);
                rc = -1;
            } else {
                rc = sxpd_process_capabilities_attr(peer, attr, code, subcode);
            }

            break;
        case SXP_ATTR_TYPE_HOLD_TIME:
            if (peer->version < 3) {
                PLOG_ERROR_FMT(
                    peer, "Unexpected attribute %s in %s message from v%" PRIu32
                          " peer",
                    sxp_attr_type_string(type), sxp_msg_type_string(msg->type),
                    peer->version);
                rc = -1;
            } else {
                rc = sxpd_process_open_resp_hold_time_attr(peer, attr, code,
                                                           subcode);
            }
            break;
        case SXP_ATTR_TYPE_ADD_IPV4:
        /*fallthrough*/
        case SXP_ATTR_TYPE_ADD_IPV6:
        /*fallthrough*/
        case SXP_ATTR_TYPE_DEL_IPV4:
        /*fallthrough*/
        case SXP_ATTR_TYPE_DEL_IPV6:
        /*fallthrough*/
        case SXP_ATTR_TYPE_IPV4_ADD_PREFIX:
        /*fallthrough*/
        case SXP_ATTR_TYPE_IPV4_DEL_PREFIX:
        /*fallthrough*/
        case SXP_ATTR_TYPE_IPV6_ADD_PREFIX:
        /*fallthrough*/
        case SXP_ATTR_TYPE_IPV6_DEL_PREFIX:
        /*fallthrough*/
        case SXP_ATTR_TYPE_PEER_SEQUENCE:
        /*fallthrough*/
        case SXP_ATTR_TYPE_SGT:
            PLOG_ERROR_FMT(peer, "Unexpected attribute %s in %s message",
                           sxp_attr_type_string(type),
                           sxp_msg_type_string(msg->type));
            break;
        }
    }
    return rc;
}

/**
 * @brief process OPEN message from peer
 *
 * @param peer peer who sent the OPEN message
 * @param socket socket on which the message was received
 * @param msg message received
 * @param[out] code error code found during processing
 * @param[out] subcode error sub-code found during processing
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_process_open_resp_msg(struct sxpd_peer *peer,
                                      struct evmgr_socket *socket,
                                      struct sxp_msg *msg,
                                      enum sxp_error_code *code,
                                      enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    uint32_t version = 0;
    bool have_node_id = false;
    bool have_capabilities = false;
    bool have_hold_time = false;
    PARAM_NULL_CHECK(rc, peer, socket, msg, code, subcode);
    RC_CHECK(rc, out);
    if (peer->outgoing != socket) {
        PLOG_ERROR_FMT(peer, "Unexpected %s message - socket %p is not "
                             "outgoing socket %p",
                       sxp_msg_type_string(msg->type), (void *)socket,
                       (void *)peer->outgoing);
        *code = SXP_ERR_CODE_OPEN;
        goto out;
    } else if (WAITING_OPEN_RESP != peer->outgoing_state) {
        PLOG_UNEXPECTED_OUT_CONN_STATE(peer, "processing OPEN_RESP message");
        *code = SXP_ERR_CODE_OPEN;
        goto out;
    } else {
        rc = sxp_open_get_version(msg, &version);
        if (RC_ISOK(rc) && 4 < version) {
            PLOG_ERROR_FMT(peer, "Unsupported protocol version %" PRIu32,
                           version);
            *code = SXP_ERR_CODE_OPEN;
            goto out;
        }
    }
    PLOG_TRACE_FMT(peer, "Processing %s message - version is %" PRIu32,
                   sxp_msg_type_string(msg->type), version);
    peer->version = version;
    RC_CHECK(rc = sxpd_setup_default_capabilities(peer), out);
    enum sxp_mode mode = SXP_MODE_SPEAKER;
    RC_CHECK(rc = sxp_open_get_mode(msg, &mode), out);
    if ((peer->type != PEER_LISTENER && SXP_MODE_SPEAKER != mode) ||
        (peer->type == PEER_LISTENER && SXP_MODE_LISTENER != mode)) {
        PLOG_ERROR_FMT(peer, "Unexpected mode %s in %s message from %s peer",
                       sxp_mode_string(mode), sxp_msg_type_string(msg->type),
                       sxp_peer_type_string(peer->type));
        *code = SXP_ERR_CODE_OPEN;
        goto out;
    }
    struct sxp_attribute *attr = NULL;
    while (sxp_isok(rc, *code, *subcode)) {
        rc = sxp_parse_msg(msg, attr, &attr, code, subcode);
        if (sxp_isnotok(rc, *code, *subcode)) {
            goto out;
        }
        if (!attr) {
            break;
        }
        enum sxp_attr_type type;
        RC_CHECK(rc = sxp_attr_get_type(attr, &type), out);
        if (SXP_ATTR_TYPE_NODE_ID == type) {
            have_node_id = true;
        } else if (SXP_ATTR_TYPE_CAPABILITIES == type) {
            have_capabilities = true;
        } else if (SXP_ATTR_TYPE_HOLD_TIME == type) {
            have_hold_time = true;
        }
        rc = sxpd_process_open_resp_attr(peer, msg, attr, code, subcode);
    }

    if (4 == peer->version) {
        if (peer->type != PEER_LISTENER && !have_node_id) {
            PLOG_ERROR_FMT(peer, "Missing node-id attribute in %s message",
                           sxp_msg_type_string(msg->type));
            *code = SXP_ERR_CODE_OPEN;
            *subcode = SXP_SUB_ERR_CODE_MISSING_WELL_KNOWN_ATTRIBUTE;
            goto out;
        } else if (peer->type == PEER_LISTENER && have_node_id) {
            PLOG_ERROR_FMT(peer, "Unexpected node-id attribute in %s message",
                           sxp_msg_type_string(msg->type));
            *code = SXP_ERR_CODE_OPEN;
            *subcode = SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE;
            goto out;
        } else if (!have_capabilities && PEER_LISTENER == peer->type) {
            PLOG_ERROR_FMT(peer, "Missing capabilities attribute in %s message",
                           sxp_msg_type_string(msg->type));
            *code = SXP_ERR_CODE_OPEN;
            *subcode = SXP_SUB_ERR_CODE_MISSING_WELL_KNOWN_ATTRIBUTE;
            goto out;
        } else if (!have_hold_time) {
            uint16_t min_hold_time = KEEPALIVE_UNUSED;
            switch (peer->type) {
            case PEER_SPEAKER:
            /* fallthrough */
            case PEER_BOTH:
                min_hold_time = peer->sxpd_ctx->listener_min_hold_time;
                break;
            case PEER_LISTENER:
                min_hold_time = peer->sxpd_ctx->speaker_min_hold_time;
                break;
            }
            if (KEEPALIVE_UNUSED != min_hold_time) {
                PLOG_ERROR_FMT(peer,
                               "Missing hold-time attribute in %s message",
                               sxp_msg_type_string(msg->type));
            }
        }
    }

    if (sxp_isok(rc, *code, *subcode)) {
        PEER_CHANGE_OUT_CONN_STATE(peer, CONNECTED);
        /* if the config is both, then listener initiates connection, so the
         * other side is speaker */
        if (PEER_LISTENER != peer->type) {
            peer->speaker = socket;
            rc = sxpd_speaker_connected(peer);
        } else {
            peer->listener = socket;
            rc = sxpd_listener_connected(peer);
        }
    }

out:
    return rc;
}

/**
 * @brief check if sxp attribute is consistent with peer's declared sxp version
 *
 * @param peer peer which sent the attribute
 * @param type attribute type
 * @param code error code filled if attribute is inconsistent
 * @param subcode error sub-code filled if attribute is inconsistent
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_check_attribute_version(struct sxpd_peer *peer,
                                        enum sxp_attr_type type,
                                        enum sxp_error_code *code,
                                        enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, peer, code, subcode);
    RC_CHECK(rc, out);
    switch (type) {
    case SXP_ATTR_TYPE_ADD_IPV4:
    /*fallthrough*/
    case SXP_ATTR_TYPE_ADD_IPV6:
    /*fallthrough*/
    case SXP_ATTR_TYPE_DEL_IPV4:
    /*fallthrough*/
    case SXP_ATTR_TYPE_DEL_IPV6:
        if (peer->version > 3) {
            PLOG_ERROR_FMT(
                peer, "Unexpected attribute %s from peer of version %" PRIu32,
                sxp_attr_type_string(type), peer->version);
            *code = SXP_ERR_CODE_UPDATE;
            *subcode = SXP_SUB_ERR_CODE_ATTRIBUTE_FLAGS_ERROR;
        }
        break;

    case SXP_ATTR_TYPE_IPV4_ADD_PREFIX:
    /*fallthrough*/
    case SXP_ATTR_TYPE_IPV6_ADD_PREFIX:
    /*fallthrough*/
    case SXP_ATTR_TYPE_IPV4_DEL_PREFIX:
    /*fallthrough*/
    case SXP_ATTR_TYPE_IPV6_DEL_PREFIX:
    /*fallthrough*/
    case SXP_ATTR_TYPE_PEER_SEQUENCE:
    /*fallthrough*/
    case SXP_ATTR_TYPE_SGT:
        if (peer->version <= 3) {
            PLOG_ERROR_FMT(
                peer, "Unexpected attribute %s from peer of version %" PRIu32,
                sxp_attr_type_string(type), peer->version);
            *code = SXP_ERR_CODE_UPDATE;
            *subcode = SXP_SUB_ERR_CODE_ATTRIBUTE_FLAGS_ERROR;
        }
        break;

    case SXP_ATTR_TYPE_NODE_ID:
    /*fallthrough*/
    case SXP_ATTR_TYPE_CAPABILITIES:
    /*fallthrough*/
    case SXP_ATTR_TYPE_HOLD_TIME:
        PLOG_ERROR_FMT(peer, "Unexpected attribute %s in %s message",
                       sxp_attr_type_string(type),
                       sxp_msg_type_string(SXP_MSG_UPDATE));
        *code = SXP_ERR_CODE_UPDATE;
        *subcode = SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE_LIST;
        goto out;
    }
out:
    return rc;
}

/**
 * @brief validate prefix-list attribute from peer
 *
 * @param peer peer which sent the update message
 * @param type sxp attribute type
 * @param attr prefix-list attribute
 * @param[out] code error code found during processing
 * @param[out] subcode error sub-code found during processing
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_validate_prefix_list(struct sxpd_peer *peer,
                                     struct sxp_attribute *attr,
                                     enum sxp_attr_type type,
                                     enum sxp_error_code *code,
                                     enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, peer, attr, code, subcode);
    RC_CHECK(rc, out);
    struct sxp_prefix *prefix = NULL;
    do {
        rc = sxp_parse_prefix_list(attr, prefix, &prefix, code, subcode);
        if (sxp_isnotok(rc, *code, *subcode) || !prefix) {
            break;
        }
        struct v4_v6_prefix tmp;
        memset(&tmp, 0, sizeof(tmp));
        rc = sxp_parse_prefix(prefix, tmp.ip.data, sizeof(tmp.ip.data),
                              &tmp.len);
        RC_CHECK(rc, out);
        if (0 == tmp.len) {
            PLOG_ERROR_FMT(peer, "Invalid attribute %s in %s message",
                           sxp_attr_type_string(type),
                           sxp_msg_type_string(SXP_MSG_UPDATE));
            *code = SXP_ERR_CODE_UPDATE;
            *subcode = SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE_LIST;
        }
    } while (RC_ISOK(rc));
out:
    return rc;
}

/**
 * @brief validate UPDATE message - check if it does not break the spec
 *
 * @param peer peer which sent the message
 * @param msg the message
 * @param[out] err_attr filled with pointer to invalid attribute if found
 * @param[out] code error code found during validation
 * @param[out] subcode error sub-code found during validation
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_validate_update_msg(struct sxpd_peer *peer, struct sxp_msg *msg,
                                    struct sxp_attribute **err_attr,
                                    enum sxp_error_code *code,
                                    enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, peer, msg, err_attr, code, subcode);
    RC_CHECK(rc, out);
    struct sxp_attribute *attr = NULL;
    bool have_peer_sequence = false;
    bool have_sgt = false;
    for (;;) {
        rc = sxp_parse_msg(msg, attr, &attr, code, subcode);
        RC_CHECK(rc, out);
        if (sxp_isnotok(rc, *code, *subcode)) {
            if (SXP_ERR_CODE_NONE == *code) {
                *code = SXP_ERR_CODE_UPDATE;
            }
            *err_attr = attr;
            goto out;
        }
        if (!attr) {
            break;
        }
        enum sxp_attr_type type;
        RC_CHECK(rc = sxp_attr_get_type(attr, &type), out);
        switch (type) {
        case SXP_ATTR_TYPE_NODE_ID:
        /*fallthrough*/
        case SXP_ATTR_TYPE_CAPABILITIES:
        /*fallthrough*/
        case SXP_ATTR_TYPE_HOLD_TIME:
            PLOG_ERROR_FMT(peer, "Unexpected attribute %s in %s message",
                           sxp_attr_type_string(type),
                           sxp_msg_type_string(msg->type));
            *code = SXP_ERR_CODE_UPDATE;
            *subcode = SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE_LIST;
            *err_attr = attr;
            goto out;
        case SXP_ATTR_TYPE_IPV4_ADD_PREFIX:
        /*fallthrough*/
        case SXP_ATTR_TYPE_IPV6_ADD_PREFIX:
            if (!have_peer_sequence || !have_sgt) {
                PLOG_DEBUG_FMT(
                    peer, "Found %s attribute without preceding %s attribute",
                    sxp_attr_type_string(type),
                    sxp_attr_type_string(have_peer_sequence
                                             ? SXP_ATTR_TYPE_SGT
                                             : SXP_ATTR_TYPE_PEER_SEQUENCE));
                *code = SXP_ERR_CODE_UPDATE;
                *subcode = SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE_LIST;
                goto out;
            }
#ifndef UPDATE_MSG_ATTR_INHERITANCE
            have_peer_sequence = false;
            have_sgt = false;
#endif
        case SXP_ATTR_TYPE_IPV4_DEL_PREFIX:
        /*fallthrough*/
        case SXP_ATTR_TYPE_IPV6_DEL_PREFIX:
            rc = sxpd_validate_prefix_list(peer, attr, type, code, subcode);
            if (sxp_isnotok(rc, *code, *subcode)) {
                *err_attr = attr;
                goto out;
            }
            break;
        case SXP_ATTR_TYPE_ADD_IPV4:
        /*fallthrough*/
        case SXP_ATTR_TYPE_ADD_IPV6:
        /*fallthrough*/
        case SXP_ATTR_TYPE_DEL_IPV4:
        /*fallthrough*/
        case SXP_ATTR_TYPE_DEL_IPV6:
            /* nothing to do here */
            break;
        case SXP_ATTR_TYPE_PEER_SEQUENCE:
            have_peer_sequence = true;
            size_t sxp_id_count = 0;
            const uint32_t *sxp_id_arr = NULL;
            rc = sxp_parse_peer_sequence(attr, &sxp_id_count, &sxp_id_arr, code,
                                         subcode);
            if (sxp_isnotok(rc, *code, *subcode)) {
                *err_attr = attr;
                goto out;
            }
            rc = sxp_validate_peer_sequence(peer->nbo_node_id, sxp_id_count,
                                            sxp_id_arr, code, subcode);
            if (sxp_isnotok(rc, *code, *subcode)) {
                if (RC_ISOK(rc)) {
                    PLOG_ERROR_FMT(
                        peer, "Found %s attribute is invalid",
                        sxp_attr_type_string(SXP_ATTR_TYPE_PEER_SEQUENCE));
                }
                *err_attr = attr;
                goto out;
            }

            break;
        case SXP_ATTR_TYPE_SGT:
            have_sgt = true;
            break;
        }
        rc = sxpd_check_attribute_version(peer, type, code, subcode);
        if (sxp_isnotok(rc, *code, *subcode)) {
            *err_attr = attr;
            goto out;
        }
    }
out:
    return rc;
}

/**
 * @brief compare bindings - store -1 as result if b1 is preferred over b2
 * 0 if b1 is equal to b2, 1 if b2 if preferred over b1
 *
 * @param b1 binding 1
 * @param b2 binding 2
 * @param result result of comparison
 *
 * @return 0 on success, -1 on error
 */
static int sxpd_binding_cmp(const struct sxpd_binding *b1,
                            const struct sxpd_binding *b2, int *result)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, b1, b2, result);
    RC_CHECK(rc, out);
    /* compare paths - shorter path has preference - if there is no peer
     * sequence, it's treated as if the peer sequence has length 1 */
    if (b1->peer_sequence && b2->peer_sequence &&
        b1->peer_sequence->node_ids_count < b2->peer_sequence->node_ids_count) {
        *result = -1;
    } else if (b1->peer_sequence && b2->peer_sequence &&
               b1->peer_sequence->node_ids_count >
                   b2->peer_sequence->node_ids_count) {
        *result = 1;
    } else if (!b1->peer_sequence && b2->peer_sequence &&
               b2->peer_sequence->node_ids_count > 1) {
        *result = -1;
    } else if (b1->peer_sequence && !b2->peer_sequence &&
               b1->peer_sequence->node_ids_count > 1) {
        *result = 1;
    } else {
        /* if the paths are of equal length, then more recent timestamp is
         * preferred */
        rc = timestamp_cmp(b2->timestamp, b1->timestamp, result);
    }
out:
    return rc;
}

/**
 * @brief add binding to binding list according to preference (shorter peer
 *sequence or more recent timestamp if equal length)
 *
 * @param bl binding list
 * @param b binding to add
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_binding_list_add_binding(struct sxpd_binding_list *bl,
                                         struct sxpd_binding *b)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, bl, b);
    RC_CHECK(rc, out);
    size_t i = 0;
    bool found_existing_idx = false; /* flag - if binding is in list already */
    size_t existing_idx = 0;         /* where the binding is currently */
    bool found_new_idx = false;      /* flag if found suitable position */
    size_t new_idx = 0;              /* where the binding should be */
    for (i = 0; i < bl->count; ++i) {
        struct sxpd_binding *tmp = bl->bindings[i];
        if (tmp == b) {
            found_existing_idx = true;
            existing_idx = i;
            continue;
        }
        int result = 0;
        RC_CHECK(rc = sxpd_binding_cmp(b, tmp, &result), out);
        if (result < 0) {
            found_new_idx = true;
            new_idx = i;
            break;
        }
    }
    if (!found_new_idx) {
        if (found_existing_idx) {
            new_idx = existing_idx;
        } else {
            new_idx = bl->count; /* put at end of list */
        }
    } else if (found_existing_idx && existing_idx == new_idx - 1) {
        new_idx = existing_idx;
    }
    if (!found_existing_idx) {
        LOG_DEBUG("Add binding %p to binding list %p at pos %zu", (void *)b,
                  (void *)bl, new_idx);
    } else {
        LOG_DEBUG("Move binding %p in binding list %p from pos %zu to %zu",
                  (void *)b, (void *)bl, existing_idx, new_idx);
    }
    if (!bl->count || new_idx > bl->count - 1 || !found_existing_idx) {
        /* need more space for extra element */
        struct sxpd_binding **tmp = NULL;
        if (bl->bindings) {
            tmp = mem_realloc(bl->bindings,
                              (bl->count + 1) * sizeof(bl->bindings[0]));
        } else {
            tmp = mem_calloc(1, sizeof(bl->bindings[0]));
        }
        if (!tmp) {
            LOG_ERROR("Cannot (re)allocate binding list elements");
            rc = -1;
            goto out;
        }
        bl->bindings = tmp;
        ++bl->count;
    }
    if (!found_existing_idx) {
        if (new_idx < bl->count - 1) {
            memmove(bl->bindings + new_idx + 1, bl->bindings + new_idx,
                    (bl->count - 1 - new_idx) * sizeof(bl->bindings[0]));
        }
    } else if (bl->count > 1) {
        if (new_idx < existing_idx) {
            memmove(bl->bindings + new_idx + 1, bl->bindings + new_idx,
                    (existing_idx - new_idx) * sizeof(bl->bindings[0]));
        } else if (new_idx > existing_idx) {
            memmove(bl->bindings + existing_idx,
                    bl->bindings + existing_idx + 1,
                    (new_idx - existing_idx) * sizeof(bl->bindings[0]));
        }
    }
    bl->bindings[new_idx] = b;
out:
    return rc;
}

/**
 * @brief update expanded entries from given binding list after binding list
 *update
 *
 * @param ctx sxpd context to operate on
 * @param prefix network prefix corresponding to binding list
 * @param bl binding list
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_update_expanded_entries(struct sxpd_ctx *ctx,
                                        const struct v4_v6_prefix *prefix,
                                        struct sxpd_binding_list *bl)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, ctx, prefix, bl);
    RC_CHECK(rc, out);
    const uint32_t count =
        prefix->len == 32 ? 1 : (1 << (32 - (uint32_t)prefix->len)) - 1;
    const uint32_t netmask =
        htonl((~(uint32_t)0) << (32 - (uint32_t)prefix->len));
    LOG_TRACE("Updating expansion tracks matching " DEBUG_V4_FMT "/%" PRIu8
              " with binding list %p (%zu elements)",
              DEBUG_V4_PRINT(prefix->ip.v4), prefix->len, (void *)bl,
              bl->count);
    uint32_t i = 0;
    for (i = 0; i < count; ++i) {
        if (32 != prefix->len && !i) {
            /* skip .0 address if this is not host entry*/
            continue;
        }
        struct v4_v6_prefix tmp = {
            .len = 32, .ip = {.v4 = ((prefix->ip.v4) & netmask) | htonl(i) }
        };
        struct radix_node *node = NULL;
        rc = radix_search(ctx->expand_entries_v4, tmp.ip.data, 32, &node);
        RC_CHECK(rc, out);
        if (!node) {
            LOG_ERROR("Internal error, entry " DEBUG_V4_FMT
                      "/32 does not exist in expanded entries",
                      DEBUG_V4_PRINT(tmp.ip.v4));
            rc = -1;
            goto out;
        }
        void *value = NULL;
        rc = radix_parse_node(node, NULL, 0, NULL, &value);
        RC_CHECK(rc, out);
        struct sxpd_expansion_track_entry *e = value;
        if (bl->count) { /* binding list is being added */
            if (!e->bl) {
                LOG_TRACE("Update expansion track %p " DEBUG_V4_FMT
                          "/32 to new binding list %p (prefix length %" PRIu8
                          ", old binding list %p)",
                          (void *)e, DEBUG_V4_PRINT(tmp.ip.v4), (void *)bl,
                          prefix->len, (void *)e->bl);
                e->bl = bl;
                e->prefix_len = prefix->len;
                RC_CHECK(rc = sxpd_mask_clear(&e->mask), out);
            } else if (e->prefix_len < prefix->len) {
                LOG_TRACE("Update expansion track %p " DEBUG_V4_FMT
                          "/32 to new binding list %p (prefix length %" PRIu8
                          ", old binding list %p, old prefix length %" PRIu8
                          ")",
                          (void *)e, DEBUG_V4_PRINT(tmp.ip.v4), (void *)bl,
                          prefix->len, (void *)e->bl, e->prefix_len);
                e->bl = bl;
                e->prefix_len = prefix->len;
                RC_CHECK(rc = sxpd_mask_clear(&e->mask), out);
            }
        } else if (e->bl == bl) { /* binding list is being removed and this
                                     entry has the binding list assigned */
            /* search for network which might have this expanded entry */
            struct radix_node *best_node = NULL;
            rc = radix_search_best(ctx->expand_bindings_v4, tmp.ip.data,
                                   prefix->len, &best_node);
            RC_CHECK(rc, out);
            if (best_node) {
                struct v4_v6_prefix cand = { 0, { { 0 } } };
                rc = radix_parse_node(best_node, cand.ip.data,
                                      sizeof(cand.ip.data), &cand.len, &value);
                RC_CHECK(rc, out);
                LOG_TRACE("Update expansion track %p " DEBUG_V4_FMT
                          "/32 to new binding list %p (prefix length %" PRIu8
                          ", old binding list %p, old prefix length %" PRIu8
                          ")",
                          (void *)e, DEBUG_V4_PRINT(tmp.ip.v4), value, cand.len,
                          (void *)e->bl, e->prefix_len);
                e->bl = value;
                e->prefix_len = cand.len;
                RC_CHECK(rc = sxpd_mask_clear(&e->mask), out);
            } else {
                LOG_TRACE(
                    "Clear binding list from expansion track %p " DEBUG_V4_FMT
                    "/32",
                    (void *)e, DEBUG_V4_PRINT(tmp.ip.v4));
                e->bl = NULL;
                e->prefix_len = 0;
                if (!ctx->connected_listener_count) {
                    /* no listeners connected, can safely discard the entry */
                    rc = radix_delete_node(ctx->expand_entries_v4, node);
                    RC_CHECK(rc, out);
                    sxpd_destroy_expansion_track_entry(e);
                } else {
                    RC_CHECK(rc = sxpd_mask_clear(&e->mask), out);
                }
            }
        } else {
            /* nothing to do here, binding list is being removed, but the entry
             * does not have it assigned, so it's not affected by the removal */
        }
    }
out:
    return rc;
}

/**
 * @brief create and store expansion track entries corresponding to network
 *prefix
 *
 * @param ctx sxpd context to operate on
 * @param prefix network prefix
 * @param bl binding list corresponding to network prefix
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_insert_expanded_entries(struct sxpd_ctx *ctx,
                                        const struct v4_v6_prefix *prefix,
                                        struct sxpd_binding_list *bl)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, ctx, prefix, bl);
    RC_CHECK(rc, out);
    rc = radix_store(ctx->expand_bindings_v4, prefix->ip.data, prefix->len, bl,
                     NULL);
    RC_CHECK(rc, out);
    const uint32_t count =
        prefix->len == 32 ? 1 : (1 << (32 - (uint32_t)prefix->len)) - 1;
    const uint32_t netmask =
        htonl((~(uint32_t)0) << (32 - (uint32_t)prefix->len));
    uint32_t i = 0;
    for (i = 0; i < count; ++i) {
        if (32 != prefix->len && !i) {
            /* skip .0 address if this is not host entry*/
            continue;
        }
        struct v4_v6_prefix tmp = {.ip = {.v4 = ((prefix->ip.v4) & netmask) |
                                                htonl(i) } };
        struct radix_node *node = NULL;
        rc = radix_search(ctx->expand_entries_v4, tmp.ip.data, 32, &node);
        RC_CHECK(rc, out);
        if (!node) {
            struct sxpd_expansion_track_entry *e = mem_calloc(1, sizeof(*e));
            rc = radix_store(ctx->expand_entries_v4, tmp.ip.data, 32, e,
                             &e->node);
            if (RC_ISNOTOK(rc)) {
                mem_free(e);
                goto out;
            }
            e->prefix_len = prefix->len;
            e->bl = bl;
            LOG_TRACE("Store expansion track entry %p " DEBUG_V4_FMT
                      "/32, binding list %p, prefix length %" PRIu8,
                      (void *)e, DEBUG_V4_PRINT(tmp.ip.v4), (void *)bl,
                      prefix->len);
            ++ctx->expanded_entry_count;
        } else {
            void *value = NULL;
            rc = radix_parse_node(node, NULL, 0, NULL, &value);
            RC_CHECK(rc, out);
            struct sxpd_expansion_track_entry *e = value;
            if (e->prefix_len < prefix->len) {
                LOG_TRACE("Update expansion track entry %p " DEBUG_V4_FMT
                          "/32 to new binding list %p (prefix length %" PRIu8
                          ", old binding list %p, old prefix length %" PRIu8
                          ")",
                          (void *)e, DEBUG_V4_PRINT(tmp.ip.v4), (void *)bl,
                          prefix->len, (void *)e->bl, e->prefix_len);
                e->bl = bl;
                e->prefix_len = prefix->len;
                RC_CHECK(rc = sxpd_mask_clear(&e->mask), out);
            }
        }
    }
out:
    return rc;
}

/**
 * @brief expand v4 network prefix/binding
 *
 * @param ctx sxpd context to operate on
 * @param prefix prefix to expand
 * @param bl binding list corresponding to prefix
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_expand_binding(struct sxpd_ctx *ctx,
                               const struct v4_v6_prefix *prefix,
                               struct sxpd_binding_list *bl)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, ctx, prefix, bl);
    RC_CHECK(rc, out);
    if (prefix->len > 32) {
        LOG_ERROR("Expanding binding of length %" PRIu8
                  " is not supported (too long)",
                  prefix->len);
        rc = -1;
        goto out;
    }
    const size_t required = (size_t)1 << (32 - prefix->len);
    const size_t available_entries =
        ctx->sub_expand_limit - ctx->expanded_entry_count;
    struct radix_node *node = NULL;
    rc = radix_search_best(ctx->expand_bindings_v4, prefix->ip.data,
                           prefix->len, &node);
    RC_CHECK(rc, out);
    if (node) {
        void *value = NULL;
        struct v4_v6_prefix tmp = { 0, { { 0 } } };
        rc = radix_parse_node(node, tmp.ip.data, sizeof(tmp.ip.data), &tmp.len,
                              &value);
        RC_CHECK(rc, out);
        if (prefix->len == tmp.len) {
            if (!bl->count) {
                /* first remove the binding list from expand bindings so that it
                 * doesn't get hit while updating expanded entries */
                rc = radix_delete_node(ctx->expand_bindings_v4, node);
                RC_CHECK(rc, out);
            }
            /* exact match - update existing entries */
            bl->expanding = true;
            rc = sxpd_update_expanded_entries(ctx, prefix, bl);
        } else if (bl->count) {
            /* non-exact match - insert binding list and update entries */
            bl->expanding = true;
            rc = sxpd_insert_expanded_entries(ctx, prefix, bl);
        }
    } else if (bl->count && required <= available_entries) {
        bl->expanding = true;
        rc = sxpd_insert_expanded_entries(ctx, prefix, bl);
    } else if (ctx->sub_expand_limit) {
        LOG_DEBUG("Expanding " DEBUG_V4_FMT "/%" PRIu8
                  " would require %zu entries, but only %zu expansion entries "
                  "available - not expanding",
                  DEBUG_V4_PRINT(prefix->ip.v4), prefix->len, required,
                  available_entries);
        LOG_ALERT("Warning: could not expand all bindings, current limit for "
                  "expansion is %zu expanded host entries",
                  ctx->sub_expand_limit);
    }
out:
    return rc;
}

/**
 * @brief contribute binding to master bindings database
 *
 * @param ctx sxpd context to operate on
 * @param type ipv4 of ipv6
 * @param b binding
 * @param prefix network prefix corresponding to binding
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_contribute_binding(struct sxpd_ctx *ctx, enum ip_type type,
                                   struct sxpd_binding *b,
                                   const struct v4_v6_prefix *prefix)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, ctx, b);
    RC_CHECK(rc, out);
    struct sxpd_binding_list *bl = NULL;
    struct radix_node *master_node = NULL;
    struct radix_tree *master_bindings =
        V6 == type ? ctx->master_bindings_v6 : ctx->master_bindings_v4;
    rc = radix_search(master_bindings, prefix->ip.data, prefix->len,
                      &master_node);
    RC_CHECK(rc, out);
    if (master_node) {
        void *tmp = NULL;
        RC_CHECK(rc = radix_parse_node(master_node, NULL, 0, NULL, &tmp), out);
        bl = tmp;
        LOG_DEBUG("Fetched binding list %p (%zu elements)", (void *)bl,
                  bl->count);
    } else {
        bl = mem_calloc(1, sizeof(*bl));
        if (!bl) {
            LOG_ERROR("Cannot allocate binding list");
            rc = -1;
            goto out;
        }
        rc = radix_store(master_bindings, prefix->ip.data, prefix->len, bl,
                         &master_node);
        if (RC_ISNOTOK(rc)) {
            mem_free(bl);
            goto out;
        }
        LOG_DEBUG("Create binding list %p", (void *)bl);
        bl->radix_node = master_node;
    }
    const struct sxpd_binding *selected = NULL;
    if (bl && bl->bindings) {
        selected = bl->bindings[0];
    }
    RC_CHECK(rc = sxpd_binding_list_add_binding(bl, b), out);
    b->binding_list = bl;
    if (selected != bl->bindings[0] || b == bl->bindings[0]) {
        RC_CHECK(rc = sxpd_mask_clear(&bl->mask), out);
        if (V4 == type) {
            rc = sxpd_expand_binding(ctx, prefix, bl);
        }
    }
out:
    return rc;
}

/**
 * @brief move binding from binding list
 *
 * @param bl binding list to remove binding from
 * @param b binding to be removed
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_binding_list_del_binding(struct sxpd_binding_list *bl,
                                         struct sxpd_binding *b)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, bl, b);
    RC_CHECK(rc, out);
    size_t i = 0;
    bool found = false;
    size_t found_pos = 0;
    for (i = 0; i < bl->count; ++i) {
        struct sxpd_binding *tmp = bl->bindings[i];
        if (tmp == b) {
            found = true;
            found_pos = i;
            break;
        }
    }
    if (found) {
        LOG_DEBUG("Delete binding %p at pos %zu from binding list %p",
                  (void *)b, found_pos, (void *)bl);
        if (found_pos < bl->count - 1) {
            memmove(bl->bindings + found_pos, bl->bindings + found_pos + 1,
                    (bl->count - found_pos - 1) * sizeof(bl->bindings[0]));
        }
        --bl->count;
        if (!bl->count) {
            LOG_DEBUG("Binding list %p is now empty", (void *)bl);
            mem_free(bl->bindings);
            bl->bindings = NULL;
            while (bl->iterator) {
                rc = sxpd_iterate_bindings_internal(bl->iterator);
            }
        }
    } else {
        LOG_DEBUG("Binding %p not found in binding list %p during delete",
                  (void *)b, (void *)bl);
    }
out:
    return rc;
}

/**
 * @brief uncontribute binding from master bindings database
 *
 * @param ctx sxpd context to operate on
 * @param type ipv4 or ipv6
 * @param b binding to uncontribute
 * @param prefix network prefix corresponding to binding
 * @param[out] binding_was_selected flag set to true, if binding was selected
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_uncontribute_binding(struct sxpd_ctx *ctx, enum ip_type type,
                                     struct sxpd_binding *b,
                                     const struct v4_v6_prefix *prefix,
                                     bool *binding_was_selected)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, ctx, b, binding_was_selected);
    RC_CHECK(rc, out);
    struct sxpd_binding_list *bl = NULL;
    struct radix_node *master_node = NULL;
    struct radix_tree *master = NULL;
    if (V6 == type) {
        master = ctx->master_bindings_v6;
    } else {
        master = ctx->master_bindings_v4;
    }
    rc = radix_search(master, prefix->ip.data, prefix->len, &master_node);
    RC_CHECK(rc, out);
    if (master_node) {
        void *tmp = NULL;
        RC_CHECK(rc = radix_parse_node(master_node, NULL, 0, NULL, &tmp), out);
        bl = tmp;
        LOG_DEBUG("Fetched binding list %p (%zu elements)", (void *)bl,
                  bl->count);
        *binding_was_selected = (bl->count && b == bl->bindings[0]);
        RC_CHECK(rc = sxpd_binding_list_del_binding(bl, b), out);
        /* if empty and no connected listeners, free the binding list */
        if (!bl->count && !ctx->connected_listener_count) {
            rc = radix_delete_node(master, b->binding_list->radix_node);
            RC_CHECK(rc, out);
            if (bl->expanding) {
                rc = sxpd_expand_binding(ctx, prefix, bl);
                RC_CHECK(rc, out);
            }
            sxpd_destroy_binding_list(bl);
            b->binding_list = NULL;
        } else if (*binding_was_selected) {
            rc = sxpd_mask_clear(&bl->mask);
            RC_CHECK(rc, out);
            if (V4 == type) {
                rc = sxpd_expand_binding(ctx, prefix, bl);
            }
        }
    } else {
        LOG_DEBUG("No corresponding binding list");
    }
out:
    return rc;
}

/**
 * @brief add binding to peer's local bindings database
 *
 * @param peer peer which sent the binding
 * @param type ipv4 or ipv6
 * @param prefix network prefix
 * @param peer_sequence peer sequence
 * @param tag tag associated with the prefix
 * @param[out] binding allocated binding in local bindings database
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_peer_add_prefix(struct sxpd_peer *peer, enum ip_type type,
                                struct v4_v6_prefix *prefix,
                                struct sxpd_peer_sequence *peer_sequence,
                                uint16_t tag, struct sxpd_binding **binding)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, peer, prefix, peer_sequence);
    RC_CHECK(rc, out);
    if (V6 == type) {
        PLOG_DEBUG_FMT(peer, "Got v6 binding " DEBUG_V6_FMT "/%" PRIu8
                             " = %" PRIu16 " with %zu element peer sequence",
                       DEBUG_V6_PRINT(prefix->ip.data), prefix->len, tag,
                       peer_sequence ? peer_sequence->node_ids_count : 0);
    } else {
        PLOG_DEBUG_FMT(peer, "Got v4 binding " DEBUG_V4_FMT "/%" PRIu8
                             " = %" PRIu16 " with %zu element peer sequence",
                       DEBUG_V4_PRINT(prefix->ip.v4), prefix->len, tag,
                       peer_sequence ? peer_sequence->node_ids_count : 0);
    }

    struct timestamp *stamp = get_timestamp();
    if (!stamp) {
        LOG_ERROR("Cannot get timestamp!");
        rc = -1;
        goto out;
    }
    struct radix_node *node = NULL;
    struct sxpd_binding *b = NULL;
    if (V6 == type) {
        rc = radix_search(peer->bindings_v6, prefix->ip.data, prefix->len,
                          &node);
    } else {
        rc = radix_search(peer->bindings_v4, prefix->ip.data, prefix->len,
                          &node);
    }
    RC_CHECK(rc, out);
    if (node) {
        void *value = NULL;
        RC_CHECK(rc = radix_parse_node(node, NULL, 0, NULL, &value), out);
        b = value;
        destroy_timestamp(b->timestamp);
        b->timestamp = stamp;
        sxpd_destroy_peer_sequence(b->peer_sequence);
        b->peer_sequence = peer_sequence;
        ++peer_sequence->refcount;
        b->tag = tag;
        b->same_peer_seq_next = NULL;
        LOG_DEBUG("Fetched binding %p", (void *)b);
    } else {
        b = mem_calloc(1, sizeof(*b));
        if (!b) {
            LOG_ERROR("Cannot allocate binding");
            rc = -1;
            goto out;
        }
        b->timestamp = stamp;
        b->peer_sequence = peer_sequence;
        ++peer_sequence->refcount;
        b->tag = tag;
        if (V6 == type) {
            rc = radix_store(peer->bindings_v6, prefix->ip.data, prefix->len, b,
                             &node);
        } else {
            rc = radix_store(peer->bindings_v4, prefix->ip.data, prefix->len, b,
                             &node);
        }
        if (RC_ISNOTOK(rc)) {
            sxpd_destroy_binding(b);
            goto out;
        }
        LOG_DEBUG("Create binding %p", (void *)b);
    }
    if (V6 == type) {
        LOG_DEBUG("Stored new binding %p " DEBUG_V6_FMT "/%" PRIu8
                  " = %" PRIu16,
                  (void *)b, DEBUG_V6_PRINT(prefix->ip.data), prefix->len, tag);
    } else {
        LOG_DEBUG("Stored new binding %p " DEBUG_V4_FMT "/%" PRIu8
                  " = %" PRIu16,
                  (void *)b, DEBUG_V4_PRINT(prefix->ip.v4), prefix->len, tag);
    }
    if (binding) {
        *binding = b;
    }
    rc = sxpd_contribute_binding(peer->sxpd_ctx, type, b, prefix);
out:
    return rc;
}

/**
 * @brief withdraw binding from peer's local database
 *
 * @param peer peer to withdraw binding from
 * @param type ipv4 or ipv6
 * @param prefix network prefix to withdraw
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_peer_del_prefix(struct sxpd_peer *peer, enum ip_type type,
                                struct v4_v6_prefix *prefix)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, peer, prefix);
    RC_CHECK(rc, out);
    bool binding_was_selected = false;
    if (V6 == type) {
        PLOG_DEBUG_FMT(peer,
                       "Got delete for v6 binding " DEBUG_V6_FMT "/%" PRIu8,
                       DEBUG_V6_PRINT(prefix->ip.v6), prefix->len);
    } else {
        PLOG_DEBUG_FMT(peer,
                       "Got delete for v4 binding " DEBUG_V4_FMT "/%" PRIu8,
                       DEBUG_V4_PRINT(prefix->ip.v4), prefix->len);
    }
    struct radix_node *node = NULL;
    struct radix_tree *tree = NULL;
    struct sxpd_binding *b = NULL;
    if (V6 == type) {
        tree = peer->bindings_v6;
    } else {
        tree = peer->bindings_v4;
    }
    RC_CHECK(rc = radix_search(tree, prefix->ip.data, prefix->len, &node), out);
    if (node) {
        void *value = NULL;
        RC_CHECK(rc = radix_parse_node(node, NULL, 0, NULL, &value), out);
        b = value;
        LOG_DEBUG("Fetched binding %p", (void *)b);
    } else {
        LOG_DEBUG("No such binding");
        goto out;
    }
    if (V6 == type) {
        LOG_DEBUG("Deleting binding %p " DEBUG_V6_FMT "/%" PRIu8 " = %" PRIu16,
                  (void *)b, DEBUG_V6_PRINT(prefix->ip.v6), prefix->len,
                  b->tag);
    } else {
        LOG_DEBUG("Deleting binding %p " DEBUG_V4_FMT "/%" PRIu8 " = %" PRIu16,
                  (void *)b, DEBUG_V4_PRINT(prefix->ip.v4), prefix->len,
                  b->tag);
    }
    rc = sxpd_uncontribute_binding(peer->sxpd_ctx, type, b, prefix,
                                   &binding_was_selected);
    RC_CHECK(rc, out);
    rc = radix_delete_node(tree, node);
    RC_CHECK(rc, out);
    sxpd_destroy_binding(b);
out:
    return rc;
}

/**
 * @brief parse prefix-list attribute from peer and add bindings to peer's db
 *
 * @param peer peer which sent the update message
 * @param type ipv4 or ipv6
 * @param attr prefix-list attribute
 * @param[out] code error code found during processing
 * @param[out] subcode error sub-code found during processing
 * @param peer_sequence peer sequence associated with the prefix-list
 * @param sgt source group tag associated with the prefix-list
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_process_add_prefix(struct sxpd_peer *peer, enum ip_type type,
                                   struct sxp_attribute *attr,
                                   enum sxp_error_code *code,
                                   enum sxp_error_sub_code *subcode,
                                   struct sxpd_peer_sequence *peer_sequence,
                                   uint16_t sgt)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, peer, attr, code, subcode, peer_sequence);
    RC_CHECK(rc, out);
    struct sxp_prefix *prefix = NULL;
    struct sxpd_binding *previous = NULL;
    do {
        rc = sxp_parse_prefix_list(attr, prefix, &prefix, code, subcode);
        if (sxp_isnotok(rc, *code, *subcode) || !prefix) {
            break;
        }
        struct sxpd_binding *b = NULL;

        struct v4_v6_prefix tmp;
        memset(&tmp, 0, sizeof(tmp));
        rc = sxp_parse_prefix(prefix, tmp.ip.data, sizeof(tmp.ip.data),
                              &tmp.len);
        RC_CHECK(rc, out);
        rc = sxpd_peer_add_prefix(peer, type, &tmp, peer_sequence, sgt, &b);
        if (previous && b == previous) {
            previous->same_peer_seq_next = b;
        }
        previous = b;
    } while (RC_ISOK(rc));
out:
    return rc;
}

/**
 * @brief parse prefix-list attribute from peer and withdraw bindings from
 *peer's db
 *
 * @param peer peer which sent the update message
 * @param type ipv4 or ipv6
 * @param attr prefix-list attribute
 * @param[out] code error code found during processing
 * @param[out] subcode error sub-code found during processing
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_process_del_prefix(struct sxpd_peer *peer, enum ip_type type,
                                   struct sxp_attribute *attr,
                                   enum sxp_error_code *code,
                                   enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, peer, attr, code, subcode);
    RC_CHECK(rc, out);
    struct sxp_prefix *prefix = NULL;
    do {
        rc = sxp_parse_prefix_list(attr, prefix, &prefix, code, subcode);
        if (sxp_isnotok(rc, *code, *subcode) || !prefix) {
            break;
        }
        struct v4_v6_prefix tmp;
        memset(&tmp, 0, sizeof(tmp));
        rc = sxp_parse_prefix(prefix, tmp.ip.data, sizeof(tmp.ip.data),
                              &tmp.len);
        RC_CHECK(rc, out);
        rc = sxpd_peer_del_prefix(peer, type, &tmp);
    } while (RC_ISOK(rc));
out:
    return rc;
}

/**
 * @brief parse peer sequence attribute
 *
 * @param attr peer-sequence attribute
 * @param sxpd_node_id node-id which identifies the sxpd instance
 * @param[out] peer_sequence parsed peer sequence
 * @param[out] loop_detected flag set to true if loop is detected
 * @param[out] code error code found during processing
 * @param[out] subcode error sub-code found during processing
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_parse_peer_sequence(struct sxp_attribute *attr,
                                    uint32_t sxpd_node_id,
                                    struct sxpd_peer_sequence **peer_sequence,
                                    bool *loop_detected,
                                    enum sxp_error_code *code,
                                    enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    struct sxpd_peer_sequence *tmp = NULL;
    PARAM_NULL_CHECK(rc, attr, peer_sequence, loop_detected, code, subcode);
    RC_CHECK(rc, out);
    tmp = sxpd_alloc_peer_sequence();
    if (!tmp) {
        LOG_ERROR("Cannot allocate peer sequence");
        rc = -1;
        goto out;
    }

    const uint32_t *node_ids_arr = NULL;
    rc = sxp_parse_peer_sequence(attr, &tmp->node_ids_count, &node_ids_arr,
                                 code, subcode);
    if (sxp_isnotok(rc, *code, *subcode)) {
        goto out;
    }
    if (!tmp->node_ids_count) {
        LOG_ERROR("Unexpected zero-length peer sequence");
        rc = -1;
        goto out;
    }
    const size_t byte_count = tmp->node_ids_count * sizeof(tmp->node_ids[0]);
    tmp->node_ids = mem_malloc(byte_count);
    if (!tmp->node_ids) {
        LOG_ERROR("Cannot allocate %zu bytes node-id array for peer sequence "
                  "of length %zu",
                  byte_count, tmp->node_ids_count);
        rc = -1;
        goto out;
    }
    *loop_detected = false;
    size_t i = 0;
    for (i = 0; i < tmp->node_ids_count; ++i) {
        tmp->node_ids[i] = node_ids_arr[i];
        if (node_ids_arr[i] == sxpd_node_id) {
            *loop_detected = true;
        }
    }
    *peer_sequence = tmp;
    tmp = NULL;
out:
    sxpd_destroy_peer_sequence(tmp);
    return rc;
}

/**
 * @brief process add-ipv4 attribute and add prefix advertised by peer
 *
 * @param peer peer which sent the update message
 * @param attr add-ipv4 attribute
 * @param[out] code error code found during processing
 * @param[out] subcode error sub-code found during processing
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_process_add_ipv4(struct sxpd_peer *peer,
                                 struct sxp_attribute *attr,
                                 enum sxp_error_code *code,
                                 enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, peer, attr, code, subcode);
    RC_CHECK(rc, out);
    struct v4_v6_prefix prefix;
    memset(&prefix, 0, sizeof(prefix));
    uint16_t sgt = 0;
    bool have_prefix_length = false;
    rc = sxp_parse_add_ipv4(attr, prefix.ip.data, sizeof(prefix.ip.data), &sgt,
                            &have_prefix_length, &prefix.len, code, subcode);
    if (sxp_isnotok(rc, *code, *subcode)) {
        goto out;
    }
    if (!have_prefix_length) {
        prefix.len = 32;
    }
    rc = sxpd_peer_add_prefix(peer, V4, &prefix,
                              peer->sxpd_ctx->v1_peer_sequence, sgt, NULL);

out:
    return rc;
}

/**
 * @brief process add-ipv6 attribute and add prefix advertised by peer
 *
 * @param peer peer which sent the update message
 * @param attr add-ipv6 attribute
 * @param[out] code error code found during processing
 * @param[out] subcode error sub-code found during processing
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_process_add_ipv6(struct sxpd_peer *peer,
                                 struct sxp_attribute *attr,
                                 enum sxp_error_code *code,
                                 enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, peer, attr, code, subcode);
    RC_CHECK(rc, out);
    struct v4_v6_prefix prefix;
    memset(&prefix, 0, sizeof(prefix));
    uint16_t sgt = 0;
    bool have_prefix_length = false;
    rc = sxp_parse_add_ipv6(attr, prefix.ip.data, sizeof(prefix.ip.data), &sgt,
                            &have_prefix_length, &prefix.len, code, subcode);
    if (sxp_isnotok(rc, *code, *subcode)) {
        goto out;
    }
    if (!have_prefix_length) {
        prefix.len = 128;
    }
    rc = sxpd_peer_add_prefix(peer, V6, &prefix,
                              peer->sxpd_ctx->v1_peer_sequence, sgt, NULL);

out:
    return rc;
}

/**
 * @brief process del-ipv4 attribute and delete withdrawn prefix
 *
 * @param peer peer which sent the update message
 * @param attr del-ipv4 attribute
 * @param[out] code error code found during processing
 * @param[out] subcode error sub-code found during processing
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_process_del_ipv4(struct sxpd_peer *peer,
                                 struct sxp_attribute *attr,
                                 enum sxp_error_code *code,
                                 enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, peer, attr, code, subcode);
    RC_CHECK(rc, out);
    struct v4_v6_prefix prefix;
    memset(&prefix, 0, sizeof(prefix));
    bool have_prefix_length = false;
    rc = sxp_parse_del_ipv4(attr, prefix.ip.data, sizeof(prefix.ip.data),
                            &have_prefix_length, &prefix.len, code, subcode);
    if (sxp_isnotok(rc, *code, *subcode)) {
        goto out;
    }
    if (!have_prefix_length) {
        prefix.len = 32;
    }
    rc = sxpd_peer_del_prefix(peer, V4, &prefix);
out:
    return rc;
}

/**
 * @brief process del-ipv6 attribute and delete withdrawn prefix
 *
 * @param peer peer which sent the update message
 * @param attr del-ipv6 attribute
 * @param[out] code error code found during processing
 * @param[out] subcode error sub-code found during processing
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_process_del_ipv6(struct sxpd_peer *peer,
                                 struct sxp_attribute *attr,
                                 enum sxp_error_code *code,
                                 enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, peer, attr, code, subcode);
    RC_CHECK(rc, out);
    struct v4_v6_prefix prefix;
    memset(&prefix, 0, sizeof(prefix));
    bool have_prefix_length = false;
    rc = sxp_parse_del_ipv6(attr, prefix.ip.data, sizeof(prefix.ip.data),
                            &have_prefix_length, &prefix.len, code, subcode);
    if (sxp_isnotok(rc, *code, *subcode)) {
        goto out;
    }
    if (!have_prefix_length) {
        prefix.len = 128;
    }
    rc = sxpd_peer_del_prefix(peer, V6, &prefix);
out:
    return rc;
}

/**
 * @brief find if attribute should be skipped if loop is detected in peer
 *sequence
 *
 * @param type attribute type to set
 *
 * @return true if should be skipped, false otherwise
 */
static bool sxpd_skip_on_loop(enum sxp_attr_type type)
{
    switch (type) {
    case SXP_ATTR_TYPE_ADD_IPV4:
    /*fallthrough*/
    case SXP_ATTR_TYPE_ADD_IPV6:
    /*fallthrough*/
    case SXP_ATTR_TYPE_DEL_IPV4:
    /*fallthrough*/
    case SXP_ATTR_TYPE_DEL_IPV6:
    /*fallthrough*/
    case SXP_ATTR_TYPE_IPV4_ADD_PREFIX:
    /*fallthrough*/
    case SXP_ATTR_TYPE_IPV6_ADD_PREFIX:
    /*fallthrough*/
    case SXP_ATTR_TYPE_IPV4_DEL_PREFIX:
    /*fallthrough*/
    case SXP_ATTR_TYPE_IPV6_DEL_PREFIX:
        return true;
    case SXP_ATTR_TYPE_NODE_ID:
    /*fallthrough*/
    case SXP_ATTR_TYPE_CAPABILITIES:
    /*fallthrough*/
    case SXP_ATTR_TYPE_HOLD_TIME:
    /*fallthrough*/
    case SXP_ATTR_TYPE_PEER_SEQUENCE:
    /*fallthrough*/
    case SXP_ATTR_TYPE_SGT:
        break;
    }
    return false;
}

/**
 * @brief process update message coming from peer
 *
 * @param peer peer who sent the update
 * @param socket socket through which the message came
 * @param msg update message to process
 * @param err_attr pointer to attribute which was found to be invalid
 * @param code error code found during message processing
 * @param subcode error sub-code found during message processing
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_process_update_msg(struct sxpd_peer *peer,
                                   struct evmgr_socket *socket,
                                   struct sxp_msg *msg,
                                   struct sxp_attribute **err_attr,
                                   enum sxp_error_code *code,
                                   enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, peer, socket, msg, err_attr, code, subcode);
    RC_CHECK(rc, out);
    rc = sxpd_validate_update_msg(peer, msg, err_attr, code, subcode);
    if (sxp_isnotok(rc, *code, *subcode)) {
        goto out;
    }
    struct sxp_attribute *attr = NULL;
    uint16_t sgt = 0;
    struct sxpd_peer_sequence *peer_sequence = NULL;
    bool loop_detected = false;
    for (;;) {
        rc = sxp_parse_msg(msg, attr, &attr, code, subcode);
        if (sxp_isnotok(rc, *code, *subcode)) {
            goto out;
        }
        if (!attr) {
            break;
        }
        enum sxp_attr_type type = SXP_ATTR_TYPE_NODE_ID;
        RC_CHECK(rc = sxp_attr_get_type(attr, &type), out);
        if (loop_detected && sxpd_skip_on_loop(type)) {
            PLOG_TRACE_FMT(
                peer,
                "Skipping processing of %s attribute due to detected loop",
                sxp_attr_type_string(type));
            continue;
        }
        switch (type) {
        case SXP_ATTR_TYPE_ADD_IPV4:
            rc = sxpd_process_add_ipv4(peer, attr, code, subcode);
            break;
        case SXP_ATTR_TYPE_ADD_IPV6:
            rc = sxpd_process_add_ipv6(peer, attr, code, subcode);
            break;
        case SXP_ATTR_TYPE_DEL_IPV4:
            rc = sxpd_process_del_ipv4(peer, attr, code, subcode);
            break;
        case SXP_ATTR_TYPE_DEL_IPV6:
            rc = sxpd_process_del_ipv6(peer, attr, code, subcode);
            break;
        case SXP_ATTR_TYPE_PEER_SEQUENCE:
            sxpd_destroy_peer_sequence(peer_sequence);
            loop_detected = false;
            rc = sxpd_parse_peer_sequence(attr, peer->sxpd_ctx->node_id,
                                          &peer_sequence, &loop_detected, code,
                                          subcode);
            if (sxp_isok(rc, *code, *subcode) && loop_detected) {
                PLOG_TRACE_FMT(peer,
                               "Loop detected - sxpd instance node id %" PRIu32
                               " is part of received peer sequence",
                               peer->sxpd_ctx->node_id);
            }
            break;
        case SXP_ATTR_TYPE_SGT:
            rc = sxp_attr_sgt_get_sgt(attr, &sgt);
            break;
        case SXP_ATTR_TYPE_IPV4_ADD_PREFIX:
            rc = sxpd_process_add_prefix(peer, V4, attr, code, subcode,
                                         peer_sequence, sgt);
            break;
        case SXP_ATTR_TYPE_IPV4_DEL_PREFIX:
            rc = sxpd_process_del_prefix(peer, V4, attr, code, subcode);
            break;
        case SXP_ATTR_TYPE_IPV6_ADD_PREFIX:
            rc = sxpd_process_add_prefix(peer, V6, attr, code, subcode,
                                         peer_sequence, sgt);
            break;
        case SXP_ATTR_TYPE_IPV6_DEL_PREFIX:
            rc = sxpd_process_del_prefix(peer, V6, attr, code, subcode);
            break;
        case SXP_ATTR_TYPE_NODE_ID:
        /*fallthrough*/
        case SXP_ATTR_TYPE_CAPABILITIES:
        /*fallthrough*/
        case SXP_ATTR_TYPE_HOLD_TIME:
            PLOG_ERROR_FMT(peer, "Unexpected attribute %s in %s message",
                           sxp_attr_type_string(type),
                           sxp_msg_type_string(msg->type));
            *code = SXP_ERR_CODE_UPDATE;
            *subcode = SXP_SUB_ERR_CODE_UNEXPECTED_ATTRIBUTE;
            goto out;
        }
        if (sxp_isnotok(rc, *code, *subcode)) {
            goto out;
        }
    }
    sxpd_destroy_peer_sequence(peer_sequence);
    RC_CHECK(rc = sxpd_export_bindings(peer->sxpd_ctx), out);
    if (peer->hold_timer) {
        PLOG_TRACE_MSG(peer,
                       "Got update message from speaker, re-arming hold timer");
        rc = evmgr_timer_disarm(peer->hold_timer);
        if (RC_ISOK(rc)) {
            rc = evmgr_timer_arm(peer->hold_timer);
            if (RC_ISNOTOK(rc)) {
                PLOG_ERROR_MSG(peer, "Cannot arm hold timer");
                goto out;
            }
        } else {
            PLOG_ERROR_MSG(peer, "Cannot disarm hold timer");
            goto out;
        }
    }
out:
    return rc;
}

/**
 * @brief process error message from peer (error message is logged only)
 *
 * @param peer peer which sent the message
 * @param msg the error message
 * @param[out] code error code found during processing
 * @param[out] subcode error sub-code found during processing
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_process_error_msg(struct sxpd_peer *peer, struct sxp_msg *msg,
                                  enum sxp_error_code *code,
                                  enum sxp_error_sub_code *subcode)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, peer, msg, code, subcode);
    RC_CHECK(rc, out);
    enum sxp_error_code msg_code = SXP_ERR_CODE_NONE;
    enum sxp_error_sub_code msg_subcode = SXP_SUB_ERR_CODE_NONE;
    enum sxp_error_non_extended_code msg_necode = SXP_NON_EXT_ERR_CODE_NONE;
    int extended = 0;
    rc = sxp_parse_error(msg, &extended, &msg_code, &msg_subcode, &msg_necode);
    RC_CHECK(rc, out);
    if (extended) {
        PLOG_ERROR_FMT(peer, "Got extended error reply from peer with error "
                             "code %d=%s and sub-code %d=%s",
                       msg_code, sxp_error_code_string(msg_code), msg_subcode,
                       sxp_error_subcode_string(msg_subcode));
    } else {
        PLOG_ERROR_FMT(
            peer,
            "Got error reply from peer with non-extended error code %d=%s",
            msg_necode, sxp_error_non_extended_code_string(msg_necode));
    }
out:
    return rc;
}

/**
 * @brief process purge-all message - delete all bindings which peer advertised
 *
 * @param peer peer which sent the purge-all
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_process_purge_all_msg(struct sxpd_peer *peer)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, peer);
    RC_CHECK(rc, out);
    bool need_export_v4 = false;
    bool need_export_v6 = false;
    rc = sxpd_peer_delete_all_bindings(peer, V4, &need_export_v4);
    RC_CHECK(rc, out);
    rc = sxpd_peer_delete_all_bindings(peer, V6, &need_export_v6);
    RC_CHECK(rc, out);
    if (need_export_v4 || need_export_v6) {
        rc = sxpd_export_bindings(peer->sxpd_ctx);
    }
out:
    return rc;
}

static int sxpd_process_keepalive_msg(struct sxpd_peer *peer,
                                      struct evmgr_socket *socket,
                                      struct sxp_msg *msg,
                                      enum sxp_error_code *code,
                                      enum sxp_error_sub_code *subcode)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, peer, socket, msg, code, subcode);
    if (RC_ISOK(rc)) {
        if (socket == peer->speaker) {
            if (peer->hold_timer) {
                PLOG_TRACE_MSG(peer, "Got keep-alive message from speaker, "
                                     "re-arming hold timer");
                rc = evmgr_timer_disarm(peer->hold_timer);
                if (RC_ISOK(rc)) {
                    rc = evmgr_timer_arm(peer->hold_timer);
                    if (RC_ISNOTOK(rc)) {
                        PLOG_ERROR_MSG(peer, "Cannot arm hold timer");
                    }
                } else {
                    PLOG_ERROR_MSG(peer, "Cannot disarm hold timer");
                }
            } else {
                PLOG_ERROR_MSG(peer, "Got keep-alive message from speaker, but "
                                     "there is no hold timer");
                rc = -1;
            }
        } else {
            PLOG_ERROR_MSG(peer,
                           "Got keep-alive message on socket which is not "
                           "speaker connection");
            rc = -1;
        }
    }

    return rc;
}

/**
 * @brief process message from peer - message is first swapped from network
 *to host byte order, then parsed
 *
 * @param[in] peer peer for which the message came
 * @param[in] socket socket on which the message was received
 * @param[in] msg message itself
 * @param[out] err_attr pointer to attribute which caused the parsing error
 * @param[out] code error code found during parsing
 * @param[out] subcode error sub-code found during parsing
 *
 * @return 0 on success, -1 on error
 */
static int sxpd_process_msg(struct sxpd_peer *peer, struct evmgr_socket *socket,
                            struct sxp_msg *msg,
                            struct sxp_attribute **err_attr,
                            enum sxp_error_code *code,
                            enum sxp_error_sub_code *subcode)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, peer, socket, msg, err_attr, code, subcode);
    RC_CHECK(rc, out);
    RC_CHECK(rc = sxp_msg_ntoh_swap(msg, code, subcode), out);
    if (sxp_isok(rc, *code, *subcode)) {
        rc = sxp_hbo_pretty_print_msg(msg, code, subcode);
    }
    if (sxp_isok(rc, *code, *subcode)) {
        switch ((enum sxp_msg_type)msg->type) {
        case SXP_MSG_OPEN:
            rc = sxpd_process_open_msg(peer, socket, msg, code, subcode);
            break;

        case SXP_MSG_OPEN_RESP:
            rc = sxpd_process_open_resp_msg(peer, socket, msg, code, subcode);
            break;

        case SXP_MSG_UPDATE:
            rc = sxpd_process_update_msg(peer, socket, msg, err_attr, code,
                                         subcode);
            break;

        case SXP_MSG_ERROR:
            rc = sxpd_process_error_msg(peer, msg, code, subcode);
            break;

        case SXP_MSG_PURGE_ALL:
            rc = sxpd_process_purge_all_msg(peer);
            break;

        case SXP_MSG_KEEPALIVE:
            rc = sxpd_process_keepalive_msg(peer, socket, msg, code, subcode);
            break;
        }
    }

out:
    return rc;
}

/**
 * @brief process incoming buffered data from peer
 *
 * @param[in] peer peer, whose buffer is being processed
 * @param[in] socket source of data
 * @param[in] buffer buffer containing the data
 * @param[out] err_attr pointer to attribute which is invalid
 * @param[out] code error code found during processing
 * @param[out] subcode error sub-code found during processing
 *
 * @return 0 if success, -1 if error
 */
static int
sxpd_process_buffer(struct sxpd_peer *peer, struct evmgr_socket *socket,
                    struct sxpd_buffer *buffer, struct sxp_attribute **err_attr,
                    enum sxp_error_code *code, enum sxp_error_sub_code *subcode)

{
    int rc = 0;
    bool need_more_data = false;
    uint32_t msg_type = 0;
    uint32_t msg_length = 0;
    PARAM_NULL_CHECK(rc, socket, peer, buffer, err_attr, code, subcode);
    RC_CHECK(rc, out);
    PLOG_TRACE_FMT(peer, "Start processing buffer %p of size %zu",
                   (void *)buffer, buffer->size);
    while (buffer->size >= sizeof(struct sxp_msg)) {
        msg_type = ntohl(buffer->u.msg.type);
        msg_length = ntohl(buffer->u.msg.length);
        if (!sxp_msg_type_known(msg_type)) {
            PLOG_ERROR_FMT(peer, "Got unknown message with type %" PRIu32,
                           msg_type);
            *code = SXP_ERR_CODE_MSG_HEAD;
        } else if (msg_length > SXP_MAX_MSG_LENGTH) {
            PLOG_ERROR_FMT(peer, "Got %s message with invalid length %" PRIu32,
                           sxp_msg_type_string(msg_type), msg_length);
            *code = SXP_ERR_CODE_MSG_HEAD;
        } else {
            PLOG_TRACE_FMT(peer, "%s header indicates %" PRIu32
                                 " bytes length, buffer contains %zu bytes",
                           sxp_msg_type_string(msg_type), msg_length,
                           buffer->size);
            if (buffer->size < msg_length) {
                need_more_data = true;
                break;
            }
        }
        if (sxp_isnotok(rc, *code, *subcode)) {
            break;
        }

        rc = sxpd_process_msg(peer, socket, &buffer->u.msg, err_attr, code,
                              subcode);

        if (sxp_isok(rc, *code, *subcode)) {
            memmove(buffer->u.data, buffer->u.data + msg_length,
                    buffer->size - msg_length);
            buffer->size -= msg_length;
        } else {
            break;
        }
    }
    if (sxp_isok(rc, *code, *subcode) && need_more_data) {
        PLOG_TRACE_FMT(peer, "Stop processing buffer %p - need more data, "
                             "buffer has size %zu",
                       (void *)buffer, buffer->size);
    }
out:
    return rc;
}

/**
 * @brief callback called when peers connection is readable
 *
 * @startuml
 * actor "peer" as apeer
 * participant "event manager" as evmgr
 * participant "sxpd peer" as peer
 * apeer->evmgr: data
 * evmgr->peer: socket is readable
 * peer->peer: allocate buffer (of maximum sxp message size) or re-use existing\
 * buffer (append to end of buffer)
 * peer->evmgr: read up to available buffer space data from socket\
 * (evmgr_socket_read)
 * evmgr-->peer: data to buffer
 * loop while no error and some data read from socket
 *  peer->peer: process buffered data (sxpd_process_buffer)
 *  alt more data required
 *   peer-->peer: success
 *  else sxp error occured during processing
 *   peer->peer: send error message to peer (sxpd_send_error)
 *   peer->evmgr: write error message to socket (evmgr_socket_write)
 *   evmgr->apeer: error message
 *  else runtime error occured during processing
 *   peer->peer: disconnect peer connection (sxpd_disconnect_peer_socket)
 *   peer->evmgr: close socket
 *  end
 * end
 * @enduml
 *
 * @param socket socket which is readable
 * @param ctx context passed to callback register function - struct sxpd_peer *
 */
static void sxpd_peer_read_callback(struct evmgr_socket *socket, void *ctx)
{
    int rc = 0;
    struct sxpd_peer *peer = ctx;
    struct sxpd_buffer *buffer = NULL;
    struct sxpd_buffer **buffer_placement = NULL;
    bool processing_error = false;
    const char *str1 = "";
    const char *str2 = "";
    const char *str3 = "";
    const char *str4 = "";
    const char *buffer_str = NULL;

    PARAM_NULL_CHECK(rc, socket, ctx);
    RC_CHECK(rc, out);
    bool match = false;
    if (peer->speaker == socket) {
        str1 = "[speaker]";
        match = true;
    }

    if (peer->listener == socket) {
        str2 = "[listener]";
        match = true;
    }

    if (peer->incoming == socket) {
        str3 = "[incoming]";
        match = true;
        buffer_placement = &peer->incoming_in_buffer;
        buffer_str = "[incoming]";
    }

    if (peer->outgoing == socket) {
        str4 = "[outgoing]";
        match = true;
        buffer_placement = &peer->outgoing_in_buffer;
        buffer_str = "[outgoing]";
    }

    if (match) {
        PLOG_TRACE_FMT(peer, "%s%s%s%s connection is readable", str1, str2,
                       str3, str4);
    } else {
        PLOG_ERROR_FMT(peer, "Read event on unknown socket %p", (void *)socket);
        evmgr_socket_destroy(socket);
        rc = -1;
        goto out;
    }

    if (buffer_placement) {
        if (!*buffer_placement) {
            *buffer_placement = sxpd_allocate_buffer(peer->sxpd_ctx);
        }

        buffer = *buffer_placement;
    }

    size_t bytes_read = 0;
    do {
        if (buffer) {
            bytes_read =
                evmgr_socket_read(socket, buffer->u.data + buffer->size,
                                  sizeof(buffer->u.data) - buffer->size);
            if (bytes_read) {
                PLOG_TRACE_FMT(peer, "Read %zu bytes from %s%s%s%s connection",
                               bytes_read, str1, str2, str3, str4);
                buffer->size += bytes_read;
            }
        } else {
            PLOG_ERROR_FMT(peer, "Cannot allocate buffer for %s connection",
                           buffer_str);
            processing_error = true;
            break;
        }

        if (!buffer->size) {
            break;
        }

        if (!processing_error) {
            struct sxp_attribute *err_attr = NULL;
            enum sxp_error_code code = SXP_ERR_CODE_NONE;
            enum sxp_error_sub_code subcode = SXP_SUB_ERR_CODE_NONE;
            rc = sxpd_process_buffer(peer, socket, buffer, &err_attr, &code,
                                     &subcode);
            if (sxp_isnotok(rc, code, subcode)) {
                if (code != SXP_ERR_CODE_NONE ||
                    subcode != SXP_SUB_ERR_CODE_NONE) {
                    /* spec doesn't allow informing client about internal
                     * errors, so don't send any error in this case */
                    rc = sxpd_send_error(peer, socket, err_attr, code, subcode);
                }
                processing_error = true;
                break;
            }
        }
    } while (bytes_read);

out:
    if (RC_ISNOTOK(rc) || processing_error) {
        rc = sxpd_error_disconnect_peer(peer, socket, false);
        if (RC_ISNOTOK(rc)) {
            PLOG_ERROR_MSG(peer, "Disconnecting peer socket failed");
        }
    }
}

/**
 * @brief start connecting peer if possible
 *
 * @param peer peer to connect
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_connect_peer(struct sxpd_peer *peer)
{
    int rc = 0;
    struct address_md5_pwd_pair pwd_pair;

    PARAM_NULL_CHECK(rc, peer);
    RC_CHECK(rc, out);
    if (!sxpd_is_enabled(peer->sxpd_ctx) || !sxpd_md5sig_ok(peer->sxpd_ctx) ||
        sxpd_peer_connections_active(peer) >=
            sxpd_peer_connections_needed(peer)) {
        goto out;
    }

    if (peer->outgoing) {
        PLOG_TRACE_MSG(peer, "Close existing outgoing connection");
        evmgr_socket_destroy(peer->outgoing);
        peer->outgoing = NULL;
    }

    peer->outgoing = evmgr_socket_create(peer->sxpd_ctx->evmgr,
                                         peer->sxpd_ctx->evmgr_settings);
    if (!peer->outgoing) {
        PLOG_ERROR_MSG(peer, "Cannot create socket");
        rc = -1;
        goto out;
    }

    if (0 != peer->pwd_pair.password_len) {
        strncpy(pwd_pair.password, peer->pwd_pair.password,
                EVMGR_TCP_MD5_MAX_PWD_LEN);
        pwd_pair.password_len = peer->pwd_pair.password_len;
    } else {
        strncpy(pwd_pair.password, peer->sxpd_ctx->default_connection_password,
                EVMGR_TCP_MD5_MAX_PWD_LEN);
        pwd_pair.password_len =
            (uint16_t)strnlen(peer->sxpd_ctx->default_connection_password,
                              EVMGR_TCP_MD5_MAX_PWD_LEN);
    }
    pwd_pair.sin = peer->pwd_pair.sin;

    PLOG_TRACE_MSG(peer, "Connecting peer");
    rc = evmgr_socket_connect(peer->outgoing, &peer->sxpd_ctx->src_address,
                              &pwd_pair, sxpd_peer_read_callback,
                              sxpd_peer_write_callback,
                              sxpd_peer_event_callback, peer);

    if (RC_ISNOTOK(rc)) {
        evmgr_socket_destroy(peer->outgoing);
        peer->outgoing = NULL;
        rc = sxpd_schedule_connect_retry(peer);
    } else {
        PEER_CHANGE_OUT_CONN_STATE(peer, WAITING_CONNECT);
    }
out:
    return rc;
}

/**
 * @brief process password update
 *
 * @param ctx sxpd context to operate on
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_pwd_update(struct sxpd_ctx *ctx)
{
    int rc = 0;
    struct sxpd_peer *peer = NULL;
    size_t i = 0;

    PARAM_NULL_CHECK(rc, ctx);
    RC_CHECK(rc, out);

    /* reconnect all peers which are using default connection password */
    for (i = 0; i < ctx->peer_count; ++i) {
        peer = ctx->peers[i];

        if (0 == peer->pwd_pair.password_len) {
            PLOG_TRACE_MSG(peer, "Disconnecting peer");
            sxpd_disconnect_peer(peer);

            rc = evmgr_listener_md5_sig_del(ctx->listener, &peer->pwd_pair);
            if (RC_ISOK(rc)) {
                PLOG_TRACE_MSG(peer, "Removing md5sig from listener");
            } else {
                PLOG_ERROR_MSG(peer, "Failed to remove md5sig from listener");
                break;
            }

            if (!sxpd_pwd_is_empty(ctx)) {
                rc = evmgr_listener_md5_sig_add(
                    ctx->listener, ctx->default_connection_password,
                    &peer->pwd_pair);
                if (RC_ISOK(rc)) {
                    PLOG_TRACE_MSG(peer, "Adding md5sig to listener");
                } else {
                    PLOG_ERROR_MSG(peer, "Failed to add md5sig to listener");
                    break;
                }
            }

            PLOG_TRACE_MSG(peer, "Connecting peer");
            rc = sxpd_connect_peer(peer);
            if (RC_ISNOTOK(rc)) {
                PLOG_ERROR_MSG(peer, "Failed to connect peer");
                break;
            }
        }
    }

out:
    return rc;
}

/**
 * @brief enable expd daemon
 *
 * @param ctx sxpd context of the daemon
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_enable(struct sxpd_ctx *ctx)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, ctx);
    RC_CHECK(rc, out);
    RC_CHECK(rc = sxpd_setup_listener(ctx), out);
    /* connect all disconnected peers */
    rc = sxpd_connect_all_peers(ctx);
    if (RC_ISNOTOK(rc)) {
        LOG_ERROR("Failed to connect peers");
    }
out:
    return rc;
}

/**
 * @brief update password
 *
 * @param ctx sxpd daemon context
 * @param new_pwd new password
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_pwd_process(struct sxpd_ctx *ctx, const char *new_pwd)
{
    int rc = 0;
    bool md5sig_ok_old;
    bool pwd_old_empty;

    PARAM_NULL_CHECK(rc, ctx, new_pwd);
    RC_CHECK(rc, out);

    md5sig_ok_old = sxpd_md5sig_ok(ctx);
    pwd_old_empty = sxpd_pwd_is_empty(ctx);
    strncpy(ctx->default_connection_password, new_pwd, CFG_PASSWORD_MAX_SIZE);

    if (sxpd_is_enabled(ctx) && sxpd_node_id_is_set(ctx)) {
        if (md5sig_ok_old && sxpd_md5sig_ok(ctx)) {

            /* skip processing if empty password is removed */
            if (!(sxpd_pwd_is_empty(ctx) && pwd_old_empty)) {

                /* reconnect all connections which are using default password */
                rc = sxpd_pwd_update(ctx);
                if (RC_ISOK(rc)) {
                    LOG_TRACE("SXP daemon password update success");
                } else {
                    LOG_ERROR("SXP daemon password update failed: %d", rc);
                }
            }
        } else if (!md5sig_ok_old && sxpd_md5sig_ok(ctx)) {

            /* md5sig configuration has been changed from invalid to valid, SXPD
             * is enabling */
            rc = sxpd_enable(ctx);
            if (RC_ISOK(rc)) {
                LOG_TRACE("Enabling SXP daemon success");
            } else {
                LOG_ERROR("Enabling SXP daemon failed: %d", rc);
            }
        } else if (md5sig_ok_old && !sxpd_md5sig_ok(ctx)) {

            /* md5sig configuration has been changed from valid to invalid, SXPD
             * is disabling */
            rc = sxpd_disable(ctx);
            if (RC_ISOK(rc)) {
                LOG_TRACE("Disabling SXP daemon success");
            } else {
                LOG_ERROR("Disabling SXP daemon failed: %d", rc);
            }
        }
    }

    if (RC_ISOK(rc) && (!sxpd_md5sig_ok(ctx))) {
        LOG_ALERT("SXP daemon is disabled, because TCP md5 signature"
                  " is not supported in this system and some peers "
                  "are configured with TCP md5sig enabled");
    }

out:
    return rc;
}

/**
 * @startuml
 * participant "config manager" as config
 * participant "sxp daemon" as sxpd
 * config->sxpd: add string setting (sxpd_cfg_add_str_setting)
 * sxpd->sxpd: check setting validity (type)
 * alt setting type invalid
 *   sxpd-->config: failure response
 * else setting valid (default connection password)
 *   sxpd->sxpd:apply setting (sxpd_pwd_process)
 *   sxpd-->config: success/failure based on sxpd_pwd_process rc
 * end
 * @enduml
 */
int sxpd_cfg_add_str_setting(struct sxpd_ctx *ctx, str_setting_type_t type,
                             const char *value)
{
    int rc = 0;
    struct sxpd_ctx *sxpd_ctx = ctx;

    PARAM_NULL_CHECK(rc, ctx, value);
    RC_CHECK(rc, out);

    if (type >= STR_SETTING_LAST) {
        LOG_ERROR("Add string setting callback received invalid setting "
                  "type <%d>",
                  type);
        rc = -1;
        goto out;
    }

    LOG_TRACE("Processing added/updated str setting #%d <%s>", type,
              cfg_get_str_setting_str(type));

    switch (type) {
    case STR_SETTING_PASSWORD:
        /* process default password update */
        rc = sxpd_pwd_process(sxpd_ctx, value);
        break;
    case STR_SETTING_LAST:
        LOG_ERROR("Add string setting callback received invalid "
                  "setting type <%d>",
                  type);
        rc = -1;
        break;
    }

    if (RC_ISOK(rc)) {
        LOG_TRACE("Processing added/updated string setting #%d <%s> value: %s "
                  "success",
                  type, cfg_get_str_setting_str(type), value);
        sxpd_ctx->str_setting_is_set[type] = true;
    } else {
        LOG_ERROR(
            "Processing added/updated string setting #%d <%s> value: %s failed",
            type, cfg_get_str_setting_str(type), value);
    }

out:
    return rc;
}

/**
 * @startuml
 * participant "config manager" as config
 * participant "sxp daemon" as sxpd
 * config->sxpd: add string setting (sxpd_cfg_del_str_setting)
 * sxpd->sxpd: check setting validity (type)
 * alt setting type invalid
 *   sxpd-->config: failure response
 * else setting valid (default connection password)
 *   sxpd->sxpd: apply setting (sxpd_pwd_process)
 *   sxpd-->config: success/failure based on sxpd_pwd_process rc
 * end
 * @enduml
 */
int sxpd_cfg_del_str_setting(struct sxpd_ctx *ctx, str_setting_type_t type)
{
    int rc = 0;
    struct sxpd_ctx *sxpd_ctx = ctx;

    PARAM_NULL_CHECK(rc, ctx);
    RC_CHECK(rc, out);

    if (type >= STR_SETTING_LAST) {
        LOG_ERROR("Del string setting callback received invalid setting "
                  "type <%d>",
                  type);
        rc = -1;
        goto out;
    }

    LOG_TRACE("Processing deleted string setting #%d <%s>", type,
              cfg_get_str_setting_str(type));

    switch (type) {
    case STR_SETTING_PASSWORD:
        /* process default password update */
        rc = sxpd_pwd_process(sxpd_ctx, "");
        break;
    case STR_SETTING_LAST:
        LOG_ERROR("Del string setting callback received invalid "
                  "setting type #%d",
                  type);
        rc = -1;
        break;
    }

    if (RC_ISOK(rc)) {
        LOG_TRACE("Processing deleted string setting #%d <%s> value success",
                  type, cfg_get_str_setting_str(type));
        sxpd_ctx->str_setting_is_set[type] = false;
    } else {
        LOG_ERROR("Processing deleted string setting #%d <%s> value failed",
                  type, cfg_get_str_setting_str(type));
    }

out:
    return rc;
}

/**
 * @brief update bind address
 *
 * @param ctx sxpd context
 * @param update_outgoing if true, then all outgoing connections are canceled
 *and restarted (used in case when bind IP address changes)
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_update_bind_address(struct sxpd_ctx *ctx, bool update_outgoing)
{
    int rc = 0;
    struct sxpd_peer *peer = NULL;
    size_t i = 0;

    PARAM_NULL_CHECK(rc, ctx);
    RC_CHECK(rc, out);

    /* recreate listening socket */
    rc = sxpd_setup_listener(ctx);
    if (RC_ISOK(rc)) {
        LOG_TRACE("SXPD listening bind address updated success: %d", rc);
    } else {
        LOG_ERROR("SXPD listening bind address update failed: %d", rc);
        goto out;
    }

    /* recreate peers outgoing sockets */
    for (i = 0; i < ctx->peer_count; ++i) {
        peer = ctx->peers[i];

        rc = evmgr_listener_md5_sig_add(
            ctx->listener, ctx->default_connection_password, &peer->pwd_pair);
        if (RC_ISOK(rc)) {
            PLOG_TRACE_MSG(peer, "Peer md5sig password was added to listener");
        } else {
            PLOG_ERROR_MSG(peer, "Failed to add md5sig password to listener");
            break;
        }

        if ((true == update_outgoing) && (NULL != peer->outgoing)) {
            PLOG_TRACE_MSG(peer, "Disconnecting peer");
            rc = sxpd_disconnect_peer_socket(peer, peer->outgoing, true);
            if (RC_ISNOTOK(rc)) {
                PLOG_ERROR_MSG(peer, "Failed to disconnect peer");
                break;
            }

            PLOG_TRACE_MSG(peer, "Connecting peer");
            rc = sxpd_connect_peer(peer);
            if (RC_ISNOTOK(rc)) {
                PLOG_ERROR_MSG(peer, "Failed to connect peer");
                break;
            }
        }
    }

out:
    return rc;
}

/**
 * @brief destroy binding list and free memory
 *
 * @param bl binding list to destroy
 */
static void sxpd_destroy_binding_list(struct sxpd_binding_list *bl)
{
    if (bl) {
        LOG_TRACE("Destroy binding list %p", (void *)bl);
        while (bl->iterator) {
            (void)sxpd_iterate_bindings_internal(bl->iterator);
        }
        bl->count = 0;
        mem_free(bl->bindings);
        bl->mask.elem_count = 0;
        mem_free(bl->mask.elems);
        mem_free(bl);
    }
}

/**
 * @brief helper function - destroy binding list stored in radix node and return
 *1
 *
 * @param node radix node
 * @param ctx unused parameter
 *
 * @return 1
 */
static int
sxpd_delete_all_binding_lists_helper(struct radix_node *node,
                                     __attribute__((unused)) void *ctx)
{
    void *value = NULL;
    radix_parse_node(node, NULL, 0, NULL, &value);
    sxpd_destroy_binding_list(value);
    return 1;
}

/**
 * @brief disable sxpd daemon - delete all bindings, send purge-all to all peers
 *and disconnect them
 *
 * @param ctx sxpd context to operate on
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_disable(struct sxpd_ctx *ctx)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, ctx);
    RC_CHECK(rc, out);
    evmgr_listener_destroy(ctx->listener);
    ctx->listener = NULL;
    /* first clear the master bindings so that the peer disconnecting calls do
     * not iterate and update masks */
    rc = radix_delete_matching(ctx->master_bindings_v4,
                               sxpd_delete_all_binding_lists_helper, NULL);
    RC_CHECK(rc, out);
    rc = radix_delete_matching(ctx->master_bindings_v6,
                               sxpd_delete_all_binding_lists_helper, NULL);
    RC_CHECK(rc, out);
    /* send purge-all and disconnect all connected peers */
    size_t i = 0;
    for (i = 0; i < ctx->peer_count; ++i) {
        struct sxpd_peer *peer = ctx->peers[i];
        sxpd_disconnect_peer(peer);
        PLOG_TRACE_MSG(peer, "Disconnected peer");
    }
    /* now repopulate master bindings with configured bindings */
    struct radix_node *node = NULL;
    for (;;) {
        RC_CHECK(rc = radix_iterate(ctx->bindings_v4, node, &node), out);
        if (!node) {
            break;
        }
        struct v4_v6_prefix tmp = { 0, { { 0 } } };
        void *value = NULL;
        rc = radix_parse_node(node, tmp.ip.data, sizeof(tmp.ip.data), &tmp.len,
                              &value);
        RC_CHECK(rc, out);
        rc = sxpd_contribute_binding(ctx, V4, value, &tmp);
        RC_CHECK(rc, out);
    }
    node = NULL;
    for (;;) {
        RC_CHECK(rc = radix_iterate(ctx->bindings_v6, node, &node), out);
        if (!node) {
            break;
        }
        struct v4_v6_prefix tmp = { 0, { { 0 } } };
        void *value = NULL;
        rc = radix_parse_node(node, tmp.ip.data, sizeof(tmp.ip.data), &tmp.len,
                              &value);
        RC_CHECK(rc, out);
        rc = sxpd_contribute_binding(ctx, V6, value, &tmp);
        RC_CHECK(rc, out);
    }
out:
    return rc;
}

/**
 * @startuml
 * participant "config manager" as config
 * participant "sxp daemon" as sxpd
 * participant "log manager" as log_manager
 * config->sxpd: add uint32 setting (sxpd_cfg_add_uint32_setting)
 * alt log-level setting
 *   sxpd->sxpd: store log-level value in sxpd_context
 *   sxpd->log_manager: set log-level (log_setloglevel)
 *   sxpd-->config: success response
 * else enabled setting
 *   sxpd->sxpd: store enabled setting value in sxpd_context
 *   alt value set to true (enabling sxpd)
 *     sxpd->sxpd: check enabling conditions (node-id set, tcp-md5 signing\
 working if required)
 *     alt daemon is disabled and can be enabled
 *       sxpd->sxpd: enable daemon (sxpd_enable)
 *       sxpd-->config: success/failure response based on sxpd_enable rc
 *     else error occured or daemon cannot be enabled
 *       sxpd->log_manager: log alert to user
 *       sxpd-->config: success response
 *     end
 *   else value set to false (disabling sxpd)
 *     sxpd->sxpd: disable sxpd (sxpd_disable)
 *     sxpd-->config: success/failure response based on sxpd_disable rc
 *   end
 * else subnet expansion limit setting
 *   sxpd->sxpd: check if limit is lower than the current number of expanded\
 entries
 *   alt more expanded entries than the value to be applied
 *     sxpd-->log_manager: log alert to user
 *     sxpd-->config: failure response
 *   else less or equal expanded entries
 *     sxpd->sxpd: store subnet expansion limit value in sxpd_context
 *     sxpd-->config: success response
 *   end
 * else bind address/port setting
 *   sxpd->sxpd: store new bind address/port value
 *   sxpd->sxpd: check if daemon is enabled and node is set
 *   alt daemon enabled and node id set
 *     sxpd->sxpd: check if tcp-md5 signing is working if required
 *     alt tcp-md5 signing check passed
 *       sxpd->sxpd: recreate listening socket and re-init outgoing\
 connections (sxpd_update_bind_address)
 *       sxpd-->config: sxpd_update_bind_address response
 *     else tcp-md5 signing check failed
 *       sxpd->log_manager: log alert message to user
 *       sxpd-->config: success response
 *     end
 *   else daemon disabled or node id not set
 *     sxpd-->config: success response
 *   end
 * else node-id setting
 *   sxpd->sxpd: store new node-id value
 *   alt sxpd is disabled
 *     sxpd-->config: success response
 *   else sxpd is enabled
 *     alt tcp-md5 signing working if required
 *       alt node-id was set before
 *         sxpd->sxpd: disable daemon (sxpd_disable)
 *         alt disabling failed
 *           sxpd-->config: failure response
 *         end
 *       end
 *       sxpd->sxpd: enable daemon (sxpd_enable)
 *       sxpd-->config: success/failure based on sxpd_enable rc
 *     else tcp-md5 signing not working and required
 *       sxpd->log_manager: log alert message to user
 *       sxpd-->config: success response
 *     end
 *   end
 * else
 *   sxpd->sxpd: store setting value in sxpd_context
 *   sxpd-->config: success response
 * end
 * @enduml
 */
int sxpd_cfg_add_uint32_setting(struct sxpd_ctx *ctx,
                                uint32_setting_type_t type, uint32_t value)
{
    int rc = 0;
    struct sxpd_ctx *sxpd_ctx = ctx;
    const char *name = NULL;

    PARAM_NULL_CHECK(rc, ctx);
    RC_CHECK(rc, out);

    if (type >= UINT32_SETTING_LAST) {
        LOG_ERROR("Add uint32 setting callback received invalid setting "
                  "type <%d>",
                  type);
        rc = -1;
        goto out;
    }

    name = cfg_get_uint32_setting_str(type);
    LOG_TRACE("Processing added/updated uint32 setting #%d <%s>", type, name);

    switch (type) {
    case UINT32_SETTING_LOG_LEVEL:
        if (LOG_LEVEL_ALERT <= value && LOG_LEVEL_DEBUG >= value) {
            enum log_level loglevel = value;
            LOG_TRACE("Updating <%s> to: <%d> <%s>", name, loglevel,
                      log_level_to_string(loglevel));
            log_setloglevel(loglevel);
        } else {
            LOG_ERROR("Add uint32 global setting <%s> value <%" PRIu32
                      "> is out of range <%d, %d>",
                      name, value, LOG_LEVEL_ALERT, LOG_LEVEL_DEBUG);
            rc = -1;
        }
        break;
    case UINT32_SETTING_ENABLED:
        if (value <= 1) {
            sxpd_ctx->enabled = (bool)value;
            if ((true == sxpd_ctx->enabled) && sxpd_node_id_is_set(sxpd_ctx)) {
                if (sxpd_md5sig_ok(sxpd_ctx)) {
                    rc = sxpd_enable(sxpd_ctx);
                    if (RC_ISOK(rc)) {
                        LOG_TRACE("Enabling SXP daemon success");
                    } else {
                        LOG_ERROR("Enabling SXP daemon failed: %d", rc);
                    }
                } else {
                    LOG_ALERT(
                        "SXP daemon is disabled, because TCP md5 signature"
                        " is not supported in this system and some peers "
                        "are configured with TCP md5sig enabled");
                }
            } else if (sxpd_md5sig_ok(sxpd_ctx)) {
                rc = sxpd_disable(sxpd_ctx);
                if (RC_ISOK(rc)) {
                    LOG_TRACE("Disabling SXP daemon success");
                } else {
                    LOG_ERROR("Disabling SXP daemon failed: %d", rc);
                }
            }
        } else {
            LOG_ERROR("Add uint32 global setting 'enabled' value <%" PRIu32
                      "> is out of range <0, %" PRIu16 ">",
                      value, 1);
            rc = -1;
        }
        break;
    case UINT32_SETTING_RETRY_TIMER:
        if (value <= UINT16_MAX) {
            sxpd_ctx->retry_timeout.tv_sec = (uint16_t)value;
        } else {
            LOG_ERROR("Add uint32 global setting retry-timer value <%" PRIu32
                      "> is out of range <0, %" PRIu16 ">",
                      value, UINT16_MAX);
            rc = -1;
        }
        break;
    case UINT32_SETTING_RECONCILIATION_TIMER:
        if (value <= UINT16_MAX) {
            sxpd_ctx->reconciliation_timeout.tv_sec = (uint16_t)value;
        } else {
            LOG_ERROR("Add uint32 global setting reconciliation-timer "
                      "value <%" PRIu32 "> is out of range <0, %" PRIu16 ">",
                      value, UINT16_MAX);
            rc = -1;
        }
        break;
    case UINT32_SETTING_SPEAKER_MIN_HOLD_TIME:
        if (value <= UINT16_MAX) {
            sxpd_ctx->speaker_min_hold_time = (uint16_t)value;
        } else {
            LOG_ERROR("Add uint32 global setting hold-timer-minimum value "
                      "<%" PRIu32 "> is out of range <0, %" PRIu16 ">",
                      value, UINT16_MAX);
            rc = -1;
        }
        break;
    case UINT32_SETTING_LISTENER_MIN_HOLD_TIME:
        if (value <= UINT16_MAX) {
            sxpd_ctx->listener_min_hold_time = (uint16_t)value;
        } else {
            LOG_ERROR("Add uint32 global setting hold-timer-minimum value "
                      "<%" PRIu32 "> is out of range <0, %" PRIu16 ">",
                      value, UINT16_MAX);
            rc = -1;
        }
        break;
    case UINT32_SETTING_LISTENER_MAX_HOLD_TIME:
        if (value <= UINT16_MAX) {
            sxpd_ctx->listener_max_hold_time = (uint16_t)value;
        } else {
            LOG_ERROR("Add uint32 global setting hold-timer-maximum value "
                      "<%" PRIu32 "> is out of range <0, %" PRIu16 ">",
                      value, UINT16_MAX);
            rc = -1;
        }
        break;
    case UINT32_SETTING_KEEPALIVE_TIMER:
        if (value <= UINT16_MAX) {
            sxpd_ctx->keepalive_timeout.tv_sec = (uint16_t)value;
        } else {
            LOG_ERROR("Add uint32 global setting keepalive-timer value "
                      "<%" PRIu32 "> is out of range <0, %" PRIu16 ">",
                      value, UINT16_MAX);
            rc = -1;
        }
        break;
    case UINT32_SETTING_SUBNET_EXPANSION_LIMIT:
        if (value <= UINT16_MAX) {
            if (sxpd_ctx->expanded_entry_count > (uint16_t)value) {
                LOG_ALERT(
                    "Cannot configure expansion limit %" PRIu32
                    " lower than the current number of expanded entries %zu",
                    value, sxpd_ctx->expanded_entry_count);
                rc = -1;
            } else {
                sxpd_ctx->sub_expand_limit = (uint16_t)value;
                rc = sxpd_expand_bindings(sxpd_ctx);
            }
        } else {
            LOG_ERROR("Add uint32 global setting subnet-expansion-limit "
                      "value <%" PRIu32 "> is out of range <0, %" PRIu16 ">",
                      value, UINT16_MAX);
            rc = -1;
        }
        break;
    case UINT32_SETTING_BIND_ADDRESS:
        sxpd_ctx->nbo_bind_ip = value;
        sxpd_ctx->src_address.sin_family = AF_INET;
        sxpd_ctx->src_address.sin_addr.s_addr = sxpd_ctx->nbo_bind_ip;
        /* recreate listening socket and all peer outgoing sockets with new
         * bind address */
        if (sxpd_is_enabled(sxpd_ctx) && sxpd_node_id_is_set(sxpd_ctx)) {
            if (sxpd_md5sig_ok(sxpd_ctx)) {
                rc = sxpd_update_bind_address(sxpd_ctx, true);
                if (RC_ISOK(rc)) {
                    LOG_TRACE("SXP daemon bind address update success");
                } else {
                    LOG_ERROR("SXP daemon bind address update failed: %d", rc);
                }
            } else {
                LOG_ALERT("SXP daemon is disabled, because TCP md5 signature"
                          " is not supported in this system and some peers "
                          "are configured with TCP md5sig enabled");
            }
        }
        break;
    case UINT32_SETTING_PORT:
        if (value <= UINT16_MAX) {
            sxpd_ctx->nbo_port = (uint16_t)value;
            /* recreate listening socket */
            if (sxpd_is_enabled(sxpd_ctx) && sxpd_node_id_is_set(sxpd_ctx)) {
                if (sxpd_md5sig_ok(sxpd_ctx)) {
                    rc = sxpd_update_bind_address(sxpd_ctx, false);
                    if (RC_ISOK(rc)) {
                        LOG_TRACE("SXP daemon bind port update success");
                    } else {
                        LOG_ERROR("SXP daemon bind port update failed: %d", rc);
                    }
                } else {
                    LOG_ALERT(
                        "SXP daemon is disabled, because TCP md5 signature"
                        " is not supported in this system and some peers "
                        "are configured with TCP md5sig enabled");
                }
            }
        } else {
            LOG_ERROR("Add uint32 global setting port value <%" PRIu32
                      "> is out of range <0, %" PRIu16 ">",
                      value, UINT16_MAX);
            rc = -1;
        }
        break;
    case UINT32_SETTING_NODE_ID:
        sxpd_ctx->node_id = value;
        if (sxpd_is_enabled(sxpd_ctx)) {
            if (sxpd_md5sig_ok(sxpd_ctx)) {
                LOG_TRACE(
                    "SXPD node id has been changed, reconnecting all peers");
                if (sxpd_node_id_is_set(sxpd_ctx)) {
                    rc = sxpd_disable(ctx);
                    if (RC_ISOK(rc)) {
                        LOG_TRACE("Disabling SXP daemon success");
                    } else {
                        LOG_ERROR("Disabling SXP daemon failed: %d", rc);
                    }
                }

                if (RC_ISOK(rc)) {
                    rc = sxpd_enable(sxpd_ctx);
                    if (RC_ISOK(rc)) {
                        LOG_TRACE("Enabling SXP daemon success");
                    } else {
                        LOG_ERROR("Enabling SXP daemon failed: %d", rc);
                    }
                }
            } else {
                LOG_ALERT("SXP daemon is disabled, because TCP md5 signature"
                          " is not supported in this system and some peers "
                          "are configured with TCP md5sig enabled");
            }
        }
        break;
    case UINT32_SETTING_LAST:
        LOG_ERROR("Add uint32 setting callback received invalid "
                  "setting type #%d",
                  type);
        rc = -1;
        break;
    }

    if (RC_ISOK(rc)) {
        LOG_TRACE(
            "Processing added/updated uint32 setting #%d <%s> value: %" PRIu32
            " success",
            type, name, value);
        sxpd_ctx->uint32_setting_is_set[type] = true;
    } else {
        LOG_ERROR(
            "Processing added/updated uint32 setting #%d <%s> value: %" PRIu32
            " failed",
            type, name, value);
    }

out:
    if (RC_ISNOTOK(rc)) {
        LOG_ALERT("Warning: applying configuration option failed");
    }
    return rc;
}

/**
 * @startuml
 * participant "config manager" as config
 * participant "sxp daemon" as sxpd
 * participant "log manager" as log_manager
 * config->sxpd: delete uint32 setting (sxpd_cfg_del_uint32_setting)
 * sxpd->sxpd: restore default value of setting
 * alt log-level setting changed
 *   sxpd->log_manager: set default log-level
 * else enabled setting removed and daemon is enabled
 *   sxpd->sxpd: disable daemon (sxpd_disable)
 *   sxpd-->config: success/failure response based on sxpd_disable rc
 * else bind address or port setting removed from active daemon
 *   alt tcp-md5 signing not supported but required by some peer
 *     sxpd->log_manager: log alert message to user
 *   else tcp-md5 signing not used or working
 *     sxpd->sxpd: recreate listening socket and re-init outgoing connections\
 (sxpd_update_bind_address)
 *     sxpd-->config: success/failure response based on\
 sxpd_update_bind_address rc
 *   end
 * else
 *   sxpd-->config: success response
 * end
 * @enduml
 */
int sxpd_cfg_del_uint32_setting(struct sxpd_ctx *ctx,
                                uint32_setting_type_t type)
{
    int rc = 0;
    struct sxpd_ctx *sxpd_ctx = ctx;
    const char *name = NULL;

    PARAM_NULL_CHECK(rc, ctx);
    RC_CHECK(rc, out);

    if (type >= UINT32_SETTING_LAST) {
        LOG_ERROR("Del uint32 setting callback received invalid setting "
                  "type <%d>",
                  type);
        rc = -1;
        goto out;
    }

    name = cfg_get_uint32_setting_str(type);
    LOG_TRACE("Processing deleted uint32 setting #%d <%s>", type, name);

    switch (type) {
    case UINT32_SETTING_LOG_LEVEL:
        LOG_TRACE("Reseting <%s> to default value: <%d> <%s>", name,
                  sxpd_ctx->default_log_level,
                  log_level_to_string(sxpd_ctx->default_log_level));
        log_setloglevel(sxpd_ctx->default_log_level);
        break;
    case UINT32_SETTING_ENABLED:
        sxpd_ctx->enabled = false;
        if (sxpd_node_id_is_set(sxpd_ctx)) {
            if (sxpd_md5sig_ok(sxpd_ctx)) {
                rc = sxpd_disable(sxpd_ctx);
                if (RC_ISOK(rc)) {
                    LOG_TRACE("Disabling SXP daemon success");
                } else {
                    LOG_ERROR("Disabling SXP daemon failed: %d", rc);
                }
            } else {
                LOG_ALERT("SXP daemon is disabled, because TCP md5 signature"
                          " is not supported in this system and some peers "
                          "are configured with TCP md5sig enabled");
            }
        }
        break;
    case UINT32_SETTING_RETRY_TIMER:
        sxpd_ctx->retry_timeout.tv_sec = UINT32_SETTING_RETRY_TIMER_DEFAULT;
        break;
    case UINT32_SETTING_RECONCILIATION_TIMER:
        sxpd_ctx->reconciliation_timeout.tv_sec =
            UINT32_SETTING_RECONCILIATION_TIMER_DEFAULT;
        break;
    case UINT32_SETTING_SPEAKER_MIN_HOLD_TIME:
        sxpd_ctx->speaker_min_hold_time =
            UINT32_SETTING_SPEAKER_MIN_HOLD_TIME_DEFAULT;
        break;
    case UINT32_SETTING_LISTENER_MIN_HOLD_TIME:
        sxpd_ctx->listener_min_hold_time =
            UINT32_SETTING_LISTENER_MIN_HOLD_TIME_DEFAULT;
        break;
    case UINT32_SETTING_LISTENER_MAX_HOLD_TIME:
        sxpd_ctx->listener_max_hold_time =
            UINT32_SETTING_LISTENER_MAX_HOLD_TIME_DEFAULT;
        break;
    case UINT32_SETTING_KEEPALIVE_TIMER:
        sxpd_ctx->keepalive_timeout.tv_sec =
            UINT32_SETTING_KEEPALIVE_TIMER_DEFAULT;
        break;
    case UINT32_SETTING_SUBNET_EXPANSION_LIMIT:
        sxpd_ctx->sub_expand_limit =
            UINT32_SETTING_SUBNET_EXPANSION_LIMIT_DEFAULT;
        break;
    case UINT32_SETTING_BIND_ADDRESS:
        sxpd_ctx->nbo_bind_ip = INADDR_ANY;
        sxpd_ctx->src_address.sin_family = AF_UNSPEC;
        sxpd_ctx->src_address.sin_addr.s_addr = sxpd_ctx->nbo_bind_ip;
        /* recreate listening socket and all peer outgoing sockets with new
         * bind address */
        if (sxpd_is_enabled(sxpd_ctx) && sxpd_node_id_is_set(sxpd_ctx)) {
            if (sxpd_md5sig_ok(sxpd_ctx)) {
                rc = sxpd_update_bind_address(sxpd_ctx, true);
                if (RC_ISOK(rc)) {
                    LOG_TRACE("Update SXP daemon bind address success");
                } else {
                    LOG_ERROR("Update SXP daemon bind address failed: %d", rc);
                }
            } else {
                LOG_ALERT("SXP daemon is disabled, because TCP md5 signature"
                          " is not supported in this system and some peers "
                          "are configured with TCP md5sig enabled");
            }
        }
        break;
    case UINT32_SETTING_PORT:
        sxpd_ctx->nbo_port = htons(UINT32_SETTING_PORT_DEFAULT);
        /* recreate listening socket */
        if (sxpd_is_enabled(sxpd_ctx) && sxpd_node_id_is_set(sxpd_ctx)) {
            if (sxpd_md5sig_ok(sxpd_ctx)) {
                rc = sxpd_update_bind_address(sxpd_ctx, false);
                if (RC_ISOK(rc)) {
                    LOG_TRACE("Update SXP daemon bind port success");
                } else {
                    LOG_ERROR("Update SXP daemon bind port failed: %d", rc);
                }
            } else {
                LOG_ALERT("SXP daemon is disabled, because TCP md5 signature"
                          " is not supported in this system and some peers "
                          "are configured with TCP md5sig enabled");
            }
        }
        break;
    case UINT32_SETTING_NODE_ID:
        assert(0);
        break;
    case UINT32_SETTING_LAST:
        LOG_ERROR("Add uint32 setting callback received invalid "
                  "setting type #%d",
                  type);
        rc = -1;
        break;
    }

    if (RC_ISOK(rc)) {
        LOG_TRACE("Processing deleted uint32 setting #%d <%s> value success",
                  type, name);
        sxpd_ctx->uint32_setting_is_set[type] = false;
    } else {
        LOG_TRACE("Processing deleted uint32 setting #%d <%s> value failed",
                  type, name);
    }

out:
    return rc;
}

/**
 * @brief allocate and initialze peer entry
 *
 * @param ctx sxpd context to operate on
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_alloc_peer(struct sxpd_ctx *ctx)
{
    int rc = 0;
    struct radix_tree *bindings_v4 = NULL;
    struct radix_tree *bindings_v6 = NULL;

    PARAM_NULL_CHECK(rc, ctx);
    RC_CHECK(rc, out);
    bindings_v4 = radix_create(RADIX_V4_MAXBITS);
    if (!bindings_v4) {
        LOG_ERROR("Cannot allocate radix tree for v4 bindings");
        rc = -1;
        goto out;
    }
    bindings_v6 = radix_create(RADIX_V6_MAXBITS);
    if (!bindings_v6) {
        LOG_ERROR("Cannot allocate radix tree for v6 bindings");
        rc = -1;
        goto out;
    }
    struct sxpd_peer **tmp_peers = NULL;
    if (ctx->peers) {
        tmp_peers =
            mem_realloc(ctx->peers, sizeof(*tmp_peers) * (ctx->peer_count + 1));
    } else {
        tmp_peers = mem_calloc(1, sizeof(*tmp_peers));
    }

    if (!tmp_peers) {
        LOG_ERROR("Cannot (re)allocate peers array");
        rc = -1;
        goto out;
    } else {
        ctx->peers = tmp_peers;
        ctx->peers[ctx->peer_count] =
            mem_calloc(1, sizeof(*ctx->peers[ctx->peer_count]));
        if (!ctx->peers[ctx->peer_count]) {
            LOG_ERROR("Cannot allocate peer");
            rc = -1;
            goto out;
        } else {
            ctx->peers[ctx->peer_count]->sxpd_ctx = ctx;
        }
    }

    ctx->peers[ctx->peer_count]->bindings_v4 = bindings_v4;
    bindings_v4 = NULL;
    ctx->peers[ctx->peer_count]->bindings_v6 = bindings_v6;
    bindings_v6 = NULL;
    ctx->peers[ctx->peer_count]->listener_hold_time = KEEPALIVE_UNUSED;
    ctx->peers[ctx->peer_count]->speaker_hold_time = KEEPALIVE_UNUSED;
    ++ctx->peer_count;

out:
    radix_destroy(bindings_v4, NULL);
    radix_destroy(bindings_v6, NULL);
    return rc;
}

/**
 * @brief destroy peer and free allocated memory
 *
 * @param ctx sxpd context to which the peer belongs
 * @param peer peer structure to destroy
 */
static void sxpd_free_peer(struct sxpd_ctx *ctx, struct sxpd_peer *peer)
{
    if (!peer) {
        return;
    }
    if (ctx) {
        size_t i = 0;
        for (i = 0; i < ctx->peer_count; ++i) {
            if (peer == ctx->peers[i]) {
                PLOG_TRACE_MSG(peer, "Found peer for removal");
                if (i == (ctx->peer_count - 1)) {
                    ctx->peers[i] = NULL;
                } else {
                    ctx->peers[i] = ctx->peers[ctx->peer_count - 1];
                    ctx->peers[ctx->peer_count - 1] = NULL;
                }
                --ctx->peer_count;
                break;
            }
        }
        for (i = 0; i < ctx->listener_count; ++i) {
            if (peer == ctx->listeners[i]) {
                if (i == (ctx->listener_count - 1)) {
                    ctx->listeners[i] = NULL;
                } else {
                    ctx->listeners[i] = ctx->listeners[ctx->listener_count - 1];
                    ctx->listeners[ctx->listener_count - 1] = NULL;
                }
                --ctx->listener_count;
            }
        }
    }
    bool unused = false;
    int rc = sxpd_peer_delete_all_bindings(peer, V4, &unused);
    if (RC_ISOK(rc)) {
        rc = sxpd_peer_delete_all_bindings(peer, V6, &unused);
    }
    if (RC_ISNOTOK(rc)) {
        LOG_ERROR("Warning, could not remove all bindings");
    }
    radix_destroy(peer->bindings_v4, NULL);
    radix_destroy(peer->bindings_v6, NULL);
    evmgr_socket_destroy(peer->outgoing);
    evmgr_socket_destroy(peer->incoming);
    evmgr_timer_destroy(peer->hold_timer);
    evmgr_timer_destroy(peer->retry_timer);
    evmgr_timer_destroy(peer->keepalive_timer);
    evmgr_timer_destroy(peer->reconciliation_timer);
    evmgr_timer_destroy(peer->delete_hold_down_timer);
    sxpd_release_buffer(ctx, peer->incoming_in_buffer);
    sxpd_release_buffer(ctx, peer->outgoing_in_buffer);

    if (NULL != peer->reconciliation_timestamp) {
        destroy_timestamp(peer->reconciliation_timestamp);
        peer->reconciliation_timestamp = NULL;
    }

    PLOG_TRACE_MSG(peer, "Removing peer");
    mem_free(peer);
}

/**
 * @startuml
 * participant "config manager" as config
 * participant "sxp daemon" as sxpd
 * database "peer database" as peerdb
 * participant "event manager" as evmgr
 * config->sxpd: add peer (sxpd_cfg_add_peer)
 * alt tcp-md5 signing applicable
 * sxpd->sxpd: check tcp-md5 password
 * alt invalid password
 * sxpd-->config: failure response
 * else valid password
 * create peer
 * sxpd->peer: allocate peer
 * alt failure (not enough memory etc.)
 * sxpd-->config: failure response
 * else success
 * sxpd->peerdb: add peer to peer database
 * peerdb-->sxpd: response
 * alt failure
 * sxpd-->config: failure response
 * else success
 * sxpd->evmgr: add tcp-md5 signing pair to listening socket
 * evmgr-->sxpd: response
 * alt failure
 * sxpd-->config: failure response
 * else success
 * sxpd-->config: success response
 * end
 * end
 * end
 * end
 * else no tcp-md5 signing
 * create peer
 * sxpd->peer: allocate peer
 * alt failure (not enough memory etc.)
 * sxpd-->config: failure response
 * else success
 * sxpd->peerdb: add peer to peer database
 * peerdb-->sxpd: response
 * alt failure
 * sxpd-->config: failure response
 * else success
 * sxpd-->config: success response
 * end
 * end
 * end
 * @enduml
 */
int sxpd_cfg_add_peer(struct sxpd_ctx *ctx, const struct peer *peer)
{
    int rc = 0;
    struct sxpd_peer *sxpd_peer = NULL;
    bool md5sig_peers_inc = false;
    bool md5sig_ok_old = false;

    PARAM_NULL_CHECK(rc, ctx, peer);
    RC_CHECK(rc, out);
    if ((NULL != peer->connection_password) &&
        (strlen(peer->connection_password) > EVMGR_TCP_MD5_MAX_PWD_LEN)) {
        LOG_ERROR("Peers password is longer then max pwd length %d",
                  EVMGR_TCP_MD5_MAX_PWD_LEN);
        rc = -1;
        goto out;
    }

    RC_CHECK(rc = sxpd_alloc_peer(ctx), out);
    sxpd_peer = ctx->peers[ctx->peer_count - 1];
    if (peer->connection_password) {
        strncpy(sxpd_peer->pwd_pair.password, peer->connection_password,
                sizeof(sxpd_peer->pwd_pair.password) - 1);
        sxpd_peer->pwd_pair.password_len =
            (uint16_t)strlen(peer->connection_password);
    } else {
        sxpd_peer->pwd_pair.password[0] = '\0';
        sxpd_peer->pwd_pair.password_len = 0;
    }
    sxpd_peer->pwd_pair.sin.sin_family = AF_INET;
    if (peer->port_is_set) {
        sxpd_peer->pwd_pair.sin.sin_port = peer->port;
    } else {
        sxpd_peer->pwd_pair.sin.sin_port = ntohs(UINT32_SETTING_PORT_DEFAULT);
    }
    sxpd_peer->pwd_pair.sin.sin_addr.s_addr = peer->ip_address;
    sxpd_peer->type = peer->peer_type;
    if (sxpd_is_listener(sxpd_peer)) {
        struct sxpd_peer **tmp = NULL;
        if (ctx->listeners) {
            tmp = mem_realloc(ctx->listeners,
                              sizeof(tmp[0]) * (ctx->listener_count + 1));
        } else {
            tmp = mem_calloc(1, sizeof(tmp[0]));
        }
        if (!tmp) {
            LOG_ERROR("Cannot (re)allocate listeners array");
            rc = -1;
            goto out;
        }
        ctx->listeners = tmp;
        ctx->listeners[ctx->listener_count] = sxpd_peer;
        sxpd_peer->listener_bit_pos = ctx->listener_count;
        ++ctx->listener_count;
    }
    PLOG_TRACE_MSG(sxpd_peer, "Registered new peer");
    sxpd_peer->outgoing_state = NONE;

    md5sig_ok_old = sxpd_md5sig_ok(ctx);
    /* if peer is using own md5sig password increase number of md5sig peers */
    if (!sxpd_peer_pwd_is_empty(sxpd_peer)) {
        md5sig_peers_inc = true;
        ctx->md5sig_peers++;
    }

    if (ctx->enabled == true) {
        if (sxpd_md5sig_ok(ctx)) {
            rc = evmgr_listener_md5_sig_add(ctx->listener,
                                            ctx->default_connection_password,
                                            &sxpd_peer->pwd_pair);
            RC_CHECK(rc, out);
            RC_CHECK(rc = sxpd_connect_peer(sxpd_peer), out);
        } else if (!sxpd_md5sig_ok(ctx)) {
            LOG_ALERT("SXP daemon is disabled, because TCP md5 signature"
                      " is not supported in this system and some peers "
                      "are configured with TCP md5sig enabled");
            if (md5sig_ok_old) {
                rc = sxpd_disable(ctx);
                if (RC_ISOK(rc)) {
                    LOG_TRACE("Disabling SXP daemon success");
                } else {
                    LOG_ERROR("Disabling SXP daemon failed: %d", rc);
                }
            }
        }
    }
out:
    if (RC_ISNOTOK(rc) && sxpd_peer) {
        sxpd_free_peer(ctx, sxpd_peer);
    }

    if (RC_ISNOTOK(rc) && md5sig_peers_inc) {
        ctx->md5sig_peers--;
    }
    return rc;
}

/**
 * @brief disconnect all peer connections
 *
 * @param peer peer to disconnect
 */
static void sxpd_disconnect_peer(struct sxpd_peer *peer)
{
    if (!peer) {
        return;
    }

    /* unregister retry timer */
    evmgr_timer_destroy(peer->retry_timer);
    peer->retry_timer = NULL;

    /* send purge all message only if peer is listener */
    if (peer->listener) {
        int rc = sxpd_send_purge_all(peer);
        /* if purge-all was a success, then do not disconnect immediately - wait
         * for data to be written, otherwise immediate disconnect
         * don't care if this succeeds - we're disconnecting anyway */
        (void)sxpd_disconnect_peer_socket(peer, peer->listener, RC_ISNOTOK(rc));
    }

    if (peer->speaker) {
        /* don't care if this succeeds - we're disconnecting anyway */
        (void)sxpd_disconnect_peer_socket(peer, peer->speaker, true);
    }

    if (peer->outgoing) {
        (void)sxpd_disconnect_peer_socket(peer, peer->outgoing, true);
    }

    if (peer->incoming) {
        (void)sxpd_disconnect_peer_socket(peer, peer->incoming, true);
    }
}

/**
 * @startuml
 * participant "config manager" as config
 * participant "sxp daemon" as sxpd
 * database "peer database" as peerdb
 * participant "event manager" as evmgr
 * participant peer
 * config->sxpd: remove peer (sxpd_cfg_del_peer)
 * sxpd->peerdb: find peer (sxpd_find_peer)
 * alt peer not found
 * sxpd-->config: failure response
 * else peer found
 * sxpd->peer: disconnect peer (sxpd_disconnect_peer)
 * sxpd->evmgr: delete tcp-md5 signing password (evmgr_listener_md5_sig_del)
 * sxpd->sxpd: check if daemon can be enabled\n(tcp-md5 signing not available\
 and this peer was the last peer with tcp-md5 password signing)
 * alt daemon is disabled and it is possible to enable
 * sxpd->sxpd: enable (sxpd_enable)
 * sxpd-->config: success/failure based on sxpd_enable rc
 * else daemon cannot be enabled or is already enabled
 * sxpd-->config: success response
 * end
 * end
 * @enduml
 */
int sxpd_cfg_del_peer(struct sxpd_ctx *ctx, const struct peer *peer)
{
    int rc = 0;
    struct sxpd_peer *sxpd_peer = NULL;
    struct sxpd_ctx *sxpd_ctx = NULL;
    struct sockaddr_in sin;
    bool md5sig_ok_old = false;

    PARAM_NULL_CHECK(rc, ctx, peer);
    RC_CHECK(rc, out);

    sxpd_ctx = ctx;
    /* find sxpd peer by peer */
    sin.sin_family = AF_INET;
    sin.sin_port = peer->port;
    sin.sin_addr.s_addr = peer->ip_address;
    sxpd_peer = sxpd_find_peer(ctx, &sin);
    if (!sxpd_peer) {
        LOG_ERROR("Peer " DEBUG_V4_FMT "not found",
                  DEBUG_V4_PRINT(peer->ip_address));
        rc = -1;
        goto out;
    }

    md5sig_ok_old = sxpd_md5sig_ok(sxpd_ctx);
    if (!sxpd_peer_pwd_is_empty(sxpd_peer)) {
        sxpd_ctx->md5sig_peers--;
    }

    if (sxpd_is_enabled(sxpd_ctx) && md5sig_ok_old) {
        sxpd_disconnect_peer(sxpd_peer);
        evmgr_listener_md5_sig_del(sxpd_ctx->listener, &sxpd_peer->pwd_pair);
    }
    sxpd_free_peer(ctx, sxpd_peer);
    LOG_TRACE("deleted peer: " DEBUG_V4_FMT ":%" PRIu16,
              DEBUG_V4_PRINT(peer->ip_address), peer->port);

    /* if md5sig configuration was changed from invalid to valid enable SXP
     * daemon */
    if (!md5sig_ok_old && sxpd_md5sig_ok(sxpd_ctx)) {
        rc = sxpd_enable(sxpd_ctx);
        if (RC_ISOK(rc)) {
            LOG_TRACE("Enabling SXP daemon success");
        } else {
            LOG_ERROR("Enabling SXP daemon failed: %d", rc);
        }
    } else if (!sxpd_md5sig_ok(sxpd_ctx)) {
        LOG_ALERT("SXP daemon is disabled, because TCP md5 signature"
                  " is not supported in this system and some peers "
                  "are configured with TCP md5sig enabled");
    }
out:
    return rc;
}

/**
 * @brief add ipv4 binding to sxpd local bindings database
 *
 * @param ctx sxpd context to operate on
 * @param prefix network prefix bits
 * @param length length of network prefix (in bits)
 * @param tag associate source group tag
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_add_binding_v4(struct sxpd_ctx *ctx, uint32_t prefix,
                               uint8_t length, uint16_t tag)
{
    int rc = 0;
    struct radix_node *node = NULL;
    struct sxpd_binding *b = NULL;
    PARAM_NULL_CHECK(rc, ctx);
    RC_CHECK(rc, out);
    struct v4_v6_prefix tmp = {.len = length, .ip = {.v4 = prefix } };
    struct timestamp *stamp = get_timestamp();
    if (!stamp) {
        LOG_ERROR("Cannot get timestamp");
        rc = -1;
        goto out;
    }
    rc = radix_search(ctx->bindings_v4, tmp.ip.data, tmp.len, &node);
    RC_CHECK(rc, out);
    if (node) {
        LOG_TRACE("Binding already stored - re-use radix node");
        void *value = NULL;
        RC_CHECK(rc = radix_parse_node(node, NULL, 0, NULL, &value), out);
        b = value;
        destroy_timestamp(b->timestamp);
        b->timestamp = stamp;
        LOG_DEBUG("Fetched binding %p", (void *)b);
    } else {
        b = mem_calloc(1, sizeof(*b));
        if (!b) {
            LOG_ERROR("Cannot allocate sxpd binding");
            rc = -1;
            goto out;
        }
        b->timestamp = stamp;
        rc = radix_store(ctx->bindings_v4, tmp.ip.data, tmp.len, b, &node);
        if (RC_ISNOTOK(rc)) {
            sxpd_destroy_binding(b);
            goto out;
        }
        LOG_DEBUG("Create binding %p", (void *)b);
    }
    b->tag = tag;
    LOG_DEBUG("Stored new binding %p " DEBUG_V4_FMT "/%" PRIu8 " = %" PRIu16,
              (void *)b, DEBUG_V4_PRINT(tmp.ip.v4), tmp.len, tag);
    rc = sxpd_contribute_binding(ctx, V4, b, &tmp);
    RC_CHECK(rc, out);
    rc = sxpd_export_bindings(ctx);
out:
    return rc;
}

/**
 * @brief remove ipv4 binding from sxpd local bindings database
 *
 * @param ctx sxpd context to operate on
 * @param prefix network prefix bits
 * @param length length of network prefix (in bits)
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_del_binding_v4(struct sxpd_ctx *ctx, uint32_t prefix,
                               uint8_t length)
{
    int rc = 0;
    struct radix_node *node = NULL;
    struct sxpd_binding *b = NULL;
    PARAM_NULL_CHECK(rc, ctx);
    RC_CHECK(rc, out);
    struct v4_v6_prefix tmp = {.len = length, .ip = {.v4 = prefix } };
    rc = radix_search(ctx->bindings_v4, tmp.ip.data, tmp.len, &node);
    RC_CHECK(rc, out);
    if (node) {
        void *value = NULL;
        RC_CHECK(rc = radix_parse_node(node, NULL, 0, NULL, &value), out);
        RC_CHECK(rc = radix_delete_node(ctx->bindings_v4, node), out);
        b = value;
        LOG_DEBUG("Fetched binding %p", (void *)b);
        bool binding_was_selected = false;
        rc = sxpd_uncontribute_binding(ctx, V4, b, &tmp, &binding_was_selected);
        RC_CHECK(rc, out);
        sxpd_destroy_binding(b);
        if (binding_was_selected) {
            rc = sxpd_export_bindings(ctx);
        }
    } else {
        LOG_ERROR("Binding " DEBUG_V4_FMT "/%" PRIu8 " not found",
                  DEBUG_V4_PRINT(tmp.ip.v4), tmp.len);
    }
out:
    return rc;
}

/**
 * @brief add ipv6 binding to sxpd local bindings database
 *
 * @param ctx sxpd context to operate on
 * @param prefix network prefix bits
 * @param length length of network prefix (in bits)
 * @param tag associate source group tag
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_add_binding_v6(struct sxpd_ctx *ctx, const uint32_t prefix[4],
                               uint8_t length, uint16_t tag)
{
    int rc = 0;
    struct radix_node *node = NULL;
    struct sxpd_binding *b = NULL;
    PARAM_NULL_CHECK(rc, ctx);
    RC_CHECK(rc, out);
    struct timestamp *stamp = get_timestamp();
    if (!stamp) {
        LOG_ERROR("Cannot get timestamp");
        rc = -1;
        goto out;
    }
    struct v4_v6_prefix tmp = {.len = length,
                               .ip = {.v6[0] = prefix[0],
                                      .v6[1] = prefix[1],
                                      .v6[2] = prefix[2],
                                      .v6[3] = prefix[3] } };
    rc = radix_search(ctx->bindings_v6, tmp.ip.data, tmp.len, &node);
    RC_CHECK(rc, out);
    if (node) {
        LOG_TRACE("Binding already stored - re-use radix node");
        void *value = NULL;
        RC_CHECK(rc = radix_parse_node(node, NULL, 0, NULL, &value), out);
        b = value;
        destroy_timestamp(b->timestamp);
        b->timestamp = stamp;
        LOG_DEBUG("Fetched binding %p", (void *)b);
    } else {
        b = mem_calloc(1, sizeof(*b));
        if (!b) {
            LOG_ERROR("Cannot allocate sxpd binding");
            rc = -1;
            goto out;
        }
        b->timestamp = stamp;
        rc = radix_store(ctx->bindings_v6, tmp.ip.data, tmp.len, b, &node);
        if (RC_ISNOTOK(rc)) {
            sxpd_destroy_binding(b);
            goto out;
        }
        LOG_DEBUG("Create binding %p", (void *)b);
    }
    b->tag = tag;
    LOG_DEBUG("Stored new binding %p " DEBUG_V6_FMT "/%" PRIu8 " = %" PRIu16,
              (void *)b, DEBUG_V6_PRINT(tmp.ip.v6), tmp.len, tag);
    rc = sxpd_contribute_binding(ctx, V6, b, &tmp);
    RC_CHECK(rc, out);
    rc = sxpd_export_bindings(ctx);
out:
    return rc;
}

/**
 * @brief remove ipv6 binding from sxpd local bindings database
 *
 * @param ctx sxpd context to operate on
 * @param prefix network prefix bits
 * @param length length of network prefix (in bits)
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_del_binding_v6(struct sxpd_ctx *ctx, const uint32_t prefix[4],
                               uint8_t length)
{
    int rc = 0;
    struct radix_node *node = NULL;
    struct sxpd_binding *b = NULL;
    PARAM_NULL_CHECK(rc, ctx);
    RC_CHECK(rc, out);
    const struct v4_v6_prefix tmp = {.len = length,
                                     .ip = {.v6[0] = prefix[0],
                                            .v6[1] = prefix[1],
                                            .v6[2] = prefix[2],
                                            .v6[3] = prefix[3] } };
    rc = radix_search(ctx->bindings_v6, tmp.ip.data, tmp.len, &node);
    RC_CHECK(rc, out);
    if (node) {
        void *value = NULL;
        RC_CHECK(rc = radix_parse_node(node, NULL, 0, NULL, &value), out);
        RC_CHECK(rc = radix_delete_node(ctx->bindings_v6, node), out);
        b = value;
        LOG_DEBUG("Fetched binding %p", (void *)b);
        bool binding_was_selected = false;
        rc = sxpd_uncontribute_binding(ctx, V6, b, &tmp, &binding_was_selected);
        RC_CHECK(rc, out);
        sxpd_destroy_binding(b);
        if (binding_was_selected) {
            rc = sxpd_export_bindings(ctx);
        }
    } else {
        LOG_ERROR("Binding " DEBUG_V6_FMT "/%" PRIu8 " not found",
                  DEBUG_V6_PRINT(tmp.ip.v6), tmp.len);
    }
out:
    return rc;
}

/**
 * @startuml
 * participant "config manager" as config
 * participant "sxp daemon" as sxpd
 * participant "local bindings database" as local_db
 * participant "master bindings database" as master_db
 * config->sxpd: sxpd_cfg_add_binding
 * sxpd->local_db: lookup binding
 * alt
 *   local_db-->sxpd: binding found
 *   sxpd->local_db: update binding (tag, timestamp)
 * else
 *   local_db-->sxpd: binding not found
 *   sxpd->local_db: store new binding with tag & timestamp
 * end
 * sxpd->master_db: contribute binding (sxpd_contribute_binding)
 * sxpd->master_db: export bindings (sxpd_export_bindings)
 * sxpd-->config: return code
 * @enduml
 */
int sxpd_cfg_add_binding(struct sxpd_ctx *ctx, const struct binding *binding)
{
    int rc = 0;
    struct sxpd_ctx *sxpd_ctx = ctx;

    PARAM_NULL_CHECK(rc, ctx, binding);
    RC_CHECK(rc, out);

    if (binding->type == PREFIX_IPV4) {
        LOG_TRACE("Configuration adds binding " DEBUG_V4_FMT "/%" PRIu8,
                  DEBUG_V4_PRINT(binding->prefix.prefix_v4),
                  binding->prefix_length);
        rc = sxpd_add_binding_v4(sxpd_ctx, binding->prefix.prefix_v4,
                                 binding->prefix_length,
                                 binding->source_group_tag);
    } else {
        LOG_TRACE("Configurations adds binding " DEBUG_V6_FMT "/%" PRIu8,
                  DEBUG_V6_PRINT(binding->prefix.prefix_v6),
                  binding->prefix_length);
        rc = sxpd_add_binding_v6(sxpd_ctx, binding->prefix.prefix_v6,
                                 binding->prefix_length,
                                 binding->source_group_tag);
    }
out:
    return rc;
}

/**
 * @startuml
 * participant "config manager" as config
 * participant "sxp daemon" as sxpd
 * participant "local bindings database" as local_db
 * participant "master bindings database" as master_db
 * config->sxpd: sxpd_cfg_del_binding
 * sxpd->local_db: lookup binding
 * alt
 *   local_db-->sxpd: binding found
 *   sxpd->local_db: delete binding
 *   sxpd->master_db: uncontribute binding (sxpd_uncontribute_binding)
 *   sxpd->master_db: export bindings (sxpd_export_bindings)
 *   sxpd-->config: return code
 * else
 *   local_db-->sxpd: binding not found
 *   sxpd-->config: failure response
 * end
 * @enduml
 */
int sxpd_cfg_del_binding(struct sxpd_ctx *ctx, const struct binding *binding)
{
    int rc = 0;
    struct sxpd_ctx *sxpd_ctx = ctx;

    PARAM_NULL_CHECK(rc, ctx, binding);
    RC_CHECK(rc, out);

    if (binding->type == PREFIX_IPV4) {
        LOG_TRACE("Configuration deletes binding " DEBUG_V4_FMT "/%" PRIu8,
                  DEBUG_V4_PRINT(binding->prefix.prefix_v4),
                  binding->prefix_length);
        rc = sxpd_del_binding_v4(sxpd_ctx, binding->prefix.prefix_v4,
                                 binding->prefix_length);
    } else {
        LOG_TRACE("Configurations deletes binding " DEBUG_V6_FMT "/%" PRIu8,
                  DEBUG_V6_PRINT(binding->prefix.prefix_v6),
                  binding->prefix_length);
        rc = sxpd_del_binding_v6(sxpd_ctx, binding->prefix.prefix_v6,
                                 binding->prefix_length);
    }
out:
    return rc;
}

/**
 * @brief find peer by ip address
 *
 * @param ctx sxpd context to search for the peer structure
 * @param sin remote address of the peer
 *
 * @return sxpd peer structure pointer or NULL if no such peer
 */
static struct sxpd_peer *sxpd_find_peer(struct sxpd_ctx *ctx,
                                        struct sockaddr_in *sin)
{
    int rc = 0;
    struct sxpd_peer *result = NULL;

    PARAM_NULL_CHECK(rc, ctx);
    if (RC_ISOK(rc)) {
        size_t i = 0;
        for (i = 0; i < ctx->peer_count; ++i) {
            struct sxpd_peer *peer = ctx->peers[i];
            if (sin->sin_family == peer->pwd_pair.sin.sin_family &&
                sin->sin_addr.s_addr == peer->pwd_pair.sin.sin_addr.s_addr) {
                result = peer;
                PLOG_TRACE_MSG(peer, "Match");
            }
        }
    }

    return result;
}

/**
 * @brief start connectiong to all registered peers
 *
 * @param ctx sxpd context to operate on
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_connect_all_peers(struct sxpd_ctx *ctx)
{
    int rc = 0;
    size_t i = 0;
    struct sxpd_peer *peer = NULL;

    PARAM_NULL_CHECK(rc, ctx);

    if (RC_ISOK(rc)) {
        for (i = 0; i < ctx->peer_count; ++i) {
            peer = ctx->peers[i];

            rc = evmgr_listener_md5_sig_add(ctx->listener,
                                            ctx->default_connection_password,
                                            &peer->pwd_pair);
            if (RC_ISOK(rc)) {
                PLOG_TRACE_MSG(peer,
                               "Peer md5sig password was added to listener");
            } else {
                PLOG_ERROR_MSG(peer,
                               "Failed to add md5sig password to listener");
                break;
            }

            PLOG_TRACE_MSG(peer, "Connecting peer");
            rc = sxpd_connect_peer(peer);
            if (RC_ISNOTOK(rc)) {
                PLOG_ERROR_MSG(peer, "Failed to connect peer");
                break;
            }
        }
    }

    return rc;
}

/**
 * @brief check if connection made by peer should be kept or closed
 *
 * @param peer peer who made the connection
 * @param socket incoming connection socket
 * @param[out] acceptable flag set to true if connection should be kept, false
 *otherwise
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_peer_connection_acceptable(struct sxpd_peer *peer,
                                           struct evmgr_socket *socket,
                                           bool *acceptable)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, peer, socket, acceptable);
    RC_CHECK(rc, out);
    if (sxpd_peer_connections_active(peer) + 1 >
            sxpd_peer_connections_needed(peer) &&
        /* accepting this connection would give us too many, so let's
         * check whose connection should be kept - outgoing or incoming */
        ntohl(peer->pwd_pair.sin.sin_addr.s_addr) <
            ntohl(peer->sxpd_ctx->src_address.sin_addr.s_addr)) {
        /* peer has lower address than we, reject the connection */
        PLOG_ERROR_FMT(peer, "Reject incoming socket %p, already have "
                             "enough connections",
                       (void *)socket);
        *acceptable = false;
    } else if (peer->incoming) {
        PLOG_ERROR_FMT(peer, "Reject incoming socket %p, already have "
                             "incoming %p",
                       (void *)socket, (void *)peer->incoming);
        *acceptable = false;
    } else {
        PLOG_TRACE_FMT(peer, "Accept incoming socket %p", (void *)socket);
        *acceptable = true;
    }

out:
    return rc;
}

/**
 * @brief callback called when connections is accepted
 *
 * @startuml
 * participant "event manager" as evmgr
 * participant "sxp daemon" as sxpd
 * participant "peer" as peer
 * database "peer database" as peerdb
 * evmgr->sxpd: connection accepted (sxpd_evmgr_global_accept_callback)
 * sxpd->peerdb: lookup peer based on address(sxpd_find_peer)
 * alt peer not found
 *  sxpd->evmgr: close incoming(accepted) connection (evmgr_socket_destroy)
 * else peer found
 *  sxpd->peer: check if more connections required\
 *  (sxpd_peer_connection_acceptable)
 *  alt connection not acceptable
 *   sxpd->evmgr: close incoming (accepted) connection (evmgr_socket_destroy)
 *  else connection acceptable
 *   sxpd->peer: close extra connection if only one required but two established
 *   peer->evmgr: close connection (evmgr_socket_destroy)
 *   alt need to disconnect outgoing connection
 *    sxpd->peer: disconnect outgoing connection (sxpd_disconnect_peer_socket)
 *    peer->evmgr: close outgoing connection (evmgr_socket_destroy)
 *   end
 *   sxpd->evmgr: register read/event callbacks on peers socket\
 *   (evmgr_socket_cb_register)
 *  end
 * end
 * @enduml
 *
 * @param listener listener which accepted the connection
 * @param socket accepted connection
 * @param address peer's address
 * @param ctx context passed when creating listener
 */
static void sxpd_evmgr_global_accept_callback(struct evmgr_listener *listener,
                                              struct evmgr_socket *socket,
                                              struct sockaddr_in *address,
                                              void *ctx)
{
    int rc = 0;
    struct sxpd_peer *peer = NULL;

    PARAM_NULL_CHECK(rc, listener, socket, address, ctx);
    RC_CHECK(rc, out);
    LOG_TRACE("New connection from address " DEBUG_SIN_FMT,
              DEBUG_SIN_PRINT(*address));
    struct sxpd_ctx *sxpd = ctx;
    peer = sxpd_find_peer(sxpd, address);
    if (!peer) {
        LOG_ERROR("Unknown peer");
        rc = -1;
        goto out;
    }

    bool acceptable = false;
    rc = sxpd_peer_connection_acceptable(peer, socket, &acceptable);
    RC_CHECK(rc, out);
    if (!acceptable) {
        evmgr_socket_destroy(socket);
        socket = NULL;
        goto out;
    }
    /* the connection is accepted - check if there are too many
     * connections now */
    peer->incoming = socket;
    if (sxpd_peer_connections_needed(peer) <
        sxpd_peer_connections_active(peer)) {
        /* we need less than we have - disconnect outgoing connection */
        PLOG_TRACE_MSG(peer, "Extra connection established and peers address "
                             "is higher, disconnect outgoing connection");
        PEER_CHANGE_OUT_CONN_STATE(peer, NONE);
        rc = sxpd_disconnect_peer_socket(peer, peer->outgoing, false);
        RC_CHECK(rc, out);
    }

    rc = evmgr_socket_cb_register(socket, sxpd_peer_read_callback, NULL,
                                  sxpd_peer_event_callback, peer);

out:
    if (RC_ISNOTOK(rc)) {
        evmgr_socket_destroy(socket);
    }
}

/**
 * @brief callback called when an error occurs during accepting a connection
 *
 * this function only logs an error message
 */
static void sxpd_evmgr_global_error_callback(
    __attribute__((unused)) struct evmgr_listener *listener,
    __attribute__((unused)) void *ctx)
{
    int rc = 0;

    if (RC_ISOK(rc)) {
        LOG_ERROR("Error accepting connection");
    }
}

/**
 * @brief setup sxpd listening socket
 *
 * @param ctx sxpd context to operate on
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_setup_listener(struct sxpd_ctx *ctx)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, ctx);
    RC_CHECK(rc, out);
    if (ctx->listener) {
        evmgr_listener_destroy(ctx->listener);
        ctx->listener = NULL;
    }
    struct sockaddr_in in;
    memset(&in, 0, sizeof(in));
    in.sin_family = AF_INET;
    in.sin_port = ctx->nbo_port;
    in.sin_addr.s_addr = ctx->nbo_bind_ip;
    ctx->listener = evmgr_listener_create(
        ctx->evmgr, ctx->evmgr_settings, &in, sxpd_evmgr_global_accept_callback,
        sxpd_evmgr_global_error_callback, ctx);
    if (!ctx->listener) {
        LOG_ERROR("Cannot create connection listener");
        rc = -1;
    }
out:

    return rc;
}

/**
 * @brief wrapper function which takes void * and destroys a binding
 */
static void sxpd_destroy_binding_wrapper(void *v)
{
    sxpd_destroy_binding(v);
}

/**
 * @brief wrapper function which takes void * and destroys a binding list
 */
static void sxpd_destroy_binding_list_wrapper(void *v)
{
    sxpd_destroy_binding_list(v);
}

/**
 * @brief wrapper function which takes void * and destroys an expansion track
 * entry
 */
static void sxpd_destroy_expansion_track_entry_wrapper(void *v)
{
    sxpd_destroy_expansion_track_entry(v);
}

/**
 * @brief destroy sxpd context and free memory
 *
 * @param ctx sxpd context to destroy
 */
void sxpd_destroy(struct sxpd_ctx *ctx)
{
    if (ctx) {
        sxpd_destroy_peer_sequence(ctx->v1_peer_sequence);
        evmgr_listener_destroy(ctx->listener);
        while (ctx->peer_count && ctx->peers) {
            sxpd_free_peer(ctx, ctx->peers[0]);
        }
        radix_destroy(ctx->bindings_v4, sxpd_destroy_binding_wrapper);
        radix_destroy(ctx->bindings_v6, sxpd_destroy_binding_wrapper);
        radix_destroy(ctx->master_bindings_v4,
                      sxpd_destroy_binding_list_wrapper);
        radix_destroy(ctx->master_bindings_v6,
                      sxpd_destroy_binding_list_wrapper);
        radix_destroy(ctx->expand_bindings_v4, NULL);
        radix_destroy(ctx->expand_entries_v4,
                      sxpd_destroy_expansion_track_entry_wrapper);
        mem_free(ctx->peers);
        mem_free(ctx->listeners);
        mem_free(ctx->expanding_listeners);
        struct sxpd_buffer_wrapper *next = ctx->buffer_pool;
        while (next) {
            struct sxpd_buffer_wrapper *tmp = next;
            next = next->next;
            mem_free(tmp);
        }
        mem_free(ctx);
    }
}

/**
 * @brief setup default values in sxpd context
 *
 * @param ctx sxpd context to initialize
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_setup_defaults(struct sxpd_ctx *ctx)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, ctx);
    if (RC_ISOK(rc)) {
        ctx->listener_min_hold_time =
            UINT32_SETTING_LISTENER_MIN_HOLD_TIME_DEFAULT;
        ctx->listener_max_hold_time =
            UINT32_SETTING_LISTENER_MAX_HOLD_TIME_DEFAULT;
        ctx->speaker_min_hold_time =
            UINT32_SETTING_SPEAKER_MIN_HOLD_TIME_DEFAULT;
        ctx->retry_timeout.tv_sec = UINT32_SETTING_RETRY_TIMER_DEFAULT;
        ctx->reconciliation_timeout.tv_sec =
            UINT32_SETTING_RECONCILIATION_TIMER_DEFAULT;
        ctx->keepalive_timeout.tv_sec = UINT32_SETTING_KEEPALIVE_TIMER_DEFAULT;
        ctx->sub_expand_limit = UINT32_SETTING_SUBNET_EXPANSION_LIMIT_DEFAULT;
        ctx->default_connection_password[0] = '\0';
        ctx->nbo_port = ntohs(UINT32_SETTING_PORT_DEFAULT);
        ctx->md5sig = false;
        ctx->md5sig_peers = 0;
        ctx->enabled = UINT32_SETTING_ENABLED_DEFAULT;
        ctx->nbo_bind_ip = INADDR_ANY;
    }
    return rc;
}

int sxpd_get_info(struct sxpd_ctx *ctx, struct sxpd_info *info)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, ctx, info);
    RC_CHECK(rc, out);
    info->default_connection_password = ctx->default_connection_password;
    info->nbo_bind_ip = ctx->nbo_bind_ip;
    info->nbo_port = ctx->nbo_port;
    info->peer_count = ctx->peer_count;
    info->expanded_entry_count = ctx->expanded_entry_count;
    info->enabled = ctx->enabled;
out:
    return rc;
}

struct sxpd_peer_iterator {
    /** index of last peer returned */
    size_t index;
};

int sxpd_iterate_peers(struct sxpd_ctx *ctx,
                       struct sxpd_peer_iterator **context,
                       struct sxpd_peer_info *peer)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, ctx, context, peer);
    RC_CHECK(rc, out);
    if (!*context) {
        *context = mem_calloc(1, sizeof(struct sxpd_peer_iterator));
        if (!*context) {
            LOG_ERROR("Cannot allocate sxpd peer iterator");
            rc = -1;
            goto out;
        }
    }
    size_t index = (*context)->index;
    if (index < ctx->peer_count) {
        struct sxpd_peer *p = ctx->peers[index];
        peer->nbo_ip = p->pwd_pair.sin.sin_addr.s_addr;
        peer->nbo_port = p->pwd_pair.sin.sin_port;
        peer->keepalive_timer_active = p->keepalive_timer ? true : false;
        peer->retry_timer_active = p->retry_timer ? true : false;
        peer->reconciliation_timer_active =
            p->reconciliation_timer ? true : false;
        peer->delete_hold_down_timer_active =
            p->delete_hold_down_timer ? true : false;
        peer->hold_timer_active = p->hold_timer ? true : false;
        peer->connections_count = sxpd_peer_connections_connected(p);
        peer->is_speaker = p->type != PEER_LISTENER;
        peer->is_listener = p->type != PEER_SPEAKER;
        peer->outgoing_connection_state = p->outgoing_state;
        ++(*context)->index;
    } else {
        /* no more peers */
        mem_free(*context);
        *context = NULL;
    }
out:
    return rc;
}

void sxpd_iterate_peers_finish(__attribute__((unused)) struct sxpd_ctx *ctx,
                               struct sxpd_peer_iterator *iterator)
{
    mem_free(iterator);
}

struct sxpd_bindings_iterator {
    /** tree being iterated */
    struct radix_tree *tree;
    /** the current radix node */
    struct radix_node *node;
    /** binding list associated to the radix node */
    struct sxpd_binding_list *bl;
    /** next bindings iterator which is set to the same radix_node */
    struct sxpd_bindings_iterator *next;
};

/**
 * @brief remove iterator from list of iterators belonging to binding list to
 *which this iterator currently points
 *
 * @param i iterator
 */
static int
sxpd_remove_iterator_from_binding_list(struct sxpd_bindings_iterator *i)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, i);
    RC_CHECK(rc, out);

    if (i->bl) {
        if (i->bl->iterator == i) {
            i->bl->iterator = i->next;
            i->bl = NULL;
        } else {
            struct sxpd_bindings_iterator *tmp = i->bl->iterator;
            while (tmp && tmp->next != i) {
                tmp = tmp->next;
            }
            if (tmp && tmp->next == i) {
                tmp->next = i->next;
                i->bl = NULL;
            }
        }
    }
out:
    return rc;
}

/**
 * @brief destroy iterator and free memory
 *
 * @param ctx unused parameter
 * @param i iterator to destroy
 */
void sxpd_iterate_bindings_finish(__attribute__((unused)) struct sxpd_ctx *ctx,
                                  struct sxpd_bindings_iterator *i)
{
    if (!i) {
        return;
    }
    (void)sxpd_remove_iterator_from_binding_list(i);
    mem_free(i);
}

/**
 * @brief move bindings iterator to next binding
 *
 * @param i iterator to move
 *
 * @return 0 if success, -1 if error
 */
static int sxpd_iterate_bindings_internal(struct sxpd_bindings_iterator *i)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, i);
    RC_CHECK(rc, out);
    LOG_DEBUG(
        "Move iterator %p pointing node %p with binding list %p to next node",
        (void *)i, (void *)i->node, (void *)i->bl);
    RC_CHECK(rc = sxpd_remove_iterator_from_binding_list(i), out);
    for (;;) {
        RC_CHECK(rc = radix_iterate(i->tree, i->node, &(i->node)), out);
        if (!i->node) {
            LOG_DEBUG("No more nodes while moving iterator %p", (void *)i);
            break;
        }
        void *value = NULL;
        RC_CHECK(rc = radix_parse_node(i->node, NULL, 0, NULL, &value), out);
        i->bl = value;
        if (!i->bl->count) {
            LOG_DEBUG("Skip empty binding list %p", (void *)i->bl);
            /* skip bindings lists which are being deleted */
            i->bl = NULL;
            continue;
        }
        LOG_DEBUG("Iterator %p set to node %p with binding list %p", (void *)i,
                  (void *)i->node, (void *)i->bl);
        i->next = i->bl->iterator;
        i->bl->iterator = i;
        break;
    };
out:
    return rc;
}

int sxpd_iterate_bindings(struct sxpd_ctx *ctx, enum ip_type type,
                          struct sxpd_bindings_iterator **context,
                          uint8_t *buffer, size_t buffer_size, uint8_t *length,
                          uint16_t *tag)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, ctx, context, buffer, length, tag);
    RC_CHECK(rc, out);
    if (*context && !(*context)->node) {
        /* all nodes remaining from last iterate have been deleted meanwhile */
        sxpd_iterate_bindings_finish(ctx, *context);
        *context = NULL;
        goto out;
    }
    if (!*context) {
        *context = mem_calloc(1, sizeof(**context));
        if (!*context) {
            LOG_ERROR("Cannot allocate sxpd bindings iterator");
            rc = -1;
            goto out;
        } else {
            LOG_TRACE("Allocate iterator %p", (void *)*context);
            (*context)->tree = (V4 == type ? ctx->master_bindings_v4
                                           : ctx->master_bindings_v6);
            RC_CHECK(rc = sxpd_iterate_bindings_internal(*context), out);
        }
    }
    if ((*context)->node) {
        void *value = NULL;
        rc = radix_parse_node((*context)->node, buffer, buffer_size, length,
                              &value);
        RC_CHECK(rc, out);
        struct sxpd_binding_list *bl = value;
        if (bl->count) {
            *tag = bl->bindings[0]->tag;
        } else {
            LOG_ERROR("Internal error, unexpected zero binding list count");
            rc = -1;
            goto out;
        }
        RC_CHECK(rc = sxpd_iterate_bindings_internal(*context), out);
    } else {
        /* no more nodes */
        sxpd_iterate_bindings_finish(ctx, *context);
        *context = NULL;
    }
out:
    return rc;
}

struct sxpd_ctx *sxpd_create(struct evmgr *evmgr,
                             struct evmgr_settings *evmgr_settings,
                             enum log_level default_log_level)
{
    int rc = 0;
    struct sxpd_ctx *ctx = NULL;
    RC_CHECK(rc, out);
    ctx = mem_calloc(1, sizeof(struct sxpd_ctx));
    if (!ctx) {
        LOG_ERROR("Cannot allocate sxpd context");
        rc = -1;
        goto out;
    }
#ifdef TESTING
    ctx->version = 4;
#endif
    ctx->evmgr = evmgr;
    ctx->evmgr_settings = evmgr_settings;
    ctx->default_log_level = default_log_level;
    ctx->bindings_v4 = radix_create(RADIX_V4_MAXBITS);
    if (!ctx->bindings_v4) {
        LOG_ERROR("Cannot allocate v4 bindings radix tree");
        rc = -1;
        goto out;
    }
    ctx->master_bindings_v4 = radix_create(RADIX_V4_MAXBITS);
    if (!ctx->master_bindings_v4) {
        LOG_ERROR("Cannot allocate master v4 bindings radix tree");
        rc = -1;
        goto out;
    }
    ctx->bindings_v6 = radix_create(RADIX_V6_MAXBITS);
    if (!ctx->bindings_v6) {
        LOG_ERROR("Cannot allocate v6 bindings radix tree");
        rc = -1;
        goto out;
    }
    ctx->master_bindings_v6 = radix_create(RADIX_V6_MAXBITS);
    if (!ctx->master_bindings_v6) {
        LOG_ERROR("Cannot allocate master v6 bindings radix tree");
        rc = -1;
        goto out;
    }
    ctx->expand_bindings_v4 = radix_create(RADIX_V4_MAXBITS);
    if (!ctx->expand_bindings_v4) {
        LOG_ERROR("Cannot allocate radix tree for expanded bindings");
        rc = -1;
        goto out;
    }
    ctx->expand_entries_v4 = radix_create(RADIX_V4_MAXBITS);
    if (!ctx->expand_entries_v4) {
        LOG_ERROR("Cannot allocate radix tree for expanded entries");
        rc = -1;
        goto out;
    }
    ctx->v1_peer_sequence = sxpd_alloc_peer_sequence();
    if (!ctx->v1_peer_sequence) {
        LOG_ERROR("Cannot allocate v1 peer sequence");
        rc = -1;
        goto out;
    }
    ctx->v1_peer_sequence->node_ids =
        mem_calloc(1, sizeof(*ctx->v1_peer_sequence->node_ids));
    if (!ctx->v1_peer_sequence->node_ids) {
        LOG_ERROR("Cannot allocate v1 peer sequence node ids");
        rc = -1;
        goto out;
    }
    ctx->v1_peer_sequence->node_ids[0] = 0;
    ctx->v1_peer_sequence->node_ids_count = 1;
    rc = sxpd_setup_defaults(ctx);
    RC_CHECK(rc, out);

out:
    if (RC_ISNOTOK(rc)) {
        sxpd_destroy(ctx);
        ctx = NULL;
    }
    return ctx;
}

/**
 * @brief register configuration manager callbacks with sxpd
 *
 * @param ctx sxpd context
 * @param cfg_ctx configuration manager context
 *
 * @return 0 if success, -1 if error
 */
int sxpd_register_config(struct sxpd_ctx *ctx, struct cfg_ctx *cfg_ctx)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, ctx, cfg_ctx);
    RC_CHECK(rc, out);

    /* test if md5 signing feature is available */
    if (RC_ISOK(rc)) {
        rc = evmgr_md5sig_test();
        if (RC_ISOK(rc)) {
            ctx->md5sig = true;
            LOG_TRACE("TCP md5 signature feature test success");
        } else {
            ctx->md5sig = false;
            LOG_ERROR("TCP md5 signature feature test failed: %d", rc);
            LOG_ERROR(
                "TCP md5 signature feature is not enabled on this system. SXPD "
                "will not be able to communicate with TCP md5sig enabled "
                "peers. Please reconfigure system to support this feature.");
            rc = 0;
        }
    }

    if (RC_ISOK(rc)) {
        rc = cfg_register_callbacks(
            cfg_ctx, ctx->evmgr, ctx, sxpd_cfg_add_uint32_setting,
            sxpd_cfg_del_uint32_setting, sxpd_cfg_add_str_setting,
            sxpd_cfg_del_str_setting, sxpd_cfg_add_peer, sxpd_cfg_del_peer,
            sxpd_cfg_add_binding, sxpd_cfg_del_binding);
    }

    if (RC_ISOK(rc) && !ctx->enabled) {
        LOG_DEBUG("Note: daemon is NOT enabled (set 'enabled' option in global "
                  "settings to 'true' to enable daemon)");
    }
out:
    return rc;
}

int sxpd_search_best(struct sxpd_ctx *ctx, enum ip_type type, uint8_t *prefix,
                     uint8_t length, uint16_t *tag, bool *found)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, ctx, prefix, tag, found);
    RC_CHECK(rc, out);
    struct v4_v6_prefix tmp;
    memset(&tmp, 0, sizeof(tmp));
    memcpy(tmp.ip.data, prefix, length / 8 + (length % 8 > 0));

    struct radix_tree *tree = NULL;
    if (V4 == type) {
        LOG_TRACE("Search for V4 prefix " DEBUG_V4_FMT "/%" PRIu8,
                  DEBUG_V4_PRINT(tmp.ip.v4), length);
        tree = ctx->master_bindings_v4;
    } else {
        LOG_TRACE("Search for V6 prefix " DEBUG_V6_FMT "/%" PRIu8,
                  DEBUG_V6_PRINT(tmp.ip.v6), length);
        tree = ctx->master_bindings_v6;
    }

    struct radix_node *node = NULL;
    rc = radix_search_best(tree, prefix, length, &node);
    RC_CHECK(rc, out);
    while (node) {
        void *value = NULL;
        uint8_t __length = 0;
        rc = radix_parse_node(node, NULL, 0, &__length, &value);
        RC_CHECK(rc, out);
        struct sxpd_binding_list *bl = value;
        if (bl->count) {
            *tag = bl->bindings[0]->tag;
            *found = true;
            LOG_TRACE("Found prefix with length %" PRIu8 " and tag %" PRIu16,
                      __length, *tag);
            goto out;
        }
        LOG_TRACE(
            "Skip binding list %p, which is being deleted, try shorter prefix",
            value);
        rc = radix_get_parent_node(node, &node);
        RC_CHECK(rc, out);
    }
    if (!node) {
        LOG_TRACE("Prefix not found");
        *found = false;
        goto out;
    }
out:
    return rc;
}

/** @} */
