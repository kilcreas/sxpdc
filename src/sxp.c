#include <inttypes.h>
#include <stddef.h>
#include <setjmp.h>
#include "sxp.h"

DECL_DEBUG_V6_STATIC_BUFFER

/* return (void*) pointer to address + n bytes */
#define OFFSET_PTR(ptr, offset) ((void *)(((char *)(ptr)) + (offset)))

#define BIT_CLEAR(bits, pos) ((bits) &= ~((uint8_t)1 << (uint8_t)(pos)))
#define BIT_SET(bits, pos) ((bits) |= ((uint8_t)1 << (uint8_t)(pos)))
#define BIT_IS_SET(bits, pos) (((bits) & ((uint8_t)1 << (pos))) != 0)

/* size of the sxp message header */
#define SXP_MSG_SIZE (sizeof(uint32_t) + sizeof(uint32_t))
#define SXP_ATTR_FLAGS_PLUS_TYPE_SIZE (2 * sizeof(uint8_t))
/* size of compact, non-extended attribute head (1B each flags, type, length)*/
#define SXP_CNE_ATTR_HEAD_SIZE (SXP_ATTR_FLAGS_PLUS_TYPE_SIZE + sizeof(uint8_t))
/* size of compact, extended attribute head (1B flags, 1B type, 2B length)*/
#define SXP_CE_ATTR_HEAD_SIZE (SXP_ATTR_FLAGS_PLUS_TYPE_SIZE + sizeof(uint16_t))
/* size of non-compact attribute head (1B flags, 3B type, 4B length) */
#define SXP_NC_ATTR_HEAD_SIZE (2 * sizeof(uint32_t))

/* size of open msg header (msg + version + sxp mode) */
#define SXP_OPEN_HEAD_SIZE (SXP_MSG_SIZE + 2 * sizeof(uint32_t))
/* size of capability attribute */
#define SXP_ATTR_CAPABILITY_SIZE (2)

#define SXP_OPEN_SET_VERSION(addr, version) ((uint32_t *)(addr))[0] = (version)
#define SXP_OPEN_GET_VERSION(addr) (((uint32_t *)(addr))[0])
#define SXP_OPEN_SET_MODE(addr, mode) ((uint32_t *)(addr))[1] = (mode)
#define SXP_OPEN_GET_MODE(addr) (((uint32_t *)(addr))[1])

/* error is 1 bit extended flag + 7 bits code + 8 bits sub-code + 16bits
 * non-extended error-code*/
#define SXP_ERROR_EXTENDED_BIT (7)
#define SXP_ERROR_SET_EXTENDED(err, value)                         \
    (value) ? BIT_SET((*(uint8_t *)(err)), SXP_ERROR_EXTENDED_BIT) \
            : BIT_CLEAR((*(uint8_t *)(err)), SXP_ERROR_EXTENDED_BIT)

#define SXP_ERROR_GET_EXTENDED(err) \
    BIT_IS_SET((*(uint8_t *)(err)), SXP_ERROR_EXTENDED_BIT)
#define SXP_ERROR_SET_CODE(err, code)      \
    ((((uint8_t *)(err))[0]) = ((uint8_t)( \
         code | SXP_ERROR_GET_EXTENDED(err) << SXP_ERROR_EXTENDED_BIT)))

#define SXP_ERROR_GET_CODE(err) \
    ((((uint8_t *)(err))[0]) & ~(1 << SXP_ERROR_EXTENDED_BIT))
#define SXP_ERROR_SET_SUBCODE(err, code) ((uint8_t *)(err))[1] = (code)
#define SXP_ERROR_GET_SUBCODE(err) ((uint8_t *)(err))[1]
#define SXP_ERROR_GET_NON_EXTENDED_ERROR_CODE(err) ((uint32_t *)(err))[0]

#define SXP_ATTR_OPTIONAL_FLAG (7)
#define SXP_ATTR_NON_TRANSITIVE_FLAG (6)
#define SXP_ATTR_PARTIAL_FLAG (5)
#define SXP_ATTR_COMPACT_FLAG (4)
#define SXP_ATTR_EXTENDED_FLAG (3)

#define SXP_ATTR_SET_FLAGS(attr, flags) ((uint8_t *)(attr))[0] = (uint8_t)flags
#define SXP_ATTR_GET_FLAGS(attr) (((uint8_t *)(attr))[0])

#define SXP_CAPABILITY_SET_CODE(cap, code) ((uint8_t *)(cap))[0] = (code)
#define SXP_CAPABILITY_GET_CODE(cap) ((uint8_t *)(cap))[0]

#define SXP_CAPABILITY_SET_LENGTH(cap, length) ((uint8_t *)(cap))[1] = (length)
#define SXP_CAPABILITY_GET_LENGTH(cap) ((uint8_t *)(cap))[1]

#define SXP_CAPABILITY_GET_VALUE(cap) (void *)(((uint8_t *)(cap)) + 2)

#define SXP_V1_TLV_HEAD_SIZE (2 * sizeof(uint32_t))

#define SXP_IPV4_MAX_BITS (8 * sizeof(((struct v4_v6_prefix *)NULL)->ip.v4))
#define SXP_IPV6_MAX_BITS (8 * sizeof(((struct v4_v6_prefix *)NULL)->ip.v6))

static void sxp_qsort_r_internal(char *left, char *right, size_t size,
                                 int (*compare)(const void *, const void *,
                                                void *),
                                 void *pointer)
{
    char *p = left;
    char *q = right;
    char *t = left;
    char x = '\0';
    size_t i = 0;

    while (1) {
        while ((*compare)(p, t, pointer) < 0) {
            if (p + size <= right) {
                p += size;
            } else {
                break;
            }
        }
        while ((*compare)(q, t, pointer) > 0) {
            if (q - size >= left) {
                q -= size;
            } else {
                break;
            }
        }
        if (p > q) {
            break;
        }
        if (p < q) {
            for (i = 0; i < size; i++) {
                x = p[i];
                p[i] = q[i];
                q[i] = x;
            }
            if (t == p) {
                t = q;
            } else if (t == q) {
                t = p;
            }
        }
        if (p + size <= right) {
            p += size;
        }
        if (q - size >= left) {
            q -= size;
        }
    }
    if (left < q) {
        sxp_qsort_r_internal(left, q, size, compare, pointer);
    }
    if (p < right) {
        sxp_qsort_r_internal(p, right, size, compare, pointer);
    }
}

static void sxp_qsort_r(void *base, size_t count, size_t size,
                        int (*compare)(const void *, const void *, void *),
                        void *pointer)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, base);

    if (RC_ISOK(rc) && count > 1) {
        sxp_qsort_r_internal((char *)base, (char *)base + (count - 1) * size,
                             size, compare, pointer);
    }
}

static int sxp_parse_msg_internal(struct sxp_msg *msg, bool nbo_attribs,
                                  struct sxp_attribute *start,
                                  struct sxp_attribute **next,
                                  enum sxp_error_code *code,
                                  enum sxp_error_sub_code *subcode);

static int sxp_attr_is_compact(const struct sxp_attribute *attr)
{
    return BIT_IS_SET((((uint8_t *)(attr))[0]), SXP_ATTR_COMPACT_FLAG);
}
static int sxp_attr_is_extended(const struct sxp_attribute *attr)
{
    return BIT_IS_SET((((uint8_t *)(attr))[0]), SXP_ATTR_EXTENDED_FLAG);
}

static int sxp_attr_set_type(struct sxp_attribute *attr,
                             enum sxp_attr_type type)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, attr);
    RC_CHECK(rc, out);
    if ((int)type > UINT8_MAX) {
        LOG_ERROR("Type %s/%d is too large to store in uint8_t",
                  sxp_attr_type_string(type), type);
        rc = -1;
    } else if (sxp_attr_is_compact(attr)) {
        ((uint8_t *)attr)[1] = type;
    } else {
        ((uint8_t *)attr)[0] = type;
    }
out:
    return rc;
}

static int sxp_attr_set_length(struct sxp_attribute *attr, size_t length)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, attr);
    RC_CHECK(rc, out);
    if (sxp_attr_is_compact(attr)) {
        if (sxp_attr_is_extended(attr)) {
            if (length > UINT16_MAX) {
                LOG_ERROR("Length %zu cannot fit in uint16_t", length);
                rc = -1;
            } else {
                ((uint16_t *)attr)[1] = (uint16_t)(length);
            }
        } else {
            if (length > UINT8_MAX) {
                LOG_ERROR("Length %zu cannot fit in uint8_t", length);
                rc = -1;
            } else {
                ((uint8_t *)attr)[2] = (uint8_t)(length);
            }
        }
    } else {
        if (length > UINT32_MAX) {
            LOG_ERROR("Length %zu cannot fit in uint32_t", length);
            rc = -1;
        } else {
            ((uint32_t *)attr)[1] = (uint32_t)length;
        }
    }
out:
    return rc;
}

static uint32_t sxp_attr_get_length(bool nbo, const struct sxp_attribute *attr)
{
    if (sxp_attr_is_compact(attr)) {
        if (sxp_attr_is_extended(attr)) {
            if (nbo) {
                return ntohs(
                    *(uint16_t *)OFFSET_PTR(attr, 2 * sizeof(uint8_t)));
            } else {
                return *(uint16_t *)OFFSET_PTR(attr, 2 * sizeof(uint8_t));
            }
        } else {
            return *(uint8_t *)OFFSET_PTR(attr, 2 * sizeof(uint8_t));
        }
    } else if (nbo) {
        return ntohl(*(uint32_t *)OFFSET_PTR(attr, sizeof(uint32_t)));
    } else {
        return *(uint32_t *)OFFSET_PTR(attr, sizeof(uint32_t));
    }
}

static size_t sxp_attr_get_head_size(const struct sxp_attribute *attr)
{
    if (sxp_attr_is_compact(attr)) {
        if (sxp_attr_is_extended(attr)) {
            return SXP_CE_ATTR_HEAD_SIZE;
        } else {
            return SXP_CNE_ATTR_HEAD_SIZE;
        }
    } else {
        return SXP_NC_ATTR_HEAD_SIZE;
    }
}

/**
 * @brief return the size of this attribute in memory
 *
 * @param nbo specified that the attribute is in network byte order
 * @param attr attribute to account
 * @param total_size location of result
 *
 * @return 0 on success, -1 on error
 */
static int sxp_attr_get_total_size(bool nbo, struct sxp_attribute *attr,
                                   uint32_t *total_size)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, attr, total_size);
    RC_CHECK(rc, out);
    if (sxp_attr_is_compact(attr)) {
        if (sxp_attr_is_extended(attr)) {
            *total_size =
                SXP_CE_ATTR_HEAD_SIZE + sxp_attr_get_length(nbo, attr);
        } else {
            *total_size =
                SXP_CNE_ATTR_HEAD_SIZE + sxp_attr_get_length(nbo, attr);
        }
    } else {
        *total_size = SXP_NC_ATTR_HEAD_SIZE + sxp_attr_get_length(nbo, attr);
    }
out:
    return rc;
}

struct qsort_ctx {
    uint32_t dup_value;
    bool dup_found;
#ifdef SXP_USE_SETJMP
    jmp_buf jmp_buf;
#endif
};

/**
 * @brief return string describing sxp message type
 *
 * @param t message type
 *
 * @return string describing the sxp message type
 */
const char *sxp_msg_type_string(enum sxp_msg_type t)
{
    switch (t) {
    case SXP_MSG_OPEN:
        return "OPEN";

    case SXP_MSG_OPEN_RESP:
        return "OPEN_RESP";

    case SXP_MSG_UPDATE:
        return "UPDATE";

    case SXP_MSG_ERROR:
        return "ERROR";

    case SXP_MSG_PURGE_ALL:
        return "PURGE_ALL";

    case SXP_MSG_KEEPALIVE:
        return "KEEPALIVE";
    }

    return "UNKNOWN";
}

/**
 * @brief return string representation of capability code
 *
 * @param c capability code
 *
 * @return string representation
 */
const char *sxp_capability_code_string(enum sxp_capability_code c)
{
    switch (c) {
    case SXP_CAPABILITY_IPV4_UNICAST:
        return "IPV4-UNICAST";

    case SXP_CAPABILITY_IPV6_UNICAST:
        return "IPV6-UNICAST";

    case SXP_CAPABILITY_SUBNET_BINDINGS:
        return "SUBNET-BINDINGS";
    }

    return "UNKNOWN";
}

const char *sxp_attr_type_string(enum sxp_attr_type e)
{
    switch (e) {
    case SXP_ATTR_TYPE_ADD_IPV4:
        return "ADD-IPV4";
    case SXP_ATTR_TYPE_ADD_IPV6:
        return "ADD-IPV6";
    case SXP_ATTR_TYPE_DEL_IPV4:
        return "DEL-IPV4";
    case SXP_ATTR_TYPE_DEL_IPV6:
        return "DEL-IPV6";
    case SXP_ATTR_TYPE_NODE_ID:
        return "NODE-ID";
    case SXP_ATTR_TYPE_CAPABILITIES:
        return "CAPABILITIES";
    case SXP_ATTR_TYPE_HOLD_TIME:
        return "HOLD-TIME";
    case SXP_ATTR_TYPE_IPV4_ADD_PREFIX:
        return "IPV4-ADD-PREFIX";
    case SXP_ATTR_TYPE_IPV6_ADD_PREFIX:
        return "IPV6-ADD-PREFIX";
    case SXP_ATTR_TYPE_IPV4_DEL_PREFIX:
        return "IPV4-DEL-PREFIX";
    case SXP_ATTR_TYPE_IPV6_DEL_PREFIX:
        return "IPV6-DEL-PREFIX";
    case SXP_ATTR_TYPE_SGT:
        return "SOURCE-GROUP-TAG";
    case SXP_ATTR_TYPE_PEER_SEQUENCE:
        return "PEER-SEQUENCE";
    }
    return "UNKNOWN";
}

enum sxp_v1_tlv_type {
    SXP_V1_TLV_SGT = 1,
    SXP_V1_TLV_PREFIX_LENGTH = 2,
};

struct sxp_v1_tlv;

static const char *sxp_v1_tlv_type_string(enum sxp_v1_tlv_type t)
{
    switch (t) {
    case SXP_V1_TLV_SGT:
        return "SGT";
    case SXP_V1_TLV_PREFIX_LENGTH:
        return "PREFIX-LENGTH";
    }
    return "UNKNOWN";
}

/**
 * @brief create sxp error message in buffer of given size
 *
 * @param buffer buffer to hold the error message, must be large enough
 * @param buffer_size size of the buffer allocated
 * @param code error code
 * @param sub_code error sub-code
 * @param err_attr attribute causing the error - included in error message, may
 *be NULL
 *
 * @return 0 on success, -1 on error
 */
int sxp_create_error_extended(void *buffer, size_t buffer_size,
                              enum sxp_error_code code,
                              enum sxp_error_sub_code sub_code,
                              struct sxp_attribute *err_attr)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, buffer);
    RC_CHECK(rc, out);
    uint32_t req_size = SXP_MSG_SIZE + 2 * sizeof(uint8_t);
    uint32_t err_attr_total_size = 0;
    if (err_attr) {
        rc = sxp_attr_get_total_size(false, err_attr, &err_attr_total_size);
        RC_CHECK(rc, out);
        req_size += err_attr_total_size;
    }
    if (buffer_size < req_size) {
        LOG_ERROR("Buffer of size %zu too small for error of size %" PRIu32,
                  buffer_size, req_size);
        rc = -1;
        goto out;
    }
    struct sxp_msg *msg = buffer;
    msg->type = SXP_MSG_ERROR;
    uint32_t *err = OFFSET_PTR(buffer, SXP_MSG_SIZE);
    SXP_ERROR_SET_EXTENDED(err, 1);
    SXP_ERROR_SET_CODE(err, (uint8_t)code);
    SXP_ERROR_SET_SUBCODE(err, sub_code);
    if (err_attr) {
        memcpy(OFFSET_PTR(msg, SXP_MSG_SIZE + 2 * sizeof(uint8_t)), err_attr,
               err_attr_total_size);
    }
    msg->length = req_size;
out:
    return rc;
}

/**
 * @brief create sxp error message in buffer of given size
 *
 * @param buffer buffer to hold the error message, must be large enough
 * @param buffer_size size of the buffer allocated
 * @param code error code
 *
 * @return 0 on success, -1 on error
 */
int sxp_create_error_basic(void *buffer, size_t buffer_size,
                           enum sxp_error_non_extended_code code)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, buffer);
    RC_CHECK(rc, out);
    uint32_t req_size = SXP_MSG_SIZE + sizeof(uint32_t);
    if (buffer_size < req_size) {
        LOG_ERROR("Buffer of size %zu too small for error of size %" PRIu32,
                  buffer_size, req_size);
        rc = -1;
        goto out;
    }
    struct sxp_msg *msg = buffer;
    msg->type = SXP_MSG_ERROR;
    msg->length = req_size;
    uint32_t *err = OFFSET_PTR(buffer, SXP_MSG_SIZE);
    *err = code;
out:
    return rc;
}

/**
 * @brief parse sxp error message
 *
 * @param msg message to parse
 * @param extended if set to 0, then non_extended_code is set, otherwise
 *code/sub_code are set
 * @param code code stored in error message
 * @param sub_code sub-code stored in error message
 * @param non_extended_code non-extended-code stored in error message
 *
 * @return 0 on success, -1 on error
 */
int sxp_parse_error(struct sxp_msg *msg, int *extended,
                    enum sxp_error_code *code,
                    enum sxp_error_sub_code *sub_code,
                    enum sxp_error_non_extended_code *non_extended_code)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, msg, extended, code, sub_code, non_extended_code);
    RC_CHECK(rc, out);
    if (SXP_MSG_ERROR != msg->type) {
        LOG_ERROR("Attempt to parse %s message as %s",
                  sxp_msg_type_string(msg->type),
                  sxp_msg_type_string(SXP_MSG_ERROR));
        rc = -1;
        goto out;
    }

    void *err = OFFSET_PTR(msg, SXP_MSG_SIZE);
    *extended = SXP_ERROR_GET_EXTENDED(err);
    if (!*extended) {
        switch (SXP_ERROR_GET_NON_EXTENDED_ERROR_CODE(err)) {
        case SXP_NON_EXT_ERR_CODE_NONE:
            *non_extended_code = SXP_NON_EXT_ERR_CODE_NONE;
            break;
        case SXP_NON_EXT_ERR_CODE_VERSION_MISMATCH:
            *non_extended_code = SXP_NON_EXT_ERR_CODE_VERSION_MISMATCH;
            break;
        case SXP_NON_EXT_ERR_CODE_MESSAGE_PARSE_ERROR:
            *non_extended_code = SXP_NON_EXT_ERR_CODE_MESSAGE_PARSE_ERROR;
            break;
        default:
            LOG_ERROR("Unrecognized non-extended error-code %" PRIu16,
                      SXP_ERROR_GET_NON_EXTENDED_ERROR_CODE(err));
            rc = -1;
            goto out;
        }
    } else {
        int tmp = SXP_ERROR_GET_CODE(err);
        switch (tmp) {
        case SXP_ERR_CODE_NONE:
            *code = SXP_ERR_CODE_NONE;
            break;
        case SXP_ERR_CODE_MSG_HEAD:
            *code = SXP_ERR_CODE_MSG_HEAD;
            break;
        case SXP_ERR_CODE_OPEN:
            *code = SXP_ERR_CODE_OPEN;
            break;
        case SXP_ERR_CODE_UPDATE:
            *code = SXP_ERR_CODE_UPDATE;
            break;
        default:
            LOG_ERROR("Unrecognized error code %" PRIu8,
                      SXP_ERROR_GET_CODE(err));
            rc = -1;
            goto out;
        }
        tmp = SXP_ERROR_GET_SUBCODE(err);
        switch (tmp) {
        case SXP_SUB_ERR_CODE_NONE:
            *sub_code = SXP_SUB_ERR_CODE_NONE;
            break;
        case SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE_LIST:
            *sub_code = SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE_LIST;
            break;
        case SXP_SUB_ERR_CODE_UNEXPECTED_ATTRIBUTE:
            *sub_code = SXP_SUB_ERR_CODE_UNEXPECTED_ATTRIBUTE;
            break;
        case SXP_SUB_ERR_CODE_MISSING_WELL_KNOWN_ATTRIBUTE:
            *sub_code = SXP_SUB_ERR_CODE_MISSING_WELL_KNOWN_ATTRIBUTE;
            break;
        case SXP_SUB_ERR_CODE_ATTRIBUTE_FLAGS_ERROR:
            *sub_code = SXP_SUB_ERR_CODE_ATTRIBUTE_FLAGS_ERROR;
            break;
        case SXP_SUB_ERR_CODE_ATTRIBUTE_LENGTH_ERROR:
            *sub_code = SXP_SUB_ERR_CODE_ATTRIBUTE_LENGTH_ERROR;
            break;
        case SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE:
            *sub_code = SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE;
            break;
        case SXP_SUB_ERR_CODE_OPTIONAL_ATTRIBUTE_ERROR:
            *sub_code = SXP_SUB_ERR_CODE_OPTIONAL_ATTRIBUTE_ERROR;
            break;
        case SXP_SUB_ERR_CODE_UNSUPPORTED_VERSION_NUMBER:
            *sub_code = SXP_SUB_ERR_CODE_UNSUPPORTED_VERSION_NUMBER;
            break;
        case SXP_SUB_ERR_CODE_UNSUPPORTED_OPTIONAL_ATTRIBUTE:
            *sub_code = SXP_SUB_ERR_CODE_UNSUPPORTED_OPTIONAL_ATTRIBUTE;
            break;
        case SXP_SUB_ERR_CODE_UNACCEPTABLE_HOLD_TIME:
            *sub_code = SXP_SUB_ERR_CODE_UNACCEPTABLE_HOLD_TIME;
            break;
        default:
            LOG_ERROR("Unrecognized error sub-code %" PRIu8,
                      SXP_ERROR_GET_SUBCODE(err));
            rc = -1;
            goto out;
        }
    }
out:
    return rc;
}

/**
 * @brief return string describing sxp mode
 *
 * @param m mode
 *
 * @return string describing sxp mode
 */
const char *sxp_mode_string(enum sxp_mode m)
{
    switch (m) {
    case SXP_MODE_SPEAKER:
        return "SPEAKER";

    case SXP_MODE_LISTENER:
        return "LISTENER";
    }

    return "UNKNOWN";
}

static int sxp_attr_node_id_set_node_id(const struct sxp_attribute *attr,
                                        uint32_t node_id)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, attr);
    RC_CHECK(rc, out);
    enum sxp_attr_type type;
    RC_CHECK(rc = sxp_attr_get_type(attr, &type), out);
    if (SXP_ATTR_TYPE_NODE_ID != type) {
        LOG_ERROR("Attempt to set node-id for %s attribute",
                  sxp_attr_type_string(type));
        rc = -1;
    } else if (sxp_attr_is_compact(attr)) {
        if (sxp_attr_is_extended(attr)) {
            LOG_ERROR("Cannot set node-id for compact, extended attribute");
            rc = -1;
        } else {
            *(uint32_t *)OFFSET_PTR(attr, SXP_CNE_ATTR_HEAD_SIZE) = node_id;
        }
    } else {
        LOG_ERROR("Cannot set node-id for non-compact, non-extended attribute");
        rc = -1;
    }
out:
    return rc;
}

/**
 * @brief get node id from node id attribute
 *
 * @param attr node id attribute
 * @param node_id pointer to storage for node id
 *
 * @return 0 on success, -1 on error
 */
int sxp_attr_node_id_get_node_id(const struct sxp_attribute *attr,
                                 uint32_t *node_id)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, attr, node_id);
    RC_CHECK(rc, out);
    enum sxp_attr_type type;
    RC_CHECK(rc = sxp_attr_get_type(attr, &type), out);
    if (SXP_ATTR_TYPE_NODE_ID != type) {
        LOG_ERROR("Attempt to get node-id from %s attribute",
                  sxp_attr_type_string(type));
        rc = -1;
    } else if (sxp_attr_is_compact(attr)) {
        if (sxp_attr_is_extended(attr)) {
            LOG_ERROR("Cannot get node-id from compact, extended attribute");
            rc = -1;
        } else {
            *node_id = *(uint32_t *)OFFSET_PTR(attr, SXP_CNE_ATTR_HEAD_SIZE);
        }
    } else {
        LOG_ERROR("Cannot get node-id from non-compact attribute");
        rc = -1;
    }
out:
    return rc;
}

/**
 * @brief create open v4 message in buffer of given size
 *
 * @param buffer buffer to hold the message, must be large enough
 * @param size buffer size
 * @param mode sxp mode to set in the message
 * @param node_id node-id to set in the message
 *
 * @return 0 on success, -1 on error
 */
int sxp_create_open_v4(void *buffer, size_t size, enum sxp_mode mode,
                       uint32_t node_id)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, buffer);
    RC_CHECK(rc, out);
    const size_t req_size =
        SXP_OPEN_HEAD_SIZE +
        (node_id ? SXP_CNE_ATTR_HEAD_SIZE + sizeof(node_id) : 0);
    if (size < req_size) {
        LOG_ERROR("Buffer of size %zu too small for open msg v4 of size %zu",
                  size, req_size);
        rc = -1;
    }
    RC_CHECK(rc, out);
    struct sxp_msg *msg = buffer;
    msg->length = (uint32_t)req_size;
    msg->type = SXP_MSG_OPEN;
    void *open = OFFSET_PTR(buffer, SXP_MSG_SIZE);

    SXP_OPEN_SET_MODE(open, mode);
    SXP_OPEN_SET_VERSION(open, 4);
    if (node_id) {
        void *attr = OFFSET_PTR(buffer, SXP_OPEN_HEAD_SIZE);
        char flags = 0;
        BIT_SET(flags, SXP_ATTR_NON_TRANSITIVE_FLAG);
        BIT_SET(flags, SXP_ATTR_COMPACT_FLAG);
        SXP_ATTR_SET_FLAGS(attr, flags);
        RC_CHECK(rc = sxp_attr_set_type(attr, SXP_ATTR_TYPE_NODE_ID), out);
        RC_CHECK(rc = sxp_attr_set_length(attr, sizeof(node_id)), out);
        rc = sxp_attr_node_id_set_node_id(attr, node_id);
    }
out:
    return rc;
}

/**
 * @brief create open resp message in buffer of given size
 *
 * @param buffer buffer to hold the message, must be large enough
 * @param version sxp version to declare inside open resp
 * @param size buffer size
 * @param mode sxp mode to set in the message
 * @param node_id node-id to set in the message(if non-zero), if zero, node-id
 *attribute is not added to the message
 *
 * @return 0 on success, -1 on error
 */
int sxp_create_open_resp(void *buffer, size_t size, uint32_t version,
                         enum sxp_mode mode, uint32_t node_id)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, buffer);
    RC_CHECK(rc, out);
    const size_t req_size =
        SXP_OPEN_HEAD_SIZE +
        (node_id ? SXP_CNE_ATTR_HEAD_SIZE + sizeof(node_id) : 0);
    if (size < req_size) {
        LOG_ERROR("Buffer of size %zu too small for open msg v4 of size %zu",
                  size, req_size);
        rc = -1;
    }
    RC_CHECK(rc, out);
    struct sxp_msg *msg = buffer;
    msg->length = (uint32_t)req_size;
    msg->type = SXP_MSG_OPEN_RESP;
    void *open = OFFSET_PTR(buffer, SXP_MSG_SIZE);

    SXP_OPEN_SET_MODE(open, mode);
    SXP_OPEN_SET_VERSION(open, version);
    if (node_id) {
        void *attr = OFFSET_PTR(buffer, SXP_OPEN_HEAD_SIZE);
        char flags = 0;
        BIT_SET(flags, SXP_ATTR_NON_TRANSITIVE_FLAG);
        BIT_SET(flags, SXP_ATTR_COMPACT_FLAG);
        SXP_ATTR_SET_FLAGS(attr, flags);
        RC_CHECK(rc = sxp_attr_set_type(attr, SXP_ATTR_TYPE_NODE_ID), out);
        RC_CHECK(rc = sxp_attr_set_length(attr, sizeof(node_id)), out);
        rc = sxp_attr_node_id_set_node_id(attr, node_id);
    }
out:
    return rc;
}

/**
 * @brief create purge-all message in buffer of given size
 *
 * @param buffer buffer to hold the message, must be large enough
 * @param size buffer size
 *
 * @return 0 on success, -1 on error
 */
int sxp_create_purge_all(void *buffer, size_t size)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, buffer);
    if (RC_ISOK(rc)) {
        if (size < SXP_MSG_SIZE) {
            LOG_ERROR(
                "Buffer size %zu too small for purge-all message of size %zu",
                size, SXP_MSG_SIZE);
            rc = -1;
        } else {
            struct sxp_msg *msg = buffer;
            msg->length = SXP_MSG_SIZE;
            msg->type = SXP_MSG_PURGE_ALL;
        }
    }
    return rc;
}

/**
 * @brief create keep-alive message in buffer of given size
 *
 * @param buffer buffer to hold the message, must be large enough
 * @param size buffer size
 *
 * @return 0 on success, -1 on error
 */
int sxp_create_keepalive(void *buffer, size_t size)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, buffer);
    RC_CHECK(rc, out);
    if (size < SXP_MSG_SIZE) {
        LOG_ERROR(
            "Buffer of size %zu too small for keep-alive message of size %zu",
            size, SXP_MSG_SIZE);
        rc = -1;
    } else {
        struct sxp_msg *msg = buffer;
        msg->length = SXP_MSG_SIZE;
        msg->type = SXP_MSG_KEEPALIVE;
    }
out:
    return rc;
}

/**
 * @brief create update message in buffer of given size
 *
 * @param buffer buffer to hold the message, must be large enough
 * @param size buffer size
 *
 * @return 0 on success, -1 on error
 */
int sxp_create_update(void *buffer, size_t size)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, buffer);
    RC_CHECK(rc, out);
    if (size < SXP_MSG_SIZE) {
        LOG_ERROR("Buffer of size %zu too small for update message of size %zu",
                  size, SXP_MSG_SIZE);
        rc = -1;
    } else {
        struct sxp_msg *msg = buffer;
        msg->length = SXP_MSG_SIZE;
        msg->type = SXP_MSG_UPDATE;
    }
out:
    return rc;
}

/**
 * @brief get the type of sxp attribute
 *
 * @param attr head to get type from
 * @param type pointer to storage for type
 *
 * @return 0 on success, -1 on error
 */
int sxp_attr_get_type(const struct sxp_attribute *attr,
                      enum sxp_attr_type *type)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, attr, type);
    RC_CHECK(rc, out);
    uint32_t _type = 0;
    if (sxp_attr_is_compact(attr)) {
        _type = ((uint8_t *)attr)[1];
    } else {
        _type = ((uint8_t *)attr)[0];
    }
    switch (_type) {
    case SXP_ATTR_TYPE_ADD_IPV4:
        *type = SXP_ATTR_TYPE_ADD_IPV4;
        break;
    case SXP_ATTR_TYPE_ADD_IPV6:
        *type = SXP_ATTR_TYPE_ADD_IPV6;
        break;
    case SXP_ATTR_TYPE_DEL_IPV4:
        *type = SXP_ATTR_TYPE_DEL_IPV4;
        break;
    case SXP_ATTR_TYPE_DEL_IPV6:
        *type = SXP_ATTR_TYPE_DEL_IPV6;
        break;
    case SXP_ATTR_TYPE_NODE_ID:
        *type = SXP_ATTR_TYPE_NODE_ID;
        break;
    case SXP_ATTR_TYPE_CAPABILITIES:
        *type = SXP_ATTR_TYPE_CAPABILITIES;
        break;
    case SXP_ATTR_TYPE_HOLD_TIME:
        *type = SXP_ATTR_TYPE_HOLD_TIME;
        break;
    case SXP_ATTR_TYPE_IPV4_ADD_PREFIX:
        *type = SXP_ATTR_TYPE_IPV4_ADD_PREFIX;
        break;
    case SXP_ATTR_TYPE_IPV4_DEL_PREFIX:
        *type = SXP_ATTR_TYPE_IPV4_DEL_PREFIX;
        break;
    case SXP_ATTR_TYPE_IPV6_ADD_PREFIX:
        *type = SXP_ATTR_TYPE_IPV6_ADD_PREFIX;
        break;
    case SXP_ATTR_TYPE_IPV6_DEL_PREFIX:
        *type = SXP_ATTR_TYPE_IPV6_DEL_PREFIX;
        break;
    case SXP_ATTR_TYPE_SGT:
        *type = SXP_ATTR_TYPE_SGT;
        break;
    case SXP_ATTR_TYPE_PEER_SEQUENCE:
        *type = SXP_ATTR_TYPE_PEER_SEQUENCE;
        break;
    default:
        LOG_ERROR("Unknown attribute type %" PRIu8, _type);
        rc = -1;
        break;
    }
out:
    return rc;
}

/**
 * @brief get source group tag from source group tag attribute
 *
 * @param attr node id attribute
 * @param sgt pointer to storage for source group tag
 *
 * @return 0 on success, -1 on error
 */
int sxp_attr_sgt_get_sgt(const struct sxp_attribute *attr, uint16_t *sgt)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, attr, sgt);
    RC_CHECK(rc, out);
    enum sxp_attr_type type;
    RC_CHECK(rc = sxp_attr_get_type(attr, &type), out);
    if (SXP_ATTR_TYPE_SGT != type) {
        LOG_ERROR("Attempt to get source group tag from %s attribute",
                  sxp_attr_type_string(type));
        rc = -1;
    } else {
        if (sxp_attr_is_compact(attr)) {
            if (sxp_attr_is_extended(attr)) {
                *sgt = *(uint16_t *)OFFSET_PTR(attr, SXP_CE_ATTR_HEAD_SIZE);
            } else {
                *sgt = *(uint16_t *)OFFSET_PTR(attr, SXP_CNE_ATTR_HEAD_SIZE);
            }
        } else {
            *sgt = *(uint16_t *)OFFSET_PTR(attr, SXP_NC_ATTR_HEAD_SIZE);
        }
    }
out:
    return rc;
}

/**
 * @brief get source group tag from source group tag attribute
 *
 * @param attr node id attribute
 * @param sgt pointer to storage for source group tag
 *
 * @return 0 on success, -1 on error
 */
static int sxp_attr_sgt_set_sgt(const struct sxp_attribute *attr, uint16_t sgt)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, attr);
    RC_CHECK(rc, out);
    enum sxp_attr_type type;
    RC_CHECK(rc = sxp_attr_get_type(attr, &type), out);
    if (SXP_ATTR_TYPE_SGT != type) {
        LOG_ERROR("Attempt to set source group tag for %s attribute",
                  sxp_attr_type_string(type));
        rc = -1;
    } else {
        if (sxp_attr_is_compact(attr)) {
            if (sxp_attr_is_extended(attr)) {
                ((uint16_t *)OFFSET_PTR(attr, SXP_CE_ATTR_HEAD_SIZE))[0] = sgt;
            } else {
                ((uint16_t *)OFFSET_PTR(attr, SXP_CNE_ATTR_HEAD_SIZE))[0] = sgt;
            }
        } else {
            ((uint16_t *)OFFSET_PTR(attr, SXP_NC_ATTR_HEAD_SIZE))[0] = sgt;
        }
    }
out:
    return rc;
}

/**
 * @brief returns true if hold time attribute contains maximum hold time
 *value
 *
 * @param attr attribute to inspect
 *
 * @return true if present/false otherwise
 */
bool sxp_attr_hold_time_has_max_val(const struct sxp_attribute *attr)
{
    if (attr) {
        return 2 * sizeof(uint16_t) == sxp_attr_get_length(false, attr);
    }
    return false;
}

/**
 * @brief get the minimum hold time value from hold time attribute
 *
 * @param attr attribute to parse
 * @param min_val pointer to storage for minimum hold time
 * @param[out] code error code found while processing attribute
 * @param[out] subcode error sub-code found while processing attribute
 *
 * @return 0 on success, -1 on error
 */
int sxp_attr_hold_time_get_min_val(const struct sxp_attribute *attr,
                                   uint16_t *min_val, enum sxp_error_code *code,
                                   enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, attr, min_val, code, subcode);
    RC_CHECK(rc, out);
    enum sxp_attr_type type;
    RC_CHECK(rc = sxp_attr_get_type(attr, &type), out);
    if (type != SXP_ATTR_TYPE_HOLD_TIME) {
        LOG_ERROR("Attempt to get minimum hold-time from %s attribute",
                  sxp_attr_type_string(type));
        rc = -1;
        goto out;
    }
    if (sxp_attr_is_compact(attr)) {
        if (sxp_attr_is_extended(attr)) {
            LOG_ERROR("Hold-time attribute with extended length is invalid");
            *code = SXP_ERR_CODE_OPEN;
            *subcode = SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE;
        } else {
            if (sxp_attr_get_length(false, attr) >= sizeof(uint16_t)) {
                *min_val =
                    *((uint16_t *)OFFSET_PTR(attr, SXP_CNE_ATTR_HEAD_SIZE));
            }
        }
    } else {
        LOG_ERROR("Non-compact hold-time attribute is invalid");
        *code = SXP_ERR_CODE_OPEN;
        *subcode = SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE;
    }
out:
    return rc;
}

/**
 * @brief get the maximum hold time value from hold time attribute
 *
 * @param attr attribute to parse
 * @param max_val pointer to storage for maximum hold time
 * @param[out] code error code found while processing attribute
 * @param[out] subcode error sub-code found while processing attribute
 *
 * @return 0 on success, -1 on error
 */
int sxp_attr_hold_time_get_max_val(const struct sxp_attribute *attr,
                                   uint16_t *max_val, enum sxp_error_code *code,
                                   enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, attr, max_val, code, subcode);
    RC_CHECK(rc, out);
    enum sxp_attr_type type;
    RC_CHECK(rc = sxp_attr_get_type(attr, &type), out);
    if (SXP_ATTR_TYPE_HOLD_TIME != type) {
        LOG_ERROR("Attempt to get maximum hold-time from %s attribute",
                  sxp_attr_type_string(type));
        rc = -1;
    }
    if (sxp_attr_is_compact(attr)) {
        if (sxp_attr_is_extended(attr)) {
            LOG_ERROR("Hold-time attribute with extended length is invalid");
            *code = SXP_ERR_CODE_OPEN;
            *subcode = SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE;
        } else {
            if (sxp_attr_get_length(false, attr) >= 2 * sizeof(uint16_t)) {
                *max_val =
                    ((uint16_t *)OFFSET_PTR(attr, SXP_CNE_ATTR_HEAD_SIZE))[1];
            }
        }
    } else {
        LOG_ERROR("Non-compact hold-time attribute is invalid");
        *code = SXP_ERR_CODE_OPEN;
        *subcode = SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE;
    }
out:
    return rc;
}

int sxp_attr_hold_time_get_val(const struct sxp_attribute *attr,
                               uint16_t *min_val, uint16_t *max_val,
                               bool *has_max_val, enum sxp_error_code *code,
                               enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, attr, min_val, max_val, has_max_val, code, subcode);
    RC_CHECK(rc, out);
    *min_val = 0;
    *max_val = 0;
    *has_max_val = false;
    if (!BIT_IS_SET(SXP_ATTR_GET_FLAGS(attr), SXP_ATTR_NON_TRANSITIVE_FLAG)) {
        LOG_ERROR("hold-time attribute is not marked as Non-Transitive");
        *code = SXP_ERR_CODE_OPEN;
        *subcode = SXP_SUB_ERR_CODE_ATTRIBUTE_FLAGS_ERROR;
        goto out;
    }
    rc = sxp_attr_hold_time_get_min_val(attr, min_val, code, subcode);
    if (sxp_isnotok(rc, *code, *subcode)) {
        goto out;
    }
    if (sxp_attr_hold_time_has_max_val(attr)) {
        rc = sxp_attr_hold_time_get_max_val(attr, max_val, code, subcode);
        if (sxp_isnotok(rc, *code, *subcode)) {
            goto out;
        }
        *has_max_val = true;
    }

out:
    return rc;
}

/**
 * @brief get version from SXP OPEN message
 *
 * @param msg message to process
 * @param version pointer to storage for version
 *
 * @return 0 on success, -1 on error
 */
int sxp_open_get_version(const struct sxp_msg *msg, uint32_t *version)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, msg, version);
    if (RC_ISOK(rc)) {
        enum sxp_msg_type type = msg->type;
        if (SXP_MSG_OPEN != type && SXP_MSG_OPEN_RESP != type) {
            LOG_ERROR("Attempt to get type from non-open msg %s type %d",
                      sxp_msg_type_string(type), type);
            rc = -1;
        } else {
            void *open = OFFSET_PTR(msg, SXP_MSG_SIZE);
            *version = SXP_OPEN_GET_VERSION(open);
        }
    }
    return rc;
}

/**
 * @brief get mode from SXP OPEN message
 *
 * @param msg message to process
 * @param mode pointer to storage for mode
 *
 * @return 0 on success, -1 on error
 */
int sxp_open_get_mode(const struct sxp_msg *msg, enum sxp_mode *mode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, msg, mode);
    if (RC_ISOK(rc)) {
        enum sxp_msg_type type = msg->type;
        if (SXP_MSG_OPEN != type && SXP_MSG_OPEN_RESP != type) {
            LOG_ERROR("Attempt to get type from non-open msg %s type %d",
                      sxp_msg_type_string(type), type);
            rc = -1;
        } else {
            void *open = OFFSET_PTR(msg, SXP_MSG_SIZE);
            *mode = SXP_OPEN_GET_MODE(open);
        }
    }
    return rc;
}

/**
 * @brief return the capability code of capability
 *
 * @param c capability
 * @param code capability code
 *
 * @return 0 on success, -1 on error
 */
int sxp_capability_get_code(const struct sxp_capability *c,
                            enum sxp_capability_code *code)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, c, code);
    if (RC_ISOK(rc)) {
        int tmp = SXP_CAPABILITY_GET_CODE(c);
        switch (tmp) {
        case SXP_CAPABILITY_IPV4_UNICAST:
            *code = SXP_CAPABILITY_IPV4_UNICAST;
            break;
        case SXP_CAPABILITY_IPV6_UNICAST:
            *code = SXP_CAPABILITY_IPV6_UNICAST;
            break;
        case SXP_CAPABILITY_SUBNET_BINDINGS:
            *code = SXP_CAPABILITY_SUBNET_BINDINGS;
            break;
        default:
            LOG_ERROR("Unknown capability code %d", tmp);
            rc = -1;
        }
    }
    return rc;
}

/**
 * @brief return length of capability
 *
 * @param c capability
 * @param length capability length
 *
 * @return 0 on success, -1 on error
 */
int sxp_capability_get_length(const struct sxp_capability *c, uint8_t *length)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, c, length);
    if (RC_ISOK(rc)) {
        *length = SXP_CAPABILITY_GET_LENGTH(c);
    }
    return rc;
}

/**
 * @brief return pointer to capability value
 *
 * @param c capability
 * @param value value stored in capability
 *
 * @return 0 on success, -1 on error
 */
int sxp_capability_get_value(const struct sxp_capability *c, const void **value)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, c, value);
    if (RC_ISOK(rc)) {
        *value = SXP_CAPABILITY_GET_VALUE(c);
    }
    return rc;
}

/**
 * @brief add new capabilities attribute to given message
 *
 * @param msg message to modify
 * @param buffer_size size of the buffer which holds the message (usable
 *memory)
 * @param capabilities pointer to newly initialized capabilities attribute
 *
 * @return 0 on success, -1 on error
 */
int sxp_msg_add_capabilities(struct sxp_msg *msg, size_t buffer_size,
                             struct sxp_attribute **capabilities)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, msg, capabilities);
    RC_CHECK(rc, out);
    if (buffer_size < msg->length) {
        LOG_ERROR("Buffer of size %zu is smaller then existing message "
                  "length "
                  "%" PRIu32,
                  buffer_size, msg->length);
        rc = -1;
    } else if (buffer_size < msg->length + SXP_CNE_ATTR_HEAD_SIZE) {
        LOG_ERROR("Buffer of size %zu cannot accomodate message with "
                  "length %" PRIu32 " + compact sxp capabilities of size %zu",
                  buffer_size, msg->length, SXP_CNE_ATTR_HEAD_SIZE);
        rc = -1;
    }
    RC_CHECK(rc, out);
    void *caps = OFFSET_PTR(msg, msg->length);
    char flags = 0;
    BIT_SET(flags, SXP_ATTR_NON_TRANSITIVE_FLAG);
    BIT_SET(flags, SXP_ATTR_COMPACT_FLAG);
    SXP_ATTR_SET_FLAGS(caps, flags);
    RC_CHECK(rc = sxp_attr_set_type(caps, SXP_ATTR_TYPE_CAPABILITIES), out);
    RC_CHECK(rc = sxp_attr_set_length(caps, 0), out);
    msg->length += SXP_CNE_ATTR_HEAD_SIZE;
    *capabilities = caps;
out:
    return rc;
}

/**
 * @brief add a new capability in capabilities
 *
 * @param msg message which holds the capabilities
 * @param buffer_size size of the buffer which holds the message (usable
 *memory)
 * @param capabilities pointer to capabilities within message
 * @param code capability code to add
 *
 * @return 0 on success, -1 on error
 */
int sxp_capabilities_add_capability(struct sxp_msg *msg, size_t buffer_size,
                                    struct sxp_attribute *capabilities,
                                    enum sxp_capability_code code)
{
    int rc = 0;
    uint32_t caps_length = 0;
    PARAM_NULL_CHECK(rc, msg, capabilities);
    RC_CHECK(rc, out);
    if (buffer_size < msg->length) {
        LOG_ERROR("Buffer of size %zu is smaller then existing message "
                  "length "
                  "%" PRIu32,
                  buffer_size, msg->length);
        rc = -1;
    } else if (buffer_size < msg->length + SXP_ATTR_CAPABILITY_SIZE) {
        LOG_ERROR("Buffer of size %zu cannot accomodate message with "
                  "length %" PRIu32 " + sxp capability of size %d",
                  buffer_size, msg->length, SXP_ATTR_CAPABILITY_SIZE);
        rc = -1;
    } else if ((char *)capabilities - (char *)msg > msg->length) {
        LOG_ERROR("Provided capabilites attribute %p not within %" PRIu32
                  " bytes of message %p",
                  (void *)capabilities, msg->length, (void *)msg);
        rc = -1;
    }
    RC_CHECK(rc, out);
    caps_length = sxp_attr_get_length(false, capabilities);
    if (sxp_attr_is_compact(capabilities)) {
        if (sxp_attr_is_extended(capabilities)) {
            if (caps_length + SXP_ATTR_CAPABILITY_SIZE > UINT8_MAX) {
                LOG_ERROR("Adding capability of length %d would overflow "
                          "compact non-extended length %" PRIu32 " maximum %d",
                          SXP_ATTR_CAPABILITY_SIZE, caps_length, UINT8_MAX);
                rc = -1;
            }
        } else if (caps_length + SXP_ATTR_CAPABILITY_SIZE > UINT16_MAX) {
            LOG_ERROR("Adding capability of length %d would "
                      "overflow compact non-extended length "
                      "%" PRIu32 " maximum %d",
                      SXP_ATTR_CAPABILITY_SIZE, caps_length, UINT16_MAX);
            rc = -1;
        }
    } else {
        LOG_ERROR("Don't know how to handle non-compact attribute");
        rc = -1;
    }
    RC_CHECK(rc, out);
    void *cap = OFFSET_PTR(msg, msg->length);
    rc = sxp_attr_set_length(capabilities,
                             caps_length + SXP_ATTR_CAPABILITY_SIZE);
    RC_CHECK(rc, out);
    SXP_CAPABILITY_SET_CODE(cap, code);
    SXP_CAPABILITY_SET_LENGTH(cap, 0);
    msg->length += SXP_ATTR_CAPABILITY_SIZE;
out:
    return rc;
}

static int sxp_attr_hold_time_set_min_val(struct sxp_attribute *attr,
                                          uint16_t min_val)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, attr);
    RC_CHECK(rc, out);
    if (sxp_attr_is_compact(attr)) {
        if (sxp_attr_is_extended(attr)) {
            LOG_ERROR("Cannot set min-value for compact, extended hold-time");
            rc = -1;
        } else {
            *((uint16_t *)OFFSET_PTR(attr, SXP_CNE_ATTR_HEAD_SIZE)) = (min_val);
        }
    } else {
        LOG_ERROR(
            "Cannot set min-value for non-compact, non-extended hold-time");
        rc = -1;
    }
out:
    return rc;
}

static int sxp_attr_hold_time_set_max_val(struct sxp_attribute *attr,
                                          uint16_t max_val)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, attr);
    RC_CHECK(rc, out);
    if (sxp_attr_is_compact(attr)) {
        if (sxp_attr_is_extended(attr)) {
            ((uint16_t *)OFFSET_PTR(attr, SXP_CE_ATTR_HEAD_SIZE))[1] =
                (max_val);
        } else {
            ((uint16_t *)OFFSET_PTR(attr, SXP_CNE_ATTR_HEAD_SIZE))[1] =
                (max_val);
        }
    } else {
        LOG_ERROR(
            "Cannot set min-value for non-compact, non-extended hold-time");
        rc = -1;
    }
out:
    return rc;
}

/**
 * @brief add hold time attribute to sxp message
 *
 * @param msg message to modify
 * @param buffer_size size of the buffer which holds the message (usable
 *memory)
 * @param min_val hold time minimum value
 * @param max_val hold time maximum value, if max-val is KEEPALIVE_UNUSED,
 *then
 *it is not added to attribute
 *
 * @return 0 on success, -1 on error
 */
int sxp_msg_add_hold_time(struct sxp_msg *msg, size_t buffer_size,
                          uint16_t min_val, uint16_t max_val)
{
    int rc = 0;
    const uint32_t attr_length =
        (KEEPALIVE_UNUSED == max_val) ? sizeof(uint16_t) : 2 * sizeof(uint16_t);
    PARAM_NULL_CHECK(rc, msg);
    RC_CHECK(rc, out);
    if (buffer_size < msg->length) {
        LOG_ERROR("Buffer of size %zu is smaller then existing message "
                  "length %" PRIu32,
                  buffer_size, msg->length);
        rc = -1;
        goto out;
    } else if (buffer_size <
               msg->length + SXP_CNE_ATTR_HEAD_SIZE + attr_length) {
        LOG_ERROR("Buffer of size %zu cannot accomodate message with length "
                  "%" PRIu32 " + compact hold time attribute of size %zu",
                  buffer_size, msg->length,
                  SXP_CNE_ATTR_HEAD_SIZE + attr_length);
        rc = -1;
        goto out;
    }
    void *hold_time = OFFSET_PTR(msg, msg->length);
    char flags = 0;
    BIT_SET(flags, SXP_ATTR_NON_TRANSITIVE_FLAG);
    BIT_SET(flags, SXP_ATTR_COMPACT_FLAG);
    SXP_ATTR_SET_FLAGS(hold_time, flags);
    RC_CHECK(rc = sxp_attr_set_type(hold_time, SXP_ATTR_TYPE_HOLD_TIME), out);
    RC_CHECK(rc = sxp_attr_hold_time_set_min_val(hold_time, min_val), out);
    RC_CHECK(rc = sxp_attr_set_length(hold_time, attr_length), out);
    if (KEEPALIVE_UNUSED != max_val) {
        RC_CHECK(rc = sxp_attr_hold_time_set_max_val(hold_time, max_val), out);
    }
    msg->length += SXP_CNE_ATTR_HEAD_SIZE + attr_length;
out:
    return rc;
}

static int sxp_add_attribute(struct sxp_msg *msg, size_t buffer_size,
                             bool optional, bool non_transitive, bool partial,
                             bool compact, bool extended,
                             enum sxp_attr_type attribute_type,
                             struct sxp_attribute **attr)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, msg, attr);
    RC_CHECK(rc, out);
    size_t attr_size = 0;
    if (compact) {
        if (extended) {
            attr_size += SXP_CE_ATTR_HEAD_SIZE;
        } else {
            attr_size += SXP_CNE_ATTR_HEAD_SIZE;
        }
    } else {
        LOG_ERROR("Don't know how to add non-compact attribute");
        rc = -1;
    }
    RC_CHECK(rc, out);
    if (buffer_size < msg->length + attr_size) {
        LOG_ERROR("Buffer of size %zu is too small to hold message of "
                  "length %" PRIu32 " + attribute %s head of size %zu",
                  buffer_size, msg->length,
                  sxp_attr_type_string(attribute_type), attr_size);
        rc = -1;
    }
    RC_CHECK(rc, out);
    void *x = OFFSET_PTR(msg, msg->length);
    uint8_t flags = 0;
    if (optional) {
        BIT_SET(flags, SXP_ATTR_OPTIONAL_FLAG);
    }
    if (non_transitive) {
        BIT_SET(flags, SXP_ATTR_NON_TRANSITIVE_FLAG);
    }
    if (partial) {
        BIT_SET(flags, SXP_ATTR_PARTIAL_FLAG);
    }
    if (compact) {
        BIT_SET(flags, SXP_ATTR_COMPACT_FLAG);
    }
    if (extended) {
        BIT_SET(flags, SXP_ATTR_EXTENDED_FLAG);
    }
    SXP_ATTR_SET_FLAGS(x, flags);
    RC_CHECK(rc = sxp_attr_set_type(x, attribute_type), out);
    RC_CHECK(rc = sxp_attr_set_length(x, 0), out);
    msg->length += attr_size;
    *attr = x;
out:
    return rc;
}

/**
 * @brief add source-group tag attribute to message
 *
 * @param msg message to modify
 * @param buffer_size size of buffer holding the message
 * @param tag tag to add
 * @param[in] optional_flag optional flag of del prefix attribute
 *
 * @return 0 on success, -1 on error
 */
int sxp_msg_add_sgt(struct sxp_msg *msg, size_t buffer_size, uint16_t tag,
                    bool optional_flag)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, msg);
    RC_CHECK(rc, out);
    const size_t req_size = msg->length + sxp_calc_sgt_size();
    if (buffer_size < req_size) {
        LOG_ERROR("Buffer of size %zu too small for update message of size %zu",
                  buffer_size, req_size);
        rc = -1;
    }
    RC_CHECK(rc, out);
    struct sxp_attribute *attr = NULL;
    rc = sxp_add_attribute(msg, buffer_size, optional_flag, false, false, true,
                           false, SXP_ATTR_TYPE_SGT, &attr);
    RC_CHECK(rc, out);
    RC_CHECK(rc = sxp_attr_set_length(attr, sizeof(uint16_t)), out);
    rc = sxp_attr_sgt_set_sgt(attr, tag);
    msg->length += sizeof(uint16_t);
out:
    return rc;
}

/**
 * @brief return the size required for storing sgt attribute
 *
 * @return size in bytes
 */
uint32_t sxp_calc_sgt_size(void)
{
    return SXP_CNE_ATTR_HEAD_SIZE + sizeof(uint16_t);
}

/**
 * @brief add peer sequence attribute to message
 *
 * @param[in] msg message to modify
 * @param[in] buffer_size size of buffer holding the message
 * @param[in] sxp_id_count the number of sxp id elements which this sequence
 *will store
 * @param[out] sxp_id_arr address of array where the sxp id elements can be
 *filled
 * @param[in] optional_flag optional flag of del prefix attribute
 *
 * @return 0 on success, -1 on error
 */
int sxp_msg_add_peer_sequence(struct sxp_msg *msg, size_t buffer_size,
                              uint32_t sxp_id_count, uint32_t **sxp_id_arr,
                              bool optional_flag)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, msg, sxp_id_arr);
    RC_CHECK(rc, out);
    if (!sxp_id_count) {
        LOG_ERROR("Attempt to add peer sequence with zero elements");
        rc = -1;
    } else {
        const size_t attr_size = sxp_calc_peer_sequence_size(sxp_id_count);
        if (msg->length + attr_size > buffer_size) {
            LOG_ERROR("Buffer of size %zu is too small to hold message of "
                      "length %" PRIu32 " + peer sequence of size %zu",
                      buffer_size, msg->length, attr_size);
            rc = -1;
        }
    }
    RC_CHECK(rc, out);
    struct sxp_attribute *attr = NULL;
    rc = sxp_add_attribute(msg, buffer_size, optional_flag, false, false, true,
                           false, SXP_ATTR_TYPE_PEER_SEQUENCE, &attr);
    RC_CHECK(rc, out);
    rc = sxp_attr_set_length(attr, sxp_id_count * sizeof(uint32_t));
    RC_CHECK(rc, out);
    *sxp_id_arr = OFFSET_PTR(attr, SXP_CNE_ATTR_HEAD_SIZE);
    msg->length += sxp_attr_get_length(false, attr);
out:
    return rc;
}

/**
 * @brief calculate the size which a peer-sequence takes
 *
 * @param sxp_id_count the number of elements in the peer sequence
 *
 * @return size in bytes
 */
uint32_t sxp_calc_peer_sequence_size(uint32_t sxp_id_count)
{
    return SXP_CNE_ATTR_HEAD_SIZE + sxp_id_count * sizeof(uint32_t);
}

static int sxp_parse_peer_sequence_internal(struct sxp_attribute *peer_sequence,
                                            size_t *sxp_id_count,
                                            uint32_t **sxp_id_arr,
                                            enum sxp_error_code *code,
                                            enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, peer_sequence, sxp_id_count, sxp_id_arr, code,
                     subcode);
    RC_CHECK(rc, out);
    enum sxp_attr_type type;
    RC_CHECK(rc = sxp_attr_get_type(peer_sequence, &type), out);
    if (SXP_ATTR_TYPE_PEER_SEQUENCE != type) {
        LOG_ERROR("Attempt to parse %s attribute as peer sequence",
                  sxp_attr_type_string(type));
        rc = -1;
    } else {
        const size_t length = sxp_attr_get_length(false, peer_sequence);
        if (length % sizeof(uint32_t)) {
            LOG_ERROR("Peer sequence length %zu, not multiple of %zu", length,
                      sizeof(uint32_t));
            *code = SXP_ERR_CODE_UPDATE;
            *subcode = SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE;
            goto out;
        }
        *sxp_id_count =
            sxp_attr_get_length(false, peer_sequence) / sizeof(uint32_t);
        if (!*sxp_id_count) {
            *code = SXP_ERR_CODE_UPDATE;
            *subcode = SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE;
            goto out;
        } else {
            *sxp_id_arr = OFFSET_PTR(peer_sequence,
                                     sxp_attr_get_head_size(peer_sequence));
        }
    }
out:
    return rc;
}

/**
 * @brief parse peer sequence attribute
 *
 * @param[in] peer_sequence peer sequence attribute to parse
 * @param[out] sxp_id_count the number of sxp id elements in peer sequence
 * @param[out] sxp_id_arr address to array of sxp id elements
 * @param[out] code error code found while processing attribute
 * @param[out] subcode error sub-code found while processing attribute
 *
 * @return 0 on success, -1 on error
 */
int sxp_parse_peer_sequence(struct sxp_attribute *peer_sequence,
                            size_t *sxp_id_count, const uint32_t **sxp_id_arr,
                            enum sxp_error_code *code,
                            enum sxp_error_sub_code *subcode)
{
    /* this is to prevent the caller from messing with the array returned
     * (which is just a pointer into the attribute's memory), so cast is ok */
    return sxp_parse_peer_sequence_internal(
        peer_sequence, sxp_id_count, (uint32_t **)sxp_id_arr, code, subcode);
}

static int qsort_cb(const void *a, const void *b, void *ctx)
{
    assert(a && b && ctx);
    struct qsort_ctx *qsort_ctx = (struct qsort_ctx *)ctx;
    if ((qsort_ctx->dup_found == false) && (a != b) &&
        ((*((uint32_t *)a)) == (*((uint32_t *)b)))) {
        qsort_ctx->dup_value = (*((uint32_t *)a));
        qsort_ctx->dup_found = true;
#ifdef SXP_USE_SETJMP
        longjmp(qsort_ctx->jmp_buf, 1);
#endif
    }

    return (*((uint32_t *)a) == *((uint32_t *)b))
               ? 0
               : ((*((uint32_t *)a) < *((uint32_t *)b)) ? -1 : 1);
}

int sxp_validate_peer_sequence(uint32_t nbo_peer_node_id, size_t sxp_id_count,
                               const uint32_t *sxp_id_arr,
                               enum sxp_error_code *code,
                               enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    uint32_t *sxp_id_arr_tmp = NULL;
    struct qsort_ctx qsort_ctx;
    qsort_ctx.dup_value = 0;
    qsort_ctx.dup_found = false;
    size_t i = 0;
    size_t a_pos = 0;
    size_t b_pos = 0;
    PARAM_NULL_CHECK(rc, sxp_id_arr, code, subcode);
    RC_CHECK(rc, out);

    if (sxp_id_count && sxp_id_arr[0] != nbo_peer_node_id) {
        LOG_ERROR("Found %s, but first node-id %" PRIu32 " is not peer's "
                  "node-id %" PRIu32,
                  sxp_attr_type_string(SXP_ATTR_TYPE_PEER_SEQUENCE),
                  sxp_id_arr[0], nbo_peer_node_id);
        *code = SXP_ERR_CODE_UPDATE;
        *subcode = SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE;
        goto out;
    }

    sxp_id_arr_tmp = mem_calloc(sxp_id_count, sizeof(*sxp_id_arr_tmp));
    if (NULL == sxp_id_arr_tmp) {
        rc = -1;
        LOG_ERROR("Memory allocation error");
        goto out;
    }

    memcpy(sxp_id_arr_tmp, sxp_id_arr, sxp_id_count * sizeof(*sxp_id_arr));

#ifdef SXP_USE_SETJMP
    if (!setjmp(qsort_ctx.jmp_buf)) {
#endif
        sxp_qsort_r(sxp_id_arr_tmp, sxp_id_count, sizeof(uint32_t), qsort_cb,
                    (void *)&qsort_ctx);
#ifdef SXP_USE_SETJMP
    }
#endif

    rc = 0;
    bool a_found = false;
    bool b_found = false;

    if (qsort_ctx.dup_found) {
        for (i = 0; i < sxp_id_count; ++i) {
            if (sxp_id_arr[i] == qsort_ctx.dup_value) {
                if (a_found == false) {
                    a_found = true;
                    a_pos = i;
                } else if (b_found == false) {
                    b_found = true;
                    b_pos = i;
                }
            }
        }

        assert(a_found && b_found);

        LOG_ERROR("Found %s, with duplicated node-id's %" PRIu32
                  " on positions %zu %zu",
                  sxp_attr_type_string(SXP_ATTR_TYPE_PEER_SEQUENCE),
                  qsort_ctx.dup_value, a_pos, b_pos);
        *code = SXP_ERR_CODE_UPDATE;
        *subcode = SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE;
        goto out;
    }
out:
    if (NULL != sxp_id_arr_tmp) {
        mem_free(sxp_id_arr_tmp);
    }
    return rc;
}

/**
 * @brief add ipv4-add-prefix attribute to message
 *
 * @param[in] msg message to modify
 * @param[in] buffer_size size of buffer holding the message
 * @param[out] attr addresss of ipv4-add-prefix attribute
 * @param[in] optional_flag optional flag of del prefix attribute
 *
 * @return 0 on success, -1 on error
 */
int sxp_msg_add_ipv4_add_prefix(struct sxp_msg *msg, size_t buffer_size,
                                struct sxp_attribute **attr, bool optional_flag)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, msg, attr);
    RC_CHECK(rc, out);
    rc = sxp_add_attribute(msg, buffer_size, optional_flag, false, false, true,
                           false, SXP_ATTR_TYPE_IPV4_ADD_PREFIX, attr);
    RC_CHECK(rc, out);
out:
    return rc;
}

/**
 * @brief return the size of ipv4-add-prefix attribute in bytes
 *
 * @return size in bytes
 */
uint32_t sxp_calc_ipv4_add_prefix_size(void)
{
    return SXP_CE_ATTR_HEAD_SIZE + sizeof(uint16_t);
}

/**
 * @brief add ipv6-add-prefix attribute to message
 *
 * @param[in] msg message to modify
 * @param[in] buffer_size size of buffer holding the message
 * @param[out] attr address of ipv6-add-prefix attribute
 * @param[in] optional_flag optional flag of del prefix attribute
 *
 * @return 0 on success, -1 on error
 */
int sxp_msg_add_ipv6_add_prefix(struct sxp_msg *msg, size_t buffer_size,
                                struct sxp_attribute **attr, bool optional_flag)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, msg, attr);
    RC_CHECK(rc, out);
    rc = sxp_add_attribute(msg, buffer_size, optional_flag, false, false, true,
                           false, SXP_ATTR_TYPE_IPV6_ADD_PREFIX, attr);
    RC_CHECK(rc, out);
out:
    return rc;
}

/**
 * @brief return the size of ipv6-add-prefix attribute in bytes
 *
 * @return size in bytes
 */
uint32_t sxp_calc_ipv6_add_prefix_size(void)
{
    return SXP_CE_ATTR_HEAD_SIZE + sizeof(uint16_t);
}

/**
 * @brief add ipv4-del-prefix attribute to message
 *
 * @param[in] msg message to modify
 * @param[in] buffer_size size of buffer holding the message
 * @param[out] attr address of ipv4-del-prefix attribute
 * @param[in] optional_flag optional flag of del prefix attribute
 *
 * @return 0 on success, -1 on error
 */
int sxp_msg_add_ipv4_del_prefix(struct sxp_msg *msg, size_t buffer_size,
                                struct sxp_attribute **attr, bool optional_flag)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, msg, attr);
    RC_CHECK(rc, out);
    rc = sxp_add_attribute(msg, buffer_size, optional_flag, false, false, true,
                           false, SXP_ATTR_TYPE_IPV4_DEL_PREFIX, attr);
out:
    return rc;
}

/**
 * @brief add ipv6-del-prefix attribute to message
 *
 * @param[in] msg message to modify
 * @param[in] buffer_size size of buffer holding the message
 * @param[out] attr address of ipv6-del-prefix attribute
 * @param[in] optional_flag optional flag of del prefix attribute
 *
 * @return 0 on success, -1 on error
 */
int sxp_msg_add_ipv6_del_prefix(struct sxp_msg *msg, size_t buffer_size,
                                struct sxp_attribute **attr, bool optional_flag)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, msg, attr);
    RC_CHECK(rc, out);
    rc = sxp_add_attribute(msg, buffer_size, optional_flag, false, false, true,
                           false, SXP_ATTR_TYPE_IPV6_DEL_PREFIX, attr);
out:
    return rc;
}

static int sxp_attr_compact_to_extended(struct sxp_attribute *attr)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, attr);
    RC_CHECK(rc, out);
    if (!sxp_attr_is_compact(attr)) {
        LOG_ERROR("Cannot convert non-compact attribute to extended");
        rc = -1;
    } else if (sxp_attr_is_extended(attr)) {
        LOG_ERROR("Cannot convert extended attribute to extended");
        rc = -1;
    }
    RC_CHECK(rc, out);
    /* get length from old location */
    uint32_t length = sxp_attr_get_length(false, attr);
    /* move data to new location */
    memmove(OFFSET_PTR(attr, SXP_CE_ATTR_HEAD_SIZE),
            OFFSET_PTR(attr, SXP_CNE_ATTR_HEAD_SIZE), length);
    /* update flags */
    uint8_t flags = SXP_ATTR_GET_FLAGS(attr);
    BIT_SET(flags, SXP_ATTR_EXTENDED_FLAG);
    SXP_ATTR_SET_FLAGS(attr, flags);
    /* store length in new location */
    RC_CHECK(rc = sxp_attr_set_length(attr, length), out);
out:
    return rc;
}

static int sxp_create_prefix(void *ptr, uint8_t length, uint8_t *prefix)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, ptr);
    RC_CHECK(rc, out);
    if (length > 128) {
        LOG_ERROR("Invalid length %" PRIu8 " for IPV6 prefix", length);
        rc = -1;
    }
    RC_CHECK(rc, out);
    uint8_t bytes = length / 8 + (length % 8 > 0);
    *(uint8_t *)ptr = length;
    switch (bytes) {
    case 16:
        ((uint8_t *)OFFSET_PTR(ptr, sizeof(length)))[15] = prefix[15];
    /* fallthrough */
    case 15:
        ((uint8_t *)OFFSET_PTR(ptr, sizeof(length)))[14] = prefix[14];
    /* fallthrough */
    case 14:
        ((uint8_t *)OFFSET_PTR(ptr, sizeof(length)))[13] = prefix[13];
    /* fallthrough */
    case 13:
        ((uint8_t *)OFFSET_PTR(ptr, sizeof(length)))[12] = prefix[12];
    /* fallthrough */
    case 12:
        ((uint8_t *)OFFSET_PTR(ptr, sizeof(length)))[11] = prefix[11];
    /* fallthrough */
    case 11:
        ((uint8_t *)OFFSET_PTR(ptr, sizeof(length)))[10] = prefix[10];
    /* fallthrough */
    case 10:
        ((uint8_t *)OFFSET_PTR(ptr, sizeof(length)))[9] = prefix[9];
    /* fallthrough */
    case 9:
        ((uint8_t *)OFFSET_PTR(ptr, sizeof(length)))[8] = prefix[8];
    /* fallthrough */
    case 8:
        ((uint8_t *)OFFSET_PTR(ptr, sizeof(length)))[7] = prefix[7];
    /* fallthrough */
    case 7:
        ((uint8_t *)OFFSET_PTR(ptr, sizeof(length)))[6] = prefix[6];
    /* fallthrough */
    case 6:
        ((uint8_t *)OFFSET_PTR(ptr, sizeof(length)))[5] = prefix[5];
    /* fallthrough */
    case 5:
        ((uint8_t *)OFFSET_PTR(ptr, sizeof(length)))[4] = prefix[4];
    /* fallthrough */
    case 4:
        ((uint8_t *)OFFSET_PTR(ptr, sizeof(length)))[3] = prefix[3];
    /* fallthrough */
    case 3:
        ((uint8_t *)OFFSET_PTR(ptr, sizeof(length)))[2] = prefix[2];
    /* fallthrough */
    case 2:
        ((uint8_t *)OFFSET_PTR(ptr, sizeof(length)))[1] = prefix[1];
    /* fallthrough */
    case 1:
        ((uint8_t *)OFFSET_PTR(ptr, sizeof(length)))[0] = prefix[0];
        break;
    }
out:
    return rc;
}

/**
 * @brief add prefix to prefix-list-like attribute (ipv4/6-add/del-prefix)
 *
 * @param msg message whose part is the attribute
 * @param buffer_size size of buffer holding the message
 * @param attr attribute to modify
 * @param length length of prefix in bits
 * @param prefix memory where prefix is stored
 *
 * @return 0 on success, -1 on error
 */
int sxp_prefix_list_add_prefix(struct sxp_msg *msg, size_t buffer_size,
                               struct sxp_attribute *attr, uint8_t length,
                               uint8_t *prefix)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, msg, attr);
    RC_CHECK(rc, out);
    const uint32_t prefix_size = sxp_calc_prefix_size(length);
    uint32_t req_msg_length = msg->length + prefix_size;
    bool grow = false;
    if (UINT8_MAX < sxp_attr_get_length(false, attr) + prefix_size &&
        sxp_attr_is_compact(attr) && !sxp_attr_is_extended(attr)) {
        /* need to grow the attribute from non-extended to extended length */
        ++req_msg_length; /* extra byte for extended length size difference */
        grow = true;
    }
    if (UINT16_MAX < sxp_attr_get_length(false, attr) + prefix_size) {
        LOG_ERROR("Cannot add any more data to ipv4-add-prefix, required "
                  "length %" PRIu32
                  " is greater then maximum extended length %d",
                  sxp_attr_get_length(false, attr) + prefix_size, UINT16_MAX);
        rc = -1;
    } else if (buffer_size < req_msg_length) {
        LOG_ERROR(
            "Buffer of size %zu is too small for growing message of length "
            "%" PRIu32 " to new length %" PRIu32,
            buffer_size, msg->length, req_msg_length);
        rc = -1;
    }
    RC_CHECK(rc, out);
    if (grow) {
        LOG_TRACE("Need to change attribute from compact to extended");
        RC_CHECK(rc = sxp_attr_compact_to_extended(attr), out);
    }
    rc = sxp_create_prefix(
        OFFSET_PTR(attr, sxp_attr_get_head_size(attr) +
                             sxp_attr_get_length(false, attr)),
        length, prefix);
    RC_CHECK(rc, out);
    rc = sxp_attr_set_length(attr,
                             sxp_attr_get_length(false, attr) + prefix_size);
    RC_CHECK(rc, out);
    msg->length = req_msg_length;
out:
    return rc;
}

/**
 * @brief return the size of prefix added to ipv4/6-prefix-list
 *
 * @param prefix_len length of the prefix in bits
 *
 * @return size in bytes
 */
uint32_t sxp_calc_prefix_size(uint8_t prefix_len)

{
    return sizeof(prefix_len) + prefix_len / 8 + (prefix_len % 8 > 0);
}

/**
 * @brief parse prefix and extract values
 *
 * @param[in] prefix prefix to parse
 * @param[out] length extracted length
 * @param[out] buffer extracted prefix
 * @param[in] buffer_size size of the buffer
 *
 * @return 0 on success, -1 on error
 */
int sxp_parse_prefix(struct sxp_prefix *prefix, uint8_t *buffer,
                     size_t buffer_size, uint8_t *length)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, prefix, length);
    RC_CHECK(rc, out);
    *length = *(uint8_t *)prefix;
    const size_t byte_count = *length / 8 + (*length % 8 > 0);
    if (buffer && byte_count > buffer_size) {
        LOG_ERROR("Buffer of size %zu is too small for prefix of length %" PRIu8
                  " bits which requires %zu bytes",
                  buffer_size, *length, byte_count);
        rc = -1;
        goto out;
    }
    if (buffer) {
        switch (byte_count) {
        case 16:
            buffer[15] = ((uint8_t *)OFFSET_PTR(prefix, sizeof(*length)))[15];
        /* fallthrough */
        case 15:
            buffer[14] = ((uint8_t *)OFFSET_PTR(prefix, sizeof(*length)))[14];
        /* fallthrough */
        case 14:
            buffer[13] = ((uint8_t *)OFFSET_PTR(prefix, sizeof(*length)))[13];
        /* fallthrough */
        case 13:
            buffer[12] = ((uint8_t *)OFFSET_PTR(prefix, sizeof(*length)))[12];
        /* fallthrough */
        case 12:
            buffer[11] = ((uint8_t *)OFFSET_PTR(prefix, sizeof(*length)))[11];
        /* fallthrough */
        case 11:
            buffer[10] = ((uint8_t *)OFFSET_PTR(prefix, sizeof(*length)))[10];
        /* fallthrough */
        case 10:
            buffer[9] = ((uint8_t *)OFFSET_PTR(prefix, sizeof(*length)))[9];
        /* fallthrough */
        case 9:
            buffer[8] = ((uint8_t *)OFFSET_PTR(prefix, sizeof(*length)))[8];
        /* fallthrough */
        case 8:
            buffer[7] = ((uint8_t *)OFFSET_PTR(prefix, sizeof(*length)))[7];
        /* fallthrough */
        case 7:
            buffer[6] = ((uint8_t *)OFFSET_PTR(prefix, sizeof(*length)))[6];
        /* fallthrough */
        case 6:
            buffer[5] = ((uint8_t *)OFFSET_PTR(prefix, sizeof(*length)))[5];
        /* fallthrough */
        case 5:
            buffer[4] = ((uint8_t *)OFFSET_PTR(prefix, sizeof(*length)))[4];
        /* fallthrough */
        case 4:
            buffer[3] = ((uint8_t *)OFFSET_PTR(prefix, sizeof(*length)))[3];
        /* fallthrough */
        case 3:
            buffer[2] = ((uint8_t *)OFFSET_PTR(prefix, sizeof(*length)))[2];
        /* fallthrough */
        case 2:
            buffer[1] = ((uint8_t *)OFFSET_PTR(prefix, sizeof(*length)))[1];
        /* fallthrough */
        case 1:
            buffer[0] = ((uint8_t *)OFFSET_PTR(prefix, sizeof(*length)))[0];
        }
    }
out:
    return rc;
}

/**
 * @brief parse prefix-list (ipv4/6-add/del-prefix) - get first/next prefix
 *
 * @param[in] prefix_list attribute to parse
 * @param[in] start if set to NULL, get first prefix, otherwise get next
 * @param[out] next first or next prefix depending on value of start or NULL
 *if no (more) prefixes present
 * @param[out] code error code found while processing attribute
 * @param[out] subcode error sub-code found while processing attribute
 *
 * @return 0 on success, -1 on error
 */
int sxp_parse_prefix_list(struct sxp_attribute *prefix_list,
                          struct sxp_prefix *start, struct sxp_prefix **next,
                          enum sxp_error_code *code,
                          enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, prefix_list, next, code, subcode);
    RC_CHECK(rc, out);
    uint32_t attr_size = 0;
    rc = sxp_attr_get_total_size(false, prefix_list, &attr_size);
    RC_CHECK(rc, out);
    if (start && (void *)start < (void *)prefix_list) {
        LOG_ERROR("Address of starting prefix %p is lower then prefix-list "
                  "address %p",
                  (void *)start, (void *)prefix_list);
        rc = -1;
    } else if (start && (uint8_t *)start > (uint8_t *)prefix_list + attr_size) {
        LOG_ERROR("Address of starting prefix %p is not inside prefix-list "
                  "attribute of total length %" PRIu32
                  " starting at address %p",
                  (void *)start, attr_size, (void *)prefix_list);
        rc = -1;
    }
    RC_CHECK(rc, out);
    struct sxp_prefix *candidate = NULL;
    if (start) {
        uint8_t length_bits = 0;
        rc = sxp_parse_prefix(start, NULL, 0, &length_bits);
        RC_CHECK(rc, out);
        size_t length_bytes = length_bits / 8 + (length_bits % 8 > 0);
        candidate = OFFSET_PTR(start, sizeof(uint8_t) + length_bytes);
    } else {
        candidate =
            OFFSET_PTR(prefix_list, sxp_attr_get_head_size(prefix_list));
    }
    if ((uint8_t *)candidate >= (uint8_t *)prefix_list + attr_size) {
        *next = NULL;
    } else {
        uint8_t cand_bits_length = 0;
        rc = sxp_parse_prefix(candidate, NULL, 0, &cand_bits_length);
        RC_CHECK(rc, out);
        const uint8_t cand_length =
            cand_bits_length / 8 + (cand_bits_length % 8 > 0);
        if ((uint8_t *)candidate + cand_length >
            (uint8_t *)prefix_list + attr_size) {
            LOG_ERROR("Candidate prefix at address %p of length %" PRIu8
                      " crossess boundary of prefix-list at address %p of "
                      "length %" PRIu8,
                      (void *)candidate, cand_length, (void *)prefix_list,
                      attr_size);
            *code = SXP_ERR_CODE_UPDATE;
            *subcode = SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE;
        } else {
            *next = candidate;
        }
    }
out:
    return rc;
}

static int sxp_v1_tlv_get_type(struct sxp_v1_tlv *tlv,
                               enum sxp_v1_tlv_type *type,
                               enum sxp_error_code *code,
                               enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, tlv, type, code, subcode);
    RC_CHECK(rc, out);
    uint32_t tmp = ((uint32_t *)tlv)[0];
    switch (tmp) {
    case SXP_V1_TLV_SGT:
        *type = SXP_V1_TLV_SGT;
        break;
    case SXP_V1_TLV_PREFIX_LENGTH:
        *type = SXP_V1_TLV_PREFIX_LENGTH;
        break;
    default:
        LOG_ERROR("Unknown v1 tlv type %" PRIu32, tmp);
        *subcode = SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE;
        break;
    }
out:
    return rc;
}

static int sxp_v1_tlv_get_length(struct sxp_v1_tlv *tlv, uint32_t *length)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, tlv, length);
    RC_CHECK(rc, out);
    *length = *(uint32_t *)OFFSET_PTR(tlv, sizeof(uint32_t));
out:
    return rc;
}

static int sxp_v1_tlv_get_total_size(bool nbo, struct sxp_v1_tlv *tlv,
                                     size_t *size)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, tlv, size);
    RC_CHECK(rc, out);
    uint32_t length = 0;
    RC_CHECK(rc = sxp_v1_tlv_get_length(tlv, &length), out);
    /* type (4 octets) + length (4 octets) + variable length */
    if (nbo) {
        *size = sizeof(uint32_t) + sizeof(uint32_t) + ntohl(length);
    } else {
        *size = sizeof(uint32_t) + sizeof(uint32_t) + length;
    }
out:
    return rc;
}

static int sxp_v1_attr_parse_tlv(bool nbo_tlvs, struct sxp_attribute *attr,
                                 struct sxp_v1_tlv *previous,
                                 struct sxp_v1_tlv **next,
                                 enum sxp_error_code *code,
                                 enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, attr, next, code, subcode);
    RC_CHECK(rc, out);
    enum sxp_attr_type type = SXP_ATTR_TYPE_NODE_ID;
    RC_CHECK(rc = sxp_attr_get_type(attr, &type), out);
    if (SXP_ATTR_TYPE_ADD_IPV4 != type && SXP_ATTR_TYPE_ADD_IPV6 != type &&
        SXP_ATTR_TYPE_DEL_IPV4 != type && SXP_ATTR_TYPE_DEL_IPV6 != type) {
        LOG_ERROR("Attempt to parse v1 attr of unexpected %s type",
                  sxp_attr_type_string(type));
        rc = -1;
        goto out;
    }
    struct sxp_v1_tlv *candidate = NULL;
    if (previous) {
        size_t tlv_size = 0;
        rc = sxp_v1_tlv_get_total_size(nbo_tlvs, previous, &tlv_size);
        RC_CHECK(rc, out);
        candidate = OFFSET_PTR(previous, tlv_size);
    } else {
        size_t skip = sizeof(((struct v4_v6_prefix *)0)->ip.v4);
        if (SXP_ATTR_TYPE_ADD_IPV6 == type || SXP_ATTR_TYPE_DEL_IPV6 == type) {
            skip = sizeof(((struct v4_v6_prefix *)0)->ip.v6);
        }
        candidate = OFFSET_PTR(attr, SXP_NC_ATTR_HEAD_SIZE + skip);
    }
    uint32_t attr_size = 0;
    RC_CHECK(rc = sxp_attr_get_total_size(false, attr, &attr_size), out);
    if ((uint8_t *)candidate >= (uint8_t *)OFFSET_PTR(attr, attr_size)) {
        /* no more TLVs, candidate address is out of this attributes space */
        *next = NULL;
    } else {
        size_t cand_size = 0;
        rc = sxp_v1_tlv_get_total_size(nbo_tlvs, candidate, &cand_size);
        RC_CHECK(rc, out);
        uint8_t *cand_end = OFFSET_PTR(candidate, cand_size);
        uint8_t *attr_end = OFFSET_PTR(attr, attr_size);
        if (cand_end > attr_end) {
            LOG_ERROR("Candidate V1 TLV at address %p with size %zu crosses "
                      "attribute boundary of attribute %p with length %" PRIu32
                      " by %zu bytes",
                      (void *)candidate, cand_size, (void *)attr, attr_size,
                      cand_end - attr_end);
            *subcode = SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE_LIST;
        } else {
            *next = candidate;
        }
    }
out:
    return rc;
}

static int sxp_v1_tlv_sgt_get_sgt(struct sxp_v1_tlv *tlv, uint16_t *sgt,
                                  enum sxp_error_code *code,
                                  enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, tlv, sgt, code, subcode);
    RC_CHECK(rc, out);
    enum sxp_v1_tlv_type type = SXP_V1_TLV_SGT;
    RC_CHECK(rc = sxp_v1_tlv_get_type(tlv, &type, code, subcode), out);
    if (SXP_V1_TLV_SGT != type) {
        LOG_ERROR("Attempt to get SGT from v1 TLV which is of %s type",
                  sxp_v1_tlv_type_string(type));
        rc = -1;
        goto out;
    }
    *sgt = *(uint16_t *)OFFSET_PTR(tlv, SXP_V1_TLV_HEAD_SIZE);
out:
    return rc;
}

static int sxp_v1_tlv_sgt_set_sgt(struct sxp_v1_tlv *tlv, uint16_t sgt)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, tlv);
    RC_CHECK(rc, out);
    enum sxp_v1_tlv_type type = SXP_V1_TLV_SGT;
    enum sxp_error_code code = SXP_ERR_CODE_NONE;
    enum sxp_error_sub_code subcode = SXP_SUB_ERR_CODE_NONE;
    rc = sxp_v1_tlv_get_type(tlv, &type, &code, &subcode);
    RC_CHECK(rc, out);
    if (sxp_isnotok(rc, code, subcode)) {
        LOG_ERROR("Internal error, parsing error indicated");
        rc = -1;
        goto out;
    }
    if (SXP_V1_TLV_SGT != type) {
        LOG_ERROR("Attempt to set SGT for v1 TLV which is of %s type",
                  sxp_v1_tlv_type_string(type));
        rc = -1;
        goto out;
    }
    *(uint16_t *)OFFSET_PTR(tlv, SXP_V1_TLV_HEAD_SIZE) = sgt;
out:
    return rc;
}

static int sxp_v1_tlv_set_type(struct sxp_v1_tlv *tlv, uint32_t type)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, tlv);
    RC_CHECK(rc, out);
    *(uint32_t *)tlv = type;
out:
    return rc;
}

static int sxp_v1_tlv_set_length(struct sxp_v1_tlv *tlv, uint32_t length)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, tlv);
    RC_CHECK(rc, out);
    *(uint32_t *)OFFSET_PTR(tlv, sizeof(uint32_t)) = length;
out:
    return rc;
}

static int sxp_v1_tlv_prefix_length_get_prefix_length(
    struct sxp_v1_tlv *tlv, uint8_t *prefix_len, enum sxp_error_code *code,
    enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, tlv, prefix_len, code, subcode);
    RC_CHECK(rc, out);
    enum sxp_v1_tlv_type tlv_type = SXP_V1_TLV_SGT;
    rc = sxp_v1_tlv_get_type(tlv, &tlv_type, code, subcode);
    if (sxp_isnotok(rc, *code, *subcode)) {
        goto out;
    }
    if (SXP_V1_TLV_PREFIX_LENGTH != tlv_type) {
        LOG_ERROR("Attempt to get prefix length from %s TLV, expected %s TLV",
                  sxp_v1_tlv_type_string(tlv_type),
                  sxp_v1_tlv_type_string(SXP_V1_TLV_PREFIX_LENGTH));
        rc = -1;
        goto out;
    }
    const uint32_t expected_length = 1;
    uint32_t length = 0;
    RC_CHECK(rc = sxp_v1_tlv_get_length(tlv, &length), out);
    if (expected_length != length) {
        LOG_ERROR("Unexpected %s TLV length %" PRIu32
                  ", expected length is %" PRIu32,
                  sxp_v1_tlv_type_string(SXP_V1_TLV_PREFIX_LENGTH),
                  expected_length, length);
        *subcode = SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE;
        goto out;
    }
    *prefix_len = ((uint8_t *)OFFSET_PTR(tlv, sizeof(SXP_V1_TLV_HEAD_SIZE)))[0];
out:
    return rc;
}

static int sxp_v1_tlv_prefix_length_set_prefix_length(struct sxp_v1_tlv *tlv,
                                                      uint8_t prefix_len)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, tlv);
    RC_CHECK(rc, out);
    enum sxp_v1_tlv_type tlv_type = SXP_V1_TLV_SGT;
    enum sxp_error_code code = SXP_ERR_CODE_NONE;
    enum sxp_error_sub_code subcode = SXP_SUB_ERR_CODE_NONE;
    RC_CHECK(rc = sxp_v1_tlv_get_type(tlv, &tlv_type, &code, &subcode), out);
    if (sxp_isnotok(rc, code, subcode)) {
        rc = -1;
        goto out;
    }
    if (SXP_V1_TLV_PREFIX_LENGTH != tlv_type) {
        LOG_ERROR("Attempt to get prefix length from %s TLV, expected %s TLV",
                  sxp_v1_tlv_type_string(tlv_type),
                  sxp_v1_tlv_type_string(SXP_V1_TLV_PREFIX_LENGTH));
        rc = -1;
        goto out;
    }
    const uint32_t expected_length = 1;
    uint32_t length = 0;
    RC_CHECK(rc = sxp_v1_tlv_get_length(tlv, &length), out);
    if (expected_length != length) {
        LOG_ERROR("Unexpected %s TLV length %" PRIu32
                  ", expected length is %" PRIu32,
                  sxp_v1_tlv_type_string(SXP_V1_TLV_PREFIX_LENGTH),
                  expected_length, length);
        rc = -1;
        goto out;
    }
    ((uint8_t *)OFFSET_PTR(tlv, sizeof(SXP_V1_TLV_HEAD_SIZE)))[0] = prefix_len;
out:
    return rc;
}

/**
 * @brief parse add-ipv4 attribute
 *
 * @param add_ipv4 attribute to parse
 * @param buffer storage for parsed ipv4 prefix
 * @param buffer_size size of storage buffer
 * @param sgt storage for parsed source group tag
 * @param have_prefix_length flag set to true if prefix length is present
 * @param prefix_length prefix length, if present
 * @param code error code found while processing attribute
 * @param subcode error sub-code found while processing attribute
 *
 * @return 0 on success, -1 on error
 */
int sxp_parse_add_ipv4(struct sxp_attribute *add_ipv4, uint8_t *buffer,
                       size_t buffer_size, uint16_t *sgt,
                       bool *have_prefix_length, uint8_t *prefix_length,
                       enum sxp_error_code *code,
                       enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, add_ipv4, buffer, sgt, have_prefix_length,
                     prefix_length, code, subcode);
    RC_CHECK(rc, out);
    const uint32_t prefix_size = sizeof(((struct v4_v6_prefix *)0)->ip.v4);
    if (buffer_size < prefix_size) {
        LOG_ERROR("Buffer of size %zu is too small to hold v4 prefix of size "
                  "%" PRIu32,
                  buffer_size, prefix_size);
        rc = -1;
        goto out;
    }
    enum sxp_attr_type type = SXP_ATTR_TYPE_NODE_ID;
    RC_CHECK(rc = sxp_attr_get_type(add_ipv4, &type), out);
    if (SXP_ATTR_TYPE_ADD_IPV4 != type) {
        LOG_ERROR("Attempt to parse %s attribute as %s attribute",
                  sxp_attr_type_string(type),
                  sxp_attr_type_string(SXP_ATTR_TYPE_ADD_IPV4));
        rc = -1;
        goto out;
    }
    uint32_t length = sxp_attr_get_length(false, add_ipv4);
    if (prefix_size > length) {
        LOG_ERROR("Unexpected size %" PRIu32
                  " of IPv4 address, expected the size to be at least %" PRIu32,
                  length, prefix_size);
        *subcode = SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE;
        goto out;
    }
    memcpy(buffer, OFFSET_PTR(add_ipv4, SXP_NC_ATTR_HEAD_SIZE), length);
    struct sxp_v1_tlv *tlv = NULL;
    bool found_sgt = false;
    bool found_prefix_length = false;
    for (;;) {
        rc = sxp_v1_attr_parse_tlv(false, add_ipv4, tlv, &tlv, code, subcode);
        if (sxp_isnotok(rc, *code, *subcode)) {
            goto out;
        }
        if (!tlv) {
            break;
        }
        enum sxp_v1_tlv_type tlv_type = SXP_V1_TLV_SGT;
        rc = sxp_v1_tlv_get_type(tlv, &tlv_type, code, subcode);
        if (sxp_isnotok(rc, *code, *subcode)) {
            goto out;
        }
        switch (tlv_type) {
        case SXP_V1_TLV_SGT:
            if (found_sgt) {
                LOG_ERROR("Found duplicate %s while parsing %s attribute",
                          sxp_v1_tlv_type_string(SXP_V1_TLV_SGT),
                          sxp_attr_type_string(SXP_ATTR_TYPE_ADD_IPV4));
                *subcode = SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE;
                goto out;
            }
            found_sgt = true;
            rc = sxp_v1_tlv_sgt_get_sgt(tlv, sgt, code, subcode);
            if (sxp_isnotok(rc, *code, *subcode)) {
                goto out;
            }
            break;
        case SXP_V1_TLV_PREFIX_LENGTH:
            if (found_prefix_length) {
                LOG_ERROR("Found duplicate %s while parsing %s attribute",
                          sxp_v1_tlv_type_string(tlv_type),
                          sxp_attr_type_string(SXP_ATTR_TYPE_ADD_IPV4));
                *subcode = SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE;
                goto out;
            }
            found_prefix_length = true;
            *have_prefix_length = true;
            rc = sxp_v1_tlv_prefix_length_get_prefix_length(tlv, prefix_length,
                                                            code, subcode);
            if (sxp_isnotok(rc, *code, *subcode)) {
                goto out;
            }
            break;
        }
    }
    if (!found_sgt) {
        LOG_ERROR("%s attribute without mandatory %s TLV",
                  sxp_attr_type_string(SXP_ATTR_TYPE_ADD_IPV4),
                  sxp_v1_tlv_type_string(SXP_V1_TLV_SGT));
        *subcode = SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE;
    }
out:
    return rc;
}

/**
 * @brief parse add-ipv6 attribute
 *
 * @param add_ipv6 attribute to parse
 * @param buffer storage for parsed ipv6 prefix
 * @param buffer_size size of storage buffer
 * @param sgt storage for parsed source group tag
 * @param have_prefix_length flag set to true if prefix length is present
 * @param prefix_length prefix length, if present
 * @param code error code found while processing attribute
 * @param subcode error sub-code found while processing attribute
 *
 * @return 0 on success, -1 on error
 */
int sxp_parse_add_ipv6(struct sxp_attribute *add_ipv6, uint8_t *buffer,
                       size_t buffer_size, uint16_t *sgt,
                       bool *have_prefix_length, uint8_t *prefix_length,
                       enum sxp_error_code *code,
                       enum sxp_error_sub_code *subcode)

{
    int rc = 0;
    PARAM_NULL_CHECK(rc, add_ipv6, buffer, sgt, have_prefix_length,
                     prefix_length, code, subcode);
    RC_CHECK(rc, out);
    const uint32_t prefix_size = sizeof(((struct v4_v6_prefix *)0)->ip.v6);
    if (buffer_size < prefix_size) {
        LOG_ERROR("Buffer of size %zu is too small to hold v4 prefix of size "
                  "%" PRIu32,
                  buffer_size, prefix_size);
        rc = -1;
        goto out;
    }
    enum sxp_attr_type type = SXP_ATTR_TYPE_NODE_ID;
    RC_CHECK(rc = sxp_attr_get_type(add_ipv6, &type), out);
    if (SXP_ATTR_TYPE_ADD_IPV6 != type) {
        LOG_ERROR("Attempt to parse %s attribute as %s attribute",
                  sxp_attr_type_string(type),
                  sxp_attr_type_string(SXP_ATTR_TYPE_ADD_IPV6));
        rc = -1;
        goto out;
    }
    uint32_t length = sxp_attr_get_length(false, add_ipv6);
    if (prefix_size > length) {
        LOG_ERROR("Unexpected size %" PRIu32
                  " of IPv6 address, expected the size to be at least%" PRIu32,
                  length, prefix_size);
        *subcode = SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE;
        goto out;
    }
    memcpy(buffer, OFFSET_PTR(add_ipv6, SXP_NC_ATTR_HEAD_SIZE), length);
    struct sxp_v1_tlv *tlv = NULL;
    bool found_sgt = false;
    bool found_prefix_length = false;
    for (;;) {
        rc = sxp_v1_attr_parse_tlv(false, add_ipv6, tlv, &tlv, code, subcode);
        if (sxp_isnotok(rc, *code, *subcode)) {
            goto out;
        }
        if (!tlv) {
            break;
        }
        enum sxp_v1_tlv_type tlv_type = SXP_V1_TLV_SGT;
        rc = sxp_v1_tlv_get_type(tlv, &tlv_type, code, subcode);
        if (sxp_isnotok(rc, *code, *subcode)) {
            goto out;
        }
        switch (tlv_type) {
        case SXP_V1_TLV_SGT:
            if (found_sgt) {
                LOG_ERROR("Found duplicate %s while parsing %s attribute",
                          sxp_v1_tlv_type_string(SXP_V1_TLV_SGT),
                          sxp_attr_type_string(SXP_ATTR_TYPE_ADD_IPV6));
                *subcode = SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE;
                goto out;
            }
            found_sgt = true;
            rc = sxp_v1_tlv_sgt_get_sgt(tlv, sgt, code, subcode);
            if (sxp_isnotok(rc, *code, *subcode)) {
                goto out;
            }
            break;
        case SXP_V1_TLV_PREFIX_LENGTH:
            if (found_prefix_length) {
                LOG_ERROR("Found duplicate %s while parsing %s attribute",
                          sxp_v1_tlv_type_string(tlv_type),
                          sxp_attr_type_string(SXP_ATTR_TYPE_ADD_IPV6));
                *subcode = SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE;
                goto out;
            }
            found_prefix_length = true;
            *have_prefix_length = true;
            rc = sxp_v1_tlv_prefix_length_get_prefix_length(tlv, prefix_length,
                                                            code, subcode);
            if (sxp_isnotok(rc, *code, *subcode)) {
                goto out;
            }
            break;
        }
    }
    if (!found_sgt) {
        LOG_ERROR("%s attribute without mandatory %s TLV",
                  sxp_attr_type_string(SXP_ATTR_TYPE_ADD_IPV6),
                  sxp_v1_tlv_type_string(SXP_V1_TLV_SGT));
        *subcode = SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE;
    }
out:
    return rc;
}

/**
 * @brief parse del-ipv4 attribute
 *
 * @param del_ipv4 attribute to parse
 * @param buffer storage for parsed ipv4 prefix
 * @param buffer_size size of storage buffer
 * @param have_prefix_length flag set to true if prefix length is present
 * @param prefix_length prefix length, if present
 * @param code error code found while processing attribute
 * @param subcode error sub-code found while processing attribute
 *
 * @return 0 on success, -1 on error
 */
int sxp_parse_del_ipv4(struct sxp_attribute *del_ipv4, uint8_t *buffer,
                       size_t buffer_size, bool *have_prefix_length,
                       uint8_t *prefix_length, enum sxp_error_code *code,
                       enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, del_ipv4, buffer, have_prefix_length, prefix_length,
                     code, subcode);
    RC_CHECK(rc, out);
    const uint32_t prefix_size = sizeof(((struct v4_v6_prefix *)0)->ip.v4);
    if (buffer_size < prefix_size) {
        LOG_ERROR("Buffer of size %zu is too small to hold v4 prefix of size "
                  "%" PRIu32,
                  buffer_size, prefix_size);
        rc = -1;
        goto out;
    }
    enum sxp_attr_type type = SXP_ATTR_TYPE_NODE_ID;
    RC_CHECK(rc = sxp_attr_get_type(del_ipv4, &type), out);
    if (SXP_ATTR_TYPE_DEL_IPV4 != type) {
        LOG_ERROR("Attempt to parse %s attribute as %s attribute",
                  sxp_attr_type_string(type),
                  sxp_attr_type_string(SXP_ATTR_TYPE_DEL_IPV4));
        rc = -1;
        goto out;
    }
    uint32_t length = sxp_attr_get_length(false, del_ipv4);
    if (prefix_size > length) {
        LOG_ERROR("Unexpected size %" PRIu32
                  " of IPv4 address, expected the size to be at least%" PRIu32,
                  length, prefix_size);
        *subcode = SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE;
        goto out;
    }
    memcpy(buffer, OFFSET_PTR(del_ipv4, SXP_NC_ATTR_HEAD_SIZE), length);
    struct sxp_v1_tlv *tlv = NULL;
    bool found_prefix_length = false;
    for (;;) {
        rc = sxp_v1_attr_parse_tlv(false, del_ipv4, tlv, &tlv, code, subcode);
        if (sxp_isnotok(rc, *code, *subcode)) {
            goto out;
        }
        if (!tlv) {
            break;
        }
        enum sxp_v1_tlv_type tlv_type = SXP_V1_TLV_SGT;
        rc = sxp_v1_tlv_get_type(tlv, &tlv_type, code, subcode);
        if (sxp_isnotok(rc, *code, *subcode)) {
            goto out;
        }
        switch (tlv_type) {
        case SXP_V1_TLV_SGT:
            LOG_ERROR("Found unexpected %s TLV while parsing %s attribute",
                      sxp_v1_tlv_type_string(SXP_V1_TLV_SGT),
                      sxp_attr_type_string(SXP_ATTR_TYPE_DEL_IPV4));
            *subcode = SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE;
            goto out;
        case SXP_V1_TLV_PREFIX_LENGTH:
            if (found_prefix_length) {
                LOG_ERROR("Found duplicate %s while parsing %s attribute",
                          sxp_v1_tlv_type_string(SXP_V1_TLV_PREFIX_LENGTH),
                          sxp_attr_type_string(SXP_ATTR_TYPE_DEL_IPV4));
                *subcode = SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE;
                goto out;
            }
            found_prefix_length = true;
            *have_prefix_length = true;
            rc = sxp_v1_tlv_prefix_length_get_prefix_length(tlv, prefix_length,
                                                            code, subcode);
            if (sxp_isnotok(rc, *code, *subcode)) {
                goto out;
            }
            break;
        }
    }
out:
    return rc;
}

/**
 * @brief parse del-ipv6 attribute
 *
 * @param del_ipv6 attribute to parse
 * @param buffer storage for parsed ipv6 prefix
 * @param buffer_size size of storage buffer
 * @param have_prefix_length flag set to true if prefix length is present
 * @param prefix_length prefix length, if present
 * @param code error code found while processing attribute
 * @param subcode error sub-code found while processing attribute
 *
 * @return 0 on success, -1 on error
 */
int sxp_parse_del_ipv6(struct sxp_attribute *del_ipv6, uint8_t *buffer,
                       size_t buffer_size, bool *have_prefix_length,
                       uint8_t *prefix_length, enum sxp_error_code *code,
                       enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, del_ipv6, buffer, have_prefix_length, prefix_length,
                     code, subcode);
    RC_CHECK(rc, out);
    const uint32_t prefix_size = sizeof(((struct v4_v6_prefix *)0)->ip.v6);
    if (buffer_size < prefix_size) {
        LOG_ERROR("Buffer of size %zu is too small to hold v4 prefix of size "
                  "%" PRIu32,
                  buffer_size, prefix_size);
        rc = -1;
        goto out;
    }
    enum sxp_attr_type type = SXP_ATTR_TYPE_NODE_ID;
    RC_CHECK(rc = sxp_attr_get_type(del_ipv6, &type), out);
    if (SXP_ATTR_TYPE_DEL_IPV6 != type) {
        LOG_ERROR("Attempt to parse %s attribute as %s attribute",
                  sxp_attr_type_string(type),
                  sxp_attr_type_string(SXP_ATTR_TYPE_DEL_IPV6));
        rc = -1;
        goto out;
    }
    uint32_t length = sxp_attr_get_length(false, del_ipv6);
    if (prefix_size > length) {
        LOG_ERROR("Unexpected size %" PRIu32
                  " of IPv6 address, expected the size to be %" PRIu32,
                  length, prefix_size);
        *subcode = SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE;
        goto out;
    }
    memcpy(buffer, OFFSET_PTR(del_ipv6, SXP_NC_ATTR_HEAD_SIZE), length);
    struct sxp_v1_tlv *tlv = NULL;
    bool found_prefix_length = false;
    for (;;) {
        rc = sxp_v1_attr_parse_tlv(false, del_ipv6, tlv, &tlv, code, subcode);
        if (sxp_isnotok(rc, *code, *subcode)) {
            goto out;
        }
        if (!tlv) {
            break;
        }
        enum sxp_v1_tlv_type tlv_type = SXP_V1_TLV_SGT;
        rc = sxp_v1_tlv_get_type(tlv, &tlv_type, code, subcode);
        if (sxp_isnotok(rc, *code, *subcode)) {
            goto out;
        }
        switch (tlv_type) {
        case SXP_V1_TLV_SGT:
            LOG_ERROR("Found unexpected %s TLV while parsing %s attribute",
                      sxp_v1_tlv_type_string(SXP_V1_TLV_SGT),
                      sxp_attr_type_string(SXP_ATTR_TYPE_DEL_IPV6));
            *subcode = SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE;
            goto out;
        case SXP_V1_TLV_PREFIX_LENGTH:
            if (found_prefix_length) {
                LOG_ERROR("Found duplicate %s while parsing %s attribute",
                          sxp_v1_tlv_type_string(SXP_V1_TLV_PREFIX_LENGTH),
                          sxp_attr_type_string(SXP_ATTR_TYPE_DEL_IPV6));
                *subcode = SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE;
                goto out;
            }
            found_prefix_length = true;
            *have_prefix_length = true;
            rc = sxp_v1_tlv_prefix_length_get_prefix_length(tlv, prefix_length,
                                                            code, subcode);
            if (sxp_isnotok(rc, *code, *subcode)) {
                goto out;
            }
            break;
        }
    }
out:
    return rc;
}

static int sxp_v1_tlv_hton_swap(struct sxp_v1_tlv *tlv,
                                enum sxp_error_code *code,
                                enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, tlv, code, subcode);
    RC_CHECK(rc, out);
    enum sxp_v1_tlv_type type = SXP_V1_TLV_SGT;
    rc = sxp_v1_tlv_get_type(tlv, &type, code, subcode);
    if (sxp_isnotok(rc, *code, *subcode)) {
        goto out;
    }
    switch (type) {
    case SXP_V1_TLV_SGT:
        do {
            uint16_t sgt = 0;
            rc = sxp_v1_tlv_sgt_get_sgt(tlv, &sgt, code, subcode);
            if (sxp_isnotok(rc, *code, *subcode)) {
                goto out;
            }
            rc = sxp_v1_tlv_sgt_set_sgt(tlv, htons(sgt));
            RC_CHECK(rc, out);
        } while (0);
        break;
    case SXP_V1_TLV_PREFIX_LENGTH:
        /* no swapping needed here */
        break;
    }
    uint32_t length = 0;
    RC_CHECK(rc = sxp_v1_tlv_get_length(tlv, &length), out);
    RC_CHECK(rc = sxp_v1_tlv_set_type(tlv, htonl(type)), out);
    RC_CHECK(rc = sxp_v1_tlv_set_length(tlv, htonl(length)), out);
out:
    return rc;
}

static int sxp_v1_attr_hton_swap(struct sxp_attribute *attr,
                                 enum sxp_error_code *code,
                                 enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, attr, code, subcode);
    RC_CHECK(rc, out);
    struct sxp_v1_tlv *tlv = NULL;
    struct sxp_v1_tlv *tlv_to_swap = NULL;
    for (;;) {
        rc = sxp_v1_attr_parse_tlv(false, attr, tlv, &tlv, code, subcode);
        RC_CHECK(rc, out);
        if (!tlv) {
            break;
        }
        if (tlv_to_swap) {
            rc = sxp_v1_tlv_hton_swap(tlv_to_swap, code, subcode);
            if (sxp_isnotok(rc, *code, *subcode)) {
                goto out;
            }
        }
        tlv_to_swap = tlv;
    }
    if (tlv_to_swap) {
        rc = sxp_v1_tlv_hton_swap(tlv_to_swap, code, subcode);
    }
out:
    return rc;
}

static int sxp_attribute_hton_swap(struct sxp_attribute *attr,
                                   enum sxp_error_code *code,
                                   enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    enum sxp_attr_type type = SXP_ATTR_TYPE_NODE_ID;
    PARAM_NULL_CHECK(rc, attr, code, subcode);
    RC_CHECK(rc, out);
    RC_CHECK(rc = sxp_attr_get_type(attr, &type), out);
    switch (type) {
    case SXP_ATTR_TYPE_ADD_IPV4:
    /* fallthrough */
    case SXP_ATTR_TYPE_ADD_IPV6:
    /* fallthrough */
    case SXP_ATTR_TYPE_DEL_IPV4:
    /* fallthrough */
    case SXP_ATTR_TYPE_DEL_IPV6:
        rc = sxp_v1_attr_hton_swap(attr, code, subcode);
        break;

    case SXP_ATTR_TYPE_NODE_ID:
        do {
            uint32_t node_id = 0;
            RC_CHECK(rc = sxp_attr_node_id_get_node_id(attr, &node_id), out);
            rc = sxp_attr_node_id_set_node_id(attr, htonl(node_id));
            RC_CHECK(rc, out);
        } while (0);
        break;
    case SXP_ATTR_TYPE_CAPABILITIES:
        /* no swapping needed for capabilities */
        break;
    case SXP_ATTR_TYPE_HOLD_TIME:
        if (sxp_attr_is_compact(attr)) {
            if (sxp_attr_is_extended(attr)) {
                LOG_ERROR("Unable to swap compact, extended hold-time");
                rc = -1;
            } else {
                uint16_t val = 0;
                rc = sxp_attr_hold_time_get_min_val(attr, &val, code, subcode);
                if (sxp_isnotok(rc, *code, *subcode)) {
                    goto out;
                }
                rc = sxp_attr_hold_time_set_min_val(attr, htons(val));
                RC_CHECK(rc, out);
                if (4 == sxp_attr_get_length(false, attr)) {
                    rc = sxp_attr_hold_time_get_max_val(attr, &val, code,
                                                        subcode);
                    if (sxp_isnotok(rc, *code, *subcode)) {
                        goto out;
                    }
                    rc = sxp_attr_hold_time_set_max_val(attr, htons(val));
                    RC_CHECK(rc, out);
                }
            }
        } else {
            LOG_ERROR("Unable to swap non-compact, extended hold-time");
            rc = -1;
        }
        break;
    case SXP_ATTR_TYPE_IPV4_ADD_PREFIX:
    /* fallthrough */
    case SXP_ATTR_TYPE_IPV4_DEL_PREFIX:
        /* no swapping needed */
        break;
    case SXP_ATTR_TYPE_IPV6_ADD_PREFIX:
    /* fallthrough */
    case SXP_ATTR_TYPE_IPV6_DEL_PREFIX:
        /* no swapping needed */
        break;
    case SXP_ATTR_TYPE_SGT:
        do {
            uint16_t tmp = 0;
            RC_CHECK(rc = sxp_attr_sgt_get_sgt(attr, &tmp), out);
            RC_CHECK(rc = sxp_attr_sgt_set_sgt(attr, htons(tmp)), out);
        } while (0);
        break;
    case SXP_ATTR_TYPE_PEER_SEQUENCE:
        do {
            size_t count = 0;
            uint32_t *arr = NULL;
            rc = sxp_parse_peer_sequence_internal(attr, &count, &arr, code,
                                                  subcode);
            RC_CHECK(rc, out);
            size_t i = 0;
            for (i = 0; i < count; ++i) {
                arr[i] = htonl(arr[i]);
            }
        } while (0);
        break;
    }
    if (sxp_attr_is_compact(attr)) {
        if (sxp_attr_is_extended(attr)) {
            ((uint16_t *)attr)[1] = htons(((uint16_t *)attr)[1]);
        } else {
            /* no swap here, as length is 1 byte only */
        }
    } else {
        ((uint32_t *)attr)[0] = htonl(((uint32_t *)attr)[0]);
        ((uint32_t *)attr)[1] = htonl(((uint32_t *)attr)[1]);
    }
out:
    return rc;
}

static int sxp_msg_attributes_hton_swap(struct sxp_msg *msg,
                                        enum sxp_error_code *code,
                                        enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, msg, code, subcode);
    RC_CHECK(rc, out);
    /* sxp_parse_msg relies on host-byte order, so first fetch next
     * attribute,
     * then swap previous one */
    struct sxp_attribute *attr_to_swap = NULL;
    struct sxp_attribute *attr = NULL;
    while (sxp_isok(rc, *code, *subcode)) {
        rc = sxp_parse_msg(msg, attr, &attr, code, subcode);
        if (sxp_isnotok(rc, *code, *subcode)) {
            break;
        }
        if (!attr) {
            break;
        }
        if (attr_to_swap) {
            rc = sxp_attribute_hton_swap(attr_to_swap, code, subcode);
        }
        attr_to_swap = attr;
    }
    if (attr_to_swap && sxp_isok(rc, *code, *subcode)) {
        rc = sxp_attribute_hton_swap(attr_to_swap, code, subcode);
    }
out:
    return rc;
}

static int sxp_open_hton_swap(struct sxp_msg *msg, enum sxp_error_code *code,
                              enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, msg, code, subcode);
    if (RC_ISOK(rc)) {
        void *open = OFFSET_PTR(msg, SXP_MSG_SIZE);
        SXP_OPEN_SET_MODE(open, htonl(SXP_OPEN_GET_MODE(open)));
        SXP_OPEN_SET_VERSION(open, htonl(SXP_OPEN_GET_VERSION(open)));
        rc = sxp_msg_attributes_hton_swap(msg, code, subcode);
    }
    return rc;
}

static int sxp_update_hton_swap(struct sxp_msg *msg, enum sxp_error_code *code,
                                enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, msg, code, subcode);
    if (RC_ISOK(rc)) {
        rc = sxp_msg_attributes_hton_swap(msg, code, subcode);
    }
    return rc;
}

/**
 * @brief swap the relevant fields of given SXP message from host to network
 * byte order
 *
 * @param msg message to swap
 * @param code error code found while processing message
 * @param subcode error sub-code found while processing message
 *
 * @return 0 on success, -1 on error
 */
int sxp_msg_hton_swap(struct sxp_msg *msg, enum sxp_error_code *code,
                      enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, msg, code, subcode);
    if (RC_ISOK(rc)) {
        switch (msg->type) {
        case SXP_MSG_OPEN:
        /* fallthrough */
        case SXP_MSG_OPEN_RESP:
            rc = sxp_open_hton_swap(msg, code, subcode);
            break;

        case SXP_MSG_UPDATE:
            rc = sxp_update_hton_swap(msg, code, subcode);
            break;

        case SXP_MSG_ERROR:
            do {
                void *err = OFFSET_PTR(msg, SXP_MSG_SIZE);
                if (!SXP_ERROR_GET_EXTENDED(err)) {
                    *(uint32_t *)err = htonl(*(uint32_t *)err);
                }
            } while (0);
            break;

        case SXP_MSG_PURGE_ALL:
            /* no swapping needed for purge-all message */
            break;

        case SXP_MSG_KEEPALIVE:
            /* no swapping needed for keep-alive message */
            break;

        default:
            LOG_ERROR("Unknown msg type %" PRIu32
                      " while swapping to network order",
                      msg->type);
            rc = -1;
        }
    }

    if (RC_ISOK(rc) && sxp_isok(rc, *code, *subcode)) {
        msg->type = htonl(msg->type);
        msg->length = htonl(msg->length);
    }
    return rc;
}

static int sxp_v1_tlv_ntoh_swap(struct sxp_v1_tlv *tlv,
                                enum sxp_error_code *code,
                                enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, tlv, code, subcode);
    RC_CHECK(rc, out);
    /* first swap type and length to host byte order */
    ((uint32_t *)tlv)[0] = ntohl(((uint32_t *)tlv)[0]);
    ((uint32_t *)tlv)[1] = ntohl(((uint32_t *)tlv)[1]);
    enum sxp_v1_tlv_type type = SXP_V1_TLV_SGT;
    rc = sxp_v1_tlv_get_type(tlv, &type, code, subcode);
    if (sxp_isnotok(rc, *code, *subcode)) {
        goto out;
    }
    switch (type) {
    case SXP_V1_TLV_SGT:
        do {
            uint16_t sgt = 0;
            rc = sxp_v1_tlv_sgt_get_sgt(tlv, &sgt, code, subcode);
            if (sxp_isnotok(rc, *code, *subcode)) {
                goto out;
            }
            rc = sxp_v1_tlv_sgt_set_sgt(tlv, ntohs(sgt));
            RC_CHECK(rc, out);
        } while (0);
        break;
    case SXP_V1_TLV_PREFIX_LENGTH:
        /* no swapping needed here */
        break;
    }
out:
    return rc;
}

static int sxp_v1_attr_ntoh_swap(struct sxp_attribute *attr,
                                 enum sxp_error_code *code,
                                 enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, attr, code, subcode);
    RC_CHECK(rc, out);
    struct sxp_v1_tlv *tlv = NULL;
    struct sxp_v1_tlv *tlv_to_swap = NULL;
    for (;;) {
        rc = sxp_v1_attr_parse_tlv(true, attr, tlv, &tlv, code, subcode);
        RC_CHECK(rc, out);
        if (!tlv) {
            break;
        }
        if (tlv_to_swap) {
            rc = sxp_v1_tlv_ntoh_swap(tlv_to_swap, code, subcode);
            if (sxp_isnotok(rc, *code, *subcode)) {
                goto out;
            }
        }
        tlv_to_swap = tlv;
    }
    if (tlv_to_swap) {
        rc = sxp_v1_tlv_ntoh_swap(tlv_to_swap, code, subcode);
        if (sxp_isnotok(rc, *code, *subcode)) {
            goto out;
        }
    }
out:
    return rc;
}

static int sxp_attribute_ntoh_swap(struct sxp_attribute *attr,
                                   enum sxp_error_code *code,
                                   enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    enum sxp_attr_type type = SXP_ATTR_TYPE_NODE_ID;
    PARAM_NULL_CHECK(rc, attr, code, subcode);
    RC_CHECK(rc, out);
    if (sxp_attr_is_compact(attr)) {
        if (sxp_attr_is_extended(attr)) {
            ((uint16_t *)attr)[1] = ntohs(((uint16_t *)attr)[1]);
        } else {
            /* no swap here, as length is 1 byte only */
        }
    } else {
        ((uint32_t *)attr)[0] = ntohl(((uint32_t *)attr)[0]);
        ((uint32_t *)attr)[1] = ntohl(((uint32_t *)attr)[1]);
    }
    RC_CHECK(rc = sxp_attr_get_type(attr, &type), out);
    switch (type) {
    case SXP_ATTR_TYPE_ADD_IPV4:
    /* fallthrough */
    case SXP_ATTR_TYPE_ADD_IPV6:
    /* fallthrough */
    case SXP_ATTR_TYPE_DEL_IPV4:
    /* fallthrough */
    case SXP_ATTR_TYPE_DEL_IPV6:
        RC_CHECK(rc = sxp_v1_attr_ntoh_swap(attr, code, subcode), out);
        break;
    case SXP_ATTR_TYPE_NODE_ID:
        do {
            uint32_t node_id = 0;
            RC_CHECK(rc = sxp_attr_node_id_get_node_id(attr, &node_id), out);
            rc = sxp_attr_node_id_set_node_id(attr, ntohl(node_id));
            RC_CHECK(rc, out);
        } while (0);
        break;

    case SXP_ATTR_TYPE_CAPABILITIES:
        /* no swapping needed for capabilities */
        break;
    case SXP_ATTR_TYPE_HOLD_TIME:
        if (sxp_attr_is_compact(attr)) {
            if (sxp_attr_is_extended(attr)) {
                LOG_ERROR("Unable to swap compact, extended hold-time");
                rc = -1;
            } else {
                uint16_t val = 0;
                rc = sxp_attr_hold_time_get_min_val(attr, &val, code, subcode);
                if (sxp_isnotok(rc, *code, *subcode)) {
                    goto out;
                }
                rc = sxp_attr_hold_time_set_min_val(attr, ntohs(val));
                RC_CHECK(rc, out);
                if (4 == sxp_attr_get_length(false, attr)) {
                    rc = sxp_attr_hold_time_get_max_val(attr, &val, code,
                                                        subcode);
                    if (sxp_isnotok(rc, *code, *subcode)) {
                        goto out;
                    }
                    rc = sxp_attr_hold_time_set_max_val(attr, ntohs(val));
                    RC_CHECK(rc, out);
                }
            }
        } else {
            LOG_ERROR("Unable to swap non-compact, extended hold-time");
            rc = -1;
        }
        break;
    case SXP_ATTR_TYPE_IPV4_ADD_PREFIX:
    /* fallthrough */
    case SXP_ATTR_TYPE_IPV4_DEL_PREFIX:
        /* no swapping needed */
        break;
    case SXP_ATTR_TYPE_IPV6_ADD_PREFIX:
    /* fallthrough */
    case SXP_ATTR_TYPE_IPV6_DEL_PREFIX:
        /* no swapping needed */
        break;
    case SXP_ATTR_TYPE_SGT:
        do {
            uint16_t tmp = 0;
            RC_CHECK(rc = sxp_attr_sgt_get_sgt(attr, &tmp), out);
            RC_CHECK(rc = sxp_attr_sgt_set_sgt(attr, ntohs(tmp)), out);
        } while (0);
        break;
    case SXP_ATTR_TYPE_PEER_SEQUENCE:
        do {
            size_t count = 0;
            uint32_t *arr = NULL;
            rc = sxp_parse_peer_sequence_internal(attr, &count, &arr, code,
                                                  subcode);
            RC_CHECK(rc, out);
            size_t i = 0;
            for (i = 0; i < count; ++i) {
                arr[i] = ntohl(arr[i]);
            }
        } while (0);
        break;
    }
out:
    return rc;
}

static int sxp_msg_attributes_ntoh_swap(struct sxp_msg *msg,
                                        enum sxp_error_code *code,
                                        enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, msg, code, subcode);
    RC_CHECK(rc, out);
    /* calling sxp_msg_parse_internal with network byte order setting causes
     * it to rely on the network byte order for previous attribute, so first
     * fetch next one, then swap previous attribute */
    struct sxp_attribute *attr_to_swap = NULL;
    struct sxp_attribute *attr = NULL;
    while (sxp_isok(rc, *code, *subcode)) {
        rc = sxp_parse_msg_internal(msg, true, attr, &attr, code, subcode);
        if (sxp_isnotok(rc, *code, *subcode)) {
            break;
        }
        if (!attr) {
            break;
        }
        if (attr_to_swap) {
            rc = sxp_attribute_ntoh_swap(attr_to_swap, code, subcode);
        }
        attr_to_swap = attr;
    }
    if (sxp_isok(rc, *code, *subcode) && attr_to_swap) {
        rc = sxp_attribute_ntoh_swap(attr_to_swap, code, subcode);
    }
out:
    return rc;
}

static int sxp_open_ntoh_swap(struct sxp_msg *msg, enum sxp_error_code *code,
                              enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, msg, code, subcode);
    if (RC_ISOK(rc)) {
        void *open = OFFSET_PTR(msg, SXP_MSG_SIZE);
        SXP_OPEN_SET_MODE(open, ntohl(SXP_OPEN_GET_MODE(open)));
        SXP_OPEN_SET_VERSION(open, ntohl(SXP_OPEN_GET_VERSION(open)));
        rc = sxp_msg_attributes_ntoh_swap(msg, code, subcode);
    }
    return rc;
}

static int sxp_update_ntoh_swap(struct sxp_msg *msg, enum sxp_error_code *code,
                                enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, msg, code, subcode);
    if (RC_ISOK(rc)) {
        rc = sxp_msg_attributes_ntoh_swap(msg, code, subcode);
    }
    return rc;
}

/**
 * @brief swap the relevant fields of given SXP message from network to host
 * byte order
 *
 * @param msg message to swap
 * @param code error code found while processing message
 * @param subcode error sub-code found while processing message
 *
 * @return 0 on success, -1 on error
 */
int sxp_msg_ntoh_swap(struct sxp_msg *msg, enum sxp_error_code *code,
                      enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, msg, code, subcode);
    if (RC_ISOK(rc)) {
        msg->type = ntohl(msg->type);
        msg->length = ntohl(msg->length);
        switch (msg->type) {
        case SXP_MSG_OPEN:
        /* fallthrough */
        case SXP_MSG_OPEN_RESP:
            rc = sxp_open_ntoh_swap(msg, code, subcode);
            break;

        case SXP_MSG_UPDATE:
            rc = sxp_update_ntoh_swap(msg, code, subcode);
            break;

        case SXP_MSG_ERROR:
            do {
                void *err = OFFSET_PTR(msg, SXP_MSG_SIZE);
                if (!SXP_ERROR_GET_EXTENDED(err)) {
                    *(uint32_t *)err = ntohl(*(uint32_t *)err);
                }
            } while (0);
            break;

        case SXP_MSG_PURGE_ALL:
            /* no swapping needed for purge-all message */
            break;

        case SXP_MSG_KEEPALIVE:
            /* no swapping needed for keep-alive message */
            break;

        default:
            LOG_ERROR("Unknown msg type %" PRIu32
                      " while swapping to host order",
                      msg->type);
            rc = -1;
        }
    }
    return rc;
}

#define TRACE_HEXA_OCTET_QUAD(array, offset, limit, description)            \
    if (offset < limit) {                                                   \
        if (offset + 1 == limit) {                                          \
            LOG_TRACE("0x%02" PRIx8 description, array[offset]);            \
        } else if (offset + 2 == limit) {                                   \
            LOG_TRACE("0x%02" PRIx8 "%02" PRIx8 description, array[offset], \
                      array[offset + 1]);                                   \
        } else if (offset + 3 == limit) {                                   \
            LOG_TRACE("0x%02" PRIx8 "%02" PRIx8 "%02" PRIx8 description,    \
                      array[offset], array[offset + 1], array[offset + 2]); \
        } else {                                                            \
            LOG_TRACE("0x%02" PRIx8 "%02" PRIx8 "%02" PRIx8                 \
                      "%02" PRIx8 description,                              \
                      array[offset], array[offset + 1], array[offset + 2],  \
                      array[offset + 3]);                                   \
        }                                                                   \
    }

static int sxp_hbo_pretty_print_attribute_head(const struct sxp_attribute *attr)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, attr);
    RC_CHECK(rc, out);
    enum sxp_attr_type type;
    RC_CHECK(rc = sxp_attr_get_type(attr, &type), out);
    if (sxp_attr_is_compact(attr)) {
        uint8_t flags = SXP_ATTR_GET_FLAGS(attr);
        if (sxp_attr_is_extended(attr)) {
            LOG_TRACE(
                "0x" DEBUG_4B_FMT " [flags=O[%d]N[%d]P[%d]C[%d]E[%d] type=%s"
                " length=%" PRIu32 "]",
                DEBUG_4B_PRINT(((uint32_t *)attr)[0]),
                BIT_IS_SET(flags, SXP_ATTR_OPTIONAL_FLAG),
                BIT_IS_SET(flags, SXP_ATTR_NON_TRANSITIVE_FLAG),
                BIT_IS_SET(flags, SXP_ATTR_PARTIAL_FLAG),
                sxp_attr_is_compact(attr), sxp_attr_is_extended(attr),
                sxp_attr_type_string(type), sxp_attr_get_length(false, attr));
        } else {
            LOG_TRACE(
                "0x%02" PRIx8 "%02" PRIx8 "%02" PRIx8
                " [flags=O[%d]N[%d]P[%d]C[%d]E[%d] type=%s length=%" PRIu32 "]",
                *(uint8_t *)attr, *(uint8_t *)OFFSET_PTR(attr, 1),
                *(uint8_t *)OFFSET_PTR(attr, 2),
                BIT_IS_SET(flags, SXP_ATTR_OPTIONAL_FLAG),
                BIT_IS_SET(flags, SXP_ATTR_NON_TRANSITIVE_FLAG),
                BIT_IS_SET(flags, SXP_ATTR_PARTIAL_FLAG),
                sxp_attr_is_compact(attr), sxp_attr_is_extended(attr),
                sxp_attr_type_string(type), sxp_attr_get_length(false, attr));
        }
    } else {
        LOG_TRACE("0x" DEBUG_4B_FMT " [type=%s]",
                  DEBUG_4B_PRINT(((uint32_t *)attr)[0]),
                  sxp_attr_type_string(type));
        LOG_TRACE("0x" DEBUG_4B_FMT " [length=%" PRIu32 "]",
                  DEBUG_4B_PRINT(((uint32_t *)attr)[1]),
                  sxp_attr_get_length(false, attr));
    }
out:
    return rc;
}

static int
sxp_hbo_pretty_print_node_id_attribute(const struct sxp_attribute *attr)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, attr);
    RC_CHECK(rc, out);
    uint32_t node_id = 0;
    RC_CHECK(rc = sxp_attr_node_id_get_node_id(attr, &node_id), out);
    LOG_TRACE("0x" DEBUG_4B_FMT " [node_id=%" PRIu32 "]",
              DEBUG_4B_PRINT(node_id), node_id);
out:
    return rc;
}

static int
sxp_hbo_pretty_print_capabilities_attribute(struct sxp_attribute *attr,
                                            enum sxp_error_code *code,
                                            enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, attr, code, subcode);
    RC_CHECK(rc, out);
    struct sxp_capability *cap = NULL;
    while (sxp_isok(rc, *code, *subcode)) {
        rc = sxp_parse_capabilities(attr, cap, &cap, code, subcode);
        if (sxp_isnotok(rc, *code, *subcode)) {
            break;
        }
        if (!cap) {
            break;
        }
        enum sxp_capability_code cap_code = SXP_CAPABILITY_IPV4_UNICAST;
        uint8_t length = 0;
        rc = sxp_capability_get_code(cap, &cap_code);
        if (RC_ISNOTOK(rc)) {
            break;
        }
        rc = sxp_capability_get_length(cap, &length);
        if (RC_ISNOTOK(rc)) {
            break;
        }
        LOG_TRACE("0x%02" PRIx8 "%02" PRIx8 "[code=%s length=%" PRIu8 "]",
                  cap_code, length, sxp_capability_code_string(cap_code),
                  length);
        const char *value = NULL;
        rc = sxp_capability_get_value(cap, (const void **)&value);
        if (RC_ISNOTOK(rc)) {
            break;
        }
        size_t offset = 0;
        while (value && offset < length) {
            TRACE_HEXA_OCTET_QUAD(value, offset, length,
                                  " [capability value bytes]");
            offset += 4;
        }
    }
out:
    return rc;
}

static int
sxp_hbo_pretty_print_hold_time_attribute(struct sxp_attribute *attr,
                                         enum sxp_error_code *code,
                                         enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, attr, code, subcode);
    RC_CHECK(rc, out);
    uint16_t min_val = 0;
    rc = sxp_attr_hold_time_get_min_val(attr, &min_val, code, subcode);
    if (sxp_isnotok(rc, *code, *subcode)) {
        goto out;
    }
    if (4 == sxp_attr_get_length(false, attr)) {
        uint16_t max_val = 0;
        rc = sxp_attr_hold_time_get_max_val(attr, &max_val, code, subcode);
        if (sxp_isnotok(rc, *code, *subcode)) {
            goto out;
        }
        LOG_TRACE("0x%04" PRIx16 "%04" PRIx16 "[min-value=%" PRIu16
                  " max-value=%" PRIu16 "]",
                  min_val, max_val, min_val, max_val);
    } else {
        LOG_TRACE("0x%04" PRIx16 "[min-value=%" PRIu16 "]", min_val, min_val);
    }
out:
    return rc;
}

static int sxp_hbo_pretty_print_sgt_attribute(struct sxp_attribute *attr)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, attr);
    RC_CHECK(rc, out);
    uint16_t sgt = 0;
    RC_CHECK(rc = sxp_attr_sgt_get_sgt(attr, &sgt), out);
    LOG_TRACE("0x%04" PRIx16 " [tag=%" PRIu16 "]", sgt, sgt);
out:
    return rc;
}

static int sxp_hbo_pretty_print_ipv4_prefix(struct sxp_prefix *p)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, p);
    RC_CHECK(rc, out);
    uint8_t length = 0;
    struct v4_v6_prefix prefix = { 0, { { 0 } } };
    rc = sxp_parse_prefix(p, prefix.ip.data, sizeof(prefix.ip.data), &length);
    RC_CHECK(rc, out);
    const size_t bytes = length / 8 + (length % 8 > 0);
    switch (bytes) {
    case 0:
        LOG_TRACE("0x%02" PRIx8 "[length=%" PRIu8 ", prefix=" DEBUG_V4_FMT "]",
                  length, length, DEBUG_V4_PRINT(prefix.ip.v4));
        break;
    case 1:
        LOG_TRACE("0x%02" PRIx8 "%02" PRIx8 " [length=%" PRIu8
                  ", prefix=" DEBUG_V4_FMT "]",
                  length, (uint8_t)prefix.ip.data[0], length,
                  DEBUG_V4_PRINT(prefix.ip.v4));
        break;
    case 2:
        LOG_TRACE("0x%02" PRIx8 "%02" PRIx8 "%02" PRIx8 " [length=%" PRIu8
                  ", prefix=" DEBUG_V4_FMT "]",
                  length, (uint8_t)prefix.ip.data[0],
                  (uint8_t)prefix.ip.data[1], length,
                  DEBUG_V4_PRINT(prefix.ip.v4));
        break;
    case 3:
        LOG_TRACE("0x%02" PRIx8 "%02" PRIx8 "%02" PRIx8 "%02" PRIx8 "%02" PRIx8
                  " [length=%" PRIu8 " prefix=" DEBUG_V4_FMT "]",
                  length, (uint8_t)prefix.ip.data[0],
                  (uint8_t)prefix.ip.data[1], (uint8_t)prefix.ip.data[2],
                  (uint8_t)prefix.ip.data[3], length,
                  DEBUG_V4_PRINT(prefix.ip.v4));
        break;
    case 4:
        LOG_TRACE("0x%02" PRIx8 DEBUG_4B_FMT " [length=%" PRIu8
                  " prefix=" DEBUG_V4_FMT "]",
                  length, DEBUG_4B_PRINT(prefix.ip.v4), length,
                  DEBUG_V4_PRINT(prefix.ip.v4));
        break;
    default:
        LOG_ERROR("IPv4 prefix with unsupported length %" PRIu8, length);
        rc = -1;
        break;
    }
out:
    return rc;
}

static int
sxp_hbo_pretty_print_ipv4_prefix_list(struct sxp_attribute *attr,
                                      enum sxp_error_code *code,
                                      enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, attr);
    RC_CHECK(rc, out);
    struct sxp_prefix *p = NULL;
    while (1) {
        rc = sxp_parse_prefix_list(attr, p, &p, code, subcode);
        if (sxp_isnotok(rc, *code, *subcode)) {
            goto out;
        }
        if (!p) {
            break;
        }
        RC_CHECK(rc = sxp_hbo_pretty_print_ipv4_prefix(p), out);
    }
out:
    return rc;
}

static int sxp_hbo_pretty_print_peer_sequence(struct sxp_attribute *attr,
                                              enum sxp_error_code *code,
                                              enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, attr);
    RC_CHECK(rc, out);
    size_t count = 0;
    uint32_t *arr = NULL;
    rc = sxp_parse_peer_sequence_internal(attr, &count, &arr, code, subcode);
    RC_CHECK(rc, out);
    size_t i = 0;
    for (i = 0; i < count; ++i) {
        LOG_TRACE("0x" DEBUG_4B_FMT " [sxp-id=%" PRIu32 "]",
                  DEBUG_4B_PRINT(arr[i]), arr[i]);
    }
out:
    return rc;
}

static int sxp_hbo_pretty_print_ipv6_prefix(struct sxp_prefix *p)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, p);
    RC_CHECK(rc, out);
    uint8_t length = 0;
    struct v4_v6_prefix prefix = { 0, { { 0 } } };
    rc = sxp_parse_prefix(p, prefix.ip.data, sizeof(prefix.ip.data), &length);
    RC_CHECK(rc, out);
    const size_t bytes = length / 8 + (length % 8 > 0);
    switch (bytes) {
    case 0:
        LOG_TRACE("0x%02" PRIx8 "[length=%" PRIu8 ", prefix=" DEBUG_V6_FMT "]",
                  length, length, DEBUG_V6_PRINT(prefix.ip.data));
        break;
    case 1:
        LOG_TRACE("0x%02" PRIx8 "%02" PRIx8 " [length=%" PRIu8
                  ", prefix=" DEBUG_V6_FMT "]",
                  length, prefix.ip.data[0], length,
                  DEBUG_V6_PRINT(prefix.ip.data));
        break;
    case 2:
        LOG_TRACE("0x%02" PRIx8 "%02" PRIx8 "%02" PRIx8 " [length=%" PRIu8
                  ", prefix=" DEBUG_V6_FMT "]",
                  length, prefix.ip.data[0], prefix.ip.data[1], length,
                  DEBUG_V6_PRINT(prefix.ip.data));
        break;
    case 3:
        LOG_TRACE("0x%02" PRIx8 "%02" PRIx8 "%02" PRIx8 "%02" PRIx8
                  " [length=%" PRIu8 " prefix=" DEBUG_V6_FMT "]",
                  length, prefix.ip.data[0], prefix.ip.data[1],
                  prefix.ip.data[2], length, DEBUG_V6_PRINT(prefix.ip.data));
        break;
    case 4:
        LOG_TRACE("0x%02" PRIx8 DEBUG_4B_FMT " [length=%" PRIu8
                  " prefix=" DEBUG_V6_FMT "]",
                  length, DEBUG_4B_PRINT(prefix.ip.v6[0]), length,
                  DEBUG_V6_PRINT(prefix.ip.data));
        break;
    case 5:
        LOG_TRACE("0x%02" PRIx8 DEBUG_4B_FMT "%02" PRIx8 "[length=%" PRIu8
                  " prefix=" DEBUG_V6_FMT "]",
                  length, DEBUG_4B_PRINT(prefix.ip.v6[0]), prefix.ip.data[4],
                  length, DEBUG_V6_PRINT(prefix.ip.data));
        break;
    case 6:
        LOG_TRACE("0x%02" PRIx8 DEBUG_4B_FMT "%02" PRIx8 "%02" PRIx8
                  " [length=%" PRIu8 " prefix=" DEBUG_V6_FMT "]",
                  length, DEBUG_4B_PRINT(prefix.ip.v6[0]), prefix.ip.data[4],
                  prefix.ip.data[5], length, DEBUG_V6_PRINT(prefix.ip.data));
        break;
    case 7:
        LOG_TRACE("0x%02" PRIx8 DEBUG_4B_FMT "%02" PRIx8 "%02" PRIx8 "%02" PRIx8
                  " [length=%" PRIu8 " prefix=" DEBUG_V6_FMT "]",
                  length, DEBUG_4B_PRINT(prefix.ip.v6[0]), prefix.ip.data[4],
                  prefix.ip.data[5], prefix.ip.data[6], length,
                  DEBUG_V6_PRINT(prefix.ip.data));
        break;
    case 8:
        LOG_TRACE("0x%02" PRIx8 DEBUG_4B_FMT DEBUG_4B_FMT "[length=%" PRIu8
                  " prefix=" DEBUG_V6_FMT "]",
                  length, DEBUG_4B_PRINT(prefix.ip.v6[0]),
                  DEBUG_4B_PRINT(prefix.ip.v6[1]), length,
                  DEBUG_V6_PRINT(prefix.ip.data));
        break;
    case 9:
        LOG_TRACE("0x%02" PRIx8 DEBUG_4B_FMT DEBUG_4B_FMT " %02" PRIx8
                  "[length=%" PRIu8 " prefix=" DEBUG_V6_FMT "]",
                  length, DEBUG_4B_PRINT(prefix.ip.v6[0]),
                  DEBUG_4B_PRINT(prefix.ip.v6[1]), prefix.ip.data[8], length,
                  DEBUG_V6_PRINT(prefix.ip.data));
        break;
    case 10:
        LOG_TRACE("0x%02" PRIx8 DEBUG_4B_FMT DEBUG_4B_FMT "%02" PRIx8
                  "%02" PRIx8 " [length=%" PRIu8 " prefix=" DEBUG_V6_FMT "]",
                  length, DEBUG_4B_PRINT(prefix.ip.v6[0]),
                  DEBUG_4B_PRINT(prefix.ip.v6[1]), prefix.ip.data[8],
                  prefix.ip.data[9], length, DEBUG_V6_PRINT(prefix.ip.data));
        break;
    case 11:
        LOG_TRACE("0x%02" PRIx8 DEBUG_4B_FMT DEBUG_4B_FMT "%02" PRIx8
                  "%02" PRIx8 "%02" PRIx8 " [length=%" PRIu8
                  " prefix=" DEBUG_V6_FMT "]",
                  length, DEBUG_4B_PRINT(prefix.ip.v6[0]),
                  DEBUG_4B_PRINT(prefix.ip.v6[1]), prefix.ip.data[8],
                  prefix.ip.data[9], prefix.ip.data[10], length,
                  DEBUG_V6_PRINT(prefix.ip.data));
        break;
    case 12:
        LOG_TRACE("0x%02" PRIx8 DEBUG_4B_FMT DEBUG_4B_FMT DEBUG_4B_FMT
                  "[length=%" PRIu8 " prefix=" DEBUG_V6_FMT "]",
                  length, DEBUG_4B_PRINT(prefix.ip.v6[0]),
                  DEBUG_4B_PRINT(prefix.ip.v6[1]),
                  DEBUG_4B_PRINT(prefix.ip.v6[2]), length,
                  DEBUG_V6_PRINT(prefix.ip.data));
        break;
    case 13:
        LOG_TRACE("0x%02" PRIx8 DEBUG_4B_FMT DEBUG_4B_FMT DEBUG_4B_FMT
                  " %02" PRIx8 "[length=%" PRIu8 " prefix=" DEBUG_V6_FMT "]",
                  length, DEBUG_4B_PRINT(prefix.ip.v6[0]),
                  DEBUG_4B_PRINT(prefix.ip.v6[1]),
                  DEBUG_4B_PRINT(prefix.ip.v6[2]), prefix.ip.data[12], length,
                  DEBUG_V6_PRINT(prefix.ip.data));
        break;
    case 14:
        LOG_TRACE("0x%02" PRIx8 DEBUG_4B_FMT DEBUG_4B_FMT DEBUG_4B_FMT
                  "%02" PRIx8 "%02" PRIx8 " [length=%" PRIu8
                  " prefix=" DEBUG_V6_FMT "]",
                  length, DEBUG_4B_PRINT(prefix.ip.v6[0]),
                  DEBUG_4B_PRINT(prefix.ip.v6[1]),
                  DEBUG_4B_PRINT(prefix.ip.v6[2]), prefix.ip.data[12],
                  prefix.ip.data[13], length, DEBUG_V6_PRINT(prefix.ip.data));
        break;
    case 15:
        LOG_TRACE("0x%02" PRIx8 DEBUG_4B_FMT DEBUG_4B_FMT DEBUG_4B_FMT
                  "%02" PRIx8 "%02" PRIx8 "%02" PRIx8 " [length=%" PRIu8
                  " prefix=" DEBUG_V6_FMT "]",
                  length, DEBUG_4B_PRINT(prefix.ip.v6[0]),
                  DEBUG_4B_PRINT(prefix.ip.v6[1]),
                  DEBUG_4B_PRINT(prefix.ip.v6[2]), prefix.ip.data[12],
                  prefix.ip.data[13], prefix.ip.data[14], length,
                  DEBUG_V6_PRINT(prefix.ip.data));
        break;
    case 16:
        LOG_TRACE(
            "0x%02" PRIx8 DEBUG_4B_FMT DEBUG_4B_FMT DEBUG_4B_FMT DEBUG_4B_FMT
            "[length=%" PRIu8 " prefix=" DEBUG_V6_FMT "]",
            length, DEBUG_4B_PRINT(prefix.ip.v6[0]),
            DEBUG_4B_PRINT(prefix.ip.v6[1]), DEBUG_4B_PRINT(prefix.ip.v6[2]),
            DEBUG_4B_PRINT(prefix.ip.v6[3]), length,
            DEBUG_V6_PRINT(prefix.ip.data));
        break;
    default:
        LOG_ERROR("IPv6 prefix with unsupported length %" PRIu8, length);
        rc = -1;
        break;
    }
out:
    return rc;
}

static int
sxp_hbo_pretty_print_ipv6_prefix_list(struct sxp_attribute *attr,
                                      enum sxp_error_code *code,
                                      enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, attr, code, subcode);
    RC_CHECK(rc, out);
    struct sxp_prefix *p = NULL;
    while (1) {
        rc = sxp_parse_prefix_list(attr, p, &p, code, subcode);
        if (sxp_isnotok(rc, *code, *subcode)) {
            goto out;
        }
        if (!p) {
            break;
        }
        RC_CHECK(rc = sxp_hbo_pretty_print_ipv6_prefix(p), out);
    }
out:
    return rc;
}

static int sxp_hbo_pretty_print_v1_tlv_sgt(struct sxp_v1_tlv *tlv,
                                           enum sxp_error_code *code,
                                           enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, tlv, code, subcode);
    RC_CHECK(rc, out);
    enum sxp_v1_tlv_type tlv_type = SXP_V1_TLV_SGT;
    rc = sxp_v1_tlv_get_type(tlv, &tlv_type, code, subcode);
    if (sxp_isnotok(rc, *code, *subcode)) {
        goto out;
    }
    if (SXP_V1_TLV_SGT != tlv_type) {
        LOG_ERROR("Attempt to pretty-print %s TLV as %s TLV",
                  sxp_v1_tlv_type_string(tlv_type),
                  sxp_v1_tlv_type_string(SXP_V1_TLV_SGT));
        rc = -1;
        goto out;
    }
    uint32_t tlv_length = 0;
    RC_CHECK(rc = sxp_v1_tlv_get_length(tlv, &tlv_length), out);
    uint16_t sgt = 0;
    rc = sxp_v1_tlv_sgt_get_sgt(tlv, &sgt, code, subcode);
    if (sxp_isnotok(rc, *code, *subcode)) {
        goto out;
    }
    LOG_TRACE("0x" DEBUG_4B_FMT " [type=%s]", DEBUG_4B_PRINT(tlv_type),
              sxp_v1_tlv_type_string(tlv_type));
    LOG_TRACE("0x" DEBUG_4B_FMT " [length=%" PRIu32 "]",
              DEBUG_4B_PRINT(tlv_length), tlv_length);
    LOG_TRACE("0x%02" PRIx8 "%02" PRIx8 " [sgt=%" PRIu16 "]",
              ((uint8_t *)&(sgt))[0], ((uint8_t *)&(sgt))[1], sgt);
out:
    return rc;
}

static int
sxp_hbo_pretty_print_v1_tlv_prefix_length(struct sxp_v1_tlv *tlv,
                                          enum sxp_error_code *code,
                                          enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, tlv, code, subcode);
    RC_CHECK(rc, out);
    enum sxp_v1_tlv_type tlv_type = SXP_V1_TLV_SGT;
    rc = sxp_v1_tlv_get_type(tlv, &tlv_type, code, subcode);
    if (sxp_isnotok(rc, *code, *subcode)) {
        goto out;
    }
    if (SXP_V1_TLV_PREFIX_LENGTH != tlv_type) {
        LOG_ERROR("Attempt to pretty-print %s TLV as %s TLV",
                  sxp_v1_tlv_type_string(tlv_type),
                  sxp_v1_tlv_type_string(SXP_V1_TLV_PREFIX_LENGTH));
        rc = -1;
        goto out;
    }
    uint32_t tlv_length = 0;
    RC_CHECK(rc = sxp_v1_tlv_get_length(tlv, &tlv_length), out);
    uint8_t prefix_length = 0;
    rc = sxp_v1_tlv_prefix_length_get_prefix_length(tlv, &prefix_length, code,
                                                    subcode);
    if (sxp_isnotok(rc, *code, *subcode)) {
        goto out;
    }
    LOG_TRACE("0x" DEBUG_4B_FMT " [type=%s]", DEBUG_4B_PRINT(tlv_type),
              sxp_v1_tlv_type_string(tlv_type));
    LOG_TRACE("0x" DEBUG_4B_FMT " [length=%" PRIu32 "]",
              DEBUG_4B_PRINT(tlv_length), tlv_length);
    LOG_TRACE("0x%02" PRIx8 " [prefix-length=%" PRIu8 "]",
              ((uint8_t *)&(prefix_length))[0], prefix_length);
out:
    return rc;
}

static int sxp_hbo_pretty_print_v1_tlvs(struct sxp_attribute *attr,
                                        enum sxp_error_code *code,
                                        enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, attr, code, subcode);
    RC_CHECK(rc, out);
    struct sxp_v1_tlv *tlv = NULL;
    for (;;) {
        rc = sxp_v1_attr_parse_tlv(false, attr, tlv, &tlv, code, subcode);
        if (sxp_isnotok(rc, *code, *subcode)) {
            goto out;
        }
        if (!tlv) {
            break;
        }
        enum sxp_v1_tlv_type tlv_type = SXP_V1_TLV_SGT;
        rc = sxp_v1_tlv_get_type(tlv, &tlv_type, code, subcode);
        if (sxp_isnotok(rc, *code, *subcode)) {
            goto out;
        }
        switch (tlv_type) {
        case SXP_V1_TLV_SGT:
            rc = sxp_hbo_pretty_print_v1_tlv_sgt(tlv, code, subcode);
            break;
        case SXP_V1_TLV_PREFIX_LENGTH:
            rc = sxp_hbo_pretty_print_v1_tlv_prefix_length(tlv, code, subcode);
            break;
        }
        if (sxp_isnotok(rc, *code, *subcode)) {
            goto out;
        }
    }
out:
    return rc;
}

static int sxp_hbo_pretty_print_v1_tlv_prefix(struct sxp_attribute *attr)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, attr);
    RC_CHECK(rc, out);
    enum sxp_attr_type type = SXP_ATTR_TYPE_NODE_ID;
    RC_CHECK(rc = sxp_attr_get_type(attr, &type), out);
    uint32_t length = sxp_attr_get_length(false, attr);
    if (SXP_ATTR_TYPE_ADD_IPV4 == type || SXP_ATTR_TYPE_DEL_IPV4 == type) {
        if (length < sizeof((struct v4_v6_prefix *)0)->ip.v4) {
            LOG_ERROR("Length of opcode %s at address %p is too small to hold "
                      "prefix of size %zu",
                      sxp_attr_type_string(type), (void *)attr,
                      sizeof((struct v4_v6_prefix *)0)->ip.v4);
            rc = -1;
            goto out;
        } else {
            const uint32_t *prefix = OFFSET_PTR(attr, SXP_NC_ATTR_HEAD_SIZE);
            struct v4_v6_prefix tmp = {.len = 0, .ip = {.v4 = *prefix } };
            LOG_TRACE("0x" DEBUG_4B_FMT " [ipv4-addr=" DEBUG_V4_FMT "]",
                      DEBUG_4B_PRINT(tmp.ip.data), DEBUG_V4_PRINT(tmp.ip.v4));
        }
    } else if (SXP_ATTR_TYPE_ADD_IPV6 == type ||
               SXP_ATTR_TYPE_DEL_IPV6 == type) {
        if (length < sizeof((struct v4_v6_prefix *)0)->ip.v6) {
            LOG_ERROR("Length of opcode %s at address %p is too small to hold "
                      "prefix of size %zu",
                      sxp_attr_type_string(type), (void *)attr,
                      sizeof((struct v4_v6_prefix *)0)->ip.v6);
            rc = -1;
            goto out;
        } else {
            const uint32_t *prefix = OFFSET_PTR(attr, SXP_NC_ATTR_HEAD_SIZE);
            struct v4_v6_prefix tmp = {.len = 0,
                                       .ip = {.v6[0] = prefix[0],
                                              .v6[1] = prefix[1],
                                              .v6[2] = prefix[2],
                                              .v6[3] = prefix[3] } };
            LOG_TRACE(
                "0x" DEBUG_4B_FMT DEBUG_4B_FMT DEBUG_4B_FMT DEBUG_4B_FMT
                " [ipv6-addr=" DEBUG_V6_FMT "]",
                DEBUG_4B_PRINT(tmp.ip.v6[0]), DEBUG_4B_PRINT(tmp.ip.v6[1]),
                DEBUG_4B_PRINT(tmp.ip.v6[2]), DEBUG_4B_PRINT(tmp.ip.v6[3]),
                DEBUG_V6_PRINT(tmp.ip.data));
        }
    } else {
        LOG_ERROR("Internal error, printing opcode, but attribute has "
                  "unexpected type %s",
                  sxp_attr_type_string(type));
        rc = -1;
        goto out;
    }
out:
    return rc;
}

static int sxp_hbo_pretty_print_attribute(struct sxp_attribute *attr,
                                          enum sxp_error_code *code,
                                          enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, attr, code, subcode);
    RC_CHECK(rc, out);
    enum sxp_attr_type type = SXP_ATTR_TYPE_NODE_ID;
    RC_CHECK(rc = sxp_attr_get_type(attr, &type), out);
    RC_CHECK(rc = sxp_hbo_pretty_print_attribute_head(attr), out);
    switch (type) {
    case SXP_ATTR_TYPE_ADD_IPV4:
    /* fallthrough */
    case SXP_ATTR_TYPE_DEL_IPV4:
    /* fallthrough */
    case SXP_ATTR_TYPE_ADD_IPV6:
    /* fallthrough */
    case SXP_ATTR_TYPE_DEL_IPV6:
        RC_CHECK(rc = sxp_hbo_pretty_print_v1_tlv_prefix(attr), out);
        rc = sxp_hbo_pretty_print_v1_tlvs(attr, code, subcode);
        break;
    case SXP_ATTR_TYPE_NODE_ID:
        rc = sxp_hbo_pretty_print_node_id_attribute(attr);
        break;
    case SXP_ATTR_TYPE_CAPABILITIES:
        rc = sxp_hbo_pretty_print_capabilities_attribute(attr, code, subcode);
        break;
    case SXP_ATTR_TYPE_HOLD_TIME:
        rc = sxp_hbo_pretty_print_hold_time_attribute(attr, code, subcode);
        break;
    case SXP_ATTR_TYPE_IPV4_ADD_PREFIX:
    /* fallthrough */
    case SXP_ATTR_TYPE_IPV4_DEL_PREFIX:
        rc = sxp_hbo_pretty_print_ipv4_prefix_list(attr, code, subcode);
        break;
    case SXP_ATTR_TYPE_IPV6_ADD_PREFIX:
    /* fallthrough */
    case SXP_ATTR_TYPE_IPV6_DEL_PREFIX:
        rc = sxp_hbo_pretty_print_ipv6_prefix_list(attr, code, subcode);
        break;
    case SXP_ATTR_TYPE_SGT:
        rc = sxp_hbo_pretty_print_sgt_attribute(attr);
        break;
    case SXP_ATTR_TYPE_PEER_SEQUENCE:
        rc = sxp_hbo_pretty_print_peer_sequence(attr, code, subcode);
        break;
    }
out:
    return rc;
}

static int sxp_hbo_pretty_print_attributes(struct sxp_msg *msg,
                                           enum sxp_error_code *code,
                                           enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, msg, code, subcode);
    struct sxp_attribute *attr = NULL;
    while (sxp_isok(rc, *code, *subcode)) {
        rc = sxp_parse_msg(msg, attr, &attr, code, subcode);
        if (sxp_isnotok(rc, *code, *subcode)) {
            break;
        }
        if (!attr) {
            break;
        }
        rc = sxp_hbo_pretty_print_attribute(attr, code, subcode);
    }
    return rc;
}

static int sxp_hbo_pretty_print_open(struct sxp_msg *msg,
                                     enum sxp_error_code *code,
                                     enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    uint32_t version = 0;
    enum sxp_mode mode = SXP_MODE_SPEAKER;
    PARAM_NULL_CHECK(rc, msg, code, subcode);
    if (RC_ISOK(rc)) {
        rc = sxp_open_get_version(msg, &version);
    }
    if (RC_ISOK(rc)) {
        rc = sxp_open_get_mode(msg, &mode);
    }
    if (RC_ISOK(rc)) {
        LOG_TRACE("0x" DEBUG_4B_FMT " [version=%" PRIu32 "]",
                  DEBUG_4B_PRINT(version), version);
        LOG_TRACE("0x" DEBUG_4B_FMT " [mode=%s]", DEBUG_4B_PRINT(mode),
                  sxp_mode_string(mode));
    }
    if (RC_ISOK(rc) && version >= 4) {
        rc = sxp_hbo_pretty_print_attributes(msg, code, subcode);
    }
    return rc;
}

static int sxp_hbo_pretty_print_error(struct sxp_msg *msg)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, msg);
    RC_CHECK(rc, out);
    void *err = OFFSET_PTR(msg, SXP_MSG_SIZE);
    size_t remaining = msg->length - SXP_MSG_SIZE;
    size_t offset = 0;
    if (remaining) {
        if (SXP_ERROR_GET_EXTENDED(err)) {
            LOG_TRACE("0x%02" PRIx8 "%02" PRIx8 " [E=1, code=%s, sub-code=%s]",
                      ((uint8_t *)err)[0], ((uint8_t *)err)[1],
                      sxp_error_code_string(SXP_ERROR_GET_CODE(err)),
                      sxp_error_subcode_string(SXP_ERROR_GET_SUBCODE(err)));
            offset = 2 * sizeof(uint8_t);
        } else {
            LOG_TRACE("0x" DEBUG_4B_FMT "[E=0, non-extended error-code=%s]",
                      DEBUG_4B_PRINT(*(uint32_t *)err),
                      sxp_error_non_extended_code_string(
                          SXP_ERROR_GET_NON_EXTENDED_ERROR_CODE(err)));
            offset = sizeof(uint32_t);
        }
        LOG_TRACE_BYTES(OFFSET_PTR(err, offset), remaining - offset);
    }
out:
    return rc;
}

static int sxp_hbo_pretty_print_update(struct sxp_msg *msg,
                                       enum sxp_error_code *code,
                                       enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, msg, code, subcode);
    RC_CHECK(rc, out);
    rc = sxp_hbo_pretty_print_attributes(msg, code, subcode);
out:
    return rc;
}

/**
 * @brief pretty-print the message in host byte-order at trace level to log
 *
 * @param msg message to pretty-print
 *
 * @return 0 on success, -1 on error
 * @param code error code found while processing message
 * @param subcode error sub-code found while processing message
 */
int sxp_hbo_pretty_print_msg(struct sxp_msg *msg, enum sxp_error_code *code,
                             enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, msg, code, subcode);
    LOG_TRACE("SXP message dump start");
    if (RC_ISOK(rc)) {
        LOG_TRACE("0x" DEBUG_4B_FMT " [length=%" PRIu32 "]",
                  DEBUG_4B_PRINT(msg->length), msg->length);
        LOG_TRACE("0x" DEBUG_4B_FMT " [type=%s]", DEBUG_4B_PRINT(msg->type),
                  sxp_msg_type_string(msg->type));

        switch (msg->type) {
        case SXP_MSG_OPEN:
        /* fallthrough */
        case SXP_MSG_OPEN_RESP:
            rc = sxp_hbo_pretty_print_open(msg, code, subcode);
            break;

        case SXP_MSG_UPDATE:
            rc = sxp_hbo_pretty_print_update(msg, code, subcode);
            break;

        case SXP_MSG_ERROR:
            rc = sxp_hbo_pretty_print_error(msg);
            break;

        case SXP_MSG_PURGE_ALL:
            /* nothing to do here */
            break;

        case SXP_MSG_KEEPALIVE:
            /* nothing to do here */
            break;

        default:
            LOG_ERROR("Unknown msg type %" PRIu32 " while printing", msg->type);
            rc = -1;
        }
    }
    LOG_TRACE("SXP message dump end");
    return rc;
}

/**
 * @brief parse capabilities - get first/next capability
 *
 * @param[in] capabilities capabilities attribute to parse
 * @param[in] start if set to NULL, get first capability within
 *capabilities,
 *otherwise get next capability
 * @param[out] next first or next capability depending on value of start or NULL
 *if no (more) capabilities present
 * @param[out] code error code found while processing attribute
 * @param[out] subcode error sub-code found while processing attribute
 *
 * @return 0 on success, -1 on error
 */
int sxp_parse_capabilities(struct sxp_attribute *capabilities,
                           struct sxp_capability *start,
                           struct sxp_capability **next,
                           enum sxp_error_code *code,
                           enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    uint32_t caps_length = 0;
    PARAM_NULL_CHECK(rc, capabilities, next, code, subcode);
    RC_CHECK(rc, out);
    enum sxp_attr_type type;
    RC_CHECK(rc = sxp_attr_get_type(capabilities, &type), out);
    if (SXP_ATTR_TYPE_CAPABILITIES != type) {
        LOG_ERROR("Attempt to parse capabilities, but attribute has "
                  "invalid type %s",
                  sxp_attr_type_string(type));
        rc = -1;
        goto out;
    }
    rc = sxp_attr_get_total_size(false, capabilities, &caps_length);
    RC_CHECK(rc, out);
    if (start) {
        if ((char *)start < (char *)capabilities) {
            LOG_ERROR("Start capability address %p is smaller then "
                      "capabilities address %p",
                      (void *)start, (void *)capabilities);
            rc = -1;
            goto out;
        } else {
            if ((size_t)((char *)start - (char *)capabilities) > caps_length) {
                LOG_ERROR("Start capability address %p not within %" PRIu32
                          " bytes of capabilities address %p",
                          (void *)start, caps_length, (void *)capabilities);
                rc = -1;
                goto out;
            }
        }
    }
    struct sxp_capability *candidate = NULL;
    if (start) {
        candidate = OFFSET_PTR(start, SXP_ATTR_CAPABILITY_SIZE +
                                          SXP_CAPABILITY_GET_LENGTH(start));
    } else {
        if (sxp_attr_is_compact(capabilities)) {
            if (sxp_attr_is_extended(capabilities)) {
                candidate = OFFSET_PTR(capabilities, SXP_CE_ATTR_HEAD_SIZE);
            } else {
                candidate = OFFSET_PTR(capabilities, SXP_CNE_ATTR_HEAD_SIZE);
            }
        }
    }
    if ((char *)candidate < (char *)capabilities) {
        LOG_ERROR("Capability address %p is smaller then capabilities "
                  "address %p",
                  (void *)candidate, (void *)capabilities);
        rc = -1;
    } else if ((char *)candidate >= ((char *)capabilities) + caps_length) {
        /* candidate address would be out of capabilities => no more
         * capabilities present */
        *next = NULL;
    } else {
        char *candidate_end = (char *)candidate + SXP_ATTR_CAPABILITY_SIZE +
                              SXP_CAPABILITY_GET_LENGTH(candidate);
        if (candidate_end > (char *)capabilities + caps_length) {
            LOG_ERROR("Capability at address %p of length %" PRIu8
                      " crossess boundary of capabilities at address %p of "
                      "size %" PRIu32,
                      (void *)candidate, SXP_CAPABILITY_GET_LENGTH(candidate),
                      (void *)capabilities, caps_length);
            *code = SXP_ERR_CODE_OPEN;
            *subcode = SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE;
        } else {
            *next = candidate;
        }
    }
out:
    return rc;
}

static int sxp_parse_msg_internal(struct sxp_msg *msg, bool nbo_attribs,
                                  struct sxp_attribute *start,
                                  struct sxp_attribute **next,
                                  enum sxp_error_code *code,
                                  enum sxp_error_sub_code *subcode)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, msg, next, code, subcode);
    RC_CHECK(rc, out);
    if (msg->length > SXP_MAX_MSG_LENGTH) {
        LOG_ERROR("Message length %" PRIu32
                  " is larger then max SXP message length %d",
                  msg->length, SXP_MAX_MSG_LENGTH);
        *code = SXP_ERR_CODE_MSG_HEAD;
        goto out;
    } else if (start && (void *)start < (void *)msg) {
        LOG_ERROR("Start attribute pointer %p is smaller then message "
                  "pointer %p",
                  (void *)start, (void *)msg);
        rc = -1;
        goto out;
    } else if (start && (char *)start - (char *)msg > msg->length) {
        LOG_ERROR("Start attribute %p not within %" PRIu32
                  " bytes of message address %p",
                  (void *)start, msg->length, (void *)msg);
        rc = -1;
        goto out;
    }
    struct sxp_attribute *candidate = NULL;
    if (start) {
        uint32_t length = 0;
        rc = sxp_attr_get_total_size(nbo_attribs, start, &length);
        RC_CHECK(rc, out);
        candidate = OFFSET_PTR(start, length);
    } else {
        switch (msg->type) {
        case SXP_MSG_OPEN:
        /*fallthrough*/
        case SXP_MSG_OPEN_RESP:
            candidate = OFFSET_PTR(msg, SXP_OPEN_HEAD_SIZE);
            break;
        case SXP_MSG_KEEPALIVE:
            candidate = OFFSET_PTR(msg, SXP_MSG_SIZE);
            break;
        case SXP_MSG_UPDATE:
            candidate = OFFSET_PTR(msg, SXP_MSG_SIZE);
            break;
        case SXP_MSG_ERROR:
            candidate = OFFSET_PTR(msg, SXP_MSG_SIZE);
            break;
        case SXP_MSG_PURGE_ALL:
            candidate = OFFSET_PTR(msg, SXP_MSG_SIZE);
            break;
        default:
            LOG_ERROR("Don't know how to parse %s message type %d",
                      sxp_msg_type_string(msg->type), msg->type);
            rc = -1;
            goto out;
        }
    }
    if ((char *)candidate - (char *)msg >= msg->length) {
        /* candidate attribute is out of message => no more attributes */
        *next = NULL;
    } else {
        uint32_t candidate_length = 0;
        rc = sxp_attr_get_total_size(nbo_attribs, candidate, &candidate_length);
        RC_CHECK(rc, out);
        char *candidate_end = (char *)candidate + candidate_length;
        if (candidate_end - (char *)msg > msg->length) {
            LOG_ERROR("Attribute at address %p with length %" PRIu32
                      " crosses message boundary of message %p with "
                      "length %" PRIu32 " by %zu bytes",
                      (void *)candidate, candidate_length, (void *)msg,
                      msg->length, candidate_end - (char *)msg - msg->length);
            *subcode = SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE_LIST;
            goto out;
        } else {
            *next = candidate;
        }
    }
out:
    return rc;
}

/**
 * @brief parse message - get first/next attribute
 *
 * @param[in] msg message to parse
 * @param[in] start if set to NULL, get first attribute present in msg,
 *otherwise get next attribute following attribute at located at start
 * @param[out] next first or next attribute found in msg or NULL if no (more)
 *attributes present
 * @param[out] code error code found during message parsing
 * @param[out] subcode error sub code found during message parsing
 *
 * @return 0 on success, -1 on error
 */
int sxp_parse_msg(struct sxp_msg *msg, struct sxp_attribute *start,
                  struct sxp_attribute **next, enum sxp_error_code *code,
                  enum sxp_error_sub_code *subcode)
{
    return sxp_parse_msg_internal(msg, false, start, next, code, subcode);
}

/**
 * @brief return the string representation of error code
 *
 * @param code code to represent
 *
 * @return string representing the code
 */
const char *sxp_error_code_string(uint8_t code)
{
    switch (code) {
    case SXP_ERR_CODE_NONE:
        return "NONE";
    case SXP_ERR_CODE_MSG_HEAD:
        return "MSG-HEAD";
    case SXP_ERR_CODE_OPEN:
        return "OPEN";
    case SXP_ERR_CODE_UPDATE:
        return "UPDATE";
    }
    return "UNKNOWN";
}

/**
 * @brief return the string representation of error subcode
 *
 * @param subcode subcode to represent
 *
 * @return string representing the subcode
 */
const char *sxp_error_subcode_string(uint8_t subcode)
{
    switch (subcode) {
    case SXP_SUB_ERR_CODE_NONE:
        return "NONE";
    case SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE_LIST:
        return "MALFORMED-ATTRIBUTE-LIST";
    case SXP_SUB_ERR_CODE_UNEXPECTED_ATTRIBUTE:
        return "UNEXPECTED-ATTRIBUTE";
    case SXP_SUB_ERR_CODE_MISSING_WELL_KNOWN_ATTRIBUTE:
        return "MISSING-WELL-KNOWN-ATTRIBUTE";
    case SXP_SUB_ERR_CODE_ATTRIBUTE_FLAGS_ERROR:
        return "ATTRIBUTE-FLAGS-ERROR";
    case SXP_SUB_ERR_CODE_ATTRIBUTE_LENGTH_ERROR:
        return "ATTRIBUTE-LENGTH-ERROR";
    case SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE:
        return "MALFORMED-ATTRIBUTE";
    case SXP_SUB_ERR_CODE_OPTIONAL_ATTRIBUTE_ERROR:
        return "OPTIONAL-ATTRIBUTE-ERROR";
    case SXP_SUB_ERR_CODE_UNSUPPORTED_VERSION_NUMBER:
        return "UNSUPPORTED-VERSION-NUMBER";
    case SXP_SUB_ERR_CODE_UNSUPPORTED_OPTIONAL_ATTRIBUTE:
        return "UNSUPPORTED-OPTIONAL-ATTRIBUTE";
    case SXP_SUB_ERR_CODE_UNACCEPTABLE_HOLD_TIME:
        return "UNACCEPTABLE-HOLD-TIME";
    }
    return "UNKNOWN";
}

/**
 * @brief return the string representation of non-extended error code
 *
 * @param code code to represent
 *
 * @return string representing the code
 */
const char *sxp_error_non_extended_code_string(uint32_t code)
{
    switch (code) {
    case SXP_NON_EXT_ERR_CODE_NONE:
        return "NONE";
    case SXP_NON_EXT_ERR_CODE_VERSION_MISMATCH:
        return "VERSION-MISMATCH";
    case SXP_NON_EXT_ERR_CODE_MESSAGE_PARSE_ERROR:
        return "MESSAGE-PARSE-ERROR";
    }
    return "UNKNOWN";
}

#define SXP_V1_TLV_SGT_SIZE (SXP_V1_TLV_HEAD_SIZE + sizeof(uint16_t))
#define SXP_V1_TLV_PREFIX_LENGTH_SIZE (SXP_V1_TLV_HEAD_SIZE + sizeof(uint8_t))

/**
 * @brief calculate the length of add-ipv4 attribute containing prefix
 *
 * @param prefix_len length of the prefix
 *
 * @return size of the element
 */
uint32_t sxp_calc_add_ipv4_size(uint8_t prefix_len)
{
    uint32_t size = SXP_NC_ATTR_HEAD_SIZE +
                    sizeof(((struct v4_v6_prefix *)0)->ip.v4) +
                    SXP_V1_TLV_SGT_SIZE;
    if (SXP_IPV4_MAX_BITS != prefix_len) {
        /* in this case prefix-length TLV is needed */
        size += SXP_V1_TLV_PREFIX_LENGTH_SIZE;
    }
    return size;
}

/**
 * @brief calculate the length of del-ipv4 attribute containing prefix
 *
 * @param prefix_len length of the prefix
 *
 * @return size of the element
 */
uint32_t sxp_calc_del_ipv4_size(uint8_t prefix_len)
{
    uint32_t size =
        SXP_NC_ATTR_HEAD_SIZE + sizeof(((struct v4_v6_prefix *)0)->ip.v4);
    if (SXP_IPV4_MAX_BITS != prefix_len) {
        /* in this case prefix-length TLV is needed */
        size += SXP_V1_TLV_PREFIX_LENGTH_SIZE;
    }
    return size;
}

/**
 * @brief calculate the length of add-ipv6 attribute containing prefix
 *
 * @param prefix_len length of the prefix
 *
 * @return size of the element
 */
uint32_t sxp_calc_add_ipv6_size(uint8_t prefix_len)
{
    uint32_t size = SXP_NC_ATTR_HEAD_SIZE +
                    sizeof(((struct v4_v6_prefix *)0)->ip.v6) +
                    SXP_V1_TLV_SGT_SIZE;
    if (128 != prefix_len) {
        /* in this case prefix-length TLV is needed */
        size += SXP_V1_TLV_PREFIX_LENGTH_SIZE;
    }
    return size;
}

/**
 * @brief calculate the length of del-ipv6 attribute containing prefix
 *
 * @param prefix_len length of the prefix
 *
 * @return size of the element
 */
uint32_t sxp_calc_del_ipv6_size(uint8_t prefix_len)
{
    uint32_t size =
        SXP_NC_ATTR_HEAD_SIZE + sizeof(((struct v4_v6_prefix *)0)->ip.v6);
    if (128 != prefix_len) {
        /* in this case prefix-length TLV is needed */
        size += SXP_V1_TLV_PREFIX_LENGTH_SIZE;
    }
    return size;
}

/**
 * @brief add add-ipv4 attribute to message
 *
 * @param msg message to modify
 * @param buffer_size size of buffer holding the message
 * @param tag source group tag associated with the prefix
 * @param prefix_len length of the prefix
 * @param prefix prefix
 *
 * @return 0 on success, -1 on error
 */
int sxp_msg_add_add_ipv4(struct sxp_msg *msg, size_t buffer_size, uint16_t tag,
                         uint8_t prefix_len, uint8_t *prefix)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, msg, prefix);
    RC_CHECK(rc, out);
    if (prefix_len > 8 * sizeof(((struct v4_v6_prefix *)NULL)->ip.v4)) {
        LOG_ERROR("Invalid prefix length for v4 prefix %" PRIu8, prefix_len);
        rc = -1;
        goto out;
    }
    if (buffer_size < msg->length) {
        LOG_ERROR("Buffer of size %zu is smaller then existing message length "
                  "%" PRIu32,
                  buffer_size, msg->length);
        rc = -1;
        goto out;
    }
    const uint32_t req_size = sxp_calc_add_ipv4_size(prefix_len);
    const uint32_t attr_length = req_size - SXP_NC_ATTR_HEAD_SIZE;
    if (buffer_size < msg->length + req_size) {
        LOG_ERROR("Buffer of size %zu cannot accomodate message with "
                  "length %" PRIu32 " + %s of size %" PRIu32,
                  buffer_size, msg->length,
                  sxp_attr_type_string(SXP_ATTR_TYPE_ADD_IPV4), req_size);
        rc = -1;
        goto out;
    }
    void *attr = OFFSET_PTR(msg, msg->length);
    SXP_ATTR_SET_FLAGS(attr, 0);
    RC_CHECK(rc = sxp_attr_set_type(attr, SXP_ATTR_TYPE_ADD_IPV4), out);
    RC_CHECK(rc = sxp_attr_set_length(attr, attr_length), out);
    memcpy(OFFSET_PTR(attr, SXP_NC_ATTR_HEAD_SIZE), prefix,
           prefix_len / 8 + (prefix_len % 8 > 0));
    void *tlv = OFFSET_PTR(attr, SXP_NC_ATTR_HEAD_SIZE +
                                     sizeof(((struct v4_v6_prefix *)0)->ip.v4));
    if (SXP_IPV4_MAX_BITS != prefix_len) {
        RC_CHECK(rc = sxp_v1_tlv_set_type(tlv, SXP_V1_TLV_PREFIX_LENGTH), out);
        RC_CHECK(rc = sxp_v1_tlv_set_length(tlv, sizeof(uint8_t)), out);
        rc = sxp_v1_tlv_prefix_length_set_prefix_length(tlv, prefix_len);
        RC_CHECK(rc, out);
        tlv = OFFSET_PTR(tlv, SXP_V1_TLV_HEAD_SIZE + sizeof(uint8_t));
    }
    RC_CHECK(rc = sxp_v1_tlv_set_type(tlv, SXP_V1_TLV_SGT), out);
    RC_CHECK(rc = sxp_v1_tlv_set_length(tlv, sizeof(uint16_t)), out);
    rc = sxp_v1_tlv_sgt_set_sgt(tlv, tag);
    msg->length += req_size;
out:
    return rc;
}

/**
 * @brief add add-ipv6 attribute to message
 *
 * @param msg message to modify
 * @param buffer_size size of buffer holding the message
 * @param tag source group tag associated with the prefix
 * @param prefix_len length of the prefix
 * @param prefix prefix
 *
 * @return 0 on success, -1 on error
 */
int sxp_msg_add_add_ipv6(struct sxp_msg *msg, size_t buffer_size, uint16_t tag,
                         uint8_t prefix_len, uint8_t *prefix)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, msg, prefix);
    RC_CHECK(rc, out);
    if (prefix_len > SXP_IPV6_MAX_BITS) {
        LOG_ERROR("Invalid prefix length for v6 prefix %" PRIu8, prefix_len);
        rc = -1;
        goto out;
    }
    if (buffer_size < msg->length) {
        LOG_ERROR("Buffer of size %zu is smaller then existing message length "
                  "%" PRIu32,
                  buffer_size, msg->length);
        rc = -1;
        goto out;
    }
    const uint32_t req_size = sxp_calc_add_ipv6_size(prefix_len);
    const uint32_t attr_length = req_size - SXP_NC_ATTR_HEAD_SIZE;
    if (buffer_size < msg->length + req_size) {
        LOG_ERROR("Buffer of size %zu cannot accomodate message with "
                  "length %" PRIu32 " + %s of size %" PRIu32,
                  buffer_size, msg->length,
                  sxp_attr_type_string(SXP_ATTR_TYPE_ADD_IPV6), req_size);
        rc = -1;
        goto out;
    }
    void *attr = OFFSET_PTR(msg, msg->length);
    SXP_ATTR_SET_FLAGS(attr, 0);
    RC_CHECK(rc = sxp_attr_set_type(attr, SXP_ATTR_TYPE_ADD_IPV6), out);
    RC_CHECK(rc = sxp_attr_set_length(attr, attr_length), out);
    memcpy(OFFSET_PTR(attr, SXP_NC_ATTR_HEAD_SIZE), prefix,
           prefix_len / 8 + (prefix_len % 8 > 0));
    void *tlv = OFFSET_PTR(attr, SXP_NC_ATTR_HEAD_SIZE +
                                     sizeof(((struct v4_v6_prefix *)0)->ip.v6));
    if (SXP_IPV6_MAX_BITS != prefix_len) {
        RC_CHECK(rc = sxp_v1_tlv_set_type(tlv, SXP_V1_TLV_PREFIX_LENGTH), out);
        RC_CHECK(rc = sxp_v1_tlv_set_length(tlv, sizeof(uint8_t)), out);
        rc = sxp_v1_tlv_prefix_length_set_prefix_length(tlv, prefix_len);
        RC_CHECK(rc, out);
        tlv = OFFSET_PTR(tlv, SXP_V1_TLV_HEAD_SIZE + sizeof(uint8_t));
    }
    RC_CHECK(rc = sxp_v1_tlv_set_type(tlv, SXP_V1_TLV_SGT), out);
    RC_CHECK(rc = sxp_v1_tlv_set_length(tlv, sizeof(uint16_t)), out);
    rc = sxp_v1_tlv_sgt_set_sgt(tlv, tag);
    msg->length += req_size;
out:
    return rc;
}

/**
 * @brief add del-ipv4 attribute to message
 *
 * @param msg message to modify
 * @param buffer_size size of buffer holding the message
 * @param prefix_len length of the prefix
 * @param prefix prefix
 *
 * @return 0 on success, -1 on error
 */
int sxp_msg_add_del_ipv4(struct sxp_msg *msg, size_t buffer_size,
                         uint8_t prefix_len, uint8_t *prefix)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, msg, prefix);
    RC_CHECK(rc, out);
    if (prefix_len > 8 * sizeof(((struct v4_v6_prefix *)NULL)->ip.v4)) {
        LOG_ERROR("Invalid prefix length for v4 prefix %" PRIu8, prefix_len);
        rc = -1;
        goto out;
    }
    if (buffer_size < msg->length) {
        LOG_ERROR("Buffer of size %zu is smaller then existing message length "
                  "%" PRIu32,
                  buffer_size, msg->length);
        rc = -1;
        goto out;
    }
    const uint32_t req_size = sxp_calc_del_ipv4_size(prefix_len);
    const uint32_t attr_length = req_size - SXP_NC_ATTR_HEAD_SIZE;
    if (buffer_size < msg->length + req_size) {
        LOG_ERROR("Buffer of size %zu cannot accomodate message with "
                  "length %" PRIu32 " + %s of size %" PRIu32,
                  buffer_size, msg->length,
                  sxp_attr_type_string(SXP_ATTR_TYPE_DEL_IPV4), req_size);
        rc = -1;
        goto out;
    }
    void *attr = OFFSET_PTR(msg, msg->length);
    SXP_ATTR_SET_FLAGS(attr, 0);
    RC_CHECK(rc = sxp_attr_set_type(attr, SXP_ATTR_TYPE_DEL_IPV4), out);
    RC_CHECK(rc = sxp_attr_set_length(attr, attr_length), out);
    memcpy(OFFSET_PTR(attr, SXP_NC_ATTR_HEAD_SIZE), prefix,
           prefix_len / 8 + (prefix_len % 8 > 0));
    if (SXP_IPV4_MAX_BITS != prefix_len) {
        void *tlv =
            OFFSET_PTR(attr, SXP_NC_ATTR_HEAD_SIZE +
                                 sizeof(((struct v4_v6_prefix *)0)->ip.v4));
        RC_CHECK(rc = sxp_v1_tlv_set_type(tlv, SXP_V1_TLV_PREFIX_LENGTH), out);
        RC_CHECK(rc = sxp_v1_tlv_set_length(tlv, sizeof(uint8_t)), out);
        rc = sxp_v1_tlv_prefix_length_set_prefix_length(tlv, prefix_len);
        RC_CHECK(rc, out);
    }
    msg->length += req_size;
out:
    return rc;
}

/**
 * @brief add del-ipv6 attribute to message
 *
 * @param msg message to modify
 * @param buffer_size size of buffer holding the message
 * @param prefix_len length of the prefix
 * @param prefix prefix
 *
 * @return 0 on success, -1 on error
 */
int sxp_msg_add_del_ipv6(struct sxp_msg *msg, size_t buffer_size,
                         uint8_t prefix_len, uint8_t *prefix)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, msg, prefix);
    RC_CHECK(rc, out);
    if (prefix_len > 8 * sizeof(((struct v4_v6_prefix *)NULL)->ip.v6)) {
        LOG_ERROR("Invalid prefix length for v6 prefix %" PRIu8, prefix_len);
        rc = -1;
        goto out;
    }
    if (buffer_size < msg->length) {
        LOG_ERROR("Buffer of size %zu is smaller then existing message length "
                  "%" PRIu32,
                  buffer_size, msg->length);
        rc = -1;
        goto out;
    }
    const uint32_t req_size = sxp_calc_del_ipv6_size(prefix_len);
    const uint32_t attr_length = req_size - SXP_NC_ATTR_HEAD_SIZE;
    if (buffer_size < msg->length + req_size) {
        LOG_ERROR("Buffer of size %zu cannot accomodate message with "
                  "length %" PRIu32 " + %s of size %" PRIu32,
                  buffer_size, msg->length,
                  sxp_attr_type_string(SXP_ATTR_TYPE_DEL_IPV6), req_size);
        rc = -1;
        goto out;
    }
    void *attr = OFFSET_PTR(msg, msg->length);
    SXP_ATTR_SET_FLAGS(attr, 0);
    RC_CHECK(rc = sxp_attr_set_type(attr, SXP_ATTR_TYPE_DEL_IPV6), out);
    RC_CHECK(rc = sxp_attr_set_length(attr, attr_length), out);
    memcpy(OFFSET_PTR(attr, SXP_NC_ATTR_HEAD_SIZE), prefix,
           prefix_len / 8 + (prefix_len % 8 > 0));
    if (SXP_IPV6_MAX_BITS != prefix_len) {
        void *tlv =
            OFFSET_PTR(attr, SXP_NC_ATTR_HEAD_SIZE +
                                 sizeof(((struct v4_v6_prefix *)0)->ip.v6));
        RC_CHECK(rc = sxp_v1_tlv_set_type(tlv, SXP_V1_TLV_PREFIX_LENGTH), out);
        RC_CHECK(rc = sxp_v1_tlv_set_length(tlv, sizeof(uint8_t)), out);
        rc = sxp_v1_tlv_prefix_length_set_prefix_length(tlv, prefix_len);
        RC_CHECK(rc, out);
    }
    msg->length += req_size;
out:
    return rc;
}
