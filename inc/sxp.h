/*------------------------------------------------------------------
 * SXP protocol parser API
 *
 * November 2014, Klement Sekera
 *
 * Copyright (c) 2014-2015 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------*/

#ifndef SXP_H
#define SXP_H

#ifdef SXP_H
/* avoid unused guard macro warning */
#endif

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "evmgr.h"
#include "util.h"

/**
 * @defgroup sxp SXP protocol parser
 * @htmlinclude sxp_protocol_parser.html
  * @addtogroup sxp
 * @{
 */

/**
 * @brief maximum length of sxp message
 */
#define SXP_MAX_MSG_LENGTH (4096)

/**
 * @brief sxp message type
 */
enum sxp_msg_type {
    SXP_MSG_OPEN = 1,      /*!< OPEN message */
    SXP_MSG_OPEN_RESP = 2, /*!< OPEN_RESP message */
    SXP_MSG_UPDATE = 3,    /*!< UPDATE message */
    SXP_MSG_ERROR = 4,     /*!< ERROR message */
    SXP_MSG_PURGE_ALL = 5, /*!< PURGE_ALL message */
    SXP_MSG_KEEPALIVE = 6, /*!< KEEPALIVE message */
};

#define SXP_MSG_TYPE_ENUMERATOR(F)                                          \
    F(SXP_MSG_OPEN) F(SXP_MSG_OPEN_RESP) F(SXP_MSG_UPDATE) F(SXP_MSG_ERROR) \
        F(SXP_MSG_PURGE_ALL) F(SXP_MSG_KEEPALIVE)

/**
 * @brief return string describing sxp message type
 *
 * @param t message type
 *
 * @return string describing the sxp message type
 */
const char *sxp_msg_type_string(enum sxp_msg_type t);

/**
 * @brief sxp extended error code
 */
enum sxp_error_code {
    SXP_ERR_CODE_NONE = 0,
    SXP_ERR_CODE_MSG_HEAD = 1,
    SXP_ERR_CODE_OPEN = 2,
    SXP_ERR_CODE_UPDATE = 3,
};

/**
 * @brief sxp extended error sub-code
 */
enum sxp_error_sub_code {
    SXP_SUB_ERR_CODE_NONE = 0,
    SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE_LIST = 1,
    SXP_SUB_ERR_CODE_UNEXPECTED_ATTRIBUTE = 2,
    SXP_SUB_ERR_CODE_MISSING_WELL_KNOWN_ATTRIBUTE = 3,
    SXP_SUB_ERR_CODE_ATTRIBUTE_FLAGS_ERROR = 4,
    SXP_SUB_ERR_CODE_ATTRIBUTE_LENGTH_ERROR = 5,
    SXP_SUB_ERR_CODE_MALFORMED_ATTRIBUTE = 6,
    SXP_SUB_ERR_CODE_OPTIONAL_ATTRIBUTE_ERROR = 7,
    SXP_SUB_ERR_CODE_UNSUPPORTED_VERSION_NUMBER = 8,
    SXP_SUB_ERR_CODE_UNSUPPORTED_OPTIONAL_ATTRIBUTE = 9,
    SXP_SUB_ERR_CODE_UNACCEPTABLE_HOLD_TIME = 10,
};

/**
 * @brief sxp non-extended error code
 */
enum sxp_error_non_extended_code {
    SXP_NON_EXT_ERR_CODE_NONE = 0,
    SXP_NON_EXT_ERR_CODE_VERSION_MISMATCH = 1,
    SXP_NON_EXT_ERR_CODE_MESSAGE_PARSE_ERROR = 2,
};

/**
 * @brief return the string representation of error code
 *
 * @param code code to represent
 *
 * @return string representing the code
 */
const char *sxp_error_code_string(uint8_t code);

/**
 * @brief return the string representation of error subcode
 *
 * @param subcode subcode to represent
 *
 * @return string representing the subcode
 */
const char *sxp_error_subcode_string(uint8_t subcode);

/**
 * @brief return the string representation of non-extended error code
 *
 * @param code code to represent
 *
 * @return string representing the code
 */
const char *sxp_error_non_extended_code_string(uint32_t code);

/**
 * @brief minimum value for hold-time minimum
 */
#define HOLD_TIME_MINIMUM_MINIMUM (3)

/**
 * @brief value which indicates that keepalive mechanism is unused
 */
#define KEEPALIVE_UNUSED (0xffff)

static inline int sxp_isok(int rc, enum sxp_error_code code,
                           enum sxp_error_sub_code subcode)
{
    return (RC_ISOK(rc) && code == SXP_ERR_CODE_NONE &&
            subcode == SXP_SUB_ERR_CODE_NONE);
}

static inline int sxp_isnotok(int rc, enum sxp_error_code code,
                              enum sxp_error_sub_code subcode)
{
    return !sxp_isok(rc, code, subcode);
}

/**
 * @brief sxp message header
 */
struct sxp_msg {
    uint32_t length;
    uint32_t type;
};

/**
 * @brief opaque sxp attribute structure
 */
struct sxp_attribute;

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
                              struct sxp_attribute *err_attr);

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
                           enum sxp_error_non_extended_code code);

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
                    enum sxp_error_non_extended_code *non_extended_code);

/**
 * @brief sxp mode
 */
enum sxp_mode {
    SXP_MODE_SPEAKER = 1,  /*!< SPEAKER mode */
    SXP_MODE_LISTENER = 2, /*!< LISTENER mode */
};

/**
 * @brief return string describing sxp mode
 *
 * @param m mode
 *
 * @return string describing sxp mode
 */
const char *sxp_mode_string(enum sxp_mode m);

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
                       uint32_t node_id);

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
                         enum sxp_mode mode, uint32_t node_id);

/**
 * @brief create keep-alive message in buffer of given size
 *
 * @param buffer buffer to hold the message, must be large enough
 * @param size buffer size
 *
 * @return 0 on success, -1 on error
 */
int sxp_create_keepalive(void *buffer, size_t size);

/**
 * @brief create purge-all message in buffer of given size
 *
 * @param buffer buffer to hold the message, must be large enough
 * @param size buffer size
 *
 * @return 0 on success, -1 on error
 */
int sxp_create_purge_all(void *buffer, size_t size);

/**
 * @brief create update message in buffer of given size
 *
 * @param buffer buffer to hold the message, must be large enough
 * @param size buffer size
 *
 * @return 0 on success, -1 on error
 */
int sxp_create_update(void *buffer, size_t size);

/**
 * @brief sxp attribute type
 */
enum sxp_attr_type {
    SXP_ATTR_TYPE_ADD_IPV4 = 1,         /*!< ADD-IPV4 */
    SXP_ATTR_TYPE_ADD_IPV6 = 2,         /*!< ADD-IPV6 */
    SXP_ATTR_TYPE_DEL_IPV4 = 3,         /*!< DEL-IPV4 */
    SXP_ATTR_TYPE_DEL_IPV6 = 4,         /*!< DEL-IPV6 */
    SXP_ATTR_TYPE_NODE_ID = 5,          /*!< NODE-ID */
    SXP_ATTR_TYPE_CAPABILITIES = 6,     /*!< CAPABILITIES */
    SXP_ATTR_TYPE_HOLD_TIME = 7,        /*!< HOLD-TIME */
    SXP_ATTR_TYPE_IPV4_ADD_PREFIX = 11, /*!< IPV4-ADD-PREFIX */
    SXP_ATTR_TYPE_IPV6_ADD_PREFIX = 12, /*!< IPV6-ADD-PREFIX */
    SXP_ATTR_TYPE_IPV4_DEL_PREFIX = 13, /*!< IPV4-DEL-PREFIX */
    SXP_ATTR_TYPE_IPV6_DEL_PREFIX = 14, /*!< IPV6-DEL_PREFIX */
    SXP_ATTR_TYPE_PEER_SEQUENCE = 16,   /*!< PEER-SEQUENCE */
    SXP_ATTR_TYPE_SGT = 17,             /*!< SOURCE-GROUP-TAG */
};

/**
 * @brief return string representation of sxp attribute type
 *
 * @param e type to return string for
 *
 * @return string representing the type
 */
const char *sxp_attr_type_string(enum sxp_attr_type e);

/**
 * @brief get the type of sxp attribute
 *
 * @param attr head to get type from
 * @param type pointer to storage for type
 *
 * @return 0 on success, -1 on error
 */
int sxp_attr_get_type(const struct sxp_attribute *attr,
                      enum sxp_attr_type *type);

/**
 * @brief get node id from node id attribute
 *
 * @param attr node id attribute
 * @param node_id pointer to storage for node id
 *
 * @return 0 on success, -1 on error
 */
int sxp_attr_node_id_get_node_id(const struct sxp_attribute *attr,
                                 uint32_t *node_id);

/**
 * @brief get source group tag from source group tag attribute
 *
 * @param attr node id attribute
 * @param sgt pointer to storage for source group tag
 *
 * @return 0 on success, -1 on error
 */
int sxp_attr_sgt_get_sgt(const struct sxp_attribute *attr, uint16_t *sgt);

/**
 * @brief returns true if hold time attribute contains maximum hold time value
 *
 * @param attr attribute to inspect
 *
 * @return true if present/false otherwise
 */
bool sxp_attr_hold_time_has_max_val(const struct sxp_attribute *attr);

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
                                   enum sxp_error_sub_code *subcode);

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
                                   enum sxp_error_sub_code *subcode);

/**
 * @brief get the minimum and maximum hold time value from time attribute
 *
 * @param attr attribute to parse
 * @param min_val pointer to storage for minimum hold time
 * @param max_val pointer to storage for maximum hold time
 * @param has_max_val pointer to indicator if maximum value has been found in
 *        time attribute
 * @param[out] code error code found while processing attribute
 * @param[out] subcode error sub-code found while processing attribute
 *
 * @return 0 on success, -1 on error
 */
int sxp_attr_hold_time_get_val(const struct sxp_attribute *attr,
                               uint16_t *min_val, uint16_t *max_val,
                               bool *has_max_val, enum sxp_error_code *code,
                               enum sxp_error_sub_code *subcode);

/**
 * @brief get version from SXP OPEN message
 *
 * @param msg message to process
 * @param version pointer to storage for version
 *
 * @return 0 on success, -1 on error
 */
int sxp_open_get_version(const struct sxp_msg *msg, uint32_t *version);

/**
 * @brief get mode from SXP OPEN message
 *
 * @param msg message to process
 * @param mode pointer to storage for mode
 *
 * @return 0 on success, -1 on error
 */
int sxp_open_get_mode(const struct sxp_msg *msg, enum sxp_mode *mode);

/**
 * @brief sxp capabilities
 */
enum sxp_capability_code {
    SXP_CAPABILITY_IPV4_UNICAST = 1,    /*!< IPV4-UNICAST capability */
    SXP_CAPABILITY_IPV6_UNICAST = 2,    /*!< IPV6-UNICAST capability */
    SXP_CAPABILITY_SUBNET_BINDINGS = 3, /*!< SUBNET-BINDINGS capability */
};

/**
 * @brief opaque sxp capability structure
 */
struct sxp_capability;

/**
 * @brief return the capability code of capability
 *
 * @param c capability
 * @param code capability code
 *
 * @return 0 on success, -1 on error
 */
int sxp_capability_get_code(const struct sxp_capability *c,
                            enum sxp_capability_code *code);

/**
 * @brief return length of capability
 *
 * @param c capability
 * @param length capability length
 *
 * @return 0 on success, -1 on error
 */
int sxp_capability_get_length(const struct sxp_capability *c, uint8_t *length);

/**
 * @brief return pointer to capability value
 *
 * @param c capability
 * @param value value stored in capability
 *
 * @return 0 on success, -1 on error
 */
int sxp_capability_get_value(const struct sxp_capability *c,
                             const void **value);

/**
 * @brief add new capabilities attribute to given message
 *
 * @param[in] msg message to modify
 * @param[in] buffer_size size of the buffer which holds the message (usable
 *memory)
 * @param[out] capabilities pointer to newly initialized capabilities attribute
 *
 * @return 0 on success, -1 on error
 */
int sxp_msg_add_capabilities(struct sxp_msg *msg, size_t buffer_size,
                             struct sxp_attribute **capabilities);

/**
 * @brief add hold time attribute to sxp message
 *
 * @param msg message to modify
 * @param buffer_size size of the buffer which holds the message (usable
 *memory)
 * @param min_val hold time minimum value
 * @param max_val hold time maximum value, if max-val is set to
 *KEEPALIVE_UNUSED, then it is not added to attribute
 *
 * @return 0 on success, -1 on error
 */
int sxp_msg_add_hold_time(struct sxp_msg *msg, size_t buffer_size,
                          uint16_t min_val, uint16_t max_val);

/**
 * @brief add a new capability in capabilities
 *
 * @param msg message which holds the capabilities
 * @param buffer_size size of the buffer which holds the message (usable memory)
 * @param capabilities pointer to capabilities within message
 * @param code capability code to add
 *
 * @return 0 on success, -1 on error
 */
int sxp_capabilities_add_capability(struct sxp_msg *msg, size_t buffer_size,
                                    struct sxp_attribute *capabilities,
                                    enum sxp_capability_code code);

/**
 * @brief parse capabilities - get first/next capability
 *
 * @param[in] capabilities capabilities attribute to parse
 * @param[in] start if set to NULL, get first capability within capabilities,
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
                           enum sxp_error_sub_code *subcode);

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
                    bool optional_flag);

/**
 * @brief return the size required for storing sgt attribute
 *
 * @return size in bytes
 */
uint32_t sxp_calc_sgt_size(void);

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
                              bool optional_flag);

/**
 * @brief calculate the size which a peer-sequence takes
 *
 * @param sxp_id_count the number of elements in the peer sequence
 *
 * @return size in bytes
 */
uint32_t sxp_calc_peer_sequence_size(uint32_t sxp_id_count);

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
                            enum sxp_error_sub_code *subcode);

/**
 * @brief peer sequence validation
 *
 * @param nbo_peer_node_id source peer node id
 * @param sxp_id_count number of node-id's
 * @param sxp_id_arr array of node-id's
 * @param[out] code error code found while processing attribute
 * @param[out] subcode error sub-code found while processing attribute
 *
 * @return 0 on success, -1 on error
 */
int sxp_validate_peer_sequence(uint32_t nbo_peer_node_id, size_t sxp_id_count,
                               const uint32_t *sxp_id_arr,
                               enum sxp_error_code *code,
                               enum sxp_error_sub_code *subcode);

/**
 * @brief add ipv4-add-prefix attribute to message
 *
 * @param[in] msg message to modify
 * @param[in] buffer_size size of buffer holding the message
 * @param[out] attr address of ipv4-add-prefix attribute
 * @param[in] optional_flag optional flag of del prefix attribute
 *
 * @return 0 on success, -1 on error
 */
int sxp_msg_add_ipv4_add_prefix(struct sxp_msg *msg, size_t buffer_size,
                                struct sxp_attribute **attr,
                                bool optional_flag);

/**
 * @brief return the size of ipv4-add-prefix attribute in bytes
 *
 * @return size in bytes
 */
uint32_t sxp_calc_ipv4_add_prefix_size(void);

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
                                struct sxp_attribute **attr,
                                bool optional_flag);

/**
 * @brief return the size of ipv6-add-prefix attribute in bytes
 *
 * @return size in bytes
 */
uint32_t sxp_calc_ipv6_add_prefix_size(void);

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
                               uint8_t *prefix);

/**
 * @brief return the size of prefix added to ipv4/6-prefix-list
 *
 * @param prefix_len length of the prefix in bits
 *
 * @return size in bytes
 */
uint32_t sxp_calc_prefix_size(uint8_t prefix_len);

/**
 * @brief opaque sxp prefix structure
 */
struct sxp_prefix;

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
                     size_t buffer_size, uint8_t *length);

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
                                struct sxp_attribute **attr,
                                bool optional_flag);

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
                                struct sxp_attribute **attr,
                                bool optional_flag);

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
                          enum sxp_error_sub_code *subcode);

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
                       enum sxp_error_sub_code *subcode);

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
                       enum sxp_error_sub_code *subcode);

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
                       enum sxp_error_sub_code *subcode);

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
                       enum sxp_error_sub_code *subcode);

/**
 * @brief calculate the length of add-ipv4 attribute containing prefix
 *
 * @param prefix_len length of the prefix
 *
 * @return size of the element
 */
uint32_t sxp_calc_add_ipv4_size(uint8_t prefix_len);

/**
 * @brief calculate the length of del-ipv4 attribute containing prefix
 *
 * @param prefix_len length of the prefix
 *
 * @return size of the element
 */
uint32_t sxp_calc_del_ipv4_size(uint8_t prefix_len);

/**
 * @brief calculate the length of add-ipv6 attribute containing prefix
 *
 * @param prefix_len length of the prefix
 *
 * @return size of the element
 */
uint32_t sxp_calc_add_ipv6_size(uint8_t prefix_len);

/**
 * @brief calculate the length of del-ipv6 attribute containing prefix
 *
 * @param prefix_len length of the prefix
 *
 * @return size of the element
 */
uint32_t sxp_calc_del_ipv6_size(uint8_t prefix_len);

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
                         uint8_t prefix_len, uint8_t *prefix);

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
                         uint8_t prefix_len, uint8_t *prefix);

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
                         uint8_t prefix_len, uint8_t *prefix);

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
                         uint8_t prefix_len, uint8_t *prefix);

/**
 * @brief return string representation of capability code
 *
 * @param c capability code
 *
 * @return string representation
 */
const char *sxp_capability_code_string(enum sxp_capability_code c);

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
                      enum sxp_error_sub_code *subcode);

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
                      enum sxp_error_sub_code *subcode);

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
                             enum sxp_error_sub_code *subcode);

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
                  enum sxp_error_sub_code *subcode);

/** @} */

#endif
