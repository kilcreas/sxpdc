/*------------------------------------------------------------------
 * Radix tree API
 *
 * November 2014, Klement Sekera
 *
 * Copyright (c) 2014-2015 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------*/

#ifndef RADIX_H
#define RADIX_H

#include <stdint.h>
#include <stdlib.h>

/**
 * @defgroup radix Radix tree
 * @htmlinclude radix_tree.html
 * @addtogroup radix
 * @{
 */

/**
 * @brief opaque radix node structure
 */
struct radix_node;

/**
 * @brief opaque radix tree structure
 */
struct radix_tree;

/**
 * @brief allocate a new radix tree
 *
 * @return non-NULL tree if success, NULL on error
 *
 */
struct radix_tree *radix_create(uint8_t maxbits);

/**
 * @brief callback called by radix_destroy for each node's data before
 *destroying the node
 *
 * @param data pointer stored in radix node
 */
typedef void (*radix_data_free_cb)(void *data);

/**
 * @brief free a radix tree
 *
 * @param tree tree to be freed
 * @param cb callback called for each node of the radix before the node is freed
 */
void radix_destroy(struct radix_tree *tree, radix_data_free_cb cb);

/**
 * @brief store prefix with prefix length in the tree associated with value
 *overwriting any existing stored value
 *
 * @param[in] tree the tree to operate on
 * @param[in] prefix memory containing bits to be stored in the tree
 * @param[in] prefix_len number of bits (at most prefix_len / 8 + 1 bytes will
 *be
 * read from prefix)
 * @param[in] value value to associate with stored prefix (must not be NULL)
 * @param[out] node the node created/updated by the store command
 *
 * @return returns 0 on success, -1 if error occurs
 */
int radix_store(struct radix_tree *tree, const uint8_t *prefix,
                uint8_t prefix_len, void *value, struct radix_node **node);

/**
 * @brief delete a node from radix tree and return next node
 *
 * @param tree tree to delete node from
 * @param node node to delete
 *
 * @return 0 on success, -1 on error
 */
int radix_delete_node(struct radix_tree *tree, struct radix_node *node);

typedef int (*radix_match_cb)(struct radix_node *node, void *ctx);

/**
 * @brief remove all entries for which the callback function returns non-zero
 *
 * @param tree tree to balk
 * @param callback function which gets value and ctx and must return zero if the
 *node should be kept or non-zero otherwise
 * @param ctx context passed to callback function
 *
 * @return 0 on success, -1 on error
 */
int radix_delete_matching(struct radix_tree *tree, radix_match_cb callback,
                          void *ctx);

/**
 * @brief search the tree for given prefix/length and return the associated node
 *
 * @param tree the tree to operate on
 * @param prefix memory containing bits to search for
 * @param prefix_len number of bits (at most prefix_len / 8 + 1 bytes will be
 * read from prefix)
 * @param[out] node radix node matching the search criteria
 *
 * @return 0 on success, -1 on error
 */
int radix_search(const struct radix_tree *tree, const uint8_t *prefix,
                 uint8_t prefix_len, struct radix_node **node);

/**
 * @brief search the tree for given prefix/length and return the node which has
 * the longest matching prefix
 *
 * @param tree the tree to operate on
 * @param prefix memory containing bits to search for
 * @param prefix_len number of bits (at most prefix_len / 8 + 1 bytes will be
 * read from prefix)
 * @param[out] result radix node matching the search criteria
 *
 * @return 0 on success, -1 on error
 */
int radix_search_best(struct radix_tree *tree, const uint8_t *prefix,
                      uint8_t prefix_len, struct radix_node **result);

/**
 * @brief iterate to first or next node in the radix tree
 *
 * NOTE: modifying the tree invalidates any pointers returned from radix_iterate
 *
 * @param[in] tree the tree to operate on
 * @param[in] node node returned by previous call of radix_iterate or NULL if
 *starting iteration
 * @param[out] next first node if NULL == node or next node otherwise
 *
 * @return 0 on success, -1 on error
 */
int radix_iterate(const struct radix_tree *tree, struct radix_node *node,
                  struct radix_node **next);

/**
 * @brief value returned from radix_next_search_cb indicating radix node should
 * be returned
 */
#define RADIX_MATCH (1)

/**
 * @brief value returned from radix_next_search_cb indicating radix node should
 * be skipped
 */
#define RADIX_SKIP (-1)

/**
 * @brief callback callback used to find next node that matches callback
 *criteria
 *
 * @param node node to be validate
 * @param ctx context passed to radix_iterate_matching
 *
 * @return RADIX_MATCH if node should be matched, RADIX_SKIP, if skipped
 */
typedef int (*radix_next_search_cb)(const struct radix_node *node, void *ctx);

/**
 * @brief iterate to first or next node in the radix tree for which the callback
 *function returns non-zero
 *
 * NOTE: modifying the tree invalidates any pointers returned from radix_iterate
 *
 * @param[in] tree the tree to operate on
 * @param[in] node node returned by previous call of radix_iterate or NULL if
 *starting iteration
 * @param[out] next first node if NULL == node or next node otherwise
 * @param cb function which gets node, next node and ctx and must return zero if
 *the
 * next node match
 * @param ctx context passed to callback function
 *
 * @return 0 on success, -1 on error
 */
#if 0
int radix_iterate_matching(const struct radix_tree *tree,
                           struct radix_node *node, struct radix_node **next,
                           radix_next_search_cb cb, void *ctx);
#endif

/**
 * @brief parse radix node
 *
 * @param[in] node node to parse, must not be NULL
 * @param[out] prefix_buffer buffer to store prefix bits - if NULL then unused
 * @param[out] prefix_buffer_size size of the buffer in bytes - if prefix_buffer
 *is NULL, then this value is not filled
 * @param[out] prefix_length actual length of prefix stored in bits
 * @param[out] value value associated with node
 *
 * @return 0 on success, -1 on error
 */
int radix_parse_node(const struct radix_node *node, uint8_t *prefix_buffer,
                     size_t prefix_buffer_size, uint8_t *prefix_length,
                     void **value);

/**
 * @brief return the parent node to the given radix node
 *
 * @param node child node
 * @param parent parent node or NULL if no such node exists
 *
 * @return 0 on success, -1 on error
 */
int radix_get_parent_node(const struct radix_node *node,
                          struct radix_node **parent);

/**
 * @brief set new value for given radix node
 *
 * @param node node to modify
 * @param value value to set
 *
 * @return 0 on success, -1 on error
 */
int radix_node_set_value(struct radix_node *node, void *value);

/** @} */

#endif
