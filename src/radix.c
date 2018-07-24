/*------------------------------------------------------------------
 * Radix tree implementation
 *
 * November 2014, Klement Sekera
 *
 * Copyright (c) 2014-2015 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------*/

/*
 * This product includes software developed by the University of Michigan,
 * Merit Network, Inc., and their contributors.
 */

#include <inttypes.h>
#include <stdbool.h>
#include "mem.h"
#include "debug.h"
#include "util.h"
#include "radix.h"

#define PATRICIA_MAXBITS (sizeof(struct in6_addr) * 8)

#define PREFIX_TOUCHAR(prefix) ((unsigned char *)&(prefix)->add.sin)
#define BIT_TEST(f, b) ((f) & (b))

#define PATRICIA_WALK(Xhead, Xnode)                      \
    do {                                                 \
        struct radix_node *Xstack[PATRICIA_MAXBITS + 1]; \
        struct radix_node **Xsp = Xstack;                \
        struct radix_node *Xrn = (Xhead);                \
        while ((Xnode = Xrn)) {                          \
            if (Xnode->prefix)

#define PATRICIA_WALK_END             \
    if (Xrn->l) {                     \
        if (Xrn->r) {                 \
            *Xsp++ = Xrn->r;          \
        }                             \
        Xrn = Xrn->l;                 \
    } else if (Xrn->r) {              \
        Xrn = Xrn->r;                 \
    } else if (Xsp != Xstack) {       \
        Xrn = *(--Xsp);               \
    } else {                          \
        Xrn = (struct radix_node *)0; \
    }                                 \
    }                                 \
    }                                 \
    while (0)

struct radix_prefix4 {
    uint8_t bitlen;
    struct in_addr sin;
};

struct radix_prefix {
    uint8_t bitlen;
    union {
        struct in_addr sin;
        struct in6_addr sin6;
    } add;
};

struct radix_node {
    uint8_t bit;
    struct radix_prefix *prefix; /* who we are in patricia tree */
    struct radix_node *l;        /* left children */
    struct radix_node *r;        /* left and right children */
    struct radix_node *parent;
    void *data; /* pointer to data */
};

struct radix_tree {
    struct radix_node *head;
    uint8_t maxbits;        /* for IP, 32 bit addresses */
    size_t num_active_node; /* number of all nodes */
};

static struct radix_prefix *radix_prefix_new(const uint8_t *prefix,
                                             uint8_t prefix_len)
{
    struct radix_prefix *pref = NULL;
    size_t size = 0;
    size = (prefix_len <= 32) ? sizeof(struct radix_prefix4)
                              : sizeof(struct radix_prefix);
    pref = mem_calloc(1, size);
    if (NULL != pref) {
        memcpy(&pref->add.sin, prefix,
               (prefix_len / 8) + ((prefix_len % 8) > 0));
        pref->bitlen = prefix_len;
    }

    return pref;
}

static struct radix_node *radix_node_new(uint8_t prefix_len,
                                         struct radix_prefix *prefix)
{
    struct radix_node *node = NULL;

    node = mem_calloc(1, (sizeof(*node)));

    if (NULL != node) {
        node->bit = prefix_len;
        node->prefix = prefix;
        node->parent = NULL;
        node->l = NULL;
        node->r = NULL;
        node->data = NULL;
    }

    return node;
}

static void radix_prefix_delete(struct radix_prefix *prefix)
{
    if (NULL != prefix) {
        mem_free(prefix);
    }
}

static void radix_node_delete(struct radix_node *node, radix_data_free_cb cb)
{
    if (NULL != node) {
        if (NULL != node->prefix) {
            radix_prefix_delete(node->prefix);
        } else {
            assert(NULL == node->data);
        }

        if ((NULL != node->data) && (NULL != cb)) {
            cb(node->data);
        }
        mem_free(node);
    }
}

/**
 * @brief allocate a new radix tree
 *
 * @return non-NULL tree if success, NULL on error
 *
 */
struct radix_tree *radix_create(uint8_t maxbits)
{
    struct radix_tree *tree = mem_calloc(1, sizeof(*tree));

    if (NULL != tree) {
        tree->maxbits = maxbits;
        tree->head = NULL;
        tree->num_active_node = 0;
        assert(maxbits <= PATRICIA_MAXBITS); /* XXX */
    }

    return (tree);
}

/**
 * @brief free a radix tree
 *
 * @param tree tree to be freed
 * @param cb callback called for each node of the radix before the node is freed
 */
void radix_destroy(struct radix_tree *tree, radix_data_free_cb cb)
{
    if (!tree) {
        return;
    }
    struct radix_node *stack[PATRICIA_MAXBITS + 1];
    struct radix_node **sp = stack;
    struct radix_node *rn = NULL;
    struct radix_node *l = NULL;
    struct radix_node *r = NULL;

    if (NULL != tree->head) {
        rn = tree->head;

        while (rn) {
            l = rn->l;
            r = rn->r;

            radix_node_delete(rn, cb);
            tree->num_active_node--;

            if (l) {
                if (r) {
                    *sp = r;
                    sp++;
                }
                rn = l;
            } else if (r) {
                rn = r;
            } else if (sp != stack) {
                --sp;
                rn = *sp;
            } else {
                rn = NULL;
            }
        }

        LOG_TRACE("%zu active nodes left", tree->num_active_node);
        assert(tree->num_active_node == 0);
    }

    mem_free(tree);
}

static int radix_store_first(struct radix_tree *tree, const uint8_t *prefix,
                             uint8_t prefix_len, void *value,
                             struct radix_node **node)
{
    int rc = 0;
    struct radix_node *tmp_node = NULL;

    PARAM_NULL_CHECK(rc, tree, prefix, value);
    RC_CHECK(rc, out);

    assert(NULL == tree->head);

    tmp_node = mem_calloc(1, sizeof(*tmp_node));
    if (NULL == tmp_node) {
        LOG_ERROR("Out of memory to create new node");
        rc = -1;
    }

    if (RC_ISOK(rc)) {
        tmp_node->bit = prefix_len;
        tmp_node->data = value;
        tmp_node->l = NULL;
        tmp_node->r = NULL;
        tmp_node->parent = NULL;
        tmp_node->prefix = radix_prefix_new(prefix, prefix_len);

        if (NULL == tmp_node->prefix) {
            LOG_ERROR("Out of memory to create new prefix");
            mem_free(tmp_node);
            tmp_node = NULL;
            rc = -1;
        }
    }

    if (RC_ISOK(rc)) {
        tree->num_active_node++;
        tree->head = tmp_node;
        if (node) {
            *node = tmp_node;
        }
    }

out:
    return rc;
}

/**
 * @brief store prefix with prefix length in the tree associated with value
 *overwriting any existing stored value
 *
 * @param[in] tree the tree to operate on
 * @param[in] prefix memory containing bits to be stored in the tree
 * @param[in] prefix_len number of bits (at most prefix_len / 8 + 1 bytes will
 *be read from prefix)
 * @param[in] value value to associate with stored prefix (must not be NULL)
 * @param[out] node the node created/updated by the store command
 *
 * @return returns 0 on success, -1 if error occurs
 */
int radix_store(struct radix_tree *tree, const uint8_t *prefix,
                uint8_t prefix_len, void *value, struct radix_node **node)
{
    int rc = 0;
    struct radix_node *tmp_node = NULL;
    struct radix_node *new_node = NULL;
    struct radix_node *parent = NULL;
    struct radix_node *glue = NULL;
    unsigned char *test_addr = NULL;
    uint8_t check_bit = 0;
    uint8_t differ_bit = 0;
    uint8_t i = 0;
    uint8_t j = 0;
    uint8_t r = 0;

    PARAM_NULL_CHECK(rc, tree, prefix, value);
    RC_CHECK(rc, out);

    if (tree->head == NULL) {
        /* if tree is empty create first head node */
        rc = radix_store_first(tree, prefix, prefix_len, value, node);
    } else {
        /* find nearest prefix node */
        tmp_node = tree->head;

        while ((tmp_node->bit < prefix_len) || (tmp_node->prefix == NULL)) {

            if ((tmp_node->bit < tree->maxbits) &&
                BIT_TEST(prefix[tmp_node->bit >> 3],
                         0x80 >> (tmp_node->bit & 0x07))) {

                if (NULL == tmp_node->r) {
                    break;
                }
                tmp_node = tmp_node->r;
            } else {
                if (NULL == tmp_node->l) {
                    break;
                }
                tmp_node = tmp_node->l;
            }
            assert(tmp_node);
        }

        assert(tmp_node->prefix);

        test_addr = PREFIX_TOUCHAR(tmp_node->prefix);

        /* find the first bit different */
        check_bit = (tmp_node->bit < prefix_len) ? tmp_node->bit : prefix_len;
        differ_bit = 0;
        for (i = 0; i * 8 < check_bit; i++) {
            r = (prefix[i] ^ test_addr[i]);
            if (!r) {
                differ_bit = (i + 1) * 8;
                continue;
            }
            /* I know the better way, but for now */
            for (j = 0; j < 8; j++) {
                if (BIT_TEST(r, (0x80 >> j))) {
                    break;
                }
            }
            /* bit must be found */
            assert(j < 8);
            differ_bit = i * 8 + j;
            break;
        }
        if (differ_bit > check_bit) {
            differ_bit = check_bit;
        }

        parent = tmp_node->parent;
        while ((NULL != parent) && (parent->bit >= differ_bit)) {
            tmp_node = parent;
            parent = tmp_node->parent;
        }

        if ((differ_bit == prefix_len) && (tmp_node->bit == prefix_len)) {
            /* return already existing node with prefix */
            if (tmp_node->prefix) {
                tmp_node->data = value;
                if (node) {
                    *node = tmp_node;
                }
            } else {
                /* set prefix to already existing node an return it */
                tmp_node->prefix = radix_prefix_new(prefix, prefix_len);
                if (NULL == tmp_node->prefix) {
                    LOG_ERROR("Out of memory to create new prefix");
                    rc = -1;
                } else {
                    assert(tmp_node->data == NULL);
                    tmp_node->data = value;
                    if (node) {
                        *node = tmp_node;
                    }
                }
            }
        } else {
            /* create new node with prefix */
            new_node = radix_node_new(prefix_len, NULL);
            if (NULL == new_node) {
                LOG_ERROR("Out of memory to create new node");
                rc = -1;
            } else {
                new_node->prefix = radix_prefix_new(prefix, prefix_len);
                assert(new_node->prefix); /* TODO assert -> if */

                tree->num_active_node++;

                if (tmp_node->bit == differ_bit) {
                    new_node->parent = tmp_node;
                    if ((tmp_node->bit < tree->maxbits) &&
                        BIT_TEST(prefix[tmp_node->bit >> 3],
                                 0x80 >> (tmp_node->bit & 0x07))) {
                        assert(tmp_node->r == NULL);
                        tmp_node->r = new_node;
                    } else {
                        assert(tmp_node->l == NULL);
                        tmp_node->l = new_node;
                    }
                } else {
                    /* move existing node to new node child position */
                    if (prefix_len == differ_bit) {
                        if (prefix_len < tree->maxbits &&
                            BIT_TEST(test_addr[prefix_len >> 3],
                                     0x80 >> (prefix_len & 0x07))) {
                            new_node->r = tmp_node;
                        } else {
                            new_node->l = tmp_node;
                        }
                        new_node->parent = tmp_node->parent;
                        if (tmp_node->parent == NULL) {
                            assert(tree->head == tmp_node);
                            tree->head = new_node;
                        } else if (tmp_node->parent->r == tmp_node) {
                            tmp_node->parent->r = new_node;
                        } else {
                            tmp_node->parent->l = new_node;
                        }
                        tmp_node->parent = new_node;
                    } else {
                        /* glue existing node and new node */
                        glue = calloc(1, sizeof *glue);
                        glue->bit = differ_bit;
                        glue->prefix = NULL;
                        glue->parent = tmp_node->parent;
                        glue->data = NULL;
                        tree->num_active_node++;
                        if ((differ_bit < tree->maxbits) &&
                            BIT_TEST(prefix[differ_bit >> 3],
                                     0x80 >> (differ_bit & 0x07))) {
                            glue->r = new_node;
                            glue->l = tmp_node;
                        } else {
                            glue->r = tmp_node;
                            glue->l = new_node;
                        }
                        new_node->parent = glue;

                        if (tmp_node->parent == NULL) {
                            assert(tree->head == tmp_node);
                            tree->head = glue;
                        } else if (tmp_node->parent->r == tmp_node) {
                            tmp_node->parent->r = glue;
                        } else {
                            tmp_node->parent->l = glue;
                        }
                        tmp_node->parent = glue;
                    }
                }
                new_node->data = value;
                if (node) {
                    *node = new_node;
                }
            }
        }
    }

out:
    return rc;
}

static void radix_delete_node_internal(struct radix_tree *tree,
                                       struct radix_node *node)
{
    struct radix_node *parent = NULL;
    struct radix_node *child = NULL;

    assert(tree);
    assert(node);

    if (node->r && node->l) {
        /* this might be a placeholder node -- have to check and make sure
         * there is a prefix associated with it ! */
        radix_prefix_delete(node->prefix);
        node->prefix = NULL;
        /* Also I needed to clear data pointer */
        node->data = NULL;
        return;
    }

    if ((NULL == node->r) && (NULL == node->l)) {
        parent = node->parent;
        radix_node_delete(node, NULL);
        tree->num_active_node--;

        /* if parent node is head */
        if (parent == NULL) {
            assert(tree->head == node);
            tree->head = NULL;
            return;
        }

        if (parent->r == node) {
            parent->r = NULL;
            child = parent->l;
        } else {
            assert(parent->l == node);
            parent->l = NULL;
            child = parent->r;
        }

        /* parent is used */
        if (parent->prefix) {
            return;
        }

        /* we need to remove parent too */

        if (parent->parent == NULL) {
            assert(tree->head == parent);
            tree->head = child;
        } else if (parent->parent->r == parent) {
            parent->parent->r = child;
        } else {
            assert(parent->parent->l == parent);
            parent->parent->l = child;
        }
        child->parent = parent->parent;
        radix_node_delete(parent, NULL);
        tree->num_active_node--;
        return;
    }

    if (node->r) {
        child = node->r;
    } else {
        child = node->l;
    }
    parent = node->parent;
    child->parent = parent;

    radix_node_delete(node, NULL);
    tree->num_active_node--;

    if (parent == NULL) {
        assert(tree->head == node);
        tree->head = child;
        return;
    }

    if (parent->r == node) {
        parent->r = child;
    } else {
        parent->l = child;
    }
}

/**
 * @brief delete a node from radix tree and return next node
 *
 * @param tree tree to delete node from
 * @param node node to delete
 *
 * @return 0 on success, -1 on error
 */
int radix_delete_node(struct radix_tree *tree, struct radix_node *node)
{
    int rc = 0;
    struct radix_node *tmp_node = NULL;

    PARAM_NULL_CHECK(rc, tree, node, node->prefix);

    if (RC_ISOK(rc)) {
        rc = radix_search(tree, (uint8_t *)&node->prefix->add.sin,
                          node->prefix->bitlen, &tmp_node);
        if ((RC_ISOK(rc)) && ((NULL == tmp_node) || (tmp_node != node))) {
            LOG_ERROR("Attempt to delete node %p which does not belong to tree",
                      (void *)node);
            rc = -1;
        }
    }

    if (RC_ISOK(rc)) {
        radix_delete_node_internal(tree, node);
    }

    return rc;
}

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
                          void *ctx)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, tree, callback);
    RC_CHECK(rc, out);

    struct radix_node *node = NULL;
    struct radix_node *next = NULL;
    for (;;) {
        rc = radix_iterate(tree, next, &next);
        RC_CHECK(rc, out);
        if (!next) {
            break;
        }
        if (node && node->prefix && callback(node, ctx)) {
            radix_delete_node_internal(tree, node);
            node = NULL;
        }
        node = next;
    }
    if (node && node->prefix && callback(node, ctx)) {
        radix_delete_node_internal(tree, node);
        node = NULL;
    }
out:
    return rc;
}

static bool bits_match(const uint8_t *bits1, const uint8_t *bits2,
                       size_t bit_count)
{
    if (bits1 && bits2) {
        const size_t whole_byte_count = bit_count / 8;
        if (memcmp(bits1, bits2, whole_byte_count)) {
            return false;
        }
        /* check if there are any remaining leftover bits to compare */
        const unsigned char rem_bits = bit_count % 8;
        if (rem_bits) {
            /* compare top rem_bits bits - mask bottom (8 - rem_bits) and
             * compare bytes */
            const unsigned char mask = (unsigned char)(1 << (8 - rem_bits)) - 1;
            if ((bits1[whole_byte_count] | mask) !=
                (bits2[whole_byte_count] | mask)) {
                return false;
            }
        }
        return true;
    }
    return false;
}

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
                 uint8_t prefix_len, struct radix_node **node)
{
    int rc = 0;
    struct radix_node *tmp_node = NULL;

    PARAM_NULL_CHECK(rc, tree, prefix, node);
    RC_CHECK(rc, out);

    assert(prefix_len <= tree->maxbits);

    tmp_node = tree->head;
    while ((NULL != tmp_node) && (tmp_node->bit < prefix_len)) {
        if (BIT_TEST(prefix[tmp_node->bit >> 3],
                     0x80 >> (tmp_node->bit & 0x07))) {
            tmp_node = tmp_node->r;
        } else {
            tmp_node = tmp_node->l;
        }
    }

    if (NULL != tmp_node) {
        if ((tmp_node->bit > prefix_len) || (NULL == tmp_node->prefix)) {
            tmp_node = NULL;
        } else {
            assert(tmp_node->bit == prefix_len);
            assert(tmp_node->bit == tmp_node->prefix->bitlen);
        }
    }

    if (NULL != tmp_node) {
        if (!bits_match((uint8_t *)&tmp_node->prefix->add, prefix,
                        prefix_len)) {
            tmp_node = NULL;
        }
    }

    *node = tmp_node;

out:
    return rc;
}

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
                      uint8_t prefix_len, struct radix_node **result)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, tree, prefix, result);
    RC_CHECK(rc, out);
    if (prefix_len > tree->maxbits) {
        LOG_ERROR("Attempt to search for prefix of length %" PRIu8
                  " in radix tree with maxbits %" PRIu8,
                  prefix_len, tree->maxbits);
        rc = -1;
        goto out;
    }

    struct radix_node *node = NULL;
    struct radix_node *stack[PATRICIA_MAXBITS + 1] = { 0 };
    int cnt = 0;

    *result = NULL;
    if (tree->head) {
        node = tree->head;

        while (node->bit < prefix_len) {

            if (node->prefix) {
                stack[cnt++] = node;
            }

            if (BIT_TEST(prefix[node->bit >> 3], 0x80 >> (node->bit & 0x07))) {
                node = node->r;
            } else {
                node = node->l;
            }

            if (node == NULL)
                break;
        }

        if (node && node->prefix)
            stack[cnt++] = node;

        if (cnt) {
            while (--cnt >= 0) {
                node = stack[cnt];
                if (bits_match((uint8_t *)&node->prefix->add, prefix,
                               node->prefix->bitlen) &&
                    node->prefix->bitlen <= prefix_len) {
                    *result = node;
                    break;
                }
            }
        }
    }
out:
    return rc;
}

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
                  struct radix_node **next)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, tree, next);
    RC_CHECK(rc, out);

    if (tree->num_active_node) {
        /* at first reach left corner point of tree */
        if (NULL == node) {
            node = tree->head;
            if (NULL != node) {
                while (node->l) {
                    node = node->l;
                }
            }
            /* reach next left corner point of tree */
        } else if (node->r) {
            node = node->r;
            while (node->l) {
                node = node->l;
            }
        } else {
            if ((NULL == node->parent) || (node == node->parent->l)) {
                node = node->parent;
            } else {
                do {
                    node = node->parent;
                } while ((node) && (node->parent) && (node == node->parent->r));
                node = node->parent;
            }
        }

        /* if found unused node, we must find next node */
        if ((NULL != node) && (NULL == node->prefix)) {
            rc = radix_iterate(tree, node, next);
        } else {
            *next = node;
        }
    } else {
        *next = NULL;
    }

out:
    return rc;
}

#if 0
int radix_iterate_matching(const struct radix_tree *tree,
                           struct radix_node *node, struct radix_node **next,
                           radix_next_search_cb cb, void *ctx)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, tree, next, cb);
    RC_CHECK(rc, out);

    struct radix_node *candidate = node;
    *next = NULL;
    for (;;) {
        RC_CHECK(rc = radix_iterate(tree, candidate, &candidate), out);
        if (NULL == candidate) {
            *next = candidate;
            break;
        }
        if (cb(candidate, ctx) == RADIX_MATCH) {
            *next = candidate;
            break;
        }
    }

out:
    return rc;
}
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
                     void **value)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, node, node->prefix, value);
    RC_CHECK(rc, out);

    if (prefix_buffer) {
        size_t bytes_required = node->prefix->bitlen / 8;
        if (node->prefix->bitlen % 8) {
            ++bytes_required;
        }
        if (bytes_required > prefix_buffer_size) {
            LOG_ERROR(
                "Provided buffer of length %zu is too small to store %zu bytes",
                prefix_buffer_size, bytes_required);
            rc = -1;
            goto out;
        }
        memcpy(prefix_buffer, &node->prefix->add.sin, bytes_required);
    }
    if (prefix_length) {
        *prefix_length = node->prefix->bitlen;
    }
    *value = node->data;
out:
    return rc;
}

/**
 * @brief return the parent node to the given radix node
 *
 * @param node child node
 * @param parent parent node or NULL if no such node exists
 *
 * @return 0 on success, -1 on error
 */
int radix_get_parent_node(const struct radix_node *node,
                          struct radix_node **parent)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, node, parent);
    RC_CHECK(rc, out);
    struct radix_node *tmp = node->parent;
    while (tmp && !tmp->prefix) {
        tmp = tmp->parent;
    }
    *parent = tmp;
out:
    return rc;
}

/**
 * @brief set new value for given radix node
 *
 * @param node node to modify
 * @param value value to set
 *
 * @return 0 on success, -1 on error
 */
int radix_node_set_value(struct radix_node *node, void *value)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, node);
    RC_CHECK(rc, out);
    node->data = value;
out:
    return rc;
}
