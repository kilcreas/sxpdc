#include <inttypes.h>
#include <sxpd.h>
#include <config.h>
#include <debug.h>
#include <radix.h>
#include <util.h>

#define TEST_SUCCESS 0

#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-parameter"

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
            if ((bits1[whole_byte_count + 1] | mask) !=
                (bits2[whole_byte_count + 1] | mask)) {
                return false;
            }
        }
        return true;
    }
    return false;
}

static void check_match(struct v4_v6_prefix *prefix, uint16_t tag,
                        struct binding *b)
{
    assert(bits_match(prefix->ip.data, (uint8_t *)&b->prefix.prefix_v4,
                      prefix->len));
    assert(prefix->len == b->prefix_length);
    assert(tag == b->source_group_tag);
    LOG_TRACE("Match: " DEBUG_V4_FMT ", tag=%" PRIu16,
              DEBUG_V4_PRINT(b->prefix.prefix_v4), tag);
}

int main(void)
{
    struct sxpd_ctx *ctx = sxpd_create(NULL, NULL, LOG_LEVEL_DEBUG);
    assert(ctx);

    struct binding b[] = {

        {.type = PREFIX_IPV4,
         .prefix = {.prefix_v4 = 0x0100007f },
         .prefix_length = 32,
         .source_group_tag = 1 },
        {.type = PREFIX_IPV4,
         .prefix = {.prefix_v4 = 0x0200007f },
         .prefix_length = 32,
         .source_group_tag = 2 },
        {.type = PREFIX_IPV4,
         .prefix = {.prefix_v4 = 0x0300007f },
         .prefix_length = 32,
         .source_group_tag = 3 },
        {.type = PREFIX_IPV4,
         .prefix = {.prefix_v4 = 0x0400007f },
         .prefix_length = 32,
         .source_group_tag = 4 },

    };

    int rc = sxpd_cfg_add_binding(ctx, &b[0]);
    assert(RC_ISOK(rc));
    struct sxpd_bindings_iterator *i1 = NULL;
    struct v4_v6_prefix prefix;
    memset(&prefix, 0, sizeof(prefix));
    uint16_t tag = 0;
    /* test 1 - simple iterate */
    LOG_TRACE("test 1 - start");
    rc = sxpd_iterate_bindings(ctx, V4, &i1, prefix.ip.data,
                               sizeof(prefix.ip.data), &prefix.len, &tag);
    assert(RC_ISOK(rc));
    assert(i1);
    check_match(&prefix, tag, &b[0]);

    rc = sxpd_iterate_bindings(ctx, V4, &i1, prefix.ip.data,
                               sizeof(prefix.ip.data), &prefix.len, &tag);
    assert(RC_ISOK(rc));
    assert(!i1);
    LOG_TRACE("test 1 - end");
    /* test 1 - end */

    /* test 2 - iterate, then add binding and start 2nd iterate, finish both
     * iterations */
    LOG_TRACE("test 2 - start");
    memset(&prefix, 0, sizeof(prefix));
    tag = 0;
    rc = sxpd_iterate_bindings(ctx, V4, &i1, prefix.ip.data,
                               sizeof(prefix.ip.data), &prefix.len, &tag);
    assert(RC_ISOK(rc));
    assert(i1);
    check_match(&prefix, tag, &b[0]);
    rc = sxpd_cfg_add_binding(ctx, &b[1]);
    assert(RC_ISOK(rc));
    struct sxpd_bindings_iterator *i2 = NULL;
    rc = sxpd_iterate_bindings(ctx, V4, &i2, prefix.ip.data,
                               sizeof(prefix.ip.data), &prefix.len, &tag);
    assert(RC_ISOK(rc));
    assert(i2);
    check_match(&prefix, tag, &b[0]);
    rc = sxpd_iterate_bindings(ctx, V4, &i1, prefix.ip.data,
                               sizeof(prefix.ip.data), &prefix.len, &tag);
    assert(RC_ISOK(rc));
    assert(!i1);
    rc = sxpd_iterate_bindings(ctx, V4, &i2, prefix.ip.data,
                               sizeof(prefix.ip.data), &prefix.len, &tag);
    assert(RC_ISOK(rc));
    assert(i2);
    check_match(&prefix, tag, &b[1]);
    rc = sxpd_iterate_bindings(ctx, V4, &i2, prefix.ip.data,
                               sizeof(prefix.ip.data), &prefix.len, &tag);
    assert(RC_ISOK(rc));
    assert(!i2);
    LOG_TRACE("test 2 - end");
    /* test 2 - end */

    /* test 3 - remove while iterating */
    LOG_TRACE("test 3 - start");
    rc = sxpd_cfg_add_binding(ctx, &b[2]);
    assert(RC_ISOK(rc));
    memset(&prefix, 0, sizeof(prefix));
    tag = 0;
    rc = sxpd_iterate_bindings(ctx, V4, &i1, prefix.ip.data,
                               sizeof(prefix.ip.data), &prefix.len, &tag);
    assert(RC_ISOK(rc));
    assert(i1);
    check_match(&prefix, tag, &b[0]);
    rc = sxpd_iterate_bindings(ctx, V4, &i2, prefix.ip.data,
                               sizeof(prefix.ip.data), &prefix.len, &tag);
    assert(RC_ISOK(rc));
    assert(i2);
    check_match(&prefix, tag, &b[0]);
    rc = sxpd_iterate_bindings(ctx, V4, &i2, prefix.ip.data,
                               sizeof(prefix.ip.data), &prefix.len, &tag);
    assert(RC_ISOK(rc));
    assert(i2);
    check_match(&prefix, tag, &b[1]);

    rc = sxpd_cfg_del_binding(ctx, &b[0]);
    assert(RC_ISOK(rc));
    rc = sxpd_cfg_del_binding(ctx, &b[1]);
    assert(RC_ISOK(rc));
    rc = sxpd_iterate_bindings(ctx, V4, &i1, prefix.ip.data,
                               sizeof(prefix.ip.data), &prefix.len, &tag);
    assert(RC_ISOK(rc));
    assert(i1);
    check_match(&prefix, tag, &b[2]);
    rc = sxpd_iterate_bindings(ctx, V4, &i2, prefix.ip.data,
                               sizeof(prefix.ip.data), &prefix.len, &tag);
    assert(RC_ISOK(rc));
    assert(i2);
    check_match(&prefix, tag, &b[2]);
    rc = sxpd_iterate_bindings(ctx, V4, &i1, prefix.ip.data,
                               sizeof(prefix.ip.data), &prefix.len, &tag);
    assert(RC_ISOK(rc));
    assert(!i1);
    rc = sxpd_iterate_bindings(ctx, V4, &i2, prefix.ip.data,
                               sizeof(prefix.ip.data), &prefix.len, &tag);
    assert(RC_ISOK(rc));
    assert(!i2);
    LOG_TRACE("test 3 - end");
    /* test 3 - end */

    /* test 4 - start iterating, delete everything, finish iteration */
    LOG_TRACE("test 4 - start");
    rc = sxpd_cfg_add_binding(ctx, &b[0]);
    assert(RC_ISOK(rc));
    rc = sxpd_cfg_add_binding(ctx, &b[1]);
    assert(RC_ISOK(rc));
    rc = sxpd_iterate_bindings(ctx, V4, &i1, prefix.ip.data,
                               sizeof(prefix.ip.data), &prefix.len, &tag);
    assert(RC_ISOK(rc));
    assert(i1);
    check_match(&prefix, tag, &b[0]);
    rc = sxpd_iterate_bindings(ctx, V4, &i2, prefix.ip.data,
                               sizeof(prefix.ip.data), &prefix.len, &tag);
    assert(RC_ISOK(rc));
    assert(i2);
    check_match(&prefix, tag, &b[0]);
    rc = sxpd_cfg_del_binding(ctx, &b[0]);
    assert(RC_ISOK(rc));
    rc = sxpd_cfg_del_binding(ctx, &b[1]);
    assert(RC_ISOK(rc));
    rc = sxpd_cfg_del_binding(ctx, &b[2]);
    assert(RC_ISOK(rc));
    rc = sxpd_iterate_bindings(ctx, V4, &i1, prefix.ip.data,
                               sizeof(prefix.ip.data), &prefix.len, &tag);
    assert(RC_ISOK(rc));
    assert(!i1);
    rc = sxpd_iterate_bindings(ctx, V4, &i2, prefix.ip.data,
                               sizeof(prefix.ip.data), &prefix.len, &tag);
    assert(RC_ISOK(rc));
    assert(!i2);
    LOG_TRACE("test 4 - end");
    /* test 4 - end */

    sxpd_destroy(ctx);
    ctx = NULL;

    return TEST_SUCCESS;
}
