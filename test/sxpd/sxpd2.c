#include <inttypes.h>
#include <sxpd.h>
#include <config.h>
#include <debug.h>
#include <radix.h>
#include <util.h>
#include <../src/sxpd_internal.h>

#define TEST_SUCCESS 0

#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"

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

int main(void)
{
    struct sxpd_ctx *ctx = sxpd_create(NULL, NULL, LOG_LEVEL_DEBUG);
    assert(ctx);

    struct binding b[] = {
        {.type = PREFIX_IPV4,
         .prefix = {.prefix_v4 = 0 },
         .prefix_length = 8,
         .source_group_tag = 1 },
        {.type = PREFIX_IPV4,
         .prefix = {.prefix_v4 = 0 },
         .prefix_length = 16,
         .source_group_tag = 2 },
        {.type = PREFIX_IPV4,
         .prefix = {.prefix_v4 = 0 },
         .prefix_length = 32,
         .source_group_tag = 3 },
    };

    int rc = inet_pton(AF_INET, "10.10.10.10", &b[0].prefix.prefix_v4);
    assert(1 == rc);
    rc = inet_pton(AF_INET, "10.10.10.10", &b[1].prefix.prefix_v4);
    assert(1 == rc);
    rc = inet_pton(AF_INET, "10.10.10.10", &b[2].prefix.prefix_v4);
    assert(1 == rc);

    rc = sxpd_cfg_add_binding(ctx, &b[0]);
    assert(RC_ISOK(rc));
    rc = sxpd_cfg_add_binding(ctx, &b[1]);
    assert(RC_ISOK(rc));
    rc = sxpd_cfg_add_binding(ctx, &b[2]);
    assert(RC_ISOK(rc));

    struct v4_v6_prefix prefix;
    memset(&prefix, 0, sizeof(prefix));
    rc = inet_pton(AF_INET, "10.10.10.10", prefix.ip.data);
    assert(1 == rc);
    uint16_t tag = 0;
    bool found = false;
    for (uint8_t i = 0; i < 8; ++i) {
        rc = sxpd_search_best(ctx, V4, prefix.ip.data, i, &tag, &found);
        assert(RC_ISOK(rc));
        assert(false == found);
    }
    for (uint8_t i = 8; i < 16; ++i) {
        rc = sxpd_search_best(ctx, V4, prefix.ip.data, i, &tag, &found);
        assert(RC_ISOK(rc));
        assert(true == found);
        assert(1 == tag);
    }
    for (uint8_t i = 16; i < 32; ++i) {
        rc = sxpd_search_best(ctx, V4, prefix.ip.data, i, &tag, &found);
        assert(RC_ISOK(rc));
        assert(true == found);
        assert(2 == tag);
    }
    rc = sxpd_search_best(ctx, V4, prefix.ip.data, 32, &tag, &found);
    assert(RC_ISOK(rc));
    assert(3 == tag);

    rc = sxpd_search_best(ctx, V4, prefix.ip.data, 33, &tag, &found);
    assert(RC_ISNOTOK(rc));

    struct radix_node *node = NULL;
    rc = radix_search(ctx->master_bindings_v4, prefix.ip.data, 16, &node);
    assert(RC_ISOK(rc));
    struct v4_v6_prefix tmp;
    memset(&tmp, 0, sizeof(tmp));
    void *value = NULL;
    rc = radix_parse_node(node, tmp.ip.data, sizeof(tmp.ip.data), &tmp.len,
                          &value);
    assert(RC_ISOK(rc));
    bool result =
        bits_match(tmp.ip.data, (uint8_t *)&b[1].prefix.prefix_v4, 16);
    assert(result);
    struct sxpd_binding_list *bl = value;
    LOG_TRACE("Simulate deleting - free bindings for binding list %p",
              (void *)bl);
    bl->count = 0;
    mem_free(bl->bindings);
    bl->bindings = NULL;

    for (uint8_t i = 0; i < 8; ++i) {
        rc = sxpd_search_best(ctx, V4, prefix.ip.data, i, &tag, &found);
        assert(RC_ISOK(rc));
        assert(false == found);
    }
    for (uint8_t i = 8; i < 32; ++i) {
        rc = sxpd_search_best(ctx, V4, prefix.ip.data, i, &tag, &found);
        assert(RC_ISOK(rc));
        assert(true == found);
        assert(1 == tag);
    }
    rc = sxpd_search_best(ctx, V4, prefix.ip.data, 32, &tag, &found);
    assert(RC_ISOK(rc));
    assert(3 == tag);

    rc = sxpd_search_best(ctx, V4, prefix.ip.data, 33, &tag, &found);
    assert(RC_ISNOTOK(rc));

    sxpd_destroy(ctx);
    ctx = NULL;

    return TEST_SUCCESS;
}
