#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <inttypes.h>
#include <math.h>
#include <arpa/inet.h>
#include <signal.h>

#include <time.h>

#include <sys/time.h>
#include <sys/resource.h>

#include "radix.h"
#include "sxpd.h"
#include "sxp.h"

#include "mem.h"
#include "util.h"

#define IP_NUM ((size_t)750000)

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

#define timespecsub(a, b, result)                        \
    do {                                                 \
        (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;    \
        (result)->tv_nsec = (a)->tv_nsec - (b)->tv_nsec; \
        if ((result)->tv_nsec < 0) {                     \
            --(result)->tv_sec;                          \
            (result)->tv_nsec += 1000000000;             \
        }                                                \
    } while (0)

static void radix_time_stat(struct timespec *treal1, struct timespec *tproc1,
                            const char *desc)
{
    struct timespec treal2 = { 0, 0 };
    struct timespec tproc2 = { 0, 0 };
    struct timespec treal = { 0, 0 };
    struct timespec tproc = { 0, 0 };

    assert(treal1 && tproc1);

    clock_gettime(CLOCK_REALTIME, &treal2);
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &tproc2);

    timespecsub(&treal2, treal1, &treal);
    timespecsub(&tproc2, tproc1, &tproc);

    LOG_TRACE("real time stat <%s> %ld(s).%ld(ns)", desc, treal.tv_sec,
              treal.tv_nsec);
    LOG_TRACE("process time stat <%s> %ld(s).%ld(ns)", desc, tproc.tv_sec,
              tproc.tv_nsec);
}

static void radix_mem_stat(size_t ip_num, size_t prefix_len)
{
    struct rusage rusage;
    double mem_diff;

    LOG_TRACE("Best expected memory usage is %zu MB",
              ((sizeof(struct radix_prefix) * ip_num) +
               (sizeof(struct radix_node) * ip_num)) /
                  (1000000));

    LOG_TRACE("Worst expected memory usage is %zu MB - (0 nodes collisions + 0 "
              "patricia tree optimalisations)",
              ((sizeof(struct radix_prefix) * ip_num) +
               (sizeof(struct radix_node) * ip_num * prefix_len)) /
                  (1000000));

    getrusage(RUSAGE_SELF, &rusage);
    LOG_TRACE("Actual  memory usage is %zu MB ",
              (size_t)((rusage.ru_maxrss * 1024L) / 1000000));

    mem_diff = ((size_t)((rusage.ru_maxrss * 1024L)) -
                (((sizeof(struct radix_prefix) * ip_num) +
                  (sizeof(struct radix_node) * ip_num))));

    LOG_TRACE("Average unused nodes between prefix and root is: %e",
              mem_diff / (sizeof(struct radix_node) * ip_num));
}

static int radix_ipv4_test()
{
    int rc = 0;
    struct radix_tree *tree = NULL;
    size_t i = 0;
    uint32_t ip = 0;
    uint8_t *prefix = (uint8_t *)&ip;
    uint8_t prefix_len = 32;
    struct radix_node *node = NULL;
    struct radix_node *next = NULL;
    void *value = NULL;

    /* expected memory values computation */
    LOG_TRACE("This test is going to generate %zu IP prefixes", IP_NUM);
    LOG_TRACE("Size of struct radix_prefix is %zu B",
              sizeof(struct radix_prefix));
    LOG_TRACE("Size of struct radix_node is %zu B", sizeof(struct radix_node));
    LOG_TRACE("Every stored prefix length is %d", prefix_len);

    /* create radix tree */
    tree = radix_create(32);
    if (NULL == tree) {
        LOG_ERROR("Failed to create new radix tree: %p", (void *)tree);
        rc = -1;
    }

    if (RC_ISOK(rc)) {
        LOG_TRACE("Generating IP prefixes...");
        ip = 0;
        for (i = 0; i < IP_NUM; ++i) {
            ip = ip + 37;
            rc = radix_store(tree, prefix, prefix_len, prefix, &node);
            if (RC_ISNOTOK(rc)) {
                LOG_ERROR("Failed to store prefix in radix tree: %d", rc);
                break;
            }
        }
    }

    if (RC_ISOK(rc)) {
        LOG_TRACE("Checking IP prefixes if exist...");
        ip = 0;
        for (i = 0; i < IP_NUM; ++i) {
            ip = ip + 37;
            rc = radix_search(tree, prefix, prefix_len, &node);
            if (RC_ISNOTOK(rc) || node == NULL) {
                LOG_ERROR("Failed to search prefix in radix tree: %d :%p", rc,
                          (void *)node);
                rc = -1;
                break;
            } else {
                value = NULL;
                rc = radix_parse_node(node, NULL, 0, NULL, &value);
                if (prefix != value) {
                    LOG_ERROR("Prefix value address %p does not match expected "
                              "address %p",
                              (void *)value, (void *)prefix);
                    rc = -1;
                    break;
                }
            }
        }
    }

    if (RC_ISOK(rc)) {
        radix_mem_stat(IP_NUM, prefix_len);
    }

    if (RC_ISOK(rc)) {
        LOG_TRACE("Iterating and deleting all IP prefixes...");
        node = NULL;
        i = 0;
        do {
            rc = radix_iterate(tree, node, &next);
            if (RC_ISNOTOK(rc)) {
                LOG_ERROR("Failed to iterate next radix node: %d :%p", rc,
                          (void *)next);
                break;
            } else if (next == NULL) {
                LOG_TRACE("Iterated last node: %d :%p", rc, (void *)next);
            } else {
                rc = radix_delete_node(tree, next);
                if (RC_ISNOTOK(rc)) {
                    LOG_TRACE("Failed to delete node: %d", rc);
                    break;
                }
                i++;
            }
            node = NULL;
        } while (next);

        if (RC_ISOK(rc) && i != IP_NUM) {
            LOG_ERROR("Radix iteration removed %zu nodes, but expected number "
                      "is  %zu",
                      i, IP_NUM);
            rc = -1;
        } else {
            LOG_TRACE("Radix iteration removed %zu of %zu nodes", i, IP_NUM);
        }
    }

    if (RC_ISOK(rc)) {
        LOG_TRACE("Checking IP prefixes if not exist");
        ip = 0;
        for (i = 0; i < IP_NUM; ++i) {
            ip = ip + 37;
            rc = radix_search(tree, prefix, prefix_len, &node);
            if (RC_ISNOTOK(rc)) {
                LOG_ERROR("Failed to search prefix in radix tree: %d :%p", rc,
                          (void *)node);
                break;
            } else if (node != NULL) {
                LOG_ERROR("No prefix should exist");
                rc = -1;
            }
        }
    }

    radix_destroy(tree, NULL);

    return rc;
}

static int radix_ipv4_random_test()
{
    int rc = 0;
    struct radix_tree *tree = NULL;
    size_t i = 0;
    size_t j = 0;
    size_t generated_num = 0;
    uint32_t ip = 0;
    uint8_t *prefix = (uint8_t *)&ip;
    uint8_t prefix_len = 32;
    unsigned char *p_ip = NULL;

    struct radix_node *node = NULL;
    struct radix_node *next = NULL;

    /* expected memory values computation */
    LOG_TRACE("This test is going to generate %zu IP prefixes", IP_NUM);
    LOG_TRACE("Size of struct radix_prefix is %zu B",
              sizeof(struct radix_prefix));
    LOG_TRACE("Size of struct radix_node is %zu B", sizeof(struct radix_node));
    LOG_TRACE("Every stored prefix length is %d", prefix_len);

    /* create radix tree */
    tree = radix_create(32);
    if (NULL == tree) {
        LOG_ERROR("Failed to create new radix tree: %p", (void *)tree);
        rc = -1;
    }

    if (RC_ISOK(rc)) {
        LOG_TRACE("Generating IP prefixes...");
        ip = 0;
        for (i = 0; i < IP_NUM; ++i) {

            p_ip = (unsigned char *)&ip;
            for (j = 0; j < sizeof(ip); j++)
                *p_ip++ = rand() % 255;

            rc = radix_store(tree, prefix, prefix_len, prefix, &node);
            if (RC_ISNOTOK(rc)) {
                LOG_ERROR("Failed to store prefix in radix tree: %d", rc);
                break;
            }
        }
    }

    if (RC_ISOK(rc)) {
        LOG_TRACE("Counting IP prefixes...");
        node = NULL;
        i = 0;
        do {
            rc = radix_iterate(tree, node, &next);
            if (RC_ISNOTOK(rc)) {
                LOG_ERROR("Failed to iterate next radix node: %d :%p", rc,
                          (void *)next);
                break;
            } else if (next == NULL) {
                LOG_TRACE("Iterated last node: %d :%p", rc, (void *)next);
            } else {
                i++;
            }
            node = next;
        } while (next);

        if (RC_ISOK(rc)) {
            LOG_TRACE("Generated %zu ~ %zu IP prefixes", i, IP_NUM);
            generated_num = i;
        }
    }

    if (RC_ISOK(rc)) {
        LOG_TRACE("Counting IP prefixes...");
        node = NULL;
        i = 0;
        do {
            rc = radix_iterate(tree, node, &next);
            if (RC_ISNOTOK(rc)) {
                LOG_ERROR("Failed to iterate next radix node: %d :%p", rc,
                          (void *)next);
                break;
            } else if (next == NULL) {
                LOG_TRACE("Iterated last node: %d :%p", rc, (void *)next);
            } else {
                i++;
            }
            node = next;
        } while (next);

        if (RC_ISOK(rc)) {
            LOG_TRACE("Generated %zu ~ %zu IP prefixes", i, IP_NUM);
            generated_num = i;
        }
    }

    if (RC_ISOK(rc)) {
        radix_mem_stat(i, prefix_len);
    }

    if (RC_ISOK(rc)) {
        LOG_TRACE("Iterating and deleting all IP prefixes...");
        node = NULL;
        i = 0;
        do {
            rc = radix_iterate(tree, node, &next);
            if (RC_ISNOTOK(rc)) {
                LOG_ERROR("Failed to iterate next radix node: %d :%p", rc,
                          (void *)next);
                break;
            } else if (next == NULL) {
                LOG_TRACE("Iterated last node: %d :%p", rc, (void *)next);
            } else {
                rc = radix_delete_node(tree, next);
                if (RC_ISNOTOK(rc)) {
                    LOG_TRACE("Failed to delete node: %d", rc);
                    break;
                }
                i++;
            }
            node = NULL;
        } while (next);

        if (RC_ISOK(rc) && i != generated_num) {
            LOG_ERROR("Radix iteration removed %zu nodes, but expected number "
                      "is  %zu",
                      i, generated_num);
            rc = -1;
        } else {
            LOG_TRACE("Radix iteration removed %zu of %zu nodes", i,
                      generated_num);
        }
    }

    radix_destroy(tree, NULL);

    return rc;
}

static int radix_ipv6_test()
{
    int rc = 0;
    struct radix_tree *tree = NULL;
    size_t i = 0;
    uint32_t ip[4] = { 0, 0, 0, 0 };
    uint8_t *prefix = (uint8_t *)&ip;
    uint8_t prefix_len = 128;
    struct radix_node *node = NULL;
    struct radix_node *next = NULL;

    /* expected memory values computation */
    LOG_TRACE("This test is going to generate %zu IP prefixes", IP_NUM);
    LOG_TRACE("Size of struct radix_prefix is %zu B",
              sizeof(struct radix_prefix));
    LOG_TRACE("Size of struct radix_node is %zu B", sizeof(struct radix_node));
    LOG_TRACE("Every stored prefix length is %d", prefix_len);

    /* create radix tree */
    tree = radix_create(128);
    if (NULL == tree) {
        LOG_ERROR("Failed to create new radix tree: %p", (void *)tree);
        rc = -1;
    }

    if (RC_ISOK(rc)) {
        LOG_TRACE("Generating IP prefixes...");
        ip[0] = 0;
        ip[1] = 0;
        ip[2] = 0;
        ip[3] = 0;
        for (i = 0; i < IP_NUM; ++i) {
            ip[0] = ip[0] + 37;
            ip[1] = ip[1] + 13;
            ip[2] = ip[2] + 7;
            ip[3] = ip[3] + 3;
            rc = radix_store(tree, prefix, prefix_len, prefix, &node);
            if (RC_ISNOTOK(rc)) {
                LOG_ERROR("Failed to store prefix in radix tree: %d", rc);
                break;
            }
        }
    }

    if (RC_ISOK(rc)) {
        LOG_TRACE("Checking IP prefixes if exist...");
        ip[0] = 0;
        ip[1] = 0;
        ip[2] = 0;
        ip[3] = 0;
        for (i = 0; i < IP_NUM; ++i) {
            ip[0] = ip[0] + 37;
            ip[1] = ip[1] + 13;
            ip[2] = ip[2] + 7;
            ip[3] = ip[3] + 3;
            rc = radix_search(tree, prefix, prefix_len, &node);
            if (RC_ISNOTOK(rc) || node == NULL) {
                LOG_ERROR("Failed to search prefix %zu in radix tree: %d :%p",
                          i, rc, (void *)node);
                rc = -1;
                break;
            }
        }
    }

    if (RC_ISOK(rc)) {
        radix_mem_stat(IP_NUM, prefix_len);
    }

    if (RC_ISOK(rc)) {
        LOG_TRACE("Iterating and deleting all IP prefixes...");
        node = NULL;
        i = 0;
        do {
            rc = radix_iterate(tree, node, &next);
            if (RC_ISNOTOK(rc)) {
                LOG_ERROR("Failed to iterate next radix node: %d :%p", rc,
                          (void *)next);
                break;
            } else if (next == NULL) {
                LOG_TRACE("Iterated last node: %d :%p", rc, (void *)next);
            } else {
                rc = radix_delete_node(tree, next);
                if (RC_ISNOTOK(rc)) {
                    LOG_TRACE("Failed to delete node: %d", rc);
                    break;
                }
                i++;
            }
            node = NULL;
        } while (next);

        if (RC_ISOK(rc) && i != IP_NUM) {
            LOG_ERROR("Radix iteration removed %zu nodes, but expected number "
                      "is  %zu",
                      i, IP_NUM);
            rc = -1;
        } else {
            LOG_TRACE("Radix iteration removed %zu of %zu nodes", i, IP_NUM);
        }
    }

    if (RC_ISOK(rc)) {
        LOG_TRACE("Checking IP prefixes if not exist");
        ip[0] = 0;
        ip[1] = 0;
        ip[2] = 0;
        ip[3] = 0;
        for (i = 0; i < IP_NUM; ++i) {
            ip[0] = ip[0] + 37;
            ip[1] = ip[1] + 13;
            ip[2] = ip[2] + 7;
            ip[3] = ip[3] + 3;
            rc = radix_search(tree, prefix, prefix_len, &node);
            if (RC_ISNOTOK(rc)) {
                LOG_ERROR("Failed to search prefix in radix tree: %d :%p", rc,
                          (void *)node);
                break;
            } else if (node != NULL) {
                LOG_ERROR("No prefix should exist");
                rc = -1;
            }
        }
    }

    radix_destroy(tree, NULL);

    return rc;
}

static int radix_ipv6_random_test()
{
    int rc = 0;
    struct radix_tree *tree = NULL;
    size_t i = 0;
    size_t j = 0;
    size_t generated_num = 0;
    uint32_t ip[4] = { 0, 0, 0, 0 };
    uint8_t *prefix = (uint8_t *)&ip;
    uint8_t prefix_len = 128;
    unsigned char *p_ip = NULL;

    struct radix_node *node = NULL;
    struct radix_node *next = NULL;

    /* expected memory values computation */
    LOG_TRACE("This test is going to generate %zu IP prefixes", IP_NUM);
    LOG_TRACE("Size of struct radix_prefix is %zu B",
              sizeof(struct radix_prefix));
    LOG_TRACE("Size of struct radix_node is %zu B", sizeof(struct radix_node));
    LOG_TRACE("Every stored prefix length is %d", prefix_len);

    /* create radix tree */
    tree = radix_create(128);
    if (NULL == tree) {
        LOG_ERROR("Failed to create new radix tree: %p", (void *)tree);
        rc = -1;
    }

    if (RC_ISOK(rc)) {
        LOG_TRACE("Generating IP prefixes...");
        ip[0] = 0;
        ip[1] = 0;
        ip[2] = 0;
        ip[3] = 0;
        for (i = 0; i < IP_NUM; ++i) {

            p_ip = (unsigned char *)&ip;
            for (j = 0; j < sizeof(ip); j++)
                *p_ip++ = rand() % 255;

            rc = radix_store(tree, prefix, prefix_len, prefix, &node);
            if (RC_ISNOTOK(rc)) {
                LOG_ERROR("Failed to store prefix in radix tree: %d", rc);
                break;
            }
        }
    }

    if (RC_ISOK(rc)) {
        LOG_TRACE("Counting IP prefixes...");
        node = NULL;
        i = 0;
        do {
            rc = radix_iterate(tree, node, &next);
            if (RC_ISNOTOK(rc)) {
                LOG_ERROR("Failed to iterate next radix node: %d :%p", rc,
                          (void *)next);
                break;
            } else if (next == NULL) {
                LOG_TRACE("Iterated last node: %d :%p", rc, (void *)next);
            } else {
                i++;
            }
            node = next;
        } while (next);

        if (RC_ISOK(rc)) {
            LOG_TRACE("Generated %zu ~ %zu IP prefixes", i, IP_NUM);
            generated_num = i;
        }
    }

    if (RC_ISOK(rc)) {
        radix_mem_stat(i, prefix_len);
    }

    if (RC_ISOK(rc)) {
        LOG_TRACE("Iterating and deleting all IP prefixes...");
        node = NULL;
        i = 0;
        do {
            rc = radix_iterate(tree, node, &next);
            if (RC_ISNOTOK(rc)) {
                LOG_ERROR("Failed to iterate next radix node: %d :%p", rc,
                          (void *)next);
                break;
            } else if (next == NULL) {
                LOG_TRACE("Iterated last node: %d :%p", rc, (void *)next);
            } else {
                rc = radix_delete_node(tree, next);
                if (RC_ISNOTOK(rc)) {
                    LOG_TRACE("Failed to delete node: %d", rc);
                    break;
                }
                i++;
            }
            node = NULL;
        } while (next);

        if (RC_ISOK(rc) && i != generated_num) {
            LOG_ERROR("Radix iteration removed %zu nodes, but expected number "
                      "is  %zu",
                      i, generated_num);
            rc = -1;
        } else {
            LOG_TRACE("Radix iteration removed %zu of %zu nodes", i,
                      generated_num);
        }
    }

    radix_destroy(tree, NULL);

    return rc;
}

static int radix_ipv4_custom_random_test()
{
    int rc = 0;
    struct radix_tree *tree = NULL;
    size_t i = 0;
    size_t j = 0;
    size_t generated_num = 0;
    uint32_t ip = 0;
    uint8_t *prefix = NULL;
    uint8_t prefix_len = 32;
    unsigned char *p_ip = NULL;

    struct radix_node *node = NULL;
    struct radix_node *next = NULL;

    struct timespec treal1 = { 0, 0 };
    struct timespec tproc1 = { 0, 0 };
    uint32_t ips[IP_NUM];

    /* expected memory values computation */
    LOG_TRACE("This test is going to generate %zu IP prefixes", IP_NUM);
    LOG_TRACE("Size of struct radix_prefix is %zu B",
              sizeof(struct radix_prefix));
    LOG_TRACE("Size of struct radix_node is %zu B", sizeof(struct radix_node));
    LOG_TRACE("Every stored prefix length is %d", prefix_len);

    /* create radix tree */
    tree = radix_create(32);
    if (NULL == tree) {
        LOG_ERROR("Failed to create new radix tree: %p", (void *)tree);
        rc = -1;
    }

    if (RC_ISOK(rc)) {
        LOG_TRACE("Generating IP prefixes...");
        ip = 0;
        for (i = 0; i < IP_NUM; ++i) {

            p_ip = (unsigned char *)&ip;
            for (j = 0; j < sizeof(ip); j++)
                *p_ip++ = rand() % 255;

            ips[i] = ip;
        }
    }

    clock_gettime(CLOCK_REALTIME, &treal1);
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &tproc1);

    if (RC_ISOK(rc)) {
        LOG_TRACE("Storing IP prefixes...");
        ip = 0;
        for (i = 0; i < IP_NUM; ++i) {

            prefix = (uint8_t *)&ips[i];
            rc = radix_store(tree, prefix, prefix_len, prefix, &node);
            if (RC_ISNOTOK(rc)) {
                LOG_ERROR("Failed to store prefix in radix tree: %d", rc);
                break;
            }
        }
    }

    radix_time_stat(&treal1, &tproc1, "storing generated ip prefixes");
    clock_gettime(CLOCK_REALTIME, &treal1);
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &tproc1);

    if (RC_ISOK(rc)) {
        LOG_TRACE("Checking IP prefixes if exist...");
        ip = 0;
        for (i = 0; i < IP_NUM; ++i) {

            prefix = (uint8_t *)&ips[i];
            rc = radix_search(tree, prefix, prefix_len, &node);
            if (RC_ISNOTOK(rc) || node == NULL) {
                LOG_ERROR("Failed to search prefix in radix tree: %d :%p", rc,
                          (void *)node);
                rc = -1;
                break;
            }
        }
    }

    radix_time_stat(&treal1, &tproc1, "searching for generated ip prefixes");
    clock_gettime(CLOCK_REALTIME, &treal1);
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &tproc1);

    if (RC_ISOK(rc)) {
        LOG_TRACE("Counting IP prefixes...");
        node = NULL;
        i = 0;
        do {
            rc = radix_iterate(tree, node, &next);
            if (RC_ISNOTOK(rc)) {
                LOG_ERROR("Failed to iterate next radix node: %d :%p", rc,
                          (void *)next);
                break;
            } else if (next == NULL) {
                LOG_TRACE("Iterated last node: %d :%p", rc, (void *)next);
            } else {
                i++;
            }
            node = next;
        } while (next);

        if (RC_ISOK(rc)) {
            LOG_TRACE("Generated %zu ~ %zu IP prefixes", i, IP_NUM);
            generated_num = i;
        }
    }

    radix_time_stat(&treal1, &tproc1, "iterating all generated ip prefixes");
    clock_gettime(CLOCK_REALTIME, &treal1);
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &tproc1);

    if (RC_ISOK(rc)) {
        radix_mem_stat(i, prefix_len);
    }

    if (RC_ISOK(rc)) {
        LOG_TRACE("Deleting all IP prefixes...");
        j = 0;
        for (i = 0; i < IP_NUM; ++i) {

            prefix = (uint8_t *)&ips[i];

            rc = radix_search(tree, prefix, prefix_len, &node);
            if (RC_ISNOTOK(rc)) {
                LOG_ERROR("Failed to search prefix in radix tree: %d :%p", rc,
                          (void *)node);
                rc = -1;
                break;
            } else if (node != NULL) {
                rc = radix_delete_node(tree, node);
                if (RC_ISNOTOK(rc)) {
                    LOG_TRACE("Failed to delete node: %d", rc);
                    break;
                }
                j++;
            }
        }

        if (RC_ISOK(rc) && j != generated_num) {
            LOG_ERROR("Radix iteration removed %zu nodes, but expected number "
                      "is  %zu",
                      j, generated_num);
            rc = -1;
        } else {
            LOG_TRACE("Radix iteration removed %zu of %zu nodes", j,
                      generated_num);
        }
    }

    radix_time_stat(&treal1, &tproc1, "removing all generated ip prefixes");

    radix_destroy(tree, NULL);

    return rc;
}

int main(void)
{
    int rc = 0;

    srand((unsigned)time(NULL));

    rc = radix_ipv4_custom_random_test();
    if (RC_ISNOTOK(rc)) {
        LOG_ERROR("Radix ipv4 random test failed: %d\n", rc);
    } else {
        LOG_TRACE("Radix ipv4 random test success: %d\n", rc);
    }

    if (RC_ISOK(rc)) {
        rc = radix_ipv4_random_test();
        if (RC_ISNOTOK(rc)) {
            LOG_ERROR("Radix ipv4 random test failed: %d\n", rc);
        } else {
            LOG_TRACE("Radix ipv4 random test success: %d\n", rc);
        }
    }

    if (RC_ISOK(rc)) {
        rc = radix_ipv4_test();
        if (RC_ISNOTOK(rc)) {
            LOG_ERROR("Radix ipv4 test failed: %d\n", rc);
        } else {
            LOG_TRACE("Radix ipv4 test success: %d\n", rc);
        }
    }

    if (RC_ISOK(rc)) {
        rc = radix_ipv6_test();
        if (RC_ISNOTOK(rc)) {
            LOG_ERROR("Radix ipv6 test failed: %d\n", rc);
        } else {
            LOG_TRACE("Radix ipv6 test success: %d\n", rc);
        }
    }

    if (RC_ISOK(rc)) {
        rc = radix_ipv6_random_test();
        if (RC_ISNOTOK(rc)) {
            LOG_ERROR("Radix ipv6 random test failed: %d\n", rc);
        } else {
            LOG_TRACE("Radix ipv6 random test success: %d\n", rc);
        }
    }

    return rc;
}
