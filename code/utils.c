/*
 *     Filename: utils.c
 *  Description: Source file for packet classification evaluation
 *
 *       Author: Xiaohe Hu
 *
 * Organization: Network Security Laboratory (NSLab),
 *               Research Institute of Information Technology (RIIT),
 *               Tsinghua University (THU)
 *
 *      History: 1. move point operation code here (Xiaohe Hu)
 */

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/queue.h>
#include "utils.h"

int is_equal(union point *left, union point *right)
{
    return left->u128.high == right->u128.high
        && left->u128.low == right->u128.low;
}

int is_less(union point *left, union point *right)
{
    return left->u128.high < right->u128.high ||
        (left->u128.high == right->u128.high &&
         left->u128.low < right->u128.low);
}

int is_less_equal(union point *left, union point *right)
{
    return is_less(left, right) || is_equal(left, right);
}

int is_greater(union point *left, union point *right)
{
    return left->u128.high > right->u128.high ||
        (left->u128.high == right->u128.high &&
         left->u128.low > right->u128.low);
}

int is_greater_equal(union point *left, union point *right)
{
    return is_greater(left, right) || is_equal(left, right);
}

void point_inc(union point *point)
{
    point->u128.low++;

    if (point->u128.low == 0) {
        point->u128.high++;
    }

    return;
}

void point_dec(union point *point)
{
    point->u128.low--;

    if (point->u128.low == -1) {
        point->u128.high--;
    }

    return;
}

void point_not(union point *out, union point *point)
{
    out->u128.high = ~point->u128.high;
    out->u128.low = ~point->u128.low;
    return;
}

void point_and(union point *out, union point *left, union point *right)
{
    out->u128.high = left->u128.high & right->u128.high;
    out->u128.low = left->u128.low & right->u128.low;
    return;
}

void point_or(union point *out, union point *left, union point *right)
{
    out->u128.high = left->u128.high | right->u128.high;
    out->u128.low = left->u128.low | right->u128.low;
    return;
}

void point_xor(union point *out, union point *left, union point *right)
{
    out->u128.high = left->u128.high ^ right->u128.high;
    out->u128.low = left->u128.low ^ right->u128.low;
    return;
}

void point_xnor(union point *out, union point *left, union point *right)
{
    out->u128.high = ~(left->u128.high ^ right->u128.high);
    out->u128.low = ~(left->u128.low ^ right->u128.low);
    return;
}

void point_print(union point *point)
{
    printf("%016llx%016llx\n", point->u128.high, point->u128.low);
}

void set_bit(union point *p, unsigned int bit, unsigned int val)
{
    if (bit < 64) {
        if (val != 0) {
            p->u128.low |= 1ULL << (bit - 64);
        } else {
            p->u128.low &= ~(1ULL << (bit - 64));
        }
    } else {
        if (val != 0) {
            p->u128.high |= 1ULL << (bit - 64);
        } else {
            p->u128.high &= ~(1ULL << (bit - 64));
        }
    }

    return;
}

void gen_prefix_mask(union point *p, unsigned int bits,
        unsigned int mask_len)
{
    if (mask_len == 0) {
        p->u128.high = 0;
        p->u128.low = 0;
    } else if (mask_len <= 64) {
        if (bits < 64) {
            p->u128.high = 0;
            p->u128.low = ~((1ULL << (bits - mask_len)) - 1)
                & ((1ULL << bits) - 1);
        } else if (bits == 64) {
            p->u128.high = 0;
            p->u128.low = ~((1ULL << (64 - mask_len)) - 1);
        } else {
            p->u128.high = ~((1ULL << (64 - mask_len)) - 1);
            p->u128.low = 0;
        }
    } else {
        p->u128.high = -1;
        p->u128.low = ~((1ULL << (128 - mask_len)) - 1);
    }

    return;
}

void gen_suffix_mask(union point *p, unsigned int mask_len)
{
    if (mask_len < 64) {
        p->u128.high = 0;
        p->u128.low = (1ULL << mask_len) - 1;
    } else if (mask_len == 64) {
        p->u128.high = 0;
        p->u128.low = - 1;
    } else if (mask_len < 128) {
        p->u128.high = (1ULL << (mask_len - 64)) - 1;
        p->u128.low = -1;
    } else {
        p->u128.high = -1;
        p->u128.low = - 1;
    }

    return;
}

void range2prefix(struct prefix_head *head, struct range *range,
        unsigned int bits)
{
    union point broad, high, tmp0;
    struct prefix_node *pn;
    struct queue_node *node, *node1;
    struct queue_head queue = STAILQ_HEAD_INITIALIZER(queue);

    STAILQ_INIT(head);

    node = calloc(1, sizeof(*node));
    if (node == NULL) {
        perror("out of memory\n");
        exit(-1);
    }

    node->r = *range;
    node->p.value.u128.high = 0;
    node->p.value.u128.low = 0;
    node->p.prefix_len = 0;

    STAILQ_INSERT_HEAD(&queue, node, n);

    /* I hate recursive function */
    while (!STAILQ_EMPTY(&queue)) {
        node = STAILQ_FIRST(&queue);
        STAILQ_REMOVE_HEAD(&queue, n);

        gen_suffix_mask(&tmp0, bits - node->p.prefix_len);
        point_or(&broad, &node->p.value, &tmp0);

        if (is_equal(&node->r.begin, &node->p.value) &&
            is_equal(&node->r.end, &broad)) {

            pn = calloc(1, sizeof(*pn));
            if (pn == NULL) {
                perror("out of memory\n");
                exit(-1);
            }

            pn->p = node->p;
            STAILQ_INSERT_TAIL(head, pn, n);
            free(node);
            continue;
        }

        node->p.prefix_len++;

        high = node->p.value;
        set_bit(&high, bits - node->p.prefix_len, 1);

        /*
         * binary cut: case A
         *                       !
         * node range     |----| !
         *                       !
         * prefix range |--------!--------|
         *                       !
         */
        if (is_less(&node->r.end, &high)) {
            STAILQ_INSERT_HEAD(&queue, node, n);

        /*
         * binary cut: case B
         *                       !
         * node range            |----|
         *                       !
         * prefix range |--------!--------|
         *                       !
         */
        } else if (is_greater_equal(&node->r.begin, &high)) {
            node->p.value = high;
            STAILQ_INSERT_HEAD(&queue, node, n);

        /*
         * binary cut: case C
         *                       !
         * node range         |--!--|
         *                       !
         * prefix range |--------!--------|
         *                       !
         */
        } else {
            node1 = calloc(1, sizeof(*node1));
            if (node1 == NULL) {
                perror("out of memory\n");
                exit(-1);
            }

            /* left part */
            node1->r.begin = node->r.begin;
            gen_suffix_mask(&tmp0, bits - node->p.prefix_len);
            point_or(&node1->r.end, &node->p.value, &tmp0);
            node1->p.value = node->p.value;
            node1->p.prefix_len = node->p.prefix_len;

            /* right part */
            node->r.begin = high;
            node->p.value = high;

            STAILQ_INSERT_HEAD(&queue, node, n);
            STAILQ_INSERT_HEAD(&queue, node1, n);
        }
    }

    return;
}

void prefix2range(struct range *range, struct prefix *prefix,
        unsigned int bits)
{
    union point point;

    gen_prefix_mask(&point, bits, prefix->prefix_len);
    point_and(&range->begin, &prefix->value, &point);

    gen_suffix_mask(&point, bits - prefix->prefix_len);
    point_or(&range->end, &prefix->value, &point);

    return;
}

void split_range_rule(struct rng_rule_head *head, struct rng_rule *rule)
{
    int i;
    struct rng_rule_node *node;
    struct prefix_node *prfx_node;
    struct prefix_head prfx_head[DIM_MAX];
    struct prefix_node *prfx_cur[DIM_MAX] = {0};
    unsigned int bits[DIM_MAX] = {32, 32, 16, 16, 8};

    bzero(prfx_head, sizeof(prfx_head));
    STAILQ_INIT(head);

    /* range2prefix on each dimension INDEPENDENTLY */
    for (i = 0; i < DIM_MAX; i++) {
        range2prefix(&prfx_head[i], (struct range *)&rule->dim[i], bits[i]);
        prfx_cur[i] = STAILQ_FIRST(&prfx_head[i]);
    }

    /* CROSS PRODUCT all dimensions */
    while (1) {
        node = calloc(1, sizeof(*node));
        if (node == NULL) {
            perror("out of memory\n");
            exit(-1);
        }

        for (i = 0; i < DIM_MAX; i++) {
            prefix2range((struct range *)&node->r.dim[i],
                    &prfx_cur[i]->p, bits[i]);
        }

        node->r.pri = rule->pri;

        STAILQ_INSERT_TAIL(head, node, n);

        /* calculate the carry from the last dimension */
        prfx_cur[DIM_PROTO] = STAILQ_NEXT(prfx_cur[DIM_PROTO], n);

        for (i = DIM_PROTO; i > DIM_INV; i--) {
            if (prfx_cur[i] != NULL) {
                continue;
            }

            /* the first dimension is overflow */
            if (i == DIM_SIP) {
                goto done;
            }

            /* carry forward */
            prfx_cur[i - 1] = STAILQ_NEXT(prfx_cur[i - 1], n);
            prfx_cur[i] = STAILQ_FIRST(&prfx_head[i]);
        }
    }

done:
    for (i = 0; i < DIM_MAX; i++) {
        while (!STAILQ_EMPTY(&prfx_head[i])) {
            prfx_node = STAILQ_FIRST(&prfx_head[i]);
            STAILQ_REMOVE_HEAD(&prfx_head[i], n);
            free(prfx_node);
        }
    }

    return;
}
