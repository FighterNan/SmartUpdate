/*
 *     Filename: utils.h
 *  Description: Header file for packet classification evaluation
 *
 *       Author: Xiaohe Hu
 *
 * Organization: Network Security Laboratory (NSLab),
 *               Research Institute of Information Technology (RIIT),
 *               Tsinghua University (THU)
 *
 *      History: 1. move point operation code here (Xiaohe Hu)
 */

#ifndef __UTILS_H__
#define __UTILS_H__

#include <sys/queue.h>
#include "pc_eval.h"

struct rng_rule_node {
    struct rng_rule r;
    STAILQ_ENTRY(rng_rule_node) n;
};

STAILQ_HEAD(rng_rule_head, rng_rule_node);

struct range {
    union point begin;
    union point end;
};

struct range_node {
    struct range r;
    STAILQ_ENTRY(range_node) n;
};

STAILQ_HEAD(range_head, range_node);

struct prefix {
    union point value;
    int prefix_len;
};

struct prefix_node {
    struct prefix p;
    STAILQ_ENTRY(prefix_node) n;
};

STAILQ_HEAD(prefix_head, prefix_node);

struct queue_node {
    struct range r;
    struct prefix p;
    STAILQ_ENTRY(queue_node) n;
};

STAILQ_HEAD(queue_head, queue_node);

int is_equal(union point *left, union point *right);
int is_less(union point *left, union point *right);
int is_less_equal(union point *left, union point *right);
int is_greater(union point *left, union point *right);
int is_greater_equal(union point *left, union point *right);

void point_inc(union point *point);
void point_dec(union point *point);
void point_not(union point *out, union point *point);
void point_and(union point *out, union point *left, union point *right);
void point_or(union point *out, union point *left, union point *right);
void point_xor(union point *out, union point *left, union point *right);
void point_xnor(union point *out, union point *left, union point *right);
void point_print(union point *point);

void set_bit(union point *p, unsigned int bit, unsigned int val);

void gen_prefix_mask(union point *p, unsigned int bits,
        unsigned int mask_len);
void gen_suffix_mask(union point *p, unsigned int mask_len);

void range2prefix(struct prefix_head *head, struct range *range,
        unsigned int bits);
void prefix2range(struct range *range, struct prefix *prefix,
        unsigned int bits);

void split_range_rule(struct rng_rule_head *head, struct rng_rule *rule);

#endif /* __UTILS_H__ */
