/*
 *     Filename: tss.h
 *  Description: Header file for packet classification algorithm
 *               Tuple Space Search
 *
 *       Author: Xiaohe Hu
 *
 * Organization: Network Security Laboratory (NSLab),
 *               Research Institute of Information Technology (RIIT),
 *               Tsinghua University (THU)
 */

#ifndef __TSS_H__
#define __TSS_H__

#include <sys/queue.h>
#include "pc_eval.h"
#include "uthash.h"

struct hash_entry {
    char *key;
    int pri;
    UT_hash_handle hh;
};

struct tss_node {
    struct hash_entry *ht;
    int tuple[DIM_MAX];
    int key_bytes;
    int highest_pri;
    int tpl_id;
    TAILQ_ENTRY(tss_node) entry;
};

TAILQ_HEAD(tss_head, tss_node);

void sort_tss_list(struct tss_head *p_th, struct tss_node *p_l_tn, struct tss_node *p_r_tn);
int tss_build(const struct rule_set *rs, void *userdata);
int tss_classify(const struct packet *pkt, const void *userdata);
int tss_search(const struct trace *t, const void *userdata);
void tss_cleanup(void *userdata);
int tss_build_estimate(const struct rule_set *rs, void *userdata);
int tss_update_estimate(const struct rule_set *rs, const struct rule_set *u_rule_set, void *userdata);

#endif /* __TSS_H__ */
