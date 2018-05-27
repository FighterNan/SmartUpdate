/*
 *     Filename: hs.h
 *  Description: Header file for packet classification algorithm
 *               HyperSplit
 *
 *       Author: Yaxuan Qi
 *               Xiang Wang
 *               Xiaohe Hu
 *               Nan Zhou
 *
 * Organization: Network Security Laboratory (NSLab),
 *               Research Institute of Information Technology (RIIT),
 *               Tsinghua University (THU)
 */

#ifndef __HS_H__
#define __HS_H__

#include "pc_eval.h"

/*
 * k-d tree
 */
struct hs_node {
    int d2s;
    uint8_t depth;
    union point thresh;
    struct hs_node *child[2];
};

int hs_build(const struct rule_set *rs, void *userdata);
int hs_insrt_update(const struct rule_set *rs, void *userdata);
int hs_classify(const struct packet *pkt, const void *userdata);
int hs_search(const struct trace *t, const void *userdata);
void hs_cleanup(void *userdata);
int hs_build_estimate(const struct rule_set *rs, void *userdata);
int hs_update_estimate(const struct rule_set *rs, const struct rule_set *u_rs, void *userdata);

#endif /* __HS_H__ */
