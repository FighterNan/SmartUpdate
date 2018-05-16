/*
 *     Filename: hs.c
 *  Description: Source file for packet classification algorithm
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <time.h>
#include "hs.h"
#include "utils.h"

/* we need a stack to traverse k-d tree */
struct s_node {
    struct rng_rule r;
    struct hs_node *p_tn;
    STAILQ_ENTRY(s_node) entry;
};

STAILQ_HEAD(s_head, s_node);

struct seg_point {
    union point pnt;
    struct { uint8_t begin :1; uint8_t end :1; } flag;
};

static struct {
    size_t segment_num[DIM_MAX];
    size_t segment_total;

    size_t worst_depth;
    size_t average_depth;

    size_t tree_node_num;
    size_t leaf_node_num;

    /* TODO: assume max_depth = 128 */
    size_t depth_node[128][2];
} g_statistics;

static struct {
    float overlap_density[DIM_MAX];
    size_t distribute[DIM_MAX];
    int segment_sum;
    int choose[DIM_MAX];
    int choose_num;
} build_estimator;

static struct {
    float overlap_density[DIM_MAX];
    size_t distribute[DIM_MAX];
} update_estimator;

static int seg_pnt_cmp(const void *a, const void *b)
{
    struct seg_point *pa = (typeof(pa))a;
    struct seg_point *pb = (typeof(pb))b;

    if (is_less(&pa->pnt, &pb->pnt)) {
        return -1;
    } else if (is_greater(&pa->pnt, &pb->pnt)) {
        return 1;
    } else {
        return 0;
    }
}


static int build_hs_tree(
        const struct rule_set *rs, struct hs_node *cur_node, int depth)
{
    int *wght, wght_all;
    float wght_avg, wght_jdg;
    int max_pnt, num, pnt_num, d2s, d, i, j;

    union point thresh;
    struct rule_set child_rs;
    struct seg_point *seg_pnts;
    struct range lrange, rrange;

    max_pnt = d2s = 0;
    num = rs->num << 1;
    wght_avg = rs->num + 1; //max, all rules project one segment

    bzero(&lrange, sizeof(lrange));
    bzero(&rrange, sizeof(rrange));

    wght = malloc(num * sizeof(*wght));
    seg_pnts  = malloc(num * sizeof(*seg_pnts));
    child_rs.r_rules = malloc(rs->num * sizeof(*child_rs.r_rules));
    if (wght == NULL || seg_pnts == NULL || child_rs.r_rules == NULL) {
        SAFE_FREE(wght);
        SAFE_FREE(seg_pnts);
        SAFE_FREE(child_rs.r_rules);
        return -1;
    }

    /*
     * start here
     */
    for (d = 0; d < DIM_MAX; d++) {
        bzero(wght, num * sizeof(*wght));
        bzero(seg_pnts, num * sizeof(*seg_pnts));

        /*
         * shadow rules on each dim
         */
        for (i = 0; i < num; i += 2) {
            seg_pnts[i].pnt = rs->r_rules[i >> 1].dim[d][0];
            seg_pnts[i].flag.begin = 1;
            seg_pnts[i + 1].pnt = rs->r_rules[i >> 1].dim[d][1];
            seg_pnts[i + 1].flag.end = 1;
        }

        qsort(seg_pnts, num, sizeof(*seg_pnts), seg_pnt_cmp);

        /*
         * make segments. Note: pnts with the same val may form one seg
         *                Deal with the same val condition
         *                Compact the seg_pnts
         */
        for (pnt_num = 0, i = pnt_num + 1; i < num; i++) {
            //for loop used to scan two indexes
            //pnt_num increases conditionally, i increases directly
            //pnt_num increases in the loops according to some condition
            //i increases every loop
            if (is_equal(&seg_pnts[pnt_num].pnt, &seg_pnts[i].pnt)) {
                seg_pnts[pnt_num].flag.begin |= seg_pnts[i].flag.begin;
                seg_pnts[pnt_num].flag.end |= seg_pnts[i].flag.end;

                if (i + 1 != num) {
                    //when i is not the end, go to the next loop
                    //pnt_num doesn't increase
                    continue;
                }

                if (seg_pnts[pnt_num].flag.begin & seg_pnts[pnt_num].flag.end) {
                    seg_pnts[pnt_num + 1] = seg_pnts[pnt_num];
                    seg_pnts[pnt_num++].flag.end = 0;
                    seg_pnts[pnt_num].flag.begin = 0;
                }

                break;
            }

            //the following statements only work
            //when seg_pnts[pnt_num] is unequal to seg_pnts[i] or i == num-1
            //when the former if is true, this if is true possibly
            if (seg_pnts[pnt_num].flag.begin & seg_pnts[pnt_num].flag.end) {
                seg_pnts[pnt_num + 1] = seg_pnts[pnt_num];
                seg_pnts[pnt_num++].flag.end = 0;
                seg_pnts[pnt_num].flag.begin = 0;
            }

            seg_pnts[++pnt_num] = seg_pnts[i];
        }

        if (++pnt_num > max_pnt) {
            max_pnt = pnt_num;
        }

        if (depth == 0) {
            g_statistics.segment_num[d] = pnt_num;
            g_statistics.segment_total *= pnt_num;
        }

        if (pnt_num < 3) {
            continue; /* skip this dim: no more ranges */
        }

        /*
         * gen heuristic info
         */
        for (wght_all = 0, i = 0; i < pnt_num - 1; i++) {
            for (wght[i] = 0, j = 0; j < rs->num; j++) {
                if (is_less_equal(&rs->r_rules[j].dim[d][0],
                        &seg_pnts[i].pnt) &&
                    is_greater_equal(&rs->r_rules[j].dim[d][1],
                        &seg_pnts[i + 1].pnt)) {
                    wght[i]++;
                    wght_all++;
                }
            }
        }

        wght_jdg = (float)wght_all / (pnt_num - 1);

        if (wght_avg <= wght_jdg) {
            continue; /* skip this dim: the less the better */
        }

        /*
         * found dimension candidate
         */
        d2s = d, wght_avg = wght_jdg;

        for (wght_jdg = wght[0], i = 1; i < pnt_num - 1;
            wght_jdg += wght[i], i++) {

            thresh = seg_pnts[i].pnt;
            if (seg_pnts[i].flag.begin) {
                point_dec(&thresh);
            }

            if (wght_jdg > (wght_all / 2.f)) {
                break; /* reach the half of the wght */
            }
        }

        lrange.begin = seg_pnts[0].pnt;
        lrange.end = thresh;

        rrange.begin = thresh;
        point_inc(&rrange.begin);
        rrange.end = seg_pnts[pnt_num - 1].pnt;

    } /* end of for (d = 0; d < DIM_MAX; d++) */

    SAFE_FREE(seg_pnts);
    SAFE_FREE(wght);

    /*
     * gen leaf node
     */
    if (max_pnt < 3) {
        cur_node->d2s = -1;
        cur_node->depth = depth;
        cur_node->thresh.u64 = rs->r_rules[0].pri;
        cur_node->child[0] = NULL;
        cur_node->child[1] = NULL;

        SAFE_FREE(child_rs.r_rules);
        g_statistics.leaf_node_num++;
        g_statistics.depth_node[depth][1]++;
        g_statistics.average_depth += depth;
        if (g_statistics.worst_depth < depth) {
            g_statistics.worst_depth = depth;
        }
        return 0;
    }

    cur_node->d2s = d2s;
    build_estimator.choose[d2s]++;
    build_estimator.choose_num++;
    cur_node->depth = depth;
    cur_node->thresh = thresh;

    /*
     * gen left child
     */
    cur_node->child[0] = malloc(sizeof(*cur_node->child[0]));
    if (cur_node->child[0] == NULL) {
        SAFE_FREE(child_rs.r_rules);
        return -1;
    }

    bzero(child_rs.r_rules, rs->num * sizeof(*child_rs.r_rules));

    for (i = 0, child_rs.num = 0; i < rs->num; i++) {
        if (is_greater(&rs->r_rules[i].dim[d2s][0], &lrange.end) ||
            is_less(&rs->r_rules[i].dim[d2s][1], &lrange.begin)) {
            continue;
        }

        child_rs.r_rules[child_rs.num] = rs->r_rules[i];

        /* rules must be trimmed */
        if (is_less(&child_rs.r_rules[child_rs.num].dim[d2s][0],
            &lrange.begin)) {
            child_rs.r_rules[child_rs.num].dim[d2s][0] = lrange.begin;
        }
        if (is_greater(&child_rs.r_rules[child_rs.num].dim[d2s][1],
            &lrange.end)) {
            child_rs.r_rules[child_rs.num].dim[d2s][1] = lrange.end;
        }

        child_rs.num++;
    }

    if (build_hs_tree(&child_rs, cur_node->child[0], depth + 1) != 0) {
        SAFE_FREE(cur_node->child[0]);
        SAFE_FREE(child_rs.r_rules);
        return -1;
    }

    /*
     * gen right child
     */
    cur_node->child[1] = malloc(sizeof(*cur_node->child[1]));
    if (cur_node->child[1] == NULL) {
        SAFE_FREE(child_rs.r_rules);
        return -1;
    }

    bzero(child_rs.r_rules, rs->num * sizeof(*child_rs.r_rules));

    for (i = 0, child_rs.num = 0; i < rs->num; i++) {
        if (is_greater(&rs->r_rules[i].dim[d2s][0], &rrange.end) ||
            is_less(&rs->r_rules[i].dim[d2s][1], &rrange.begin)) {
            continue;
        }

        child_rs.r_rules[child_rs.num] = rs->r_rules[i];

        /* rules must be trimmed */
        if (is_less(&child_rs.r_rules[child_rs.num].dim[d2s][0],
            &rrange.begin)) {
            child_rs.r_rules[child_rs.num].dim[d2s][0] = rrange.begin;
        }
        if (is_greater(&child_rs.r_rules[child_rs.num].dim[d2s][1],
            &rrange.end)) {
            child_rs.r_rules[child_rs.num].dim[d2s][1] = rrange.end;
        }

        child_rs.num++;
    }

    if (build_hs_tree(&child_rs, cur_node->child[1], depth + 1) != 0) {
        SAFE_FREE(cur_node->child[1]);
        SAFE_FREE(child_rs.r_rules);
        return -1;
    }

    SAFE_FREE(child_rs.r_rules);
    g_statistics.tree_node_num++;
    g_statistics.depth_node[depth][0]++;
    return 0;
}

static void cleanup_hs_tree(struct hs_node *node)
{
    if (node->child[0] == NULL && node->child[1] == NULL) {
        return;
    }

    cleanup_hs_tree(node->child[0]);
    SAFE_FREE(node->child[0]);

    cleanup_hs_tree(node->child[1]);
    SAFE_FREE(node->child[1]);

    return;
}

static void printf_stats_nodes()
{
    int i;

    /* depth statistics */
    printf("\nworst_depth = %lu", g_statistics.worst_depth);
    printf("\naverage_depth = %f", (float)g_statistics.average_depth /
            g_statistics.leaf_node_num);

    /* node statistics */
    printf("\ntree_node_num = %lu", g_statistics.tree_node_num);
    printf("\nleaf_node_num = %lu", g_statistics.leaf_node_num);
    printf("\ntotal_memory = %lu", (g_statistics.tree_node_num +
        g_statistics.leaf_node_num) << 3);

    /* node statistics detail */
    printf("\ndepth   node    intrnl  leaf\n");
    for (i = 0; i <= g_statistics.worst_depth; i++) {
        printf("%-8d%-8lu%-8lu%-8lu\n", i, g_statistics.depth_node[i][0] +
            g_statistics.depth_node[i][1], g_statistics.depth_node[i][0],
            g_statistics.depth_node[i][1]);
    }
    printf("\n");

    return;
}

int hs_build(const struct rule_set *rs, void *userdata)
{
    int i;
    struct hs_node *root = calloc(1, sizeof(*root));

    if (root == NULL || rs->r_rules == NULL) {
        return -1;
    }

    g_statistics.segment_total = 1;

    // init
    for (i=0; i<DIM_MAX; ++i) {
        build_estimator.choose[i]=0;
    }

    if (build_hs_tree(rs, root, 0) == 0) {
        /* rule_set statistics */
        printf("segment_num = ");
        for (i = 0; i < DIM_MAX; i++) {
            printf("%lu ", g_statistics.segment_num[i]);
        }
        printf("\n");

        printf("\nsegment_total = %lu", g_statistics.segment_total);

        printf_stats_nodes();

        *(struct hs_node **) userdata = root;
        return 0;
    } else {
        *(struct hs_node **) userdata = NULL;
        return -1;
    }
}

int hs_insrt_rule(struct rng_rule *p_r, void *userdata)
{
    struct hs_node *p_tnode = *(typeof(p_tnode) *)userdata;
    struct s_node *p_sn = NULL, *p_tmp_sn = NULL;
    struct s_head *p_sh = malloc(sizeof *p_sh);
    int i;

    STAILQ_INIT(p_sh);
    p_sn = calloc(1, sizeof *p_sn);
    p_sn->r.dim[0][1].u32 = (1UL << 32) - 1;
    p_sn->r.dim[1][1].u32 = (1UL << 32) - 1;
    p_sn->r.dim[2][1].u16 = (1U << 16) - 1;
    p_sn->r.dim[3][1].u16 = (1U << 16) - 1;
    p_sn->r.dim[4][1].u8 = 255;
    p_sn->p_tn = p_tnode;
    STAILQ_INSERT_HEAD(p_sh, p_sn, entry);

    while (!STAILQ_EMPTY(p_sh)) {
        p_sn = STAILQ_FIRST(p_sh);
        STAILQ_REMOVE_HEAD(p_sh, entry);
        while (p_sn->p_tn->d2s != -1) {
            if (is_less_equal(&p_r->dim[p_sn->p_tn->d2s][1], &p_sn->p_tn->thresh)) {
                p_sn->r.dim[p_sn->p_tn->d2s][1] = p_sn->p_tn->thresh;
                p_sn->p_tn = p_sn->p_tn->child[0];
            } else if (is_less(&p_sn->p_tn->thresh, &p_r->dim[p_sn->p_tn->d2s][0])) {
                p_sn->r.dim[p_sn->p_tn->d2s][0] = p_sn->p_tn->thresh;
                point_inc(&p_sn->r.dim[p_sn->p_tn->d2s][0]);
                p_sn->p_tn = p_sn->p_tn->child[1];
            } else {
                p_tmp_sn = malloc(sizeof *p_tmp_sn);
                p_tmp_sn->p_tn = p_sn->p_tn->child[1];
                p_tmp_sn->r = p_sn->r;
                p_tmp_sn->r.dim[p_sn->p_tn->d2s][0] = p_sn->p_tn->thresh;
                point_inc(&p_tmp_sn->r.dim[p_sn->p_tn->d2s][0]);
                STAILQ_INSERT_HEAD(p_sh, p_tmp_sn, entry);
                p_sn->r.dim[p_sn->p_tn->d2s][1] = p_sn->p_tn->thresh;
                p_sn->p_tn = p_sn->p_tn->child[0];
            }
        }
        if (p_r->pri >= p_sn->p_tn->thresh.u32) {
            SAFE_FREE(p_sn);
            continue;
        }
        /* in case that p_sn->r is "in" p_r */
        for (i = 0; i < DIM_MAX; i++) {
            if (is_greater(&p_r->dim[i][0], &p_sn->r.dim[i][0])) {
                /* left */
                p_tnode = calloc(1, sizeof *p_tnode);
                p_tnode->d2s = -1;
                p_tnode->depth = p_sn->p_tn->depth + 1;
                p_tnode->thresh.u32 = p_sn->p_tn->thresh.u32;
                p_sn->p_tn->child[0] = p_tnode;
                /* right */
                p_tnode = calloc(1, sizeof *p_tnode);
                p_tnode->d2s = -1;
                p_tnode->depth = p_sn->p_tn->depth + 1;
                p_tnode->thresh.u32 = p_sn->p_tn->thresh.u32;
                p_sn->p_tn->child[1] = p_tnode;
                /* g_statistics */
                g_statistics.tree_node_num++;
                g_statistics.leaf_node_num++;
                g_statistics.depth_node[p_sn->p_tn->depth][0]++;
                g_statistics.depth_node[p_sn->p_tn->depth][1]--;
                g_statistics.depth_node[p_tnode->depth][1] += 2;
                g_statistics.average_depth += 1 + p_tnode->depth;
                if (g_statistics.worst_depth < p_tnode->depth) {
                    g_statistics.worst_depth = p_tnode->depth;
                }
                /* itself */
                p_sn->p_tn->d2s = i;
                p_sn->p_tn->thresh = p_r->dim[i][0];
                point_dec(&p_sn->p_tn->thresh);
                //printf("d2s:%d; thresh:%u; left_pri:%u\n", i, p_sn->p_tn->thresh.u32, p_tnode->thresh.u32);
                p_sn->p_tn = p_sn->p_tn->child[1];
                p_sn->r.dim[i][0] = p_r->dim[i][0];
            }
            if (is_less(&p_r->dim[i][1], &p_sn->r.dim[i][1])) {
                /* right */
                p_tnode = calloc(1, sizeof *p_tnode);
                p_tnode->d2s = -1;
                p_tnode->depth = p_sn->p_tn->depth + 1;
                p_tnode->thresh.u32 = p_sn->p_tn->thresh.u32;
                p_sn->p_tn->child[1] = p_tnode;
                /* left */
                p_tnode = calloc(1, sizeof *p_tnode);
                p_tnode->d2s = -1;
                p_tnode->depth = p_sn->p_tn->depth + 1;
                p_tnode->thresh.u32 = p_sn->p_tn->thresh.u32;
                p_sn->p_tn->child[0] = p_tnode;
                /* g_statistics */
                g_statistics.tree_node_num++;
                g_statistics.leaf_node_num++;
                g_statistics.depth_node[p_sn->p_tn->depth][0]++;
                g_statistics.depth_node[p_sn->p_tn->depth][1]--;
                g_statistics.depth_node[p_tnode->depth][1] += 2;
                g_statistics.average_depth += 1 + p_tnode->depth;
                if (g_statistics.worst_depth < p_tnode->depth) {
                    g_statistics.worst_depth = p_tnode->depth;
                }
                /* itself */
                p_sn->p_tn->d2s = i;
                p_sn->p_tn->thresh = p_r->dim[i][1];
                //printf("d2s:%d; thresh:%u; right_pri:%u\n", i, p_sn->p_tn->thresh.u32, p_tnode->thresh.u32);
                p_sn->p_tn = p_sn->p_tn->child[0];
            }
        }
        p_sn->p_tn->thresh.u32 = p_r->pri;
        SAFE_FREE(p_sn);
    }
    SAFE_FREE(p_sh);
    return 0;
}


int hs_insrt_update(const struct rule_set *rs, void *userdata)
{
    if (!*(void **) userdata || !rs->r_rules) return -1;
    int i;

    for (i = 0; i < rs->num; i++) {
        if (hs_insrt_rule(&rs->r_rules[i], userdata) != 0) {
            return -1;
        }
    }

    printf_stats_nodes();

    return 0;
}

int hs_classify(const struct packet *pkt, const void *userdata)
{
    struct hs_node *node = *(typeof(node) *)userdata;

    while (node->child[0] != NULL || node->child[1] != NULL) {
        //printf("d2s:%d; pkt->val[%d].u32:%u; node.thresh.u32:%u\n", node->d2s, node->d2s, pkt->val[node->d2s].u32, node->thresh.u32);
        if (pkt->val[node->d2s].u32 <= node->thresh.u32) {
            //printf("left\n");
            node = node->child[0];
        } else {
            //printf("right\n");
            node = node->child[1];
        }
    }

    return node->thresh.u32;
}

int hs_search(const struct trace *t, const void *userdata)
{
    int i, c;

    for (i = 0; i < t->num; i++) {
        if ((c = hs_classify(&t->pkts[i], userdata)) != t->pkts[i].match) {
            fprintf(stderr, "pkt[%d] match:%d, classify:%d\n", i+1, t->pkts[i].match+1, c+1);
            return -1;
        }
    }

    return 0;
}

int estimate_build_hs_tree(const struct rule_set *rs, struct hs_node *cur_node) {
    int *wght, wght_all;
    float wght_avg;
    int max_pnt, num, pnt_num, d2s, d, i, j;

    union point thresh;
    struct rule_set child_rs;
    struct seg_point *seg_pnts;
    struct range lrange, rrange;

    max_pnt = d2s = 0;
    num = rs->num << 1;

    wght_avg = rs->num + 1;

    bzero(&lrange, sizeof(lrange));
    bzero(&rrange, sizeof(rrange));

    wght = malloc(num * sizeof(*wght));
    seg_pnts  = malloc(num * sizeof(*seg_pnts));
    child_rs.r_rules = malloc(rs->num * sizeof(*child_rs.r_rules));
    if (wght == NULL || seg_pnts == NULL || child_rs.r_rules == NULL) {
        SAFE_FREE(wght);
        SAFE_FREE(seg_pnts);
        SAFE_FREE(child_rs.r_rules);
        return -1;
    }

    /*
     * estimating starts here
     */
    build_estimator.segment_sum=0;
    for (d = 0; d < DIM_MAX; d++) {
        bzero(wght, num * sizeof(*wght));
        bzero(seg_pnts, num * sizeof(*seg_pnts));

        for (i = 0; i < num; i += 2) {
            seg_pnts[i].pnt = rs->r_rules[i >> 1].dim[d][0];
            seg_pnts[i].flag.begin = 1;
            seg_pnts[i + 1].pnt = rs->r_rules[i >> 1].dim[d][1];
            seg_pnts[i + 1].flag.end = 1;
        }

        qsort(seg_pnts, num, sizeof(*seg_pnts), seg_pnt_cmp);

        /*
         * make segments. Note: pnts with the same val may form one seg
         *                Deal with the same val condition
         *                Compact the seg_pnts
         */

        for (pnt_num = 0, i = pnt_num + 1; i < num; i++) {
            if (is_equal(&seg_pnts[pnt_num].pnt, &seg_pnts[i].pnt)) {
                seg_pnts[pnt_num].flag.begin |= seg_pnts[i].flag.begin;
                seg_pnts[pnt_num].flag.end |= seg_pnts[i].flag.end;

                if (i + 1 != num) {
                    //when i is not the end, go to the next loop
                    //pnt_num doesn't increase
                    continue;
                }

                if (seg_pnts[pnt_num].flag.begin & seg_pnts[pnt_num].flag.end) {
                    seg_pnts[pnt_num + 1] = seg_pnts[pnt_num];
                    seg_pnts[pnt_num++].flag.end = 0;
                    seg_pnts[pnt_num].flag.begin = 0;
                }
                break;
            }
            //the following statements only work
            //when seg_pnts[pnt_num] is unequal to seg_pnts[i] or i == num-1
            //when the former if is true, this if is true possibly
            if (seg_pnts[pnt_num].flag.begin & seg_pnts[pnt_num].flag.end) {
                seg_pnts[pnt_num + 1] = seg_pnts[pnt_num];
                seg_pnts[pnt_num++].flag.end = 0;
                seg_pnts[pnt_num].flag.begin = 0;
            }
            seg_pnts[++pnt_num] = seg_pnts[i];
        }
        if (++pnt_num > max_pnt) {
            max_pnt = pnt_num;
        }
        if (pnt_num < 3) {
            continue; /* skip this dim: no more ranges */
        }
        build_estimator.distribute[d]=pnt_num;
        build_estimator.segment_sum+=pnt_num;

        /*
         * gen heuristic info
         */
        for (wght_all = 0, i = 0; i < pnt_num - 1; i++) {
            for (wght[i] = 0, j = 0; j < rs->num; j++) {
                if (is_less_equal(&rs->r_rules[j].dim[d][0],
                                  &seg_pnts[i].pnt) &&
                    is_greater_equal(&rs->r_rules[j].dim[d][1],
                                     &seg_pnts[i + 1].pnt)) {
                    wght[i]++;
                    wght_all++;
                }
            }
        }
        build_estimator.overlap_density[d] = (float)wght_all / (rs->num - 1);
    }
    return 0;
}

int estimate_update_hs_tree(const struct rule_set *rs, const struct rule_set *u_rs, struct hs_node *cur_node) {
    int *wght, wght_all;
    float wght_avg;
    int max_pnt, num, pnt_num, d2s, d, i, j;

    union point thresh;
    struct rule_set child_rs;
    struct seg_point *seg_pnts;
    struct range lrange, rrange;

    max_pnt = d2s = 0;
    num = rs->num << 1;

    wght_avg = rs->num + 1;

    bzero(&lrange, sizeof(lrange));
    bzero(&rrange, sizeof(rrange));

    wght = malloc(num * sizeof(*wght));
    seg_pnts  = malloc(num * sizeof(*seg_pnts));
    child_rs.r_rules = malloc(rs->num * sizeof(*child_rs.r_rules));
    if (wght == NULL || seg_pnts == NULL || child_rs.r_rules == NULL) {
        SAFE_FREE(wght);
        SAFE_FREE(seg_pnts);
        SAFE_FREE(child_rs.r_rules);
        return -1;
    }

    /*
     * estimating starts here
     */
    for (d = 0; d < DIM_MAX; d++) {
        bzero(wght, num * sizeof(*wght));
        bzero(seg_pnts, num * sizeof(*seg_pnts));

        for (i = 0; i < num; i += 2) {
            seg_pnts[i].pnt = rs->r_rules[i >> 1].dim[d][0];
            seg_pnts[i].flag.begin = 1;
            seg_pnts[i + 1].pnt = rs->r_rules[i >> 1].dim[d][1];
            seg_pnts[i + 1].flag.end = 1;
        }

        qsort(seg_pnts, num, sizeof(*seg_pnts), seg_pnt_cmp);

        /*
         * make segments. Note: pnts with the same val may form one seg
         *                Deal with the same val condition
         *                Compact the seg_pnts
         */

        for (pnt_num = 0, i = pnt_num + 1; i < num; i++) {
            if (is_equal(&seg_pnts[pnt_num].pnt, &seg_pnts[i].pnt)) {
                seg_pnts[pnt_num].flag.begin |= seg_pnts[i].flag.begin;
                seg_pnts[pnt_num].flag.end |= seg_pnts[i].flag.end;

                if (i + 1 != num) {
                    //when i is not the end, go to the next loop
                    //pnt_num doesn't increase
                    continue;
                }

                if (seg_pnts[pnt_num].flag.begin & seg_pnts[pnt_num].flag.end) {
                    seg_pnts[pnt_num + 1] = seg_pnts[pnt_num];
                    seg_pnts[pnt_num++].flag.end = 0;
                    seg_pnts[pnt_num].flag.begin = 0;
                }
                break;
            }
            //the following statements only work
            //when seg_pnts[pnt_num] is unequal to seg_pnts[i] or i == num-1
            //when the former if is true, this if is true possibly
            if (seg_pnts[pnt_num].flag.begin & seg_pnts[pnt_num].flag.end) {
                seg_pnts[pnt_num + 1] = seg_pnts[pnt_num];
                seg_pnts[pnt_num++].flag.end = 0;
                seg_pnts[pnt_num].flag.begin = 0;
            }
            seg_pnts[++pnt_num] = seg_pnts[i];
        }
        if (++pnt_num > max_pnt) {
            max_pnt = pnt_num;
        }
        if (pnt_num < 3) {
            continue; /* skip this dim: no more ranges */
        }
        update_estimator.distribute[d]=pnt_num;

        /*
         * gen heuristic info
         */
        for (wght_all = 0, i = 0; i < pnt_num - 1; i++) {
            for (wght[i] = 0, j = 0; j < u_rs->num; j++) {
                if (is_less_equal(&u_rs->r_rules[j].dim[d][0],
                                  &seg_pnts[i].pnt) &&
                    is_greater_equal(&u_rs->r_rules[j].dim[d][1],
                                     &seg_pnts[i + 1].pnt)) {
                    wght[i]++;
                    wght_all++;
                }
            }
        }
        update_estimator.overlap_density[d] = (float)wght_all / (u_rs->num - 1);
    }
    return 0;
}

int hs_build_estimate(const struct rule_set *rs, void *userdata) {
    int i;
    float time_base_operation = 10;
    float avg_density, estimate_build_time;
    struct hs_node *root = calloc(1, sizeof(*root));

    if (root == NULL || rs->r_rules == NULL) {
        return -1;
    }

    if (estimate_build_hs_tree(rs, root) == 0) {
        printf("Overlap density = ");
        for (i = 0; i < DIM_MAX; i++) {
            printf("%f ", build_estimator.overlap_density[i]);
        }
        printf("\n");
        printf("Distribute = ");
        for (i = 0; i < DIM_MAX; i++) {
            printf("%zu ", build_estimator.distribute[i]);
        }
        printf("\n");
        avg_density=0;
        for(i=0; i<DIM_MAX; ++i)
            avg_density+=build_estimator.distribute[i]*build_estimator.overlap_density[i]
                         /(float)build_estimator.segment_sum;
        printf("Average density = %f \n", avg_density);
        printf("Building rule num = %d \n", rs->num);
        estimate_build_time=time_base_operation*rs->num*avg_density;
        printf("Estimated time:%f \n", estimate_build_time);
    } else {
        *(struct hs_node **) userdata = NULL;
        return -1;
    }
    return 0;
}

//float get_base_operation(const struct rule_set *u_rs, void *userdata) {
//
//    uint64_t timediff;
//    struct timeval starttime, stoptime;
//    int num = ADAPTED_RULE_NUM<u_rs->num?ADAPTED_RULE_NUM:u_rs->num;
////    int num = u_rs->num/100;
//    int rand_index[num];
//    int i, j;
//
//    if (!*(void **) userdata || !u_rs->r_rules) return -1;
//
//    // randomly choose ADAPTED_RULE_NUM rules from u_rs
//    srand((int)time(0));
//    rand_index[0]=rand()%u_rs->num+1;
//    for(i=1; i<num; ++i)
//    {
//        rand_index[i]=rand()%u_rs->num+1;
//        for(j=0;j<i;j++)
//        {
//            if(rand_index[i]==rand_index[j])
//            {
//                i--;
//            }
//        }
//    }
//
//    gettimeofday(&starttime, NULL);
//
//    for (i = 0; i < num; i++) {
//        if (hs_insrt_rule(&u_rs->r_rules[rand_index[i]], userdata) != 0) {
//            return -1;
//        }
//    }
//    gettimeofday(&stoptime, NULL);
//    timediff = make_timediff(&starttime, &stoptime);
//
//    return timediff/(float)num;
//}

int hs_update_estimate(const struct rule_set *rs, const struct rule_set *u_rs, void *userdata) {
    int i;

    float time_base_operation = 1;
    int thresh = 40;
    float avg_density, estimate_build_time;
    struct hs_node *root = calloc(1, sizeof(*root));

    uint64_t timediff;
    struct timeval starttime, stoptime;

    if (root == NULL || rs->r_rules == NULL) {
        return -1;
    }

    gettimeofday(&starttime, NULL);

//    // method 1
//    time_base_operation = get_base_operation(u_rs, userdata);
//    estimate_build_time = u_rs->num*time_base_operation;
//    printf("Base operation = %f \n", time_base_operation);
//    printf("Estimated time:%f \n", estimate_build_time);

//     method 2
    if (estimate_update_hs_tree(rs, u_rs, root) == 0) {
        printf("Overlap density = ");
        for (i = 0; i < DIM_MAX; i++) {
            printf("%f ", update_estimator.overlap_density[i]);
        }
        printf("\n");
        printf("Choose = ");
        for (i = 0; i < DIM_MAX; i++) {
            printf("%d ", build_estimator.choose[i]);
        }
        printf("\n");
        avg_density=0;
        for(i=0; i<DIM_MAX; ++i)
            avg_density+=build_estimator.choose[i]*update_estimator.overlap_density[i]
                         /(float)build_estimator.choose_num;
        printf("Average density = %f \n", avg_density);
        printf("Updating rule num = %d \n", u_rs->num);

        if (avg_density > thresh)
            time_base_operation=10;

        printf("Adapted base operation = %f \n", time_base_operation);
        estimate_build_time=time_base_operation*u_rs->num*avg_density;
        printf("Estimated time:%f \n", estimate_build_time);
    } else {
        *(struct hs_node **) userdata = NULL;
        return -1;
    }
    gettimeofday(&stoptime, NULL);
    timediff = make_timediff(&starttime, &stoptime);
    printf("Estimating pass\n");
    printf("Time for estimating(us): %llu\n", timediff);
    return 0;
}

void hs_cleanup(void *userdata)
{
    struct hs_node *rt = *(typeof(rt) *)userdata;
    cleanup_hs_tree(rt);
    SAFE_FREE(rt);

    return;
}
