/*
 *     Filename: tss.c
 *  Description: Source file for packet classification algorithm
 *               Tuple Space Search
 *
 *       Author: Xiaohe Hu
 *               Nan Zhou
 *
 * Organization: Network Security Laboratory (NSLab),
 *               Research Institute of Information Technology (RIIT),
 *               Tsinghua University (THU)
 */

#include <stdio.h>
#include <assert.h>
#include "tss.h"
#include "uthash.h"

int field_widths[DIM_MAX] = {4, 4, 2, 2, 1};    /* bytes */

static int tpl_is_equal(int *t1, int *t2, int num)
{
    int i;
    for (i = 0; i < num; i++) {
        if (t1[i] != t2[i]) {
            return 0;
        }
    }
    return 1;
}


static char *create_key(int key_bytes, const union point *dim, int *tuple)
{
    // tuple[32, 32, 0, 16, 8]
    int j, offset = 0;
    union point p;
    char *key = calloc(key_bytes, sizeof *key);
    for (j = 0; j < DIM_MAX; j++) {
        if (!tuple[j]) continue;
        p.u32 = dim[j].u32 & ~((1U << (field_widths[j] * 8 - tuple[j])) - 1);
        memcpy(key + offset, &p, field_widths[j]);
        offset += field_widths[j];
    }
    assert(offset == key_bytes);
    return key;
}


static void cpy_tss_node(struct tss_node *p_l_tn, struct tss_node *p_r_tn)
{
    if (!p_l_tn || !p_r_tn) return;
    int i;
    p_l_tn->ht = p_r_tn->ht;
    for (i = 0; i < DIM_MAX; i++) {
        p_l_tn->tuple[i] = p_r_tn->tuple[i];
    }
    p_l_tn->key_bytes = p_r_tn->key_bytes;
    p_l_tn->highest_pri = p_r_tn->highest_pri;
}

static void swap_tss_node(struct tss_node *p_l_tn, struct tss_node *p_r_tn)
{
    if (p_l_tn == p_r_tn) return;
    struct tss_node *p_tmp_tn = calloc(1, sizeof *p_tmp_tn);
    cpy_tss_node(p_tmp_tn, p_l_tn);
    cpy_tss_node(p_l_tn, p_r_tn);
    cpy_tss_node(p_r_tn, p_tmp_tn);
    SAFE_FREE(p_tmp_tn);
}

/* partition list to let left elements <= pivot <= right elements */
static struct tss_node *part_tss_list(struct tss_head *p_th, struct tss_node *p_l_tn, struct tss_node *p_r_tn)
{
    /* we meet p_r_tn's highest_pri as pivot value */
    struct tss_node *p_pivot_tn = p_l_tn, *p_trav_tn = p_l_tn;
    while (p_trav_tn != p_r_tn) {
        if (p_trav_tn->highest_pri < p_r_tn->highest_pri) {
            swap_tss_node(p_trav_tn, p_pivot_tn);
            p_pivot_tn = TAILQ_NEXT(p_pivot_tn, entry);
        }
        p_trav_tn = TAILQ_NEXT(p_trav_tn, entry);
    }
    swap_tss_node(p_pivot_tn, p_r_tn);
    return p_pivot_tn;
}

/* qsort style */
void sort_tss_list(struct tss_head *p_th, struct tss_node *p_l_tn, struct tss_node *p_r_tn)
{
    if (!p_l_tn || !p_r_tn || p_l_tn->tpl_id >= p_r_tn->tpl_id) return;
    struct tss_node *p_pivot_tn = part_tss_list(p_th, p_l_tn, p_r_tn);
    sort_tss_list(p_th, p_l_tn, TAILQ_PREV(p_pivot_tn, tss_head, entry));
    sort_tss_list(p_th, TAILQ_NEXT(p_pivot_tn, entry), p_r_tn);
}

int tss_build(const struct rule_set *rs, void *userdata)
{
    int i, j, tpl_exist = 0, tpl_num = 0, bytes = 0, hash_overhead = 0, nodes = 0;
    struct tss_head *p_th = NULL;
    struct tss_node *p_trav_tn = NULL, *p_tmp_tn = NULL;
    struct hash_entry *p_he = NULL;
    char *key;
    if (rs->p_rules == NULL) return -1;

    if (*(void **) userdata == NULL) {
        p_th = malloc(sizeof *p_th);
        TAILQ_INIT(p_th);
    } else {
        p_th = *(typeof(p_th) *) userdata;
        tpl_num = TAILQ_LAST(p_th, tss_head)->tpl_id;
        tpl_num++;
    }

    for (i = 0; i < rs->num; i++) {
        /* traverse current tss hash_table list */
        tpl_exist = 0;
        TAILQ_FOREACH(p_trav_tn, p_th, entry) {
            if (!tpl_is_equal(p_trav_tn->tuple, rs->p_rules[i].len, DIM_MAX)) continue;
            tpl_exist = 1;
            /* hash table operation */
            key = create_key(p_trav_tn->key_bytes, rs->p_rules[i].dim, rs->p_rules[i].len);
            HASH_FIND(hh, p_trav_tn->ht, key, p_trav_tn->key_bytes, p_he);
            if (p_he) {
                SAFE_FREE(key);
                if (rs->p_rules[i].pri < p_he->pri) {
                    p_he->pri = rs->p_rules[i].pri;
                }
            } else {
                p_he = malloc(sizeof *p_he);
                p_he->key = key;
                p_he->pri = rs->p_rules[i].pri;
                HASH_ADD_KEYPTR(hh, p_trav_tn->ht, p_he->key, p_trav_tn->key_bytes, p_he);
            }
            /* update highest priority */
            if (p_trav_tn->highest_pri > rs->p_rules[i].pri) {
                p_trav_tn->highest_pri = rs->p_rules[i].pri;
            }
            break;
        }
        if (tpl_exist) continue;
        /* new tss list node */
        p_tmp_tn = malloc(sizeof *p_tmp_tn);
        p_tmp_tn->highest_pri = rs->p_rules[i].pri;
        p_tmp_tn->ht = NULL;
        p_tmp_tn->tpl_id = tpl_num;
        tpl_num++;
        /* new tuple */
        p_tmp_tn->key_bytes = 0;
        for (j = 0; j < DIM_MAX; j++) {
            p_tmp_tn->tuple[j] = rs->p_rules[i].len[j];
            if (rs->p_rules[i].len[j] == 0) continue;
            p_tmp_tn->key_bytes += field_widths[j];
        }
        /* hash table operation */
        p_he = malloc(sizeof *p_he);
        p_he->key = create_key(p_tmp_tn->key_bytes, rs->p_rules[i].dim, rs->p_rules[i].len);
        p_he->pri = rs->p_rules[i].pri;
        HASH_ADD_KEYPTR(hh, p_tmp_tn->ht, p_he->key, p_tmp_tn->key_bytes, p_he);
        /* insert the new node to tss list tail */
        TAILQ_INSERT_TAIL(p_th, p_tmp_tn, entry);
    }

    /* sort tss list by the highest_pri of node */
    sort_tss_list(p_th, TAILQ_FIRST(p_th), TAILQ_LAST(p_th, tss_head));

    /* statistical numbers */
    printf("tuple num = %d\n", tpl_num);
    *(struct tss_head **) userdata = p_th;
    TAILQ_FOREACH(p_trav_tn, p_th, entry) {
        hash_overhead += HASH_OVERHEAD(hh, p_trav_tn->ht);
        nodes += HASH_COUNT(p_trav_tn->ht);
        bytes += HASH_COUNT(p_trav_tn->ht) * (4 + p_trav_tn->key_bytes);
        //printf("tuple_id:%d, hash_overhead:%lu bytes\n", p_trav_tn->tpl_id, HASH_OVERHEAD(hh, p_trav_tn->ht));
    }
    printf("hash items:%d\n", nodes);
    printf("hash_overhead:%d bytes; total memory:%d bytes\n", hash_overhead, bytes + hash_overhead);

    return 0;
}

int tss_build_estimate(const struct rule_set *rule_set, void *userdata) {
    int tuple_num, i, tpl_exist, j;
    double estimate_build_time;
    float time_base_operation = 0.01;
    char *key;

    if (rule_set->p_rules == NULL) return -1;

    struct tss_head *p_th = NULL;
    struct tss_node *p_trav_tn = NULL, *p_tmp_tn = NULL;
    struct hash_entry *p_he = NULL;

    p_th = malloc(sizeof *p_th);
    TAILQ_INIT(p_th);

    for (i = 0; i < rule_set->num; i++) {
        /* traverse current tss hash_table list */
        tpl_exist = 0;
        TAILQ_FOREACH(p_trav_tn, p_th, entry) {
            if (!tpl_is_equal(p_trav_tn->tuple, rule_set->p_rules[i].len, DIM_MAX))
                continue;
            tpl_exist = 1;
            continue;
        }
        if (tpl_exist)
            continue;
        /* new tss list node */
        p_tmp_tn = malloc(sizeof *p_tmp_tn);
        p_tmp_tn->highest_pri = rule_set->p_rules[i].pri;
        p_tmp_tn->ht = NULL;
        p_tmp_tn->tpl_id = tuple_num;

        p_tmp_tn->key_bytes = 0;
        for (j = 0; j < DIM_MAX; j++) {
            p_tmp_tn->tuple[j] = rule_set->p_rules[i].len[j];
            if (rule_set->p_rules[i].len[j] == 0) continue;
            p_tmp_tn->key_bytes += field_widths[j];
        }
        /* hash table operation */
        p_he = malloc(sizeof *p_he);
        p_he->key = create_key(p_tmp_tn->key_bytes, rule_set->p_rules[i].dim, rule_set->p_rules[i].len);
        p_he->pri = rule_set->p_rules[i].pri;
        HASH_ADD_KEYPTR(hh, p_tmp_tn->ht, p_he->key, p_tmp_tn->key_bytes, p_he);
        /* insert the new node to tss list tail */
        TAILQ_INSERT_TAIL(p_th, p_tmp_tn, entry);

        tuple_num++;
    }
    printf("Tuple num = %d\n", tuple_num);
    printf("Rule num = %d\n", rule_set->num);
    estimate_build_time=time_base_operation*(tuple_num*(tuple_num-1)/2.0+(rule_set->num-tuple_num)*tuple_num);
    printf("Estimated time: %f\n", estimate_build_time);
    return 0;
}

int tss_update_estimate(const struct rule_set *rule_set, const struct rule_set *u_rule_set, void *userdata) {
    int tuple_num, u_tuple_num, i, tpl_exist, j;
    float estimate_update_time;
    float time_base_operation = 0.01;
    char *key;
    uint64_t timediff;
    struct timeval starttime, stoptime;

    if (rule_set->p_rules == NULL) return -1;

    struct tss_head *p_th = NULL;
    struct tss_node *p_trav_tn = NULL, *p_tmp_tn = NULL;
    struct hash_entry *p_he = NULL;

    p_th = malloc(sizeof *p_th);
    TAILQ_INIT(p_th);

    tuple_num=0;
    u_tuple_num=0;
    for (i = 0; i < rule_set->num; i++) {
        /* traverse current tss hash_table list */
        tpl_exist = 0;
        TAILQ_FOREACH(p_trav_tn, p_th, entry) {
            if (!tpl_is_equal(p_trav_tn->tuple, rule_set->p_rules[i].len, DIM_MAX))
                continue;
            tpl_exist = 1;
            continue;
        }
        if (tpl_exist)
            continue;
        /* new tss list node */
        p_tmp_tn = malloc(sizeof *p_tmp_tn);
        p_tmp_tn->highest_pri = rule_set->p_rules[i].pri;
        p_tmp_tn->ht = NULL;
        p_tmp_tn->tpl_id = tuple_num;

        p_tmp_tn->key_bytes = 0;
        for (j = 0; j < DIM_MAX; j++) {
            p_tmp_tn->tuple[j] = rule_set->p_rules[i].len[j];
            if (rule_set->p_rules[i].len[j] == 0) continue;
            p_tmp_tn->key_bytes += field_widths[j];
        }
        /* hash table operation */
        p_he = malloc(sizeof *p_he);
        p_he->key = create_key(p_tmp_tn->key_bytes, rule_set->p_rules[i].dim, rule_set->p_rules[i].len);
        p_he->pri = rule_set->p_rules[i].pri;
        HASH_ADD_KEYPTR(hh, p_tmp_tn->ht, p_he->key, p_tmp_tn->key_bytes, p_he);
        /* insert the new node to tss list tail */
        TAILQ_INSERT_TAIL(p_th, p_tmp_tn, entry);

        tuple_num++;
    }
    printf("Original tuple num = %d\n", tuple_num);
    printf("Original rule num = %d\n", rule_set->num);
    u_tuple_num=tuple_num;

    p_th = malloc(sizeof *p_th);
    TAILQ_INIT(p_th);

    gettimeofday(&starttime, NULL);
    for (i = 0; i < u_rule_set->num; i++) {
        /* traverse current tss hash_table list */
        tpl_exist = 0;
        TAILQ_FOREACH(p_trav_tn, p_th, entry) {
            if (!tpl_is_equal(p_trav_tn->tuple, u_rule_set->p_rules[i].len, DIM_MAX))
                continue;
            tpl_exist = 1;
            continue;
        }
        if (tpl_exist)
            continue;
        /* new tss list node */
        p_tmp_tn = malloc(sizeof *p_tmp_tn);
        p_tmp_tn->highest_pri = u_rule_set->p_rules[i].pri;
        p_tmp_tn->ht = NULL;
        p_tmp_tn->tpl_id = tuple_num;

        p_tmp_tn->key_bytes = 0;
        for (j = 0; j < DIM_MAX; j++) {
            p_tmp_tn->tuple[j] = u_rule_set->p_rules[i].len[j];
            if (u_rule_set->p_rules[i].len[j] == 0) continue;
            p_tmp_tn->key_bytes += field_widths[j];
        }
        /* hash table operation */
        p_he = malloc(sizeof *p_he);
        p_he->key = create_key(p_tmp_tn->key_bytes, u_rule_set->p_rules[i].dim, u_rule_set->p_rules[i].len);
        p_he->pri = u_rule_set->p_rules[i].pri;
        HASH_ADD_KEYPTR(hh, p_tmp_tn->ht, p_he->key, p_tmp_tn->key_bytes, p_he);
        /* insert the new node to tss list tail */
        TAILQ_INSERT_TAIL(p_th, p_tmp_tn, entry);

        tuple_num++;
    }
    u_tuple_num=tuple_num-u_tuple_num;
    tuple_num-=u_tuple_num;

    printf("Updating tuple num = %d\n", u_tuple_num);
    printf("Updating rule num = %d\n", u_rule_set->num);

    estimate_update_time=time_base_operation*((2*tuple_num+u_tuple_num-1)*u_tuple_num/2.0+
            (u_rule_set->num-u_tuple_num)*(tuple_num+u_tuple_num));

    printf("Estimated time: %f\n", estimate_update_time);
    gettimeofday(&stoptime, NULL);
    timediff = make_timediff(&starttime, &stoptime);
    printf("Estimating pass\n");
    printf("Time for estimating: %llu(us)\n", timediff);
    return 0;
}


int tss_classify(const struct packet *pkt, const void *userdata)
{
    struct tss_head *p_th = *(typeof(p_th) *) userdata;
    struct tss_node *p_trav_tn = NULL;
    struct hash_entry *p_he = NULL;
    char *key;
    int ret = -1;

    TAILQ_FOREACH(p_trav_tn, p_th, entry) {
        //printf("\ntuple id:%d, current highest_pri:%d\n", p_trav_tn->tpl_id, p_trav_tn->highest_pri);
        if (ret != -1 && ret <= p_trav_tn->highest_pri) {
            return ret;
        }
        key = create_key(p_trav_tn->key_bytes, pkt->val, p_trav_tn->tuple);
        HASH_FIND(hh, p_trav_tn->ht, key, p_trav_tn->key_bytes, p_he);
        SAFE_FREE(key);
        if (!p_he) continue;
        //printf("....matched rule:%d\n", p_he->pri);
        if (ret == -1 || p_he->pri < ret) {
            ret = p_he->pri;
        }
    }
    return ret;
}

int tss_search(const struct trace *t, const void *userdata)
{
    int i, c;

    for (i = 0; i < t->num; i++) {
        if ((c = tss_classify(&t->pkts[i], userdata)) != t->pkts[i].match) {
            //fprintf(stderr, "pkt[%d] match:%d, classify:%d\n", i+1, t->pkts[i].match+1, c+1);
            //return -1;
        }
    }

    return 0;
}

void tss_cleanup(void *userdata)
{
    struct tss_head *p_th = *(typeof(p_th) *) userdata;
    struct tss_node *p_trav_tn;
    struct hash_entry *p_he, *p_tmp_he;

    while (!TAILQ_EMPTY(p_th)) {
        p_trav_tn = TAILQ_FIRST(p_th);
        TAILQ_REMOVE(p_th, p_trav_tn, entry);
        HASH_ITER(hh, p_trav_tn->ht, p_he, p_tmp_he) {
            HASH_DEL(p_trav_tn->ht, p_he);
            SAFE_FREE(p_he->key);
            SAFE_FREE(p_he);
        }
        SAFE_FREE(p_trav_tn);
    }
    SAFE_FREE(p_th);

    return;
}
