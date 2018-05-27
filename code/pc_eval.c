/*
 *     Filename: pc_eval.c
 *  Description: Source file for packet classification evaluation
 *
 *       Author: Xiang Wang
 *               Chang Chen
 *               Xiaohe Hu
 *
 * Organization: Network Security Laboratory (NSLab),
 *               Research Institute of Information Technology (RIIT),
 *               Tsinghua University (THU)
 *
 *      History:  1. Unified packet classification algorithm / evaluation
 *                   framework design (Xiang Wang & Chang Chen)
 *
 *                2. Add build & search time evaluation in main (Chang Chen)
 *
 *                3. Add range2prefix, prefix2range function
 *                   (Xiang Wang & Chang Chen)
 *
 *                4. Add split_range_rule function (Xiang Wang)
 *
 *                5. Support multi algorithms (Xiaohe Hu)
 *
 *                6. Add estimators of building time & updating time (Nan Zhou)
 */

#include <stdio.h>
#include "pc_eval.h"
#include "hs.h"
#include "tss.h"

#define swap(a, b) \
    do { typeof(a) __tmp = (a); (a) = (b); (b) = __tmp; } while (0)

struct algo_t algrthms[ALGO_NUM] = {
    {
        load_cb_rules,
        hs_build,
        hs_insrt_update,
        hs_classify,
        hs_search,
        hs_cleanup,
        hs_build_estimate,
        hs_update_estimate
    },
    {
        load_prfx_rules,
        tss_build,
        tss_build,
        tss_classify,
        tss_search,
        tss_cleanup,
        tss_build_estimate,
        tss_update_estimate
    }
};

uint64_t make_timediff(struct timeval *start, struct timeval *stop)
{
    return (1000000ULL * stop->tv_sec + stop->tv_usec) -
        (1000000ULL * start->tv_sec + start->tv_usec);
}

void load_cb_rules(struct rule_set *rs, const char *rf)
{
    FILE *rule_fp;
    uint32_t src_ip, src_ip_0, src_ip_1, src_ip_2, src_ip_3, src_ip_mask;
    uint32_t dst_ip, dst_ip_0, dst_ip_1, dst_ip_2, dst_ip_3, dst_ip_mask;
    uint32_t src_port_begin, src_port_end, dst_port_begin, dst_port_end;
    uint32_t proto, proto_mask;
    uint32_t rule_id;
    unsigned int i = 0;

    printf("Loading rules from %s\n", rf);

    if ((rule_fp = fopen(rf, "r")) == NULL) {
        fprintf(stderr, "Cannot open file %s", rf);
        exit(-1);
    }

    rs->r_rules = calloc(RULE_MAX, sizeof(*rs->r_rules));
    if (rs->r_rules == NULL) {
        perror("Cannot allocate memory for rules");
        exit(-1);
    }
    rs->num = 0;

    while (!feof(rule_fp)) {
        if (i >= RULE_MAX) {
            fprintf(stderr, "Too many rules\n");
            exit(-1);
        }

        if (fscanf(rule_fp, CB_RULE_FMT,
            &src_ip_0, &src_ip_1, &src_ip_2, &src_ip_3, &src_ip_mask,
            &dst_ip_0, &dst_ip_1, &dst_ip_2, &dst_ip_3, &dst_ip_mask,
            &src_port_begin, &src_port_end, &dst_port_begin, &dst_port_end,
            &proto, &proto_mask, &rule_id) != 17) {
            fprintf(stderr, "Illegal rule format\n");
            exit(-1);
        }

        /* src ip */
        src_ip = ((src_ip_0 & 0xff) << 24) | ((src_ip_1 & 0xff) << 16) |
            ((src_ip_2 & 0xff) << 8) | (src_ip_3 & 0xff);
        src_ip_mask = src_ip_mask > 32 ? 32 : src_ip_mask;
        src_ip_mask = (uint32_t)(~((1ULL << (32 - src_ip_mask)) - 1));
        rs->r_rules[i].dim[DIM_SIP][0].u32 = src_ip & src_ip_mask;
        rs->r_rules[i].dim[DIM_SIP][1].u32 = src_ip | (~src_ip_mask);

        /* dst ip */
        dst_ip = ((dst_ip_0 & 0xff) << 24) | ((dst_ip_1 & 0xff) << 16) |
            ((dst_ip_2 & 0xff) << 8) | (dst_ip_3 & 0xff);
        dst_ip_mask = dst_ip_mask > 32 ? 32 : dst_ip_mask;
        dst_ip_mask = (uint32_t)(~((1ULL << (32 - dst_ip_mask)) - 1));
        rs->r_rules[i].dim[DIM_DIP][0].u32 = dst_ip & dst_ip_mask;
        rs->r_rules[i].dim[DIM_DIP][1].u32 = dst_ip | (~dst_ip_mask);

        /* src port */
        rs->r_rules[i].dim[DIM_SPORT][0].u16 = src_port_begin & 0xffff;
        rs->r_rules[i].dim[DIM_SPORT][1].u16 = src_port_end & 0xffff;
        if (rs->r_rules[i].dim[DIM_SPORT][0].u16 >
                rs->r_rules[i].dim[DIM_SPORT][1].u16) {
            swap(rs->r_rules[i].dim[DIM_SPORT][0].u16,
                    rs->r_rules[i].dim[DIM_SPORT][1].u16);
        }

        /* dst port */
        rs->r_rules[i].dim[DIM_DPORT][0].u16 = dst_port_begin & 0xffff;
        rs->r_rules[i].dim[DIM_DPORT][1].u16 = dst_port_end & 0xffff;
        if (rs->r_rules[i].dim[DIM_DPORT][0].u16 >
                rs->r_rules[i].dim[DIM_DPORT][1].u16) {
            swap(rs->r_rules[i].dim[DIM_DPORT][0].u16,
                    rs->r_rules[i].dim[DIM_DPORT][1].u16);
        }

        /* proto */
        if (proto_mask == 0xff) {
            rs->r_rules[i].dim[DIM_PROTO][0].u8 = proto & 0xff;
            rs->r_rules[i].dim[DIM_PROTO][1].u8 = proto & 0xff;
        } else if (proto_mask == 0) {
            rs->r_rules[i].dim[DIM_PROTO][0].u8 = 0;
            rs->r_rules[i].dim[DIM_PROTO][1].u8 = 0xff;
        } else {
            fprintf(stderr, "Protocol mask error: %02x\n", proto_mask);
            exit(-1);
        }

        rs->r_rules[i].pri = rule_id - 1;

        rs->num++;
        i++;
    }

    fclose(rule_fp);

    printf("%d rules loaded\n", rs->num);

    return;
}

void load_prfx_rules(struct rule_set *rs, const char *rf)
{
    FILE *rule_fp;
    uint32_t src_ip, src_ip_0, src_ip_1, src_ip_2, src_ip_3, src_ip_mask;
    uint32_t dst_ip, dst_ip_0, dst_ip_1, dst_ip_2, dst_ip_3, dst_ip_mask;
    uint32_t src_port, src_port_mask, dst_port, dst_port_mask;
    uint32_t proto, proto_mask;
    uint32_t rule_id;
    unsigned int i = 0;

    printf("Loading rules from %s\n", rf);

    if ((rule_fp = fopen(rf, "r")) == NULL) {
        fprintf(stderr, "Cannot open file %s", rf);
        exit(-1);
    }

    rs->p_rules = calloc(RULE_MAX, sizeof(*rs->p_rules));
    if (rs->p_rules == NULL) {
        perror("Cannot allocate memory for rules");
        exit(-1);
    }
    rs->num = 0;

    while (!feof(rule_fp)) {
        if (i >= RULE_MAX) {
            fprintf(stderr, "Too many rules\n");
            exit(-1);
        }

        if (fscanf(rule_fp, PRFX_RULE_FMT,
            &src_ip_0, &src_ip_1, &src_ip_2, &src_ip_3, &src_ip_mask,
            &dst_ip_0, &dst_ip_1, &dst_ip_2, &dst_ip_3, &dst_ip_mask,
            &src_port, &src_port_mask, &dst_port, &dst_port_mask,
            &proto, &proto_mask, &rule_id) != 17) {
            fprintf(stderr, "Illegal rule format\n");
            exit(-1);
        }

        /* src ip */
        src_ip = ((src_ip_0 & 0xff) << 24) | ((src_ip_1 & 0xff) << 16) |
            ((src_ip_2 & 0xff) << 8) | (src_ip_3 & 0xff);
        src_ip_mask = src_ip_mask > 32 ? 32 : src_ip_mask;
        rs->p_rules[i].dim[DIM_SIP].u32 = src_ip & \
            (uint32_t)(~((1ULL << (32 - src_ip_mask)) - 1));
        rs->p_rules[i].len[DIM_SIP] = src_ip_mask;

        /* dst ip */
        dst_ip = ((dst_ip_0 & 0xff) << 24) | ((dst_ip_1 & 0xff) << 16) |
            ((dst_ip_2 & 0xff) << 8) | (dst_ip_3 & 0xff);
        dst_ip_mask = dst_ip_mask > 32 ? 32 : dst_ip_mask;
        rs->p_rules[i].dim[DIM_DIP].u32 = dst_ip & \
            (uint32_t)(~((1ULL << (32 - dst_ip_mask)) - 1));
        rs->p_rules[i].len[DIM_DIP] = dst_ip_mask;

        /* src port */
        rs->p_rules[i].dim[DIM_SPORT].u16 = src_port & 0xffff;
        rs->p_rules[i].len[DIM_SPORT] = src_port_mask;

        /* dst port */
        rs->p_rules[i].dim[DIM_DPORT].u16 = dst_port & 0xffff;
        rs->p_rules[i].len[DIM_DPORT] = dst_port_mask;

        /* proto */
        if (proto_mask == 0xff) {
            rs->p_rules[i].dim[DIM_PROTO].u8 = proto & 0xff;
            rs->p_rules[i].len[DIM_PROTO] = 8;
        } else if (proto_mask == 0) {
            rs->p_rules[i].dim[DIM_PROTO].u8 = 0;
            rs->p_rules[i].len[DIM_PROTO] = 0;
        } else {
            fprintf(stderr, "Protocol mask error: %02x\n", proto_mask);
            exit(-1);
        }

        rs->p_rules[i].pri = rule_id - 1;

        rs->num++;
        i++;
    }

    fclose(rule_fp);

    printf("%d rules loaded\n", rs->num);

    return;
}

void unload_rules(struct rule_set *rs)
{
    SAFE_FREE(rs->r_rules);
    SAFE_FREE(rs->p_rules);
    return;
}

void load_trace(struct trace *t, const char *tf)
{
    FILE *trace_fp;
    unsigned int i = 0;

    printf("Loading trace from %s\n", tf);

    if ((trace_fp = fopen(tf, "r")) == NULL) {
        fprintf(stderr, "Cannot open file %s", tf);
        exit(-1);
    }

    t->pkts = calloc(PKT_MAX, sizeof(struct packet));
    if (t->pkts == NULL) {
        perror("Cannot allocate memory for packets");
        exit(-1);
    }
    t->num = 0;

    while (!feof(trace_fp)) {
        if (i >= PKT_MAX) {
            fprintf(stderr, "Too many packets\n");
            exit(-1);
        }

        if (fscanf(trace_fp, PKT_FMT,
            &t->pkts[i].val[DIM_SIP].u32, &t->pkts[i].val[DIM_DIP].u32,
            &t->pkts[i].val[DIM_SPORT].u32, &t->pkts[i].val[DIM_DPORT].u32,
            &t->pkts[i].val[DIM_PROTO].u32, &t->pkts[i].match) != 6) {
            fprintf(stderr, "Illegal packet format\n");
            exit(-1);
        }

        t->pkts[i].val[DIM_SPORT].u16 = t->pkts[i].val[DIM_SPORT].u32 & 0xffff;
        t->pkts[i].val[DIM_DPORT].u16 = t->pkts[i].val[DIM_DPORT].u32 & 0xffff;
        t->pkts[i].val[DIM_PROTO].u8 = t->pkts[i].val[DIM_PROTO].u32 & 0xff;
        t->pkts[i].match--; //rule priority start @ 0

        t->num++;
        i++;
    }

    fclose(trace_fp);

    printf("Packets loaded:%d\n", t->num);

    return;
}

void unload_trace(struct trace *t)
{
    free(t->pkts);
    return;
}
