/*
 *     Filename: pc_eval.h
 *  Description: Header file for packet classification evaluation
 *
 *       Author: Xiang Wang
 *               Chang Chen
 *               Xiaohe Hu
 *               Nan Zhou
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
 */

#ifndef __PC_EVAL_H__
#define __PC_EVAL_H__

#include <stdint.h>
#include <sys/time.h>

#define RULE_MAX (1 << 19)  /* 512K */
#define PKT_MAX (1 << 21)   /* 2048K */

#define CACHE_LINE_SIZE 64 /* 64 bytes */

#define ALIGN(size, align) ({ \
        const typeof(align) __align = align; \
        ((size) + (__align - 1)) & ~(__align - 1);})

#define SAFE_FREE(ptr) \
    { if ((ptr) != NULL) { free(ptr); (ptr) = NULL; } }

/* compatible with classbench from wustl */
#define CB_RULE_FMT "@%u.%u.%u.%u/%u %u.%u.%u.%u/%u %u : %u %u : %u %x/%x %u\n"
/* prefix rule format, the last integer is original rule_id/priority */
#define PRFX_RULE_FMT "@%u.%u.%u.%u/%u %u.%u.%u.%u/%u %u/%u %u/%u %x/%x %u\n"
#define PKT_FMT "%u %u %u %u %u %d\n"

enum {
    ALGO_INV = -1,
    ALGO_HS = 0,
    ALGO_TSS = 1,
    ALGO_NUM = 2
};

// smart-update
enum {
    SLEEP = 0,
    ENABLE = 1,
    ESTIMATE_MODE_NUM = 2,
//    ADAPTED_RULE_NUM = 100
};

enum {
    DIM_INV = -1,
    DIM_SIP = 0,
    DIM_DIP = 1,
    DIM_SPORT = 2,
    DIM_DPORT = 3,
    DIM_PROTO = 4,
    DIM_MAX = 5
};

/* little endian */
union point {
    struct { uint64_t low, high; } u128;
    uint64_t u64;
    uint32_t u32;
    uint16_t u16;
    uint8_t u8;
};

/* range rule, compatible with struct range */
struct rng_rule {
    union point dim[DIM_MAX][2];
    int pri;
};

struct prfx_rule {
    union point dim[DIM_MAX];
    int len[DIM_MAX];
    int pri;
};

struct rule_set {
    struct rng_rule *r_rules; // range rule_set_array_ptr
    struct prfx_rule *p_rules; // prefix rule_set_array_ptr
    int num;
};

struct packet {
    union point val[DIM_MAX];
    int match; //match the rule's row num
};

struct trace {
    struct packet *pkts; //pts_array_ptr
    int num;
};

struct algo_t {
    void (*load_rules)(struct rule_set *, const char *);
    int (*build)(const struct rule_set *, void *);
    int (*insrt_update)(const struct rule_set *, void *);
    int (*classify)(const struct packet *, const void *);
    int (*search)(const struct trace *, const void *);
    void (*cleanup)(void *);
    int (*build_estimate)(const struct rule_set *, void *);
    int (*update_estimate)(const struct rule_set *, const struct rule_set *, void *);
};

extern struct algo_t algrthms[ALGO_NUM];

uint64_t make_timediff(struct timeval *start, struct timeval *stop);

void load_cb_rules(struct rule_set *rs, const char *rf);     // classbench rule format
void load_prfx_rules(struct rule_set *rs, const char *rf);   // prefix rule format
void unload_rules(struct rule_set *rs);

void load_trace(struct trace *t, const char *tf);
void unload_trace(struct trace *t);

#endif /* __PC_EVAL_H__ */
