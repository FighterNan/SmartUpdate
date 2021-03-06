/*
 *     Filename: mem_sim.c
 *  Description: Source file for packet classification evaluation
 *
 *       Author: Xiaohe Hu,
 *               Nan Zhou
 *
 * Organization: Network Security Laboratory (NSLab),
 *               Research Institute of Information Technology (RIIT),
 *               Tsinghua University (THU)
 *
 *      History:  1. main file
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <assert.h>
#include "pc_eval.h"

static struct {
    char *rule_file;
    char *u_rule_file;
    char *trace_file;
    int algrthm_id;
    int estimate;
    int system;
} cfg = {
    NULL,
    NULL,
    NULL,
    0,
    0,
    0
};

static void print_help(void)
{
    static const char *help =

        "Valid options:\n"
        "  -h, --help         display this help and exit\n"
        "  -r, --rule FILE    specify a rule file for building\n"
        "  -t, --trace FILE   specify a trace file for searching\n"
        "  -u, --update FILE  specify a update rule file for searching\n"
        "  -a, --algorithm ID specify an algorithm, 0:HyperSplit, 1:TSS\n"
        "  -e  --estimate     specify mode of the estimator, 0:Sleep, 1:Enable\n"
        "  -s  --system       specify mode of the system, 0:build verifier, 1:build estimator, 2:update verifier, 3:update estimator\n"
        "\n";

    printf("%s", help);
    return;
}

static void parse_args(int argc, char *argv[])
{
    int option;


    static const char *optstr = "hr:t:u:a:e:s:";
    static struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {"rule", required_argument, NULL, 'r'},
        {"trace", required_argument, NULL, 't'},
        {"update", required_argument, NULL, 'u'},
        {"algorithm", required_argument, NULL, 'a'},
        {"estimate", required_argument, NULL, 'e'},
        {"system", required_argument, NULL, 's'},
        {NULL, 0, NULL, 0}
    };

    while ((option = getopt_long(argc, argv, optstr, longopts, NULL)) != -1) {
        switch (option) {
        case 'h':
            print_help();
            exit(0);

        case 'a':
            cfg.algrthm_id = atoi(optarg);
            assert(cfg.algrthm_id >= 0 && cfg.algrthm_id < ALGO_NUM);
            break;

        case 'r':
        case 't':
        case 'u':
            if (access(optarg, F_OK) == -1) {
                perror(optarg);
                exit(-1);
            } else {
                if (option == 'r') {
                    cfg.rule_file = optarg;
                } else if (option == 't') {
                    cfg.trace_file = optarg;
                } else if (option == 'u') {
                    cfg.u_rule_file = optarg;
                }
                break;
            }
        case 'e':
            cfg.estimate=atoi(optarg);
            assert(cfg.estimate >= SLEEP && cfg.estimate < ESTIMATE_MODE_NUM);
            break;

        case 's':
            cfg.system=atoi(optarg);
            assert(cfg.system >= VERIFY_BUILD && cfg.system < SYSTEM_MODE_NUM);
            break;

        default:
            print_help();
            exit(-1);
        }
    }

    return;
}

int main(int argc, char *argv[])
{
    uint64_t timediff;
    struct timeval starttime, stoptime;
    struct rule_set rule_set = {NULL, NULL, 0};
    struct rule_set u_rule_set = {NULL, NULL, 0};
    struct trace t;
    void *root = NULL, *root_for_estimating = NULL;

    printf("****************************** start *********************************\n");

    if (argc < 2) {
        print_help();
        exit(-1);
    }

    parse_args(argc, argv);

    if(cfg.estimate==ENABLE)
        printf("Note: estimator has been enabled!\n");
    switch (cfg.system){
        case VERIFY_BUILD:
            printf("System is in build verifier mode\n");
            break;
        case ESTIMATE_BUILD:
            printf("System is in build estimator mode\n");
            break;
        case VERIFY_UPDATE:
            printf("System is in update verifier mode\n");
            break;
        case ESTIMATE_UPDATE:
            printf("System is in update estimator mode\n");
            break;
    }

    /*
     * Building
     */
    if (cfg.rule_file == NULL) {
        fprintf(stderr, "No rules for processing\n");
        exit(-1);
    }

    printf("\n");
    printf("Loading rule\n");
    algrthms[cfg.algrthm_id].load_rules(&rule_set, cfg.rule_file);

    /*
     * Estimating before building
     */
    if (cfg.estimate==ENABLE) {
        printf("\n");
        printf("Estimate before building\n");
        gettimeofday(&starttime, NULL);

        if (algrthms[cfg.algrthm_id].build_estimate(&rule_set, &root_for_estimating) != 0) {
            fprintf(stderr, "Building estimating failed\n");
            unload_rules(&rule_set);
            exit(-1);
        }

        gettimeofday(&stoptime, NULL);
        timediff = make_timediff(&starttime, &stoptime);
        printf("Estimating pass\n");
        printf("Time for estimating(us): %llu\n", timediff);

    }

    if (cfg.system!=ESTIMATE_BUILD) {
        printf("\n");
        printf("Building\n");

        gettimeofday(&starttime, NULL);
        if (algrthms[cfg.algrthm_id].build(&rule_set, &root) != 0) {
            fprintf(stderr, "Building failed\n");
            unload_rules(&rule_set);
            exit(-1);
        }
        gettimeofday(&stoptime, NULL);
        timediff = make_timediff(&starttime, &stoptime);

        printf("Building pass\n");
        printf("Time for building(us): %llu\n", timediff);
    }

//    unload_rules(&rule_set);

    /*
     * Updating
     */
    if ((cfg.system != VERIFY_UPDATE || cfg.system != ESTIMATE_UPDATE) && cfg.trace_file == NULL) {
        printf("****************************** end *********************************\n");
        return 0;
    }

    if (cfg.u_rule_file != NULL) {

        algrthms[cfg.algrthm_id].load_rules(&u_rule_set, cfg.u_rule_file);

        /*
         * Estimating before Updating
         */
        if (cfg.estimate==ENABLE) {
            printf("\n");
            printf("Estimate before updating\n");

            if (algrthms[cfg.algrthm_id].update_estimate(&rule_set, &u_rule_set, &root) != 0) {
                fprintf(stderr, "Updating estimating failed\n");
                unload_rules(&rule_set);
                exit(-1);
            }
        }

        if (cfg.system==VERIFY_UPDATE) {
            printf("\n");
            printf("Updating\n");
            gettimeofday(&starttime, NULL);

            if (algrthms[cfg.algrthm_id].insrt_update(&u_rule_set, &root) != 0) {
                fprintf(stderr, "Updating failed\n");
                unload_rules(&u_rule_set);
                exit(-1);
            }
            gettimeofday(&stoptime, NULL);
            timediff = make_timediff(&starttime, &stoptime);

            printf("Updating pass\n");
            printf("Time for updating(us): %llu\n", timediff);

            unload_rules(&u_rule_set);
        }
    }

    /*
     * Searching
     */
    if (cfg.trace_file == NULL) {
        algrthms[cfg.algrthm_id].cleanup(&root);
        printf("****************************** end *********************************\n");
        return 0;
    }

    printf("\n");
    load_trace(&t, cfg.trace_file);
    printf("Searching\n");

    gettimeofday(&starttime, NULL);
    if (algrthms[cfg.algrthm_id].search(&t, &root) != 0) {
        fprintf(stderr, "Searching failed\n");
        unload_trace(&t);
        algrthms[cfg.algrthm_id].cleanup(&root);
        exit(-1);
    }
    gettimeofday(&stoptime, NULL);
    timediff = make_timediff(&starttime, &stoptime);

    printf("Searching pass\n");
    printf("Time for searching(us): %llu\n", timediff);
    printf("Searching speed(pps): %lld\n", (t.num * 1000000ULL) / timediff);

    unload_trace(&t);
    algrthms[cfg.algrthm_id].cleanup(&root);

    printf("****************************** end *********************************\n");
    return 0;
}
