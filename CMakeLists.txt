cmake_minimum_required(VERSION 1.0)
project(SmartUpdate)

set(CMAKE_CXX_STANDARD 11)

add_executable(SmartUpdate
        code/hs.c
        code/hs.h
        code/mem_sim.c
        code/pc_eval.c
        code/pc_eval.h
        code/tss.c
        code/tss.h
        code/uthash.h
        code/utils.c
        code/utils.h)
