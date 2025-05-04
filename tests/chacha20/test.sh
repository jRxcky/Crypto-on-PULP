#!/bin/bash

make clean all run USE_CLUSTER=1 NUM_CORES=8 MEM_SIZE=512 runner_args="--trace=insn" -> print512b.txt
make clean all run USE_CLUSTER=1 NUM_CORES=8 MEM_SIZE=1 runner_args="--trace=insn" -> print1k.txt
make clean all run USE_CLUSTER=1 NUM_CORES=8 MEM_SIZE=2 runner_args="--trace=insn" -> print2k.txt
make clean all run USE_CLUSTER=1 NUM_CORES=8 MEM_SIZE=4 runner_args="--trace=insn" -> print4k.txt
make clean all run USE_CLUSTER=1 NUM_CORES=8 MEM_SIZE=8 runner_args="--trace=insn" -> print8k.txt
make clean all run USE_CLUSTER=1 NUM_CORES=8 MEM_SIZE=16 runner_args="--trace=insn" -> print16k.txt
make clean all run USE_CLUSTER=1 NUM_CORES=8 MEM_SIZE=32 runner_args="--trace=insn" -> print32k.txt
