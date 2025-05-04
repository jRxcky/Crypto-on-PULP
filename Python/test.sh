
#!/bin/bash

# Directory to store the output files
OUTPUT_DIR="output_files"
mkdir -p "$OUTPUT_DIR"

# Array of MEM_SIZE values
MEM_SIZES=(512 1 2 4 8 16 32)

# Loop over NUM_CORES from 1 to 8
for NUM_CORES in {1..8}; do
    # Loop over each MEM_SIZE value
    for MEM_SIZE in "${MEM_SIZES[@]}"; do
        # Run the make command and redirect the output to a file
        OUTPUT_FILE="${OUTPUT_DIR}/${MEM_SIZE}_${NUM_CORES}cores.txt"
        echo "Running with NUM_CORES=$NUM_CORES and MEM_SIZE=${MEM_SIZE}"
        make clean all run USE_CLUSTER=1 NUM_CORES=$NUM_CORES MEM_SIZE=$MEM_SIZE runner_args="--trace=insn" > "$OUTPUT_FILE"
    done
done


