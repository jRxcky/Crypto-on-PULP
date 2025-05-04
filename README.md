# CPS Project - Crypto on PULP

### Gaspari Riccardo, Vignati Giulio, Franchi Matteo

This project involves the implementation and performance evaluation of cryptographic algorithms on GVSoC, exploiting the 8-core cluster for parallelized execution.
Watch the full Presentation [📄 here](https://github.com/jRxcky/Crypto-on-PULP/blob/main/CPS_project.pdf)

## Cryptographic Algorithms Implemented
- **AES-256-CTR**
- **AES-256-GCM**
- **ChaCha20**
- **ChaCha20-Poly1305**

## Test Vector Generation

To generate arbitrary-length test vectors, we developed a Python script (`/Python/testvector.ipynb`). The script:

1. Verifies the correctness of built-in Python functions using official test vectors (also tested in the GVSoC implementation).
2. Generates plaintext and corresponding ciphertext files with selected lengths (512B, 1kB, 2kB, 4kB, 8kB, 16kB, 32kB).

## Run it yourself

### Prerequisites
Before proceeding, ensure that:
- You are running **Ubuntu 22.04** within **WSL**.
- You have internet access to download dependencies.

### Installation Instructions
To install all required components, simply execute the following command in your terminal (after making the script executable (chmod +x <path-to-setup_pulp.sh>)):

~~~~~shell
./setup_pulp.sh
~~~~~

### Running the Tests
You can find test directories for each of the four encryption algorithms in the `/tests` folder. To run a test, navigate to the desired algorithm's directory and execute:

~~~~~shell
make clean all run USE_CLUSTER=1 NUM_CORES=<NUM_CORES> MEM_SIZE=<SIZE>
~~~~~
- **USE_CLUSTER**: always set to 1
- **NUM_CORES**: Choose any value from 1 to 8
- **MEM_SIZE**: Choose from {512, 1, 2, 4, 8, 16, 32} to correspond to input files of 512B, 1kB, 2kB, ..., 32kB

To enable debug mode, add the *DEBUG* option to verify encryption correctness against the Python-generated ciphertext (make clean all run ... DEBUG=1).

## Performance evaluation

The performances of the implementation have been assesed by running:

~~~~~shell
make clean all run USE_CLUSTER=1 NUM_CORES=<NUM_CORES> MEM_SIZE=<SIZE> runner_args="--trace=insn"
~~~~~

This command was executed for all possible configurations of (NUM_CORES, MEM_SIZE), resulting in a total of 56 runs. The trace files generated were then analyzed using a Python script (`/Python/Performance_Eval_<algorithm>.ipynb`).

We automated the trace file generation process with a script (`/Python/test.sh`), which runs all simulations and places the trace files in the `output_files` folder. Note that the output files of all four implementations are not included in the Git repository due to their large size.

