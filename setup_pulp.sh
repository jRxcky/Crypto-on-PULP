#!/bin/bash
set -e  # Stops the script if any command fails

echo "Installing dependencies..."
sudo apt-get update
sudo apt-get install -y build-essential git libftdi-dev libftdi1 doxygen python3-pip libsdl2-dev curl
sudo apt install -y gcc-9 g++-9 cmake python3-pip python3-venv

echo "Setting up Python virtual environment..."
python3 -m venv myenv
source myenv/bin/activate
pip install six
sudo apt install python3-prettytable python3-argcomplete python3-pyelftools
deactivate

echo "Cloning PULP SDK..."
git clone https://github.com/pulp-platform/pulp-sdk.git

echo "Downloading and extracting PULP RISC-V GNU toolchain..."
wget https://github.com/pulp-platform/pulp-riscv-gnu-toolchain/releases/download/v1.0.16/v1.0.16-pulp-riscv-gcc-ubuntu-18.tar.bz2
tar -xvjf v1.0.16-pulp-riscv-gcc-ubuntu-18.tar.bz2
rm v1.0.16-pulp-riscv-gcc-ubuntu-18.tar.bz2

echo "Configuring environment..."
source myenv/bin/activate
export PULP_RISCV_GCC_TOOLCHAIN=$HOME/v1.0.16-pulp-riscv-gcc-ubuntu-18
cd pulp-sdk
source configs/pulp-open.sh

echo "Building PULP SDK..."
CC=gcc-9 CXX=g++-9 make all

echo "Testing setup..."
cd tests/cluster/fork
make clean all run runner_args="--trace=insn"

echo "Setup complete!"
