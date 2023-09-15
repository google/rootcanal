#!/bin/bash

set -e

# Build the python wheel package for rootcanal including
# the binary release of the rootcanal executable and shared library.

# 0. Extract build artifacts.

unzip rootcanal-linux-x86_64.zip
mkdir -p py/src/rootcanal/bin/linux-x86_64
cp rootcanal-linux-x86_64/bin/rootcanal py/src/rootcanal/bin/linux-x86_64/rootcanal
cp rootcanal-linux-x86_64/lib/librootcanal_ffi.so py/src/rootcanal/bin/linux-x86_64/librootcanal_ffi.so

unzip rootcanal-macos-x86_64.zip
mkdir -p py/src/rootcanal/bin/macos-x86_64
cp rootcanal-macos-x86_64/bin/rootcanal py/src/rootcanal/bin/macos-x86_64/rootcanal
cp rootcanal-macos-x86_64/lib/librootcanal_ffi.so py/src/rootcanal/bin/macos-x86_64/librootcanal_ffi.so

# 1. Generate the python backends for packet parsing.
mkdir -p py/src/rootcanal/packets
pdlc packets/hci_packets.pdl |./third_party/pdl/pdl-compiler/scripts/generate_python_backend.py \
    --custom-type-location "..bluetooth" \
    --output "py/src/rootcanal/packets/hci.py"
pdlc packets/link_layer_packets.pdl |./third_party/pdl/pdl-compiler/scripts/generate_python_backend.py \
    --custom-type-location "..bluetooth" \
    --output "py/src/rootcanal/packets/ll.py"
pdlc rust/lmp_packets.pdl |./third_party/pdl/pdl-compiler/scripts/generate_python_backend.py \
    --output "py/src/rootcanal/packets/lmp.py"
pdlc rust/llcp_packets.pdl |./third_party/pdl/pdl-compiler/scripts/generate_python_backend.py \
    --output "py/src/rootcanal/packets/llcp.py"

# 2. Configure the version.
cd py
python3 -m hatch version ${1}

# 3. Build wheel.
python3 -m hatch build -t wheel
cd -
