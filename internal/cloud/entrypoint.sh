#!/bin/bash

# Run enumeraga with provided arguments
./enumeraga cloud "$@"

# Check if /tmp/enumeraga exists and is a directory
if [ -d "/tmp/enumeraga" ]; then
    # Create a temporary directory in the host's current directory
    temp_dir=$(mktemp -d)

    # Copy /tmp/enumeraga to the temporary directory
    cp -r /tmp/enumeraga "$temp_dir"

    # Print a message indicating where the output is copied
    echo "Enumeraga output copied to: $temp_dir"
else
    echo "/tmp/enumeraga directory not found."
fi