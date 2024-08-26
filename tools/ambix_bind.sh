#!/bin/bash

# Function to bind the current process to Ambix
bind_to_ambix() {
    local pid=$$
    echo "bind $pid 1" > /proc/ambix/objects
    if [ $? -ne 0 ]; then
        echo "Failed to bind process $pid to Ambix."
        exit 1
    fi
}

# Check if at least one argument (the command) is provided
if [ $# -lt 1 ]; then
    echo "Usage: $0 <command> [args...]"
    exit 1
fi

# Bind the current shell's PID to Ambix
bind_to_ambix

# Execute the command with the same PID
exec "$@"
