#!/usr/bin/env sh

# Builds and runs tests for a particular target passed as an argument to this
# script.

set -ex

: "${TOOLCHAIN?The TOOLCHAIN environment variable must be set.}"
: "${OS?The OS environment variable must be set.}"

RUST=${TOOLCHAIN}

echo "Testing Rust ${RUST} on ${OS}"

# FIXME: rustup often fails to download some artifacts due to network
# issues, so we retry this N times.
N=5
n=0
until [ $n -ge $N ]
do
    if rustup override set "${RUST}" ; then
        break
    fi
    n=$((n+1))
    sleep 1
done

echo "Testing default features"

cargo test

echo "Testing no default features (no std, no alloc)"

cargo test --no-default-features

echo "Testing only alloc"

cargo test --features alloc

echo "Testing std without error strings or custom layer selection"

cargo test --features std

echo "Testing no-std,no-alloc with error strings and custom layer selection"

cargo test --features custom_layer_selection,error_string
