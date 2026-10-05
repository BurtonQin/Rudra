#!/bin/sh -e
rustup install nightly-2026-02-07
rustup default nightly-2026-02-07
rustup component add rustc-dev
rustup component add miri
