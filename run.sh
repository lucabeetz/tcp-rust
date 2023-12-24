#!/bin/bash

sudo route delete -net 10.0.0.0/24 10.0.0.1
cargo b --release
./target/release/tcp &
pid=$!
sudo route -n add -net 10.0.0.0/24 10.0.0.1
trap "kill $pid" TERM
wait $pid
