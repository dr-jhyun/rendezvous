#!/bin/bash

set -e

echo Delete old data...
rm -f rendezvous

echo Copy new data...
cp ../rendezvous .

docker build --no-cache --rm --tag dryun/rendezvous:1.0.1 .
