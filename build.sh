#!/bin/bash
set -e

IMAGE="openssl:latest"
docker build -t $IMAGE .
make all
echo "Build $IMAGE successful!"