#!/bin/bash 

cd ../..

docker buildx build \
--platform linux/amd64,linux/arm64 \
-t bfloerschddog/logs-only-agent:latest \
-f cmd/logs-agent/Dockerfile \
--push .

# docker build --progress plain -f cmd/logs-agent/Dockerfile -t logs-image .