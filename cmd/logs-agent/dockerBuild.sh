#!/bin/bash 

cd ../..

docker build --progress plain -f cmd/logs-agent/Dockerfile -t logs-image .