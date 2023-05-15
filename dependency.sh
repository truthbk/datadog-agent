#!/bin/bash

inv -e system-probe.kitchen-prepare --ci

DD_AGENT_TESTING_DIR=../..
DEPENDENCIES=env-deps/dependencies
ARCHIVE_NAME=dependencies-x86_64.tar.gz
CLANG_BPF=$DD_AGENT_TESTING_DIR/test/kitchen/site-cookbooks/dd-system-probe-check/files/default/clang-bpf
LLC_BPF=$DD_AGENT_TESTING_DIR/test/kitchen/site-cookbooks/dd-system-probe-check/files/default/llc-bpf
GO_BIN=go/bin
GOTESTSUM=$DD_AGENT_TESTING_DIR/test/kitchen/site-cookbooks/dd-system-probe-check/files/default/gotestsum
TEST2JSON=$DD_AGENT_TESTING_DIR/test/kitchen/site-cookbooks/dd-system-probe-check/files/default/test2json
EMBEDDED_BIN=opt/datadog-agent/embedded/bin
EMBEDDED_INC=opt/datadog-agent/embedded/include
SYSTEM_PROBE_TESTS=opt/system-probe-tests
KITCHEN_TESTS=$DD_AGENT_TESTING_DIR/test/kitchen/site-cookbooks/dd-system-probe-check/files/default/tests/pkg

mkdir -p $DEPENDENCIES
pushd $DEPENDENCIES
mkdir -p $EMBEDDED_BIN
cp $CLANG_BPF $EMBEDDED_BIN
cp $LLC_BPF $EMBEDDED_BIN
mkdir -p $EMBEDDED_INC
mkdir -p $GO_BIN
cp $GOTESTSUM $GO_BIN
cp $TEST2JSON $GO_BIN
mkdir junit
mkdir testjson
mkdir pkgjson
mkdir -p $SYSTEM_PROBE_TESTS
cp -R $KITCHEN_TESTS $SYSTEM_PROBE_TESTS
cp $DD_AGENT_TESTING_DIR/test/new-e2e/system-probe/test/micro-vm-init.sh ./
GOOS=linux GOARCH=amd64 go build $DD_AGENT_TESTING_DIR/test/new-e2e/system-probe/test/system-probe-test_spec.go
popd

ls -la $DEPENDENCIES
pushd env-deps
tar czvf $ARCHIVE_NAME dependencies
popd
