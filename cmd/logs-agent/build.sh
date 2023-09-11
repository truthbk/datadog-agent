#!/bin/bash 

go build -tags "containerd cri docker etcd kubeapiserver kubelet podman" .