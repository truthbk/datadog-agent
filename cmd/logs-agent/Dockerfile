FROM golang:1.20 as build 

WORKDIR /src
COPY . . 

RUN ls -la

RUN go build -mod=mod -tags "containerd cri docker etcd kubeapiserver kubelet podman" -o ./bin/logs-agent/logs-agent github.com/DataDog/datadog-agent/cmd/logs-agent

FROM ubuntu:22.04 as app 

RUN apt update 
RUN apt dist-upgrade
RUN apt install curl -y
COPY --from=build /src/bin/logs-agent/logs-agent /

ENTRYPOINT [ "/logs-agent", "start" ]