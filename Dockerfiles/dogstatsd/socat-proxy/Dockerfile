ARG LINUX_BASEIMAGE_REGISTRY=""
FROM ${LINUX_BASEIMAGE_REGISTRY}library/alpine:3.12

LABEL maintainer "Datadog <package@datadoghq.com>"

RUN apk add --no-cache socat

EXPOSE 8125/udp

CMD ["socat", "-s", "-u", "UDP-RECV:8125", "UNIX-SENDTO:/socket/statsd.socket"]
