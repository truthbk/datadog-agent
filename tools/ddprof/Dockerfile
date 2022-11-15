ARG AGENT_VERSION
FROM datadog/agent:${AGENT_VERSION}

# install ddprof
ARG DDPROF_VERSION=0.10.1
ARG TARGETARCH
RUN curl -L https://github.com/DataDog/ddprof/releases/download/v${DDPROF_VERSION}/ddprof-${DDPROF_VERSION}-${TARGETARCH}-linux.tar.xz -o ddprof.tar.xz \
 && tar --strip-components=2 -C /opt/datadog-agent/embedded/bin -xf ddprof.tar.xz ddprof/bin/ddprof \
 && rm -f ddprof.tar.xz

# Install datadog-agent-dbg at the right version
RUN apt-get update && apt-get install --no-install-recommends -y gnupg dirmngr ca-certificates \
 && apt-key adv --recv-keys --keyserver hkp://keyserver.ubuntu.com:80 33EE313BAD9589B7
ARG AGENT_VERSION
ARG APT_REPO=apt.datadoghq.com
ARG APT_DISTRIBUTION=stable
RUN echo "deb http://${APT_REPO}/ ${APT_DISTRIBUTION} 7 6" > /etc/apt/sources.list.d/datadog.list \
 && apt-get update -o Dir::Etc::sourcelist="sources.list.d/datadog.list" \
 && cd /root/ \
 && DEB_AGENT_VERSION=$(echo "${AGENT_VERSION}" | sed "s/-/~/") \
 && apt-get download datadog-agent-dbg=1:${DEB_AGENT_VERSION}-1 \
 && dpkg -X ./datadog-agent-dbg*.deb / \
 && rm -f ./datadog-agent-dbg*.deb

RUN mkdir -p /usr/lib/debug/.build-id/$(readelf -n /opt/datadog-agent/bin/agent/agent | perl -nE 'say $1 if /Build ID: (..)(.*)/')

RUN cp /opt/datadog-agent/.debug/opt/datadog-agent/bin/agent/agent.dbg \
       /usr/lib/debug/.build-id/$(readelf -n /opt/datadog-agent/bin/agent/agent | perl -nE 'say "$1/$2.debug" if /Build ID: (..)(.*)/')
