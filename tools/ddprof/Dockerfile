ARG AGENT_VERSION
FROM datadog/agent:${AGENT_VERSION}

# install ddprof
ARG DDPROF_VERSION=0.9.3
ARG TARGETARCH
RUN curl -L https://github.com/DataDog/ddprof/releases/download/v${DDPROF_VERSION}/ddprof-${DDPROF_VERSION}-${TARGETARCH}-unknown-linux-gnu.tar.xz -o ddprof.tar.xz \
 && tar --strip-components=2 -C /opt/datadog-agent/embedded/bin -xf ddprof.tar.xz ddprof/bin/ddprof \
 && rm -f ddprof.tar.xz

# Install datadog-agent-dbg at the right version
RUN apt-get update && apt-get install -o Dpkg::Options::="--force-confold" --no-install-recommends -y gnupg dirmngr ca-certificates \
 && apt-key adv --recv-keys --keyserver hkp://keyserver.ubuntu.com:80 A2923DFF56EDA6E76E55E492D3A80E30382E94DE
ARG AGENT_VERSION
ARG APT_REPO=apt.datadoghq.com
ARG APT_DISTRIBUTION=stable
RUN echo "deb https://${APT_REPO}/ ${APT_DISTRIBUTION} 7 6" > /etc/apt/sources.list.d/datadog.list \
 && apt-get update -o Dir::Etc::sourcelist="sources.list.d/datadog.list" \
 && cd /root/ \
 && DEB_AGENT_VERSION=$(echo "${AGENT_VERSION}" | sed "s/-/~/") \
 && apt-get download datadog-agent-dbg=1:${DEB_AGENT_VERSION}-1 \
 && dpkg -i --ignore-depends=datadog-agent ./datadog-agent-dbg*.deb \
 && rm -f ./datadog-agent-dbg*.deb

# move true binary to system-probe-wrapped, so ddprof gets called if k8s uses `command`
RUN mv /opt/datadog-agent/embedded/bin/system-probe /opt/datadog-agent/embedded/bin/system-probe-wrapped
ADD entrypoint.sh /opt/datadog-agent/embedded/bin/system-probe
RUN mkdir -p /usr/lib/debug && cp /opt/datadog-agent/.debug/opt/datadog-agent/embedded/bin/system-probe.dbg /usr/lib/debug/system-probe.dbg
