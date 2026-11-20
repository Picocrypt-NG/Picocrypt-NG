ARG BASE_IMAGE=scratch
FROM ${BASE_IMAGE}
RUN --mount=type=bind,source=packages,target=/packages \
    set -eu; \
    export DEBIAN_FRONTEND=noninteractive; \
    printf '%s\n' 'deb [trusted=yes] file:/packages ./' > /tmp/snap-host.list; \
    apt-get -o Dir::Etc::sourcelist=/tmp/snap-host.list -o Dir::Etc::sourceparts=/dev/null update; \
    xargs -r apt-get -y --no-install-recommends \
        -o Dir::Etc::sourcelist=/tmp/snap-host.list -o Dir::Etc::sourceparts=/dev/null \
        install < /packages/install.list; \
    test -z "$(dpkg --audit)"; \
    rm -f /tmp/snap-host.list; \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*.deb
