ARG BASE_IMAGE=scratch
FROM ${BASE_IMAGE}
COPY packages /packages
RUN set -eu; \
    printf '%s\n' 'deb [trusted=yes] file:/packages ./' > /packages/source.list; \
    apt-get -o Dir::Etc::sourcelist=/packages/source.list -o Dir::Etc::sourceparts=/dev/null update; \
    xargs -r apt-get -y --no-install-recommends \
        -o Dir::Etc::sourcelist=/packages/source.list -o Dir::Etc::sourceparts=/dev/null \
        install < /packages/install.list; \
    test -z "$(dpkg --audit)"; \
    rm -rf /packages /var/lib/apt/lists/* /var/cache/apt/archives/*.deb
ENV DEBIAN_FRONTEND=noninteractive
