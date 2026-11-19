ARG BASE_IMAGE=scratch
FROM ${BASE_IMAGE}
COPY packages/ /tmp/packages/
RUN dpkg --unpack /tmp/packages/*.deb \
    && dpkg --configure -a \
    && gpg --version \
    && gpg-agent --version \
    && file --version \
    && rm -r /tmp/packages
COPY appimagetool /tmp/appimagetool
RUN mkdir /tools \
    && cd /tools \
    && /tmp/appimagetool --appimage-extract >/dev/null \
    && mv squashfs-root appimagetool \
    && rm /tmp/appimagetool
COPY runtime /tools/runtime
COPY sign.sh /tools/sign.sh
USER 65532:65532
ENV LC_ALL=C TMPDIR=/tmp
ENTRYPOINT ["/bin/bash", "/tools/sign.sh"]
