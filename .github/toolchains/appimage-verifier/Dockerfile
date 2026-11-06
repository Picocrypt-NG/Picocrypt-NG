FROM ubuntu@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11 AS build
WORKDIR /build
COPY inputs/ inputs/
COPY SHA256SUMS build.sh manifest.json sources.lock.json os-packages.lock.json ./
RUN sha256sum --check --strict SHA256SUMS \
    && dpkg --unpack /build/inputs/*.deb \
    && dpkg --configure -a \
    && bash build.sh

FROM scratch
COPY --from=build /runtime/ /
USER 65532:65532
ENV TMPDIR=/tmp GNUPGHOME=/tmp LC_ALL=C
ENTRYPOINT ["/usr/local/bin/validate"]
CMD ["/input/AppImage"]
