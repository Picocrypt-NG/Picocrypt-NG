ARG BASE_IMAGE=scratch
FROM ${BASE_IMAGE} AS build
COPY java/ /opt/java/
COPY apksigner.jar /signer/apksigner.jar
COPY AndroidApkSigner.java /signer/AndroidApkSigner.java
RUN /opt/java/bin/javac -cp /signer/apksigner.jar -d /signer /signer/AndroidApkSigner.java

FROM ${BASE_IMAGE}
COPY --from=build /opt/java/ /opt/java/
COPY --from=build /signer/apksigner.jar /signer/AndroidApkSigner.class /signer/
COPY sign.sh /signer/sign.sh
USER 65532:65532
ENV LC_ALL=C TMPDIR=/tmp
ENTRYPOINT ["/bin/bash", "/signer/sign.sh"]
