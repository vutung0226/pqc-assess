# A scanner binary built elsewhere, for a machine with too little disk or CPU
# to build it (scripts/deploy.sh cross-compiles it). The image runs the same
# way as the ones docker/cryptoscan.Dockerfile and docker/qryx.Dockerfile make.
FROM gcr.io/distroless/static-debian12:nonroot
ARG BIN
COPY ${BIN} /tool
ENTRYPOINT ["/tool"]
