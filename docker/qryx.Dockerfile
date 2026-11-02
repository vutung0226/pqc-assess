# qryx at the version tools.lock.json pins. go install checks every module
# against the Go checksum database, so the build fetches what was published.
FROM golang:1.22 AS build
ARG MODULE
ARG VERSION
ENV GOTOOLCHAIN=go1.27.3
RUN CGO_ENABLED=0 GOBIN=/out go install -trimpath "$MODULE@$VERSION"

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/qryx /qryx
ENTRYPOINT ["/qryx"]
