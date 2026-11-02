# CryptoScan at the commit tools.lock.json pins, with the patches in
# patches/cryptoscan applied. Drop a patch once upstream has merged it.
FROM golang:1.22 AS build
ARG REPO
ARG COMMIT
RUN git clone --quiet "$REPO" /src && git -C /src checkout --quiet "$COMMIT"
COPY patches/cryptoscan/ /patches/
RUN cd /src && git apply /patches/*.patch \
 && CGO_ENABLED=0 go build -trimpath -buildvcs=false -o /cryptoscan ./cmd/cryptoscan

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /cryptoscan /cryptoscan
ENTRYPOINT ["/cryptoscan"]
