# --platform=$BUILDPLATFORM: the builder always runs natively and CROSS-compiles
# for $TARGETARCH. Running the amd64 toolchain under qemu/Rosetta emulation is
# both slow and unreliable (Go runtime faults during go mod download).
FROM --platform=$BUILDPLATFORM golang:1.27.2-alpine3.23@sha256:2ac5c2a64f1f970b5120fe21c6a5e3d9190b196a9ead95797564738ecd07a8a2 AS builder

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
ARG TARGETOS TARGETARCH
WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY app/ ./app/
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -ldflags="-s -w \
      -X github.com/codeswhat/sockguard/v2/app/internal/version.Version=${VERSION} \
      -X github.com/codeswhat/sockguard/v2/app/internal/version.Commit=${COMMIT} \
      -X github.com/codeswhat/sockguard/v2/app/internal/version.BuildDate=${BUILD_DATE}" \
    -trimpath \
    -o /sockguard ./app/cmd/sockguard/
RUN install -d -m 0700 /runtime/sockguard && touch /runtime/sockguard/.volume-init

FROM cgr.dev/chainguard/static:latest@sha256:399c8cb4858f05aaa33f43f02a2e75f28d40f016c0f86e5ba6075769e3303791

LABEL maintainer="CodesWhat"
LABEL org.opencontainers.image.title="sockguard"
LABEL org.opencontainers.image.description="Docker socket proxy — guide what gets through"
LABEL org.opencontainers.image.source="https://github.com/CodesWhat/sockguard"
LABEL org.opencontainers.image.licenses="MIT"

COPY --from=builder /sockguard /sockguard
COPY app/configs/ /etc/sockguard/
COPY --from=builder --chown=65532:65532 --chmod=0700 /runtime/sockguard/ /var/run/sockguard/

USER 65532:65532

ENTRYPOINT ["/sockguard"]
CMD ["serve"]