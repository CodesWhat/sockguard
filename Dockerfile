# --platform=$BUILDPLATFORM: the builder always runs natively and CROSS-compiles
# for $TARGETARCH. Running the amd64 toolchain under qemu/Rosetta emulation is
# both slow and unreliable (Go runtime faults during go mod download).
FROM --platform=$BUILDPLATFORM golang:1.26.5-alpine3.23@sha256:622e56dbc11a8cfe87cafa2331e9a201877271cbff918af53d3be315f3da88cc AS builder

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
ARG TARGETOS TARGETARCH
WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY app/ ./app/
# Temporary compatibility copy while imports move to their canonical /app paths.
COPY app/internal/ ./internal/
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -ldflags="-s -w \
      -X github.com/codeswhat/sockguard/app/internal/version.Version=${VERSION} \
      -X github.com/codeswhat/sockguard/app/internal/version.Commit=${COMMIT} \
      -X github.com/codeswhat/sockguard/app/internal/version.BuildDate=${BUILD_DATE}" \
    -trimpath \
    -o /sockguard ./app/cmd/sockguard/
RUN install -d -m 0700 /runtime/sockguard && touch /runtime/sockguard/.volume-init

FROM cgr.dev/chainguard/static:latest@sha256:399c8cb4858f05aaa33f43f02a2e75f28d40f016c0f86e5ba6075769e3303791

LABEL maintainer="CodesWhat"
LABEL org.opencontainers.image.title="sockguard"
LABEL org.opencontainers.image.description="Docker socket proxy — guide what gets through"
LABEL org.opencontainers.image.source="https://github.com/CodesWhat/sockguard"
LABEL org.opencontainers.image.licenses="Apache-2.0"

COPY --from=builder /sockguard /sockguard
COPY app/configs/ /etc/sockguard/
COPY --from=builder --chown=65532:65532 --chmod=0700 /runtime/sockguard/ /var/run/sockguard/

USER 65532:65532

ENTRYPOINT ["/sockguard"]
CMD ["serve"]
