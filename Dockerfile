FROM golang:1.26.2-alpine3.23@sha256:c2a1f7b2095d046ae14b286b18413a05bb82c9bca9b25fe7ff5efef0f0826166 AS builder

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
WORKDIR /build

COPY app/go.mod app/go.sum ./
RUN go mod download

COPY app/ .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w \
      -X github.com/codeswhat/sockguard/internal/version.Version=${VERSION} \
      -X github.com/codeswhat/sockguard/internal/version.Commit=${COMMIT} \
      -X github.com/codeswhat/sockguard/internal/version.BuildDate=${BUILD_DATE}" \
    -trimpath \
    -o /sockguard ./cmd/sockguard/

FROM cgr.dev/chainguard/static:latest@sha256:1f14279403150757d801f6308bb0f4b816b162fddce10b9bd342f10adc3cf7fa

LABEL maintainer="CodesWhat"
LABEL org.opencontainers.image.title="sockguard"
LABEL org.opencontainers.image.description="Docker socket proxy — guide what gets through"
LABEL org.opencontainers.image.source="https://github.com/CodesWhat/sockguard"
LABEL org.opencontainers.image.licenses="Apache-2.0"

COPY --from=builder /sockguard /sockguard
COPY app/configs/ /etc/sockguard/

USER 0:0

ENTRYPOINT ["/sockguard"]
CMD ["serve"]
