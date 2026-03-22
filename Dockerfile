FROM golang:1.26-alpine AS builder

ARG VERSION=dev
WORKDIR /build

COPY app/go.mod app/go.sum ./
RUN go mod download

COPY app/ .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X github.com/codeswhat/sockguard/internal/version.Version=${VERSION}" \
    -trimpath \
    -o /sockguard ./cmd/sockguard/

FROM cgr.dev/chainguard/static:latest

LABEL maintainer="CodesWhat"
LABEL org.opencontainers.image.title="sockguard"
LABEL org.opencontainers.image.description="Docker socket proxy — guide what gets through"
LABEL org.opencontainers.image.source="https://github.com/CodesWhat/sockguard"
LABEL org.opencontainers.image.licenses="AGPL-3.0"

COPY --from=builder /sockguard /sockguard
COPY app/configs/ /etc/sockguard/

USER 65534:65534

ENTRYPOINT ["/sockguard"]
CMD ["serve"]
