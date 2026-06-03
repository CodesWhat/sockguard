FROM golang:1.26.4-alpine3.23@sha256:f23e8b227fb4493eabe03bede4d5a32d04092da71962f1fb79b5f7d1e6c2a17f AS builder

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

FROM cgr.dev/chainguard/static:latest@sha256:77d8b8925dc27970ec2f48243f44c7a260d52c49cd778288e4ee97566e0cb75b

LABEL maintainer="CodesWhat"
LABEL org.opencontainers.image.title="sockguard"
LABEL org.opencontainers.image.description="Docker socket proxy — guide what gets through"
LABEL org.opencontainers.image.source="https://github.com/CodesWhat/sockguard"
LABEL org.opencontainers.image.licenses="Apache-2.0"

COPY --from=builder /sockguard /sockguard
COPY app/configs/ /etc/sockguard/

USER 65532:65532

ENTRYPOINT ["/sockguard"]
CMD ["serve"]
