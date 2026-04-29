FROM golang:1.26.2-alpine3.23@sha256:f85330846cde1e57ca9ec309382da3b8e6ae3ab943d2739500e08c86393a21b1 AS builder

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

USER 0:0

ENTRYPOINT ["/sockguard"]
CMD ["serve"]
