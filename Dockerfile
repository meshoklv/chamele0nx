# syntax=docker/dockerfile:1
#
# Chamele0nX — one image with the server and the client.
#   docker build -t chamele0nx .
#   docker run --rm chamele0nx chamele0nx-server -version
#
# The default entrypoint is the server. The client binary is in the same
# image (docker-compose.yml runs it with `--profile client`).

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ENV CGO_ENABLED=0
RUN set -eu; \
    for c in chamele0nx-server chamele0nx-client chamele0nx-profiler chamele0nx-validator; do \
      go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/$c ./cmd/$c; \
    done

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ /usr/local/bin/
# Placeholder cover site. Replace it (see docs/en/INSTALL.md, section 4).
COPY deploy/cover-site /var/www/cover
USER nonroot:nonroot
EXPOSE 443
ENTRYPOINT ["/usr/local/bin/chamele0nx-server"]
