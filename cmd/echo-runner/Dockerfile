# The echo runner's image (P05 D12): its own binary, so runner code is never linked into the
# protected command, on the control plane's Debian 13 base with git and ca-certificates, run as a
# non-root user. Built from the repository's root by Cloud Build (cloudbuild.yaml) and deployed by
# digest. Protected (**/Dockerfile).
FROM golang:1.27.1-trixie@sha256:433790e515d27dc6003e847e644cc0af956985cf315c1c58a3b73ee2dd305183 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 go build -trimpath -o /out/echo-runner ./cmd/echo-runner

FROM debian:13-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --user-group --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin runner
COPY --from=build /out/echo-runner /usr/local/bin/echo-runner
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/echo-runner"]
