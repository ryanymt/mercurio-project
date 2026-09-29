# The control plane's image (P05 D12): foreman, one binary for callback-api, dispatch, migrate, project
# activate and db rights, chosen by the job's or service's arguments. Debian 13, for its git (2.47:
# the risk evaluator's git runner refuses anything older than 2.41) and ca-certificates (git only
# recommends it, and without it every https call fails); run as a non-root user. Built by Cloud
# Build (cloudbuild.yaml) and deployed by digest. Protected (**/Dockerfile).
FROM golang:1.27.1-trixie@sha256:433790e515d27dc6003e847e644cc0af956985cf315c1c58a3b73ee2dd305183 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
COPY migrations/ migrations/
RUN CGO_ENABLED=0 go build -trimpath -o /out/foreman ./cmd/foreman

FROM debian:13-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --user-group --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin foreman
COPY --from=build /out/foreman /usr/local/bin/foreman
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/foreman"]
