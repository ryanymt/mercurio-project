#!/usr/bin/env bash
# Run the Go tests against a throwaway PostgreSQL 17 database.
#
# With DATABASE_URL set in the environment, the tests simply run against that
# database and nothing is started. Otherwise a postgres:17 container is started
# in Docker, published on a random 127.0.0.1-only port, and removed again when
# the script exits — whether the tests pass, fail or are interrupted.
#
# Usage: bash scripts/dev/testdb.sh [go test arguments...]
set -euo pipefail

args=("$@")
if (( ${#args[@]} == 0 )); then
  args=(./...)
fi

# Run the tests, preserving go test's exit status for the caller.
run_tests() {
  local status=0
  go test "$@" || status=$?
  return "$status"
}

# An outside database means nothing to start, and no need for Docker at all.
if [[ -n ${DATABASE_URL:-} ]]; then
  run_tests "${args[@]}"
  exit
fi

if ! command -v docker >/dev/null; then
  echo "testdb.sh: needs Docker, or DATABASE_URL pointing at a database" >&2
  exit 1
fi

# The password travels through the environment, never the command line, so it
# stays out of `docker ps` output and the shell history.
pw=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')

cid=$(POSTGRES_PASSWORD="$pw" docker run -d \
  --label mercurio-project.testdb=1 \
  -e POSTGRES_PASSWORD \
  -p 127.0.0.1::5432 \
  --tmpfs /var/lib/postgresql/data \
  postgres:17)

# No --name above, so parallel runs cannot collide; the label is what
# `make testdb-clean` sweeps up, including containers a hard kill left behind.
remove_container() { docker rm -f -v "$cid" >/dev/null 2>&1 || true; }
trap remove_container EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

ready=0
for _ in $(seq 1 60); do
  if docker exec "$cid" pg_isready -q -h 127.0.0.1 -U postgres >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
if (( ready == 0 )); then
  echo "testdb.sh: postgres:17 in container $cid never accepted connections" >&2
  exit 1
fi

# `docker port` prints "127.0.0.1:NNNNN"; keep what follows the last colon.
port_line=$(docker port "$cid" 5432/tcp | tail -n 1)
port=${port_line##*:}
if [[ ! $port =~ ^[0-9]+$ ]]; then
  echo "testdb.sh: could not read the published port from '$port_line'" >&2
  exit 1
fi

echo "testdb.sh: postgres:17 in container $cid on 127.0.0.1:$port" >&2
export DATABASE_URL="postgres://postgres:${pw}@127.0.0.1:${port}/postgres?sslmode=disable"
run_tests "${args[@]}"
