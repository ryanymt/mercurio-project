# Phase P02: The Callback API (Fencing, Leases, and Identity)

## The Perils of Asynchronous Agent Coordination

In a traditional microservices architecture, services communicate with RPCs, return responses within milliseconds, and fail predictably. 

AI coding agents are nothing like that. An agent runner might boot up, start cloning a 2 GB repository, chew on an LLM inference for 90 seconds, run a suite of unit tests for 3 minutes, freeze briefly during a network blip, and then suddenly attempt to update its ticket state.

If your API does not have formal lease fencing, you will experience the classic "Zombie Runner Problem":
1. Runner A claims Ticket 10 and starts working.
2. Runner A hits an unexpected pause or network delay. Its lease expires.
3. The dispatcher notices the expired lease, reaps the ticket, and assigns it to Runner B.
4. Runner B starts writing fresh code.
5. Runner A suddenly unfreezes, thinks it is still in charge, and submits its outdated, half-baked commit to the database, overwriting Runner B.

Phase P02 built the Callback API (`internal/callback_api`) to make this failure mode mathematically impossible.

## What Was Built

Phase P02 implemented the core communication bridge between runner containers and the Foreman control plane:

1. The Hardened Transition Engine:
   * Replaces ad-hoc state updates with a strict transition matrix.
   * Every transition is verified against an immutable table of allowed (from_state, to_state, actor_role) tuples.
   * Transitions are executed inside database transactions guarded by row-level locks.

2. Cryptographic Lease Fencing:
   * When a ticket is claimed, the control plane generates a cryptographically random `claim_token` and sets a `lease_expires_at` timestamp (default 5 minutes).
   * Every single call from a runner (heartbeats, start progress, submit code) must provide this exact token.
   * If the database clock passes `lease_expires_at`, the lease is considered dead. Any subsequent mutation from that token receives HTTP 409 Conflict.
   * Heartbeats extend the lease if and only if the current lease is still active and valid.

3. Two-Layer Identity Verification:
   * Layer 1 (Infrastructure): Cloud Run IAM invoker checks at Google Cloud's network boundary.
   * Layer 2 (Application): The Go application directly verifies Google-signed OIDC ID tokens using `go-oidc`.
   * Verifies cryptographic signatures against Google's public JWKS endpoints over HTTPS.
   * Maps authenticated service account emails to verified (Project, Role) pairs via an embedded identity map.

4. Idempotent Execution Engine:
   * Network retries are inevitable in distributed systems.
   * Every state-changing API request requires an idempotency key.
   * The API hashes the request payload and stores the response in the `request_log` table.
   * Replaying an identical request returns the cached response without re-triggering state machine side effects.

## Why We Built It That Way (Design Defenses)

### 1. Fencing Tokens over Optimistic Locking
Optimistic locking (e.g. `WHERE version = 5`) sounds simple, but in asynchronous agent workflows where runners operate across multiple external systems (GitHub branches, test runners, artifact buckets), a simple version counter is insufficient.

A cryptographic fencing token ties the physical execution session to the database state. When the lease expires, the token is permanently invalidated. The runner cannot heartbeat, cannot push status, and cannot submit code. The zombie process is cleanly neutralized before it can corrupt state.

### 2. A Hardcoded State Matrix over Dynamic Rules
Engineers frequently attempt to make state machines "configurable" with dynamic rules engines or graph databases. In an AI platform, configurable state transitions are an invitation to disaster. 

We explicitly hardcoded every allowable transition in Go code. For example, moving from `in_qa` to `approved` can only be performed by the authorized evaluation pipeline, never by a developer runner. If a rogue or hallucinating agent sends a request attempting to jump from `claimed` directly to `approved`, the transition engine rejects it with HTTP 403 Forbidden without touching the database row.

### 3. Rate-Limited JWKS Refetches
A subtle vulnerability in OIDC verifiers is key-fetching denial of service. If an attacker sends a flood of requests with randomly generated `kid` (key ID) headers, a naive verifier will make an outbound HTTPS request to Google's JWKS server for every single request, quickly exhausting outbound sockets or getting IP-banned.

Our verifier enforces a strict rate-limit: it refetches keys from Google's HTTPS JWKS endpoint at most once per minute for unknown key IDs. Bursts of invalid tokens are rejected locally in memory.

### 4. Clock Skew Tripwires
Token expiry and lease evaluations depend on time. If the host running the Go API has a clock that drifts by 30 seconds relative to the PostgreSQL database, valid tokens can be rejected or expired leases can be improperly accepted.

The Callback API performs a clock skew check at startup. It compares its local system time with the PostgreSQL database time via `SELECT clock_timestamp()`. If the clock drift exceeds a tight threshold, the service logs an error and refuses to start.

## Verification & Validation

Phase P02 was verified through an extensive battery of tests:
* Concurrency and race testing using Go's race detector (`go test -race`).
* Simulated network dropouts and delayed heartbeat tests proving that expired runners are locked out with HTTP 409 Conflict.
* Token forgery and audience mismatch tests asserting that tokens minted for other services or without full email claims are refused.
* 532 passing automated tests at phase close.
