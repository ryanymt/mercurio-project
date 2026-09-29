# Phase P01: The Bedrock (PostgreSQL 17, Schema Design, and Terraform)

## The Philosophy of Boring Foundations

When building an autonomous software house powered by AI, the temptation is to start with the fun stuff: prompt templates, agent personalities, and fancy terminal animations. 

We did the exact opposite. We spent Phase P01 building a boring, rock-solid relational schema on PostgreSQL 17, configuring deterministic database migrations, setting up reproducible CI pipelines, and provisioning foundational Google Cloud infrastructure in Terraform.

Why? Because when an autonomous agent goes haywire at 2:00 AM, the only thing standing between you and an empty bank account is a set of rigid database constraints and atomic transactions.

## What Was Built

Phase P01 established the bedrock upon which the rest of the Foreman platform operates:

1. Relational Database Schema (PostgreSQL 17): Managed via versioned goose migrations, defining the core domain models:
   * projects: Tracks target code repositories, default git branches, and project flags.
   * tickets: Represents tasks, states, prompt descriptions, git commit SHAs, and attempt counters.
   * events: An immutable, append-only flight recorder logging every state transition, actor, and payload.
   * attempts: Individual execution attempts by runner containers, tracking roles, model tiers, and claim tokens.
   * budgets: Token and monetary budget allocations per provider with sliding window quotas.
   * request_log: Idempotency keys and request/response hashes to prevent duplicate webhook and API calls.

2. The Single Active Project Invariant: A partial unique index in PostgreSQL:
   ```sql
   /* Enforce at most one active project across the entire system */
   CREATE UNIQUE INDEX one_active_project ON projects (is_active) WHERE is_active = true;
   ```

3. Infrastructure as Code (Terraform):
   * Runtime project setup on Google Cloud Platform.
   * Dedicated Virtual Private Cloud (foreman-vpc) with private subnet (foreman-us-central1).
   * Private Google Access enabled for internal communication without public internet egress.
   * Artifact Registry repository (foreman) with immutable tag protection.
   * Initial service account definitions for control plane and runner roles.

4. Developer & CI Tooling:
   * Local containerized PostgreSQL 17 test harness running via Docker.
   * Zero-skip testing discipline: if a test requires a database and none is available, the test fails loudly rather than silently skipping.
   * Automated linting, vet checks, and shell syntax verification.

## Why We Built It That Way (Design Defenses)

### 1. Relational PostgreSQL 17 over NoSQL or Document Stores
A common trope in early AI projects is dumping agent state into MongoDB or DynamoDB because JSON blobs feel flexible. We rejected this immediately.

Agent coordination is fundamentally a distributed locking and state progression problem. We need row-level locking (SELECT FOR UPDATE SKIP LOCKED), strict foreign key constraints, atomic transactions across multiple tables, and serialized isolation levels. If two runner processes attempt to claim the same ticket concurrently, PostgreSQL guarantees that exactly one succeeds while the other safely skips or backs off. Eventual consistency is an anti-pattern when granting execution leases.

### 2. The Database Enforces Invariants, Not Just the Application
It is trivial to write an application check that says `if count(active_projects) > 0 { return error }`. It is equally trivial for concurrent operations or a subtle bug in application code to bypass that check and activate two projects simultaneously.

By placing a partial unique index directly in the PostgreSQL catalog, the database engine itself makes split-brain states physically impossible. Even if a developer writes an errant SQL script by hand, the database rejects the second active project.

### 3. The Append-Only Event Flight Recorder
In autonomous agent architectures, debugging requires forensic auditing. When an agent transitions a ticket from `in_progress` to `escalated`, asking "what happened?" cannot depend on checking ephemeral container logs that evaporated ten minutes ago.

Every single state mutation in Foreman requires an accompanying row in the `events` table. The events table is append-only. It records the originating state, destination state, acting entity (developer runner, QA reviewer, dispatcher, or human operator), a reason code, and a structured JSON payload. If the ticket state is ever questioned, the entire sequence of events can be replayed and inspected.

### 4. The Three-Strike Attempt Ceiling
Software development with AI models can run into unexpected loops: an agent misinterprets a compiler error, tries the same broken fix three times, and enters a recursive failure mode.

The `tickets` table enforces an explicit attempt cap (maximum 3 attempts). Reaching the cap without successful QA submission diverts the ticket directly into `failed` or `escalated`. No agent is ever permitted to run indefinitely or burn unbounded compute.

## Verification & Validation

The P01 foundation was validated through comprehensive test suites:
* Migration verification: Applying migrations from scratch on a clean database, tearing down, and re-applying cleanly.
* Constraint testing: Asserting that database foreign keys, unique indexes, and check constraints actively reject malformed rows.
* CI pipeline integration: GitHub Actions executing test suites on every pull request against ephemeral PostgreSQL containers.
