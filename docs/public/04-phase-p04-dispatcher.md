# Phase P04: The Dispatcher (Priority Queues, Locking Hierarchies, and Budget Gates)

## The Art of Not Melting Your Infrastructure

Building an autonomous agent platform is easy when you have one agent doing one task. 

It becomes an operational nightmare when you have multiple concurrent queues, three different AI model providers with varying rate limits and token costs, tickets moving across development, QA, and integration stages, and background cron jobs firing every sixty seconds.

Without disciplined concurrency control and budget enforcement, you get:
* Database deadlocks where the dispatcher and callback API freeze each other.
* Spurious race conditions where two workers claim the same ticket simultaneously.
* API rate limit cascading failures where one provider returning HTTP 429 brings down the entire software house.
* Runaway container loops that launch dozens of broken jobs when an image fails to boot.

Phase P04 built the Foreman Dispatcher (`internal/dispatcher` and `foreman dispatch`) to manage these operational realities with mathematical precision.

## What Was Built

Phase P04 delivered the orchestration tick that powers autonomous progression:

1. The Periodic Dispatcher Tick:
   * Driven by Cloud Scheduler or local execution: evaluates state, cleans up stale tasks, and dispatches new work in discrete passes.
   * Runs with zero model SDK imports and zero outbound AI network traffic.

2. Three Priority Queues (Right-to-Left WIP Management):
   * Integration Queue: Highest priority. Picks tickets in `approved` state to perform merge verification into `main`.
   * QA Queue: Medium priority. Picks tickets in `awaiting_review` state to launch independent testing containers.
   * New Work Queue: Standard priority. Picks tickets in `ready` state to launch developer sessions.

3. Strict PostgreSQL Lock Hierarchy:
   * Enforces an absolute lock acquisition order across all database transactions:
     1. Project Lock: `SELECT ... FOR NO KEY UPDATE`
     2. Candidate Ticket: `SELECT ... FOR UPDATE SKIP LOCKED`
     3. Provider Budget: `SELECT ... FOR UPDATE`
   * Prevents cross-component database deadlocks by construction.

4. Atomic Claim Transactions:
   * A ticket claim, lease issuance, token generation, attempt record creation, request logging, event recording, and provider budget deduction all commit in a single ACID transaction *before* the runner container is launched.
   * If container launch fails, the ticket is immediately returned to its previous state and the budget unit is refunded.

5. Hardened Lease Reaper & Return Tracking:
   * Scans for expired leases across all active states (`claimed`, `in_progress`, `in_qa`, `merging`).
   * Re-evaluates lease expiration under row locks using statement-level timestamps.
   * Tracks consecutive returns: if a ticket is returned from `claimed` three times in a row without reaching `in_progress` (indicating runner container crashes or launch failures), it diverts directly to `escalated`.

6. Provider-Specific Rate Limit Gating:
   * Runners encountering an HTTP 429 report the reset time via `POST /v1/tickets/{id}/rate-limit`.
   * Pauses only the affected provider (e.g. Anthropic or Z.ai) until the reset time (clamped to at most 24 hours).
   * Queues requiring other providers continue running without interruption.

## Why We Built It That Way (Design Defenses)

### 1. Theory of Constraints: Clearing WIP First
Why does the Integration Queue take precedence over New Work? 

In manufacturing and software engineering (Kanban and Theory of Constraints), starting new work when downstream queues are blocked leads to disastrous inventory buildup. If the integration branch is blocked or QA is backed up, launching five more developer agents will only generate stale branches and git conflicts. By processing Integration first, then QA, then New Work, the dispatcher actively pulls work toward completion.

### 2. Lock Mode Subtleties: `FOR NO KEY UPDATE`
Why did we use `FOR NO KEY UPDATE` on the project row rather than standard `FOR UPDATE`?

A standard `FOR UPDATE` lock takes an exclusive lock on the entire project row. In PostgreSQL, inserting a new row into the `tickets` table requires checking foreign key constraints against `projects`, which requires acquiring a `KEY SHARE` lock on the referenced project row. 

If the dispatcher held a standard `FOR UPDATE` lock on the project while processing tickets, any user or webhook attempting to create a new ticket would block and hang until the dispatcher tick finished! By using `FOR NO KEY UPDATE`, the dispatcher serializes tick processing while allowing concurrent ticket creation to proceed unimpeded.

### 3. The PostgreSQL Clock Trap: `now()` vs `clock_timestamp()`
Here is a terrifying PostgreSQL edge case we discovered and conquered:
* In PostgreSQL, `now()` returns the start time of the *transaction*, not the current wall clock time.
* If a tick transaction starts, waits behind a lock for several seconds, and then checks `WHERE lease_expires_at <= now()`, `now()` evaluates to the transaction's start time and sees the lease as still valid!
* Furthermore, with `clock_timestamp()` evaluated inside a `SELECT ... FOR UPDATE` query, PostgreSQL evaluates the where-clause *before* acquiring the row lock (EvalPlanQual semantics).

Our solution: The reaper first acquires the row lock, and then executes a separate statement that evaluates `lease_expires_at <= clock_timestamp()` under the acquired lock. Expired leases are accurately identified with zero race windows.

### 4. Isolating Provider Rate Limits
When an AI provider experiences high traffic and returns HTTP 429, naive platforms pause the entire application or spin in retry loops. 

Our rate-limit endpoint identifies the caller's provider directly from its active `attempts` row in PostgreSQL (preventing runners from spoofing other providers). It pauses only that provider's budget row. If Anthropic is rate-limited, Sonnet and Opus tickets pause, while Flash and DeepSeek tickets continue executing smoothly on Z.ai. When the reset timestamp passes, the provider automatically unpauses.

### 5. Git Remote Suffix Matching Defenses
Before claiming new work, the dispatcher checks the remote head of the default branch over HTTPS via `git ls-remote`. 

A subtle security flaw in `git ls-remote`: passing a pattern like `refs/heads/main` matches ref suffixes! An attacker could push a branch named `user/refs/heads/main`, and `git ls-remote <url> refs/heads/main` would return both refs! 

Our runner invokes `git ls-remote` with explicit parameter delimiters, parses the output line by line, and enforces exact-line equality matching `refs/heads/<default_branch>`. Argument injection and ref spoofing are blocked at the parser boundary.

## Verification & Validation

Phase P04 was verified across 886 passing tests and armed mutation suites:
* Concurrency stress testing: Overlapping dispatcher ticks forced to run concurrently under artificial lock delays, proving that at most one ticket per role holds an active lease.
* Zero-overdraw budget testing: Multiple workers competing for limited token budgets, confirming that provider limits are never exceeded.
* Armed mutation tests: Deliberately breaking the lock order, refund logic, and return counting to verify that test suites catch every violation.
