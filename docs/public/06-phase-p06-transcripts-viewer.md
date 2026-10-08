# Phase P06: Transcripts, Viewer, and Human Approvals (Observability, Zero-Trust Storage, and IAP Relay)

## The Human-in-the-Loop Dilemma

When you set loose a fleet of autonomous AI agents on a codebase, you quickly realize a sobering truth: without deep, tamper-proof observability, an autonomous software house is a black box that nobody trusts.

If an agent proposes a pull request, you need to know:
* What exact prompt was it given?
* Which files did it inspect, edit, or delete?
* Did it run tests, and what was the raw compiler output?
* What did the security risk evaluator think of the change?
* Did any secrets or credentials leak into the execution logs?

Most platforms solve this by building a sloppy administrative web dashboard: they spin up a web server, give it full read/write database credentials, hardcode a privileged API token, and expose it behind a basic password form.

Phase P06 rejected that shortcuts-first mindset. We built a zero-trust observability and human-approval pipeline where:
1. Runner transcripts are scrubbed in memory and stored as immutable chunks in Google Cloud Storage.
2. The web viewer connects to PostgreSQL as an aggressively restricted user with zero write permissions and no access to live lease tokens.
3. The viewer refuses to start if it detects any write privilege on any database object.
4. Human identity is cryptographically asserted at Google's edge via Identity-Aware Proxy (IAP).
5. Human approvals are mathematically bound to the exact commit SHA and escalation state displayed on the operator's screen.

## What Was Built

Phase P06 completed the human control interface and observability pipeline:

1. Transcript Capture and In-Memory Scrubbing:
   * Chunks are written to Google Cloud Storage under strict path hierarchies: `{project}/{ticket}/{attempt}/{role}-{run}/{kind}/{seq}.jsonl`.
   * Chunks are uploaded with generation checks (`ifGenerationMatch=0`), guaranteeing that existing chunks are never overwritten or mutated.
   * Flushes occur at least every two minutes, immediately prior to lease-ending calls, and upon container exit.
   * An in-memory regex scrubber (based on gitleaks rules) redacts private keys, GitHub personal access tokens, OAuth tokens, GCP API keys, Anthropic/OpenAI keys, bearer tokens, and URL credentials before payloads leave the container.
   * Storage IAM lockdown: Runner service accounts are granted write-only access restricted to their specific project prefix (`only-<project>`). Runners cannot read or list anything in the bucket.

2. The Self-Restricting Viewer Service:
   * Deployed as a Cloud Run service behind Google Cloud Identity-Aware Proxy (IAP) without requiring an external HTTP(S) load balancer.
   * Restricted strictly to authorized corporate identities in IAP's access policy.
   * Connects to PostgreSQL using a dedicated `viewer` role granted column-level SELECT privileges. The sensitive `claim_token` column is explicitly excluded, preventing the viewer from ever reading live fencing tokens.
   * Startup Rights Check: At startup, the viewer queries PostgreSQL catalog functions (`has_table_privilege`, `has_any_column_privilege`, `has_sequence_privilege`) across all database objects. If the user possesses any write privilege (INSERT, UPDATE, DELETE, TRUNCATE, TRIGGER, or sequence updates), the viewer logs a fatal error and refuses to start.

3. The Secure Relay Architecture:
   * The viewer application never modifies the database directly.
   * When an operator creates a ticket, approves an escalation, or parks a task, the viewer constructs a clean request from scratch and relays it to the Callback API.
   * Request sanitization: The relay discards client cookies and headers, attaching only the viewer service account's ID token in `Authorization` (to satisfy Cloud Run edge IAM) and the operator's cryptographic IAP assertion in a dedicated header.
   * The Callback API directly validates the IAP JWT signature against Google's public keys, verifies the expected audience and issuer, and maps the email to the authorized human identity map.

4. Approvals Bound to What You Saw:
   * Race conditions in code reviews can be disastrous: a human reads Commit A, decides to approve it, but an agent pushes Commit B a split second before the button is pressed.
   * Every decision form in the viewer embeds the exact commit SHA and escalation timestamp that was rendered on the screen.
   * The Callback API asserts that the ticket's current `head_sha` and escalation timestamp match what the form submitted. If the state or commit changed, the transition is rejected with HTTP 409 Conflict.

5. Claim Lease Window Realignment:
   * To absorb Google Cloud Run Jobs batch scheduling latency (observed between 2 and 4 minutes in regional queues), the initial claim lease window was lengthened from 5 minutes to 10 minutes.
   * Subsequent runner heartbeats continue to refresh the lease in 5-minute increments once the container is active.
   * The Cloud Scheduler dispatcher tick was adjusted to fire every 2 minutes.

## Why We Built It That Way (Design Defenses)

### 1. Stripping `claim_token` from the Viewer
Why did migration 00008 grant column-level SELECT on `tickets` and `attempts` rather than granting SELECT on the whole table?

The `claim_token` column contains the active, high-entropy secret that fences a runner's lease. If the viewer role had SELECT access on `claim_token`, any vulnerability in the web UI (such as template injection, error leak, or compromised session) could expose active claim tokens, allowing an attacker to impersonate a live runner and force-transition tickets. By omitting `claim_token` from the grant, PostgreSQL ensures the viewer can never read a live fence token.

### 2. The Startup Rights Sanity Check
Database administrators often make well-intentioned mistakes, such as granting broad permissions to roles or running scripts that add write privileges to `PUBLIC`.

The viewer contains an automated defense: at boot time, it runs `CheckRights()`. It dynamically checks whether the connected user has INSERT, UPDATE, DELETE, or TRUNCATE permissions on any table or column, or USAGE on any sequence. If any write capability exists, it halts. This guarantees that the viewer cannot become an accidental write backdoor.

### 3. Identity-Aware Proxy (IAP) Relay vs Direct User Tokens
In Phase P05, we discovered that Google Cloud Run's edge proxy automatically redacts the signature of generic user identity tokens (`SIGNATURE_REMOVED_BY_GOOGLE`) sent in standard `Authorization` headers.

By placing Google Identity-Aware Proxy (IAP) in front of the viewer, Google verifies the human operator at the network edge and issues an intact, cryptographically signed IAP assertion header (`X-Goog-IAP-JWT-Assertion`). The viewer's relay forwards this assertion to the Callback API, which validates the signature using Google's public JWKS. This provides true end-to-end user identity verification without requiring expensive load balancers or third-party identity providers.

### 4. Zero Overwrite Cloud Storage Chunks
Runner logs and test outputs are uploaded in discrete numbered chunks with `ifGenerationMatch=0`. 

If a runner container restarts, crashes, or experiences network retries, it cannot overwrite previously uploaded transcript chunks. Every flushed chunk is immutable. Even if a compromised runner attempts to erase its past actions, Google Cloud Storage rejects object modification.

## Live Operational Discoveries in GCP

Deploying and verifying Phase P06 in Google Cloud Platform yielded valuable production insights:

### Discovery 1: Cold Starts and Relay Timeouts
During live testing, the Callback API experienced an initial cold start of 69 seconds while scaling up from zero instances. 

The viewer's initial HTTP relay timeout was set to 30 seconds, causing the viewer to report a timeout error to the user even though the Callback API eventually processed the request. Because every action form carries a unique idempotency key, the operator was able to safely resubmit the form without creating duplicate tickets. The relay timeout was subsequently adjusted to 90 seconds to comfortably outlast cold-start provisioning.

### Discovery 2: Dual Token Forwarding Discipline
Google Cloud Run forwards both `X-Serverless-Authorization` and incoming cookies to backend containers. 

To ensure complete protocol hygiene, the viewer's relay explicitly constructs clean HTTP requests from scratch rather than proxying incoming client headers. It forwards only the freshly minted service account token for Cloud Run IAM and the IAP assertion header for application identity.

## The Proof: Live Verification

Phase P06 was verified end-to-end on live infrastructure:
* Ticket 4: Created via the Viewer UI on a desktop browser. The runner claimed the task, flushed five immutable transcript chunks to Cloud Storage, and pushed its commit. The operator reviewed the full transcript, test report, and unified GitHub diff directly in the viewer.
* Ticket 5: Created from a mobile device (Chrome on iOS) via IAP. The ticket was intentionally pushed into `escalated` state. The operator reviewed the escalation and approved the ticket directly from the mobile browser. The Callback API recorded the transition to `approved` attributed to the verified human identity.
* Secret Scan Verification: A full scan across all stored transcript chunks and Cloud Logging entries confirmed zero credential leaks (`ghs_`, `ya29.`, `eyJ`, and private keys were completely absent).
* Automated Test Suite: All 13 Go packages passing cleanly with zero skips.
