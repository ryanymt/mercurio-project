# Foreman: An Agentic Software House on Google Cloud

## Executive Summary: Beyond the Toy Demos

Most autonomous software agent demonstrations follow a depressingly familiar script: an LLM is given shell access, a terminal pipe, and a prompt that says "be a 10x developer". Five minutes later, the agent has hallucinated an invalid git flag, overwritten the wrong file, hit a rate limit, looped thirty times burning fifty dollars, and left the workspace in an unrecoverable state.

Foreman was designed on a fundamentally different premise:
1. Software development is an asynchronous, stateful, multi-agent process requiring formal boundaries.
2. The control plane must be deterministic, pure, and completely free of language model calls.
3. Code changes, reviews, and deployments must be mediated by Git as the central message bus.
4. Security must fail closed at every layer: network, database, filesystem, and credentials.

Foreman is a production-grade control plane written in Go 1.27.1 that coordinates teams of AI agents on real software projects hosted in GitHub and deployed to Google Cloud Platform. It enforces strict state machine transitions, cryptographic fencing leases, deterministic risk evaluations, provider budget gating, and least-privilege cloud isolation.

```
Developer Agent (commits to branch) -> GitHub Repository
QA Reviewer Agent (tests branch)    -> GitHub Repository

GitHub Repository (ls-remote / diff) <-> Foreman Control Plane (Go)
Foreman Control Plane (ACID State)   <-> Cloud SQL Postgres (Private IP)
Foreman Control Plane (Launches)     -> Cloud Run Runner Jobs (Air-Gapped)
```

## Core Architectural Pillars

### 1. The Git Repository is the Message Bus
We do not invent bespoke RPC protocols or fragile websockets for agent coordination. When an agent writes code, it commits to a dedicated git branch: `foreman/<ticket_id>/<attempt_number>`. When an agent submits work, it presents the commit hash. Git commits are cryptographically signed, immutable, diffable, and native to existing developer workflows.

### 2. The Deterministic Control Plane
The Foreman control plane (the Callback API, Risk Evaluator, and Dispatcher) never calls an LLM. It contains zero prompt chains. It is written in pure Go and backed by PostgreSQL 17. Decisions about state progression, leases, permissions, and risk are computed using deterministic logic, compiled-in policies, and database constraints.

### 3. Asymmetric Escalation & Fail-Closed Gates
Agents operate under an asymmetric trust model. An agent is free to propose modifications on its isolated branch. However, transitioning a ticket from `in_qa` to `approved` and merging into `main` requires either passing a strict, deterministic risk policy (for trivial, low-risk changes) or triggering an escalation to human engineering operators. If any check fails, times out, or encounters unexpected data, the system halts or escalates. It never guesses.

### 4. Ephemeral, Air-Gapped Execution
Agents do not live on persistent development machines. Every task run is executed inside an ephemeral Cloud Run Job container. Crucially, the runner containers have no Direct VPC egress: they possess no network route to the private Cloud SQL database. An agent communicates strictly with the public Callback API using short-lived tokens.

## The Lifecycle of a Ticket

A ticket represents a discrete unit of software work. It transitions through a strict, finite state machine:

* `draft`: Initial ticket specification created by an operator or architectural planner.
* `ready`: Ticket dependencies are satisfied; ticket enters the candidate dispatch queue.
* `claimed`: A dispatcher worker locks the ticket, generates an exclusive claim token, charges provider budget, and triggers a container launch.
* `in_progress`: The runner container boots, validates its token, and begins code modifications.
* `in_qa`: Code has been committed and pushed; ticket moves to the QA queue for independent test execution.
* `awaiting_review`: QA verification has completed; ticket awaits automated risk scoring or human sign-off.
* `approved`: Risk evaluation verified that all changed files are low-risk and no protected control plane paths were touched.
* `merging`: The integration queue claims the ticket to fast-forward merge into `main`.
* `merged`: Code has safely landed on the default branch.
* `escalated`: The automated path encountered a risk violation, three failed launches, or a test discrepancy. Execution pauses for human intervention.
* `failed`: The ticket exhausted all retry attempts without success.

## Project Construction Overview

Foreman was constructed systematically across sequential development phases:

* Phase P01 (Foundation): Relational database schema on PostgreSQL 17, migration tooling, CI harness, and base GCP Terraform definitions.
* Phase P02 (Callback API): The authenticated REST control plane, cryptographic lease fencing, Google ID token verification, and replay-proof idempotency.
* Phase P03 (Risk Evaluator): Pure-function risk evaluation, sterile Git diff extraction, and compiled-in protection for meta-control paths.
* Phase P04 (Dispatcher): Priority queue dispatching (Integration, QA, New Work), provider budget gating, deadlock-free PostgreSQL row-level locks, and automated lease reaping.
* Phase P05 (Echo Runner & Deployment): Physical provisioning on GCP (Cloud SQL, Cloud Run, Secret Manager), zero-log secret versioning, database permission hardening, and live end-to-end execution.

The following documents detail the exact technical choices, engineering rationale, and security defenses for each phase.
