# Mercurio

Mercurio is a deterministic control plane for teams of AI coding agents working on GitHub
repositories. It decides which agent runs, with which credentials, and whether its work may land,
and it never calls a language model to make those decisions. It runs on Google Cloud.

In the code, the binary and the design documents, the control plane is called **foreman**.

**Status.** The control plane (callback API, risk evaluator, dispatcher), a model-less *echo
runner* and a web *viewer* deploy to Google Cloud. A ticket travels from `ready` to
`awaiting_review` in a sandbox repository with no human steps; each run's transcript and test
output are captured and scrubbed; and an operator creates tickets, reads transcripts and diffs, and
decides escalations in the viewer, behind Identity-Aware Proxy. Runners that call models are not
part of this repository yet.

## How it works

- **Git is the message bus.** An agent commits to its own branch, `foreman/<ticket>/<attempt>`,
  and submits the commit hash. No bespoke RPC between agents.
- **The control plane is deterministic.** The callback API, the risk evaluator and the dispatcher
  are Go on PostgreSQL 17. State transitions, leases, permissions and risk are decided by code,
  compiled-in policies and database constraints.
- **Escalation is asymmetric and fails closed.** A change is approved automatically only when every
  rule passes; any error, timeout or unexpected input escalates to a human.
- **Runners are ephemeral and have no route to the database.** Each run is a Cloud Run job
  execution with no VPC egress. It talks to GitHub and to the public callback API, with short-lived
  tokens, and writes its scrubbed transcript to its own prefix of a bucket it cannot read.
- **People act only through the viewer.** The viewer reads the database as a user that cannot
  write, and relays each decision to the callback API with the person's IAP assertion, bound to the
  commit and escalation that were on their screen.

```
Developer Agent (commits to branch) -> GitHub Repository
QA Reviewer Agent (tests branch)    -> GitHub Repository

GitHub Repository (ls-remote / diff) <-> Foreman Control Plane (Go)
Foreman Control Plane (ACID State)   <-> Cloud SQL Postgres (Private IP)
Foreman Control Plane (Launches)     -> Cloud Run Runner Jobs (Air-Gapped)
```

| Document | What it covers |
|---|---|
| [Overview and architecture](docs/public/00-overview-and-architecture.md) | The premise, the pillars and the ticket lifecycle |
| [P01: foundation](docs/public/01-phase-p01-foundation.md) | The schema, its invariants and the base infrastructure |
| [P02: callback API](docs/public/02-phase-p02-callback-api.md) | Lease fencing, identity verification and idempotency |
| [P03: risk evaluator](docs/public/03-phase-p03-risk-evaluator.md) | Pure-function risk evaluation, sterile git and meta protection |
| [P04: dispatcher](docs/public/04-phase-p04-dispatcher.md) | Priority queues, the lock hierarchy and budget gates |
| [P05: echo runner and deployment](docs/public/05-phase-p05-echo-runner.md) | The first deployment on Google Cloud, the air-gapped runner and secret hygiene |
| [P06: transcripts and viewer](docs/public/06-phase-p06-transcripts-viewer.md) | Transcript capture and scrubbing, the read-only viewer behind IAP, and approvals |

Code comments cite design decisions by phase and number (for example `P05 D12`) and design notes
that are not published here; the documents above summarise them.

## Build and test

Needs Go 1.27.1, GNU Make and Docker.

```sh
make build    # the operator CLI and every control-plane command, as bin/foreman
make test     # go test ./... against a throwaway postgres:17 in Docker, removed afterwards
make lint     # gofmt, go vet, shell syntax
```

Tests that need Postgres fail, rather than skip, when there is none. With `DATABASE_URL` set,
`make test` uses that database and starts nothing. `make testdb-clean` removes test databases a
hard-killed run left behind.

A long-lived development database:

```sh
make db-up      # postgres:17 on 127.0.0.1:55432, data kept in a Docker volume
make migrate    # builds bin/foreman and applies pending migrations (to DATABASE_URL if set)
make db-down    # removes the database and its data
```

`bin/foreman` without arguments lists its commands. Locally, `foreman dispatch` makes one
dispatcher tick and prints each launch request instead of launching it.

## Deploy to Google Cloud

The deployment in [`infra/`](infra/) creates:

- Cloud SQL for PostgreSQL 17 (`db-f1-micro`, private IP only);
- the callback API and the viewer as Cloud Run services, the viewer behind IAP;
- the dispatcher, migrations and the echo runner as Cloud Run jobs;
- Cloud Scheduler, running the dispatcher every two minutes (created paused);
- a private bucket for transcripts and test output, Secret Manager secrets, an Artifact Registry
  repository, and one service account per component, each granted only what it needs.

You need:

- **Your own fork of this repository.** The identities in step 1 are compiled into the images, and
  `make images` builds only commits that are on `origin/main`.
- **A Google Cloud project in an organization, with billing enabled**, where you are Owner, with
  `gcloud` signed in (`gcloud auth login`, and `gcloud auth application-default login` for
  Terraform). The operators must be accounts of that organization: IAP's Google-managed sign-in
  admits no others.
- **Terraform 1.14**, Go 1.27.1, GNU Make and Docker.
- **A GitHub repository for the echo runner to work in** (the *sandbox*), with at least one commit
  on `main`, and a GitHub account that can create two GitHub Apps.

Set these once for the commands below:

```sh
PROJECT=my-project            # your Google Cloud project id
REGION=us-central1
OPERATOR=you@example.org      # an account of the project's organization, the operator
SANDBOX=my-org/my-sandbox     # the sandbox repository, owner/name
```

### 1. Put your identities into the code

Three things are compiled in: the service-account domain
(`internal/dispatcher/service_accounts.go`), the identity map that maps Google accounts to roles
(`internal/callback_api/transitions_identity_map.json`), and the sandbox repository
(`migrations/00006_sandbox.sql`). The tests check the same values, so replace the placeholders
everywhere at once (GNU sed; on macOS use `sed -i ''`):

```sh
grep -rlZ -e your-project-id -e operator@example.com -e your-org/sandbox-repo -e '"sandbox-repo"' cmd internal migrations |
  xargs -0 sed -i -e "s/your-project-id/$PROJECT/g" -e "s/operator@example\.com/$OPERATOR/g" \
    -e "s#your-org/sandbox-repo#$SANDBOX#g" -e "s#\"sandbox-repo\"#\"${SANDBOX#*/}\"#g"
make lint test
git commit -am "Configure the deployment for $PROJECT" && git push origin main
```

Each identity-map entry gives an account a role: `dispatcher`; `viewer`, the account the viewer
relays as; a runner role (`dev`, `qa`, `spec`, `architect` or `integrator`) for one project; or
`human`, for operators. Every account the dispatcher runs a runner as,
`<role>-<project>@<project-id>.iam.gserviceaccount.com`, must be in the map with the same role and
project. To add an operator, add a `human` entry here and their email to `operator_emails` in step
2. The callback API refuses every account that is not in the map.

### 2. Create the state bucket and initialise Terraform

```sh
gcloud storage buckets create gs://$PROJECT-tfstate --project $PROJECT --location $REGION \
  --uniform-bucket-level-access --public-access-prevention
gcloud storage buckets update gs://$PROJECT-tfstate --versioning
cd infra
cp terraform.tfvars.example terraform.tfvars    # set project_id, project_number, region, operator_emails
terraform init -backend-config="bucket=$PROJECT-tfstate"
```

`terraform.tfvars` is git-ignored. It can also set a monthly budget (`billing_account` and
`monthly_budget_usd`).

### 3. Enable the APIs and prepare the image build

The images do not exist yet, so these applies create only the APIs and what `make images` needs:
the registry, the Cloud Build staging bucket and the `builder` account. In between, create IAP's
service agent, which the viewer's invoker binding names and Terraform cannot create.

```sh
terraform apply -target=google_project_service.enabled
gcloud beta services identity create --service=iap.googleapis.com --project $PROJECT
terraform apply -target=google_artifact_registry_repository_iam_member.builder_push \
  -target=google_storage_bucket_iam_member.builder_source -target=google_project_iam_member.builder_logs
```

### 4. Build the images

```sh
cd ..
make images PROJECT_ID=$PROJECT REGION=$REGION
```

Cloud Build builds both images from `HEAD`, checks them (non-root, git 2.41 or later, https
works), and pushes them. The digests are written to `infra/images.auto.tfvars`, and Terraform
deploys by digest.

### 5. Create the database, migrate, then deploy the rest

The viewer refuses to start until migration `00008` has given its database user its rights, and
the migrations grant rights only to users that exist. So the database, its users and the `migrate`
job come first:

```sh
cd infra
terraform apply -target=google_cloud_run_v2_job.migrate -target=google_sql_user.app -target=google_sql_user.viewer
cd ..
J="--region $REGION --project $PROJECT --wait"
gcloud run jobs execute migrate $J
cd infra
terraform plan -out=plan.tfplan    # read it
terraform apply plan.tfplan
cd ..
```

Cloud SQL takes several minutes to create. The dispatcher's schedule starts paused.

### 6. Connect the two GitHub Apps

Create two GitHub Apps (GitHub: Settings, Developer settings, GitHub Apps), each with no webhook and
no events, and generate a private key for each:

- **The runners' App:** repository permission **Contents: Read and write**, installed on the
  sandbox repository only. The dispatcher mints a one-hour token for one repository for each launch.
- **The viewer's App:** **Contents: Read-only**, installed on the repositories whose diffs the
  viewer shows (the sandbox). The viewer reads diffs with it and can change nothing.

Give each App's id and key to its component, then delete the downloaded keys:

```sh
printf '%s' '<runners App id>' | gcloud secrets versions add github-app-id --data-file=- --project $PROJECT
gcloud secrets versions add github-app-key --data-file=<runners App key>.pem --project $PROJECT
printf '%s' '<viewer App id>' | gcloud secrets versions add viewer-github-app-id --data-file=- --project $PROJECT
gcloud secrets versions add viewer-github-app-key --data-file=<viewer App key>.pem --project $PROJECT
shred -u <runners App key>.pem <viewer App key>.pem
```

Protect the sandbox's `main` with a ruleset that has no bypass actors, so that no token can push to
it. Runners push only to their own `foreman/<ticket>/<attempt>` branches.

### 7. Activate the sandbox and resume

```sh
gcloud run jobs execute migrate $J --args=project,activate,sandbox   # the one active project
gcloud run jobs execute dispatcher $J --args=db,rights               # what the app's database user may do
make resume PROJECT_ID=$PROJECT REGION=$REGION
```

`db rights` writes its report to the execution's logs. The app user should not be a
`cloudsqlsuperuser`, and it should be refused `CREATE TABLE`.

### 8. Run a ticket from the viewer

Open the viewer at `https://viewer-<project number>.<region>.run.app` and sign in as an operator.
Create a ticket for the sandbox with an acceptance criterion. On a later tick, the dispatcher
claims it and launches `echo-runner-sandbox`; a Cloud Run job execution can take a few minutes to
start. The runner commits one file under `echo/` to `foreman/<ticket>/1` in the sandbox, submits
it, and the ticket reaches `awaiting_review`. The viewer shows the run's transcript, its test
output and the diff, and is where escalations are decided.

If you open the viewer through the URL Cloud Run gave the service when it was created
(`gcloud run services describe viewer --region $REGION --project $PROJECT --format='value(urls)'`),
add that origin to `viewer_extra_origins` and apply, or the viewer refuses its forms.

Logs are in Cloud Logging:

```sh
gcloud logging read 'resource.type="cloud_run_job" OR resource.type="cloud_run_revision"' --project $PROJECT --limit 50
```

### Operating it

- **Pause and resume.** `make pause PROJECT_ID=$PROJECT REGION=$REGION` stops the schedule and then
  Cloud SQL, so only storage is billed. `make resume` starts Cloud SQL (this takes several minutes)
  and then the schedule. Terraform ignores both states. Deploy only while resumed, because the
  callback API and the viewer connect to the database when they start.
- **Deploy a change** once it is on `main`: `make images`, then `terraform plan` and `apply` in
  `infra/`, then the `migrate` job. When a change adds a migration the viewer needs, run the
  `migrate` job before the apply that gives the viewer its new image.
- **Costs.** While Cloud SQL runs, `db-f1-micro` costs roughly ten US dollars a month. The
  dispatcher's executions add a few dollars a month while resumed, and the callback API and the
  viewer scale to zero. The first request after idle waits for a cold start, which has taken over a
  minute.
- **Tear down.** Cloud SQL is protected against deletion. Set both of its deletion-protection
  settings in `infra/sql.tf` to `false`, apply, then run `terraform destroy`.

## Repository layout

| Path | What it holds |
|---|---|
| `cmd/foreman` | The operator CLI and every control-plane command: `migrate`, `callback-api`, `viewer`, `dispatch`, `project activate`, `db rights` |
| `cmd/echo-runner` | The echo runner's command |
| `internal/callback_api` | The callback API: token and IAP-assertion verification, the transition engine, leases, idempotency |
| `internal/viewer` | The viewer: pages, transcripts, diffs, and the relay of a person's decisions |
| `internal/capture` | Transcript capture: the scrubber and the write-once upload to Cloud Storage |
| `internal/risk_evaluator` | The risk evaluator, its git adapter and its embedded policy |
| `internal/dispatcher` | The dispatcher's tick, its Cloud Run launcher and GitHub App tokens |
| `internal/runner` | The echo runner |
| `internal/db`, `internal/testdb` | Database access and migrations; a fresh database per test |
| `migrations` | The schema, as goose migrations embedded in the binary |
| `infra` | The Google Cloud deployment, in Terraform |
| `docs/public` | The design documents, one per build phase |

## Security

Please report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE). `internal/capture` adapts detection rules from
gitleaks, under the MIT license in `internal/capture/GITLEAKS_LICENSE`.
