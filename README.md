# Mercurio

Mercurio is a deterministic control plane for teams of AI coding agents working on GitHub
repositories. It decides which agent runs, with which credentials, and whether its work may land,
and it never calls a language model to make those decisions. It runs on Google Cloud.

In the code, the binary and the design documents, the control plane is called **foreman**.

**Status.** The control plane (callback API, risk evaluator, dispatcher) and a model-less *echo
runner* deploy to Google Cloud and take a ticket from `ready` to `awaiting_review` in a sandbox
repository with no human steps. Runners that call models are not part of this repository yet.

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
  tokens.

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
`make test` uses that database and starts nothing.

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
- the callback API as a Cloud Run service;
- the dispatcher, migrations and the echo runner as Cloud Run jobs;
- Cloud Scheduler, running the dispatcher every minute (created paused);
- Secret Manager secrets, an Artifact Registry repository and one service account per component,
  each granted only what it needs.

You need:

- **Your own fork of this repository.** The identities in step 1 are compiled into the images, and
  `make images` builds only commits that are on `origin/main`.
- **A Google Cloud project with billing enabled**, where you are Owner, with `gcloud` signed in
  (`gcloud auth login`, and `gcloud auth application-default login` for Terraform).
- **Terraform 1.14**, Go 1.27.1, GNU Make and Docker.
- **A GitHub repository for the echo runner to work in** (the *sandbox*), with at least one commit
  on `main`, and a GitHub account that can create a GitHub App.

Set these once for the commands below:

```sh
PROJECT=my-project            # your Google Cloud project id
REGION=us-central1
OPERATOR=you@example.org      # the Google account that will act as the operator
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

Each identity-map entry gives an account a role: `dispatcher`; a runner role (`dev`, `qa`,
`spec`, `architect` or `integrator`) for one project; or `human`, for operators. Every account the
dispatcher runs a runner as, `<role>-<project>@<project-id>.iam.gserviceaccount.com`, must be in
the map with the same role and project. To add an operator, add a `human` entry. The callback API
refuses every account that is not in the map.

### 2. Create the state bucket and initialise Terraform

```sh
gcloud storage buckets create gs://$PROJECT-tfstate --project $PROJECT --location $REGION \
  --uniform-bucket-level-access --public-access-prevention
gcloud storage buckets update gs://$PROJECT-tfstate --versioning
cd infra
cp terraform.tfvars.example terraform.tfvars    # set project_id, project_number and region
terraform init -backend-config="bucket=$PROJECT-tfstate"
```

`terraform.tfvars` is git-ignored. It can also set a monthly budget (`billing_account` and
`monthly_budget_usd`).

### 3. Enable the APIs and prepare the image build

The images do not exist yet, so the first two applies create only the APIs and what `make images`
needs: the registry, the Cloud Build staging bucket and the `builder` account.

```sh
terraform apply -target=google_project_service.enabled
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

### 5. Deploy

```sh
cd infra
terraform plan -out=plan.tfplan    # read it
terraform apply plan.tfplan
cd ..
J="--region $REGION --project $PROJECT --wait"
gcloud run jobs execute migrate $J
```

Cloud SQL takes several minutes to create. The dispatcher's schedule starts paused.

### 6. Connect the GitHub App

Create a GitHub App (GitHub: Settings, Developer settings, GitHub Apps) with no webhook, the
repository permission **Contents: Read and write**, and no events. Install it on the sandbox
repository only, and generate a private key. Then give the App's id and key to the dispatcher,
and delete the downloaded key:

```sh
printf '%s' '<the App id>' | gcloud secrets versions add github-app-id --data-file=- --project $PROJECT
gcloud secrets versions add github-app-key --data-file=<the downloaded key>.pem --project $PROJECT
shred -u <the downloaded key>.pem
```

The dispatcher mints a one-hour token for one repository for each launch. Protect the sandbox's
`main` with a ruleset that has no bypass actors, so that no token can push to it. Runners push only
to their own `foreman/<ticket>/<attempt>` branches.

### 7. Activate the sandbox and resume

```sh
gcloud run jobs execute migrate $J --args=project,activate,sandbox   # the one active project
gcloud run jobs execute dispatcher $J --args=db,rights               # what the app's database user may do
make resume PROJECT_ID=$PROJECT REGION=$REGION
```

`db rights` writes its report to the execution's logs. The app user should not be a
`cloudsqlsuperuser`, and it should be refused `CREATE TABLE`.

### 8. Run a ticket

Operators create tickets as an execution of the dispatcher job. `^;^` makes `;` the argument
separator, so a title may contain commas:

```sh
gcloud run jobs execute dispatcher $J \
  --args='^;^ticket;create;--as;'"$OPERATOR"';--project;sandbox;--title;An echo;--criteria;[{"id": "AC1", "text": "it echoes"}]'
```

On a later tick, the dispatcher claims the ticket and launches `echo-runner-sandbox`. A Cloud Run
job execution can take two to three minutes to start. The runner commits one file under `echo/`
to `foreman/<ticket>/1` in the sandbox and submits it, and the ticket reaches `awaiting_review`.
The logs are in Cloud Logging:

```sh
gcloud logging read 'resource.type="cloud_run_job"' --project $PROJECT --limit 50
```

### Operating it

- **Pause and resume.** `make pause PROJECT_ID=$PROJECT REGION=$REGION` stops the schedule and then
  Cloud SQL, so only storage is billed. `make resume` starts Cloud SQL (this takes several minutes)
  and then the schedule. Terraform ignores both states. Deploy only while resumed, because the
  callback API connects to the database when it starts.
- **Deploy a change** once it is on `main`: `make images`, then `terraform plan` and `apply` in
  `infra/`, then the `migrate` job.
- **Costs.** While Cloud SQL runs, `db-f1-micro` costs roughly ten US dollars a month. The
  dispatcher's executions add a few dollars a month while resumed, and the callback API scales to
  zero.
- **Tear down.** Cloud SQL is protected against deletion. Set both of its deletion-protection
  settings in `infra/sql.tf` to `false`, apply, then run `terraform destroy`.

## Repository layout

| Path | What it holds |
|---|---|
| `cmd/foreman` | The operator CLI and every control-plane command: `migrate`, `callback-api`, `dispatch`, `project activate`, `db rights`, `ticket create` |
| `cmd/echo-runner` | The echo runner's command |
| `internal/callback_api` | The callback API: token verification, the transition engine, leases, idempotency |
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

Apache License 2.0. See [LICENSE](LICENSE).
