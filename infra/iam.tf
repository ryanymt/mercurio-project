# IAM, per resource, each account only what it needs. The builder's bindings are in identities.tf,
# beside its repository. Not granted here: the operator's own roles, and Google-managed service
# agents.

locals {
  # Who reads each secret's payload.
  secret_accessors = {
    "dispatcher-app-url"   = { secret = "database-url-app", account = "dispatcher" }
    "dispatcher-app-key"   = { secret = "github-app-key", account = "dispatcher" }
    "dispatcher-app-id"    = { secret = "github-app-id", account = "dispatcher" }
    "callback-api-app-url" = { secret = "database-url-app", account = "callback-api" }
    "migrate-migrator-url" = { secret = "database-url-migrator", account = "migrate" }
    "dev-sandbox-token"    = { secret = "github-token-dev-sandbox", account = "dev-sandbox" }
  }
}

resource "google_secret_manager_secret_iam_member" "accessor" {
  for_each  = local.secret_accessors
  secret_id = google_secret_manager_secret.secret[each.value.secret].id
  role      = "roles/secretmanager.secretAccessor"
  member    = google_service_account.role[each.value.account].member
}

# The launcher adds each token as a version, lists the enabled ones and destroys the older: no
# payload is read.
resource "google_secret_manager_secret_iam_member" "dispatcher_manages_tokens" {
  secret_id = google_secret_manager_secret.secret["github-token-dev-sandbox"].id
  role      = "roles/secretmanager.secretVersionManager"
  member    = google_service_account.role["dispatcher"].member
}

# The launcher runs the echo runner's job with its overrides.
resource "google_cloud_run_v2_job_iam_member" "dispatcher_runs_echo_runner" {
  name     = google_cloud_run_v2_job.echo_runner_sandbox.name
  location = google_cloud_run_v2_job.echo_runner_sandbox.location
  role     = "roles/run.jobsExecutorWithOverrides"
  member   = google_service_account.role["dispatcher"].member
}

# The scheduler runs the dispatcher's job, with no overrides.
resource "google_cloud_run_v2_job_iam_member" "scheduler_runs_dispatcher" {
  name     = google_cloud_run_v2_job.dispatcher.name
  location = google_cloud_run_v2_job.dispatcher.location
  role     = "roles/run.jobsExecutor"
  member   = google_service_account.role["scheduler"].member
}

# The echo runner calls the callback API.
resource "google_cloud_run_v2_service_iam_member" "dev_sandbox_invokes_callback_api" {
  name     = google_cloud_run_v2_service.callback_api.name
  location = google_cloud_run_v2_service.callback_api.location
  role     = "roles/run.invoker"
  member   = google_service_account.role["dev-sandbox"].member
}
