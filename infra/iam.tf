# IAM, per resource, each account only what it needs. The builder's bindings are in identities.tf,
# beside its repository. Not granted here: the operator's own project roles, and Google-managed
# service agents' own roles.

locals {
  # Who reads each secret's payload.
  secret_accessors = {
    "dispatcher-app-url"   = { secret = "database-url-app", account = "dispatcher" }
    "dispatcher-app-key"   = { secret = "github-app-key", account = "dispatcher" }
    "dispatcher-app-id"    = { secret = "github-app-id", account = "dispatcher" }
    "callback-api-app-url" = { secret = "database-url-app", account = "callback-api" }
    "migrate-migrator-url" = { secret = "database-url-migrator", account = "migrate" }
    "dev-sandbox-token"    = { secret = "github-token-dev-sandbox", account = "dev-sandbox" }
    "viewer-db-url"        = { secret = "database-url-viewer", account = "viewer" }
    "viewer-csrf-key"      = { secret = "viewer-csrf-key", account = "viewer" }
    "viewer-app-key"       = { secret = "viewer-github-app-key", account = "viewer" }
    "viewer-app-id"        = { secret = "viewer-github-app-id", account = "viewer" }
  }

  # The runner accounts, each with the project whose prefix it may write under.
  runner_projects = {
    for account in keys(local.service_accounts) : account => regex("-(foreman|sandbox)$", account)[0]
    if can(regex("^(dev|qa|spec|architect|integrator)-(foreman|sandbox)$", account))
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

# The viewer is reached through IAP only: IAP admits the operators (var.operator_emails), and its
# service agent is the only invoker. The agent must exist before the first apply; create it with
# `gcloud beta services identity create --service=iap.googleapis.com` (see the README), which the
# provider cannot do.
locals {
  iap_agent = "serviceAccount:service-${var.project_number}@gcp-sa-iap.iam.gserviceaccount.com"
}

resource "google_iap_web_cloud_run_service_iam_member" "operator_uses_viewer" {
  for_each               = toset(var.operator_emails)
  cloud_run_service_name = google_cloud_run_v2_service.viewer.name
  location               = google_cloud_run_v2_service.viewer.location
  role                   = "roles/iap.httpsResourceAccessor"
  member                 = "user:${each.value}"
}

resource "google_cloud_run_v2_service_iam_member" "iap_invokes_viewer" {
  name     = google_cloud_run_v2_service.viewer.name
  location = google_cloud_run_v2_service.viewer.location
  role     = "roles/run.invoker"
  member   = local.iap_agent
}

# The viewer relays a person's acts to the callback API as itself.
resource "google_cloud_run_v2_service_iam_member" "viewer_invokes_callback_api" {
  name     = google_cloud_run_v2_service.callback_api.name
  location = google_cloud_run_v2_service.callback_api.location
  role     = "roles/run.invoker"
  member   = google_service_account.role["viewer"].member
}

# The viewer reads transcripts and test output: get and list, nothing more.
resource "google_storage_bucket_iam_member" "viewer_reads_artifacts" {
  bucket = google_storage_bucket.artifacts.name
  role   = "roles/storage.objectViewer"
  member = google_service_account.role["viewer"].member
}

# A runner creates objects under its own project's prefix and nothing else: no read, no list, and
# no overwrite, since it creates with ifGenerationMatch=0 and holds no delete.
resource "google_storage_bucket_iam_member" "runner_writes_its_prefix" {
  for_each = local.runner_projects
  bucket   = google_storage_bucket.artifacts.name
  role     = "roles/storage.objectCreator"
  member   = google_service_account.role[each.key].member

  condition {
    title       = "only-${each.value}"
    description = "Objects under ${each.value}/ only"
    expression  = "resource.name.startsWith(\"projects/_/buckets/${google_storage_bucket.artifacts.name}/objects/${each.value}/\")"
  }
}
