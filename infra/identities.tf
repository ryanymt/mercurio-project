# One service account per control-plane component and per runner role and project. Each is granted
# what its component needs, and nothing more (iam.tf, and the builder's bindings below).
# The runner accounts' emails must match the identity map compiled into the callback API
# (internal/callback_api/transitions_identity_map.json) and the dispatcher's service-account domain
# (internal/dispatcher/service_accounts.go): see the README.

locals {
  service_accounts = {
    "dispatcher"         = "Dispatcher (Cloud Run job)"
    "callback-api"       = "Callback API (Cloud Run service)"
    "viewer"             = "Viewer (Cloud Run service, behind IAP)"
    "migrate"            = "Migrations (Cloud Run job)"
    "scheduler"          = "Cloud Scheduler, running the dispatcher's job"
    "dev-foreman"        = "Dev runner, project foreman"
    "qa-foreman"         = "QA runner, project foreman"
    "spec-foreman"       = "Spec runner, project foreman"
    "architect-foreman"  = "Architect runner, project foreman"
    "integrator-foreman" = "Integrator, project foreman"
    "dev-sandbox"        = "Dev runner, project sandbox"
    "qa-sandbox"         = "QA runner, project sandbox"
    "spec-sandbox"       = "Spec runner, project sandbox"
    "architect-sandbox"  = "Architect runner, project sandbox"
    "integrator-sandbox" = "Integrator, project sandbox"
    "builder"            = "Cloud Build, building foreman's images"
  }
}

resource "google_service_account" "role" {
  for_each     = local.service_accounts
  account_id   = each.key
  display_name = each.value
}

# Component images, deployed by digest only. Tags cannot be moved once pushed, so a tag can never
# silently point somewhere new.
resource "google_artifact_registry_repository" "images" {
  repository_id = "foreman"
  location      = var.region
  format        = "DOCKER"
  description   = "foreman component images, promoted by digest"

  docker_config {
    immutable_tags = true
  }

  # Each `make images` adds a version of each image. A version is deleted only when it is both
  # older than 30 days and outside its image's 10 newest (a KEEP policy wins over a DELETE), so the
  # deployed digest stays while it is recent or among the newest.
  cleanup_policy_dry_run = false
  cleanup_policies {
    id     = "keep-newest-10"
    action = "KEEP"
    most_recent_versions {
      keep_count = 10
    }
  }
  cleanup_policies {
    id     = "delete-older-than-30-days"
    action = "DELETE"
    condition {
      tag_state  = "ANY"
      older_than = "2592000s"
    }
  }
}

# The account `make images` builds as (cloudbuild.yaml). Cloud Build's default account has no role
# here, so a builder of its own that can read the staged source, push to this repository and write
# its logs, and nothing more.
resource "google_artifact_registry_repository_iam_member" "builder_push" {
  repository = google_artifact_registry_repository.images.name
  location   = google_artifact_registry_repository.images.location
  role       = "roles/artifactregistry.writer"
  member     = google_service_account.role["builder"].member
}

resource "google_storage_bucket_iam_member" "builder_source" {
  bucket = google_storage_bucket.cloudbuild.name
  role   = "roles/storage.objectViewer"
  member = google_service_account.role["builder"].member
}

resource "google_project_iam_member" "builder_logs" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = google_service_account.role["builder"].member
}
