# Cloud Run: the callback API and the viewer as services, the dispatcher and migrations as jobs,
# all with Direct VPC egress to reach Cloud SQL, and the echo runner as a job without it. Images are
# deployed by digest (images.auto.tfvars, written by `make images`). The images' entrypoint is the
# binary, so each resource's args choose the command, and an execution's args override runs another
# (`foreman db rights`, `foreman project activate`).

locals {
  # The callback API's one audience: the service's deterministic URL, which runners call, ask their
  # ID tokens for, and the API verifies as FOREMAN_SERVICE_AUDIENCE.
  callback_url = "https://callback-api-${var.project_number}.${var.region}.run.app"
  # No FOREMAN_HUMAN_AUDIENCES: the API accepts no person's own token. A person acts only through
  # the viewer, which relays their IAP assertion; the API verifies it for this audience.
  viewer_iap_audience = "/projects/${var.project_number}/locations/${var.region}/services/viewer"
  # The viewer's own origins, for a browser that sends Origin and no Sec-Fetch-Site: its
  # deterministic URL, and any more you give (var.viewer_extra_origins).
  viewer_origins = concat(["https://viewer-${var.project_number}.${var.region}.run.app"], var.viewer_extra_origins)

  app_url_secret      = google_secret_manager_secret.secret["database-url-app"].secret_id
  migrator_url_secret = google_secret_manager_secret.secret["database-url-migrator"].secret_id

  # The launcher's jobs: one per runner role and project; here, dev for sandbox.
  runner_jobs = [{
    role         = "dev"
    project      = "sandbox"
    job          = "projects/${var.project_id}/locations/${var.region}/jobs/echo-runner-sandbox"
    account      = google_service_account.role["dev-sandbox"].email
    token_secret = google_secret_manager_secret.secret["github-token-dev-sandbox"].id
  }]
}

resource "google_cloud_run_v2_service" "callback_api" {
  name     = "callback-api"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL" # public; Cloud Run's invoker check, then the API's own

  template {
    service_account = google_service_account.role["callback-api"].email

    scaling {
      min_instance_count = 0 # nothing runs, and nothing is billed, while idle
      max_instance_count = 2
    }

    vpc_access {
      network_interfaces {
        network    = google_compute_network.foreman.id
        subnetwork = google_compute_subnetwork.main.id
      }
      egress = "PRIVATE_RANGES_ONLY"
    }

    containers {
      image = var.foreman_image
      args  = ["callback-api"]

      env {
        name  = "FOREMAN_SERVICE_AUDIENCE"
        value = local.callback_url
      }
      env {
        name  = "FOREMAN_IAP_AUDIENCE"
        value = local.viewer_iap_audience
      }
      env {
        name = "DATABASE_URL"
        value_source {
          secret_key_ref {
            secret  = local.app_url_secret
            version = "latest"
          }
        }
      }
    }
  }

  lifecycle {
    postcondition {
      condition     = contains(self.urls, local.callback_url)
      error_message = "The callback API's URLs do not include ${local.callback_url}, the audience its callers ask for."
    }
  }

  # It pings the database at start, so its user, its URL and its right to read it come first.
  depends_on = [
    google_sql_database.foreman,
    google_secret_manager_secret_version.database_url_app,
    google_secret_manager_secret_iam_member.accessor,
  ]
}

# The viewer: reached only through IAP, enabled on the service itself with no load balancer. IAP
# signs people in with its Google-managed OAuth client, admits only the identities given IAP access
# (iam.tf), and passes Cloud Run's invoker check with its service agent's token. It reads the
# database as `viewer` over Direct VPC egress, the bucket as its own account, and GitHub through the
# read-only App; it relays a person's acts to the callback API (cmd/foreman documents its
# environment). At startup it refuses to run if its database user could write, or cannot read what
# it shows, so migration 00008 must have run.
resource "google_cloud_run_v2_service" "viewer" {
  name        = "viewer"
  location    = var.region
  ingress     = "INGRESS_TRAFFIC_ALL" # behind IAP; the invoker check admits only IAP's service agent
  iap_enabled = true

  template {
    service_account = google_service_account.role["viewer"].email

    scaling {
      min_instance_count = 0 # nothing runs, and nothing is billed, while idle
      max_instance_count = 2
    }

    vpc_access {
      network_interfaces {
        network    = google_compute_network.foreman.id
        subnetwork = google_compute_subnetwork.main.id
      }
      egress = "PRIVATE_RANGES_ONLY"
    }

    containers {
      image = var.foreman_image
      args  = ["viewer"]

      env {
        name = "DATABASE_URL"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.secret["database-url-viewer"].secret_id
            version = "latest"
          }
        }
      }
      env {
        name  = "FOREMAN_IAP_AUDIENCE"
        value = local.viewer_iap_audience
      }
      env {
        name  = "FOREMAN_CALLBACK_URL"
        value = local.callback_url
      }
      env {
        name  = "FOREMAN_ORIGINS"
        value = join(",", local.viewer_origins)
      }
      env {
        name  = "FOREMAN_ARTIFACTS_BUCKET"
        value = google_storage_bucket.artifacts.name
      }
      env {
        name  = "FOREMAN_CSRF_KEY_SECRET"
        value = "${google_secret_manager_secret.secret["viewer-csrf-key"].id}/versions/latest"
      }
      env {
        name  = "FOREMAN_GITHUB_APP_ID_SECRET"
        value = "${google_secret_manager_secret.secret["viewer-github-app-id"].id}/versions/latest"
      }
      env {
        name  = "FOREMAN_GITHUB_APP_KEY_SECRET"
        value = "${google_secret_manager_secret.secret["viewer-github-app-key"].id}/versions/latest"
      }
    }
  }

  lifecycle {
    postcondition {
      condition     = alltrue([for o in local.viewer_origins : contains(self.urls, o)])
      error_message = "The viewer's URLs do not include all of ${join(" and ", local.viewer_origins)}, the origins it accepts a form from."
    }
  }

  # It checks its database rights and reads its CSRF key at start, so its user, its URL, the key and
  # its right to read them come first.
  depends_on = [
    google_secret_manager_secret_version.database_url_viewer,
    google_secret_manager_secret_version.viewer_csrf_key,
    google_secret_manager_secret_iam_member.accessor,
  ]
}

resource "google_cloud_run_v2_job" "dispatcher" {
  name     = "dispatcher"
  location = var.region

  template {
    template {
      service_account = google_service_account.role["dispatcher"].email
      max_retries     = 0      # a failed tick waits for the next one
      timeout         = "120s" # no longer than the two minutes between ticks

      vpc_access {
        network_interfaces {
          network    = google_compute_network.foreman.id
          subnetwork = google_compute_subnetwork.main.id
        }
        egress = "PRIVATE_RANGES_ONLY"
      }

      containers {
        image = var.foreman_image
        args  = ["dispatch"]

        env {
          name = "DATABASE_URL"
          value_source {
            secret_key_ref {
              secret  = local.app_url_secret
              version = "latest"
            }
          }
        }
        env {
          name  = "FOREMAN_LAUNCHER"
          value = "cloudrun"
        }
        env {
          name  = "FOREMAN_RUNNER_JOBS"
          value = jsonencode(local.runner_jobs)
        }
        env {
          name  = "FOREMAN_CALLBACK_URL"
          value = local.callback_url
        }
        env {
          name  = "FOREMAN_CALLBACK_AUDIENCE"
          value = local.callback_url
        }
        env {
          name  = "FOREMAN_GITHUB_APP_ID_SECRET"
          value = "${google_secret_manager_secret.secret["github-app-id"].id}/versions/latest"
        }
        env {
          name  = "FOREMAN_GITHUB_APP_KEY_SECRET"
          value = "${google_secret_manager_secret.secret["github-app-key"].id}/versions/latest"
        }
      }
    }
  }

  depends_on = [
    google_secret_manager_secret_version.database_url_app,
    google_secret_manager_secret_iam_member.accessor,
  ]
}

resource "google_cloud_run_v2_job" "migrate" {
  name     = "migrate"
  location = var.region

  template {
    template {
      service_account = google_service_account.role["migrate"].email
      max_retries     = 0
      timeout         = "300s"

      vpc_access {
        network_interfaces {
          network    = google_compute_network.foreman.id
          subnetwork = google_compute_subnetwork.main.id
        }
        egress = "PRIVATE_RANGES_ONLY"
      }

      containers {
        image = var.foreman_image
        args  = ["migrate", "up"]

        env {
          name = "DATABASE_URL"
          value_source {
            secret_key_ref {
              secret  = local.migrator_url_secret
              version = "latest"
            }
          }
        }
      }
    }
  }

  depends_on = [
    google_secret_manager_secret_version.database_url_migrator,
    google_secret_manager_secret_iam_member.accessor,
  ]
}

# The echo runner for the sandbox, as its dev runner account. No VPC egress: it talks only to
# public endpoints, so it cannot reach the database's private IP. It maps no secret: its token's
# version comes in the launcher's overrides, and it reads it itself.
resource "google_cloud_run_v2_job" "echo_runner_sandbox" {
  name     = "echo-runner-sandbox"
  location = var.region

  template {
    template {
      service_account = google_service_account.role["dev-sandbox"].email
      max_retries     = 0 # a refused runner is not run again
      timeout         = "600s"

      containers {
        image = var.echo_runner_image

        env {
          name  = "ECHO_HOLD_SECONDS"
          value = "90"
        }
        env {
          name  = "FOREMAN_ARTIFACTS_BUCKET"
          value = google_storage_bucket.artifacts.name
        }
      }
    }
  }
}
