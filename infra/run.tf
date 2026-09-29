# Cloud Run: the callback API as a service, the dispatcher and migrations as jobs with Direct VPC
# egress to reach Cloud SQL, and the echo runner as a job without it. Images are deployed by digest
# (images.auto.tfvars, written by `make images`). The images' entrypoint is the binary, so each
# resource's args choose the command, and an execution's args override runs another (`foreman db
# rights`, `foreman project activate`, `foreman ticket create`).

locals {
  # The callback API's one audience: the service's deterministic URL, which runners call, ask their
  # ID tokens for, and the API verifies as FOREMAN_SERVICE_AUDIENCE.
  callback_url = "https://callback-api-${var.project_number}.${var.region}.run.app"
  # No FOREMAN_HUMAN_AUDIENCES: the deployed API accepts no person's token. Cloud Run strips the
  # signature of a person's gcloud ID token it checks, so it could never verify; operators make
  # tickets with `foreman ticket create`, as an execution of the dispatcher job (see the README).

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

resource "google_cloud_run_v2_job" "dispatcher" {
  name     = "dispatcher"
  location = var.region

  template {
    template {
      service_account = google_service_account.role["dispatcher"].email
      max_retries     = 0      # a failed tick waits for the next minute's
      timeout         = "120s" # well inside the minute between ticks

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
      }
    }
  }
}
