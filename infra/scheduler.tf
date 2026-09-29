# The dispatcher's tick: Cloud Scheduler runs the dispatcher job every minute as its own account.
# Created paused; `make resume` and `make pause` own its state, which Terraform ignores.

resource "google_cloud_scheduler_job" "dispatcher_tick" {
  name             = "dispatcher-tick"
  region           = var.region
  description      = "Runs the dispatcher job once a minute"
  schedule         = "* * * * *"
  time_zone        = "Etc/UTC"
  paused           = true
  attempt_deadline = "30s"
  # No retry_config: Cloud Scheduler's default is no retries (the next minute's tick is the retry),
  # and it does not return an explicit retry_count of 0, so writing one is a diff on every plan.

  http_target {
    http_method = "POST"
    uri         = "https://run.googleapis.com/v2/${google_cloud_run_v2_job.dispatcher.id}:run"

    oauth_token {
      service_account_email = google_service_account.role["scheduler"].email
      scope                 = "https://www.googleapis.com/auth/cloud-platform"
    }
  }

  lifecycle {
    ignore_changes = [paused]
  }

  depends_on = [google_cloud_run_v2_job_iam_member.scheduler_runs_dispatcher]
}
