# Buckets: the artifacts bucket and Cloud Build's staging bucket. The Terraform state bucket is not
# here: it must exist before `terraform init`.

# Session transcripts, diffs, test reports and logs, under {project}/{ticket}/{attempt}/.
# Transcripts can hold whatever an agent read, so the bucket is private by construction.
resource "google_storage_bucket" "artifacts" {
  name                        = "${var.project_id}-artifacts"
  location                    = upper(var.region)
  storage_class               = "STANDARD"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
}

# Cloud Build's staging bucket, the one `gcloud builds submit` uses when it exists, made here so the
# builder can read it from the first build. It holds the archives `make images` sends, each read
# once by its build, so they are deleted after 30 days.
resource "google_storage_bucket" "cloudbuild" {
  name                        = "${var.project_id}_cloudbuild"
  location                    = "US"
  storage_class               = "STANDARD"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  lifecycle_rule {
    condition {
      age = 30
    }
    action {
      type = "Delete"
    }
  }
}
