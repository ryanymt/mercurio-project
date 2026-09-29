# The deployment's values. Set them in terraform.tfvars (from terraform.tfvars.example); `make
# images` writes the two images to images.auto.tfvars.

variable "project_id" {
  description = "The Google Cloud project to deploy into."
  type        = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must be a Google Cloud project id."
  }
}

variable "project_number" {
  description = "The project's number (gcloud projects describe <project_id> --format='value(projectNumber)'). The callback API's URL is built from it."
  type        = string
  validation {
    condition     = can(regex("^[0-9]+$", var.project_number))
    error_message = "project_number must be the project's number, digits only."
  }
}

variable "region" {
  description = "The region of every regional resource."
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "Cloud SQL's zone. Default: the region's zone a."
  type        = string
  default     = null
}

variable "billing_account" {
  description = "Optional: the billing account (XXXXXX-XXXXXX-XXXXXX) to put a monthly budget on. No budget unless monthly_budget_usd is set too."
  type        = string
  default     = null
}

variable "monthly_budget_usd" {
  description = "Optional: the monthly budget in US dollars, alerting at 50%, 90% and 100% of current spend. No budget unless billing_account is set too."
  type        = number
  default     = null
}

# The images, deployed by digest from this project's `foreman` repository. Unset only for the first
# apply on a new project, which targets what `make images` needs (see the README); every other
# apply needs them.
variable "foreman_image" {
  description = "The control plane's image, by digest."
  type        = string
  default     = null
  validation {
    condition     = var.foreman_image == null || can(regex("^${var.region}-docker\\.pkg\\.dev/${var.project_id}/foreman/foreman@sha256:[0-9a-f]{64}$", var.foreman_image))
    error_message = "foreman_image must be the foreman image in this project's foreman repository, by digest."
  }
}

variable "echo_runner_image" {
  description = "The echo runner's image, by digest."
  type        = string
  default     = null
  validation {
    condition     = var.echo_runner_image == null || can(regex("^${var.region}-docker\\.pkg\\.dev/${var.project_id}/foreman/echo-runner@sha256:[0-9a-f]{64}$", var.echo_runner_image))
    error_message = "echo_runner_image must be the echo-runner image in this project's foreman repository, by digest."
  }
}
