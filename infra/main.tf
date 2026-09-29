# Mercurio's runtime on Google Cloud, in one root module: Cloud SQL on a private IP, the callback
# API as a Cloud Run service, the dispatcher, migrations and the echo runner as Cloud Run jobs,
# Cloud Scheduler, Secret Manager, and IAM granted per resource, each account only what it needs.
# Every deployment-specific value is a variable (variables.tf; copy terraform.tfvars.example to
# terraform.tfvars). The README's quick start gives the order for a new project.
#
# The state lives in a GCS bucket that must exist before init, named at init:
#   terraform init -backend-config="bucket=<your-state-bucket>"
#   terraform plan -out=plan.tfplan && terraform apply plan.tfplan
#
# With user credentials, billing_project and user_project_override send every API call's quota to
# the deployment's project; the budgets API needs that.

terraform {
  required_version = "~> 1.14.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "= 8.4.0"
    }
    # Database passwords, generated ephemerally and written only to write-only fields.
    random = {
      source  = "hashicorp/random"
      version = "= 3.9.1"
    }
  }

  # Partial configuration: the bucket is given at init.
  backend "gcs" {
    prefix = "runtime"
  }
}

provider "google" {
  project               = var.project_id
  region                = var.region
  zone                  = local.zone
  billing_project       = var.project_id
  user_project_override = true
}

locals {
  zone = coalesce(var.zone, "${var.region}-a")
}
