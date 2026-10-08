# Secrets. The database URLs, their versions written by Terraform through the write-only field, so
# neither password nor URL is in the state. The GitHub App's key and id, whose versions the operator
# adds. The dev runner's token for the sandbox, whose versions the launcher adds, one per launch,
# destroying the older ones; the runner is given only the version number. The viewer's: its
# database URL; its CSRF key, written by Terraform like the URLs; and the read-only App's key and
# id, whose versions the operator adds.

locals {
  secrets = {
    "database-url-migrator"    = "The migrator's DATABASE_URL (the migrate job)"
    "database-url-app"         = "The app user's DATABASE_URL (the callback API and the dispatcher)"
    "github-app-key"           = "The GitHub App's private key (PEM), added by the operator"
    "github-app-id"            = "The GitHub App's id, added by the operator"
    "github-token-dev-sandbox" = "The sandbox dev runner's GitHub token, a version per launch"
    "database-url-viewer"      = "The viewer user's DATABASE_URL (the viewer), SELECT only"
    "viewer-csrf-key"          = "The viewer's CSRF key, the same in every instance"
    "viewer-github-app-key"    = "The read-only GitHub App's private key (PEM), added by the operator"
    "viewer-github-app-id"     = "The read-only GitHub App's id, added by the operator"
  }
  database_host = google_sql_database_instance.foreman.private_ip_address
}

resource "google_secret_manager_secret" "secret" {
  for_each  = local.secrets
  secret_id = each.key
  labels    = { component = "foreman" }
  annotations = {
    purpose = each.value
  }

  replication {
    user_managed {
      replicas {
        location = var.region
      }
    }
  }
}

resource "google_secret_manager_secret_version" "database_url_migrator" {
  secret                 = google_secret_manager_secret.secret["database-url-migrator"].id
  secret_data_wo         = "postgres://migrator:${ephemeral.random_password.migrator.result}@${local.database_host}:5432/foreman?sslmode=require"
  secret_data_wo_version = "1"
  depends_on             = [google_sql_user.migrator]
}

resource "google_secret_manager_secret_version" "database_url_app" {
  secret                 = google_secret_manager_secret.secret["database-url-app"].id
  secret_data_wo         = "postgres://app:${ephemeral.random_password.app.result}@${local.database_host}:5432/foreman?sslmode=require"
  secret_data_wo_version = "1"
  depends_on             = [google_sql_user.app]
}

resource "google_secret_manager_secret_version" "database_url_viewer" {
  secret                 = google_secret_manager_secret.secret["database-url-viewer"].id
  secret_data_wo         = "postgres://viewer:${ephemeral.random_password.viewer.result}@${local.database_host}:5432/foreman?sslmode=require"
  secret_data_wo_version = "1"
  depends_on             = [google_sql_user.viewer]
}

# The CSRF key signs every form's token. Generated for the run and written only to the write-only
# field, so it is never in the state; every viewer instance reads the same version.
ephemeral "random_password" "csrf_key" {
  length  = 64
  special = false
}

resource "google_secret_manager_secret_version" "viewer_csrf_key" {
  secret                 = google_secret_manager_secret.secret["viewer-csrf-key"].id
  secret_data_wo         = ephemeral.random_password.csrf_key.result
  secret_data_wo_version = "1"
}
