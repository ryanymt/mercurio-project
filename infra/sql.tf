# Cloud SQL: Postgres 17 on a private IP only, reached through Private Services Access on
# foreman-vpc, with two users whose passwords never reach Terraform's state. `make pause` stops the
# instance; Terraform ignores its activation policy, so pausing never drifts.

resource "google_compute_global_address" "private_services" {
  name          = "foreman-private-services"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 20
  network       = google_compute_network.foreman.id
}

resource "google_service_networking_connection" "private_services" {
  network                 = google_compute_network.foreman.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_services.name]
}

resource "google_sql_database_instance" "foreman" {
  name                = "foreman"
  database_version    = "POSTGRES_17"
  region              = var.region
  deletion_protection = true # set false (and apply) before destroying the instance

  settings {
    # Postgres 16 and later default to Enterprise Plus, which has no shared-core tier.
    edition                     = "ENTERPRISE"
    tier                        = "db-f1-micro"
    availability_type           = "ZONAL"
    activation_policy           = "ALWAYS"
    deletion_protection_enabled = true

    location_preference {
      zone = local.zone
    }

    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.foreman.id
      ssl_mode        = "ENCRYPTED_ONLY"
    }

    backup_configuration {
      enabled = false # the echo runner's tickets only; enable backups before real work lands here
    }
  }

  lifecycle {
    ignore_changes = [settings[0].activation_policy] # `make pause` and `make resume` own it
  }

  depends_on = [google_service_networking_connection.private_services]
}

resource "google_sql_database" "foreman" {
  name     = "foreman"
  instance = google_sql_database_instance.foreman.name
}

# The passwords are generated for each run and written only to write-only fields: the user's
# password and its URL's secret version, both sent once (their _wo_version) and never stored in
# the state. No special characters, so they sit in a URL as they are.
ephemeral "random_password" "migrator" {
  length  = 40
  special = false
}

ephemeral "random_password" "app" {
  length  = 40
  special = false
}

# Owns the schema: the migrate job runs as it. Cloud SQL makes it a cloudsqlsuperuser member.
resource "google_sql_user" "migrator" {
  name                = "migrator"
  instance            = google_sql_database_instance.foreman.name
  type                = "BUILT_IN"
  password_wo         = ephemeral.random_password.migrator.result
  password_wo_version = 1
}

# The deployed components' user: row rights only, granted by migration 00007. Its roles are an
# explicit list without cloudsqlsuperuser. The list must name a role: the provider drops an empty
# list when it creates the user, and Cloud SQL then makes it a cloudsqlsuperuser member.
# pg_read_all_stats reads statistics views and nothing else. The provider never reads the roles
# back, so `foreman db rights` is the check.
resource "google_sql_user" "app" {
  name                = "app"
  instance            = google_sql_database_instance.foreman.name
  type                = "BUILT_IN"
  password_wo         = ephemeral.random_password.app.result
  password_wo_version = 1
  database_roles      = ["pg_read_all_stats"]
}
