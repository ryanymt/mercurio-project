# The VPC and its one subnet. Custom mode and no firewall rule: a custom-mode VPC has no implied
# allow, so all ingress is denied. Cloud SQL's private IP is on it (sql.tf); the callback API, the
# dispatcher and migrations reach it through Direct VPC egress, and the echo runner cannot.

resource "google_compute_network" "foreman" {
  name                    = "foreman-vpc"
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
}

resource "google_compute_subnetwork" "main" {
  name                     = "foreman-${var.region}"
  region                   = var.region
  network                  = google_compute_network.foreman.id
  ip_cidr_range            = "10.10.0.0/24"
  private_ip_google_access = true # reach Google APIs without a public path
}
