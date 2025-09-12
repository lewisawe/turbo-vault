# Terraform configuration for GCP deployment of Vault Agent

terraform {
  required_version = ">= 1.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.0"
    }
  }
}

# Variables
variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "GCP region"
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "GCP zone"
  type        = string
  default     = "us-central1-a"
}

variable "cluster_name" {
  description = "GKE cluster name"
  type        = string
  default     = "vault-agent-cluster"
}

variable "node_count" {
  description = "Number of worker nodes per zone"
  type        = number
  default     = 1
}

variable "node_machine_type" {
  description = "Machine type for worker nodes"
  type        = string
  default     = "e2-standard-2"
}

# Configure the Google Cloud Provider
provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

# Enable required APIs
resource "google_project_service" "required_apis" {
  for_each = toset([
    "container.googleapis.com",
    "compute.googleapis.com",
    "sqladmin.googleapis.com",
    "redis.googleapis.com",
    "secretmanager.googleapis.com",
    "storage.googleapis.com"
  ])

  project = var.project_id
  service = each.value

  disable_dependent_services = true
}

# VPC Network
resource "google_compute_network" "vault_agent" {
  name                    = "${var.cluster_name}-vpc"
  auto_create_subnetworks = false
  
  depends_on = [google_project_service.required_apis]
}

# Subnet for GKE
resource "google_compute_subnetwork" "gke" {
  name          = "${var.cluster_name}-gke-subnet"
  ip_cidr_range = "10.0.0.0/24"
  region        = var.region
  network       = google_compute_network.vault_agent.id

  secondary_ip_range {
    range_name    = "gke-pods"
    ip_cidr_range = "10.1.0.0/16"
  }

  secondary_ip_range {
    range_name    = "gke-services"
    ip_cidr_range = "10.2.0.0/16"
  }
}

# Firewall rules
resource "google_compute_firewall" "vault_agent_internal" {
  name    = "${var.cluster_name}-internal"
  network = google_compute_network.vault_agent.name

  allow {
    protocol = "tcp"
    ports    = ["0-65535"]
  }

  allow {
    protocol = "udp"
    ports    = ["0-65535"]
  }

  allow {
    protocol = "icmp"
  }

  source_ranges = ["10.0.0.0/8"]
}

# GKE Cluster
resource "google_container_cluster" "vault_agent" {
  name     = var.cluster_name
  location = var.region

  # We can't create a cluster with no node pool defined, but we want to only use
  # separately managed node pools. So we create the smallest possible default
  # node pool and immediately delete it.
  remove_default_node_pool = true
  initial_node_count       = 1

  network    = google_compute_network.vault_agent.name
  subnetwork = google_compute_subnetwork.gke.name

  ip_allocation_policy {
    cluster_secondary_range_name  = "gke-pods"
    services_secondary_range_name = "gke-services"
  }

  # Enable network policy
  network_policy {
    enabled = true
  }

  # Enable Workload Identity
  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  # Enable shielded nodes
  enable_shielded_nodes = true

  # Master auth configuration
  master_auth {
    client_certificate_config {
      issue_client_certificate = false
    }
  }

  depends_on = [google_project_service.required_apis]
}

# GKE Node Pool
resource "google_container_node_pool" "vault_agent_nodes" {
  name       = "${var.cluster_name}-nodes"
  location   = var.region
  cluster    = google_container_cluster.vault_agent.name
  node_count = var.node_count

  node_config {
    preemptible  = false
    machine_type = var.node_machine_type

    # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
    service_account = google_service_account.gke_nodes.email
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]

    labels = {
      environment = "production"
      project     = "vault-agent"
    }

    taint {
      key    = "vault-agent.io/dedicated"
      value  = "true"
      effect = "NO_SCHEDULE"
    }

    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }

    workload_metadata_config {
      mode = "GKE_METADATA"
    }
  }

  management {
    auto_repair  = true
    auto_upgrade = true
  }

  upgrade_settings {
    max_surge       = 1
    max_unavailable = 0
  }
}

# Service Account for GKE nodes
resource "google_service_account" "gke_nodes" {
  account_id   = "${var.cluster_name}-gke-nodes"
  display_name = "GKE Node Service Account for ${var.cluster_name}"
}

resource "google_project_iam_member" "gke_nodes" {
  for_each = toset([
    "roles/logging.logWriter",
    "roles/monitoring.metricWriter",
    "roles/monitoring.viewer",
    "roles/stackdriver.resourceMetadata.writer"
  ])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.gke_nodes.email}"
}

# Service Account for Vault Agent
resource "google_service_account" "vault_agent" {
  account_id   = "${var.cluster_name}-vault-agent"
  display_name = "Vault Agent Service Account"
}

resource "google_project_iam_member" "vault_agent" {
  for_each = toset([
    "roles/secretmanager.admin",
    "roles/storage.objectAdmin",
    "roles/cloudsql.client"
  ])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.vault_agent.email}"
}

# Workload Identity binding
resource "google_service_account_iam_member" "vault_agent_workload_identity" {
  service_account_id = google_service_account.vault_agent.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[vault-agent/vault-agent]"
}

# Cloud SQL PostgreSQL instance
resource "google_sql_database_instance" "vault_agent" {
  name             = "${var.cluster_name}-postgresql"
  database_version = "POSTGRES_15"
  region           = var.region

  settings {
    tier = "db-custom-2-4096"

    backup_configuration {
      enabled                        = true
      start_time                     = "03:00"
      point_in_time_recovery_enabled = true
      backup_retention_settings {
        retained_backups = 7
      }
    }

    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.vault_agent.id
      require_ssl     = true
    }

    database_flags {
      name  = "log_checkpoints"
      value = "on"
    }

    database_flags {
      name  = "log_connections"
      value = "on"
    }

    database_flags {
      name  = "log_disconnections"
      value = "on"
    }

    maintenance_window {
      day          = 7
      hour         = 4
      update_track = "stable"
    }
  }

  deletion_protection = true

  depends_on = [google_service_networking_connection.private_vpc_connection]
}

resource "google_sql_database" "vault_agent" {
  name     = "vault_agent"
  instance = google_sql_database_instance.vault_agent.name
}

resource "google_sql_user" "vault_agent" {
  name     = "vault_agent"
  instance = google_sql_database_instance.vault_agent.name
  password = random_password.postgresql_password.result
}

resource "random_password" "postgresql_password" {
  length  = 32
  special = true
}

# Private service networking for Cloud SQL
resource "google_compute_global_address" "private_ip_address" {
  name          = "${var.cluster_name}-private-ip"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.vault_agent.id
}

resource "google_service_networking_connection" "private_vpc_connection" {
  network                 = google_compute_network.vault_agent.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_ip_address.name]
}

# Redis instance
resource "google_redis_instance" "vault_agent" {
  name           = "${var.cluster_name}-redis"
  tier           = "STANDARD_HA"
  memory_size_gb = 4
  region         = var.region

  authorized_network = google_compute_network.vault_agent.id

  redis_version     = "REDIS_7_0"
  display_name      = "Vault Agent Redis"
  reserved_ip_range = "10.3.0.0/29"

  auth_enabled = true

  depends_on = [google_project_service.required_apis]
}

# Cloud Storage bucket for backups
resource "google_storage_bucket" "vault_agent_backups" {
  name     = "${var.project_id}-${var.cluster_name}-backups"
  location = var.region

  uniform_bucket_level_access = true

  versioning {
    enabled = true
  }

  lifecycle_rule {
    condition {
      age = 90
    }
    action {
      type = "Delete"
    }
  }

  lifecycle_rule {
    condition {
      num_newer_versions = 5
    }
    action {
      type = "Delete"
    }
  }
}

resource "google_storage_bucket_iam_member" "vault_agent_backups" {
  bucket = google_storage_bucket.vault_agent_backups.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.vault_agent.email}"
}

# Outputs
output "cluster_name" {
  description = "GKE Cluster Name"
  value       = google_container_cluster.vault_agent.name
}

output "cluster_endpoint" {
  description = "Endpoint for GKE control plane"
  value       = google_container_cluster.vault_agent.endpoint
  sensitive   = true
}

output "cluster_ca_certificate" {
  description = "Base64 encoded certificate data required to communicate with the cluster"
  value       = google_container_cluster.vault_agent.master_auth.0.cluster_ca_certificate
  sensitive   = true
}

output "postgresql_connection_name" {
  description = "PostgreSQL instance connection name"
  value       = google_sql_database_instance.vault_agent.connection_name
  sensitive   = true
}

output "postgresql_private_ip" {
  description = "PostgreSQL instance private IP"
  value       = google_sql_database_instance.vault_agent.private_ip_address
  sensitive   = true
}

output "postgresql_password" {
  description = "PostgreSQL password"
  value       = random_password.postgresql_password.result
  sensitive   = true
}

output "redis_host" {
  description = "Redis instance host"
  value       = google_redis_instance.vault_agent.host
  sensitive   = true
}

output "redis_auth_string" {
  description = "Redis AUTH string"
  value       = google_redis_instance.vault_agent.auth_string
  sensitive   = true
}

output "backup_bucket" {
  description = "Cloud Storage bucket for backups"
  value       = google_storage_bucket.vault_agent_backups.name
}

output "vault_agent_service_account_email" {
  description = "Vault Agent service account email"
  value       = google_service_account.vault_agent.email
}