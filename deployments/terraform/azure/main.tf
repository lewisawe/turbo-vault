# Terraform configuration for Azure deployment of Vault Agent

terraform {
  required_version = ">= 1.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
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

# Configure the Microsoft Azure Provider
provider "azurerm" {
  features {}
}

# Variables
variable "location" {
  description = "Azure region"
  type        = string
  default     = "East US"
}

variable "resource_group_name" {
  description = "Resource group name"
  type        = string
  default     = "vault-agent-rg"
}

variable "cluster_name" {
  description = "AKS cluster name"
  type        = string
  default     = "vault-agent-cluster"
}

variable "node_count" {
  description = "Number of worker nodes"
  type        = number
  default     = 3
}

variable "node_vm_size" {
  description = "VM size for worker nodes"
  type        = string
  default     = "Standard_D2s_v3"
}

# Resource Group
resource "azurerm_resource_group" "vault_agent" {
  name     = var.resource_group_name
  location = var.location

  tags = {
    Environment = "production"
    Project     = "vault-agent"
  }
}

# Virtual Network
resource "azurerm_virtual_network" "vault_agent" {
  name                = "${var.cluster_name}-vnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.vault_agent.location
  resource_group_name = azurerm_resource_group.vault_agent.name

  tags = {
    Environment = "production"
    Project     = "vault-agent"
  }
}

# Subnet for AKS
resource "azurerm_subnet" "aks" {
  name                 = "${var.cluster_name}-aks-subnet"
  resource_group_name  = azurerm_resource_group.vault_agent.name
  virtual_network_name = azurerm_virtual_network.vault_agent.name
  address_prefixes     = ["10.0.1.0/24"]
}

# Subnet for PostgreSQL
resource "azurerm_subnet" "postgresql" {
  name                 = "${var.cluster_name}-postgresql-subnet"
  resource_group_name  = azurerm_resource_group.vault_agent.name
  virtual_network_name = azurerm_virtual_network.vault_agent.name
  address_prefixes     = ["10.0.2.0/24"]
  
  delegation {
    name = "postgresql-delegation"
    service_delegation {
      name = "Microsoft.DBforPostgreSQL/flexibleServers"
      actions = [
        "Microsoft.Network/virtualNetworks/subnets/join/action",
      ]
    }
  }
}

# Network Security Group for PostgreSQL
resource "azurerm_network_security_group" "postgresql" {
  name                = "${var.cluster_name}-postgresql-nsg"
  location            = azurerm_resource_group.vault_agent.location
  resource_group_name = azurerm_resource_group.vault_agent.name

  security_rule {
    name                       = "PostgreSQL"
    priority                   = 1001
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "5432"
    source_address_prefix      = "10.0.0.0/16"
    destination_address_prefix = "*"
  }

  tags = {
    Environment = "production"
    Project     = "vault-agent"
  }
}

resource "azurerm_subnet_network_security_group_association" "postgresql" {
  subnet_id                 = azurerm_subnet.postgresql.id
  network_security_group_id = azurerm_network_security_group.postgresql.id
}

# AKS Cluster
resource "azurerm_kubernetes_cluster" "vault_agent" {
  name                = var.cluster_name
  location            = azurerm_resource_group.vault_agent.location
  resource_group_name = azurerm_resource_group.vault_agent.name
  dns_prefix          = "${var.cluster_name}-dns"

  default_node_pool {
    name           = "default"
    node_count     = var.node_count
    vm_size        = var.node_vm_size
    vnet_subnet_id = azurerm_subnet.aks.id
    
    node_taints = ["vault-agent.io/dedicated=true:NoSchedule"]
    
    node_labels = {
      "vault-agent.io/dedicated" = "true"
    }
  }

  identity {
    type = "SystemAssigned"
  }

  network_profile {
    network_plugin = "azure"
    service_cidr   = "10.1.0.0/16"
    dns_service_ip = "10.1.0.10"
  }

  tags = {
    Environment = "production"
    Project     = "vault-agent"
  }
}

# PostgreSQL Flexible Server
resource "azurerm_postgresql_flexible_server" "vault_agent" {
  name                   = "${var.cluster_name}-postgresql"
  resource_group_name    = azurerm_resource_group.vault_agent.name
  location               = azurerm_resource_group.vault_agent.location
  version                = "15"
  delegated_subnet_id    = azurerm_subnet.postgresql.id
  administrator_login    = "vault_agent"
  administrator_password = random_password.postgresql_password.result
  zone                   = "1"

  storage_mb = 32768

  sku_name = "GP_Standard_D2s_v3"

  backup_retention_days        = 7
  geo_redundant_backup_enabled = false

  tags = {
    Environment = "production"
    Project     = "vault-agent"
  }
}

resource "azurerm_postgresql_flexible_server_database" "vault_agent" {
  name      = "vault_agent"
  server_id = azurerm_postgresql_flexible_server.vault_agent.id
  collation = "en_US.utf8"
  charset   = "utf8"
}

resource "random_password" "postgresql_password" {
  length  = 32
  special = true
}

# Redis Cache
resource "azurerm_redis_cache" "vault_agent" {
  name                = "${var.cluster_name}-redis"
  location            = azurerm_resource_group.vault_agent.location
  resource_group_name = azurerm_resource_group.vault_agent.name
  capacity            = 2
  family              = "C"
  sku_name            = "Standard"
  enable_non_ssl_port = false
  minimum_tls_version = "1.2"

  redis_configuration {
    enable_authentication = true
  }

  tags = {
    Environment = "production"
    Project     = "vault-agent"
  }
}

# Storage Account for backups
resource "azurerm_storage_account" "vault_agent_backups" {
  name                     = "${replace(var.cluster_name, "-", "")}backups${random_id.storage_suffix.hex}"
  resource_group_name      = azurerm_resource_group.vault_agent.name
  location                 = azurerm_resource_group.vault_agent.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  
  blob_properties {
    versioning_enabled = true
    
    delete_retention_policy {
      days = 30
    }
  }

  tags = {
    Environment = "production"
    Project     = "vault-agent"
  }
}

resource "random_id" "storage_suffix" {
  byte_length = 4
}

resource "azurerm_storage_container" "vault_agent_backups" {
  name                  = "backups"
  storage_account_name  = azurerm_storage_account.vault_agent_backups.name
  container_access_type = "private"
}

# Key Vault for secrets
resource "azurerm_key_vault" "vault_agent" {
  name                = "${var.cluster_name}-kv-${random_id.keyvault_suffix.hex}"
  location            = azurerm_resource_group.vault_agent.location
  resource_group_name = azurerm_resource_group.vault_agent.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id

    secret_permissions = [
      "Get",
      "List",
      "Set",
      "Delete",
      "Recover",
      "Backup",
      "Restore"
    ]
  }

  # Access policy for AKS cluster
  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = azurerm_kubernetes_cluster.vault_agent.identity[0].principal_id

    secret_permissions = [
      "Get",
      "List",
      "Set",
      "Delete"
    ]
  }

  tags = {
    Environment = "production"
    Project     = "vault-agent"
  }
}

resource "random_id" "keyvault_suffix" {
  byte_length = 4
}

# Data sources
data "azurerm_client_config" "current" {}

# Outputs
output "cluster_name" {
  description = "AKS Cluster Name"
  value       = azurerm_kubernetes_cluster.vault_agent.name
}

output "cluster_endpoint" {
  description = "Endpoint for AKS control plane"
  value       = azurerm_kubernetes_cluster.vault_agent.kube_config.0.host
}

output "cluster_ca_certificate" {
  description = "Base64 encoded certificate data required to communicate with the cluster"
  value       = azurerm_kubernetes_cluster.vault_agent.kube_config.0.cluster_ca_certificate
  sensitive   = true
}

output "postgresql_fqdn" {
  description = "PostgreSQL server FQDN"
  value       = azurerm_postgresql_flexible_server.vault_agent.fqdn
  sensitive   = true
}

output "postgresql_password" {
  description = "PostgreSQL server password"
  value       = random_password.postgresql_password.result
  sensitive   = true
}

output "redis_hostname" {
  description = "Redis cache hostname"
  value       = azurerm_redis_cache.vault_agent.hostname
  sensitive   = true
}

output "redis_primary_access_key" {
  description = "Redis cache primary access key"
  value       = azurerm_redis_cache.vault_agent.primary_access_key
  sensitive   = true
}

output "storage_account_name" {
  description = "Storage account name for backups"
  value       = azurerm_storage_account.vault_agent_backups.name
}

output "key_vault_uri" {
  description = "Key Vault URI"
  value       = azurerm_key_vault.vault_agent.vault_uri
}