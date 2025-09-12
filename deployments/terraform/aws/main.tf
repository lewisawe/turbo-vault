# Terraform configuration for AWS deployment of Vault Agent

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
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
variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-west-2"
}

variable "cluster_name" {
  description = "EKS cluster name"
  type        = string
  default     = "vault-agent-cluster"
}

variable "node_instance_type" {
  description = "EC2 instance type for worker nodes"
  type        = string
  default     = "t3.medium"
}

variable "min_size" {
  description = "Minimum number of worker nodes"
  type        = number
  default     = 3
}

variable "max_size" {
  description = "Maximum number of worker nodes"
  type        = number
  default     = 10
}

variable "desired_size" {
  description = "Desired number of worker nodes"
  type        = number
  default     = 3
}

# Data sources
data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

# VPC Configuration
module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = "${var.cluster_name}-vpc"
  cidr = "10.0.0.0/16"

  azs             = slice(data.aws_availability_zones.available.names, 0, 3)
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]

  enable_nat_gateway = true
  enable_vpn_gateway = false
  enable_dns_hostnames = true
  enable_dns_support = true

  tags = {
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
    Environment = "production"
    Project     = "vault-agent"
  }

  public_subnet_tags = {
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
    "kubernetes.io/role/elb" = "1"
  }

  private_subnet_tags = {
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
    "kubernetes.io/role/internal-elb" = "1"
  }
}

# EKS Cluster
module "eks" {
  source = "terraform-aws-modules/eks/aws"
  version = "~> 19.0"

  cluster_name    = var.cluster_name
  cluster_version = "1.28"

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  cluster_endpoint_public_access = true
  cluster_endpoint_private_access = true

  cluster_addons = {
    coredns = {
      most_recent = true
    }
    kube-proxy = {
      most_recent = true
    }
    vpc-cni = {
      most_recent = true
    }
    aws-ebs-csi-driver = {
      most_recent = true
    }
  }

  eks_managed_node_groups = {
    vault_agent_nodes = {
      name = "vault-agent-nodes"
      
      instance_types = [var.node_instance_type]
      
      min_size     = var.min_size
      max_size     = var.max_size
      desired_size = var.desired_size

      disk_size = 50
      disk_type = "gp3"

      labels = {
        Environment = "production"
        Project     = "vault-agent"
      }

      taints = {
        vault-agent = {
          key    = "vault-agent.io/dedicated"
          value  = "true"
          effect = "NO_SCHEDULE"
        }
      }

      tags = {
        Environment = "production"
        Project     = "vault-agent"
      }
    }
  }

  tags = {
    Environment = "production"
    Project     = "vault-agent"
  }
}

# RDS PostgreSQL Database
resource "aws_db_subnet_group" "vault_agent" {
  name       = "${var.cluster_name}-db-subnet-group"
  subnet_ids = module.vpc.private_subnets

  tags = {
    Name        = "${var.cluster_name} DB subnet group"
    Environment = "production"
    Project     = "vault-agent"
  }
}

resource "aws_security_group" "rds" {
  name_prefix = "${var.cluster_name}-rds-"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [module.vpc.vpc_cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.cluster_name}-rds-sg"
    Environment = "production"
    Project     = "vault-agent"
  }
}

resource "aws_db_instance" "vault_agent" {
  identifier = "${var.cluster_name}-db"

  engine         = "postgres"
  engine_version = "15.4"
  instance_class = "db.t3.medium"

  allocated_storage     = 100
  max_allocated_storage = 1000
  storage_type          = "gp3"
  storage_encrypted     = true

  db_name  = "vault_agent"
  username = "vault_agent"
  password = random_password.db_password.result

  vpc_security_group_ids = [aws_security_group.rds.id]
  db_subnet_group_name   = aws_db_subnet_group.vault_agent.name

  backup_retention_period = 7
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"

  skip_final_snapshot = false
  final_snapshot_identifier = "${var.cluster_name}-db-final-snapshot"

  tags = {
    Name        = "${var.cluster_name}-db"
    Environment = "production"
    Project     = "vault-agent"
  }
}

resource "random_password" "db_password" {
  length  = 32
  special = true
}

# ElastiCache Redis
resource "aws_elasticache_subnet_group" "vault_agent" {
  name       = "${var.cluster_name}-cache-subnet"
  subnet_ids = module.vpc.private_subnets
}

resource "aws_security_group" "redis" {
  name_prefix = "${var.cluster_name}-redis-"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = [module.vpc.vpc_cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.cluster_name}-redis-sg"
    Environment = "production"
    Project     = "vault-agent"
  }
}

resource "aws_elasticache_replication_group" "vault_agent" {
  replication_group_id       = "${var.cluster_name}-redis"
  description                = "Redis cluster for Vault Agent"

  node_type            = "cache.t3.medium"
  port                 = 6379
  parameter_group_name = "default.redis7"

  num_cache_clusters = 3
  
  subnet_group_name  = aws_elasticache_subnet_group.vault_agent.name
  security_group_ids = [aws_security_group.redis.id]

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token                 = random_password.redis_password.result

  tags = {
    Name        = "${var.cluster_name}-redis"
    Environment = "production"
    Project     = "vault-agent"
  }
}

resource "random_password" "redis_password" {
  length  = 32
  special = false
}

# S3 Bucket for backups
resource "aws_s3_bucket" "vault_agent_backups" {
  bucket = "${var.cluster_name}-backups-${random_id.bucket_suffix.hex}"

  tags = {
    Name        = "${var.cluster_name}-backups"
    Environment = "production"
    Project     = "vault-agent"
  }
}

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket_versioning" "vault_agent_backups" {
  bucket = aws_s3_bucket.vault_agent_backups.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_encryption" "vault_agent_backups" {
  bucket = aws_s3_bucket.vault_agent_backups.id

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "vault_agent_backups" {
  bucket = aws_s3_bucket.vault_agent_backups.id

  rule {
    id     = "backup_lifecycle"
    status = "Enabled"

    expiration {
      days = 90
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

# IAM Role for Vault Agent
resource "aws_iam_role" "vault_agent" {
  name = "${var.cluster_name}-vault-agent-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRoleWithWebIdentity"
        Effect = "Allow"
        Principal = {
          Federated = module.eks.oidc_provider_arn
        }
        Condition = {
          StringEquals = {
            "${replace(module.eks.cluster_oidc_issuer_url, "https://", "")}:sub" = "system:serviceaccount:vault-agent:vault-agent"
            "${replace(module.eks.cluster_oidc_issuer_url, "https://", "")}:aud" = "sts.amazonaws.com"
          }
        }
      }
    ]
  })

  tags = {
    Environment = "production"
    Project     = "vault-agent"
  }
}

resource "aws_iam_policy" "vault_agent" {
  name = "${var.cluster_name}-vault-agent-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.vault_agent_backups.arn,
          "${aws_s3_bucket.vault_agent_backups.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue",
          "secretsmanager:CreateSecret",
          "secretsmanager:DeleteSecret",
          "secretsmanager:ListSecrets"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Environment = "production"
    Project     = "vault-agent"
  }
}

resource "aws_iam_role_policy_attachment" "vault_agent" {
  role       = aws_iam_role.vault_agent.name
  policy_arn = aws_iam_policy.vault_agent.arn
}

# Outputs
output "cluster_endpoint" {
  description = "Endpoint for EKS control plane"
  value       = module.eks.cluster_endpoint
}

output "cluster_security_group_id" {
  description = "Security group ids attached to the cluster control plane"
  value       = module.eks.cluster_security_group_id
}

output "cluster_iam_role_name" {
  description = "IAM role name associated with EKS cluster"
  value       = module.eks.cluster_iam_role_name
}

output "cluster_certificate_authority_data" {
  description = "Base64 encoded certificate data required to communicate with the cluster"
  value       = module.eks.cluster_certificate_authority_data
}

output "cluster_name" {
  description = "Kubernetes Cluster Name"
  value       = module.eks.cluster_name
}

output "database_endpoint" {
  description = "RDS instance endpoint"
  value       = aws_db_instance.vault_agent.endpoint
  sensitive   = true
}

output "database_password" {
  description = "RDS instance password"
  value       = random_password.db_password.result
  sensitive   = true
}

output "redis_endpoint" {
  description = "Redis cluster endpoint"
  value       = aws_elasticache_replication_group.vault_agent.primary_endpoint_address
  sensitive   = true
}

output "redis_password" {
  description = "Redis cluster password"
  value       = random_password.redis_password.result
  sensitive   = true
}

output "backup_bucket" {
  description = "S3 bucket for backups"
  value       = aws_s3_bucket.vault_agent_backups.bucket
}