# Quick Start Guide

Get your KeyVault agent running in under 5 minutes.

## Prerequisites
- Docker installed
- 2GB RAM minimum
- Network access to control plane

## Step 1: Deploy Vault Agent

```bash
# Create data directory
mkdir -p ./keyvault-data

# Run vault agent
docker run -d --name keyvault-agent \
  -v ./keyvault-data:/data \
  -p 8080:8080 \
  -e KEYVAULT_CONTROL_PLANE=https://your-control-plane.com \
  keyvault/agent:latest
```

## Step 2: Register Agent

```bash
# Install CLI
curl -sSL https://get.keyvault.dev | bash

# Register with control plane
keyvault-cli register \
  --endpoint https://your-control-plane.com \
  --token <your-registration-token>
```

## Step 3: Store Your First Secret

```bash
# Create a secret
keyvault-cli secrets create \
  --path /myapp/database/password \
  --value "super-secure-password"

# Retrieve the secret
keyvault-cli secrets get --path /myapp/database/password
```

## Step 4: Verify Setup

```bash
# Check agent health
curl https://localhost:8080/health

# List your secrets
keyvault-cli secrets list
```

## Next Steps

- [Complete Installation Guide](installation.md)
- [Security Best Practices](../security/comprehensive-security-guide.md)
- [API Documentation](../api/comprehensive-api-guide.md)

## Need Help?

- Check [Troubleshooting Guide](../operations/troubleshooting.md)
- Review [Common Issues](../operations/troubleshooting.md#common-issues-and-solutions)
