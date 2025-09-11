# Technical Architecture

## System Components

### 1. Control Plane (SaaS)
- **Purpose**: Metadata management, user interface, analytics
- **Data Stored**: User accounts, vault registrations, usage metrics, policies
- **Technology**: Node.js/TypeScript, PostgreSQL, Redis
- **Security**: Never stores actual secrets, only encrypted metadata

### 2. Vault Agent (Customer-Hosted)
- **Purpose**: Secret storage, encryption, access control
- **Data Stored**: Encrypted secrets, access logs, local policies
- **Technology**: Go binary, SQLite/PostgreSQL, AES-256-GCM encryption
- **Security**: All secrets encrypted at rest, mTLS communication

### 3. Communication Protocol
- **Authentication**: mTLS with client certificates
- **Encryption**: TLS 1.3 with perfect forward secrecy
- **API**: RESTful JSON over HTTPS, WebSocket for real-time updates

## Security Model

### Zero-Trust Principles
1. **No Secret Transit**: Secrets never leave customer infrastructure
2. **Metadata Only**: Control plane only receives encrypted metadata
3. **Mutual Authentication**: Both sides verify identity via certificates
4. **Audit Trail**: All operations logged locally and centrally (metadata only)

### Encryption Strategy
- **At Rest**: AES-256-GCM with customer-managed keys
- **In Transit**: TLS 1.3 with certificate pinning
- **Key Derivation**: PBKDF2 with 100,000 iterations minimum

## Deployment Models

### Docker Container
```yaml
version: '3.8'
services:
  keyvault-agent:
    image: keyvault/agent:latest
    volumes:
      - ./config:/app/config
      - ./data:/app/data
    environment:
      - VAULT_MASTER_KEY_FILE=/app/config/master.key
      - CONTROL_PLANE_URL=https://api.keyvault.com
    ports:
      - "8080:8080"
```

### Kubernetes Operator
```yaml
apiVersion: keyvault.io/v1
kind: VaultAgent
metadata:
  name: production-vault
spec:
  replicas: 3
  storage:
    size: 10Gi
    storageClass: fast-ssd
  controlPlane:
    endpoint: https://api.keyvault.com
    certificateRef: vault-client-cert
```

### Native Binary
- Single binary with embedded SQLite
- Configuration via YAML or environment variables
- Systemd service integration for Linux
- Windows Service support

## API Design

### Vault Agent API
```
POST   /api/v1/secrets                 # Create secret
GET    /api/v1/secrets/{id}            # Retrieve secret
PUT    /api/v1/secrets/{id}            # Update secret
DELETE /api/v1/secrets/{id}            # Delete secret
GET    /api/v1/secrets                 # List secrets (metadata only)
POST   /api/v1/secrets/{id}/rotate     # Rotate secret
GET    /api/v1/health                  # Health check
GET    /api/v1/metrics                 # Prometheus metrics
```

### Control Plane API
```
POST   /api/v1/vaults/register         # Register new vault
GET    /api/v1/vaults                  # List registered vaults
GET    /api/v1/analytics/usage         # Usage analytics
POST   /api/v1/policies                # Create rotation policy
GET    /api/v1/alerts                  # Get alerts
```