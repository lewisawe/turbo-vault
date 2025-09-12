# Security Hardening Guide for Vault Agent

## Overview

This guide provides comprehensive security hardening recommendations for deploying and operating Vault Agent in production environments. Following these guidelines will help ensure your deployment meets industry security standards and compliance requirements.

## Table of Contents

1. [Infrastructure Security](#infrastructure-security)
2. [Network Security](#network-security)
3. [Authentication and Authorization](#authentication-and-authorization)
4. [Encryption and Key Management](#encryption-and-key-management)
5. [Audit and Monitoring](#audit-and-monitoring)
6. [Compliance Considerations](#compliance-considerations)
7. [Incident Response](#incident-response)
8. [Security Testing](#security-testing)

## Infrastructure Security

### Operating System Hardening

#### Linux Systems
```bash
# Disable unnecessary services
systemctl disable telnet
systemctl disable ftp
systemctl disable rsh
systemctl disable rlogin

# Configure firewall
ufw enable
ufw default deny incoming
ufw default allow outgoing
ufw allow 8080/tcp  # Vault Agent API port
ufw allow 8443/tcp  # Vault Agent HTTPS port

# Set secure file permissions
chmod 600 /etc/vault-agent/config.yaml
chmod 700 /var/lib/vault-agent/
chown vault-agent:vault-agent /etc/vault-agent/
```

#### Container Security
```dockerfile
# Use minimal base images
FROM alpine:3.18

# Run as non-root user
RUN addgroup -g 1001 vault-agent && \
    adduser -D -s /bin/sh -u 1001 -G vault-agent vault-agent

USER vault-agent

# Set security options
LABEL security.non-root=true
LABEL security.no-new-privileges=true
```

### File System Security

#### Secure Configuration Storage
```yaml
# /etc/vault-agent/config.yaml
server:
  bind_address: "127.0.0.1:8080"
  tls:
    enabled: true
    cert_file: "/etc/vault-agent/certs/server.crt"
    key_file: "/etc/vault-agent/certs/server.key"
    min_version: "1.2"

storage:
  type: "postgresql"
  connection_string: "postgresql://vault_user:${DB_PASSWORD}@localhost/vault_db?sslmode=require"
  encryption_key_file: "/etc/vault-agent/keys/storage.key"

audit:
  enabled: true
  file_path: "/var/log/vault-agent/audit.log"
  format: "json"
  integrity_protection: true
```

## Network Security

### Zero-Trust Architecture

#### Network Segmentation
```yaml
# Network policy example for Kubernetes
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: vault-agent-network-policy
spec:
  podSelector:
    matchLabels:
      app: vault-agent
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: vault-clients
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: database
    ports:
    - protocol: TCP
      port: 5432
```

#### mTLS Configuration
```yaml
# Vault Agent mTLS configuration
network:
  mtls:
    enabled: true
    ca_cert_file: "/etc/vault-agent/certs/ca.crt"
    server_cert_file: "/etc/vault-agent/certs/server.crt"
    server_key_file: "/etc/vault-agent/certs/server.key"
    client_cert_verification: "require"
    cipher_suites:
      - "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
      - "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
      - "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"
```

### Firewall Configuration

#### iptables Rules
```bash
#!/bin/bash
# Vault Agent firewall rules

# Flush existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow Vault Agent API (from specific networks only)
iptables -A INPUT -p tcp --dport 8080 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 8443 -s 10.0.0.0/8 -j ACCEPT

# Allow SSH (from management network only)
iptables -A INPUT -p tcp --dport 22 -s 192.168.100.0/24 -j ACCEPT

# Log dropped packets
iptables -A INPUT -j LOG --log-prefix "DROPPED: "
iptables -A INPUT -j DROP
```

## Authentication and Authorization

### Multi-Factor Authentication

#### TOTP Configuration
```yaml
auth:
  mfa:
    enabled: true
    methods:
      - type: "totp"
        issuer: "VaultAgent"
        algorithm: "SHA256"
        digits: 6
        period: 30
      - type: "webauthn"
        rp_id: "vault.example.com"
        rp_name: "Vault Agent"
```

### Role-Based Access Control

#### RBAC Policy Example
```json
{
  "roles": [
    {
      "name": "secret-admin",
      "permissions": [
        {
          "resource": "secrets/*",
          "actions": ["create", "read", "update", "delete", "rotate"]
        },
        {
          "resource": "policies/*",
          "actions": ["create", "read", "update", "delete"]
        }
      ]
    },
    {
      "name": "secret-reader",
      "permissions": [
        {
          "resource": "secrets/app/*",
          "actions": ["read"]
        }
      ]
    },
    {
      "name": "secret-rotator",
      "permissions": [
        {
          "resource": "secrets/*/rotate",
          "actions": ["execute"]
        }
      ]
    }
  ]
}
```

### API Key Management

#### Secure API Key Generation
```go
// Example API key generation with proper entropy
func generateAPIKey() (string, error) {
    // Generate 32 bytes of random data
    randomBytes := make([]byte, 32)
    _, err := rand.Read(randomBytes)
    if err != nil {
        return "", err
    }
    
    // Encode as base64url
    apiKey := base64.URLEncoding.EncodeToString(randomBytes)
    return apiKey, nil
}
```

## Encryption and Key Management

### Encryption Standards

#### AES-256-GCM Configuration
```yaml
encryption:
  algorithm: "AES-256-GCM"
  key_derivation:
    function: "PBKDF2"
    iterations: 100000
    salt_length: 32
  key_rotation:
    enabled: true
    interval: "90d"
    retain_old_keys: 3
```

### Hardware Security Module Integration

#### HSM Configuration
```yaml
key_management:
  type: "hsm"
  hsm:
    library_path: "/usr/lib/libpkcs11.so"
    slot_id: 0
    pin: "${HSM_PIN}"
    key_label: "vault-agent-master-key"
```

### Key Rotation Procedures

#### Automated Key Rotation
```bash
#!/bin/bash
# Key rotation script

VAULT_AGENT_API="https://localhost:8443"
API_KEY="${VAULT_AGENT_API_KEY}"

# Rotate encryption keys
curl -X POST \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  "${VAULT_AGENT_API}/api/v1/keys/rotate"

# Verify rotation
curl -X GET \
  -H "Authorization: Bearer ${API_KEY}" \
  "${VAULT_AGENT_API}/api/v1/keys/status"
```

## Audit and Monitoring

### Comprehensive Audit Logging

#### Audit Configuration
```yaml
audit:
  enabled: true
  events:
    - "authentication"
    - "authorization"
    - "secret_access"
    - "secret_modification"
    - "policy_changes"
    - "key_rotation"
    - "system_events"
  
  outputs:
    - type: "file"
      path: "/var/log/vault-agent/audit.log"
      format: "json"
      rotation:
        max_size: "100MB"
        max_files: 10
        compress: true
    
    - type: "syslog"
      facility: "local0"
      severity: "info"
    
    - type: "webhook"
      url: "https://siem.example.com/vault-agent"
      headers:
        Authorization: "Bearer ${SIEM_TOKEN}"
```

### Security Monitoring

#### Prometheus Metrics
```yaml
monitoring:
  prometheus:
    enabled: true
    listen_address: "127.0.0.1:9090"
    metrics:
      - "vault_agent_requests_total"
      - "vault_agent_request_duration_seconds"
      - "vault_agent_authentication_failures_total"
      - "vault_agent_secrets_accessed_total"
      - "vault_agent_key_rotations_total"
```

### Alerting Rules

#### Security Alert Configuration
```yaml
# Prometheus alerting rules
groups:
- name: vault-agent-security
  rules:
  - alert: HighAuthenticationFailures
    expr: rate(vault_agent_authentication_failures_total[5m]) > 0.1
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: "High authentication failure rate detected"
      
  - alert: UnauthorizedSecretAccess
    expr: vault_agent_unauthorized_access_total > 0
    for: 0m
    labels:
      severity: critical
    annotations:
      summary: "Unauthorized secret access detected"
      
  - alert: KeyRotationFailure
    expr: vault_agent_key_rotation_failures_total > 0
    for: 0m
    labels:
      severity: high
    annotations:
      summary: "Key rotation failure detected"
```

## Compliance Considerations

### SOC 2 Compliance

#### Control Implementation Checklist
- [ ] Access controls implemented (CC6.1)
- [ ] Logical access security measures (CC6.2)
- [ ] Network security controls (CC6.7)
- [ ] Data transmission controls (CC6.7)
- [ ] System monitoring (CC7.1)
- [ ] Change management (CC8.1)

### ISO 27001 Compliance

#### Information Security Controls
- [ ] A.9.1.1 - Access control policy
- [ ] A.9.2.1 - User registration and de-registration
- [ ] A.9.4.2 - Secure log-on procedures
- [ ] A.10.1.1 - Cryptographic controls policy
- [ ] A.12.4.1 - Event logging
- [ ] A.12.6.1 - Management of technical vulnerabilities

### PCI DSS Compliance

#### Requirements Implementation
- [ ] Requirement 3 - Protect stored cardholder data
- [ ] Requirement 4 - Encrypt transmission of cardholder data
- [ ] Requirement 7 - Restrict access by business need to know
- [ ] Requirement 8 - Identify and authenticate access
- [ ] Requirement 10 - Track and monitor all access

## Incident Response

### Security Incident Response Plan

#### Incident Classification
1. **Critical**: Data breach, system compromise
2. **High**: Unauthorized access, service disruption
3. **Medium**: Policy violation, suspicious activity
4. **Low**: Failed authentication, minor configuration issue

#### Response Procedures
```bash
#!/bin/bash
# Incident response script

INCIDENT_TYPE="$1"
SEVERITY="$2"

case "$INCIDENT_TYPE" in
  "data_breach")
    # Immediate containment
    systemctl stop vault-agent
    # Preserve evidence
    cp /var/log/vault-agent/audit.log /tmp/incident-evidence/
    # Notify stakeholders
    curl -X POST -d "Incident: Data breach detected" \
      https://alerts.example.com/critical
    ;;
  "unauthorized_access")
    # Block suspicious IPs
    iptables -A INPUT -s "$SUSPICIOUS_IP" -j DROP
    # Enhanced monitoring
    tail -f /var/log/vault-agent/audit.log | grep "$SUSPICIOUS_IP"
    ;;
esac
```

### Forensic Data Collection

#### Evidence Preservation
```bash
#!/bin/bash
# Forensic data collection script

INCIDENT_ID="$1"
EVIDENCE_DIR="/tmp/forensics/${INCIDENT_ID}"

mkdir -p "$EVIDENCE_DIR"

# Collect system information
uname -a > "$EVIDENCE_DIR/system_info.txt"
ps aux > "$EVIDENCE_DIR/processes.txt"
netstat -tulpn > "$EVIDENCE_DIR/network_connections.txt"

# Collect Vault Agent logs
cp /var/log/vault-agent/*.log "$EVIDENCE_DIR/"

# Collect configuration
cp /etc/vault-agent/config.yaml "$EVIDENCE_DIR/"

# Create integrity hashes
find "$EVIDENCE_DIR" -type f -exec sha256sum {} \; > "$EVIDENCE_DIR/integrity.sha256"

# Compress evidence
tar -czf "/tmp/evidence-${INCIDENT_ID}.tar.gz" -C /tmp/forensics "$INCIDENT_ID"
```

## Security Testing

### Vulnerability Assessment

#### Automated Security Scanning
```bash
#!/bin/bash
# Security scanning script

# Network vulnerability scan
nmap -sS -O -A vault-agent.example.com

# SSL/TLS configuration test
testssl.sh --full vault-agent.example.com:8443

# Web application security scan
nikto -h https://vault-agent.example.com:8443

# Configuration security check
./vault-agent security scan --config /etc/vault-agent/config.yaml
```

### Penetration Testing

#### Security Test Scenarios
1. **Authentication Bypass**: Attempt to bypass authentication mechanisms
2. **Privilege Escalation**: Test for privilege escalation vulnerabilities
3. **Data Exfiltration**: Simulate unauthorized data access attempts
4. **Denial of Service**: Test system resilience against DoS attacks
5. **Man-in-the-Middle**: Test TLS/mTLS implementation

#### Automated Security Tests
```go
// Example security test
func TestAuthenticationSecurity(t *testing.T) {
    // Test weak password rejection
    client := NewVaultAgentClient("https://localhost:8443")
    
    weakPasswords := []string{"password", "123456", "admin"}
    for _, password := range weakPasswords {
        err := client.Authenticate("testuser", password)
        assert.Error(t, err, "Weak password should be rejected")
    }
    
    // Test account lockout
    for i := 0; i < 6; i++ {
        client.Authenticate("testuser", "wrongpassword")
    }
    
    err := client.Authenticate("testuser", "correctpassword")
    assert.Error(t, err, "Account should be locked after failed attempts")
}
```

## Security Checklist

### Pre-Deployment Security Review
- [ ] All default passwords changed
- [ ] Unnecessary services disabled
- [ ] Firewall rules configured
- [ ] TLS/mTLS properly configured
- [ ] Audit logging enabled
- [ ] Backup and recovery tested
- [ ] Monitoring and alerting configured
- [ ] Security policies applied
- [ ] Vulnerability scan completed
- [ ] Penetration testing performed

### Ongoing Security Maintenance
- [ ] Regular security updates applied
- [ ] Vulnerability assessments performed monthly
- [ ] Access reviews conducted quarterly
- [ ] Incident response plan tested annually
- [ ] Security training completed
- [ ] Compliance audits passed
- [ ] Key rotation performed as scheduled
- [ ] Backup integrity verified

## Conclusion

Following this security hardening guide will help ensure your Vault Agent deployment maintains a strong security posture. Regular review and updates of these security measures are essential to address evolving threats and maintain compliance with security standards.

For additional security guidance, consult the official Vault Agent security documentation and industry security frameworks such as NIST Cybersecurity Framework and CIS Controls.