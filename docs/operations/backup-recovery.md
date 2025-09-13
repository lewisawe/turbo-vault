# Backup & Recovery Guide

## Backup Strategy

### What to Backup
- **Vault data**: Encrypted secrets and metadata
- **Configuration files**: Agent and policy configurations
- **Certificates**: TLS certificates and keys
- **Audit logs**: Security and access logs

### Backup Schedule
- **Daily**: Incremental vault data backup
- **Weekly**: Full system backup
- **Monthly**: Long-term archive backup

## Automated Backup

### Backup Script
```bash
#!/bin/bash
set -euo pipefail

BACKUP_ROOT="/backups/keyvault"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="$BACKUP_ROOT/$DATE"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Backup vault data
echo "Backing up vault data..."
keyvault-cli backup create \
  --output "$BACKUP_DIR/vault-data.enc" \
  --compression gzip

# Backup configuration
echo "Backing up configuration..."
tar -czf "$BACKUP_DIR/config.tar.gz" /etc/keyvault/

# Backup certificates
echo "Backing up certificates..."
tar -czf "$BACKUP_DIR/certs.tar.gz" /etc/ssl/keyvault/

# Backup audit logs
echo "Backing up audit logs..."
tar -czf "$BACKUP_DIR/audit-logs.tar.gz" /var/log/keyvault/

# Create manifest
cat > "$BACKUP_DIR/manifest.json" << EOF
{
  "timestamp": "$(date -Iseconds)",
  "version": "$(keyvault-agent --version)",
  "files": [
    "vault-data.enc",
    "config.tar.gz",
    "certs.tar.gz",
    "audit-logs.tar.gz"
  ]
}
EOF

# Upload to remote storage
aws s3 sync "$BACKUP_DIR" "s3://your-backup-bucket/keyvault/$DATE/"

# Cleanup old local backups (keep 7 days)
find "$BACKUP_ROOT" -type d -mtime +7 -exec rm -rf {} +

echo "Backup completed: $BACKUP_DIR"
```

### Cron Configuration
```bash
# Add to crontab
0 2 * * * /usr/local/bin/keyvault-backup.sh >> /var/log/keyvault-backup.log 2>&1
```

## Recovery Procedures

### Full System Recovery

#### 1. Prepare New System
```bash
# Install KeyVault agent
# (Follow installation guide)

# Stop agent service
systemctl stop keyvault-agent
```

#### 2. Restore Data
```bash
# Download backup
aws s3 sync "s3://your-backup-bucket/keyvault/20240913_020000/" /tmp/restore/

# Restore configuration
tar -xzf /tmp/restore/config.tar.gz -C /

# Restore certificates
tar -xzf /tmp/restore/certs.tar.gz -C /

# Restore vault data
keyvault-cli backup restore \
  --input /tmp/restore/vault-data.enc \
  --output /var/lib/keyvault/

# Set permissions
chown -R keyvault:keyvault /var/lib/keyvault/
chmod 600 /etc/keyvault/config.yaml
```

#### 3. Verify Recovery
```bash
# Start agent
systemctl start keyvault-agent

# Check health
curl -k https://localhost:8080/health

# Verify secrets
keyvault-cli secrets list
```

### Partial Recovery

#### Restore Single Secret
```bash
# Extract specific secret from backup
keyvault-cli backup extract \
  --input vault-data.enc \
  --path /myapp/database/password \
  --output restored-secret.json

# Import to running vault
keyvault-cli secrets import --input restored-secret.json
```

#### Restore Configuration Only
```bash
# Stop agent
systemctl stop keyvault-agent

# Restore config
tar -xzf config.tar.gz -C /

# Restart agent
systemctl start keyvault-agent
```

## Disaster Recovery

### Multi-Region Setup
```bash
# Primary region backup
keyvault-cli backup create --output primary-backup.enc

# Replicate to secondary region
aws s3 cp primary-backup.enc s3://backup-bucket-us-west/

# In secondary region
aws s3 cp s3://backup-bucket-us-west/primary-backup.enc ./
keyvault-cli backup restore --input primary-backup.enc
```

### Recovery Testing
```bash
#!/bin/bash
# Monthly DR test script

# Create test backup
keyvault-cli backup create --output dr-test-backup.enc

# Simulate failure
systemctl stop keyvault-agent
mv /var/lib/keyvault /var/lib/keyvault.bak

# Restore from backup
keyvault-cli backup restore --input dr-test-backup.enc

# Verify functionality
systemctl start keyvault-agent
keyvault-cli secrets list

# Cleanup
systemctl stop keyvault-agent
rm -rf /var/lib/keyvault
mv /var/lib/keyvault.bak /var/lib/keyvault
systemctl start keyvault-agent
```
