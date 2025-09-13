# Operational Runbooks

## Daily Operations

### Health Monitoring
```bash
# Check all vault agents
for agent in $(keyvault-cli agents list --format json | jq -r '.[].id'); do
    echo "Checking agent: $agent"
    keyvault-cli agents health --id $agent
done

# Review metrics dashboard
# Access: https://your-monitoring.com/keyvault-dashboard
```

### Log Review
```bash
# Check for errors in last 24 hours
journalctl -u keyvault-agent --since "24 hours ago" | grep -i error

# Monitor failed authentication attempts
grep "authentication failed" /var/log/keyvault/audit.log
```

## Backup Procedures

### Automated Backup
```bash
#!/bin/bash
BACKUP_DIR="/backups/keyvault/$(date +%Y%m%d)"
mkdir -p $BACKUP_DIR

# Backup configuration
cp -r /etc/keyvault/ $BACKUP_DIR/config/

# Backup encrypted data
keyvault-cli backup create --output $BACKUP_DIR/vault-backup.enc

# Upload to secure storage
aws s3 cp $BACKUP_DIR/ s3://your-backup-bucket/keyvault/ --recursive
```

### Restore Procedure
```bash
# Stop agent
systemctl stop keyvault-agent

# Restore configuration
cp -r /backups/keyvault/20240913/config/* /etc/keyvault/

# Restore data
keyvault-cli backup restore --input /backups/keyvault/20240913/vault-backup.enc

# Start agent
systemctl start keyvault-agent
```

## Maintenance Windows

### Agent Updates
```bash
# 1. Drain traffic (if load balanced)
keyvault-cli agents drain --id agent-001

# 2. Create backup
keyvault-cli backup create --output pre-update-backup.enc

# 3. Update agent
systemctl stop keyvault-agent
apt update && apt upgrade keyvault-agent
systemctl start keyvault-agent

# 4. Verify health
keyvault-cli agents health --id agent-001

# 5. Resume traffic
keyvault-cli agents resume --id agent-001
```

### Certificate Rotation
```bash
# Generate new certificates
keyvault-cli certs generate --output /tmp/new-certs/

# Update agent configuration
keyvault-cli config update --cert-path /tmp/new-certs/agent.pem

# Restart agent
systemctl restart keyvault-agent

# Verify connectivity
curl -k https://localhost:8080/health
```

## Incident Response

### Security Incident
1. **Immediate Actions**
   ```bash
   # Revoke compromised tokens
   keyvault-cli tokens revoke --all --reason "security-incident"
   
   # Enable audit logging
   keyvault-cli config set audit.enabled=true
   
   # Notify security team
   ```

2. **Investigation**
   ```bash
   # Export audit logs
   keyvault-cli audit export --since "24 hours ago" --output incident-logs.json
   
   # Check access patterns
   keyvault-cli audit analyze --suspicious-activity
   ```

### Performance Degradation
1. **Quick Diagnostics**
   ```bash
   # Check system resources
   htop
   iotop
   
   # Check agent metrics
   curl https://localhost:8080/metrics | grep -E "(cpu|memory|disk)"
   ```

2. **Scaling Actions**
   ```bash
   # Add more agents (Kubernetes)
   kubectl scale deployment keyvault-agent --replicas=5
   
   # Increase resources
   kubectl patch deployment keyvault-agent -p '{"spec":{"template":{"spec":{"containers":[{"name":"agent","resources":{"requests":{"memory":"2Gi","cpu":"1000m"}}}]}}}}'
   ```
