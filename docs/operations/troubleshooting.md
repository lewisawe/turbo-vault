# Troubleshooting Guide

## Common Issues and Solutions

### Vault Agent Issues

#### Agent Won't Start
**Symptoms**: Agent fails to start or exits immediately
**Causes**: 
- Invalid configuration
- Port conflicts
- Permission issues

**Solutions**:
```bash
# Check configuration
keyvault-agent validate-config --config /path/to/config.yaml

# Check port availability
netstat -tulpn | grep :8080

# Fix permissions
chmod 600 /path/to/config.yaml
chown keyvault:keyvault /data/vault
```

#### Connection Refused
**Symptoms**: Cannot connect to vault agent API
**Causes**:
- Agent not running
- Firewall blocking port
- Wrong endpoint configuration

**Solutions**:
```bash
# Check agent status
systemctl status keyvault-agent

# Test connectivity
curl -k https://localhost:8080/health

# Check firewall
ufw status
```

### Authentication Issues

#### Token Expired
**Symptoms**: 401 Unauthorized responses
**Solution**:
```bash
# Refresh token
keyvault-cli auth refresh

# Re-authenticate
keyvault-cli auth login --endpoint https://your-control-plane.com
```

#### Certificate Errors
**Symptoms**: SSL/TLS certificate validation failures
**Solutions**:
```bash
# Update CA certificates
update-ca-certificates

# Use custom CA
keyvault-agent --ca-cert /path/to/ca.pem
```

### Performance Issues

#### Slow Response Times
**Causes**:
- High CPU/memory usage
- Disk I/O bottlenecks
- Network latency

**Diagnostics**:
```bash
# Check system resources
top
iostat -x 1
ping control-plane-endpoint

# Check agent metrics
curl https://localhost:8080/metrics
```

### Data Issues

#### Secrets Not Found
**Symptoms**: 404 errors when retrieving secrets
**Solutions**:
```bash
# List available secrets
keyvault-cli secrets list

# Check secret path
keyvault-cli secrets get --path /exact/path

# Verify permissions
keyvault-cli policies show --secret-path /path
```

## Diagnostic Procedures

### Health Check Script
```bash
#!/bin/bash
echo "=== KeyVault Health Check ==="

# Check agent status
if systemctl is-active --quiet keyvault-agent; then
    echo "✓ Agent is running"
else
    echo "✗ Agent is not running"
fi

# Check API endpoint
if curl -sf https://localhost:8080/health > /dev/null; then
    echo "✓ API is responding"
else
    echo "✗ API is not responding"
fi

# Check disk space
DISK_USAGE=$(df /data | tail -1 | awk '{print $5}' | sed 's/%//')
if [ $DISK_USAGE -lt 90 ]; then
    echo "✓ Disk usage: ${DISK_USAGE}%"
else
    echo "⚠ High disk usage: ${DISK_USAGE}%"
fi
```

### Log Analysis
```bash
# View recent logs
journalctl -u keyvault-agent -f

# Search for errors
journalctl -u keyvault-agent | grep ERROR

# Export logs for support
journalctl -u keyvault-agent --since "1 hour ago" > keyvault-logs.txt
```
