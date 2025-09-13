# Docker Deployment Guide

This guide covers deploying the Vault Agent using Docker containers, including single-node and multi-node configurations.

## Prerequisites

- Docker Engine 20.10+ or Docker Desktop
- Docker Compose 2.0+ (for multi-container setups)
- At least 2GB RAM and 10GB disk space
- Network access for container registry

## Quick Start

### Single Container Deployment

The fastest way to get started is with a single container:

```bash
# Pull the latest image
docker pull vaultagent/vault-agent:latest

# Run with default configuration
docker run -d \
  --name vault-agent \
  -p 8200:8200 \
  -v vault-data:/data \
  -e VAULT_AGENT_LOG_LEVEL=info \
  vaultagent/vault-agent:latest
```

### Using Docker Compose

Create a `docker-compose.yml` file:

```yaml
version: '3.8'

services:
  vault-agent:
    image: vaultagent/vault-agent:latest
    container_name: vault-agent
    ports:
      - "8200:8200"
      - "8201:8201"  # Metrics port
    volumes:
      - vault-data:/data
      - vault-config:/config
      - vault-logs:/logs
    environment:
      - VAULT_AGENT_LOG_LEVEL=info
      - VAULT_AGENT_STORAGE_TYPE=sqlite
      - VAULT_AGENT_STORAGE_PATH=/data/vault.db
      - VAULT_AGENT_ENCRYPTION_KEY_FILE=/config/master.key
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8200/api/v1/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    restart: unless-stopped

volumes:
  vault-data:
    driver: local
  vault-config:
    driver: local
  vault-logs:
    driver: local
```

Start the services:

```bash
docker-compose up -d
```

## Configuration

### Environment Variables

Configure the vault agent using environment variables:

```bash
# Core Configuration
VAULT_AGENT_LOG_LEVEL=info                    # debug, info, warn, error
VAULT_AGENT_HTTP_PORT=8200                    # HTTP API port
VAULT_AGENT_METRICS_PORT=8201                 # Prometheus metrics port
VAULT_AGENT_WEB_PORT=8080                     # Web interface port

# Storage Configuration
VAULT_AGENT_STORAGE_TYPE=sqlite               # sqlite, postgres, mysql
VAULT_AGENT_STORAGE_PATH=/data/vault.db       # SQLite database path
VAULT_AGENT_STORAGE_CONNECTION_STRING=        # For PostgreSQL/MySQL

# Encryption Configuration
VAULT_AGENT_ENCRYPTION_KEY_FILE=/config/master.key
VAULT_AGENT_ENCRYPTION_KEY_ROTATION_INTERVAL=30d

# Control Plane Configuration
VAULT_AGENT_CONTROL_PLANE_URL=https://api.vaultagent.com
VAULT_AGENT_CONTROL_PLANE_CERT_FILE=/config/client.crt
VAULT_AGENT_CONTROL_PLANE_KEY_FILE=/config/client.key

# Authentication Configuration
VAULT_AGENT_AUTH_METHODS=api_key,jwt,mtls     # Enabled auth methods
VAULT_AGENT_JWT_SECRET_FILE=/config/jwt.key
VAULT_AGENT_API_KEY_HASH_ROUNDS=12

# Backup Configuration
VAULT_AGENT_BACKUP_ENABLED=true
VAULT_AGENT_BACKUP_SCHEDULE="0 2 * * *"      # Daily at 2 AM
VAULT_AGENT_BACKUP_RETENTION_DAYS=30
```

### Configuration File

Create a configuration file at `/config/vault-agent.yaml`:

```yaml
# Core server configuration
server:
  http_port: 8200
  metrics_port: 8201
  web_port: 8080
  tls:
    enabled: true
    cert_file: /config/server.crt
    key_file: /config/server.key
    min_version: "1.3"

# Logging configuration
logging:
  level: info
  format: json
  output: /logs/vault-agent.log
  rotation:
    max_size: 100MB
    max_files: 10
    max_age: 30d

# Storage backend configuration
storage:
  type: sqlite
  sqlite:
    path: /data/vault.db
    connection_pool_size: 10
    busy_timeout: 30s
  # postgres:
  #   connection_string: "postgres://user:pass@localhost/vault"
  #   max_connections: 20
  #   max_idle_connections: 5

# Encryption configuration
encryption:
  key_manager:
    type: file
    file:
      key_file: /config/master.key
      rotation_interval: 30d
  # hsm:
  #   provider: pkcs11
  #   library_path: /usr/lib/libpkcs11.so
  #   slot_id: 0

# Authentication methods
authentication:
  methods:
    - api_key
    - jwt
    - mtls
  api_key:
    hash_rounds: 12
  jwt:
    secret_file: /config/jwt.key
    expiration: 24h
  mtls:
    ca_file: /config/ca.crt
    verify_client_cert: true

# Policy engine configuration
policies:
  cache_size: 1000
  cache_ttl: 5m
  evaluation_timeout: 10s

# Backup configuration
backup:
  enabled: true
  schedule: "0 2 * * *"  # Daily at 2 AM
  retention:
    days: 30
    max_backups: 100
  destinations:
    - type: local
      path: /data/backups
    - type: s3
      bucket: vault-backups
      region: us-west-2
      encryption: true

# Monitoring and metrics
monitoring:
  prometheus:
    enabled: true
    path: /metrics
  health_check:
    enabled: true
    path: /health
    interval: 30s

# Control plane integration
control_plane:
  enabled: true
  url: https://api.vaultagent.com
  cert_file: /config/client.crt
  key_file: /config/client.key
  heartbeat_interval: 30s
  offline_mode: true
```

### Volume Mounts

Mount necessary directories for persistent data:

```bash
docker run -d \
  --name vault-agent \
  -p 8200:8200 \
  -v $(pwd)/data:/data \
  -v $(pwd)/config:/config \
  -v $(pwd)/logs:/logs \
  -v $(pwd)/backups:/backups \
  vaultagent/vault-agent:latest
```

## Multi-Architecture Support

The vault agent supports multiple architectures:

```bash
# AMD64 (x86_64)
docker pull vaultagent/vault-agent:latest-amd64

# ARM64 (Apple Silicon, ARM servers)
docker pull vaultagent/vault-agent:latest-arm64

# Multi-arch (automatically selects correct architecture)
docker pull vaultagent/vault-agent:latest
```

## Production Deployment

### High Availability Setup

For production environments, deploy multiple instances with shared storage:

```yaml
version: '3.8'

services:
  vault-agent-1:
    image: vaultagent/vault-agent:latest
    ports:
      - "8200:8200"
    volumes:
      - vault-data:/data
      - ./config:/config
    environment:
      - VAULT_AGENT_INSTANCE_ID=vault-1
      - VAULT_AGENT_STORAGE_TYPE=postgres
      - VAULT_AGENT_STORAGE_CONNECTION_STRING=postgres://vault:password@postgres:5432/vault
    depends_on:
      - postgres
    restart: unless-stopped

  vault-agent-2:
    image: vaultagent/vault-agent:latest
    ports:
      - "8201:8200"
    volumes:
      - vault-data:/data
      - ./config:/config
    environment:
      - VAULT_AGENT_INSTANCE_ID=vault-2
      - VAULT_AGENT_STORAGE_TYPE=postgres
      - VAULT_AGENT_STORAGE_CONNECTION_STRING=postgres://vault:password@postgres:5432/vault
    depends_on:
      - postgres
    restart: unless-stopped

  postgres:
    image: postgres:15
    environment:
      - POSTGRES_DB=vault
      - POSTGRES_USER=vault
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres-data:/var/lib/postgresql/data
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - vault-agent-1
      - vault-agent-2
    restart: unless-stopped

volumes:
  vault-data:
  postgres-data:
```

### Load Balancer Configuration

Create `nginx.conf` for load balancing:

```nginx
upstream vault_agents {
    least_conn;
    server vault-agent-1:8200 max_fails=3 fail_timeout=30s;
    server vault-agent-2:8200 max_fails=3 fail_timeout=30s;
}

server {
    listen 80;
    server_name vault.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name vault.example.com;

    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;

    location / {
        proxy_pass http://vault_agents;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Health check
        proxy_next_upstream error timeout invalid_header http_500 http_502 http_503;
        proxy_connect_timeout 5s;
        proxy_send_timeout 10s;
        proxy_read_timeout 10s;
    }

    location /health {
        access_log off;
        proxy_pass http://vault_agents/api/v1/health;
    }
}
```

## Security Hardening

### Container Security

Run containers with security best practices:

```bash
docker run -d \
  --name vault-agent \
  --user 1000:1000 \
  --read-only \
  --tmpfs /tmp \
  --tmpfs /var/run \
  --cap-drop ALL \
  --cap-add CHOWN \
  --cap-add SETGID \
  --cap-add SETUID \
  --security-opt no-new-privileges:true \
  -p 8200:8200 \
  -v vault-data:/data \
  -v vault-config:/config:ro \
  vaultagent/vault-agent:latest
```

### Secrets Management

Use Docker secrets for sensitive configuration:

```yaml
version: '3.8'

services:
  vault-agent:
    image: vaultagent/vault-agent:latest
    secrets:
      - master_key
      - jwt_secret
      - db_password
    environment:
      - VAULT_AGENT_ENCRYPTION_KEY_FILE=/run/secrets/master_key
      - VAULT_AGENT_JWT_SECRET_FILE=/run/secrets/jwt_secret
      - VAULT_AGENT_DB_PASSWORD_FILE=/run/secrets/db_password

secrets:
  master_key:
    file: ./secrets/master.key
  jwt_secret:
    file: ./secrets/jwt.key
  db_password:
    file: ./secrets/db.password
```

## Monitoring and Logging

### Prometheus Metrics

Expose metrics for monitoring:

```yaml
version: '3.8'

services:
  vault-agent:
    image: vaultagent/vault-agent:latest
    ports:
      - "8200:8200"
      - "8201:8201"  # Metrics port
    environment:
      - VAULT_AGENT_METRICS_ENABLED=true
      - VAULT_AGENT_METRICS_PORT=8201

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana-data:/var/lib/grafana

volumes:
  grafana-data:
```

### Log Aggregation

Configure centralized logging:

```yaml
version: '3.8'

services:
  vault-agent:
    image: vaultagent/vault-agent:latest
    logging:
      driver: "fluentd"
      options:
        fluentd-address: localhost:24224
        tag: vault-agent
    environment:
      - VAULT_AGENT_LOG_FORMAT=json

  fluentd:
    image: fluent/fluentd:latest
    ports:
      - "24224:24224"
    volumes:
      - ./fluentd.conf:/fluentd/etc/fluent.conf
      - fluentd-data:/var/log/fluentd

volumes:
  fluentd-data:
```

## Backup and Recovery

### Automated Backups

Configure automated backups with Docker:

```bash
# Create backup script
cat > backup.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/backups/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Backup database
docker exec vault-agent sqlite3 /data/vault.db ".backup $BACKUP_DIR/vault.db"

# Backup configuration
docker cp vault-agent:/config "$BACKUP_DIR/"

# Compress backup
tar -czf "$BACKUP_DIR.tar.gz" -C /backups "$(basename $BACKUP_DIR)"
rm -rf "$BACKUP_DIR"

# Cleanup old backups (keep last 30 days)
find /backups -name "*.tar.gz" -mtime +30 -delete
EOF

chmod +x backup.sh

# Schedule with cron
echo "0 2 * * * /path/to/backup.sh" | crontab -
```

### Disaster Recovery

Restore from backup:

```bash
# Stop the container
docker stop vault-agent

# Extract backup
tar -xzf backup_20250913_020000.tar.gz

# Restore database
docker run --rm \
  -v vault-data:/data \
  -v $(pwd)/backup_20250913_020000:/backup \
  alpine:latest \
  cp /backup/vault.db /data/vault.db

# Restore configuration
docker run --rm \
  -v vault-config:/config \
  -v $(pwd)/backup_20250913_020000:/backup \
  alpine:latest \
  cp -r /backup/config/* /config/

# Start the container
docker start vault-agent
```

## Troubleshooting

### Common Issues

**Container won't start:**
```bash
# Check logs
docker logs vault-agent

# Check configuration
docker exec vault-agent cat /config/vault-agent.yaml

# Verify permissions
docker exec vault-agent ls -la /data /config
```

**Database connection issues:**
```bash
# Test database connectivity
docker exec vault-agent nc -zv postgres 5432

# Check database logs
docker logs postgres
```

**Performance issues:**
```bash
# Monitor resource usage
docker stats vault-agent

# Check metrics
curl http://localhost:8201/metrics
```

### Health Checks

Verify container health:

```bash
# Built-in health check
docker inspect vault-agent | jq '.[0].State.Health'

# Manual health check
curl -f http://localhost:8200/api/v1/health

# Detailed system status
curl http://localhost:8200/api/v1/status
```

## Upgrading

### Rolling Updates

Perform zero-downtime upgrades:

```bash
# Pull new image
docker pull vaultagent/vault-agent:latest

# Update with rolling restart
docker-compose up -d --no-deps vault-agent-1
sleep 30
docker-compose up -d --no-deps vault-agent-2
```

### Backup Before Upgrade

Always backup before upgrading:

```bash
# Create pre-upgrade backup
./backup.sh

# Verify backup
tar -tzf /backups/$(ls -t /backups/*.tar.gz | head -1)

# Proceed with upgrade
docker-compose pull
docker-compose up -d
```

## Best Practices

1. **Use specific image tags** instead of `latest` in production
2. **Set resource limits** to prevent resource exhaustion
3. **Use health checks** for automatic recovery
4. **Mount volumes** for persistent data
5. **Use secrets management** for sensitive configuration
6. **Enable monitoring** and alerting
7. **Regular backups** with tested restore procedures
8. **Security scanning** of container images
9. **Network segmentation** with proper firewall rules
10. **Regular updates** with proper testing procedures