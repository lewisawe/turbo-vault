# KeyVault Troubleshooting Guide

## Installation Issues

### Docker Build Fails
```bash
# Error: go: go.mod requires go >= 1.23.0
```
**Solution**: Update Docker to use Go 1.23+ or use the provided Dockerfile which has the correct version.

### Port 8080 Already in Use
```bash
# Error: bind: address already in use
```
**Solutions**:
1. Stop the conflicting service: `sudo lsof -ti:8080 | xargs kill -9`
2. Change port in `docker-compose.yml`: `ports: - "8081:8080"`

### Permission Denied on master.key
```bash
# Error: permission denied: config/master.key
```
**Solution**: Fix file permissions: `chmod 600 config/master.key`

### Docker Daemon Not Running
```bash
# Error: Cannot connect to the Docker daemon
```
**Solution**: Start Docker service:
- Linux: `sudo systemctl start docker`
- macOS/Windows: Start Docker Desktop

## Runtime Issues

### Web Interface Not Loading
1. Check if container is running: `docker compose ps`
2. Check logs: `docker compose logs vault-agent`
3. Verify port mapping: `docker compose port vault-agent 8080`

### CLI Commands Fail
```bash
# Error: connection refused
```
**Solutions**:
1. Ensure service is running: `curl http://localhost:8080/api/v1/system/stats`
2. Check CLI config: `cat .vault-cli.yaml`
3. Verify endpoint: `./vault-cli system status -v`

### Authentication Issues
```bash
# Error: 401 Unauthorized
```
**Solutions**:
1. Use demo credentials: `admin / admin123`
2. Check token in CLI config
3. Clear browser cache/cookies

### Database Connection Errors
```bash
# Error: database is locked
```
**Solutions**:
1. Stop all containers: `docker compose down`
2. Remove lock file: `rm -f data/vault.db-wal data/vault.db-shm`
3. Restart: `docker compose up -d`

## Performance Issues

### Slow Startup
- First run takes longer due to image building
- Subsequent starts should be faster
- Check available disk space: `df -h`

### High Memory Usage
- Default SQLite uses minimal memory
- For production, consider PostgreSQL
- Monitor with: `docker stats`

## Common Commands

### Reset Everything
```bash
docker compose down -v
rm -rf data/
rm config/master.key
./install.sh
```

### View All Logs
```bash
docker compose logs -f
```

### Check Service Health
```bash
curl -s http://localhost:8080/api/v1/system/stats | jq
```

### Backup Data
```bash
cp -r data/ backup-$(date +%Y%m%d)/
cp config/master.key backup-$(date +%Y%m%d)/
```

## Getting Help

1. Check logs first: `docker compose logs`
2. Verify system requirements
3. Try the reset procedure above
4. Open an issue with:
   - Operating system
   - Docker version
   - Error messages
   - Steps to reproduce

## System Requirements

- **OS**: Linux, macOS, Windows with WSL2
- **Docker**: 20.10+ 
- **Docker Compose**: 2.0+
- **Memory**: 512MB minimum
- **Disk**: 1GB free space
- **Network**: Port 8080 available
