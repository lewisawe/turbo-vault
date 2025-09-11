#!/bin/bash

# KeyVault Agent Setup Script

set -e

echo "🔐 Setting up KeyVault Agent..."

# Create necessary directories
mkdir -p config data

# Generate a sample master key (DO NOT USE IN PRODUCTION)
echo "Generating sample master key..."
openssl rand -hex 32 > config/master.key
chmod 600 config/master.key

# Create sample configuration
cat > config/agent.yaml << EOF
database:
  type: sqlite
  path: ./data/vault.db

control_plane:
  url: https://api.keyvault.com
  cert_file: ./config/client.crt
  key_file: ./config/client.key

security:
  master_key_file: ./config/master.key
  rotation_interval: 30d
  backup_enabled: true

logging:
  level: info
  file: ./data/agent.log
EOF

echo "✅ Setup complete!"
echo ""
echo "Next steps:"
echo "1. Review and update config/agent.yaml"
echo "2. Replace the sample master key with a secure one"
echo "3. Run: docker-compose up -d"
echo "4. Access the web UI at http://localhost:3000"
echo ""
echo "API endpoints:"
echo "- Health: http://localhost:8080/health"
echo "- Secrets: http://localhost:8080/api/v1/secrets"
echo ""
echo "⚠️  IMPORTANT: This is a development setup. Do not use in production without proper security configuration!"