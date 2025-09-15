#!/bin/bash

# Create vault-agent user and group
if ! getent group vault-agent >/dev/null 2>&1; then
    groupadd --system vault-agent
fi

if ! getent passwd vault-agent >/dev/null 2>&1; then
    useradd --system --gid vault-agent --home-dir /var/lib/vault-agent --shell /bin/false vault-agent
fi

# Create data directory
mkdir -p /var/lib/vault-agent
chown vault-agent:vault-agent /var/lib/vault-agent
chmod 750 /var/lib/vault-agent

# Create log directory
mkdir -p /var/log/vault-agent
chown vault-agent:vault-agent /var/log/vault-agent
chmod 750 /var/log/vault-agent

# Set permissions
chmod +x /usr/local/bin/vault-agent
chown root:root /usr/local/bin/vault-agent

# Reload systemd and enable service
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    systemctl enable vault-agent
    echo "Vault Agent service enabled. Start with: systemctl start vault-agent"
fi

echo "Vault Agent installation completed successfully!"
