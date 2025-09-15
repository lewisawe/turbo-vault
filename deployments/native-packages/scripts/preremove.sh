#!/bin/bash

# Stop and disable service
if command -v systemctl >/dev/null 2>&1; then
    systemctl stop vault-agent || true
    systemctl disable vault-agent || true
fi

echo "Vault Agent service stopped and disabled"
