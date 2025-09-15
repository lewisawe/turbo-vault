#!/usr/bin/env python3
"""
Advanced usage examples for Vault Agent Python SDK
Demonstrates cloud integration, policy management, and advanced features
"""

import asyncio
import logging
from datetime import datetime, timedelta
from vault_agent_sdk import (
    VaultAgentClient, 
    APIKeyAuth, 
    JWTAuth,
    ClientConfig,
    CloudConfig,
    CloudIntegration
)
from vault_agent_sdk.models import Policy, PolicyRule, PolicyCondition

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def cloud_integration_example():
    """Demonstrate cloud provider integration"""
    logger.info("=== Cloud Integration Example ===")
    
    # Configure cloud providers
    cloud_configs = [
        CloudConfig(
            provider='aws',
            region='us-east-1',
            credentials={
                'access_key_id': 'your-access-key',
                'secret_access_key': 'your-secret-key'
            },
            sync_enabled=True,
            tags={'source': 'vault-agent', 'environment': 'production'}
        ),
        CloudConfig(
            provider='azure',
            credentials={
                'vault_url': 'https://your-vault.vault.azure.net/'
            },
            sync_enabled=True,
            tags={'source': 'vault-agent'}
        )
    ]
    
    # Initialize cloud integration
    cloud_integration = CloudIntegration(cloud_configs)
    
    # Configure client
    config = ClientConfig(
        timeout=30,
        max_connections=10,
        verify_ssl=True,
        cache_enabled=True,
        cache_ttl=300  # 5 minutes
    )
    
    auth = APIKeyAuth("your-api-key-here")
    
    async with VaultAgentClient(
        base_url="https://localhost:8200",
        auth=auth,
        config=config
    ) as client:
        # Enable cloud integration
        client.enable_cloud_integration(cloud_configs)
        
        # Create a secret (will automatically sync to cloud providers)
        secret = await client.acreate_secret(
            name="database-connection",
            value="postgresql://user:pass@localhost:5432/db",
            metadata={
                "environment": "production",
                "service": "api-server",
                "rotation_interval": "30d"
            },
            tags=["database", "production", "critical"]
        )
        logger.info(f"Created secret {secret.id} with cloud sync")
        
        # Verify cloud sync status
        sync_results = await cloud_integration.sync_secret(
            secret.name, 
            secret.value, 
            secret.metadata
        )
        logger.info(f"Cloud sync results: {sync_results}")
        
        # List secrets from cloud providers
        for provider in ['aws', 'azure']:
            try:
                cloud_secrets = await cloud_integration.list_secrets_from_provider(provider)
                logger.info(f"Found {len(cloud_secrets)} secrets in {provider}")
            except Exception as e:
                logger.warning(f"Failed to list secrets from {provider}: {e}")

async def policy_management_example():
    """Demonstrate advanced policy management"""
    logger.info("=== Policy Management Example ===")
    
    config = ClientConfig(verify_ssl=False)
    auth = APIKeyAuth("your-api-key-here")
    
    async with VaultAgentClient(
        base_url="https://localhost:8200",
        auth=auth,
        config=config
    ) as client:
        # Create a comprehensive access policy
        policy = Policy(
            name="production-database-policy",
            description="Access policy for production database secrets",
            rules=[
                PolicyRule(
                    resource="secrets",
                    actions=["read", "list"],
                    conditions=[
                        PolicyCondition(
                            field="tags",
                            operator="contains",
                            value="database"
                        ),
                        PolicyCondition(
                            field="metadata.environment",
                            operator="equals",
                            value="production"
                        )
                    ]
                ),
                PolicyRule(
                    resource="secrets",
                    actions=["create", "update", "delete"],
                    conditions=[
                        PolicyCondition(
                            field="user.role",
                            operator="in",
                            value=["admin", "database-admin"]
                        ),
                        PolicyCondition(
                            field="time.hour",
                            operator="between",
                            value=[9, 17]  # Business hours only
                        )
                    ]
                )
            ],
            priority=100,
            enabled=True
        )
        
        created_policy = await client.acreate_policy(policy)
        logger.info(f"Created policy: {created_policy.id}")
        
        # List all policies
        policies = await client.alist_policies()
        logger.info(f"Total policies: {len(policies)}")

async def secret_rotation_example():
    """Demonstrate secret rotation and lifecycle management"""
    logger.info("=== Secret Rotation Example ===")
    
    config = ClientConfig(verify_ssl=False)
    auth = APIKeyAuth("your-api-key-here")
    
    async with VaultAgentClient(
        base_url="https://localhost:8200",
        auth=auth,
        config=config
    ) as client:
        # Create a secret with rotation policy
        secret = await client.acreate_secret(
            name="api-key-service-a",
            value="initial-api-key-value",
            metadata={
                "service": "service-a",
                "rotation_enabled": "true",
                "rotation_interval": "7d",
                "last_rotated": datetime.utcnow().isoformat()
            },
            tags=["api-key", "auto-rotate"]
        )
        logger.info(f"Created secret with rotation: {secret.id}")
        
        # Simulate rotation
        rotated_secret = await client.arotate_secret(secret.id)
        logger.info(f"Rotated secret to version {rotated_secret.version}")
        
        # Get version history
        versions = await client.aget_secret_versions(secret.id)
        logger.info(f"Secret has {len(versions)} versions")
        
        # Rollback to previous version if needed
        if len(versions) > 1:
            previous_version = versions[-2].version
            rolled_back = await client.arollback_secret(secret.id, previous_version)
            logger.info(f"Rolled back to version {rolled_back.version}")

async def backup_and_recovery_example():
    """Demonstrate backup and recovery operations"""
    logger.info("=== Backup and Recovery Example ===")
    
    config = ClientConfig(verify_ssl=False)
    auth = APIKeyAuth("your-api-key-here")
    
    async with VaultAgentClient(
        base_url="https://localhost:8200",
        auth=auth,
        config=config
    ) as client:
        # Create a backup
        backup_name = f"backup-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
        backup = await client.acreate_backup(
            name=backup_name,
            options={
                "include_secrets": True,
                "include_policies": True,
                "include_audit_logs": True,
                "compression": True,
                "encryption": True
            }
        )
        logger.info(f"Created backup: {backup.id}")
        
        # List all backups
        backups = await client.alist_backups()
        logger.info(f"Available backups: {len(backups)}")
        
        # Backup metadata
        for backup_info in backups[-3:]:  # Show last 3 backups
            logger.info(f"Backup {backup_info.name}: {backup_info.size} bytes, "
                       f"created {backup_info.created_at}")

async def monitoring_and_metrics_example():
    """Demonstrate monitoring and metrics collection"""
    logger.info("=== Monitoring and Metrics Example ===")
    
    config = ClientConfig(verify_ssl=False)
    auth = APIKeyAuth("your-api-key-here")
    
    async with VaultAgentClient(
        base_url="https://localhost:8200",
        auth=auth,
        config=config
    ) as client:
        # Health check
        health = await client.ahealth_check()
        logger.info(f"Vault status: {health['status']}")
        logger.info(f"Version: {health.get('version', 'unknown')}")
        logger.info(f"Uptime: {health.get('uptime', 0)} seconds")
        
        # Get Prometheus metrics
        metrics = await client.aget_metrics()
        logger.info(f"Metrics data length: {len(metrics['metrics'])} characters")
        
        # Parse some key metrics (simplified)
        metrics_lines = metrics['metrics'].split('\n')
        for line in metrics_lines:
            if 'vault_secrets_total' in line and not line.startswith('#'):
                logger.info(f"Secrets metric: {line}")
            elif 'vault_requests_total' in line and not line.startswith('#'):
                logger.info(f"Requests metric: {line}")

async def audit_and_compliance_example():
    """Demonstrate audit logging and compliance features"""
    logger.info("=== Audit and Compliance Example ===")
    
    config = ClientConfig(verify_ssl=False)
    auth = APIKeyAuth("your-api-key-here")
    
    async with VaultAgentClient(
        base_url="https://localhost:8200",
        auth=auth,
        config=config
    ) as client:
        # Get recent audit events
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=24)
        
        audit_events = await client.aget_audit_events(
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat(),
            limit=50
        )
        
        logger.info(f"Found {len(audit_events)} audit events in last 24 hours")
        
        # Analyze events by type
        event_types = {}
        for event in audit_events:
            event_type = event.event_type
            event_types[event_type] = event_types.get(event_type, 0) + 1
        
        logger.info("Event types distribution:")
        for event_type, count in event_types.items():
            logger.info(f"  {event_type}: {count}")
        
        # Show recent security events
        security_events = [e for e in audit_events if e.event_type == 'security']
        if security_events:
            logger.info(f"Recent security events: {len(security_events)}")
            for event in security_events[-5:]:  # Last 5 security events
                logger.info(f"  {event.timestamp}: {event.action} by {event.actor}")

async def jwt_authentication_example():
    """Demonstrate JWT token authentication"""
    logger.info("=== JWT Authentication Example ===")
    
    # JWT token (in real usage, this would be obtained from your auth system)
    jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    
    config = ClientConfig(verify_ssl=False)
    auth = JWTAuth(jwt_token)
    
    async with VaultAgentClient(
        base_url="https://localhost:8200",
        auth=auth,
        config=config
    ) as client:
        # Test authentication
        try:
            health = await client.ahealth_check()
            logger.info(f"JWT authentication successful: {health['status']}")
        except Exception as e:
            logger.error(f"JWT authentication failed: {e}")

async def error_handling_and_retry_example():
    """Demonstrate error handling and retry mechanisms"""
    logger.info("=== Error Handling and Retry Example ===")
    
    config = ClientConfig(
        verify_ssl=False,
        retry_max_attempts=3,
        retry_initial_delay=1.0,
        retry_max_delay=10.0,
        retry_backoff_factor=2.0
    )
    auth = APIKeyAuth("your-api-key-here")
    
    async with VaultAgentClient(
        base_url="https://localhost:8200",
        auth=auth,
        config=config
    ) as client:
        try:
            # Try to get a non-existent secret
            secret = await client.aget_secret("non-existent-secret")
        except Exception as e:
            logger.info(f"Expected error for non-existent secret: {type(e).__name__}: {e}")
        
        try:
            # Try with invalid authentication
            invalid_auth = APIKeyAuth("invalid-key")
            invalid_client = VaultAgentClient(
                base_url="https://localhost:8200",
                auth=invalid_auth,
                config=config
            )
            await invalid_client.alist_secrets()
        except Exception as e:
            logger.info(f"Expected authentication error: {type(e).__name__}: {e}")
        finally:
            await invalid_client.aclose()

async def main():
    """Run all examples"""
    examples = [
        cloud_integration_example,
        policy_management_example,
        secret_rotation_example,
        backup_and_recovery_example,
        monitoring_and_metrics_example,
        audit_and_compliance_example,
        jwt_authentication_example,
        error_handling_and_retry_example
    ]
    
    for example in examples:
        try:
            await example()
            print()  # Add spacing between examples
        except Exception as e:
            logger.error(f"Example {example.__name__} failed: {e}")
            print()

if __name__ == "__main__":
    asyncio.run(main())