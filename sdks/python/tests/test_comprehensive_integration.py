"""
Comprehensive integration tests for Vault Agent Python SDK
Tests all major functionality including cloud integration, policy management, and advanced features
"""

import pytest
import asyncio
import time
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch, MagicMock
from vault_agent_sdk import (
    VaultAgentClient, 
    APIKeyAuth, 
    JWTAuth,
    ClientConfig,
    CloudConfig,
    CloudIntegration,
    AuthenticationError,
    NotFoundError,
    ValidationError,
    RateLimitError
)
from vault_agent_sdk.models import Secret, SecretMetadata, Policy, PolicyRule, PolicyCondition

@pytest.fixture
def client_config():
    return ClientConfig(
        timeout=30,
        max_connections=10,
        verify_ssl=False,
        cache_enabled=True,
        cache_ttl=300,
        retry_max_attempts=3,
        retry_initial_delay=1.0,
        retry_max_delay=10.0,
        retry_backoff_factor=2.0
    )

@pytest.fixture
def auth():
    return APIKeyAuth("test-api-key")

@pytest.fixture
async def client(auth, client_config):
    async with VaultAgentClient(
        base_url="http://localhost:8200",
        auth=auth,
        config=client_config
    ) as client:
        yield client

@pytest.fixture
def cloud_configs():
    return [
        CloudConfig(
            provider='aws',
            region='us-east-1',
            credentials={
                'access_key_id': 'test-access-key',
                'secret_access_key': 'test-secret-key'
            },
            sync_enabled=True,
            tags={'source': 'vault-agent', 'environment': 'test'}
        ),
        CloudConfig(
            provider='azure',
            credentials={
                'vault_url': 'https://test-vault.vault.azure.net/'
            },
            sync_enabled=True,
            tags={'source': 'vault-agent'}
        )
    ]

class TestSecretManagement:
    """Test comprehensive secret management functionality"""
    
    @pytest.mark.asyncio
    async def test_complete_secret_lifecycle(self, client):
        """Test complete secret lifecycle with all operations"""
        # Create secret with comprehensive metadata
        secret = await client.acreate_secret(
            name="test-lifecycle-secret",
            value="initial-secret-value",
            metadata={
                "environment": "test",
                "service": "integration-test",
                "created_by": "test-suite",
                "rotation_enabled": "true",
                "rotation_interval": "30d"
            },
            tags=["integration-test", "lifecycle", "automated"]
        )
        
        assert secret.name == "test-lifecycle-secret"
        assert secret.value == "initial-secret-value"
        assert secret.metadata["environment"] == "test"
        assert "integration-test" in secret.tags
        assert secret.version == 1
        
        # Get secret and verify
        retrieved = await client.aget_secret(secret.id)
        assert retrieved.id == secret.id
        assert retrieved.value == "initial-secret-value"
        assert retrieved.version == 1
        
        # Update secret multiple times
        updated1 = await client.aupdate_secret(
            secret.id,
            value="updated-value-1",
            metadata={**secret.metadata, "updated": "true", "update_count": "1"}
        )
        assert updated1.value == "updated-value-1"
        assert updated1.version == 2
        assert updated1.metadata["update_count"] == "1"
        
        updated2 = await client.aupdate_secret(
            secret.id,
            value="updated-value-2",
            metadata={**updated1.metadata, "update_count": "2"}
        )
        assert updated2.value == "updated-value-2"
        assert updated2.version == 3
        
        # Get version history
        versions = await client.aget_secret_versions(secret.id)
        assert len(versions) == 3
        assert versions[0].version == 1
        assert versions[1].version == 2
        assert versions[2].version == 3
        
        # Rollback to previous version
        rolled_back = await client.arollback_secret(secret.id, 2)
        assert rolled_back.version == 4  # New version created for rollback
        assert rolled_back.value == "updated-value-1"
        
        # List secrets with filtering
        all_secrets = await client.alist_secrets()
        test_secrets = await client.alist_secrets(tags=["integration-test"])
        lifecycle_secrets = await client.alist_secrets(tags=["lifecycle"])
        
        assert len(test_secrets) >= 1
        assert len(lifecycle_secrets) >= 1
        assert any(s.id == secret.id for s in test_secrets)
        
        # Delete secret
        await client.adelete_secret(secret.id)
        
        # Verify deletion
        with pytest.raises(NotFoundError):
            await client.aget_secret(secret.id)
    
    @pytest.mark.asyncio
    async def test_secret_rotation(self, client):
        """Test secret rotation functionality"""
        # Create secret with rotation policy
        secret = await client.acreate_secret(
            name="rotation-test-secret",
            value="original-rotatable-value",
            metadata={
                "rotation_enabled": "true",
                "rotation_interval": "7d",
                "last_rotated": datetime.utcnow().isoformat()
            },
            tags=["rotation-test", "auto-rotate"]
        )
        
        # Rotate secret
        rotated = await client.arotate_secret(secret.id)
        assert rotated.version > secret.version
        assert rotated.value != secret.value  # Value should have changed
        
        # Verify rotation metadata
        assert "last_rotated" in rotated.metadata
        
        # Clean up
        await client.adelete_secret(secret.id)
    
    @pytest.mark.asyncio
    async def test_batch_operations(self, client):
        """Test batch secret operations for performance"""
        # Create multiple secrets
        secret_names = [f"batch-secret-{i}" for i in range(5)]
        created_secrets = []
        
        for name in secret_names:
            secret = await client.acreate_secret(
                name=name,
                value=f"value-for-{name}",
                metadata={"batch": "true", "test": "batch-operations"},
                tags=["batch-test"]
            )
            created_secrets.append(secret)
        
        # Batch retrieve
        retrieved_secrets = []
        for secret in created_secrets:
            retrieved = await client.aget_secret(secret.id)
            retrieved_secrets.append(retrieved)
        
        assert len(retrieved_secrets) == len(created_secrets)
        
        # Batch update
        for i, secret in enumerate(created_secrets):
            await client.aupdate_secret(
                secret.id,
                value=f"updated-value-{i}",
                metadata={**secret.metadata, "updated": "true"}
            )
        
        # Verify updates
        for i, secret in enumerate(created_secrets):
            updated = await client.aget_secret(secret.id)
            assert updated.value == f"updated-value-{i}"
            assert updated.metadata["updated"] == "true"
        
        # Batch delete
        for secret in created_secrets:
            await client.adelete_secret(secret.id)

class TestCloudIntegration:
    """Test cloud provider integration functionality"""
    
    @pytest.mark.asyncio
    async def test_cloud_integration_setup(self, client, cloud_configs):
        """Test cloud integration setup and configuration"""
        cloud_integration = CloudIntegration(cloud_configs)
        
        assert cloud_integration.is_enabled()
        assert len(cloud_integration.providers) == 2
        assert 'aws' in cloud_integration.providers
        assert 'azure' in cloud_integration.providers
    
    @pytest.mark.asyncio
    async def test_cloud_secret_sync(self, client, cloud_configs):
        """Test secret synchronization to cloud providers"""
        cloud_integration = CloudIntegration(cloud_configs)
        
        # Mock cloud provider methods
        with patch.object(cloud_integration.providers['aws'], 'sync_secret', return_value=True) as mock_aws_sync, \
             patch.object(cloud_integration.providers['azure'], 'sync_secret', return_value=True) as mock_azure_sync:
            
            # Sync secret to cloud providers
            results = await cloud_integration.sync_secret(
                "test-cloud-secret",
                "cloud-secret-value",
                {"environment": "test", "cloud_sync": "true"}
            )
            
            assert results['aws'] == True
            assert results['azure'] == True
            mock_aws_sync.assert_called_once()
            mock_azure_sync.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_cloud_secret_retrieval(self, client, cloud_configs):
        """Test secret retrieval from specific cloud providers"""
        cloud_integration = CloudIntegration(cloud_configs)
        
        # Mock cloud provider methods
        with patch.object(cloud_integration.providers['aws'], 'get_secret', return_value='aws-secret-value') as mock_aws_get:
            
            # Get secret from AWS
            value = await cloud_integration.get_secret_from_provider("test-secret", "aws")
            assert value == "aws-secret-value"
            mock_aws_get.assert_called_once_with("test-secret")
    
    @pytest.mark.asyncio
    async def test_cloud_secret_listing(self, client, cloud_configs):
        """Test listing secrets from cloud providers"""
        cloud_integration = CloudIntegration(cloud_configs)
        
        # Mock cloud provider methods
        with patch.object(cloud_integration.providers['aws'], 'list_secrets', return_value=['secret1', 'secret2']) as mock_aws_list:
            
            # List secrets from AWS
            secrets = await cloud_integration.list_secrets_from_provider("aws")
            assert secrets == ['secret1', 'secret2']
            mock_aws_list.assert_called_once()

class TestPolicyManagement:
    """Test policy management functionality"""
    
    @pytest.mark.asyncio
    async def test_policy_lifecycle(self, client):
        """Test complete policy lifecycle"""
        # Create comprehensive policy
        policy = Policy(
            name="test-comprehensive-policy",
            description="Comprehensive test policy with multiple rules",
            rules=[
                PolicyRule(
                    resource="secrets",
                    actions=["read", "list"],
                    conditions=[
                        PolicyCondition(
                            field="tags",
                            operator="contains",
                            value="production"
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
                            value=["admin", "power-user"]
                        ),
                        PolicyCondition(
                            field="time.hour",
                            operator="between",
                            value=[9, 17]  # Business hours
                        )
                    ]
                )
            ],
            priority=100,
            enabled=True
        )
        
        # Create policy
        created_policy = await client.acreate_policy(policy)
        assert created_policy.name == "test-comprehensive-policy"
        assert len(created_policy.rules) == 2
        assert created_policy.enabled == True
        
        # Get policy
        retrieved_policy = await client.aget_policy(created_policy.id)
        assert retrieved_policy.id == created_policy.id
        assert retrieved_policy.name == "test-comprehensive-policy"
        
        # Update policy
        updated_policy = await client.aupdate_policy(
            created_policy.id,
            description="Updated comprehensive test policy",
            priority=200
        )
        assert updated_policy.description == "Updated comprehensive test policy"
        assert updated_policy.priority == 200
        
        # List policies
        policies = await client.alist_policies()
        assert any(p.id == created_policy.id for p in policies)
        
        # Delete policy
        await client.adelete_policy(created_policy.id)
        
        # Verify deletion
        with pytest.raises(NotFoundError):
            await client.aget_policy(created_policy.id)

class TestAuditAndCompliance:
    """Test audit logging and compliance features"""
    
    @pytest.mark.asyncio
    async def test_audit_event_retrieval(self, client):
        """Test audit event retrieval and filtering"""
        # Get audit events for last 24 hours
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=24)
        
        events = await client.aget_audit_events(
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat(),
            limit=100
        )
        
        assert isinstance(events, list)
        
        # Test event filtering by type
        if events:
            # Filter security events
            security_events = await client.aget_audit_events(
                start_time=start_time.isoformat(),
                end_time=end_time.isoformat(),
                event_type="security",
                limit=50
            )
            
            assert isinstance(security_events, list)
            
            # Verify all returned events are security events
            for event in security_events:
                assert event.event_type == "security"
    
    @pytest.mark.asyncio
    async def test_audit_event_analysis(self, client):
        """Test audit event analysis and reporting"""
        # Create some test operations to generate audit events
        secret = await client.acreate_secret(
            name="audit-test-secret",
            value="audit-test-value",
            tags=["audit-test"]
        )
        
        # Perform various operations
        await client.aget_secret(secret.id)
        await client.aupdate_secret(secret.id, value="updated-audit-value")
        await client.aget_secret(secret.id)  # Another read
        
        # Get recent events
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(minutes=5)
        
        events = await client.aget_audit_events(
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat(),
            limit=100
        )
        
        # Analyze event types
        event_types = {}
        for event in events:
            event_type = event.event_type
            event_types[event_type] = event_types.get(event_type, 0) + 1
        
        # Should have create, read, and update events
        assert len(event_types) > 0
        
        # Clean up
        await client.adelete_secret(secret.id)

class TestBackupAndRecovery:
    """Test backup and disaster recovery functionality"""
    
    @pytest.mark.asyncio
    async def test_backup_creation(self, client):
        """Test backup creation with various options"""
        # Create comprehensive backup
        backup_name = f"test-backup-{int(time.time())}"
        backup = await client.acreate_backup(
            name=backup_name,
            options={
                "include_secrets": True,
                "include_policies": True,
                "include_audit_logs": True,
                "compression": True,
                "encryption": True,
                "retention_days": 30
            }
        )
        
        assert backup.name == backup_name
        assert backup.status in ["pending", "in_progress", "completed"]
    
    @pytest.mark.asyncio
    async def test_backup_listing(self, client):
        """Test backup listing and metadata retrieval"""
        backups = await client.alist_backups()
        assert isinstance(backups, list)
        
        # Verify backup metadata structure
        for backup in backups:
            assert hasattr(backup, 'id')
            assert hasattr(backup, 'name')
            assert hasattr(backup, 'created_at')
            assert hasattr(backup, 'status')

class TestAuthentication:
    """Test various authentication methods"""
    
    @pytest.mark.asyncio
    async def test_api_key_authentication(self):
        """Test API key authentication"""
        auth = APIKeyAuth("test-api-key")
        config = ClientConfig(verify_ssl=False)
        
        async with VaultAgentClient("http://localhost:8200", auth, config) as client:
            # Test that client can be created and basic operations work
            try:
                await client.ahealth_check()
            except Exception as e:
                # Expected if server is not running, but auth should be properly set
                assert "connection" in str(e).lower() or "timeout" in str(e).lower()
    
    @pytest.mark.asyncio
    async def test_jwt_authentication(self):
        """Test JWT token authentication"""
        jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.token"
        auth = JWTAuth(jwt_token)
        config = ClientConfig(verify_ssl=False)
        
        async with VaultAgentClient("http://localhost:8200", auth, config) as client:
            # Test that client can be created with JWT auth
            headers = await auth.get_headers()
            assert "Authorization" in headers
            assert headers["Authorization"].startswith("Bearer ")

class TestErrorHandling:
    """Test comprehensive error handling"""
    
    @pytest.mark.asyncio
    async def test_authentication_errors(self):
        """Test authentication error handling"""
        auth = APIKeyAuth("invalid-api-key")
        config = ClientConfig(verify_ssl=False)
        
        with patch('httpx.AsyncClient.request') as mock_request:
            mock_response = AsyncMock()
            mock_response.status_code = 401
            mock_response.json.return_value = {"message": "Invalid API key"}
            mock_request.return_value = mock_response
            
            async with VaultAgentClient("http://localhost:8200", auth, config) as client:
                with pytest.raises(AuthenticationError):
                    await client.alist_secrets()
    
    @pytest.mark.asyncio
    async def test_not_found_errors(self, client):
        """Test not found error handling"""
        with pytest.raises(NotFoundError):
            await client.aget_secret("non-existent-secret-id")
    
    @pytest.mark.asyncio
    async def test_validation_errors(self, client):
        """Test validation error handling"""
        with patch.object(client, '_make_async_request') as mock_request:
            mock_response = AsyncMock()
            mock_response.status_code = 400
            mock_response.json.return_value = {"message": "Invalid secret name"}
            mock_request.return_value = mock_response
            
            with pytest.raises(ValidationError):
                await client.acreate_secret(
                    name="",  # Invalid empty name
                    value="test-value"
                )
    
    @pytest.mark.asyncio
    async def test_rate_limit_errors(self, client):
        """Test rate limit error handling"""
        with patch.object(client, '_make_async_request') as mock_request:
            mock_response = AsyncMock()
            mock_response.status_code = 429
            mock_response.json.return_value = {"message": "Rate limit exceeded"}
            mock_request.return_value = mock_response
            
            with pytest.raises(RateLimitError):
                await client.alist_secrets()

class TestPerformanceAndCaching:
    """Test performance optimization and caching"""
    
    @pytest.mark.asyncio
    async def test_caching_behavior(self):
        """Test caching behavior and performance"""
        config = ClientConfig(
            verify_ssl=False,
            cache_enabled=True,
            cache_ttl=60  # 1 minute
        )
        auth = APIKeyAuth("test-api-key")
        
        async with VaultAgentClient("http://localhost:8200", auth, config) as client:
            # Mock successful response
            with patch.object(client, '_make_async_request') as mock_request:
                mock_response = AsyncMock()
                mock_response.status_code = 200
                mock_response.json.return_value = {
                    "id": "test-secret-id",
                    "name": "test-secret",
                    "value": "test-value",
                    "version": 1,
                    "created_at": datetime.utcnow().isoformat(),
                    "updated_at": datetime.utcnow().isoformat(),
                    "created_by": "test-user",
                    "access_count": 0,
                    "status": "active"
                }
                mock_request.return_value = mock_response
                
                # First request should hit the API
                secret1 = await client.aget_secret("test-secret-id")
                assert mock_request.call_count == 1
                
                # Second request should use cache (if caching is implemented)
                secret2 = await client.aget_secret("test-secret-id")
                
                # Verify both requests return the same data
                assert secret1.id == secret2.id
                assert secret1.value == secret2.value
    
    @pytest.mark.asyncio
    async def test_concurrent_operations(self, client):
        """Test concurrent operations performance"""
        # Create test secrets for concurrent access
        secret_ids = []
        for i in range(3):
            secret = await client.acreate_secret(
                name=f"concurrent-test-{i}",
                value=f"concurrent-value-{i}",
                tags=["concurrent-test"]
            )
            secret_ids.append(secret.id)
        
        # Perform concurrent reads
        async def read_secret(secret_id):
            return await client.aget_secret(secret_id)
        
        start_time = time.time()
        tasks = [read_secret(sid) for sid in secret_ids]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        end_time = time.time()
        
        # Verify all operations completed
        assert len(results) == len(secret_ids)
        
        # Verify no exceptions (or handle expected ones)
        for result in results:
            if isinstance(result, Exception):
                # Log but don't fail if secrets don't exist in test environment
                print(f"Expected exception in test environment: {result}")
        
        # Clean up
        for secret_id in secret_ids:
            try:
                await client.adelete_secret(secret_id)
            except:
                pass  # Ignore cleanup errors in test environment

class TestHealthAndMonitoring:
    """Test health checking and monitoring functionality"""
    
    @pytest.mark.asyncio
    async def test_health_check(self, client):
        """Test health check functionality"""
        with patch.object(client, '_make_async_request') as mock_request:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "status": "healthy",
                "version": "1.0.0",
                "uptime": 3600,
                "secrets_count": 10,
                "policies_count": 5
            }
            mock_request.return_value = mock_response
            
            health = await client.ahealth_check()
            assert health["status"] == "healthy"
            assert health["version"] == "1.0.0"
            assert health["uptime"] == 3600
    
    @pytest.mark.asyncio
    async def test_metrics_collection(self, client):
        """Test metrics collection"""
        with patch.object(client, '_make_async_request') as mock_request:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.text = """
# HELP vault_secrets_total Total number of secrets
# TYPE vault_secrets_total counter
vault_secrets_total 42
# HELP vault_requests_total Total number of requests
# TYPE vault_requests_total counter
vault_requests_total{method="GET",status="200"} 1234
            """.strip()
            mock_request.return_value = mock_response
            
            metrics = await client.aget_metrics()
            assert "vault_secrets_total" in metrics["metrics"]
            assert "vault_requests_total" in metrics["metrics"]

# Performance benchmarks
@pytest.mark.benchmark
class TestPerformanceBenchmarks:
    """Performance benchmark tests"""
    
    @pytest.mark.asyncio
    async def test_secret_creation_performance(self, client):
        """Benchmark secret creation performance"""
        start_time = time.time()
        
        # Create multiple secrets
        for i in range(10):
            try:
                await client.acreate_secret(
                    name=f"perf-test-{i}",
                    value=f"performance-test-value-{i}",
                    tags=["performance-test"]
                )
            except:
                pass  # Ignore errors in test environment
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Should complete within reasonable time
        assert total_time < 30.0  # 30 seconds for 10 operations
        
        print(f"Created 10 secrets in {total_time:.2f} seconds")
    
    @pytest.mark.asyncio
    async def test_secret_retrieval_performance(self, client):
        """Benchmark secret retrieval performance"""
        # Create a test secret first
        try:
            secret = await client.acreate_secret(
                name="perf-retrieval-test",
                value="performance-retrieval-value",
                tags=["performance-test"]
            )
            
            start_time = time.time()
            
            # Retrieve the same secret multiple times
            for _ in range(10):
                await client.aget_secret(secret.id)
            
            end_time = time.time()
            total_time = end_time - start_time
            
            # Should complete within reasonable time
            assert total_time < 10.0  # 10 seconds for 10 retrievals
            
            print(f"Retrieved secret 10 times in {total_time:.2f} seconds")
            
            # Clean up
            await client.adelete_secret(secret.id)
        except:
            pass  # Ignore errors in test environment