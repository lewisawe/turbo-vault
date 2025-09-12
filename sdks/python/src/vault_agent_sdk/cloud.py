"""
Cloud provider integration for hybrid deployments
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class CloudConfig:
    """Configuration for cloud provider integration"""
    provider: str  # aws, azure, gcp
    region: Optional[str] = None
    credentials: Optional[Dict[str, Any]] = None
    sync_enabled: bool = True
    backup_enabled: bool = False
    encryption_enabled: bool = True
    tags: Optional[Dict[str, str]] = None

class CloudProvider(ABC):
    """Abstract base class for cloud provider integrations"""
    
    @abstractmethod
    async def sync_secret(self, name: str, value: str, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Sync a secret to the cloud provider"""
        pass
    
    @abstractmethod
    async def get_secret(self, name: str) -> Optional[str]:
        """Get a secret from the cloud provider"""
        pass
    
    @abstractmethod
    async def delete_secret(self, name: str) -> bool:
        """Delete a secret from the cloud provider"""
        pass
    
    @abstractmethod
    async def list_secrets(self) -> List[str]:
        """List all secrets in the cloud provider"""
        pass

class AWSSecretsManager(CloudProvider):
    """AWS Secrets Manager integration"""
    
    def __init__(self, config: CloudConfig):
        self.config = config
        self._client = None
    
    async def _get_client(self):
        """Get or create AWS client"""
        if self._client is None:
            try:
                import boto3
                session = boto3.Session(
                    aws_access_key_id=self.config.credentials.get('access_key_id'),
                    aws_secret_access_key=self.config.credentials.get('secret_access_key'),
                    region_name=self.config.region
                )
                self._client = session.client('secretsmanager')
            except ImportError:
                raise ImportError("boto3 is required for AWS integration. Install with: pip install boto3")
        return self._client
    
    async def sync_secret(self, name: str, value: str, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Sync secret to AWS Secrets Manager"""
        try:
            client = await self._get_client()
            
            # Prepare secret data
            secret_data = {
                'Name': f"vault-agent/{name}",
                'SecretString': value,
                'Description': f"Synced from Vault Agent: {metadata.get('description', '')}",
            }
            
            if self.config.tags:
                secret_data['Tags'] = [
                    {'Key': k, 'Value': v} for k, v in self.config.tags.items()
                ]
            
            try:
                # Try to update existing secret
                client.update_secret(**secret_data)
                logger.info(f"Updated secret {name} in AWS Secrets Manager")
            except client.exceptions.ResourceNotFoundException:
                # Create new secret
                client.create_secret(**secret_data)
                logger.info(f"Created secret {name} in AWS Secrets Manager")
            
            return True
        except Exception as e:
            logger.error(f"Failed to sync secret {name} to AWS: {e}")
            return False
    
    async def get_secret(self, name: str) -> Optional[str]:
        """Get secret from AWS Secrets Manager"""
        try:
            client = await self._get_client()
            response = client.get_secret_value(SecretId=f"vault-agent/{name}")
            return response['SecretString']
        except Exception as e:
            logger.error(f"Failed to get secret {name} from AWS: {e}")
            return None
    
    async def delete_secret(self, name: str) -> bool:
        """Delete secret from AWS Secrets Manager"""
        try:
            client = await self._get_client()
            client.delete_secret(
                SecretId=f"vault-agent/{name}",
                ForceDeleteWithoutRecovery=True
            )
            logger.info(f"Deleted secret {name} from AWS Secrets Manager")
            return True
        except Exception as e:
            logger.error(f"Failed to delete secret {name} from AWS: {e}")
            return False
    
    async def list_secrets(self) -> List[str]:
        """List secrets from AWS Secrets Manager"""
        try:
            client = await self._get_client()
            paginator = client.get_paginator('list_secrets')
            secrets = []
            
            for page in paginator.paginate():
                for secret in page['SecretList']:
                    name = secret['Name']
                    if name.startswith('vault-agent/'):
                        secrets.append(name.replace('vault-agent/', ''))
            
            return secrets
        except Exception as e:
            logger.error(f"Failed to list secrets from AWS: {e}")
            return []

class AzureKeyVault(CloudProvider):
    """Azure Key Vault integration"""
    
    def __init__(self, config: CloudConfig):
        self.config = config
        self._client = None
    
    async def _get_client(self):
        """Get or create Azure client"""
        if self._client is None:
            try:
                from azure.keyvault.secrets import SecretClient
                from azure.identity import DefaultAzureCredential
                
                credential = DefaultAzureCredential()
                vault_url = self.config.credentials.get('vault_url')
                if not vault_url:
                    raise ValueError("vault_url is required for Azure Key Vault")
                
                self._client = SecretClient(vault_url=vault_url, credential=credential)
            except ImportError:
                raise ImportError("azure-keyvault-secrets is required for Azure integration")
        return self._client
    
    async def sync_secret(self, name: str, value: str, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Sync secret to Azure Key Vault"""
        try:
            client = await self._get_client()
            
            # Azure Key Vault has naming restrictions
            azure_name = name.replace('_', '-').replace('.', '-')
            
            client.set_secret(azure_name, value, tags=self.config.tags)
            logger.info(f"Synced secret {name} to Azure Key Vault as {azure_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to sync secret {name} to Azure: {e}")
            return False
    
    async def get_secret(self, name: str) -> Optional[str]:
        """Get secret from Azure Key Vault"""
        try:
            client = await self._get_client()
            azure_name = name.replace('_', '-').replace('.', '-')
            secret = client.get_secret(azure_name)
            return secret.value
        except Exception as e:
            logger.error(f"Failed to get secret {name} from Azure: {e}")
            return None
    
    async def delete_secret(self, name: str) -> bool:
        """Delete secret from Azure Key Vault"""
        try:
            client = await self._get_client()
            azure_name = name.replace('_', '-').replace('.', '-')
            client.begin_delete_secret(azure_name)
            logger.info(f"Deleted secret {name} from Azure Key Vault")
            return True
        except Exception as e:
            logger.error(f"Failed to delete secret {name} from Azure: {e}")
            return False
    
    async def list_secrets(self) -> List[str]:
        """List secrets from Azure Key Vault"""
        try:
            client = await self._get_client()
            secrets = []
            
            for secret_properties in client.list_properties_of_secrets():
                # Convert back from Azure naming convention
                name = secret_properties.name.replace('-', '_')
                secrets.append(name)
            
            return secrets
        except Exception as e:
            logger.error(f"Failed to list secrets from Azure: {e}")
            return []

class GCPSecretManager(CloudProvider):
    """Google Cloud Secret Manager integration"""
    
    def __init__(self, config: CloudConfig):
        self.config = config
        self._client = None
    
    async def _get_client(self):
        """Get or create GCP client"""
        if self._client is None:
            try:
                from google.cloud import secretmanager
                self._client = secretmanager.SecretManagerServiceClient()
            except ImportError:
                raise ImportError("google-cloud-secret-manager is required for GCP integration")
        return self._client
    
    async def sync_secret(self, name: str, value: str, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Sync secret to GCP Secret Manager"""
        try:
            client = await self._get_client()
            project_id = self.config.credentials.get('project_id')
            if not project_id:
                raise ValueError("project_id is required for GCP Secret Manager")
            
            parent = f"projects/{project_id}"
            secret_id = f"vault-agent-{name.replace('_', '-').replace('.', '-')}"
            
            try:
                # Try to create secret
                secret = {
                    'replication': {'automatic': {}},
                }
                if self.config.tags:
                    secret['labels'] = self.config.tags
                
                client.create_secret(
                    request={
                        'parent': parent,
                        'secret_id': secret_id,
                        'secret': secret
                    }
                )
            except Exception:
                # Secret might already exist
                pass
            
            # Add secret version
            secret_name = f"{parent}/secrets/{secret_id}"
            client.add_secret_version(
                request={
                    'parent': secret_name,
                    'payload': {'data': value.encode('utf-8')}
                }
            )
            
            logger.info(f"Synced secret {name} to GCP Secret Manager as {secret_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to sync secret {name} to GCP: {e}")
            return False
    
    async def get_secret(self, name: str) -> Optional[str]:
        """Get secret from GCP Secret Manager"""
        try:
            client = await self._get_client()
            project_id = self.config.credentials.get('project_id')
            secret_id = f"vault-agent-{name.replace('_', '-').replace('.', '-')}"
            
            secret_name = f"projects/{project_id}/secrets/{secret_id}/versions/latest"
            response = client.access_secret_version(request={'name': secret_name})
            return response.payload.data.decode('utf-8')
        except Exception as e:
            logger.error(f"Failed to get secret {name} from GCP: {e}")
            return None
    
    async def delete_secret(self, name: str) -> bool:
        """Delete secret from GCP Secret Manager"""
        try:
            client = await self._get_client()
            project_id = self.config.credentials.get('project_id')
            secret_id = f"vault-agent-{name.replace('_', '-').replace('.', '-')}"
            
            secret_name = f"projects/{project_id}/secrets/{secret_id}"
            client.delete_secret(request={'name': secret_name})
            
            logger.info(f"Deleted secret {name} from GCP Secret Manager")
            return True
        except Exception as e:
            logger.error(f"Failed to delete secret {name} from GCP: {e}")
            return False
    
    async def list_secrets(self) -> List[str]:
        """List secrets from GCP Secret Manager"""
        try:
            client = await self._get_client()
            project_id = self.config.credentials.get('project_id')
            parent = f"projects/{project_id}"
            
            secrets = []
            for secret in client.list_secrets(request={'parent': parent}):
                name = secret.name.split('/')[-1]
                if name.startswith('vault-agent-'):
                    # Convert back from GCP naming convention
                    original_name = name.replace('vault-agent-', '').replace('-', '_')
                    secrets.append(original_name)
            
            return secrets
        except Exception as e:
            logger.error(f"Failed to list secrets from GCP: {e}")
            return []

class CloudIntegration:
    """Main cloud integration manager"""
    
    def __init__(self, configs: List[CloudConfig]):
        self.providers: Dict[str, CloudProvider] = {}
        
        for config in configs:
            if config.provider == 'aws':
                self.providers['aws'] = AWSSecretsManager(config)
            elif config.provider == 'azure':
                self.providers['azure'] = AzureKeyVault(config)
            elif config.provider == 'gcp':
                self.providers['gcp'] = GCPSecretManager(config)
            else:
                logger.warning(f"Unknown cloud provider: {config.provider}")
    
    def is_enabled(self) -> bool:
        """Check if any cloud integration is enabled"""
        return len(self.providers) > 0
    
    async def sync_secret(self, name: str, value: str, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, bool]:
        """Sync secret to all configured cloud providers"""
        results = {}
        
        tasks = []
        for provider_name, provider in self.providers.items():
            task = asyncio.create_task(
                provider.sync_secret(name, value, metadata),
                name=f"sync_{provider_name}"
            )
            tasks.append((provider_name, task))
        
        for provider_name, task in tasks:
            try:
                results[provider_name] = await task
            except Exception as e:
                logger.error(f"Failed to sync to {provider_name}: {e}")
                results[provider_name] = False
        
        return results
    
    async def delete_secret(self, name: str) -> Dict[str, bool]:
        """Delete secret from all configured cloud providers"""
        results = {}
        
        tasks = []
        for provider_name, provider in self.providers.items():
            task = asyncio.create_task(
                provider.delete_secret(name),
                name=f"delete_{provider_name}"
            )
            tasks.append((provider_name, task))
        
        for provider_name, task in tasks:
            try:
                results[provider_name] = await task
            except Exception as e:
                logger.error(f"Failed to delete from {provider_name}: {e}")
                results[provider_name] = False
        
        return results
    
    async def get_secret_from_provider(self, name: str, provider: str) -> Optional[str]:
        """Get secret from a specific cloud provider"""
        if provider not in self.providers:
            raise ValueError(f"Provider {provider} not configured")
        
        return await self.providers[provider].get_secret(name)
    
    async def list_secrets_from_provider(self, provider: str) -> List[str]:
        """List secrets from a specific cloud provider"""
        if provider not in self.providers:
            raise ValueError(f"Provider {provider} not configured")
        
        return await self.providers[provider].list_secrets()