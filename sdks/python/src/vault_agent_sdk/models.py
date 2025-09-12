"""
Data models for Vault Agent SDK.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, ConfigDict


class SecretStatus(str, Enum):
    """Secret status enumeration."""
    ACTIVE = "active"
    EXPIRED = "expired"
    ROTATED = "rotated"
    DELETED = "deleted"


class AuditEventType(str, Enum):
    """Audit event type enumeration."""
    SECRET_CREATE = "secret_create"
    SECRET_READ = "secret_read"
    SECRET_UPDATE = "secret_update"
    SECRET_DELETE = "secret_delete"
    SECRET_ROTATE = "secret_rotate"
    POLICY_CREATE = "policy_create"
    POLICY_UPDATE = "policy_update"
    POLICY_DELETE = "policy_delete"
    AUTH_LOGIN = "auth_login"
    AUTH_LOGOUT = "auth_logout"
    AUTH_FAILURE = "auth_failure"


class SecretMetadata(BaseModel):
    """Secret metadata (without sensitive value)."""
    model_config = ConfigDict(extra="forbid")
    
    id: str = Field(..., description="Unique secret identifier")
    name: str = Field(..., description="Secret name")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Custom metadata")
    tags: List[str] = Field(default_factory=list, description="Secret tags")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    expires_at: Optional[datetime] = Field(None, description="Expiration timestamp")
    rotation_due: Optional[datetime] = Field(None, description="Next rotation timestamp")
    version: int = Field(..., description="Secret version")
    created_by: str = Field(..., description="Creator identifier")
    access_count: int = Field(0, description="Number of times accessed")
    last_accessed: Optional[datetime] = Field(None, description="Last access timestamp")
    status: SecretStatus = Field(SecretStatus.ACTIVE, description="Secret status")


class Secret(SecretMetadata):
    """Complete secret with sensitive value."""
    
    value: str = Field(..., description="Secret value (sensitive)")


class RotationPolicy(BaseModel):
    """Secret rotation policy configuration."""
    model_config = ConfigDict(extra="forbid")
    
    id: str = Field(..., description="Policy identifier")
    enabled: bool = Field(True, description="Whether rotation is enabled")
    interval_days: int = Field(..., description="Rotation interval in days")
    max_usage_count: Optional[int] = Field(None, description="Maximum usage before rotation")
    rotator_type: str = Field(..., description="Type of rotator to use")
    rotator_config: Dict[str, Any] = Field(default_factory=dict, description="Rotator configuration")
    notification_channels: List[str] = Field(default_factory=list, description="Notification channels")


class PolicyRule(BaseModel):
    """Policy rule definition."""
    model_config = ConfigDict(extra="forbid")
    
    id: str = Field(..., description="Rule identifier")
    resource: str = Field(..., description="Resource pattern")
    actions: List[str] = Field(..., description="Allowed actions")
    effect: str = Field("allow", description="Rule effect (allow/deny)")
    conditions: Dict[str, Any] = Field(default_factory=dict, description="Rule conditions")


class Policy(BaseModel):
    """Access control policy."""
    model_config = ConfigDict(extra="forbid")
    
    id: str = Field(..., description="Policy identifier")
    name: str = Field(..., description="Policy name")
    description: Optional[str] = Field(None, description="Policy description")
    rules: List[PolicyRule] = Field(..., description="Policy rules")
    priority: int = Field(100, description="Policy priority")
    enabled: bool = Field(True, description="Whether policy is enabled")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")


class Actor(BaseModel):
    """Audit event actor."""
    model_config = ConfigDict(extra="forbid")
    
    type: str = Field(..., description="Actor type (user, service, system)")
    id: str = Field(..., description="Actor identifier")
    name: Optional[str] = Field(None, description="Actor display name")


class Resource(BaseModel):
    """Audit event resource."""
    model_config = ConfigDict(extra="forbid")
    
    type: str = Field(..., description="Resource type")
    id: Optional[str] = Field(None, description="Resource identifier")
    name: Optional[str] = Field(None, description="Resource name")


class AuditEvent(BaseModel):
    """Audit event record."""
    model_config = ConfigDict(extra="forbid")
    
    id: str = Field(..., description="Event identifier")
    vault_id: str = Field(..., description="Vault agent identifier")
    event_type: AuditEventType = Field(..., description="Event type")
    actor: Actor = Field(..., description="Event actor")
    resource: Resource = Field(..., description="Event resource")
    action: str = Field(..., description="Action performed")
    result: str = Field(..., description="Action result (success/failure)")
    context: Dict[str, Any] = Field(default_factory=dict, description="Additional context")
    timestamp: datetime = Field(..., description="Event timestamp")
    ip_address: Optional[str] = Field(None, description="Client IP address")
    user_agent: Optional[str] = Field(None, description="Client user agent")


class BackupInfo(BaseModel):
    """Backup information."""
    model_config = ConfigDict(extra="forbid")
    
    id: str = Field(..., description="Backup identifier")
    name: str = Field(..., description="Backup name")
    backup_type: str = Field(..., description="Backup type")
    status: str = Field(..., description="Backup status")
    file_path: Optional[str] = Field(None, description="Backup file path")
    file_size: Optional[int] = Field(None, description="Backup file size in bytes")
    checksum: Optional[str] = Field(None, description="Backup file checksum")
    created_at: datetime = Field(..., description="Backup creation timestamp")
    completed_at: Optional[datetime] = Field(None, description="Backup completion timestamp")
    expires_at: Optional[datetime] = Field(None, description="Backup expiration timestamp")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Backup metadata")


class VaultStatus(BaseModel):
    """Vault agent status information."""
    model_config = ConfigDict(extra="forbid")
    
    status: str = Field(..., description="Overall status")
    version: str = Field(..., description="Vault agent version")
    uptime: int = Field(..., description="Uptime in seconds")
    secrets_count: int = Field(..., description="Number of secrets")
    policies_count: int = Field(..., description="Number of policies")
    last_backup: Optional[datetime] = Field(None, description="Last backup timestamp")
    storage_usage: Dict[str, Any] = Field(default_factory=dict, description="Storage usage statistics")
    performance_metrics: Dict[str, Any] = Field(default_factory=dict, description="Performance metrics")


class CloudProviderConfig(BaseModel):
    """Cloud provider integration configuration."""
    model_config = ConfigDict(extra="forbid")
    
    provider: str = Field(..., description="Cloud provider (aws, azure, gcp)")
    region: Optional[str] = Field(None, description="Cloud region")
    credentials: Dict[str, Any] = Field(default_factory=dict, description="Provider credentials")
    service_config: Dict[str, Any] = Field(default_factory=dict, description="Service-specific configuration")


class HybridConfig(BaseModel):
    """Hybrid deployment configuration."""
    model_config = ConfigDict(extra="forbid")
    
    enabled: bool = Field(False, description="Whether hybrid mode is enabled")
    primary_provider: str = Field(..., description="Primary secret storage provider")
    fallback_providers: List[str] = Field(default_factory=list, description="Fallback providers")
    sync_interval: int = Field(300, description="Sync interval in seconds")
    conflict_resolution: str = Field("primary_wins", description="Conflict resolution strategy")
    cloud_providers: Dict[str, CloudProviderConfig] = Field(
        default_factory=dict, description="Cloud provider configurations"
    )