"""
Configuration classes for Vault Agent SDK.
"""

from typing import Optional
from pydantic import BaseModel, Field


class ClientConfig(BaseModel):
    """Configuration for Vault Agent client."""
    
    timeout: float = Field(30.0, description="Request timeout in seconds")
    max_connections: int = Field(10, description="Maximum number of connections")
    max_retries: int = Field(3, description="Maximum number of retries")
    retry_backoff_factor: float = Field(2.0, description="Retry backoff factor")
    verify_ssl: bool = Field(True, description="Whether to verify SSL certificates")
    ca_bundle: Optional[str] = Field(None, description="Path to CA bundle file")
    
    # Caching configuration
    enable_caching: bool = Field(True, description="Whether to enable response caching")
    cache_ttl: int = Field(300, description="Cache TTL in seconds")
    max_cache_size: int = Field(1000, description="Maximum cache size")
    
    # Logging configuration
    log_level: str = Field("INFO", description="Logging level")
    log_requests: bool = Field(False, description="Whether to log HTTP requests")
    log_responses: bool = Field(False, description="Whether to log HTTP responses")
    
    # Rate limiting
    rate_limit_requests: Optional[int] = Field(None, description="Rate limit requests per second")
    rate_limit_burst: Optional[int] = Field(None, description="Rate limit burst size")
    
    class Config:
        extra = "forbid"