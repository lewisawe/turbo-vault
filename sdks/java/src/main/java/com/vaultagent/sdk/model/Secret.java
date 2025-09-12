package com.vaultagent.sdk.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Represents a secret with its metadata and value
 */
public class Secret {
    
    @JsonProperty("id")
    private String id;
    
    @JsonProperty("name")
    private String name;
    
    @JsonProperty("value")
    private String value;
    
    @JsonProperty("metadata")
    private Map<String, Object> metadata;
    
    @JsonProperty("tags")
    private List<String> tags;
    
    @JsonProperty("created_at")
    private Instant createdAt;
    
    @JsonProperty("updated_at")
    private Instant updatedAt;
    
    @JsonProperty("expires_at")
    private Instant expiresAt;
    
    @JsonProperty("rotation_due")
    private Instant rotationDue;
    
    @JsonProperty("version")
    private Integer version;
    
    @JsonProperty("created_by")
    private String createdBy;
    
    @JsonProperty("access_count")
    private Long accessCount;
    
    @JsonProperty("last_accessed")
    private Instant lastAccessed;
    
    @JsonProperty("status")
    private String status;
    
    // Constructors
    public Secret() {}
    
    public Secret(String name, String value) {
        this.name = name;
        this.value = value;
    }
    
    // Getters and setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    
    public String getValue() { return value; }
    public void setValue(String value) { this.value = value; }
    
    public Map<String, Object> getMetadata() { return metadata; }
    public void setMetadata(Map<String, Object> metadata) { this.metadata = metadata; }
    
    public List<String> getTags() { return tags; }
    public void setTags(List<String> tags) { this.tags = tags; }
    
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
    
    public Instant getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }
    
    public Instant getExpiresAt() { return expiresAt; }
    public void setExpiresAt(Instant expiresAt) { this.expiresAt = expiresAt; }
    
    public Instant getRotationDue() { return rotationDue; }
    public void setRotationDue(Instant rotationDue) { this.rotationDue = rotationDue; }
    
    public Integer getVersion() { return version; }
    public void setVersion(Integer version) { this.version = version; }
    
    public String getCreatedBy() { return createdBy; }
    public void setCreatedBy(String createdBy) { this.createdBy = createdBy; }
    
    public Long getAccessCount() { return accessCount; }
    public void setAccessCount(Long accessCount) { this.accessCount = accessCount; }
    
    public Instant getLastAccessed() { return lastAccessed; }
    public void setLastAccessed(Instant lastAccessed) { this.lastAccessed = lastAccessed; }
    
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    
    @Override
    public String toString() {
        return "Secret{" +
                "id='" + id + '\'' +
                ", name='" + name + '\'' +
                ", version=" + version +
                ", status='" + status + '\'' +
                ", createdAt=" + createdAt +
                '}';
    }
}