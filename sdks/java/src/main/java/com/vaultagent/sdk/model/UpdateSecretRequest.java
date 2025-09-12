package com.vaultagent.sdk.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Map;

/**
 * Request object for updating an existing secret
 */
public class UpdateSecretRequest {
    
    @JsonProperty("value")
    private String value;
    
    @JsonProperty("metadata")
    private Map<String, Object> metadata;
    
    @JsonProperty("tags")
    private List<String> tags;
    
    // Constructors
    public UpdateSecretRequest() {}
    
    public UpdateSecretRequest(String value) {
        this.value = value;
    }
    
    // Getters and setters
    public String getValue() { return value; }
    public void setValue(String value) { this.value = value; }
    
    public Map<String, Object> getMetadata() { return metadata; }
    public void setMetadata(Map<String, Object> metadata) { this.metadata = metadata; }
    
    public List<String> getTags() { return tags; }
    public void setTags(List<String> tags) { this.tags = tags; }
    
    /**
     * Create a builder for UpdateSecretRequest
     */
    public static Builder builder() {
        return new Builder();
    }
    
    public static class Builder {
        private UpdateSecretRequest request = new UpdateSecretRequest();
        
        public Builder value(String value) {
            request.setValue(value);
            return this;
        }
        
        public Builder metadata(Map<String, Object> metadata) {
            request.setMetadata(metadata);
            return this;
        }
        
        public Builder tags(List<String> tags) {
            request.setTags(tags);
            return this;
        }
        
        public UpdateSecretRequest build() {
            return request;
        }
    }
}