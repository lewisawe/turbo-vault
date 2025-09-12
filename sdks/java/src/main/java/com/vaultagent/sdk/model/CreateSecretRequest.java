package com.vaultagent.sdk.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Map;

/**
 * Request object for creating a new secret
 */
public class CreateSecretRequest {
    
    @JsonProperty("name")
    private String name;
    
    @JsonProperty("value")
    private String value;
    
    @JsonProperty("metadata")
    private Map<String, Object> metadata;
    
    @JsonProperty("tags")
    private List<String> tags;
    
    // Constructors
    public CreateSecretRequest() {}
    
    public CreateSecretRequest(String name, String value) {
        this.name = name;
        this.value = value;
    }
    
    public CreateSecretRequest(String name, String value, Map<String, Object> metadata, List<String> tags) {
        this.name = name;
        this.value = value;
        this.metadata = metadata;
        this.tags = tags;
    }
    
    // Getters and setters
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    
    public String getValue() { return value; }
    public void setValue(String value) { this.value = value; }
    
    public Map<String, Object> getMetadata() { return metadata; }
    public void setMetadata(Map<String, Object> metadata) { this.metadata = metadata; }
    
    public List<String> getTags() { return tags; }
    public void setTags(List<String> tags) { this.tags = tags; }
    
    /**
     * Create a builder for CreateSecretRequest
     */
    public static Builder builder() {
        return new Builder();
    }
    
    public static class Builder {
        private CreateSecretRequest request = new CreateSecretRequest();
        
        public Builder name(String name) {
            request.setName(name);
            return this;
        }
        
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
        
        public CreateSecretRequest build() {
            return request;
        }
    }
}