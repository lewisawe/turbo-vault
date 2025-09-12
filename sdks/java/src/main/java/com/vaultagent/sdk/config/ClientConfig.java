package com.vaultagent.sdk.config;

import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * Configuration class for VaultAgentClient
 */
public class ClientConfig {
    
    private Duration timeout = Duration.ofSeconds(30);
    private boolean verifySSL = true;
    private int maxConnections = 10;
    private String userAgent = "VaultAgent-Java-SDK/1.0.0";
    private Map<String, String> defaultHeaders = Map.of();
    private String logLevel = "INFO";
    
    // Cache configuration
    private boolean cacheEnabled = true;
    private Duration cacheTtl = Duration.ofMinutes(5);
    private int cacheMaxSize = 1000;
    
    // Retry configuration
    private RetryConfig retry = new RetryConfig();
    
    public static class RetryConfig {
        private int maxAttempts = 3;
        private Duration initialDelay = Duration.ofSeconds(1);
        private Duration maxDelay = Duration.ofSeconds(30);
        private double backoffFactor = 2.0;
        private List<Integer> retryableStatusCodes = Arrays.asList(500, 502, 503, 504, 408, 429);
        
        // Getters and setters
        public int getMaxAttempts() { return maxAttempts; }
        public void setMaxAttempts(int maxAttempts) { this.maxAttempts = maxAttempts; }
        
        public Duration getInitialDelay() { return initialDelay; }
        public void setInitialDelay(Duration initialDelay) { this.initialDelay = initialDelay; }
        
        public Duration getMaxDelay() { return maxDelay; }
        public void setMaxDelay(Duration maxDelay) { this.maxDelay = maxDelay; }
        
        public double getBackoffFactor() { return backoffFactor; }
        public void setBackoffFactor(double backoffFactor) { this.backoffFactor = backoffFactor; }
        
        public List<Integer> getRetryableStatusCodes() { return retryableStatusCodes; }
        public void setRetryableStatusCodes(List<Integer> retryableStatusCodes) { 
            this.retryableStatusCodes = retryableStatusCodes; 
        }
    }
    
    // Getters and setters
    public Duration getTimeout() { return timeout; }
    public void setTimeout(Duration timeout) { this.timeout = timeout; }
    
    public boolean isVerifySSL() { return verifySSL; }
    public void setVerifySSL(boolean verifySSL) { this.verifySSL = verifySSL; }
    
    public int getMaxConnections() { return maxConnections; }
    public void setMaxConnections(int maxConnections) { this.maxConnections = maxConnections; }
    
    public String getUserAgent() { return userAgent; }
    public void setUserAgent(String userAgent) { this.userAgent = userAgent; }
    
    public Map<String, String> getDefaultHeaders() { return defaultHeaders; }
    public void setDefaultHeaders(Map<String, String> defaultHeaders) { this.defaultHeaders = defaultHeaders; }
    
    public String getLogLevel() { return logLevel; }
    public void setLogLevel(String logLevel) { this.logLevel = logLevel; }
    
    public boolean isCacheEnabled() { return cacheEnabled; }
    public void setCacheEnabled(boolean cacheEnabled) { this.cacheEnabled = cacheEnabled; }
    
    public Duration getCacheTtl() { return cacheTtl; }
    public void setCacheTtl(Duration cacheTtl) { this.cacheTtl = cacheTtl; }
    
    public int getCacheMaxSize() { return cacheMaxSize; }
    public void setCacheMaxSize(int cacheMaxSize) { this.cacheMaxSize = cacheMaxSize; }
    
    public RetryConfig getRetry() { return retry; }
    public void setRetry(RetryConfig retry) { this.retry = retry; }
    
    /**
     * Create a builder for ClientConfig
     */
    public static Builder builder() {
        return new Builder();
    }
    
    public static class Builder {
        private ClientConfig config = new ClientConfig();
        
        public Builder timeout(Duration timeout) {
            config.setTimeout(timeout);
            return this;
        }
        
        public Builder verifySSL(boolean verifySSL) {
            config.setVerifySSL(verifySSL);
            return this;
        }
        
        public Builder maxConnections(int maxConnections) {
            config.setMaxConnections(maxConnections);
            return this;
        }
        
        public Builder userAgent(String userAgent) {
            config.setUserAgent(userAgent);
            return this;
        }
        
        public Builder defaultHeaders(Map<String, String> defaultHeaders) {
            config.setDefaultHeaders(defaultHeaders);
            return this;
        }
        
        public Builder logLevel(String logLevel) {
            config.setLogLevel(logLevel);
            return this;
        }
        
        public Builder cacheEnabled(boolean cacheEnabled) {
            config.setCacheEnabled(cacheEnabled);
            return this;
        }
        
        public Builder cacheTtl(Duration cacheTtl) {
            config.setCacheTtl(cacheTtl);
            return this;
        }
        
        public Builder cacheMaxSize(int cacheMaxSize) {
            config.setCacheMaxSize(cacheMaxSize);
            return this;
        }
        
        public Builder retry(RetryConfig retry) {
            config.setRetry(retry);
            return this;
        }
        
        public ClientConfig build() {
            return config;
        }
    }
}