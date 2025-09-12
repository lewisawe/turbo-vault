package com.vaultagent.sdk;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.vaultagent.sdk.auth.AuthMethod;
import com.vaultagent.sdk.cloud.CloudIntegration;
import com.vaultagent.sdk.config.ClientConfig;
import com.vaultagent.sdk.exception.*;
import com.vaultagent.sdk.model.*;
import okhttp3.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * Main client for interacting with Vault Agent instances.
 * 
 * Supports both synchronous and asynchronous operations with comprehensive
 * error handling, retry logic, and connection pooling.
 */
public class VaultAgentClient implements AutoCloseable {
    
    private static final Logger logger = LoggerFactory.getLogger(VaultAgentClient.class);
    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");
    
    private final OkHttpClient httpClient;
    private final String baseUrl;
    private final AuthMethod auth;
    private final ClientConfig config;
    private final ObjectMapper objectMapper;
    private final Cache<String, Object> cache;
    private CloudIntegration cloudIntegration;
    
    public VaultAgentClient(String baseUrl, AuthMethod auth, ClientConfig config) {
        this.baseUrl = baseUrl.replaceAll("/$", "");
        this.auth = auth;
        this.config = config;
        
        // Initialize ObjectMapper
        this.objectMapper = new ObjectMapper();
        this.objectMapper.registerModule(new JavaTimeModule());
        
        // Initialize cache
        if (config.isCacheEnabled()) {
            this.cache = Caffeine.newBuilder()
                .maximumSize(config.getCacheMaxSize())
                .expireAfterWrite(config.getCacheTtl())
                .build();
        } else {
            this.cache = null;
        }
        
        // Initialize HTTP client
        this.httpClient = createHttpClient();
        
        logger.info("VaultAgentClient initialized for URL: {}", baseUrl);
    }
    
    private OkHttpClient createHttpClient() {
        OkHttpClient.Builder builder = new OkHttpClient.Builder()
            .connectTimeout(config.getTimeout())
            .readTimeout(config.getTimeout())
            .writeTimeout(config.getTimeout())
            .connectionPool(new ConnectionPool(
                config.getMaxConnections(),
                5,
                TimeUnit.MINUTES
            ));
        
        // Configure TLS
        if (!config.isVerifySSL()) {
            try {
                final TrustManager[] trustAllCerts = new TrustManager[] {
                    new X509TrustManager() {
                        @Override
                        public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                        
                        @Override
                        public void checkServerTrusted(X509Certificate[] chain, String authType) {}
                        
                        @Override
                        public X509Certificate[] getAcceptedIssuers() {
                            return new X509Certificate[]{};
                        }
                    }
                };
                
                final SSLContext sslContext = SSLContext.getInstance("SSL");
                sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
                
                builder.sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager) trustAllCerts[0]);
                builder.hostnameVerifier((hostname, session) -> true);
            } catch (Exception e) {
                logger.warn("Failed to configure SSL bypass", e);
            }
        }
        
        // Add authentication interceptor
        builder.addInterceptor(new AuthInterceptor());
        
        // Add retry interceptor
        builder.addInterceptor(new RetryInterceptor());
        
        return builder.build();
    }
    
    /**
     * Enable cloud integration for hybrid deployments
     */
    public void enableCloudIntegration(Map<String, Object> config) {
        this.cloudIntegration = new CloudIntegration(config);
    }
    
    // Secret Management Methods
    
    /**
     * Create a new secret
     */
    public Secret createSecret(CreateSecretRequest request) throws VaultAgentException {
        logger.info("Creating secret: {}", request.getName());
        
        try {
            String json = objectMapper.writeValueAsString(request);
            RequestBody body = RequestBody.create(json, JSON);
            
            Request httpRequest = new Request.Builder()
                .url(baseUrl + "/api/v1/secrets")
                .post(body)
                .build();
            
            try (Response response = httpClient.newCall(httpRequest).execute()) {
                handleErrorResponse(response);
                
                Secret secret = objectMapper.readValue(response.body().string(), Secret.class);
                
                // Sync to cloud providers if enabled
                if (cloudIntegration != null && cloudIntegration.isEnabled()) {
                    try {
                        cloudIntegration.syncSecret(secret.getName(), secret.getValue());
                    } catch (Exception e) {
                        logger.warn("Failed to sync secret to cloud providers", e);
                    }
                }
                
                invalidateCache("secrets");
                return secret;
            }
        } catch (IOException e) {
            throw new ConnectionError("Failed to create secret", e);
        }
    }
    
    /**
     * Create a new secret (async)
     */
    public CompletableFuture<Secret> createSecretAsync(CreateSecretRequest request) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return createSecret(request);
            } catch (VaultAgentException e) {
                throw new RuntimeException(e);
            }
        });
    }
    
    /**
     * Create a new secret (reactive)
     */
    public Mono<Secret> createSecretReactive(CreateSecretRequest request) {
        return Mono.fromCallable(() -> createSecret(request));
    }
    
    /**
     * Get a secret by ID
     */
    public Secret getSecret(String secretId) throws VaultAgentException {
        String cacheKey = "secret:" + secretId;
        
        if (cache != null) {
            Secret cached = (Secret) cache.getIfPresent(cacheKey);
            if (cached != null) {
                logger.debug("Cache hit for key: {}", cacheKey);
                return cached;
            }
        }
        
        logger.info("Getting secret: {}", secretId);
        
        try {
            Request request = new Request.Builder()
                .url(baseUrl + "/api/v1/secrets/" + secretId)
                .get()
                .build();
            
            try (Response response = httpClient.newCall(request).execute()) {
                handleErrorResponse(response);
                
                Secret secret = objectMapper.readValue(response.body().string(), Secret.class);
                
                if (cache != null) {
                    cache.put(cacheKey, secret);
                    logger.debug("Cache set for key: {}", cacheKey);
                }
                
                return secret;
            }
        } catch (IOException e) {
            throw new ConnectionError("Failed to get secret", e);
        }
    }
    
    /**
     * Get a secret by ID (async)
     */
    public CompletableFuture<Secret> getSecretAsync(String secretId) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return getSecret(secretId);
            } catch (VaultAgentException e) {
                throw new RuntimeException(e);
            }
        });
    }
    
    /**
     * Get a secret by ID (reactive)
     */
    public Mono<Secret> getSecretReactive(String secretId) {
        return Mono.fromCallable(() -> getSecret(secretId));
    }
    
    /**
     * Update an existing secret
     */
    public Secret updateSecret(String secretId, UpdateSecretRequest request) throws VaultAgentException {
        logger.info("Updating secret: {}", secretId);
        
        try {
            String json = objectMapper.writeValueAsString(request);
            RequestBody body = RequestBody.create(json, JSON);
            
            Request httpRequest = new Request.Builder()
                .url(baseUrl + "/api/v1/secrets/" + secretId)
                .put(body)
                .build();
            
            try (Response response = httpClient.newCall(httpRequest).execute()) {
                handleErrorResponse(response);
                
                Secret secret = objectMapper.readValue(response.body().string(), Secret.class);
                
                // Sync to cloud providers if enabled
                if (cloudIntegration != null && cloudIntegration.isEnabled() && request.getValue() != null) {
                    try {
                        cloudIntegration.syncSecret(secret.getName(), request.getValue());
                    } catch (Exception e) {
                        logger.warn("Failed to sync updated secret to cloud providers", e);
                    }
                }
                
                invalidateCache("secret:" + secretId);
                invalidateCache("secrets");
                return secret;
            }
        } catch (IOException e) {
            throw new ConnectionError("Failed to update secret", e);
        }
    }
    
    /**
     * Delete a secret
     */
    public void deleteSecret(String secretId) throws VaultAgentException {
        logger.info("Deleting secret: {}", secretId);
        
        // Get secret name for cloud sync
        String secretName = null;
        if (cloudIntegration != null && cloudIntegration.isEnabled()) {
            try {
                Secret secret = getSecret(secretId);
                secretName = secret.getName();
            } catch (Exception e) {
                logger.warn("Failed to get secret name for cloud deletion", e);
            }
        }
        
        try {
            Request request = new Request.Builder()
                .url(baseUrl + "/api/v1/secrets/" + secretId)
                .delete()
                .build();
            
            try (Response response = httpClient.newCall(request).execute()) {
                handleErrorResponse(response);
                
                // Delete from cloud providers if enabled
                if (cloudIntegration != null && cloudIntegration.isEnabled() && secretName != null) {
                    try {
                        cloudIntegration.deleteSecret(secretName);
                    } catch (Exception e) {
                        logger.warn("Failed to delete secret from cloud providers", e);
                    }
                }
                
                invalidateCache("secret:" + secretId);
                invalidateCache("secrets");
            }
        } catch (IOException e) {
            throw new ConnectionError("Failed to delete secret", e);
        }
    }
    
    /**
     * List secrets (metadata only)
     */
    public List<SecretMetadata> listSecrets(ListSecretsOptions options) throws VaultAgentException {
        String cacheKey = "secrets:" + options.toString();
        
        if (cache != null) {
            @SuppressWarnings("unchecked")
            List<SecretMetadata> cached = (List<SecretMetadata>) cache.getIfPresent(cacheKey);
            if (cached != null) {
                logger.debug("Cache hit for key: {}", cacheKey);
                return cached;
            }
        }
        
        logger.info("Listing secrets");
        
        try {
            HttpUrl.Builder urlBuilder = HttpUrl.parse(baseUrl + "/api/v1/secrets").newBuilder();
            
            if (options.getTags() != null && !options.getTags().isEmpty()) {
                urlBuilder.addQueryParameter("tags", String.join(",", options.getTags()));
            }
            if (options.getLimit() != null) {
                urlBuilder.addQueryParameter("limit", options.getLimit().toString());
            }
            if (options.getOffset() != null) {
                urlBuilder.addQueryParameter("offset", options.getOffset().toString());
            }
            
            Request request = new Request.Builder()
                .url(urlBuilder.build())
                .get()
                .build();
            
            try (Response response = httpClient.newCall(request).execute()) {
                handleErrorResponse(response);
                
                SecretsResponse secretsResponse = objectMapper.readValue(
                    response.body().string(), 
                    SecretsResponse.class
                );
                
                List<SecretMetadata> secrets = secretsResponse.getSecrets();
                
                if (cache != null) {
                    cache.put(cacheKey, secrets);
                    logger.debug("Cache set for key: {}", cacheKey);
                }
                
                return secrets;
            }
        } catch (IOException e) {
            throw new ConnectionError("Failed to list secrets", e);
        }
    }
    
    /**
     * List secrets (reactive)
     */
    public Flux<SecretMetadata> listSecretsReactive(ListSecretsOptions options) {
        return Mono.fromCallable(() -> listSecrets(options))
            .flatMapMany(Flux::fromIterable);
    }
    
    // Policy Management Methods
    
    /**
     * Create a new policy
     */
    public Policy createPolicy(Policy policy) throws VaultAgentException {
        logger.info("Creating policy: {}", policy.getName());
        
        try {
            String json = objectMapper.writeValueAsString(policy);
            RequestBody body = RequestBody.create(json, JSON);
            
            Request request = new Request.Builder()
                .url(baseUrl + "/api/v1/policies")
                .post(body)
                .build();
            
            try (Response response = httpClient.newCall(request).execute()) {
                handleErrorResponse(response);
                
                Policy result = objectMapper.readValue(response.body().string(), Policy.class);
                invalidateCache("policies");
                return result;
            }
        } catch (IOException e) {
            throw new ConnectionError("Failed to create policy", e);
        }
    }
    
    /**
     * Get a policy by ID
     */
    public Policy getPolicy(String policyId) throws VaultAgentException {
        String cacheKey = "policy:" + policyId;
        
        if (cache != null) {
            Policy cached = (Policy) cache.getIfPresent(cacheKey);
            if (cached != null) {
                logger.debug("Cache hit for key: {}", cacheKey);
                return cached;
            }
        }
        
        logger.info("Getting policy: {}", policyId);
        
        try {
            Request request = new Request.Builder()
                .url(baseUrl + "/api/v1/policies/" + policyId)
                .get()
                .build();
            
            try (Response response = httpClient.newCall(request).execute()) {
                handleErrorResponse(response);
                
                Policy policy = objectMapper.readValue(response.body().string(), Policy.class);
                
                if (cache != null) {
                    cache.put(cacheKey, policy);
                    logger.debug("Cache set for key: {}", cacheKey);
                }
                
                return policy;
            }
        } catch (IOException e) {
            throw new ConnectionError("Failed to get policy", e);
        }
    }
    
    // Health and Status Methods
    
    /**
     * Check vault agent health
     */
    public VaultStatus healthCheck() throws VaultAgentException {
        logger.debug("Performing health check");
        
        try {
            Request request = new Request.Builder()
                .url(baseUrl + "/api/v1/health")
                .get()
                .build();
            
            try (Response response = httpClient.newCall(request).execute()) {
                handleErrorResponse(response);
                return objectMapper.readValue(response.body().string(), VaultStatus.class);
            }
        } catch (IOException e) {
            throw new ConnectionError("Failed to perform health check", e);
        }
    }
    
    /**
     * Get Prometheus metrics
     */
    public String getMetrics() throws VaultAgentException {
        logger.debug("Getting metrics");
        
        try {
            Request request = new Request.Builder()
                .url(baseUrl + "/metrics")
                .header("Accept", "text/plain")
                .get()
                .build();
            
            try (Response response = httpClient.newCall(request).execute()) {
                handleErrorResponse(response);
                return response.body().string();
            }
        } catch (IOException e) {
            throw new ConnectionError("Failed to get metrics", e);
        }
    }
    
    // Utility Methods
    
    /**
     * Clear all cached data
     */
    public void clearCache() {
        if (cache != null) {
            cache.invalidateAll();
            logger.info("Cache cleared");
        }
    }
    
    /**
     * Get cache statistics
     */
    public Map<String, Object> getCacheStats() {
        if (cache == null) {
            return null;
        }
        
        return Map.of(
            "size", cache.estimatedSize(),
            "hitCount", cache.stats().hitCount(),
            "missCount", cache.stats().missCount(),
            "hitRate", cache.stats().hitRate()
        );
    }
    
    @Override
    public void close() {
        if (cache != null) {
            cache.invalidateAll();
        }
        httpClient.dispatcher().executorService().shutdown();
        httpClient.connectionPool().evictAll();
        logger.info("Client closed");
    }
    
    // Private helper methods
    
    private void handleErrorResponse(Response response) throws VaultAgentException {
        if (response.isSuccessful()) {
            return;
        }
        
        String requestId = response.header("X-Request-ID");
        String errorBody;
        
        try {
            errorBody = response.body().string();
        } catch (IOException e) {
            errorBody = "Unknown error";
        }
        
        Map<String, Object> errorData;
        try {
            errorData = objectMapper.readValue(errorBody, Map.class);
        } catch (Exception e) {
            errorData = Map.of("message", errorBody);
        }
        
        String message = (String) errorData.getOrDefault("message", "Unknown error");
        
        switch (response.code()) {
            case 401:
                throw new AuthenticationError(message, requestId);
            case 403:
                throw new AuthorizationError(message, requestId);
            case 404:
                throw new NotFoundError(message, requestId);
            case 400:
                throw new ValidationError(message, requestId);
            case 429:
                throw new RateLimitError(message, requestId);
            default:
                throw new VaultAgentException("HTTP " + response.code() + ": " + message, requestId);
        }
    }
    
    private void invalidateCache(String pattern) {
        if (cache == null) {
            return;
        }
        
        cache.asMap().keySet().removeIf(key -> key.contains(pattern));
        logger.debug("Invalidated cache entries matching: {}", pattern);
    }
    
    // Inner classes for interceptors
    
    private class AuthInterceptor implements Interceptor {
        @Override
        public Response intercept(Chain chain) throws IOException {
            Request original = chain.request();
            
            try {
                Map<String, String> authHeaders = auth.getHeaders();
                Request.Builder builder = original.newBuilder();
                
                for (Map.Entry<String, String> entry : authHeaders.entrySet()) {
                    builder.header(entry.getKey(), entry.getValue());
                }
                
                return chain.proceed(builder.build());
            } catch (Exception e) {
                throw new IOException("Failed to add authentication headers", e);
            }
        }
    }
    
    private class RetryInterceptor implements Interceptor {
        @Override
        public Response intercept(Chain chain) throws IOException {
            Request request = chain.request();
            Response response = null;
            IOException lastException = null;
            
            for (int attempt = 0; attempt < config.getRetry().getMaxAttempts(); attempt++) {
                try {
                    if (response != null) {
                        response.close();
                    }
                    
                    response = chain.proceed(request);
                    
                    if (response.isSuccessful() || !isRetryableStatus(response.code())) {
                        return response;
                    }
                    
                    if (attempt < config.getRetry().getMaxAttempts() - 1) {
                        long delay = calculateDelay(attempt);
                        try {
                            Thread.sleep(delay);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            throw new IOException("Retry interrupted", e);
                        }
                    }
                } catch (IOException e) {
                    lastException = e;
                    if (attempt < config.getRetry().getMaxAttempts() - 1) {
                        long delay = calculateDelay(attempt);
                        try {
                            Thread.sleep(delay);
                        } catch (InterruptedException ie) {
                            Thread.currentThread().interrupt();
                            throw new IOException("Retry interrupted", ie);
                        }
                    }
                }
            }
            
            if (response != null) {
                return response;
            } else {
                throw lastException;
            }
        }
        
        private boolean isRetryableStatus(int statusCode) {
            return config.getRetry().getRetryableStatusCodes().contains(statusCode);
        }
        
        private long calculateDelay(int attempt) {
            long delay = (long) (config.getRetry().getInitialDelay().toMillis() * 
                Math.pow(config.getRetry().getBackoffFactor(), attempt));
            delay = Math.min(delay, config.getRetry().getMaxDelay().toMillis());
            
            // Add jitter
            long jitter = (long) (Math.random() * delay * 0.1);
            return delay + jitter;
        }
    }
}