package com.vaultagent.sdk;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.vaultagent.sdk.auth.APIKeyAuth;
import com.vaultagent.sdk.auth.JWTAuth;
import com.vaultagent.sdk.config.ClientConfig;
import com.vaultagent.sdk.exception.*;
import com.vaultagent.sdk.model.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Duration;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive integration tests for VaultAgentClient
 */
@ExtendWith(MockitoExtension.class)
@Testcontainers
class VaultAgentClientIntegrationTest {

    private WireMockServer wireMockServer;
    private VaultAgentClient client;
    private ClientConfig config;
    private APIKeyAuth auth;

    @BeforeEach
    void setUp() {
        // Start WireMock server
        wireMockServer = new WireMockServer(8089);
        wireMockServer.start();
        WireMock.configureFor("localhost", 8089);

        // Create test configuration
        config = ClientConfig.builder()
                .timeout(Duration.ofSeconds(10))
                .verifySSL(false)
                .maxConnections(5)
                .cacheEnabled(true)
                .cacheTtl(Duration.ofMinutes(5))
                .build();

        // Create authentication
        auth = new APIKeyAuth("test-api-key");

        // Create client
        try {
            client = new VaultAgentClient("http://localhost:8089", auth, config);
        } catch (Exception e) {
            fail("Failed to create client: " + e.getMessage());
        }
    }

    @AfterEach
    void tearDown() {
        if (client != null) {
            try {
                client.close();
            } catch (Exception e) {
                // Ignore cleanup errors
            }
        }
        if (wireMockServer != null) {
            wireMockServer.stop();
        }
    }

    // Secret Management Tests

    @Test
    @DisplayName("Should create secret successfully")
    void testCreateSecretSuccess() throws Exception {
        // Arrange
        stubFor(post(urlEqualTo("/api/v1/secrets"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {
                                    "id": "secret-123",
                                    "name": "test-secret",
                                    "value": "secret-value",
                                    "version": 1,
                                    "created_at": "2023-01-01T00:00:00Z",
                                    "metadata": {"env": "test"},
                                    "tags": ["test"],
                                    "status": "active"
                                }
                                """)));

        CreateSecretRequest request = CreateSecretRequest.builder()
                .name("test-secret")
                .value("secret-value")
                .metadata(Map.of("env", "test"))
                .tags(List.of("test"))
                .build();

        // Act
        Secret secret = client.createSecret(null, request);

        // Assert
        assertNotNull(secret);
        assertEquals("secret-123", secret.getId());
        assertEquals("test-secret", secret.getName());
        assertEquals("secret-value", secret.getValue());
        assertEquals(1, secret.getVersion());
        assertEquals("test", secret.getMetadata().get("env"));
        assertTrue(secret.getTags().contains("test"));
        assertEquals("active", secret.getStatus());

        // Verify request
        verify(postRequestedFor(urlEqualTo("/api/v1/secrets"))
                .withHeader("Authorization", equalTo("Bearer test-api-key"))
                .withHeader("Content-Type", equalTo("application/json")));
    }

    @Test
    @DisplayName("Should handle create secret validation error")
    void testCreateSecretValidationError() {
        // Arrange
        stubFor(post(urlEqualTo("/api/v1/secrets"))
                .willReturn(aResponse()
                        .withStatus(400)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {
                                    "message": "Invalid secret name",
                                    "type": "validation"
                                }
                                """)));

        CreateSecretRequest request = CreateSecretRequest.builder()
                .name("")
                .value("secret-value")
                .build();

        // Act & Assert
        ValidationError exception = assertThrows(ValidationError.class, () -> {
            client.createSecret(null, request);
        });

        assertTrue(exception.getMessage().contains("Invalid secret name"));
    }

    @Test
    @DisplayName("Should get secret successfully")
    void testGetSecretSuccess() throws Exception {
        // Arrange
        stubFor(get(urlEqualTo("/api/v1/secrets/secret-123"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {
                                    "id": "secret-123",
                                    "name": "test-secret",
                                    "value": "secret-value",
                                    "version": 1,
                                    "created_at": "2023-01-01T00:00:00Z",
                                    "access_count": 5,
                                    "last_accessed": "2023-01-01T12:00:00Z"
                                }
                                """)));

        // Act
        Secret secret = client.getSecret(null, "secret-123");

        // Assert
        assertNotNull(secret);
        assertEquals("secret-123", secret.getId());
        assertEquals("test-secret", secret.getName());
        assertEquals("secret-value", secret.getValue());
        assertEquals(5L, secret.getAccessCount());

        // Verify request
        verify(getRequestedFor(urlEqualTo("/api/v1/secrets/secret-123"))
                .withHeader("Authorization", equalTo("Bearer test-api-key")));
    }

    @Test
    @DisplayName("Should handle secret not found error")
    void testGetSecretNotFound() {
        // Arrange
        stubFor(get(urlEqualTo("/api/v1/secrets/nonexistent"))
                .willReturn(aResponse()
                        .withStatus(404)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {
                                    "message": "Secret not found",
                                    "type": "not_found"
                                }
                                """)));

        // Act & Assert
        NotFoundError exception = assertThrows(NotFoundError.class, () -> {
            client.getSecret(null, "nonexistent");
        });

        assertTrue(exception.getMessage().contains("Secret not found"));
    }

    @Test
    @DisplayName("Should update secret successfully")
    void testUpdateSecretSuccess() throws Exception {
        // Arrange
        stubFor(put(urlEqualTo("/api/v1/secrets/secret-123"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {
                                    "id": "secret-123",
                                    "name": "test-secret",
                                    "value": "updated-value",
                                    "version": 2,
                                    "updated_at": "2023-01-01T12:00:00Z"
                                }
                                """)));

        UpdateSecretRequest request = UpdateSecretRequest.builder()
                .value("updated-value")
                .metadata(Map.of("env", "production"))
                .build();

        // Act
        Secret secret = client.updateSecret(null, "secret-123", request);

        // Assert
        assertNotNull(secret);
        assertEquals("secret-123", secret.getId());
        assertEquals("updated-value", secret.getValue());
        assertEquals(2, secret.getVersion());

        // Verify request
        verify(putRequestedFor(urlEqualTo("/api/v1/secrets/secret-123"))
                .withHeader("Authorization", equalTo("Bearer test-api-key")));
    }

    @Test
    @DisplayName("Should delete secret successfully")
    void testDeleteSecretSuccess() throws Exception {
        // Arrange
        stubFor(delete(urlEqualTo("/api/v1/secrets/secret-123"))
                .willReturn(aResponse()
                        .withStatus(200)));

        // Act & Assert
        assertDoesNotThrow(() -> {
            client.deleteSecret(null, "secret-123");
        });

        // Verify request
        verify(deleteRequestedFor(urlEqualTo("/api/v1/secrets/secret-123"))
                .withHeader("Authorization", equalTo("Bearer test-api-key")));
    }

    @Test
    @DisplayName("Should list secrets successfully")
    void testListSecretsSuccess() throws Exception {
        // Arrange
        stubFor(get(urlMatching("/api/v1/secrets.*"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {
                                    "secrets": [
                                        {
                                            "id": "secret-1",
                                            "name": "secret-1",
                                            "version": 1,
                                            "created_at": "2023-01-01T00:00:00Z",
                                            "tags": ["production"],
                                            "status": "active"
                                        },
                                        {
                                            "id": "secret-2",
                                            "name": "secret-2",
                                            "version": 2,
                                            "created_at": "2023-01-01T00:00:00Z",
                                            "tags": ["test"],
                                            "status": "active"
                                        }
                                    ]
                                }
                                """)));

        ListSecretsOptions options = new ListSecretsOptions();
        options.setTags(List.of("test"));
        options.setLimit(10);
        options.setOffset(0);

        // Act
        List<SecretMetadata> secrets = client.listSecrets(null, options);

        // Assert
        assertNotNull(secrets);
        assertEquals(2, secrets.size());
        assertEquals("secret-1", secrets.get(0).getId());
        assertEquals("secret-2", secrets.get(1).getId());
        assertEquals(List.of("production"), secrets.get(0).getTags());
        assertEquals(List.of("test"), secrets.get(1).getTags());

        // Verify request
        verify(getRequestedFor(urlMatching("/api/v1/secrets.*"))
                .withQueryParam("tags", equalTo("test"))
                .withQueryParam("limit", equalTo("10"))
                .withQueryParam("offset", equalTo("0")));
    }

    // Policy Management Tests

    @Test
    @DisplayName("Should create policy successfully")
    void testCreatePolicySuccess() throws Exception {
        // Arrange
        stubFor(post(urlEqualTo("/api/v1/policies"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {
                                    "id": "policy-123",
                                    "name": "test-policy",
                                    "rules": [{"action": "read", "resource": "secrets/*"}],
                                    "enabled": true,
                                    "created_at": "2023-01-01T00:00:00Z"
                                }
                                """)));

        Policy policy = new Policy();
        policy.setName("test-policy");
        policy.setRules(List.of(Map.of("action", "read", "resource", "secrets/*")));
        policy.setEnabled(true);

        // Act
        Policy result = client.createPolicy(null, policy);

        // Assert
        assertNotNull(result);
        assertEquals("policy-123", result.getId());
        assertEquals("test-policy", result.getName());
        assertTrue(result.getEnabled());

        // Verify request
        verify(postRequestedFor(urlEqualTo("/api/v1/policies"))
                .withHeader("Authorization", equalTo("Bearer test-api-key")));
    }

    @Test
    @DisplayName("Should get policy successfully")
    void testGetPolicySuccess() throws Exception {
        // Arrange
        stubFor(get(urlEqualTo("/api/v1/policies/policy-123"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {
                                    "id": "policy-123",
                                    "name": "test-policy",
                                    "rules": [{"action": "read", "resource": "secrets/*"}],
                                    "enabled": true,
                                    "created_at": "2023-01-01T00:00:00Z"
                                }
                                """)));

        // Act
        Policy policy = client.getPolicy(null, "policy-123");

        // Assert
        assertNotNull(policy);
        assertEquals("policy-123", policy.getId());
        assertEquals("test-policy", policy.getName());
        assertTrue(policy.getEnabled());
    }

    // Health and Status Tests

    @Test
    @DisplayName("Should perform health check successfully")
    void testHealthCheckSuccess() throws Exception {
        // Arrange
        stubFor(get(urlEqualTo("/api/v1/health"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {
                                    "status": "healthy",
                                    "version": "1.0.0",
                                    "uptime": 3600,
                                    "database": "connected",
                                    "cache": "enabled"
                                }
                                """)));

        // Act
        VaultStatus status = client.healthCheck(null);

        // Assert
        assertNotNull(status);
        assertEquals("healthy", status.getStatus());
        assertEquals("1.0.0", status.getVersion());
        assertEquals(3600L, status.getUptime());
    }

    @Test
    @DisplayName("Should get metrics successfully")
    void testGetMetricsSuccess() throws Exception {
        // Arrange
        String metricsData = "# HELP vault_requests_total Total requests\nvault_requests_total 100";
        stubFor(get(urlEqualTo("/metrics"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "text/plain")
                        .withBody(metricsData)));

        // Act
        String metrics = client.getMetrics(null);

        // Assert
        assertNotNull(metrics);
        assertTrue(metrics.contains("vault_requests_total 100"));

        // Verify request
        verify(getRequestedFor(urlEqualTo("/metrics"))
                .withHeader("Accept", equalTo("text/plain")));
    }

    // Authentication Tests

    @Test
    @DisplayName("Should handle authentication with JWT")
    void testJWTAuthentication() throws Exception {
        // Arrange
        JWTAuth jwtAuth = new JWTAuth("test-jwt-token");
        VaultAgentClient jwtClient = new VaultAgentClient("http://localhost:8089", jwtAuth, config);

        stubFor(get(urlEqualTo("/api/v1/health"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"status\": \"healthy\"}")));

        // Act
        VaultStatus status = jwtClient.healthCheck(null);

        // Assert
        assertNotNull(status);
        assertEquals("healthy", status.getStatus());

        // Verify JWT token was used
        verify(getRequestedFor(urlEqualTo("/api/v1/health"))
                .withHeader("Authorization", equalTo("Bearer test-jwt-token")));

        jwtClient.close();
    }

    // Error Handling Tests

    @Test
    @DisplayName("Should handle authentication error")
    void testAuthenticationError() {
        // Arrange
        stubFor(get(urlEqualTo("/api/v1/secrets/secret-123"))
                .willReturn(aResponse()
                        .withStatus(401)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {
                                    "message": "Invalid API key",
                                    "type": "authentication"
                                }
                                """)));

        // Act & Assert
        AuthenticationError exception = assertThrows(AuthenticationError.class, () -> {
            client.getSecret(null, "secret-123");
        });

        assertTrue(exception.getMessage().contains("Invalid API key"));
    }

    @Test
    @DisplayName("Should handle authorization error")
    void testAuthorizationError() {
        // Arrange
        stubFor(get(urlEqualTo("/api/v1/secrets/secret-123"))
                .willReturn(aResponse()
                        .withStatus(403)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {
                                    "message": "Insufficient permissions",
                                    "type": "authorization"
                                }
                                """)));

        // Act & Assert
        AuthorizationError exception = assertThrows(AuthorizationError.class, () -> {
            client.getSecret(null, "secret-123");
        });

        assertTrue(exception.getMessage().contains("Insufficient permissions"));
    }

    @Test
    @DisplayName("Should handle rate limit error")
    void testRateLimitError() {
        // Arrange
        stubFor(get(urlEqualTo("/api/v1/secrets/secret-123"))
                .willReturn(aResponse()
                        .withStatus(429)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {
                                    "message": "Rate limit exceeded",
                                    "type": "rate_limit"
                                }
                                """)));

        // Act & Assert
        RateLimitError exception = assertThrows(RateLimitError.class, () -> {
            client.getSecret(null, "secret-123");
        });

        assertTrue(exception.getMessage().contains("Rate limit exceeded"));
    }

    // Async Tests

    @Test
    @DisplayName("Should handle async operations")
    void testAsyncOperations() throws Exception {
        // Arrange
        stubFor(post(urlEqualTo("/api/v1/secrets"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {
                                    "id": "secret-123",
                                    "name": "test-secret",
                                    "value": "secret-value",
                                    "version": 1
                                }
                                """)));

        CreateSecretRequest request = CreateSecretRequest.builder()
                .name("test-secret")
                .value("secret-value")
                .build();

        // Act
        CompletableFuture<Secret> future = client.createSecretAsync(request);
        Secret secret = future.get(5, TimeUnit.SECONDS);

        // Assert
        assertNotNull(secret);
        assertEquals("secret-123", secret.getId());
        assertEquals("test-secret", secret.getName());
    }

    // Caching Tests

    @Test
    @DisplayName("Should cache responses when enabled")
    void testCachingBehavior() throws Exception {
        // Arrange
        stubFor(get(urlEqualTo("/api/v1/secrets/secret-123"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {
                                    "id": "secret-123",
                                    "name": "test-secret",
                                    "value": "secret-value",
                                    "version": 1
                                }
                                """)));

        // Act - Make two requests
        Secret secret1 = client.getSecret(null, "secret-123");
        Secret secret2 = client.getSecret(null, "secret-123");

        // Assert
        assertEquals(secret1.getId(), secret2.getId());
        assertEquals(secret1.getName(), secret2.getName());

        // Verify cache statistics
        Map<String, Object> cacheStats = client.getCacheStats();
        assertNotNull(cacheStats);
    }

    // Retry Logic Tests

    @Test
    @DisplayName("Should retry on server errors")
    void testRetryOnServerError() throws Exception {
        // Arrange - First call fails, second succeeds
        stubFor(get(urlEqualTo("/api/v1/secrets/secret-123"))
                .inScenario("Retry Scenario")
                .whenScenarioStateIs("Started")
                .willReturn(aResponse()
                        .withStatus(500)
                        .withBody("Internal Server Error"))
                .willSetStateTo("First Failure"));

        stubFor(get(urlEqualTo("/api/v1/secrets/secret-123"))
                .inScenario("Retry Scenario")
                .whenScenarioStateIs("First Failure")
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {
                                    "id": "secret-123",
                                    "name": "test-secret",
                                    "value": "secret-value",
                                    "version": 1
                                }
                                """)));

        // Act
        Secret secret = client.getSecret(null, "secret-123");

        // Assert
        assertNotNull(secret);
        assertEquals("secret-123", secret.getId());

        // Verify retry happened
        verify(2, getRequestedFor(urlEqualTo("/api/v1/secrets/secret-123")));
    }

    // Performance Tests

    @Test
    @DisplayName("Should handle concurrent requests")
    void testConcurrentRequests() throws Exception {
        // Arrange
        stubFor(get(urlMatching("/api/v1/secrets.*"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {
                                    "secrets": []
                                }
                                """)));

        ExecutorService executor = Executors.newFixedThreadPool(10);
        List<CompletableFuture<List<SecretMetadata>>> futures = new ArrayList<>();

        // Act - Make 10 concurrent requests
        for (int i = 0; i < 10; i++) {
            CompletableFuture<List<SecretMetadata>> future = CompletableFuture.supplyAsync(() -> {
                try {
                    return client.listSecrets(null, new ListSecretsOptions());
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }, executor);
            futures.add(future);
        }

        // Wait for all requests to complete
        CompletableFuture<Void> allFutures = CompletableFuture.allOf(
                futures.toArray(new CompletableFuture[0])
        );
        allFutures.get(10, TimeUnit.SECONDS);

        // Assert
        for (CompletableFuture<List<SecretMetadata>> future : futures) {
            List<SecretMetadata> result = future.get();
            assertNotNull(result);
        }

        executor.shutdown();
    }

    // Cloud Integration Tests

    @Test
    @DisplayName("Should setup cloud integration")
    void testCloudIntegrationSetup() {
        // Arrange
        Map<String, Object> cloudConfig = new HashMap<>();
        Map<String, Object> awsConfig = new HashMap<>();
        awsConfig.put("region", "us-east-1");
        awsConfig.put("secret_manager_enabled", true);
        cloudConfig.put("aws", awsConfig);

        Map<String, Object> azureConfig = new HashMap<>();
        azureConfig.put("vault_url", "https://test.vault.azure.net/");
        azureConfig.put("enabled", false);
        cloudConfig.put("azure", azureConfig);

        // Act & Assert
        assertDoesNotThrow(() -> {
            client.enableCloudIntegration(cloudConfig);
        });
    }

    // Utility Tests

    @Test
    @DisplayName("Should clear cache")
    void testClearCache() {
        // Act & Assert
        assertDoesNotThrow(() -> {
            client.clearCache();
        });
    }

    @Test
    @DisplayName("Should get cache statistics")
    void testGetCacheStatistics() {
        // Act
        Map<String, Object> stats = client.getCacheStats();

        // Assert
        if (config.isCacheEnabled()) {
            assertNotNull(stats);
        } else {
            assertNull(stats);
        }
    }
}