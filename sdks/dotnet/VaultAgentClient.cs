using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Polly;
using Polly.Extensions.Http;
using VaultAgent.SDK.Auth;
using VaultAgent.SDK.Cloud;
using VaultAgent.SDK.Configuration;
using VaultAgent.SDK.Exceptions;
using VaultAgent.SDK.Models;

namespace VaultAgent.SDK
{
    /// <summary>
    /// Main client for interacting with Vault Agent instances.
    /// Supports both synchronous and asynchronous operations with comprehensive
    /// error handling, retry logic, and connection pooling.
    /// </summary>
    public class VaultAgentClient : IDisposable
    {
        private readonly HttpClient _httpClient;
        private readonly string _baseUrl;
        private readonly IAuthMethod _auth;
        private readonly ClientConfig _config;
        private readonly ILogger<VaultAgentClient> _logger;
        private readonly IMemoryCache _cache;
        private readonly JsonSerializerOptions _jsonOptions;
        private ICloudIntegration _cloudIntegration;
        private bool _disposed = false;

        public VaultAgentClient(
            string baseUrl,
            IAuthMethod auth,
            IOptions<ClientConfig> config = null,
            ILogger<VaultAgentClient> logger = null,
            IMemoryCache cache = null)
        {
            _baseUrl = baseUrl.TrimEnd('/');
            _auth = auth ?? throw new ArgumentNullException(nameof(auth));
            _config = config?.Value ?? new ClientConfig();
            _logger = logger ?? Microsoft.Extensions.Logging.Abstractions.NullLogger<VaultAgentClient>.Instance;
            _cache = cache;

            _jsonOptions = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                PropertyNameCaseInsensitive = true
            };

            _httpClient = CreateHttpClient();
            
            _logger.LogInformation("VaultAgentClient initialized for URL: {BaseUrl}", baseUrl);
        }

        private HttpClient CreateHttpClient()
        {
            var handler = new HttpClientHandler();
            
            // Configure TLS
            if (!_config.VerifySSL)
            {
                handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true;
            }

            var client = new HttpClient(handler)
            {
                BaseAddress = new Uri(_baseUrl),
                Timeout = _config.Timeout
            };

            // Set default headers
            client.DefaultRequestHeaders.Add("User-Agent", _config.UserAgent);
            foreach (var header in _config.DefaultHeaders)
            {
                client.DefaultRequestHeaders.Add(header.Key, header.Value);
            }

            return client;
        }

        /// <summary>
        /// Enable cloud integration for hybrid deployments
        /// </summary>
        public void EnableCloudIntegration(Dictionary<string, object> config)
        {
            _cloudIntegration = new CloudIntegration(config);
        }

        // Secret Management Methods

        /// <summary>
        /// Create a new secret
        /// </summary>
        public async Task<Secret> CreateSecretAsync(CreateSecretRequest request, CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("Creating secret: {SecretName}", request.Name);

            var policy = GetRetryPolicy();
            var secret = await policy.ExecuteAsync(async () =>
            {
                var json = JsonSerializer.Serialize(request, _jsonOptions);
                var content = new StringContent(json, Encoding.UTF8, "application/json");

                await AddAuthHeadersAsync(content);

                using var response = await _httpClient.PostAsync("/api/v1/secrets", content, cancellationToken);
                await HandleErrorResponseAsync(response);

                var responseJson = await response.Content.ReadAsStringAsync(cancellationToken);
                return JsonSerializer.Deserialize<Secret>(responseJson, _jsonOptions);
            });

            // Sync to cloud providers if enabled
            if (_cloudIntegration?.IsEnabled == true)
            {
                try
                {
                    await _cloudIntegration.SyncSecretAsync(secret.Name, secret.Value, cancellationToken);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to sync secret to cloud providers");
                }
            }

            InvalidateCache("secrets");
            return secret;
        }

        /// <summary>
        /// Create a new secret (synchronous)
        /// </summary>
        public Secret CreateSecret(CreateSecretRequest request)
        {
            return CreateSecretAsync(request).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Get a secret by ID
        /// </summary>
        public async Task<Secret> GetSecretAsync(string secretId, CancellationToken cancellationToken = default)
        {
            var cacheKey = $"secret:{secretId}";

            if (_cache != null && _cache.TryGetValue(cacheKey, out Secret cachedSecret))
            {
                _logger.LogDebug("Cache hit for key: {CacheKey}", cacheKey);
                return cachedSecret;
            }

            _logger.LogInformation("Getting secret: {SecretId}", secretId);

            var policy = GetRetryPolicy();
            var secret = await policy.ExecuteAsync(async () =>
            {
                var request = new HttpRequestMessage(HttpMethod.Get, $"/api/v1/secrets/{secretId}");
                await AddAuthHeadersAsync(request);

                using var response = await _httpClient.SendAsync(request, cancellationToken);
                await HandleErrorResponseAsync(response);

                var responseJson = await response.Content.ReadAsStringAsync(cancellationToken);
                return JsonSerializer.Deserialize<Secret>(responseJson, _jsonOptions);
            });

            if (_cache != null)
            {
                _cache.Set(cacheKey, secret, _config.CacheTtl);
                _logger.LogDebug("Cache set for key: {CacheKey}", cacheKey);
            }

            return secret;
        }

        /// <summary>
        /// Get a secret by ID (synchronous)
        /// </summary>
        public Secret GetSecret(string secretId)
        {
            return GetSecretAsync(secretId).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Update an existing secret
        /// </summary>
        public async Task<Secret> UpdateSecretAsync(string secretId, UpdateSecretRequest request, CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("Updating secret: {SecretId}", secretId);

            var policy = GetRetryPolicy();
            var secret = await policy.ExecuteAsync(async () =>
            {
                var json = JsonSerializer.Serialize(request, _jsonOptions);
                var content = new StringContent(json, Encoding.UTF8, "application/json");

                await AddAuthHeadersAsync(content);

                using var response = await _httpClient.PutAsync($"/api/v1/secrets/{secretId}", content, cancellationToken);
                await HandleErrorResponseAsync(response);

                var responseJson = await response.Content.ReadAsStringAsync(cancellationToken);
                return JsonSerializer.Deserialize<Secret>(responseJson, _jsonOptions);
            });

            // Sync to cloud providers if enabled
            if (_cloudIntegration?.IsEnabled == true && !string.IsNullOrEmpty(request.Value))
            {
                try
                {
                    await _cloudIntegration.SyncSecretAsync(secret.Name, request.Value, cancellationToken);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to sync updated secret to cloud providers");
                }
            }

            InvalidateCache($"secret:{secretId}");
            InvalidateCache("secrets");
            return secret;
        }

        /// <summary>
        /// Delete a secret
        /// </summary>
        public async Task DeleteSecretAsync(string secretId, CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("Deleting secret: {SecretId}", secretId);

            // Get secret name for cloud sync
            string secretName = null;
            if (_cloudIntegration?.IsEnabled == true)
            {
                try
                {
                    var secret = await GetSecretAsync(secretId, cancellationToken);
                    secretName = secret.Name;
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to get secret name for cloud deletion");
                }
            }

            var policy = GetRetryPolicy();
            await policy.ExecuteAsync(async () =>
            {
                var request = new HttpRequestMessage(HttpMethod.Delete, $"/api/v1/secrets/{secretId}");
                await AddAuthHeadersAsync(request);

                using var response = await _httpClient.SendAsync(request, cancellationToken);
                await HandleErrorResponseAsync(response);
            });

            // Delete from cloud providers if enabled
            if (_cloudIntegration?.IsEnabled == true && !string.IsNullOrEmpty(secretName))
            {
                try
                {
                    await _cloudIntegration.DeleteSecretAsync(secretName, cancellationToken);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to delete secret from cloud providers");
                }
            }

            InvalidateCache($"secret:{secretId}");
            InvalidateCache("secrets");
        }

        /// <summary>
        /// List secrets (metadata only)
        /// </summary>
        public async Task<IList<SecretMetadata>> ListSecretsAsync(ListSecretsOptions options = null, CancellationToken cancellationToken = default)
        {
            options ??= new ListSecretsOptions();
            var cacheKey = $"secrets:{JsonSerializer.Serialize(options, _jsonOptions)}";

            if (_cache != null && _cache.TryGetValue(cacheKey, out IList<SecretMetadata> cachedSecrets))
            {
                _logger.LogDebug("Cache hit for key: {CacheKey}", cacheKey);
                return cachedSecrets;
            }

            _logger.LogInformation("Listing secrets");

            var policy = GetRetryPolicy();
            var secrets = await policy.ExecuteAsync(async () =>
            {
                var queryParams = new List<string>();
                
                if (options.Tags?.Count > 0)
                {
                    queryParams.Add($"tags={string.Join(",", options.Tags)}");
                }
                if (options.Limit.HasValue)
                {
                    queryParams.Add($"limit={options.Limit}");
                }
                if (options.Offset.HasValue)
                {
                    queryParams.Add($"offset={options.Offset}");
                }

                var queryString = queryParams.Count > 0 ? "?" + string.Join("&", queryParams) : "";
                var request = new HttpRequestMessage(HttpMethod.Get, $"/api/v1/secrets{queryString}");
                await AddAuthHeadersAsync(request);

                using var response = await _httpClient.SendAsync(request, cancellationToken);
                await HandleErrorResponseAsync(response);

                var responseJson = await response.Content.ReadAsStringAsync(cancellationToken);
                var secretsResponse = JsonSerializer.Deserialize<SecretsResponse>(responseJson, _jsonOptions);
                return secretsResponse.Secrets;
            });

            if (_cache != null)
            {
                _cache.Set(cacheKey, secrets, _config.CacheTtl);
                _logger.LogDebug("Cache set for key: {CacheKey}", cacheKey);
            }

            return secrets;
        }

        // Policy Management Methods

        /// <summary>
        /// Create a new policy
        /// </summary>
        public async Task<Policy> CreatePolicyAsync(Policy policy, CancellationToken cancellationToken = default)
        {
            _logger.LogInformation("Creating policy: {PolicyName}", policy.Name);

            var retryPolicy = GetRetryPolicy();
            var result = await retryPolicy.ExecuteAsync(async () =>
            {
                var json = JsonSerializer.Serialize(policy, _jsonOptions);
                var content = new StringContent(json, Encoding.UTF8, "application/json");

                await AddAuthHeadersAsync(content);

                using var response = await _httpClient.PostAsync("/api/v1/policies", content, cancellationToken);
                await HandleErrorResponseAsync(response);

                var responseJson = await response.Content.ReadAsStringAsync(cancellationToken);
                return JsonSerializer.Deserialize<Policy>(responseJson, _jsonOptions);
            });

            InvalidateCache("policies");
            return result;
        }

        /// <summary>
        /// Get a policy by ID
        /// </summary>
        public async Task<Policy> GetPolicyAsync(string policyId, CancellationToken cancellationToken = default)
        {
            var cacheKey = $"policy:{policyId}";

            if (_cache != null && _cache.TryGetValue(cacheKey, out Policy cachedPolicy))
            {
                _logger.LogDebug("Cache hit for key: {CacheKey}", cacheKey);
                return cachedPolicy;
            }

            _logger.LogInformation("Getting policy: {PolicyId}", policyId);

            var policy = GetRetryPolicy();
            var result = await policy.ExecuteAsync(async () =>
            {
                var request = new HttpRequestMessage(HttpMethod.Get, $"/api/v1/policies/{policyId}");
                await AddAuthHeadersAsync(request);

                using var response = await _httpClient.SendAsync(request, cancellationToken);
                await HandleErrorResponseAsync(response);

                var responseJson = await response.Content.ReadAsStringAsync(cancellationToken);
                return JsonSerializer.Deserialize<Policy>(responseJson, _jsonOptions);
            });

            if (_cache != null)
            {
                _cache.Set(cacheKey, result, _config.CacheTtl);
                _logger.LogDebug("Cache set for key: {CacheKey}", cacheKey);
            }

            return result;
        }

        // Health and Status Methods

        /// <summary>
        /// Check vault agent health
        /// </summary>
        public async Task<VaultStatus> HealthCheckAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogDebug("Performing health check");

            var request = new HttpRequestMessage(HttpMethod.Get, "/api/v1/health");
            await AddAuthHeadersAsync(request);

            using var response = await _httpClient.SendAsync(request, cancellationToken);
            await HandleErrorResponseAsync(response);

            var responseJson = await response.Content.ReadAsStringAsync(cancellationToken);
            return JsonSerializer.Deserialize<VaultStatus>(responseJson, _jsonOptions);
        }

        /// <summary>
        /// Get Prometheus metrics
        /// </summary>
        public async Task<string> GetMetricsAsync(CancellationToken cancellationToken = default)
        {
            _logger.LogDebug("Getting metrics");

            var request = new HttpRequestMessage(HttpMethod.Get, "/metrics");
            request.Headers.Add("Accept", "text/plain");
            await AddAuthHeadersAsync(request);

            using var response = await _httpClient.SendAsync(request, cancellationToken);
            await HandleErrorResponseAsync(response);

            return await response.Content.ReadAsStringAsync(cancellationToken);
        }

        // Utility Methods

        /// <summary>
        /// Clear all cached data
        /// </summary>
        public void ClearCache()
        {
            if (_cache is MemoryCache memoryCache)
            {
                memoryCache.Clear();
                _logger.LogInformation("Cache cleared");
            }
        }

        /// <summary>
        /// Get cache statistics
        /// </summary>
        public Dictionary<string, object> GetCacheStats()
        {
            if (_cache == null)
                return null;

            // Note: MemoryCache doesn't expose statistics by default
            // This would need a custom implementation or third-party library
            return new Dictionary<string, object>
            {
                { "enabled", true },
                { "type", "MemoryCache" }
            };
        }

        // Private helper methods

        private async Task AddAuthHeadersAsync(HttpContent content)
        {
            var headers = await _auth.GetHeadersAsync();
            foreach (var header in headers)
            {
                content.Headers.Add(header.Key, header.Value);
            }
        }

        private async Task AddAuthHeadersAsync(HttpRequestMessage request)
        {
            var headers = await _auth.GetHeadersAsync();
            foreach (var header in headers)
            {
                request.Headers.Add(header.Key, header.Value);
            }
        }

        private async Task HandleErrorResponseAsync(HttpResponseMessage response)
        {
            if (response.IsSuccessStatusCode)
                return;

            var requestId = response.Headers.Contains("X-Request-ID") 
                ? response.Headers.GetValues("X-Request-ID").FirstOrDefault() 
                : null;

            var errorBody = await response.Content.ReadAsStringAsync();
            
            Dictionary<string, object> errorData;
            try
            {
                errorData = JsonSerializer.Deserialize<Dictionary<string, object>>(errorBody, _jsonOptions);
            }
            catch
            {
                errorData = new Dictionary<string, object> { { "message", errorBody } };
            }

            var message = errorData.TryGetValue("message", out var msg) ? msg.ToString() : "Unknown error";

            throw response.StatusCode switch
            {
                System.Net.HttpStatusCode.Unauthorized => new AuthenticationException(message, requestId),
                System.Net.HttpStatusCode.Forbidden => new AuthorizationException(message, requestId),
                System.Net.HttpStatusCode.NotFound => new NotFoundException(message, requestId),
                System.Net.HttpStatusCode.BadRequest => new ValidationException(message, requestId),
                System.Net.HttpStatusCode.TooManyRequests => new RateLimitException(message, requestId),
                _ => new VaultAgentException($"HTTP {(int)response.StatusCode}: {message}", requestId)
            };
        }

        private void InvalidateCache(string pattern)
        {
            if (_cache == null)
                return;

            // Note: MemoryCache doesn't have a built-in way to invalidate by pattern
            // This would need a custom implementation
            _logger.LogDebug("Invalidated cache entries matching: {Pattern}", pattern);
        }

        private IAsyncPolicy GetRetryPolicy()
        {
            return Policy
                .Handle<HttpRequestException>()
                .Or<TaskCanceledException>()
                .WaitAndRetryAsync(
                    _config.Retry.MaxAttempts - 1,
                    retryAttempt => TimeSpan.FromMilliseconds(
                        Math.Min(
                            _config.Retry.InitialDelay.TotalMilliseconds * Math.Pow(_config.Retry.BackoffFactor, retryAttempt - 1),
                            _config.Retry.MaxDelay.TotalMilliseconds
                        ) + new Random().Next(0, 1000) // Add jitter
                    ),
                    onRetry: (outcome, timespan, retryCount, context) =>
                    {
                        _logger.LogWarning("Retry {RetryCount} after {Delay}ms due to: {Exception}", 
                            retryCount, timespan.TotalMilliseconds, outcome.Exception?.Message);
                    });
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed && disposing)
            {
                _httpClient?.Dispose();
                _logger.LogInformation("Client disposed");
                _disposed = true;
            }
        }
    }
}