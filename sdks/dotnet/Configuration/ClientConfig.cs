using System;
using System.Collections.Generic;

namespace VaultAgent.SDK.Configuration
{
    /// <summary>
    /// Configuration options for VaultAgentClient
    /// </summary>
    public class ClientConfig
    {
        public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);
        public bool VerifySSL { get; set; } = true;
        public int MaxConnections { get; set; } = 10;
        public string UserAgent { get; set; } = "VaultAgent-DotNet-SDK/1.0.0";
        public Dictionary<string, string> DefaultHeaders { get; set; } = new();
        public string LogLevel { get; set; } = "Information";

        // Cache configuration
        public bool CacheEnabled { get; set; } = true;
        public TimeSpan CacheTtl { get; set; } = TimeSpan.FromMinutes(5);
        public int CacheMaxSize { get; set; } = 1000;

        // Retry configuration
        public RetryConfig Retry { get; set; } = new();
    }

    /// <summary>
    /// Retry configuration options
    /// </summary>
    public class RetryConfig
    {
        public int MaxAttempts { get; set; } = 3;
        public TimeSpan InitialDelay { get; set; } = TimeSpan.FromSeconds(1);
        public TimeSpan MaxDelay { get; set; } = TimeSpan.FromSeconds(30);
        public double BackoffFactor { get; set; } = 2.0;
        public List<int> RetryableStatusCodes { get; set; } = new() { 500, 502, 503, 504, 408, 429 };
    }
}