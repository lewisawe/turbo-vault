using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace VaultAgent.SDK.Models
{
    /// <summary>
    /// Represents a secret with its metadata and value
    /// </summary>
    public class Secret
    {
        [JsonPropertyName("id")]
        public string Id { get; set; }

        [JsonPropertyName("name")]
        public string Name { get; set; }

        [JsonPropertyName("value")]
        public string Value { get; set; }

        [JsonPropertyName("metadata")]
        public Dictionary<string, object> Metadata { get; set; } = new();

        [JsonPropertyName("tags")]
        public List<string> Tags { get; set; } = new();

        [JsonPropertyName("created_at")]
        public DateTime CreatedAt { get; set; }

        [JsonPropertyName("updated_at")]
        public DateTime UpdatedAt { get; set; }

        [JsonPropertyName("expires_at")]
        public DateTime? ExpiresAt { get; set; }

        [JsonPropertyName("rotation_due")]
        public DateTime? RotationDue { get; set; }

        [JsonPropertyName("version")]
        public int Version { get; set; }

        [JsonPropertyName("created_by")]
        public string CreatedBy { get; set; }

        [JsonPropertyName("access_count")]
        public long AccessCount { get; set; }

        [JsonPropertyName("last_accessed")]
        public DateTime? LastAccessed { get; set; }

        [JsonPropertyName("status")]
        public string Status { get; set; }

        public override string ToString()
        {
            return $"Secret{{Id='{Id}', Name='{Name}', Version={Version}, Status='{Status}', CreatedAt={CreatedAt}}}";
        }
    }

    /// <summary>
    /// Represents secret metadata without the actual value
    /// </summary>
    public class SecretMetadata
    {
        [JsonPropertyName("id")]
        public string Id { get; set; }

        [JsonPropertyName("name")]
        public string Name { get; set; }

        [JsonPropertyName("metadata")]
        public Dictionary<string, object> Metadata { get; set; } = new();

        [JsonPropertyName("tags")]
        public List<string> Tags { get; set; } = new();

        [JsonPropertyName("created_at")]
        public DateTime CreatedAt { get; set; }

        [JsonPropertyName("updated_at")]
        public DateTime UpdatedAt { get; set; }

        [JsonPropertyName("expires_at")]
        public DateTime? ExpiresAt { get; set; }

        [JsonPropertyName("rotation_due")]
        public DateTime? RotationDue { get; set; }

        [JsonPropertyName("version")]
        public int Version { get; set; }

        [JsonPropertyName("created_by")]
        public string CreatedBy { get; set; }

        [JsonPropertyName("access_count")]
        public long AccessCount { get; set; }

        [JsonPropertyName("last_accessed")]
        public DateTime? LastAccessed { get; set; }

        [JsonPropertyName("status")]
        public string Status { get; set; }

        public override string ToString()
        {
            return $"SecretMetadata{{Id='{Id}', Name='{Name}', Version={Version}, Status='{Status}', CreatedAt={CreatedAt}}}";
        }
    }

    /// <summary>
    /// Request object for creating a new secret
    /// </summary>
    public class CreateSecretRequest
    {
        [JsonPropertyName("name")]
        public string Name { get; set; }

        [JsonPropertyName("value")]
        public string Value { get; set; }

        [JsonPropertyName("metadata")]
        public Dictionary<string, object> Metadata { get; set; } = new();

        [JsonPropertyName("tags")]
        public List<string> Tags { get; set; } = new();

        public CreateSecretRequest() { }

        public CreateSecretRequest(string name, string value)
        {
            Name = name;
            Value = value;
        }

        public CreateSecretRequest(string name, string value, Dictionary<string, object> metadata, List<string> tags)
        {
            Name = name;
            Value = value;
            Metadata = metadata ?? new();
            Tags = tags ?? new();
        }
    }

    /// <summary>
    /// Request object for updating an existing secret
    /// </summary>
    public class UpdateSecretRequest
    {
        [JsonPropertyName("value")]
        public string Value { get; set; }

        [JsonPropertyName("metadata")]
        public Dictionary<string, object> Metadata { get; set; }

        [JsonPropertyName("tags")]
        public List<string> Tags { get; set; }

        public UpdateSecretRequest() { }

        public UpdateSecretRequest(string value)
        {
            Value = value;
        }
    }

    /// <summary>
    /// Options for listing secrets
    /// </summary>
    public class ListSecretsOptions
    {
        public List<string> Tags { get; set; }
        public int? Limit { get; set; }
        public int? Offset { get; set; }
    }

    /// <summary>
    /// Response object for listing secrets
    /// </summary>
    public class SecretsResponse
    {
        [JsonPropertyName("secrets")]
        public List<SecretMetadata> Secrets { get; set; } = new();
    }
}