using System;

namespace VaultAgent.SDK.Exceptions
{
    /// <summary>
    /// Base exception class for Vault Agent SDK
    /// </summary>
    public class VaultAgentException : Exception
    {
        public string RequestId { get; }

        public VaultAgentException(string message) : base(message)
        {
        }

        public VaultAgentException(string message, string requestId) : base(message)
        {
            RequestId = requestId;
        }

        public VaultAgentException(string message, Exception innerException) : base(message, innerException)
        {
        }

        public VaultAgentException(string message, Exception innerException, string requestId) : base(message, innerException)
        {
            RequestId = requestId;
        }

        public override string ToString()
        {
            var result = base.ToString();
            if (!string.IsNullOrEmpty(RequestId))
            {
                result += $" (Request ID: {RequestId})";
            }
            return result;
        }
    }

    /// <summary>
    /// Exception thrown when authentication fails
    /// </summary>
    public class AuthenticationException : VaultAgentException
    {
        public AuthenticationException(string message) : base(message) { }
        public AuthenticationException(string message, string requestId) : base(message, requestId) { }
    }

    /// <summary>
    /// Exception thrown when authorization fails
    /// </summary>
    public class AuthorizationException : VaultAgentException
    {
        public AuthorizationException(string message) : base(message) { }
        public AuthorizationException(string message, string requestId) : base(message, requestId) { }
    }

    /// <summary>
    /// Exception thrown when a resource is not found
    /// </summary>
    public class NotFoundException : VaultAgentException
    {
        public NotFoundException(string message) : base(message) { }
        public NotFoundException(string message, string requestId) : base(message, requestId) { }
    }

    /// <summary>
    /// Exception thrown when validation fails
    /// </summary>
    public class ValidationException : VaultAgentException
    {
        public ValidationException(string message) : base(message) { }
        public ValidationException(string message, string requestId) : base(message, requestId) { }
    }

    /// <summary>
    /// Exception thrown when rate limit is exceeded
    /// </summary>
    public class RateLimitException : VaultAgentException
    {
        public RateLimitException(string message) : base(message) { }
        public RateLimitException(string message, string requestId) : base(message, requestId) { }
    }

    /// <summary>
    /// Exception thrown when connection fails
    /// </summary>
    public class ConnectionException : VaultAgentException
    {
        public ConnectionException(string message) : base(message) { }
        public ConnectionException(string message, Exception innerException) : base(message, innerException) { }
        public ConnectionException(string message, string requestId) : base(message, requestId) { }
    }
}