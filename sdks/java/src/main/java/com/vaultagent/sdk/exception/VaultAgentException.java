package com.vaultagent.sdk.exception;

/**
 * Base exception class for Vault Agent SDK
 */
public class VaultAgentException extends Exception {
    
    private final String requestId;
    
    public VaultAgentException(String message) {
        super(message);
        this.requestId = null;
    }
    
    public VaultAgentException(String message, String requestId) {
        super(message);
        this.requestId = requestId;
    }
    
    public VaultAgentException(String message, Throwable cause) {
        super(message, cause);
        this.requestId = null;
    }
    
    public VaultAgentException(String message, Throwable cause, String requestId) {
        super(message, cause);
        this.requestId = requestId;
    }
    
    public String getRequestId() {
        return requestId;
    }
    
    @Override
    public String toString() {
        String result = super.toString();
        if (requestId != null) {
            result += " (Request ID: " + requestId + ")";
        }
        return result;
    }
}

/**
 * Exception thrown when authentication fails
 */
class AuthenticationError extends VaultAgentException {
    public AuthenticationError(String message) {
        super(message);
    }
    
    public AuthenticationError(String message, String requestId) {
        super(message, requestId);
    }
}

/**
 * Exception thrown when authorization fails
 */
class AuthorizationError extends VaultAgentException {
    public AuthorizationError(String message) {
        super(message);
    }
    
    public AuthorizationError(String message, String requestId) {
        super(message, requestId);
    }
}

/**
 * Exception thrown when a resource is not found
 */
class NotFoundError extends VaultAgentException {
    public NotFoundError(String message) {
        super(message);
    }
    
    public NotFoundError(String message, String requestId) {
        super(message, requestId);
    }
}

/**
 * Exception thrown when validation fails
 */
class ValidationError extends VaultAgentException {
    public ValidationError(String message) {
        super(message);
    }
    
    public ValidationError(String message, String requestId) {
        super(message, requestId);
    }
}

/**
 * Exception thrown when rate limit is exceeded
 */
class RateLimitError extends VaultAgentException {
    public RateLimitError(String message) {
        super(message);
    }
    
    public RateLimitError(String message, String requestId) {
        super(message, requestId);
    }
}

/**
 * Exception thrown when connection fails
 */
class ConnectionError extends VaultAgentException {
    public ConnectionError(String message) {
        super(message);
    }
    
    public ConnectionError(String message, Throwable cause) {
        super(message, cause);
    }
    
    public ConnectionError(String message, String requestId) {
        super(message, requestId);
    }
}