# First Steps Tutorial

## Your First Secrets and Policies

### Step 1: Create Your First Secret

```bash
# Store a database password
keyvault-cli secrets create \
  --path /myapp/prod/db-password \
  --value "$(openssl rand -base64 32)" \
  --description "Production database password"

# Store API keys
keyvault-cli secrets create \
  --path /myapp/prod/stripe-api-key \
  --value "sk_live_..." \
  --description "Stripe API key for payments"
```

### Step 2: Organize with Paths

```bash
# Create environment-specific secrets
keyvault-cli secrets create --path /myapp/dev/db-password --value "dev-password"
keyvault-cli secrets create --path /myapp/staging/db-password --value "staging-password"
keyvault-cli secrets create --path /myapp/prod/db-password --value "prod-password"

# List secrets by environment
keyvault-cli secrets list --prefix /myapp/prod/
```

### Step 3: Create Access Policies

```bash
# Developer policy - read access to dev environment
keyvault-cli policies create \
  --name developers \
  --path "/myapp/dev/*" \
  --actions read \
  --description "Developer access to dev environment"

# Production policy - limited access
keyvault-cli policies create \
  --name production-apps \
  --path "/myapp/prod/*" \
  --actions read \
  --description "Production application access"
```

### Step 4: Retrieve Secrets in Applications

#### Using CLI
```bash
# Get single secret
DB_PASSWORD=$(keyvault-cli secrets get --path /myapp/prod/db-password --output value)

# Get multiple secrets as environment variables
eval $(keyvault-cli secrets env --prefix /myapp/prod/)
```

#### Using API
```bash
# Direct API call
curl -H "Authorization: Bearer $KEYVAULT_TOKEN" \
  https://localhost:8080/api/v1/secrets/myapp/prod/db-password
```

#### Using SDK (Python)
```python
from keyvault import Client

client = Client(endpoint="https://localhost:8080")
password = client.get_secret("/myapp/prod/db-password")
```

### Step 5: Set Up Rotation

```bash
# Enable automatic rotation for database password
keyvault-cli rotation create \
  --path /myapp/prod/db-password \
  --interval 30d \
  --type database \
  --connection-string "postgres://user@host:5432/db"
```

## Common Patterns

### Environment Variables
```bash
# Export all secrets for an environment
keyvault-cli secrets env --prefix /myapp/prod/ > .env.prod

# Use in Docker
docker run --env-file .env.prod myapp:latest
```

### Configuration Files
```bash
# Template-based configuration
keyvault-cli template render \
  --template config.yaml.tmpl \
  --output config.yaml \
  --secrets-prefix /myapp/prod/
```

### CI/CD Integration
```bash
# In your CI pipeline
export DB_PASSWORD=$(keyvault-cli secrets get --path /myapp/prod/db-password --output value)
docker build --build-arg DB_PASSWORD="$DB_PASSWORD" .
```

## Best Practices

1. **Use descriptive paths**: `/service/environment/secret-name`
2. **Set descriptions**: Always add meaningful descriptions
3. **Rotate regularly**: Enable automatic rotation for sensitive secrets
4. **Least privilege**: Grant minimal required access
5. **Audit access**: Regularly review who has access to what
