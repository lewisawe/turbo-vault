#!/bin/bash

# Automated deployment tests for Vault Agent
# Tests various deployment scenarios and configurations

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TEST_NAMESPACE="vault-agent-test-$(date +%s)"
TIMEOUT=300

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Cleanup function
cleanup() {
    log "Cleaning up test resources..."
    
    # Delete test namespace
    kubectl delete namespace "${TEST_NAMESPACE}" --ignore-not-found=true --timeout=60s || true
    
    # Clean up any test files
    rm -f /tmp/vault-agent-test-*
    
    success "Cleanup completed"
}

# Set up cleanup trap
trap cleanup EXIT

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    local missing_tools=()
    
    if ! command -v kubectl &> /dev/null; then
        missing_tools+=("kubectl")
    fi
    
    if ! command -v helm &> /dev/null; then
        missing_tools+=("helm")
    fi
    
    if ! command -v docker &> /dev/null; then
        missing_tools+=("docker")
    fi
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        error "Missing required tools: ${missing_tools[*]}"
        exit 1
    fi
    
    # Check Kubernetes connectivity
    if ! kubectl cluster-info &> /dev/null; then
        error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    success "Prerequisites check passed"
}

# Test Docker deployment
test_docker_deployment() {
    log "Testing Docker deployment..."
    
    local container_name="vault-agent-test-$(date +%s)"
    local test_config="/tmp/vault-agent-test-config.yaml"
    
    # Create test configuration
    cat > "${test_config}" << 'EOF'
server:
  bind_address: "0.0.0.0:8200"
  log_level: "info"

storage:
  type: "sqlite"
  connection_string: "/data/vault-agent.db"

cache:
  type: "memory"
  ttl: "5m"
EOF
    
    # Run container
    docker run -d \
        --name "${container_name}" \
        -p 18200:8200 \
        -v "${test_config}:/etc/vault-agent/config.yaml:ro" \
        vault-agent:latest \
        server --config /etc/vault-agent/config.yaml
    
    # Wait for container to be ready
    local attempts=0
    while [[ ${attempts} -lt 30 ]]; do
        if curl -sf http://localhost:18200/health &> /dev/null; then
            break
        fi
        sleep 2
        ((attempts++))
    done
    
    if [[ ${attempts} -eq 30 ]]; then
        docker logs "${container_name}"
        docker stop "${container_name}" || true
        docker rm "${container_name}" || true
        error "Docker deployment test failed - container not ready"
        return 1
    fi
    
    # Test basic functionality
    local health_response
    health_response=$(curl -s http://localhost:18200/health)
    
    if [[ "${health_response}" != *"healthy"* ]]; then
        docker logs "${container_name}"
        docker stop "${container_name}" || true
        docker rm "${container_name}" || true
        error "Docker deployment test failed - health check failed"
        return 1
    fi
    
    # Cleanup
    docker stop "${container_name}"
    docker rm "${container_name}"
    rm -f "${test_config}"
    
    success "Docker deployment test passed"
}

# Test Kubernetes deployment
test_kubernetes_deployment() {
    log "Testing Kubernetes deployment..."
    
    # Create test namespace
    kubectl create namespace "${TEST_NAMESPACE}"
    
    # Deploy using Helm
    helm install vault-agent-test "${PROJECT_ROOT}/deployments/helm/vault-agent" \
        --namespace "${TEST_NAMESPACE}" \
        --set replicaCount=1 \
        --set image.tag=latest \
        --set resources.requests.cpu=100m \
        --set resources.requests.memory=128Mi \
        --set resources.limits.cpu=200m \
        --set resources.limits.memory=256Mi \
        --set persistence.enabled=false \
        --set postgresql.enabled=false \
        --set redis.enabled=false \
        --wait --timeout=5m
    
    # Wait for pods to be ready
    kubectl wait --for=condition=ready pod \
        -l app.kubernetes.io/name=vault-agent \
        -n "${TEST_NAMESPACE}" \
        --timeout=300s
    
    # Test service connectivity
    kubectl port-forward -n "${TEST_NAMESPACE}" svc/vault-agent-test 18201:8200 &
    local port_forward_pid=$!
    
    sleep 5
    
    # Test health endpoint
    local attempts=0
    while [[ ${attempts} -lt 15 ]]; do
        if curl -sf http://localhost:18201/health &> /dev/null; then
            break
        fi
        sleep 2
        ((attempts++))
    done
    
    if [[ ${attempts} -eq 15 ]]; then
        kubectl logs -l app.kubernetes.io/name=vault-agent -n "${TEST_NAMESPACE}"
        kill ${port_forward_pid} || true
        error "Kubernetes deployment test failed - service not ready"
        return 1
    fi
    
    # Test basic API functionality
    local health_response
    health_response=$(curl -s http://localhost:18201/health)
    
    if [[ "${health_response}" != *"healthy"* ]]; then
        kubectl logs -l app.kubernetes.io/name=vault-agent -n "${TEST_NAMESPACE}"
        kill ${port_forward_pid} || true
        error "Kubernetes deployment test failed - health check failed"
        return 1
    fi
    
    # Test metrics endpoint
    if ! curl -sf http://localhost:18201/metrics &> /dev/null; then
        warn "Metrics endpoint not accessible"
    fi
    
    kill ${port_forward_pid} || true
    
    success "Kubernetes deployment test passed"
}

# Test Helm chart configuration options
test_helm_configurations() {
    log "Testing Helm chart configuration options..."
    
    local test_cases=(
        "minimal:--set replicaCount=1 --set persistence.enabled=false --set postgresql.enabled=false --set redis.enabled=false"
        "ha:--set replicaCount=3 --set persistence.enabled=true --set postgresql.enabled=true --set redis.enabled=true"
        "security:--set securityContext.runAsNonRoot=true --set podSecurityContext.readOnlyRootFilesystem=true"
    )
    
    for test_case in "${test_cases[@]}"; do
        local name="${test_case%%:*}"
        local args="${test_case#*:}"
        
        log "Testing configuration: ${name}"
        
        local release_name="vault-agent-${name}-test"
        
        # Install with specific configuration
        helm install "${release_name}" "${PROJECT_ROOT}/deployments/helm/vault-agent" \
            --namespace "${TEST_NAMESPACE}" \
            --set image.tag=latest \
            ${args} \
            --wait --timeout=3m
        
        # Verify deployment
        kubectl wait --for=condition=ready pod \
            -l app.kubernetes.io/instance="${release_name}" \
            -n "${TEST_NAMESPACE}" \
            --timeout=180s
        
        # Cleanup this test
        helm uninstall "${release_name}" -n "${TEST_NAMESPACE}"
        
        success "Configuration test passed: ${name}"
    done
}

# Test upgrade scenarios
test_upgrade_scenarios() {
    log "Testing upgrade scenarios..."
    
    local release_name="vault-agent-upgrade-test"
    
    # Install initial version
    helm install "${release_name}" "${PROJECT_ROOT}/deployments/helm/vault-agent" \
        --namespace "${TEST_NAMESPACE}" \
        --set replicaCount=2 \
        --set image.tag=latest \
        --set persistence.enabled=false \
        --set postgresql.enabled=false \
        --set redis.enabled=false \
        --wait --timeout=3m
    
    # Wait for initial deployment
    kubectl wait --for=condition=ready pod \
        -l app.kubernetes.io/instance="${release_name}" \
        -n "${TEST_NAMESPACE}" \
        --timeout=180s
    
    # Perform upgrade (simulate version change)
    helm upgrade "${release_name}" "${PROJECT_ROOT}/deployments/helm/vault-agent" \
        --namespace "${TEST_NAMESPACE}" \
        --set replicaCount=3 \
        --set image.tag=latest \
        --set persistence.enabled=false \
        --set postgresql.enabled=false \
        --set redis.enabled=false \
        --wait --timeout=3m
    
    # Verify upgrade
    kubectl wait --for=condition=ready pod \
        -l app.kubernetes.io/instance="${release_name}" \
        -n "${TEST_NAMESPACE}" \
        --timeout=180s
    
    # Check that we have 3 replicas
    local replica_count
    replica_count=$(kubectl get pods -l app.kubernetes.io/instance="${release_name}" -n "${TEST_NAMESPACE}" --no-headers | wc -l)
    
    if [[ ${replica_count} -ne 3 ]]; then
        error "Upgrade test failed - expected 3 replicas, got ${replica_count}"
        return 1
    fi
    
    # Test rollback
    helm rollback "${release_name}" 1 -n "${TEST_NAMESPACE}" --wait --timeout=3m
    
    # Verify rollback
    kubectl wait --for=condition=ready pod \
        -l app.kubernetes.io/instance="${release_name}" \
        -n "${TEST_NAMESPACE}" \
        --timeout=180s
    
    # Check that we're back to 2 replicas
    replica_count=$(kubectl get pods -l app.kubernetes.io/instance="${release_name}" -n "${TEST_NAMESPACE}" --no-headers | wc -l)
    
    if [[ ${replica_count} -ne 2 ]]; then
        error "Rollback test failed - expected 2 replicas, got ${replica_count}"
        return 1
    fi
    
    success "Upgrade scenarios test passed"
}

# Test failure scenarios
test_failure_scenarios() {
    log "Testing failure scenarios..."
    
    # Test pod failure recovery
    local release_name="vault-agent-failure-test"
    
    helm install "${release_name}" "${PROJECT_ROOT}/deployments/helm/vault-agent" \
        --namespace "${TEST_NAMESPACE}" \
        --set replicaCount=2 \
        --set image.tag=latest \
        --set persistence.enabled=false \
        --set postgresql.enabled=false \
        --set redis.enabled=false \
        --wait --timeout=3m
    
    # Wait for deployment
    kubectl wait --for=condition=ready pod \
        -l app.kubernetes.io/instance="${release_name}" \
        -n "${TEST_NAMESPACE}" \
        --timeout=180s
    
    # Delete one pod to simulate failure
    local pod_name
    pod_name=$(kubectl get pods -l app.kubernetes.io/instance="${release_name}" -n "${TEST_NAMESPACE}" -o jsonpath='{.items[0].metadata.name}')
    
    kubectl delete pod "${pod_name}" -n "${TEST_NAMESPACE}"
    
    # Wait for replacement pod
    sleep 10
    kubectl wait --for=condition=ready pod \
        -l app.kubernetes.io/instance="${release_name}" \
        -n "${TEST_NAMESPACE}" \
        --timeout=180s
    
    # Verify we still have 2 pods
    local pod_count
    pod_count=$(kubectl get pods -l app.kubernetes.io/instance="${release_name}" -n "${TEST_NAMESPACE}" --no-headers | wc -l)
    
    if [[ ${pod_count} -ne 2 ]]; then
        error "Failure recovery test failed - expected 2 pods, got ${pod_count}"
        return 1
    fi
    
    success "Failure scenarios test passed"
}

# Test resource limits and requests
test_resource_constraints() {
    log "Testing resource constraints..."
    
    local release_name="vault-agent-resources-test"
    
    # Deploy with specific resource constraints
    helm install "${release_name}" "${PROJECT_ROOT}/deployments/helm/vault-agent" \
        --namespace "${TEST_NAMESPACE}" \
        --set replicaCount=1 \
        --set image.tag=latest \
        --set resources.requests.cpu=50m \
        --set resources.requests.memory=64Mi \
        --set resources.limits.cpu=100m \
        --set resources.limits.memory=128Mi \
        --set persistence.enabled=false \
        --set postgresql.enabled=false \
        --set redis.enabled=false \
        --wait --timeout=3m
    
    # Verify deployment with resource constraints
    kubectl wait --for=condition=ready pod \
        -l app.kubernetes.io/instance="${release_name}" \
        -n "${TEST_NAMESPACE}" \
        --timeout=180s
    
    # Check resource specifications
    local pod_name
    pod_name=$(kubectl get pods -l app.kubernetes.io/instance="${release_name}" -n "${TEST_NAMESPACE}" -o jsonpath='{.items[0].metadata.name}')
    
    local cpu_request
    cpu_request=$(kubectl get pod "${pod_name}" -n "${TEST_NAMESPACE}" -o jsonpath='{.spec.containers[0].resources.requests.cpu}')
    
    if [[ "${cpu_request}" != "50m" ]]; then
        error "Resource constraint test failed - expected CPU request 50m, got ${cpu_request}"
        return 1
    fi
    
    success "Resource constraints test passed"
}

# Test network policies (if supported)
test_network_policies() {
    log "Testing network policies..."
    
    # Check if network policies are supported
    if ! kubectl api-resources | grep -q networkpolicies; then
        warn "Network policies not supported in this cluster, skipping test"
        return 0
    fi
    
    local release_name="vault-agent-netpol-test"
    
    # Deploy with network policies enabled
    helm install "${release_name}" "${PROJECT_ROOT}/deployments/helm/vault-agent" \
        --namespace "${TEST_NAMESPACE}" \
        --set replicaCount=1 \
        --set image.tag=latest \
        --set networkPolicy.enabled=true \
        --set persistence.enabled=false \
        --set postgresql.enabled=false \
        --set redis.enabled=false \
        --wait --timeout=3m
    
    # Verify network policy was created
    if ! kubectl get networkpolicy -n "${TEST_NAMESPACE}" | grep -q "${release_name}"; then
        error "Network policy test failed - policy not created"
        return 1
    fi
    
    success "Network policies test passed"
}

# Run performance tests
test_performance() {
    log "Testing performance under load..."
    
    local release_name="vault-agent-perf-test"
    
    # Deploy for performance testing
    helm install "${release_name}" "${PROJECT_ROOT}/deployments/helm/vault-agent" \
        --namespace "${TEST_NAMESPACE}" \
        --set replicaCount=2 \
        --set image.tag=latest \
        --set resources.requests.cpu=200m \
        --set resources.requests.memory=256Mi \
        --set resources.limits.cpu=500m \
        --set resources.limits.memory=512Mi \
        --set persistence.enabled=false \
        --set postgresql.enabled=false \
        --set redis.enabled=false \
        --wait --timeout=3m
    
    # Wait for deployment
    kubectl wait --for=condition=ready pod \
        -l app.kubernetes.io/instance="${release_name}" \
        -n "${TEST_NAMESPACE}" \
        --timeout=180s
    
    # Set up port forwarding for load testing
    kubectl port-forward -n "${TEST_NAMESPACE}" svc/"${release_name}" 18202:8200 &
    local port_forward_pid=$!
    
    sleep 5
    
    # Simple load test using curl
    log "Running basic load test..."
    
    local success_count=0
    local total_requests=50
    
    for i in $(seq 1 ${total_requests}); do
        if curl -sf http://localhost:18202/health &> /dev/null; then
            ((success_count++))
        fi
    done
    
    kill ${port_forward_pid} || true
    
    local success_rate=$((success_count * 100 / total_requests))
    
    if [[ ${success_rate} -lt 95 ]]; then
        error "Performance test failed - success rate ${success_rate}% < 95%"
        return 1
    fi
    
    success "Performance test passed - success rate: ${success_rate}%"
}

# Main test runner
main() {
    log "Starting Vault Agent deployment tests..."
    
    check_prerequisites
    
    local test_functions=(
        "test_docker_deployment"
        "test_kubernetes_deployment"
        "test_helm_configurations"
        "test_upgrade_scenarios"
        "test_failure_scenarios"
        "test_resource_constraints"
        "test_network_policies"
        "test_performance"
    )
    
    local passed=0
    local failed=0
    
    for test_func in "${test_functions[@]}"; do
        log "Running ${test_func}..."
        
        if ${test_func}; then
            ((passed++))
        else
            ((failed++))
            error "Test failed: ${test_func}"
        fi
        
        echo
    done
    
    # Summary
    log "Test Summary:"
    success "Passed: ${passed}"
    
    if [[ ${failed} -gt 0 ]]; then
        error "Failed: ${failed}"
        exit 1
    else
        success "All tests passed!"
    fi
}

# Handle command line arguments
case "${1:-}" in
    docker)
        check_prerequisites
        test_docker_deployment
        ;;
    kubernetes)
        check_prerequisites
        test_kubernetes_deployment
        ;;
    helm)
        check_prerequisites
        test_helm_configurations
        ;;
    performance)
        check_prerequisites
        test_performance
        ;;
    *)
        main "$@"
        ;;
esac