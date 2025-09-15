#!/bin/bash

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "🔍 KeyVault Deployment Validation"
echo "=================================="

# Test 1: API Health
echo -n "Testing API health... "
if curl -s http://localhost:8080/api/v1/system/stats > /dev/null 2>&1; then
    echo -e "${GREEN}✅ PASS${NC}"
else
    echo -e "${RED}❌ FAIL${NC}"
    exit 1
fi

# Test 2: Web Interface
echo -n "Testing web interface... "
if curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/ | grep -q "200"; then
    echo -e "${GREEN}✅ PASS${NC}"
else
    echo -e "${RED}❌ FAIL${NC}"
    exit 1
fi

# Test 3: CLI
echo -n "Testing CLI... "
cd vault-agent
if ./vault-cli system status > /dev/null 2>&1; then
    echo -e "${GREEN}✅ PASS${NC}"
else
    echo -e "${RED}❌ FAIL${NC}"
    exit 1
fi

# Test 4: Authentication
echo -n "Testing authentication... "
if curl -s -X POST http://localhost:8080/api/v1/auth/login \
   -H "Content-Type: application/json" \
   -d '{"username":"admin","password":"admin123"}' | grep -q "token"; then
    echo -e "${GREEN}✅ PASS${NC}"
else
    echo -e "${RED}❌ FAIL${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}🎉 All tests passed! KeyVault is ready for use.${NC}"
echo ""
echo "📋 Access Information:"
echo "  🌐 Web Interface: http://localhost:3000"
echo "  📚 API Documentation: http://localhost:8080/swagger/index.html"
echo "  🔑 Demo Login: admin / admin123"
echo ""
echo "🛠️  CLI Usage:"
echo "  cd vault-agent"
echo "  ./vault-cli --help"
