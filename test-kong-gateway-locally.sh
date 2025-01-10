#!/bin/bash
set -e

# Configuration
KONG_ADMIN_URL="http://localhost:8001"
AUTH_SERVICE_URL="http://host.docker.internal:8081"
PRODUCT_SERVICE_URL="http://host.docker.internal:8083"
SERVICE_NAME="products"

# Color definitions for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper function to print status
print_status() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✓ Success${NC}: $2"
    else
        echo -e "${RED}✗ Failed${NC}: $2"
        echo -e "${YELLOW}Response${NC}: $3"
    fi
}

echo "Testing Kong configuration with following parameters:"
echo "Kong Admin URL: $KONG_ADMIN_URL"
echo "Service Name: $SERVICE_NAME"
echo "Product Service URL: $PRODUCT_SERVICE_URL"
echo "Auth Service URL: $AUTH_SERVICE_URL"
echo "----------------------------------------"

# Test 2: Create the product service
echo -e "\n2. Creating product service..."
response=$(curl -s -X POST "$KONG_ADMIN_URL/services" \
    --data "name=$SERVICE_NAME" \
    --data "url=$PRODUCT_SERVICE_URL")
status=$?
print_status $status "Service creation" "$response"

# Test 3: Create a route for the product service
echo -e "\n3. Creating route for product service..."
response=$(curl -s -X POST "$KONG_ADMIN_URL/services/$SERVICE_NAME/routes" \
    --data "paths[]=/products" \
    --data "methods[]=GET" \
    --data "protocols[]=http" \
    --data "strip_path=false" \
    --data "name=$SERVICE_NAME")
status=$?
print_status $status "Route creation" "$response"


# Test 4: Enable the custom-auth plugin
echo -e "\n4. Enabling custom-auth plugin..."
response=$(curl -s -X POST "$KONG_ADMIN_URL/plugins" \
    --data "name=custom-auth" \
    --data "config.auth_url=$AUTH_SERVICE_URL")
status=$?
print_status $status "Plugin creation" "$response"

# Verify configurations
echo -e "\n5. Verifying Service configuration..."
response=$(curl -s "$KONG_ADMIN_URL/services/$SERVICE_NAME")
status=$?
print_status $status "Service verification" "$response"

echo -e "\n6. Verifying Route configuration..."
response=$(curl -s "$KONG_ADMIN_URL/routes/$SERVICE_NAME")
status=$?
print_status $status "Route verification" "$response"

echo -e "\n7. Verifying Plugin configuration..."
response=$(curl -s "$KONG_ADMIN_URL/plugins")
status=$?
print_status $status "Plugin verification" "$response"

# Test the endpoints
echo -e "\n8. Testing endpoints..."
echo -e "\na. Testing direct access (should fail with 401)..."
response=$(curl -s -w "\nStatus: %{http_code}" http://localhost:8000/products)
echo -e "\n$response"

echo -e "\nb. Testing with invalid access token (should fail with 401)..."
response=$(curl -s -w "\nStatus: %{http_code}" http://localhost:8000/products \
    -H "Cookie: access_token=invalid_token")
echo -e "\n$response"

echo -e "\nc. Testing PIN-based authentication... expecting 204"
response=$(curl -s -w "\nStatus: %{http_code}" http://localhost:8000/products \
    -H "Cookie: pin=1234; refresh_token=eyJhbGciOiJIUzUxMiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI4ZDFkMDlkZC1lOTE0LTRiZjktODRiNy01ZTlkMmY3ZmI4OWEifQ.eyJleHAiOjE3MzkxMDg4NzUsImlhdCI6MTczNjUxNjg5NCwianRpIjoiODlkOTU4OTEtMDcwZi00N2FmLWJiMTEtNWE5NTY0YTE3ODU4IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9wdHNzLXN1cHBvcnQiLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvcmVhbG1zL3B0c3Mtc3VwcG9ydCIsInN1YiI6IjQyMTNlN2U5LTc3YzctNDk0Ni05ZDg1LWZlMzNmNjk0MGYwZCIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJhdXRoZW50aWNhdGlvbi1zZXJ2aWNlIiwic2lkIjoiN2JmYWFkYjctMzNlMC00ODNjLWE3ZTYtNzkyZTBhYmJhYmE4Iiwic2NvcGUiOiJvcGVuaWQgd2ViLW9yaWdpbnMgYWNyIHVzZXItZGV0YWlscyBiYXNpYyJ9.KM1F37tHOzyozYyldarY1fsKALehXbZ1JT5MgoFq4Q8SK33DpbgkgiFG7Te6n2RcbUqGZl29SC_hI3mQuev-VQ")
echo -e "\n$response"


echo -e "\n${GREEN}Testing complete!${NC}"