#!/bin/bash

# 🔐 Rekuway IDN - Automated Test Script
# Tests: CREATE → VALIDATE → REGENERATE → KILL

API_URL="https://rekuway-idn-mvp.vercel.app"
PARANOIA_LEVEL="high"  # Change to: low, medium, high, deadman

echo "🔐 REKUWAY IDN - AUTOMATED TEST"
echo "================================"
echo "Paranoia Level: $PARANOIA_LEVEL"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Step 1: Create Identity
echo -e "${GREEN}📝 STEP 1: Creating identity...${NC}"
CREATE_RESPONSE=$(curl -s -X POST "$API_URL/identity/new" \
  -H "Content-Type: application/json" \
  -d "{\"paranoiaLevel\": \"$PARANOIA_LEVEL\"}")

IDENTITY_ID=$(echo $CREATE_RESPONSE | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
PRIVATE_KEY=$(echo $CREATE_RESPONSE | grep -o '"privateKey":"[^"]*"' | head -1 | cut -d'"' -f4)

if [ -z "$IDENTITY_ID" ]; then
  echo -e "${RED}❌ Failed to create identity${NC}"
  echo $CREATE_RESPONSE
  exit 1
fi

echo -e "${GREEN}✅ Identity created: $IDENTITY_ID${NC}"
echo ""
sleep 1

# Step 2: Valid Key Test
echo -e "${GREEN}✅ STEP 2: Testing with CORRECT key...${NC}"
VALID_RESPONSE=$(curl -s -X POST "$API_URL/identity/check" \
  -H "Content-Type: application/json" \
  -d "{\"identityId\": \"$IDENTITY_ID\", \"privateKey\": \"$PRIVATE_KEY\"}")

echo $VALID_RESPONSE | grep -q '"success":true' && echo -e "${GREEN}✅ Valid key accepted (attempts: 0)${NC}" || echo -e "${RED}❌ Valid key rejected${NC}"
echo ""
sleep 1

# Step 3: Wrong Key Tests (until KILL)
CURRENT_ID=$IDENTITY_ID
ATTEMPT=1
MAX_ATTEMPTS=15
REGENERATE_COUNT=0

echo -e "${YELLOW}⚠️  STEP 3: Testing with WRONG keys (until KILL)...${NC}"
echo ""

while [ $ATTEMPT -le $MAX_ATTEMPTS ]; do
  echo -e "${RED}❌ Attempt $ATTEMPT: Wrong key...${NC}"
  
  WRONG_RESPONSE=$(curl -s -X POST "$API_URL/identity/check" \
    -H "Content-Type: application/json" \
    -d "{\"identityId\": \"$CURRENT_ID\", \"privateKey\": \"-----BEGIN PRIVATE KEY-----\nFAKE_KEY_$ATTEMPT\n-----END PRIVATE KEY-----\n\"}")
  
  # Check for REGENERATE
  if echo $WRONG_RESPONSE | grep -q '"action":"REGENERATE"'; then
    REGENERATE_COUNT=$((REGENERATE_COUNT + 1))
    NEW_ID=$(echo $WRONG_RESPONSE | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
    echo -e "${BLUE}🔄 REGENERATE #$REGENERATE_COUNT detected!${NC}"
    echo -e "${BLUE}   New identity: $NEW_ID${NC}"
    CURRENT_ID=$NEW_ID
    echo ""
  fi
  
  # Check for KILL
  if echo $WRONG_RESPONSE | grep -q '"action":"KILLED"'; then
    echo -e "${RED}💀 KILL DETECTED!${NC}"
    echo -e "${RED}   Identity destroyed permanently${NC}"
    echo ""
    echo $WRONG_RESPONSE
    echo ""
    break
  fi
  
  # Show attempts/remaining
  ATTEMPTS=$(echo $WRONG_RESPONSE | grep -o '"attempts":[0-9]*' | cut -d':' -f2)
  REMAINING=$(echo $WRONG_RESPONSE | grep -o '"remaining":[0-9]*' | cut -d':' -f2)
  
  if [ ! -z "$ATTEMPTS" ]; then
    echo -e "   Attempts: $ATTEMPTS | Remaining: $REMAINING"
  fi
  
  echo ""
  sleep 1
  ATTEMPT=$((ATTEMPT + 1))
done

# Summary
echo "================================"
echo -e "${GREEN}📊 TEST SUMMARY${NC}"
echo "================================"
echo "Paranoia Level: $PARANOIA_LEVEL"
echo "Total Attempts: $((ATTEMPT - 1))"
echo "Regenerations: $REGENERATE_COUNT"

if echo $WRONG_RESPONSE | grep -q '"action":"KILLED"'; then
  echo -e "${GREEN}✅ KILL system working correctly${NC}"
else
  echo -e "${YELLOW}⚠️  No KILL detected (max attempts reached)${NC}"
fi

echo ""
echo "🎉 Test completed!"
