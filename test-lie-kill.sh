#!/bin/bash

# 🔥 TESTE RÁPIDO - LIE → KILL (SEM JQ)

API_URL="https://rekuway-idn-mvp.vercel.app/api"

echo "🔐 REKUWAY IDN - TESTE RÁPIDO LIE→KILL"
echo "========================================"
echo ""

# 1. Criar identidade
echo "📝 Criando identidade HIGH..."
RESPONSE=$(curl -s -X POST "$API_URL/identity/new" \
  -H "Content-Type: application/json" \
  -d '{"paranoiaLevel":"high"}')

ID=$(echo $RESPONSE | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
echo "✅ Identity: $ID"
echo ""

# 2. Tentativa 1 (ALLOW)
echo "❌ Tentativa 1 (esperado: ALLOW)..."
R1=$(curl -s -X POST "$API_URL/identity/check" \
  -H "Content-Type: application/json" \
  -d "{\"identityId\":\"$ID\",\"privateKey\":\"wrong1\"}")

ACTION1=$(echo $R1 | grep -o '"action":"[^"]*"' | cut -d'"' -f4)
echo "   Resultado: $ACTION1"
echo ""

# 3. Tentativa 2 (REGENERATE)
echo "❌ Tentativa 2 (esperado: REGENERATE)..."
R2=$(curl -s -X POST "$API_URL/identity/check" \
  -H "Content-Type: application/json" \
  -d "{\"identityId\":\"$ID\",\"privateKey\":\"wrong2\"}")

ACTION2=$(echo $R2 | grep -o '"action":"[^"]*"' | cut -d'"' -f4)
NEW_ID=$(echo $R2 | grep -o '"newIdentity":{[^}]*"id":"[^"]*"' | grep -o '"id":"[^"]*"' | cut -d'"' -f4)

echo "   Resultado: $ACTION2"
echo "   Nova ID: $NEW_ID"
echo ""

# 4. Tentativa 3 (LIE - CRÍTICO!)
echo "❌ Tentativa 3 (esperado: LIE 🎭)..."
R3=$(curl -s -X POST "$API_URL/identity/check" \
  -H "Content-Type: application/json" \
  -d "{\"identityId\":\"$NEW_ID\",\"privateKey\":\"wrong3\"}")

ACTION3=$(echo $R3 | grep -o '"action":"[^"]*"' | cut -d'"' -f4)

echo "   Resultado: $ACTION3"
echo "   📊 Resposta completa:"
echo "$R3"
echo ""

if [ "$ACTION3" = "LIE" ]; then
  echo "   ✅ LIE FUNCIONANDO! 🎭"
else
  echo "   ❌ LIE NÃO FUNCIONOU! Action: $ACTION3"
fi
echo ""

# 5. Tentativa 4 (KILL)
echo "❌ Tentativa 4 (esperado: KILL 💀)..."
R4=$(curl -s -X POST "$API_URL/identity/check" \
  -H "Content-Type: application/json" \
  -d "{\"identityId\":\"$NEW_ID\",\"privateKey\":\"wrong4\"}")

ACTION4=$(echo $R4 | grep -o '"action":"[^"]*"' | cut -d'"' -f4)

echo "   Resultado: $ACTION4"
echo "   📊 Resposta completa:"
echo "$R4"
echo ""

# Resumo
echo "========================================"
echo "📊 RESUMO"
echo "========================================"
echo "T1: $ACTION1 | T2: $ACTION2 | T3: $ACTION3 | T4: $ACTION4"

if [ "$ACTION3" = "LIE" ]; then
  echo "🎉 ✅ SISTEMA PERFEITO! LIE FUNCIONANDO!"
else
  echo "⚠️ LIE NÃO FUNCIONOU!"
fi
