#!/bin/bash
API_URL="https://rekuway-idn-mvp.vercel.app"
echo "🔐 TESTE RÁPIDO LIE→KILL"
echo "========================"
echo ""
echo "📝 Criando identidade..."
RESPONSE=$(curl -s -X POST "$API_URL/identity/new" -H "Content-Type: application/json" -d '{"paranoiaLevel":"high"}')
ID=$(echo $RESPONSE | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
echo "✅ ID: $ID"
echo ""
echo "❌ Tentativa 1 (ALLOW)..."
R1=$(curl -s -X POST "$API_URL/identity/check" -H "Content-Type: application/json" -d "{\"identityId\":\"$ID\",\"privateKey\":\"wrong1\"}")
ACTION1=$(echo $R1 | grep -o '"action":"[^"]*"' | cut -d'"' -f4)
echo "Resultado: $ACTION1"
echo ""
echo "❌ Tentativa 2 (REGENERATE)..."
R2=$(curl -s -X POST "$API_URL/identity/check" -H "Content-Type: application/json" -d "{\"identityId\":\"$ID\",\"privateKey\":\"wrong2\"}")
ACTION2=$(echo $R2 | grep -o '"action":"[^"]*"' | cut -d'"' -f4)
NEW_ID=$(echo $R2 | grep -o '"newIdentity":{[^}]*"id":"[^"]*"' | grep -o '"id":"[^"]*"' | cut -d'"' -f4)
echo "Resultado: $ACTION2"
echo "Nova ID: $NEW_ID"
echo ""
echo "❌ Tentativa 3 (LIE 🎭)..."
R3=$(curl -s -X POST "$API_URL/identity/check" -H "Content-Type: application/json" -d "{\"identityId\":\"$NEW_ID\",\"privateKey\":\"wrong3\"}")
ACTION3=$(echo $R3 | grep -o '"action":"[^"]*"' | cut -d'"' -f4)
echo "Resultado: $ACTION3"
echo "Resposta completa:"
echo "$R3"
echo ""
if [ "$ACTION3" = "LIE" ]; then
  echo "✅ LIE FUNCIONANDO! 🎭"
else
  echo "❌ LIE NÃO FUNCIONOU! Action: $ACTION3"
fi
echo ""
echo "❌ Tentativa 4 (KILL 💀)..."
R4=$(curl -s -X POST "$API_URL/identity/check" -H "Content-Type: application/json" -d "{\"identityId\":\"$NEW_ID\",\"privateKey\":\"wrong4\"}")
ACTION4=$(echo $R4 | grep -o '"action":"[^"]*"' | cut -d'"' -f4)
echo "Resultado: $ACTION4"
echo "Resposta completa:"
echo "$R4"
echo ""
echo "========================"
echo "RESUMO: T1=$ACTION1 | T2=$ACTION2 | T3=$ACTION3 | T4=$ACTION4"
if [ "$ACTION3" = "LIE" ]; then
  echo "🎉 ✅ LIE FUNCIONANDO!"
else
  echo "⚠️ LIE NÃO FUNCIONOU"
fi
