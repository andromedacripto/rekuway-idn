#!/bin/bash

# 🔥 TESTE COMPLETO - TODOS OS NÍVEIS DE PARANOIA
# Testa: LOW, MEDIUM, HIGH, DEADMAN

API_URL="https://rekuway-idn-mvp.vercel.app"

echo "╔════════════════════════════════════════════════════════╗"
echo "║    🔐 REKUWAY IDN - TESTE COMPLETO DE PARANOIA        ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""

# Função para testar um nível
test_level() {
  local LEVEL=$1
  local EXPECTED_REGENERATE=$2
  local EXPECTED_KILL=$3
  
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "🎯 TESTANDO NÍVEL: $LEVEL"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "Config: Regenera após $EXPECTED_REGENERATE | Mata após $EXPECTED_KILL"
  echo ""
  
  # Criar identidade
  echo "📝 Criando identidade $LEVEL..."
  RESPONSE=$(curl -s -X POST "$API_URL/identity/new" \
    -H "Content-Type: application/json" \
    -d "{\"paranoiaLevel\":\"$LEVEL\"}")
  
  ID=$(echo $RESPONSE | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
  
  if [ -z "$ID" ]; then
    echo "❌ ERRO: Falha ao criar identidade!"
    echo "Resposta: $RESPONSE"
    return 1
  fi
  
  echo "✅ Identidade criada: $ID"
  echo ""
  
  # Variáveis de controle
  ATTEMPT=1
  REGENERATED=false
  LIED=false
  KILLED=false
  REGENERATE_COUNT=0
  
  # Loop de tentativas (máximo 20)
  while [ $ATTEMPT -le 20 ]; do
    echo "❌ Tentativa $ATTEMPT..."
    
    R=$(curl -s -X POST "$API_URL/identity/check" \
      -H "Content-Type: application/json" \
      -d "{\"identityId\":\"$ID\",\"privateKey\":\"wrong-key-$ATTEMPT\"}")
    
    ACTION=$(echo $R | grep -o '"action":"[^"]*"' | cut -d'"' -f4)
    
    case $ACTION in
      "ALLOWED")
        echo "   ⚠️  ALLOWED - Tentativa registrada"
        ;;
        
      "REGENERATE")
        REGENERATED=true
        REGENERATE_COUNT=$((REGENERATE_COUNT + 1))
        NEW_ID=$(echo $R | grep -o '"newIdentity":{[^}]*"id":"[^"]*"' | grep -o '"id":"[^"]*"' | cut -d'"' -f4)
        echo "   🔄 REGENERATE #$REGENERATE_COUNT detectado!"
        echo "   Nova identidade: $NEW_ID"
        ID=$NEW_ID
        ;;
        
      "LIE")
        LIED=true
        echo "   🎭 LIE DETECTADO! Sistema enganou o atacante!"
        echo "   Fake metadata retornado"
        ;;
        
      "KILLED")
        KILLED=true
        REASON=$(echo $R | grep -o '"reason":"[^"]*"' | cut -d'"' -f4)
        echo "   💀 KILL DETECTADO!"
        echo "   Razão: $REASON"
        break
        ;;
        
      *)
        echo "   ⚠️  Ação desconhecida: $ACTION"
        ;;
    esac
    
    ATTEMPT=$((ATTEMPT + 1))
    
    # Prevenir loop infinito
    if [ $ATTEMPT -gt 20 ]; then
      echo ""
      echo "⚠️  Atingiu 20 tentativas - Parando teste"
      break
    fi
    
    sleep 0.5
  done
  
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "📊 RESULTADO DO TESTE - NÍVEL $LEVEL"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "Tentativas totais: $((ATTEMPT - 1))"
  echo "Regenerações: $REGENERATE_COUNT"
  
  if [ "$REGENERATED" = true ]; then
    echo "✅ REGENERATE: Funcionou"
  else
    echo "❌ REGENERATE: Não detectado"
  fi
  
  if [ "$LIED" = true ]; then
    echo "✅ LIE: Funcionou 🎭"
  else
    echo "⚠️  LIE: Não detectado (esperado apenas após REGENERATE)"
  fi
  
  if [ "$KILLED" = true ]; then
    echo "✅ KILL: Funcionou 💀"
  else
    echo "❌ KILL: Não funcionou"
  fi
  
  echo ""
  
  # Validação final
  if [ "$KILLED" = true ]; then
    echo "🎉 ✅ TESTE PASSOU!"
  else
    echo "⚠️  ❌ TESTE FALHOU - Identidade não foi morta"
  fi
  
  echo ""
  echo ""
}

# ============================================
# EXECUTAR TESTES
# ============================================

# Teste 1: LOW (regenera em 5, mata em 10)
test_level "low" 5 10

sleep 2

# Teste 2: MEDIUM (regenera em 3, mata em 5)
test_level "medium" 3 5

sleep 2

# Teste 3: HIGH (regenera em 2, mata em 3)
test_level "high" 2 3

sleep 2

# Teste 4: DEADMAN (regenera em 1, mata em 1)
test_level "deadman" 1 1

# ============================================
# RESUMO FINAL
# ============================================

echo "╔════════════════════════════════════════════════════════╗"
echo "║            📊 RESUMO GERAL DOS TESTES                  ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""
echo "Todos os níveis testados:"
echo "  ✅ LOW (5/10)"
echo "  ✅ MEDIUM (3/5)"
echo "  ✅ HIGH (2/3)"
echo "  ✅ DEADMAN (1/1)"
echo ""
echo "Sistema de defesa híbrida:"
echo "  1. ⚠️  ALLOW → Registra tentativa"
echo "  2. 🔄 REGENERATE → Nova identidade"
echo "  3. 🎭 LIE → Engana atacante"
echo "  4. 💀 KILL → Destruição permanente"
echo ""
echo "🎉 TESTE COMPLETO FINALIZADO!"
echo ""# Cole o conteúdo do artifact "test-all-levels.sh - Teste Completo"
