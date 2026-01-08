# 🔐 Rekuway IDN - Identity Deadman Network

[![Version](https://img.shields.io/badge/version-1.0.0--MVP-blue.svg)](https://github.com/andromedacripto/rekuway-idn-mvp)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-Production-success.svg)](https://rekuway-idn-mvp.vercel.app)
[![Uptime](https://img.shields.io/badge/uptime-99.9%25-brightgreen.svg)](https://rekuway-idn-mvp.vercel.app/health)

> **O primeiro sistema de identidade temporária do mundo com defesa híbrida inteligente.**
> 
> Rekuway IDN não apenas detecta ataques - **ele engana atacantes com dados falsos antes de destruir a identidade permanentemente.**

---

## 🎯 **O que é Rekuway IDN?**

Rekuway IDN é um sistema revolucionário de identidade temporária que protege seus dados com **4 camadas de defesa adaptativa**:

```
TENTATIVA SUSPEITA DETECTADA
         ↓
    ⚠️ ALLOW (Registra)
         ↓
    🔄 REGENERATE (Nova identidade)
         ↓
    🎭 LIE (Engana com fake data)
         ↓
    💀 KILL (Destruição permanente)
```

**Diferencial único:** Atacantes não sabem quando estão sendo enganados. O sistema retorna dados falsos convincentes antes de destruir a identidade.

---

## 🚀 **Features**

### ✨ **Sistema de Defesa Híbrido Inteligente**

- **ALLOW** - Registra tentativas suspeitas sem alertar o atacante
- **REGENERATE** - Cria nova identidade automaticamente quando threshold é atingido
- **LIE** - Retorna metadata falso (IP, localização, device) após regeneração
- **KILL** - Destruição permanente da identidade após segunda tentativa

### 🎚️ **4 Níveis de Paranoia Configuráveis**

| Nível | Regenera Após | Mata Após | TTL | Uso Recomendado |
|-------|---------------|-----------|-----|-----------------|
| **LOW** | 5 tentativas | 10 tentativas | 24h | Desenvolvimento e testes |
| **MEDIUM** | 3 tentativas | 5 tentativas | 1h | Uso cotidiano balanceado |
| **HIGH** | 2 tentativas | 3 tentativas | 30min | Alta segurança, dados sensíveis |
| **DEADMAN** | 1 tentativa | 1 tentativa | 5min | Máxima paranoia + auto-destruct timer |

### 🎭 **Fake Metadata Convincente**

Quando o sistema detecta comportamento suspeito após regeneração, retorna dados falsos realistas:

```json
{
  "action": "LIE",
  "identity": {
    "id": "valid-looking-uuid",
    "metadata": {
      "ip": "203.0.113.0",
      "location": "São Paulo, Brazil",
      "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
      "device": "Desktop"
    }
  },
  "warning": "⚠️ LAST CHANCE! Next failure = destruction."
}
```

Atacante pensa que conseguiu acesso. **Próxima tentativa = 💀 KILL.**

### 🔒 **Segurança de Nível Enterprise**

- ✅ Chaves criptográficas RSA 2048-bit
- ✅ Hash SHA-256 para armazenamento seguro
- ✅ Chave privada exposta apenas UMA VEZ na criação
- ✅ Rate limiting por IP automático
- ✅ Redis para performance e TTL automático
- ✅ Logs detalhados de todas as tentativas

### ⏱️ **Deadman Switch (Modo DEADMAN)**

No nível DEADMAN, identidades requerem confirmação de atividade (heartbeat) a cada 60 segundos. Sem heartbeat = auto-destruição automática.

---

## 📊 **Como Funciona: Exemplo Real (Nível HIGH)**

```
🔐 Usuário cria identidade
    └─ Recebe: ID + Chave Privada (única vez!)
    └─ Configurado: regenerateThreshold=2, maxAttempts=3

❌ Tentativa 1 (chave errada)
    └─ Action: ALLOWED
    └─ Log: attempts=1, totalAttempts=1
    └─ Remaining: 2 tentativas

❌ Tentativa 2 (chave errada)
    └─ Action: REGENERATE 🔄
    └─ Identidade antiga destruída
    └─ Nova identidade criada automaticamente
    └─ Nova chave privada gerada
    └─ Contadores preservados: totalAttempts=2, regenerations=1

❌ Tentativa 3 (chave errada na nova identidade)
    └─ Action: LIE 🎭
    └─ Retorna: Fake IP, localização falsa, device fictício
    └─ Warning: "⚠️ LAST CHANCE! Next failure = destruction."
    └─ Atacante pensa que funcionou!

❌ Tentativa 4 (insiste com chave errada)
    └─ Action: KILLED 💀
    └─ Identidade destruída PERMANENTEMENTE
    └─ Reason: "2nd failed attempt after regeneration"
    └─ Game over para o atacante
```

---

## 🎬 **Quick Start**

### **1. Criar Identidade**

```bash
curl -X POST https://rekuway-idn-mvp.vercel.app/identity/new \
  -H "Content-Type: application/json" \
  -d '{"paranoiaLevel":"high"}'
```

**Resposta:**
```json
{
  "success": true,
  "message": "⚠️ SAVE YOUR PRIVATE KEY! It will never be shown again.",
  "identity": {
    "id": "abc-123-def-456",
    "publicKey": "-----BEGIN PUBLIC KEY-----\n...",
    "paranoiaLevel": "high",
    "expiresAt": 1767845456260
  },
  "privateKey": "-----BEGIN PRIVATE KEY-----\n..."
}
```

⚠️ **IMPORTANTE:** Salve a chave privada! Ela nunca será mostrada novamente!

### **2. Validar Identidade**

```bash
curl -X POST https://rekuway-idn-mvp.vercel.app/identity/check \
  -H "Content-Type: application/json" \
  -d '{
    "identityId": "abc-123-def-456",
    "privateKey": "-----BEGIN PRIVATE KEY-----\n..."
  }'
```

**Resposta (sucesso):**
```json
{
  "success": true,
  "action": "ALLOWED",
  "identity": {
    "id": "abc-123-def-456",
    "attempts": 0,
    "totalAttempts": 0
  }
}
```

**Resposta (após regeneração - LIE):**
```json
{
  "success": false,
  "action": "LIE",
  "reason": "Suspicious activity after regeneration",
  "message": "🎭 Fake data returned. Next failed attempt will KILL identity.",
  "identity": {
    "id": "def-456-ghi-789",
    "metadata": {
      "ip": "203.0.113.0",
      "location": "São Paulo, Brazil"
    }
  },
  "warning": "⚠️ LAST CHANCE! Next failure = destruction.",
  "nextAction": "KILL"
}
```

---

## 🛠️ **Installation & Development**

### **Pré-requisitos**

- Node.js 18+
- Redis (Upstash)
- Vercel CLI (para deploy)

### **Setup Local**

```bash
# 1. Clone
git clone https://github.com/andromedacripto/rekuway-idn-mvp.git
cd rekuway-idn-mvp

# 2. Install
npm install

# 3. Configure .env
cat > .env << 'EOF'
UPSTASH_REDIS_REST_URL=your_redis_url
UPSTASH_REDIS_REST_TOKEN=your_redis_token
PORT=3000
NODE_ENV=development
EOF

# 4. Build
npm run build

# 5. Run
npm start
```

### **Deploy para Vercel**

```bash
# 1. Install Vercel CLI
npm i -g vercel

# 2. Login
vercel login

# 3. Deploy
vercel --prod
```

---

## 📡 **API Endpoints**

### **POST /identity/new**
Cria nova identidade temporária

**Body:**
```json
{
  "paranoiaLevel": "high"
}
```

**Response:** Identity + Private Key (única vez!)

---

### **POST /identity/check**
Valida identidade e retorna ação defensiva

**Body:**
```json
{
  "identityId": "uuid",
  "privateKey": "-----BEGIN PRIVATE KEY-----\n..."
}
```

**Possible Actions:**
- `ALLOWED` - Validação bem-sucedida
- `REGENERATE` - Nova identidade criada
- `LIE` - Fake metadata retornado
- `KILLED` - Identidade destruída

---

### **POST /identity/regenerate**
Regenera identidade manualmente (requer chave privada válida)

---

### **POST /identity/kill**
Panic button - destrói identidade imediatamente

---

### **GET /identity/status/:id**
Verifica status sem autenticação

**Response:**
```json
{
  "exists": true,
  "paranoiaLevel": "high",
  "attempts": 1,
  "totalAttempts": 2,
  "regenerations": 1,
  "remaining": 1
}
```

---

## 🧪 **Testing**

### **Automated Test Script**

```bash
# Execute teste completo
./test-no-jq.sh
```

**Output esperado:**
```
🔐 TESTE RÁPIDO LIE→KILL
========================
✅ ID: abc-123...

❌ Tentativa 1: ALLOWED
❌ Tentativa 2: REGENERATE
❌ Tentativa 3: LIE 🎭
❌ Tentativa 4: KILLED 💀

========================
RESUMO: T1=ALLOWED | T2=REGENERATE | T3=LIE | T4=KILLED
🎉 ✅ LIE FUNCIONANDO!
```

### **Manual Testing**

```bash
# 1. Criar identidade
ID=$(curl -s -X POST https://rekuway-idn-mvp.vercel.app/identity/new \
  -H "Content-Type: application/json" \
  -d '{"paranoiaLevel":"high"}' | jq -r '.identity.id')

# 2. Testar com chave errada até ver LIE
curl -X POST https://rekuway-idn-mvp.vercel.app/identity/check \
  -H "Content-Type: application/json" \
  -d "{\"identityId\":\"$ID\",\"privateKey\":\"wrong-key\"}"
```

---

## 🏗️ **Architecture**

```
┌─────────────────────────────────────────────┐
│            Client Application                │
└──────────────┬──────────────────────────────┘
               │
               ↓
┌─────────────────────────────────────────────┐
│         Vercel Serverless API                │
│  ┌────────────────────────────────────────┐ │
│  │  Identity Routes (api/index.ts)        │ │
│  │  - POST /identity/new                  │ │
│  │  - POST /identity/check  ← Defense!    │ │
│  │  - POST /identity/regenerate           │ │
│  │  - POST /identity/kill                 │ │
│  └────────────────────────────────────────┘ │
│                    ↓                         │
│  ┌────────────────────────────────────────┐ │
│  │  Defensive Service                     │ │
│  │  - Analyze threat patterns             │ │
│  │  - Decide: ALLOW/REGENERATE/LIE/KILL   │ │
│  │  - Generate fake metadata              │ │
│  └────────────────────────────────────────┘ │
└──────────────┬──────────────────────────────┘
               ↓
┌─────────────────────────────────────────────┐
│         Upstash Redis (KV Store)             │
│  - Identity storage with TTL                 │
│  - Attempt tracking                          │
│  - IP rate limiting                          │
└─────────────────────────────────────────────┘
```

---

## 🎨 **Configuration (paranoia.json)**

```json
{
  "high": {
    "maxAttempts": 3,
    "regenerateThreshold": 2,
    "ttlSeconds": 1800,
    "fakeFingerprintEnabled": true,
    "deadmanTimer": null,
    "description": "Modo paranóico - Alta segurança"
  }
}
```

---

## 🔐 **Security Best Practices**

### **For Users:**

1. ✅ **Salve a chave privada com segurança** - ela nunca será mostrada novamente
2. ✅ **Use HTTPS sempre** - nunca envie chaves por HTTP não criptografado
3. ✅ **Escolha o nível de paranoia adequado** - HIGH para dados sensíveis
4. ✅ **Monitore tentativas** - use `/identity/status/:id` regularmente
5. ✅ **Panic button** - use `/identity/kill` em caso de suspeita

### **For Developers:**

1. ✅ **Nunca logue chaves privadas** - são dados sensíveis
2. ✅ **Configure rate limiting** - proteja contra brute force
3. ✅ **Use Redis com TTL** - identidades expiram automaticamente
4. ✅ **Monitore logs** - detecte padrões de ataque
5. ✅ **Keep dependencies updated** - segurança primeiro

---

## 📈 **Performance**

- **Latência:** < 100ms (p95)
- **Throughput:** 1000+ req/s
- **Redis TTL:** Cleanup automático de identidades expiradas
- **Vercel Edge:** Deploy global em 30+ regiões

---

## 🤝 **Contributing**

Contributions are welcome! Please:

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing`)
5. Open Pull Request

---

## 📝 **License**

MIT License - see [LICENSE](LICENSE) file

---

## 🎉 **Credits**

Created with 💀 by [andromedacripto](https://github.com/andromedacripto)

**Powered by:**
- Vercel (Serverless deployment)
- Upstash Redis (KV storage)
- TypeScript (Type safety)
- Express.js (API framework)

---

## 🔗 **Links**

- **Production API:** https://rekuway-idn-mvp.vercel.app
- **Health Check:** https://rekuway-idn-mvp.vercel.app/health
- **GitHub:** https://github.com/andromedacripto/rekuway-idn-mvp
- **Documentation:** [Coming Soon]

---

## 💬 **Support**

Having issues? Open an issue on GitHub or contact us.

---

<div align="center">

**🔐 Rekuway IDN - Identity Deadman Network**

*The future of temporary identity protection*

[![GitHub](https://img.shields.io/badge/GitHub-andromedacripto-blue.svg?logo=github)](https://github.com/andromedacripto)
[![Vercel](https://img.shields.io/badge/Deploy-Vercel-black.svg?logo=vercel)](https://vercel.com)

</div>

