# 🔐 Rekuway IDN - Identity Deadman Network

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/andromedacripto/rekuway-idn-mvp/releases/tag/v1.0.0)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-Production%20Ready-success.svg)]()
[![Node](https://img.shields.io/badge/node-%3E%3D18.x-brightgreen.svg)]()

**The first identity system with active defense mechanisms.**

Temporary identities that protect themselves through automatic threat detection, regeneration, and self-destruction.

---

## 🎯 What Makes Rekuway IDN Unique

While VPNs hide and encryption protects, **Rekuway IDN fights back**.

| Feature | Traditional Systems | Rekuway IDN |
|---------|-------------------|-------------|
| **Identity Type** | Permanent | Temporary |
| **Defense** | Passive | **Active** |
| **Threat Response** | Manual | **Automatic** |
| **Regeneration** | None | **Auto-regeneration** |
| **Panic Button** | None | **Instant destruction** |
| **Deadman Switch** | None | **Auto-destroy without check-in** |

---

## ✨ Features

### 🛡️ **Active Defense System**
- Detects tracking attempts in real-time
- Automatically regenerates identities under attack
- Returns fake metadata when fingerprinting is detected
- Self-destructs under coercion

### 🔑 **API Key Authentication**
- Secure API key generation with tier-based limits
- Rate limiting per user (100 requests/minute for Startup tier)
- Monthly identity creation limits (1,000 identities/month)

### ⚙️ **Four Paranoia Levels**

| Level | Max Attempts | Auto-Regenerate | TTL | Use Case |
|-------|--------------|-----------------|-----|----------|
| `low` | 10 | After 5 attempts | 24 hours | General privacy |
| `medium` | 5 | After 3 attempts | 1 hour | Sensitive data |
| `high` | 3 | After 2 attempts | 30 minutes | Journalism, activism |
| `deadman` | 1 | After 1 attempt | 5 minutes* | Whistleblowing |

*Deadman mode requires check-in every 60 seconds or identity auto-destroys.

### 🎭 **Four Defense Actions**

1. **ALLOW** - Normal operation, logs activity
2. **LIE** - Returns fake IP, location, and device metadata
3. **REGENERATE** - Creates new identity automatically
4. **KILL** - Permanently destroys identity

---

## 🚀 Quick Start

### Prerequisites
- Node.js >= 18.x
- npm or yarn

### Installation

```bash
# Clone repository
git clone https://github.com/andromedacripto/rekuway-idn-mvp.git
cd rekuway-idn-mvp

# Install dependencies
npm install

# Run development server
npm run dev
```

Server starts on `http://localhost:3000`

---

## 📡 API Endpoints

### 1. Create API Key

```bash
POST /api-keys
Content-Type: application/json

{
  "userId": "user_001",
  "name": "My API Key",
  "tier": "startup"
}
```

**Response:**
```json
{
  "success": true,
  "apiKey": {
    "key": "rkwy_live_abc123...",
    "tier": "startup",
    "limits": {
      "identitiesPerMonth": 1000,
      "requestsPerMinute": 100
    }
  }
}
```

⚠️ **Save your API key! It will never be shown again.**

---

### 2. Create Identity

```bash
POST /identity/new
Authorization: Bearer YOUR_API_KEY
Content-Type: application/json

{
  "paranoiaLevel": "high"
}
```

**Response:**
```json
{
  "success": true,
  "identity": {
    "id": "1a3c2608-8c31-4aee-8a59-29926cd500d3",
    "publicKey": "-----BEGIN PUBLIC KEY-----...",
    "paranoiaLevel": "high",
    "expiresAt": 1767763445909,
    "isAlive": true
  },
  "privateKey": "-----BEGIN PRIVATE KEY-----..."
}
```

⚠️ **Save your private key! It will never be shown again.**

---

### 3. Validate Identity (With Active Defense)

```bash
POST /identity/check
Authorization: Bearer YOUR_API_KEY
Content-Type: application/json

{
  "identityId": "1a3c2608-8c31-4aee-8a59-29926cd500d3",
  "privateKey": "-----BEGIN PRIVATE KEY-----..."
}
```

**Possible Responses:**

**ALLOWED - Normal operation:**
```json
{
  "success": true,
  "action": "ALLOWED",
  "identity": {
    "id": "1a3c2608-8c31-4aee-8a59-29926cd500d3",
    "attempts": 1
  }
}
```

**LYING - Fake metadata returned:**
```json
{
  "success": true,
  "action": "LYING",
  "reason": "Fingerprint match detected",
  "identity": {
    "metadata": {
      "ip": "203.0.113.0",
      "location": "Tokyo, Japan",
      "device": "Mobile"
    }
  }
}
```

**REGENERATED - New identity created:**
```json
{
  "success": true,
  "action": "REGENERATED",
  "reason": "Exceeded suspicious attempt threshold",
  "newIdentity": {
    "id": "f1a632c7-9925-4e0b-9f81-5692b9e91e1e",
    "publicKey": "-----BEGIN PUBLIC KEY-----...",
    "privateKey": "-----BEGIN PRIVATE KEY-----...",
    "expiresAt": 1767765245909
  }
}
```

---

### 4. Kill Identity (Panic Button)

```bash
POST /identity/kill
Authorization: Bearer YOUR_API_KEY
Content-Type: application/json

{
  "identityId": "1a3c2608-8c31-4aee-8a59-29926cd500d3",
  "privateKey": "-----BEGIN PRIVATE KEY-----..."
}
```

**Response:**
```json
{
  "success": true,
  "message": "💀 Identity destroyed successfully"
}
```

---

### 5. Check Identity Status

```bash
GET /identity/status/:id
Authorization: Bearer YOUR_API_KEY
```

**Response:**
```json
{
  "exists": true,
  "expiresAt": 1767763445909,
  "paranoiaLevel": "high",
  "isAlive": true
}
```

---

## 🎯 Use Cases

### 🗞️ **Whistleblowing & Journalism**
Journalists and sources communicate anonymously with auto-destroy on compromise.

### 🔒 **Anonymous Reporting**
Report corruption or crimes without fear of retaliation.

### 🎭 **Privacy-First Applications**
Dating apps, social networks with true anonymity.

### ✊ **Activist Protection**
Protests in authoritarian regimes with deadman protection.

### 💼 **Corporate Whistleblowing**
Employees report violations safely with panic button protection.

---

## 🔐 Security Model

### What Rekuway IDN Protects:
✅ User identities with active defense  
✅ Auto-regeneration under attack  
✅ Fake metadata injection  
✅ Panic button & deadman switch  

### What You Need to Add:
- HTTPS/TLS (transport security)
- WAF/Cloudflare (infrastructure security)
- Redis encryption (data security for production)

**Rekuway IDN = Identity protection layer**

---

## 🗺️ Roadmap

### v1.0 (Current) ✅
- [x] RSA 2048 encryption
- [x] 4 paranoia levels
- [x] Active defense mechanisms
- [x] API key authentication
- [x] Rate limiting
- [x] Panic button
- [x] Deadman monitor

### v2.0 (Q2 2025)
- [ ] Post-quantum cryptography (hybrid RSA + Kyber)
- [ ] Redis distributed storage
- [ ] Advanced ML threat detection
- [ ] Webhooks & real-time alerts
- [ ] Web dashboard

### v3.0 (Q4 2025)
- [ ] Full quantum-resistant (Kyber + Dilithium)
- [ ] Blockchain audit logs
- [ ] Mobile SDKs (iOS/Android)
- [ ] Zero-knowledge proofs
- [ ] P2P distributed network

---

## 🧪 Testing

The system includes comprehensive logging for security auditing:

```
[API_KEY] Created for user landerson_teste (tier: startup)
[IDENTITY] Created new identity: 1a3c2608-... (level: high)
[DEFENSE] Event: fingerprint_match | Attempts: 2/3
[IDENTITY] 💀 KILLED: 1a3c2608-...
[IDENTITY] Regenerated: old -> new
```

All defensive actions are logged for compliance and security audits.

---

## 📚 Documentation

- [API Documentation](https://rekuway.com/docs) (Coming soon)
- [Security Whitepaper](https://rekuway.com/security) (Coming soon)
- [Integration Guide](https://rekuway.com/integration) (Coming soon)

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-feature`
3. Commit your changes: `git commit -m 'Add new feature'`
4. Push to the branch: `git push origin feature/new-feature`
5. Open a Pull Request

---

## ⚠️ Important Notes

**This is a v1.0 MVP:**
- Uses in-memory storage (data lost on restart)
- Requires HTTPS in production
- No user authentication system yet
- Basic rate limiting (upgrade to Redis for production)

**For production deployment:**
- Add Redis for persistent storage
- Configure HTTPS/SSL certificates
- Set up proper monitoring and logging
- Add WAF/DDoS protection (Cloudflare recommended)

---

## 📝 License

MIT License - See [LICENSE](LICENSE) file for details

---

## 👨‍💻 Author

**Landerson Gamarra**  
Rekuway Team

---

## 🌟 Support

If you find this project valuable:
- ⭐ Star this repository
- 🐛 Report issues
- 💡 Suggest features
- 🔗 Share with your network

---

## 📞 Contact

- **Website:** [rekuway.com](https://rekuway.xyz)
- **Email:** rekuway@gmail.com
- **Twitter:** [@rekuway](https://twitter.com/rekuway)
- **LinkedIn:** [Rekuway](https://linkedin.com/company/rekuway)

---

**Rekuway IDN: Your identity. Your shield.** 🛡️

Built with ❤️ for a more private internet.

