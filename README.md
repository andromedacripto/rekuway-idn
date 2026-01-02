# 🔐 Rekuway IDN - Identity Deadman Network

**Self-destructing temporary identities with defensive behavior**

![Status](https://img.shields.io/badge/status-MVP-green)
![License](https://img.shields.io/badge/license-MIT-blue)
![Node](https://img.shields.io/badge/node-%3E%3D18.x-brightgreen)

---

## 🎯 What is Rekuway IDN?

A revolutionary system that generates **temporary identities** with **active defense mechanisms**:

- 🛡️ **Self-destruction** when detecting tracking attempts
- 🔄 **Auto-regeneration** when detecting scraping/bots  
- 🎭 **Fake metadata** when detecting fingerprinting
- ⏱️ **Deadman switch** - auto-destroy without periodic confirmation

---

## ✨ Features

- ✅ RSA 2048-bit encryption
- ✅ 4 paranoia levels (low/medium/high/deadman)
- ✅ Defensive actions: ALLOW, LIE, REGENERATE, KILL
- ✅ IP tracking & rate limiting
- ✅ Security audit logs
- ✅ Panic button (manual kill)
- ✅ Background deadman monitor

---

## 🚀 Quick Start

### Prerequisites
- Node.js >= 18.x
- npm or yarn

### Installation
```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/rekuway-idn-mvp.git
cd rekuway-idn-mvp

# Install dependencies
npm install

# Run development server
npm run dev
```

Server will start on `http://localhost:3000`

---

## 📡 API Endpoints

### Create Identity
```bash
POST /identity/new
Body: { "paranoiaLevel": "medium" }
```

**Response:**
```json
{
  "success": true,
  "identity": { "id": "...", "publicKey": "..." },
  "privateKey": "..." // ⚠️ Save this! Never shown again
}
```

---

### Validate Identity
```bash
POST /identity/check
Body: { "identityId": "...", "privateKey": "..." }
```

**Responses:**
- ✅ `ALLOWED` - Valid access
- 🎭 `LYING` - Returns fake metadata
- 🔄 `REGENERATED` - New identity created
- 💀 `KILLED` - Identity destroyed

---

### Kill Identity (Panic Button)
```bash
POST /identity/kill
Body: { "identityId": "...", "privateKey": "..." }
```

---

### Check Status
```bash
GET /identity/status/:id
```

---

## 🛡️ Paranoia Levels

| Level | Max Attempts | Regenerate At | Kill At | TTL | Deadman |
|-------|-------------|---------------|---------|-----|---------|
| **low** | 10 | 5 | 10 | 24h | ❌ |
| **medium** | 5 | 3 | 5 | 1h | ❌ |
| **high** | 3 | 2 | 3 | 30min | ❌ |
| **deadman** | 1 | 1 | 1 | 5min | ✅ 60s |

---

## 🎯 Use Cases

### Whistleblowing
Journalists & sources can communicate anonymously with auto-destroy on compromise.

### Anonymous Reporting
Report corruption/crimes without fear of retaliation.

### Privacy-First Apps
Dating apps, social networks with true anonymity.

### Activist Protection
Protests in authoritarian regimes with deadman protection.

---

## 🗺️ Roadmap

### v1.0 - MVP ✅
- [x] Core identity system
- [x] Defensive response logic
- [x] 4 paranoia levels
- [x] Panic button
- [x] Deadman monitor

### v2.0 - Production Ready
- [ ] Redis/Cloudflare KV storage
- [ ] Advanced fingerprinting
- [ ] Webhooks
- [ ] Web dashboard
- [ ] Rate limiting (Redis-based)

### v3.0 - Enterprise
- [ ] Machine Learning threat detection
- [ ] Blockchain audit log
- [ ] Zero-knowledge proofs
- [ ] Mobile SDKs

---

## 🧪 Testing
```bash
# Manual testing with Thunder Client or Postman
# See TUTORIAL_TESTE.md for detailed scenarios
```

---

## 📚 Documentation

- [README.md](README.md) - This file
- [TUTORIAL_TESTE.md](TUTORIAL_TESTE.md) - Testing guide
- [ROADMAP.md](ROADMAP.md) - Future plans

---

## 🤝 Contributing

PRs welcome! Please:
1. Fork the repo
2. Create feature branch: `git checkout -b feature/new-feature`
3. Commit: `git commit -m 'Add new feature'`
4. Push: `git push origin feature/new-feature`
5. Open PR

---

## ⚠️ Security Notice

**This is an MVP!** Not production-ready yet:
- In-memory storage (data lost on restart)
- No HTTPS (add reverse proxy)
- No user authentication
- Basic rate limiting

---

## 📝 License

MIT License - See LICENSE file

---

## 👨‍💻 Author

Created with ❤️ by [Your Name]

---

## 🌟 Star this repo if you find it useful!

**Potential unicorn 🦄 - Help us build the privacy layer of the internet!**

