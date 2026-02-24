<p align="center">
  <h1 align="center">🛡️ VulnInventory</h1>
</p>

<p align="center">
  <strong>Open Source Vulnerability Management Platform</strong><br>
  Built for penetration testing teams and cybersecurity consultants
</p>

<p align="center">
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-features">Features</a> •
  <a href="#-screenshots">Screenshots</a> •
  <a href="#-documentation">Docs</a> •
  <a href="#-contributing">Contributing</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" />
  <img src="https://img.shields.io/badge/python-3.11+-blue.svg" />
  <img src="https://img.shields.io/badge/react-18+-61dafb.svg" />
  <img src="https://img.shields.io/badge/fastapi-0.100+-009688.svg" />
  <img src="https://img.shields.io/badge/docker-ready-2496ED.svg" />
</p>

---

## 🔍 What is VulnInventory?

VulnInventory is a vulnerability management platform designed for cybersecurity consultants and pentesting teams. It centralizes findings, assets, and scans across multiple clients and projects.

- **Free and open source** — No licensing fees, no vendor lock-in
- **Multi-tenant** — Manage multiple clients/organizations securely
- **Import-friendly** — Nessus, Qualys, Burp, SARIF, CSV, JSON
- **CVE-aware** — Built-in vulnerability catalog with NVD integration
- **Consultant-focused** — Built by pentesters, for pentesters

## ✨ Features

| Category | Details |
|----------|---------|
| **Findings** | Full lifecycle management, CVSS scoring, CWE/OWASP, comments, assignments |
| **Assets** | Per-project tracking, environment/criticality tagging, associations |
| **Scans** | Queue-based with Wapiti, Nuclei, OSV Scanner, VulnAPI |
| **Import/Export** | CSV, JSON, Nessus XML, Burp XML, SARIF |
| **VulnDB Catalog** | CVE dictionary, auto-fill forms, custom templates |
| **Multi-Tenant** | Organizations, projects, roles (Admin/Analyst/Viewer) |
| **Security** | httpOnly cookies, CSRF protection, scoped API keys, rate limiting |
| **Audit** | Full trail of all user actions |

## 📸 Screenshots

## 🚀 Quick Start

### Prerequisites
- [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/)

### 1. Clone

```bash
git clone https://github.com/CrisorHacker/vulninventory.git
cd vulninventory
```

### 2. Configure

```bash
cp .env.example .env
# REQUIRED: Change JWT_SECRET to a random string (min 32 chars)
# Generate one: python -c "import secrets; print(secrets.token_urlsafe(48))"
```

### 3. Start

```bash
docker compose up -d
```

### 4. Open

Go to [http://localhost:5173](http://localhost:5173), register an account, and start working.

## 📚 Vulnerability Catalog (Optional)

VulnInventory **no incluye un catalogo precargado**. Cada equipo carga su propio VulnDB desde una fuente externa.
El endpoint de importacion espera **JSONL** (un JSON por linea).

### Importar JSONL o CSV

**Ejemplo minimo (sin datos sensibles):**

- `docs/examples/vulndb_sample.jsonl`
- `docs/examples/vulndb_sample.csv`

**Script de importacion (acepta JSONL o CSV):**

```bash
API_BASE_URL=http://localhost:8001 \
API_KEY=TU_API_KEY \
./scripts/import_vulndb.sh docs/examples/vulndb_sample.jsonl
```

CSV:
```bash
API_BASE_URL=http://localhost:8001 \
API_KEY=TU_API_KEY \
./scripts/import_vulndb.sh docs/examples/vulndb_sample.csv
```

**Via UI:** Hallazgos → 📚 Catálogo → Importar JSONL → Upload file

### Formato JSONL esperado (un JSON por linea)

```json
{"short_id":"CVE-2024-1234","name":"Example RCE","base_score":9.8,"details":"Remote code execution in example library.","recommendations":"Actualizar a la version 1.2.3","ext_references":["https://example.com/advisory"],"cpe":""}
```

Documentacion completa: `docs/vulndb-import.md`.

## 🛠️ Development

```bash
# Backend
cd api && python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
# Start DB and Redis: docker compose -f docker-compose.dev.yml up -d
uvicorn app.main:app --reload --port 8000

# Frontend (separate terminal)
cd ui && npm install && npm run dev

# Worker (separate terminal)
cd worker && python worker.py
```

## 📖 Documentation

- [Architecture](docs/architecture.md)
- [API Reference](docs/api-reference.md)
- [Deployment](docs/deployment.md)
- [Development](docs/development.md)

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md).

**Help needed:**
- [ ] i18n (English UI)
- [ ] PDF report generation
- [ ] Additional scan adapters (Nmap, OpenVAS, Trivy)
- [ ] Test coverage
- [ ] React Router + component modularization

## 📋 Roadmap

- [x] Multi-tenant organizations
- [x] Finding lifecycle management
- [x] Scan queue with worker
- [x] Import/Export (CSV, JSON, Nessus, Burp, SARIF)
- [x] VulnDB catalog
- [x] Audit logging
- [x] httpOnly cookie auth + CSRF
- [ ] PDF report generation
- [ ] Slack/Teams notifications
- [ ] GraphQL API
- [ ] Plugin system for scan tools

## 🔒 Security

Report vulnerabilities responsibly. See [SECURITY.md](SECURITY.md).

**Do NOT open public issues for security vulnerabilities.**

## 📄 License

MIT — see [LICENSE](LICENSE).

---

<p align="center">
  Made with ❤️ for the cybersecurity community
</p>
