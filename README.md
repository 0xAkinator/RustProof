# 🛡️ RustProof - Professional Solana Security Analysis Platform

![RustProof Logo](https://img.shields.io/badge/RustProof-Security%20Scanner-orange?style=for-the-badge&logo=rust)

RustProof is a comprehensive, professional-grade security analysis platform specifically designed for Solana smart contracts written in Rust. It provides advanced vulnerability detection, compliance reporting, and detailed security insights for DeFi protocols, NFT projects, and other Solana-based applications.

## 🚀 Features

### 🔍 Advanced Security Analysis
- **60+ Professional Security Rules** covering critical Solana vulnerabilities
- **Real-time Pattern Matching** with advanced regex-based detection
- **Context-Aware Analysis** with multi-line code snippet evaluation
- **Vulnerability Correlation** to identify complex attack patterns

### 🎯 Comprehensive Vulnerability Coverage
- **Access Control Vulnerabilities** - Signer authorization, account ownership
- **DeFi Security Issues** - Oracle manipulation, slippage protection, flash loans
- **Solana-Specific Patterns** - PDA bump manipulation, CPI security
- **Token Security** - Mint authority, burn authority, metadata manipulation
- **Cross-Chain Security** - Bridge verification, message validation
- **Governance Security** - DAO proposals, voting mechanisms
- **Advanced DeFi Patterns** - AMM manipulation, yield farming, liquidation

### 📊 Professional Reporting
- **Interactive Web Dashboard** with real-time analysis
- **PDF Security Reports** with executive summaries
- **JSON Data Export** for integration with CI/CD pipelines
- **Compliance Scoring** for SOC 2, NIST, and OWASP frameworks

### 🏢 Enterprise Features
- **Session-based Scanning** for team collaboration
- **Platform Analytics** with aggregate security metrics
- **Vulnerability Prioritization** based on impact and exploitability
- **Real-world Context** with actual exploit examples
## 🚀 Quick Start

### Try the Live Platform
**🌐 Live Demo**: [https://rustproof.dev](https://rustproof.dev)

No setup required - upload your Rust files and get instant security analysis!

### Or Run Locally with Docker
## 🛠️ Technology Stack

- **Frontend**: React 19, Tailwind CSS, Axios
- **Backend**: FastAPI, Python 3.8+
- **Database**: MongoDB with Motor (async driver)
- **PDF Generation**: ReportLab
- **Architecture**: Microservices with Docker containerization

## 📋 Prerequisites

- Docker and Docker Compose
- Node.js 18+ (for local development)
- Python 3.8+ (for local development)
- MongoDB (containerized)

## 🚀 Quick Start with Docker

### 1. Clone the Repository
```bash
git clone https://github.com/0xAkinator/RustProof.git
cd rustproof
```

### 2. Environment Setup
Create environment files:

**.env** (root directory):
```env
MONGO_URL=mongodb://mongodb:27017
DB_NAME=rustproof
NODE_ENV=production
```

**frontend/.env**:
```env
REACT_APP_BACKEND_URL=http://localhost:8001
```

**backend/.env**:
```env
MONGO_URL=mongodb://mongodb:27017
DB_NAME=rustproof
```

### 3. Launch with Docker Compose
```bash
# Build and start all services
docker-compose up --build

# Or run in background
docker-compose up -d --build
```

### 4. Access the Application
- **Web Interface**: http://localhost:3000
- **API Documentation**: http://localhost:8001/docs
- **Health Check**: http://localhost:8001/api/health

## 🔧 Manual Development Setup

### Backend Setup
```bash
cd backend
pip install -r requirements.txt
uvicorn server:app --host 0.0.0.0 --port 8001 --reload
```

### Frontend Setup
```bash
cd frontend
yarn install
yarn start
```

### Database Setup
```bash
# Start MongoDB
docker run -d -p 27017:27017 --name mongodb mongo:latest
```

## 🎯 Usage Guide

### Web Interface
1. **Upload Rust Files**: Drag and drop .rs files or browse to select
2. **Real-time Analysis**: Watch as RustProof analyzes your code
3. **Review Results**: Examine vulnerabilities with detailed explanations
4. **Export Reports**: Download PDF or JSON reports for documentation

### API Integration
```python
import requests

# Upload file for analysis
with open('contract.rs', 'rb') as f:
    response = requests.post(
        'http://localhost:8001/api/scan',
        files={'file': f}
    )
    
scan_result = response.json()
print(f"Security Score: {scan_result['security_score']}")
```

### CLI Usage (Coming Soon)
```bash
rustproof scan contract.rs --format json --output report.json
```

## 📊 Vulnerability Categories

### Critical Vulnerabilities
- **Missing Signer Authorization** (RP-001)
- **Account Ownership Bypass** (RP-003)
- **PDA Bump Manipulation** (RP-004)
- **Oracle Price Manipulation** (RP-005)
- **Cross-Chain Bridge Verification** (RP-023)

### High-Risk Patterns
- **Integer Overflow** (RP-002)
- **Slippage Protection Missing** (RP-006)
- **Flash Loan Atomicity** (RP-007)
- **Token Authority Escalation** (RP-021, RP-022)
- **AMM Manipulation** (RP-026, RP-048)

### DeFi-Specific Issues
- **Liquidation Manipulation** (RP-014)
- **Yield Farm Exploits** (RP-027)
- **Interest Rate Manipulation** (RP-031)
- **Synthetic Asset Risks** (RP-040)
- **Stablecoin Peg Manipulation** (RP-055)

## 🔒 Security Rules Reference

RustProof includes 60+ professional security rules covering:

| Category | Rules | Description |
|----------|--------|-------------|
| Access Control | RP-001, RP-003, RP-009 | Authorization and permission checks |
| DeFi Security | RP-006, RP-007, RP-014, RP-026 | Financial protocol vulnerabilities |
| Token Security | RP-021, RP-022, RP-042 | Token minting, burning, and authority |
| Cross-Chain | RP-023, RP-054 | Bridge and message verification |
| Oracle Security | RP-005, RP-047 | Price feed and data validation |
| Governance | RP-015, RP-032 | DAO and voting mechanisms |

## 📈 Compliance Frameworks

RustProof provides compliance scoring for:
- **SOC 2** - Security controls and access management
- **NIST Cybersecurity Framework** - Risk management and security standards
- **OWASP Smart Contract Security** - Application security best practices

## 🧪 Testing

```bash
# Backend tests
cd backend
pytest tests/

# Frontend tests
cd frontend
npm test

# Integration tests
docker-compose -f docker-compose.test.yml up --abort-on-container-exit
```

## 📦 Docker Configuration

### Dockerfile (Multi-stage build)
```dockerfile
# Frontend build stage
FROM node:18-alpine as frontend-build
WORKDIR /app/frontend
COPY frontend/package.json frontend/yarn.lock ./
RUN yarn install --frozen-lockfile
COPY frontend/ ./
RUN yarn build

# Backend stage
FROM python:3.9-slim
WORKDIR /app
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ ./backend/
COPY --from=frontend-build /app/frontend/build ./frontend/build
EXPOSE 8001
CMD ["uvicorn", "backend.server:app", "--host", "0.0.0.0", "--port", "8001"]
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes and add tests
4. Run the test suite: `npm test && pytest`
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: [Wiki](https://github.com/0xAkinator/RustProof/wiki)
- **Issues**: [GitHub Issues](https://github.com/0xAkinator/RustProof/issues)
- **Discussions**: [GitHub Discussions](https://github.com/0xAkinator/rustproof/discussions)

## 🏆 Acknowledgments

- Solana Foundation for blockchain infrastructure
- Anchor Framework for Solana development patterns
- Security research community for vulnerability insights
- Open source contributors and maintainers

## 📊 Project Statistics

![GitHub stars](https://img.shields.io/github/stars/0xAkinator/rustproof?style=social)
![GitHub forks](https://img.shields.io/github/forks/0xAkinator/rustproof?style=social)
![GitHub issues](https://img.shields.io/github/issues/0xAkinator/rustproof)
![GitHub license](https://img.shields.io/github/license/0xAkinator/rustproof)

---

**RustProof** - Making Solana development safer, one scan at a time. 🛡️
