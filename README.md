# Certctl — Open-Source Certificate Control Plane

A self-hosted, cloud-agnostic certificate management platform for teams. Manage issuance, deployment, and renewal of TLS certificates at scale with zero private key exposure in the control plane.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/shankar0123/certctl)](https://goreportcard.com/report/github.com/shankar0123/certctl)
![Status: Active Development](https://img.shields.io/badge/status-active%20development-green)

## Overview

Certctl decouples certificate management into a control plane and lightweight agents deployed across your infrastructure. The control plane orchestrates issuance and renewal via multiple ACME issuers, while agents securely request, deploy, and renew certificates on target systems—all without exposing private keys outside the edge.

### Why Certctl?

- **Decoupled architecture**: Control plane + edge agents, no SSH or privileged access required
- **Multi-issuer support**: ACME (Let's Encrypt, Sectigo, etc.), with extensible connector framework
- **Zero private key exposure**: Keys generated and managed on agents, never sent to control plane
- **Audit-first design**: Every action logged with full traceability
- **Connector ecosystem**: Extensible issuer, target, and notifier connectors
- **Self-hosted**: Run on Kubernetes, Docker Compose, or bare metal—no cloud lock-in
- **Production-ready**: Graceful error handling, observability, database-backed state

## Quick Start

### With Docker Compose (Recommended)

```bash
# Clone the repo
git clone https://github.com/shankar0123/certctl.git
cd certctl

# Copy example environment variables
cp .env.example .env

# Start the stack
make docker-up

# Check health
curl http://localhost:8443/health
```

The stack includes PostgreSQL, certctl server, and a sample agent. Logs available via:

```bash
make docker-logs-server
make docker-logs-agent
```

### Manual Build & Run

#### Prerequisites
- Go 1.22+
- PostgreSQL 14+
- (Optional) Docker & Docker Compose

#### Build from Source

```bash
# Install dependencies
go mod download

# Build binaries
make build

# Run migrations
export DB_URL="postgres://certctl:certctl@localhost:5432/certctl?sslmode=disable"
make migrate-up

# Start server (in one terminal)
make run

# Start agent (in another terminal, with API key from server logs)
API_KEY="<key-from-server>" SERVER_URL=http://localhost:8443 ./bin/agent
```

## Architecture

### System Components

```
┌─────────────────────────────────────────────────────────┐
│                   CONTROL PLANE                         │
│  ┌──────────────────────────────────────────────────┐   │
│  │ API Server (8443)                                │   │
│  │  • Certificate management                        │   │
│  │  • Issuance orchestration                        │   │
│  │  • Audit logging                                 │   │
│  └──────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────┐   │
│  │ PostgreSQL Database                              │   │
│  │  • Certificates, agents, targets, policies       │   │
│  │  • Complete audit trail                          │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
         │                           │
         │ (mTLS + API Key)          │
         │                           │
    ┌────┴────┐             ┌────────┴────┐
    │         │             │             │
┌───┴──┐  ┌──┴───┐   ┌─────┴──┐  ┌──────┴────┐
│Agent │  │Agent │   │ Agent  │  │   Agent   │
│  #1  │  │  #2  │   │  #3    │  │   #N      │
└──────┘  └──────┘   └────────┘  └───────────┘
   │         │           │           │
   ├────┬────┼────┬───┬──┴─────┬─────┴──┬───┐
   │    │    │    │   │        │        │   │
┌──┴─┐┌─┴──┐┌───┴──┐│┌───────┐│┌──────┐│   │
│ACME││K8s ││F5 ││Vault│  │Webhook│
│    ││LB ││LB  ││  │   │
└────┘└────┘└────┘└────┘└──────┘
```

### Data Flow: Certificate Issuance

1. **Create Certificate** → Control plane stores managed certificate record
2. **Generate CSR** → Agent creates private key (stays local) and CSR
3. **Request Certificate** → Agent sends CSR to control plane
4. **Issue via ACME** → Control plane submits to issuer (Let's Encrypt, etc.)
5. **Return Certificate** → Agent receives signed cert, stores locally
6. **Deploy** → Agent pushes certificate to targets (NGINX, F5, IIS, etc.)
7. **Notify** → Webhook or email notification sent on completion

### Database Schema Overview

| Entity | Purpose |
|--------|---------|
| `certificates` | Managed certificate records with metadata |
| `agents` | Registered agents in the fleet |
| `targets` | Deployment targets (NGINX, F5, IIS, etc.) |
| `issuers` | ACME issuer configurations |
| `jobs` | Issuance and deployment jobs |
| `audit_logs` | Complete action trail |

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SERVER_HOST` | `0.0.0.0` | Server bind address |
| `SERVER_PORT` | `8443` | Server listen port |
| `DB_HOST` | `localhost` | PostgreSQL host |
| `DB_PORT` | `5432` | PostgreSQL port |
| `DB_USER` | `certctl` | Database user |
| `DB_PASSWORD` | — | Database password |
| `DB_NAME` | `certctl` | Database name |
| `LOG_LEVEL` | `info` | Log level (debug, info, warn, error) |
| `ACME_DIRECTORY_URL` | staging | ACME directory URL |
| `ACME_EMAIL` | — | ACME registration email |
| `SMTP_HOST` | — | SMTP server for email notifications |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_USERNAME` | — | SMTP username |
| `SMTP_PASSWORD` | — | SMTP password |
| `SMTP_FROM_ADDRESS` | — | Email from address |

See `.env.example` for complete reference.

## API Overview

### Key Endpoints

#### Certificates
- `POST /api/v1/certificates` — Create managed certificate
- `GET /api/v1/certificates` — List certificates
- `GET /api/v1/certificates/:id` — Get certificate details
- `PUT /api/v1/certificates/:id` — Update certificate
- `DELETE /api/v1/certificates/:id` — Archive certificate

#### Agents
- `POST /api/v1/agents` — Register new agent
- `GET /api/v1/agents` — List agents
- `GET /api/v1/agents/:id` — Get agent details
- `PUT /api/v1/agents/:id` — Update agent

#### Targets
- `POST /api/v1/targets` — Add deployment target
- `GET /api/v1/targets` — List targets
- `PUT /api/v1/targets/:id` — Update target
- `DELETE /api/v1/targets/:id` — Remove target

#### Issuers
- `POST /api/v1/issuers` — Register ACME issuer
- `GET /api/v1/issuers` — List issuers
- `PUT /api/v1/issuers/:id` — Update issuer

#### Audit
- `GET /api/v1/audit/logs` — Query audit trail
- `GET /api/v1/audit/logs/:id` — Get specific log entry

#### System
- `GET /health` — Health check

Full API docs: [docs/api.md](docs/api.md) (coming soon)

## Agent Setup Guide

### Installation

Agents can be deployed as:
- **Docker container**: `docker pull certctl:agent`
- **Systemd service**: `systemctl start certctl-agent`
- **Kubernetes DaemonSet**: See [docs/k8s-deployment.md](docs/k8s-deployment.md)

### Configuration

Agents require:
1. **Server URL**: Control plane address (e.g., `https://certctl.example.com:8443`)
2. **API Key**: Issued by control plane on agent registration
3. **Agent Name**: Unique identifier in fleet

Example systemd unit:

```ini
[Unit]
Description=Certctl Agent
After=network.target

[Service]
Type=simple
ExecStart=/opt/certctl-agent/agent
Environment="SERVER_URL=https://certctl.example.com:8443"
Environment="API_KEY=ey..."
Environment="AGENT_NAME=prod-web-01"
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=multi-user.target
```

## Supported Integrations

### Certificate Issuers
| Issuer | Status | Connector |
|--------|--------|-----------|
| Let's Encrypt (ACME v2) | ✓ Production | `acme` |
| Sectigo ACME | ✓ Tested | `acme` |
| Vault PKI | ◐ Planned | `vault` |
| DigiCert | ◐ Planned | `digicert` |

### Deployment Targets
| Target | Status | Connector |
|--------|--------|-----------|
| NGINX | ✓ Production | `nginx` |
| F5 BIG-IP | ✓ Tested | `f5` |
| Microsoft IIS | ✓ Tested | `iis` |
| Kubernetes Secrets | ◐ Planned | `k8s` |
| AWS CloudFront | ◐ Planned | `aws` |

### Notifiers
| Notifier | Status | Connector |
|----------|--------|-----------|
| Email (SMTP) | ✓ Production | `email` |
| Webhooks | ✓ Production | `webhook` |
| Slack | ◐ Planned | `slack` |
| PagerDuty | ◐ Planned | `pagerduty` |

## Development

### Local Setup

```bash
make install-tools
cp .env.example .env
make docker-up-dev

# Access PgAdmin at http://localhost:5050
# Server logs: make docker-logs-server
```

### Testing

```bash
# Run all tests
make test

# Run with coverage
make test-coverage

# Run specific package
go test -v ./internal/service/...
```

### Linting & Format

```bash
make lint
make fmt
make vet
```

### Building Connectors

See [docs/connectors.md](docs/connectors.md) for a step-by-step guide to building issuers, targets, and notifier connectors.

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit changes: `git commit -am 'Add feature'`
4. Push to branch: `git push origin feature/my-feature`
5. Open a pull request

### Code Standards
- Go 1.22+ with `go fmt`, `go vet`, `golangci-lint`
- Tests required for new features (>80% coverage)
- Clear commit messages
- Update relevant documentation

## Security

### Private Key Management
- Private keys **never** sent to control plane
- Keys generated and managed exclusively on agents
- Encrypted at rest on agent systems
- Cleared from memory after use

### Authentication
- Agent-to-server: mTLS + API key
- API key rotation supported
- Audit logging of all authenticated actions

### Audit Trail
- Complete action history in PostgreSQL
- Immutable audit logs
- Queryable by resource, user, timestamp, action

For security issues, email security@example.com (do not open public issues).

## Performance & Scaling

- **Agents**: Stateless, horizontal scaling via fleet management
- **Control Plane**: Single server handles 1000+ agents
- **Database**: PostgreSQL; vertical scaling recommended
- **Jobs**: Asynchronous processing; tunable concurrency

See [docs/scaling.md](docs/scaling.md) for deployment guidance.

## Troubleshooting

### Server Won't Start
```bash
# Check database connection
psql -h localhost -U certctl -d certctl

# Check logs
make docker-logs-server

# Verify environment variables
env | grep -E "DB_|SERVER_|ACME_"
```

### Agent Can't Connect
```bash
# Check server health
curl -v https://certctl.example.com:8443/health

# Verify API key
echo $API_KEY

# Check agent logs
make docker-logs-agent
```

### Certificate Not Deploying
1. Check agent is registered: `curl http://localhost:8443/api/v1/agents`
2. Check target is reachable: `curl http://target-server:22` (SSH test)
3. Review audit log: `curl http://localhost:8443/api/v1/audit/logs`

## Roadmap

- [ ] Kubernetes CRD for certificate management
- [ ] Terraform provider
- [ ] Multi-region deployment
- [ ] HA control plane with etcd backend
- [ ] Advanced scheduling policies
- [ ] Certificate pinning validation
- [ ] Hardware security module (HSM) support

## License

Certctl is licensed under the [Apache License 2.0](LICENSE). See LICENSE file for details.

