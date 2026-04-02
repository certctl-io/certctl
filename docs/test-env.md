# certctl Testing Environment

A step-by-step guide to running certctl locally with real certificate authorities. Every command is spelled out. Every expected output is shown. If something goes wrong, the troubleshooting section tells you exactly what to check.

---

## What Is This?

certctl manages TLS certificates — the things that put the padlock icon in your browser. This test environment lets you run the entire platform on your laptop so you can see it work end-to-end: create a certificate, have it signed by a CA, deploy it to a web server, and watch the dashboard track everything.

You'll start 7 Docker containers that talk to each other:

| Container | What it does | IP Address | You access it at |
|---|---|---|---|
| **PostgreSQL** | Stores all certctl data (certs, jobs, agents, audit trail) | 10.30.50.2 | Not directly — internal only |
| **pebble-challtestsrv** | DNS/HTTP challenge test server for Pebble | 10.30.50.3 | Not directly — Pebble talks to it |
| **Pebble** | A fake Let's Encrypt (tests the ACME protocol without touching the real internet) | 10.30.50.4 | Not directly — the server talks to it |
| **step-ca** | A private Certificate Authority (think: your company's internal CA) | 10.30.50.5 | Not directly — the server talks to it |
| **certctl-server** | The brain. API + web dashboard + scheduler + ACME challenge server | 10.30.50.6 | **http://localhost:8443** |
| **NGINX** | A web server. The agent deploys certificates here. | 10.30.50.7 | **https://localhost:8444** |
| **certctl-agent** | The hands. Generates keys, deploys certs to NGINX | 10.30.50.8 | Not directly — it talks to the server |

**Why 7 containers?** Because certctl sits between CAs (who sign certificates) and servers (who use certificates). To test the full flow, you need at least one CA and one server. We include two different CAs (Pebble for ACME, step-ca for private CA) plus a third built-in one (Local CA) so you can test all three issuance methods.

**Why static IPs?** Pebble uses challtestsrv as its DNS server (it needs to know the IP). challtestsrv resolves all domains to the certctl-server (10.30.50.6) so Pebble can validate HTTP-01 challenges. Static IPs avoid DNS race conditions during startup.

---

## Before You Start

### Install Docker Desktop

If you don't have Docker yet:

1. Go to [https://www.docker.com/products/docker-desktop/](https://www.docker.com/products/docker-desktop/)
2. Download Docker Desktop for your OS (Mac, Windows, or Linux)
3. Install it and open it
4. Wait for the Docker icon in your menu bar/taskbar to say "Docker Desktop is running"

Verify it works by opening a terminal and running:

```bash
docker --version
```

You should see something like:

```
Docker version 27.x.x, build xxxxxxx
```

If you get "command not found", Docker isn't installed or isn't in your PATH. Restart your terminal and try again.

Also verify Docker Compose is available:

```bash
docker compose version
```

You should see:

```
Docker Compose version v2.x.x
```

If this says "command not found", you have an old Docker version. Update Docker Desktop.

### Make Sure You Have the certctl Repo

You need the certctl source code on your machine. If you haven't cloned it yet:

```bash
git clone https://github.com/shankar0123/certctl.git
cd certctl
```

If you already have it, make sure you're on the latest version:

```bash
cd certctl
git pull
```

---

## Step 1: Start Everything

Open a terminal. Navigate to the `deploy` directory inside the certctl repo:

```bash
cd certctl/deploy
```

Verify you're in the right place:

```bash
ls docker-compose.test.yml
```

You should see:

```
docker-compose.test.yml
```

If you see "No such file or directory", you're in the wrong directory. Run `pwd` to see where you are, then navigate to the correct path.

Now start the test environment:

```bash
docker compose -f docker-compose.test.yml up --build
```

**What this does**: Builds the certctl server and agent from source code (compiles Go + React), downloads Docker images for PostgreSQL, NGINX, Pebble, and step-ca, then starts all 7 containers.

**First run takes 2-5 minutes** because it has to:
- Download ~2 GB of Docker images
- Compile the Go server binary
- Compile the React frontend
- Wait for each service to become healthy

**What you'll see**: A wall of colored log lines from all 7 containers. This is normal. You're looking for lines like:

```
certctl-test-server    | {"level":"INFO","msg":"server started","address":"0.0.0.0:8443"}
certctl-test-agent     | {"level":"INFO","msg":"agent starting","server_url":"http://certctl-server:8443"}
certctl-test-stepca    | Serving HTTPS on :9000 ...
certctl-test-pebble    | Listening on: 0.0.0.0:14000
```

**Leave this terminal running.** The logs will keep scrolling — that's fine. You need a second terminal for the next steps.

### Open a Second Terminal

Open a new terminal window or tab. Navigate to the deploy directory again:

```bash
cd certctl/deploy
```

Check that all containers are up:

```bash
docker compose -f docker-compose.test.yml ps
```

You should see 7 services. The important thing is that none say `Exit` or `Restarting`:

```
NAME                        STATUS
certctl-test-agent          Up
certctl-test-challtestsrv   Up
certctl-test-nginx          Up (healthy)
certctl-test-pebble         Up
certctl-test-postgres       Up (healthy)
certctl-test-server         Up (healthy)
certctl-test-stepca         Up (healthy)
```

**If certctl-test-server says "Restarting"**: It probably started before step-ca or Pebble were ready. Wait 30 seconds and check again. If it keeps restarting, see [Troubleshooting](#troubleshooting).

---

## Step 2: Open the Dashboard

Open your web browser and go to:

**http://localhost:8443**

You'll see a login screen asking for an API key. Enter:

```
test-key-2026
```

Click "Login" (or press Enter).

**What you should see**: The certctl dashboard. It will be mostly empty because we haven't created any certificates yet. That's expected — you're looking at a clean environment.

You should see a sidebar on the left with navigation items like Dashboard, Certificates, Jobs, Agents, Issuers, Targets, etc.

**If the page doesn't load**: The server might still be starting. Wait 30 seconds and refresh. Check that `certctl-test-server` shows "healthy" in `docker compose ps`.

**If you get "Unauthorized"**: Make sure you typed the API key exactly: `test-key-2026`

---

## Step 3: Verify the Pre-Seeded Data

The test environment comes with **pre-seeded data** in the database. This gives you everything you need to start testing immediately — an agent, an owner, a team, three issuers (one per CA), a certificate profile, and an NGINX deployment target. No manual setup required.

The seed data comes from two files:
- `migrations/seed.sql` — default renewal policy and policy rules (loaded in all environments)
- `migrations/seed_test.sql` — test-specific data: team, owner, agent, issuers, profile, and NGINX target

Go back to your second terminal. Let's verify the data loaded correctly.

### Check the agent

```bash
curl -s -H "Authorization: Bearer test-key-2026" \
  http://localhost:8443/api/v1/agents | python3 -m json.tool
```

**What this command does**:
- `curl` makes an HTTP request (like a browser but from the terminal)
- `-s` means "silent" (don't show progress bars)
- `-H "Authorization: Bearer test-key-2026"` sends the API key (same one you used to log in)
- `python3 -m json.tool` formats the JSON response so it's readable

**What you should see**: A JSON response showing agents, including `agent-test-01`:

```json
{
    "agents": [
        {
            "id": "agent-test-01",
            "name": "test-agent-01",
            "status": "online",
            ...
        }
    ],
    ...
}
```

The important parts: `"id": "agent-test-01"` and `"status": "online"`. If the status says `"online"`, the agent container has already sent its first heartbeat to the server.

**If the status is still "offline"**: The agent container hasn't finished starting. Wait 30 seconds and try again. The agent sends a heartbeat every 60 seconds.

**If you get "Connection refused"**: The server isn't running. Run `docker compose -f docker-compose.test.yml ps` and check the server status.

### Check the issuers

```bash
curl -s -H "Authorization: Bearer test-key-2026" \
  http://localhost:8443/api/v1/issuers | python3 -m json.tool
```

You should see three issuers:
- `iss-local` — Local CA (Self-Signed)
- `iss-acme-staging` — ACME (Pebble Test CA)
- `iss-stepca` — step-ca (Private CA)

### Check the target

```bash
curl -s -H "Authorization: Bearer test-key-2026" \
  http://localhost:8443/api/v1/targets | python3 -m json.tool
```

You should see `target-test-nginx` — the NGINX deployment target, assigned to `agent-test-01`.

The target config uses no-op commands for `reload_command` and `validate_command` (both set to `"true"`, the Unix command that always succeeds). This is because the agent runs in a separate container from NGINX — it can't directly run `nginx -s reload`. Instead, the agent writes cert files to a shared Docker volume, and we reload NGINX manually (or via the test script).

### See it all in the dashboard

Open the dashboard at http://localhost:8443 and click through the sidebar:
- **Agents** — you should see `test-agent-01`
- **Issuers** — you should see all three CAs
- **Targets** — you should see `Test NGINX`

Everything is wired up. The agent knows about the server, the server knows about the agent, and the NGINX target is linked to the agent. Time to issue certificates.

---

## Step 4: Issue Your First Certificate (Local CA)

Now the good part. You're going to create a certificate record and trigger issuance. Here's what will happen behind the scenes:

1. You tell the server "I want a certificate for local.certctl.test"
2. The server creates an issuance **job** (status: AwaitingCSR) and waits
3. The agent **polls** the server for work (every 30 seconds)
4. The agent sees the job, **generates an ECDSA P-256 key pair** locally
5. The agent creates a **CSR** (Certificate Signing Request) containing the public key — NOT the private key
6. The agent submits the CSR to the server
7. The server forwards the CSR to the **Local CA** issuer, which signs it
8. The server stores the signed certificate and creates a **deployment job** (status: Pending)
9. The agent picks up the deployment job, fetches the signed cert, reads the local private key
10. The agent writes cert + key + chain to the shared NGINX volume (`/nginx-certs/`)
11. You reload NGINX, and it starts serving the new certificate

The private key **never leaves the agent**. The server only ever sees the CSR (public key + metadata).

**Important**: The deployment job is routed to the specific agent via `agent_id`. The server's job processor skips deployment jobs that have an `agent_id` set — those are exclusively for the agent to pick up via polling. This prevents a race condition where the server would set the job to "Running" before the agent could see it.

### Step 4a: Create the certificate record

```bash
curl -s -X POST http://localhost:8443/api/v1/certificates \
  -H "Authorization: Bearer test-key-2026" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "mc-local-test",
    "name": "local-test-cert",
    "common_name": "local.certctl.test",
    "sans": ["local.certctl.test"],
    "issuer_id": "iss-local",
    "owner_id": "owner-test-admin",
    "team_id": "team-test-ops",
    "renewal_policy_id": "rp-default",
    "certificate_profile_id": "prof-test-tls",
    "environment": "development"
  }' | python3 -m json.tool
```

**What each field means**:
- `id`: Unique certificate identifier (you choose this; the `mc-` prefix is convention for "managed certificate")
- `name`: Human-readable display name (must be unique across all certs)
- `common_name`: The domain name for the certificate. Doesn't need to be a real domain for testing.
- `sans`: Subject Alternative Names — additional domain names the cert is valid for. Always include the common_name here too.
- `issuer_id`: Which CA should sign this cert. `iss-local` is the built-in self-signed CA (pre-seeded in Step 3).
- `owner_id`: Who owns this certificate. `owner-test-admin` was pre-seeded. This controls notification routing.
- `team_id`: Which team is responsible. `team-test-ops` was pre-seeded. Used for organizational grouping.
- `renewal_policy_id`: The renewal rules to follow. `rp-default` was created by seed.sql — 30-day renewal window, auto-renew enabled, alert at 30/14/7/0 days before expiry.
- `certificate_profile_id`: Crypto constraints. `prof-test-tls` allows ECDSA P-256 and RSA-2048 keys, 90-day max TTL, serverAuth EKU.
- `environment`: A label for organization (development, staging, production)

**What you should see**: The certificate record echoed back as JSON with `"status": "pending"`.

**If you get a 400 error** with a message about a missing field: double-check that every field in the JSON above is present. The API requires `name`, `common_name`, `owner_id`, `team_id`, `issuer_id`, and `renewal_policy_id` — all of them.

This just creates the record. The certificate isn't issued yet.

### Step 4b: Link it to the NGINX target

The certificate record exists, but certctl doesn't know WHERE to deploy it yet. We need to create a mapping in the `certificate_target_mappings` table that says "deploy this cert to this target." This is done via SQL (the API doesn't expose a mapping endpoint):

```bash
docker exec certctl-test-postgres psql -U certctl -d certctl -c \
  "INSERT INTO certificate_target_mappings (certificate_id, target_id) VALUES ('mc-local-test', 'target-test-nginx') ON CONFLICT DO NOTHING;"
```

**What this does**: Inserts a row into the join table that links your certificate to the NGINX target. When certctl creates deployment jobs, it queries this table to figure out where to deploy.

**If you get "connection refused"**: The postgres container isn't running. Check `docker compose ps`.

### Step 4c: Trigger issuance

```bash
curl -s -X POST http://localhost:8443/api/v1/certificates/mc-local-test/renew \
  -H "Authorization: Bearer test-key-2026" | python3 -m json.tool
```

**What this does**: Tells certctl "issue (or renew) this certificate now." The server creates a job, and the background system takes over.

**What you should see**: A JSON response confirming the job was created.

### Step 4d: Watch it happen

Switch to your first terminal (the one running `docker compose up`) and watch the logs. You should see a sequence like this (simplified):

```
certctl-test-server  | "msg":"created renewal job" ...
certctl-test-agent   | "msg":"polling for work" ...
certctl-test-agent   | "msg":"generating ECDSA P-256 key pair" ...
certctl-test-agent   | "msg":"submitting CSR" ...
certctl-test-server  | "msg":"CSR received, forwarding to issuer" ...
certctl-test-server  | "msg":"certificate signed by Local CA" ...
certctl-test-agent   | "msg":"deploying certificate to target" ...
certctl-test-agent   | "msg":"deployment complete" ...
```

This takes about 30-60 seconds because the agent polls for work every 30 seconds.

### Step 4e: Reload NGINX and verify

The agent writes cert files to the shared volume, but NGINX doesn't automatically detect the change (the agent's reload command is a no-op in this test setup). Reload NGINX manually:

```bash
docker exec certctl-test-nginx nginx -s reload
```

Wait a few seconds, then check what certificate NGINX is now serving:

```bash
echo | openssl s_client -connect localhost:8444 -servername local.certctl.test 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates
```

**What this command does**: Connects to NGINX on port 8444 (HTTPS), downloads the certificate it presents, and prints the subject (who the cert is for), issuer (who signed it), and validity dates.

**What you should see**:

```
subject=CN=local.certctl.test
issuer=CN=certctl Local CA
notBefore=...
notAfter=...
```

The `subject` should match the domain name you chose. The `issuer` should say "certctl Local CA". The dates should show it was just issued (today) and expires in about 90 days.

**If you see the old self-signed placeholder cert** (issuer says something like `CN=placeholder.certctl.test`): The deployment hasn't happened yet. Wait another 30 seconds for the agent to poll, then reload NGINX and try again. Check the agent logs for errors.

### Step 4f: Check the dashboard

Open the dashboard at http://localhost:8443 and:

1. Click **Certificates** in the sidebar — you should see `mc-local-test` with status "Active"
2. Click on it to see the detail page — you should see version history, the signed certificate details, and the deployment timeline
3. Click **Jobs** — you should see the issuance and deployment jobs with their statuses

---

## Step 5: Issue a Certificate via ACME (Pebble)

This is the real deal. ACME is the protocol that Let's Encrypt uses to issue certificates automatically. Pebble is a test ACME server that runs locally — it does everything real Let's Encrypt does, just without the internet.

**How it works behind the scenes**: When you trigger issuance, certctl talks to Pebble and says "I want a cert for acme.certctl.test." Pebble says "prove you control that domain — serve this random token at `http://acme.certctl.test/.well-known/acme-challenge/<token>`." certctl starts a temporary HTTP server on port 80 inside the certctl-server container (10.30.50.6) to serve the token. Meanwhile, Pebble resolves `acme.certctl.test` via challtestsrv, which is configured to return 10.30.50.6 for ALL domains. So Pebble connects to the certctl-server on port 80, finds the challenge token, and validates. It's all self-contained within the Docker network.

**Key detail**: The `CERTCTL_ACME_INSECURE=true` env var is set on the server because Pebble uses a self-signed TLS certificate on its ACME directory endpoint (port 14000). Without this flag, Go's HTTP client would reject the connection. This is only for test environments — never use this in production.

### Step 5a: Create the certificate record

```bash
curl -s -X POST http://localhost:8443/api/v1/certificates \
  -H "Authorization: Bearer test-key-2026" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "mc-acme-test",
    "name": "acme-test-cert",
    "common_name": "acme.certctl.test",
    "sans": ["acme.certctl.test"],
    "issuer_id": "iss-acme-staging",
    "owner_id": "owner-test-admin",
    "team_id": "team-test-ops",
    "renewal_policy_id": "rp-default",
    "certificate_profile_id": "prof-test-tls",
    "environment": "staging"
  }' | python3 -m json.tool
```

Notice `issuer_id` is `iss-acme-staging` this time — that routes to Pebble instead of the Local CA.

### Step 5b: Link to target and trigger issuance

```bash
# Link to NGINX target (same SQL pattern as Step 4b)
docker exec certctl-test-postgres psql -U certctl -d certctl -c \
  "INSERT INTO certificate_target_mappings (certificate_id, target_id) VALUES ('mc-acme-test', 'target-test-nginx') ON CONFLICT DO NOTHING;"

# Trigger issuance
curl -s -X POST http://localhost:8443/api/v1/certificates/mc-acme-test/renew \
  -H "Authorization: Bearer test-key-2026" | python3 -m json.tool
```

### Step 5c: Watch the ACME exchange

In your first terminal (the log stream), watch for ACME-related messages:

```
certctl-test-server  | "msg":"ACME order created" ...
certctl-test-server  | "msg":"solving HTTP-01 challenge" ...
certctl-test-server  | "msg":"challenge server started","address":":80" ...
certctl-test-server  | "msg":"challenge validated" ...
certctl-test-server  | "msg":"certificate issued via ACME" ...
```

This takes a bit longer than Local CA (maybe 30-60 seconds for the challenge validation plus the agent poll cycle).

### Step 5d: Reload NGINX and verify

```bash
docker exec certctl-test-nginx nginx -s reload
sleep 3

echo | openssl s_client -connect localhost:8444 -servername acme.certctl.test 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates
```

The issuer should now say something like "Pebble Intermediate CA" instead of "certctl Local CA".

**If issuance fails**: Check the server logs with `docker logs certctl-test-server --tail 50`. Look for ACME-related errors. Common issues: "x509: certificate signed by unknown authority" (Pebble trust issue — the `setup-trust.sh` script should handle this, but CERTCTL_ACME_INSECURE=true is the belt-and-suspenders fix).

---

## Step 6: step-ca (Private CA)

step-ca is a private CA by Smallstep. Companies use it for internal certificates (things that don't need to be publicly trusted). Unlike ACME, step-ca doesn't do challenge validation — it uses a provisioner key for authentication.

The step-ca connector now supports proper JWE decryption of the provisioner key (PBES2-HS256+A128KW) and JWT-based authentication against step-ca's `/sign` API. The production code is fully functional.

**Test environment status**: The automated test script fully tests step-ca issuance (Phase 6). The `setup-trust.sh` script extracts the provisioner key from step-ca's `ca.json` configuration and copies it to the server container. The step-ca connector decrypts the JWE-encrypted provisioner key, generates JWT auth tokens, and issues certificates via the native `/sign` API.

You can verify step-ca is healthy:

```bash
docker exec certctl-test-server curl -sk https://step-ca:9000/health
```

You should see `{"status":"ok"}`.

**Alternative**: step-ca also supports ACME. You can configure it as an ACME issuer pointing to `https://step-ca:9000/acme/acme/directory` instead of using the native `/sign` API.

---

## Step 7: Test Revocation

Revocation means "this certificate is no longer trusted, even though it hasn't expired yet." You'd do this if a private key was compromised, a server was decommissioned, or a cert was superseded by a new one.

### Step 7a: Revoke the Local CA cert

```bash
curl -s -X POST http://localhost:8443/api/v1/certificates/mc-local-test/revoke \
  -H "Authorization: Bearer test-key-2026" \
  -H "Content-Type: application/json" \
  -d '{"reason": "superseded"}' | python3 -m json.tool
```

**What `"reason": "superseded"` means**: You're telling the system WHY you're revoking. These reasons come from RFC 5280 (the TLS certificate standard). Other valid reasons: `keyCompromise`, `affiliationChanged`, `cessationOfOperation`, `certificateHold`, `privilegeWithdrawn`.

### Step 7b: Check the CRL (Certificate Revocation List)

```bash
curl -s -H "Authorization: Bearer test-key-2026" \
  http://localhost:8443/api/v1/crl | python3 -m json.tool
```

**What you should see**: A list that includes the revoked certificate's serial number, the reason, and the timestamp.

### Step 7c: Check in the dashboard

Go to **Certificates** in the sidebar. The `mc-local-test` cert should now show "Revoked" status with a red indicator. Click on it — the detail page should show a revocation banner with the reason and timestamp.

---

## Step 8: Test Discovery

The agent is configured to scan `/nginx-certs` every 6 hours for existing certificates. It already ran a scan when it started up. Let's see what it found.

```bash
curl -s -H "Authorization: Bearer test-key-2026" \
  http://localhost:8443/api/v1/discovered-certificates | python3 -m json.tool
```

**What you should see**: Any certificates that exist in the NGINX cert directory, including the ones you deployed in Steps 4-5. The discovery system extracts metadata (CN, SANs, issuer, expiry, fingerprint) from the PEM files.

Check the summary:

```bash
curl -s -H "Authorization: Bearer test-key-2026" \
  http://localhost:8443/api/v1/discovery-summary | python3 -m json.tool
```

This shows counts: how many are Unmanaged, Managed, and Dismissed.

In the dashboard: click **Discovery** in the sidebar to see the triage view.

---

## Step 9: Test Renewal

Force a renewal on the ACME certificate to see the full cycle happen again:

```bash
curl -s -X POST http://localhost:8443/api/v1/certificates/mc-acme-test/renew \
  -H "Authorization: Bearer test-key-2026" | python3 -m json.tool
```

After 30-90 seconds (agent poll + ACME challenge validation), reload NGINX and check:

```bash
docker exec certctl-test-nginx nginx -s reload
sleep 3

echo | openssl s_client -connect localhost:8444 -servername acme.certctl.test 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -serial
```

Go to **Certificates** in the dashboard, click on `mc-acme-test`, and look at the **Version History** section. You should see two versions now — the original and the renewal. The newer one should have a "Current" badge.

---

## Step 10: Test EST Enrollment (RFC 7030)

EST (Enrollment over Secure Transport) is a standard protocol for certificate enrollment used by devices, WiFi networks (802.1X), MDM systems, and IoT. The certctl server includes a built-in EST server that delegates to whichever issuer you configure.

The test environment enables EST with `CERTCTL_EST_ENABLED=true` and `CERTCTL_EST_ISSUER_ID=iss-local`, meaning EST enrollments are signed by the Local CA.

### Step 10a: Check available CA certificates

```bash
curl -sk http://localhost:8443/.well-known/est/cacerts \
  -H "Authorization: Bearer test-key-2026"
```

**What this does**: Requests the CA certificate chain in PKCS#7 format (base64-encoded DER). This is the EST equivalent of "show me your trust anchor."

**What you should see**: A base64-encoded blob. This is a degenerate PKCS#7 SignedData structure containing the Local CA's certificate.

### Step 10b: Check CSR attributes

```bash
curl -sk http://localhost:8443/.well-known/est/csrattrs \
  -H "Authorization: Bearer test-key-2026"
```

This returns the CSR attributes the server expects. It may return an empty response if no specific attributes are required — that's normal for the Local CA.

### Step 10c: Enroll a certificate via EST

Generate a CSR and submit it:

```bash
# Generate a key pair and CSR
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout /tmp/est-test.key -out /tmp/est-test.csr -nodes \
  -subj "/CN=est-device.certctl.test" 2>/dev/null

# Convert CSR to base64-encoded DER (EST wire format)
EST_CSR=$(openssl req -in /tmp/est-test.csr -outform DER | base64 -w 0)

# Submit to EST simpleenroll endpoint
curl -sk -X POST http://localhost:8443/.well-known/est/simpleenroll \
  -H "Authorization: Bearer test-key-2026" \
  -H "Content-Type: application/pkcs10" \
  -d "$EST_CSR"
```

**What you should see**: A base64-encoded PKCS#7 response containing the signed certificate. The Local CA signed your CSR without any challenge validation (it trusts the API key).

### Step 10d: Verify the issued certificate

Decode and inspect the response (if you saved it to a variable):

```bash
curl -s -H "Authorization: Bearer test-key-2026" \
  http://localhost:8443/api/v1/audit-events | python3 -m json.tool | head -30
```

Check the audit trail — you should see an `est_enrollment` event with the CN `est-device.certctl.test`.

### Step 10e: Re-enroll (simplereenroll)

EST also supports re-enrollment (certificate renewal). The same CSR format works:

```bash
curl -sk -X POST http://localhost:8443/.well-known/est/simplereenroll \
  -H "Authorization: Bearer test-key-2026" \
  -H "Content-Type: application/pkcs10" \
  -d "$EST_CSR"
```

This should return another signed certificate.

---

## Step 11: Test S/MIME Certificate Issuance

S/MIME certificates are used for email signing and encryption — a different use case from TLS server certificates. The test environment includes a pre-seeded S/MIME profile (`prof-test-smime`) with the `emailProtection` Extended Key Usage (EKU).

**How it differs from TLS**: TLS certs use `serverAuth` EKU and `KeyUsage: DigitalSignature | KeyEncipherment`. S/MIME certs use `emailProtection` EKU and `KeyUsage: DigitalSignature | ContentCommitment` (formerly NonRepudiation). The Local CA issuer adapts its KeyUsage flags based on the EKU — this is the "adaptive KeyUsage" feature.

### Step 11a: Create an S/MIME certificate record

```bash
curl -s -X POST http://localhost:8443/api/v1/certificates \
  -H "Authorization: Bearer test-key-2026" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "mc-smime-test",
    "name": "smime-test-cert",
    "common_name": "testuser@certctl.test",
    "sans": ["testuser@certctl.test"],
    "issuer_id": "iss-local",
    "owner_id": "owner-test-admin",
    "team_id": "team-test-ops",
    "renewal_policy_id": "rp-default",
    "certificate_profile_id": "prof-test-smime",
    "environment": "development"
  }' | python3 -m json.tool
```

Notice:
- `common_name` is an email address, not a domain
- `sans` contains the email address (the agent's CSR builder routes email SANs to the `EmailAddresses` field instead of `DNSNames`)
- `certificate_profile_id` is `prof-test-smime` (not `prof-test-tls`)

### Step 11b: Link to target and trigger issuance

```bash
docker exec certctl-test-postgres psql -U certctl -d certctl -c \
  "INSERT INTO certificate_target_mappings (certificate_id, target_id) VALUES ('mc-smime-test', 'target-test-nginx') ON CONFLICT DO NOTHING;"

curl -s -X POST http://localhost:8443/api/v1/certificates/mc-smime-test/renew \
  -H "Authorization: Bearer test-key-2026" | python3 -m json.tool
```

### Step 11c: Verify the S/MIME certificate

After the agent processes the job (30-60 seconds), check the certificate details:

```bash
curl -s -H "Authorization: Bearer test-key-2026" \
  http://localhost:8443/api/v1/certificates/mc-smime-test | python3 -m json.tool
```

The certificate should show `"status": "active"`. To verify the EKU on the actual cert, you can export it:

```bash
curl -s -H "Authorization: Bearer test-key-2026" \
  http://localhost:8443/api/v1/certificates/mc-smime-test/export/pem | python3 -m json.tool
```

If you decode the certificate PEM, you should see:
- **Extended Key Usage**: `E-mail Protection` (OID 1.3.6.1.5.5.7.3.4)
- **Key Usage**: `Digital Signature, Non Repudiation` (not KeyEncipherment)
- **Subject Alternative Name**: `email:testuser@certctl.test`

---

## Step 12: Explore the Dashboard

Now that you have real data from TLS, ACME, EST, and S/MIME tests, poke around the dashboard:

- **Dashboard** (home page): Charts showing certificate status distribution, expiration timeline, job trends, and issuance rate. These populate based on the certs and jobs you just created.
- **Certificates**: List of all certificates. Click one to see full details, version history, deployment timeline, and the revoke/export buttons.
- **Jobs**: Every action (issuance, renewal, deployment) creates a job. You can see the full history with status transitions. Click a job ID to see its detail page with verification status.
- **Agents**: Shows `test-agent-01` with its heartbeat status, OS info, architecture, and IP address.
- **Issuers**: Shows the three active issuers (Local CA, ACME/Pebble, step-ca). Click one to see its configuration and the certificates it has issued.
- **Targets**: Shows the NGINX target with its configuration and deployment history.
- **Discovery**: Triage view for discovered certificates. You can claim them (link to a managed cert) or dismiss them.
- **Audit**: Every API call is recorded. You can filter by time range, actor, and action type. Try exporting as CSV or JSON.
- **Observability**: Health status, metrics gauges, and Prometheus scrape configuration.

---

## Step 13: Run the Automated Test Script

The repo includes a comprehensive test script that automates everything in Steps 4-11 plus additional API spot checks:

```bash
cd certctl/deploy
bash test/run-test.sh
```

**What it does** (13 phases):
1. **Phase 0**: Checks prerequisites (Docker, curl, openssl, python3)
2. **Phase 1**: Starts the Docker Compose environment (or reuses if running)
3. **Phase 2**: Waits for all services to become healthy
4. **Phase 3**: Verifies pre-seeded data (agents, issuers, targets, profiles — including `prof-test-smime`)
5. **Phase 4**: Issues a certificate via Local CA, deploys to NGINX, verifies TLS
6. **Phase 5**: Issues a certificate via ACME/Pebble (full HTTP-01 challenge flow)
7. **Phase 6**: step-ca issuance via native `/sign` API with JWK provisioner auth
8. **Phase 7**: Revokes the Local CA cert, checks CRL
9. **Phase 8**: Checks discovery results
10. **Phase 9**: Tests renewal on the ACME cert
11. **Phase 10**: EST enrollment — tests `cacerts`, `csrattrs`, `simpleenroll` (generates CSR, submits base64 DER), and `simplereenroll`
12. **Phase 11**: S/MIME issuance — creates cert with `prof-test-smime` profile and `emailProtection` EKU, verifies the issued cert has the correct EKU, KeyUsage (Digital Signature, not KeyEncipherment), and email SAN
13. **Phase 12**: API spot checks (health, metrics, stats, audit, Prometheus)

The script prints PASS/FAIL/SKIP for each check. At the end, you get a summary with total counts.

**Note on NGINX reloads**: The test script runs `docker exec certctl-test-nginx nginx -s reload` after each deployment phase because the agent's reload command is a no-op (agent and NGINX are separate containers with a shared volume).

---

## Step 14: Test via the CLI (Optional)

If you have Go installed, you can build and test the CLI tool:

```bash
# From the certctl repo root
go build -o certctl-cli ./cmd/cli

# List certificates
./certctl-cli --server http://localhost:8443 --api-key test-key-2026 list-certs

# Get a specific certificate
./certctl-cli --server http://localhost:8443 --api-key test-key-2026 get-cert mc-acme-test

# Check health
./certctl-cli --server http://localhost:8443 --api-key test-key-2026 health

# Get metrics (JSON format)
./certctl-cli --server http://localhost:8443 --api-key test-key-2026 --format json metrics
```

---

## Architecture Notes (For Experts)

### Container Network Topology

All containers share a bridge network (`certctl-test`, subnet 10.30.50.0/24) with static IPs. This is required because:

- **Pebble** uses challtestsrv as its DNS server (configured via `-dnsserver 10.30.50.3:8053`)
- **challtestsrv** resolves ALL domains to 10.30.50.6 (certctl-server) for HTTP-01 challenge validation
- **Pebble** validates challenges by connecting to the resolved IP on port 80 (configured in `pebble-config.json` with `"httpPort": 80`)

### Key Generation Flow (Agent-Side)

```
Server creates job (AwaitingCSR) → Agent polls, sees job →
Agent generates ECDSA P-256 key pair locally →
Agent creates CSR (public key + CN + SANs) →
Agent POSTs CSR to server → Server signs via issuer →
Server stores cert, creates Deployment job (Pending) →
Agent polls, sees Deployment job →
Agent fetches signed cert from server →
Agent reads local private key from /var/lib/certctl/keys/ →
Agent writes cert + key + chain to /nginx-certs/ (shared volume) →
Job marked Completed
```

### Shared Volume Architecture

The `nginx_certs` Docker volume is mounted at different paths in different containers:
- **NGINX** mounts it at `/etc/nginx/certs/` (where nginx.conf reads cert.pem and key.pem)
- **Agent** mounts it at `/nginx-certs/` (where the target config tells it to write)

Same volume, different mount paths. The agent writes to `/nginx-certs/cert.pem` and NGINX reads from `/etc/nginx/certs/cert.pem` — they're the same file.

### Why NGINX Needs Manual Reload

The agent and NGINX run in separate containers. The target config's `reload_command` runs inside the agent container, not NGINX. So `reload_command` is set to `"true"` (a no-op). To reload NGINX after the agent deploys a cert, run:

```bash
docker exec certctl-test-nginx nginx -s reload
```

In production, you'd either: (a) run the agent on the same host as NGINX so reload works directly, or (b) use inotify/polling inside the NGINX container to watch the cert directory for changes.

### Trust Store Setup

The `setup-trust.sh` script runs inside the certctl-server container at startup:

1. Fetches Pebble's root CA from its management API (`https://pebble:15000/roots/0`) — this is container-to-container only, port 15000 is **not** exposed to the host
2. Copies step-ca's root CA from the shared volume (`/stepca-data/certs/root_ca.crt`)
3. Runs `update-ca-certificates` to add both to Alpine's trust store
4. Execs the certctl server binary

This is needed because the ACME and step-ca connectors use Go's default HTTP client (which validates TLS). As a fallback, `CERTCTL_ACME_INSECURE=true` skips TLS verification for the ACME directory specifically.

### Deployment Job Routing

Deployment jobs have an `agent_id` field set at creation time (resolved from target → agent relationship). The server's job processor (`ProcessPendingJobs`) skips deployment jobs that have an `agent_id` — those are exclusively for the agent to pick up via `GetPendingWork()`. This prevents a race condition where the server would set the job to "Running" before the agent could see it (the agent's `ListPendingByAgentID` only returns jobs in "Pending" status).

---

## Troubleshooting

### The server keeps restarting

**Symptom**: `docker compose ps` shows certctl-test-server with status "Restarting".

**Why**: The server tried to start before Pebble or step-ca were ready, and the trust store setup failed.

**Fix**: Wait 30 seconds for Pebble and step-ca to finish starting, then restart just the server:

```bash
docker compose -f docker-compose.test.yml restart certctl-server
```

Then check:

```bash
docker compose -f docker-compose.test.yml ps
```

The server should now show "Up (healthy)".

### "x509: certificate signed by unknown authority"

**Symptom**: You see this error in the server logs when trying to issue a cert via ACME.

**Why**: The server doesn't trust Pebble's CA certificate. The `setup-trust.sh` script should have added it, but Pebble wasn't ready when the server started.

**Diagnose**:

```bash
# Check if the CA certs were added to the trust store
docker exec certctl-test-server ls -la /usr/local/share/ca-certificates/
```

You should see `pebble-ca.crt` and `step-ca-root.crt`. If either is missing:

```bash
# Check if Pebble is reachable from the server container
docker exec certctl-test-server curl -sk https://pebble:15000/roots/0
```

If this prints a PEM certificate, the fetch works but the trust store wasn't updated. Restart the server:

```bash
docker compose -f docker-compose.test.yml restart certctl-server
```

**Fallback**: The `CERTCTL_ACME_INSECURE=true` environment variable is set on the server, which skips TLS verification for the ACME directory. This should prevent this error for ACME. If you still see it, the issue is likely with step-ca's TLS.

### step-ca issuance fails with "provisioner not found"

**Symptom**: Server logs show `"provisioner not found or invalid audience"` when trying to issue via step-ca.

**Why**: The provisioner key path (`CERTCTL_STEPCA_KEY_PATH`) doesn't point to the correct JWE-encrypted key file, or the password (`CERTCTL_STEPCA_PASSWORD`) doesn't match. In the test environment, step-ca auto-bootstraps and stores the provisioner key inside the `stepca_data` Docker volume. The certctl-server mounts this volume read-only at `/stepca-data/`.

**Fix**: Verify the provisioner key exists at the configured path inside the server container:

```bash
docker exec certctl-test-server ls -la /stepca-data/secrets/
```

You should see a `provisioner_key` file. If it's missing, step-ca hasn't finished bootstrapping yet — restart the server after step-ca is healthy.

### Agent isn't picking up jobs

**Symptom**: You triggered issuance but nothing happens. No deployment, no cert on NGINX.

**Step 1**: Check agent logs:

```bash
docker logs certctl-test-agent --tail 50
```

Look for error messages. Common ones:
- "401 Unauthorized" — API key mismatch
- "connection refused" — server isn't running
- "no pending work" — jobs exist but aren't assigned to this agent

**Step 2**: Verify the agent is registered:

```bash
curl -s -H "Authorization: Bearer test-key-2026" \
  http://localhost:8443/api/v1/agents/agent-test-01 | python3 -m json.tool
```

**Step 3**: Check for pending jobs:

```bash
curl -s -H "Authorization: Bearer test-key-2026" \
  "http://localhost:8443/api/v1/jobs?status=Pending&status=AwaitingCSR" | python3 -m json.tool
```

If there are pending jobs but the agent isn't picking them up, check that the job's `agent_id` matches `agent-test-01`.

**Step 4**: Check if the server's job processor is stealing deployment jobs. Look in server logs for `"skipping agent-routed deployment job"`. If you DON'T see this message but see deployment jobs going to "Running" status, there's a bug in the job processor skip logic.

### NGINX still shows the placeholder cert

**Symptom**: After issuance, `openssl s_client` still shows the self-signed placeholder cert (issuer says `CN=placeholder.certctl.test`).

**Why**: Either the deployment job hasn't run yet, or NGINX needs reloading.

**Step 1**: Check if the cert files exist with recent timestamps:

```bash
docker exec certctl-test-nginx ls -la /etc/nginx/certs/
```

You should see `cert.pem`, `key.pem`, and `chain.pem` with recent timestamps (not from when the container first started).

**Step 2**: If the files are there but NGINX is serving the old cert, force a reload:

```bash
docker exec certctl-test-nginx nginx -s reload
```

**Step 3**: If the files aren't there, the deployment job hasn't completed. Check the jobs:

```bash
curl -s -H "Authorization: Bearer test-key-2026" \
  "http://localhost:8443/api/v1/jobs?type=Deployment" | python3 -m json.tool
```

Look at the job status. If it's "Running" and stuck, the server's job processor may have picked it up instead of the agent (this was a known bug — the fix skips deployment jobs with `agent_id` in the server's `ProcessPendingJobs`).

### ACME challenge validation fails

**Symptom**: Server logs show ACME challenge failed or timed out.

**Diagnose**:

```bash
# Check that challtestsrv is resolving to certctl-server
docker exec certctl-test-pebble curl -s http://10.30.50.3:8055/dns-request-history
```

The challenge server runs on port 80 inside the certctl-server container. Verify it's listening:

```bash
docker exec certctl-test-server netstat -tlnp 2>/dev/null | grep :80 || \
  docker exec certctl-test-server ss -tlnp | grep :80
```

If the ACME connector hasn't started the challenge server yet (it only starts during issuance), you won't see port 80 listening. Trigger issuance and check again.

### Port conflict (address already in use)

**Symptom**: `docker compose up` fails with "Bind for 0.0.0.0:8443 failed: port is already allocated".

**Why**: Another process is using port 8443 (maybe a previous test run, or another service).

**Fix**: Either stop the other process, or change the port in docker-compose.test.yml. Find the line:

```yaml
    ports:
      - "8443:8443"
```

Change it to a different port, like:

```yaml
    ports:
      - "9443:8443"
```

Then access the dashboard at http://localhost:9443 instead.

### Starting completely fresh

If something is really broken, nuke everything and start over:

```bash
# Stop everything and delete ALL data (database, step-ca state, certs, everything)
docker compose -f docker-compose.test.yml down -v

# Rebuild from scratch
docker compose -f docker-compose.test.yml up --build
```

The `-v` flag deletes all Docker volumes. step-ca will regenerate its root CA. The database will re-seed from scratch. You'll need to redo Steps 4-11.

---

## How to Stop

When you're done testing:

```bash
# Stop all containers (keeps data for next time)
docker compose -f docker-compose.test.yml down
```

To start again later (without rebuilding):

```bash
docker compose -f docker-compose.test.yml up
```

To start fresh (wipe all data):

```bash
docker compose -f docker-compose.test.yml down -v
docker compose -f docker-compose.test.yml up --build
```

---

## Quick Reference

| What | Value |
|---|---|
| Dashboard URL | http://localhost:8443 |
| API key | `test-key-2026` |
| NGINX HTTP | http://localhost:8080 |
| NGINX HTTPS | https://localhost:8444 |
| Agent ID | `agent-test-01` |
| Local CA issuer | `iss-local` |
| ACME issuer | `iss-acme-staging` |
| step-ca issuer | `iss-stepca` |
| NGINX target | `target-test-nginx` |
| TLS profile | `prof-test-tls` |
| S/MIME profile | `prof-test-smime` |
| Renewal policy | `rp-default` |
| Owner | `owner-test-admin` |
| Team | `team-test-ops` |
| Docker subnet | `10.30.50.0/24` |
