# DockScan

[![License: GPL v3](https://img.shields.io/badge/license-GPLv3-1a1a1a?style=flat-square&labelColor=1a1a1a&color=8a6f3a)](LICENSE)
[![Built with Claude Code](https://img.shields.io/badge/built%20with-Claude%20Code-1a1a1a?style=flat-square&labelColor=1a1a1a&color=d8b66b)](https://claude.com/claude-code)
[![Status](https://img.shields.io/badge/status-alpha-1a1a1a?style=flat-square&labelColor=1a1a1a&color=c8302f)](https://github.com/murat-akpinar/DockScan/releases)
[![Go](https://img.shields.io/badge/Go-1.25-1a1a1a?style=flat-square&labelColor=1a1a1a&color=00ADD8&logo=go&logoColor=fff)](https://go.dev)
[![React](https://img.shields.io/badge/React-18-1a1a1a?style=flat-square&labelColor=1a1a1a&color=61DAFB&logo=react&logoColor=fff)](https://react.dev)
[![Docker](https://img.shields.io/badge/Docker-compose-1a1a1a?style=flat-square&labelColor=1a1a1a&color=2496ED&logo=docker&logoColor=fff)](https://www.docker.com)

[🇬🇧 English](README.md) | [🇹🇷 Türkçe](README_TR.md)

A web dashboard that collects and visualizes Trivy security scan results. Aggregates Trivy JSON outputs from CI/CD pipelines into a single central location for easy review.

<div align="center">
  <img src="/images/dashboard.png" alt="Dashboard" width="32%" />
  <img src="/images/project.png" alt="Project" width="32%" />
  <img src="/images/comparison.png" alt="Comparison" width="32%" />
</div>

## Features

- **Project-Based View**: View all Docker image scans for each project on a single page
- **Severity Filtering**: Filter projects by CRITICAL, HIGH, MEDIUM, and LOW severity levels
- **Letter Grade System**: Automatic security grade (A–F) for Trivy, Checkov, and OSV results
- **Checkov IaC Scanning**: Detect misconfigurations in Dockerfiles and infrastructure code
- **OSV-Scanner**: Find vulnerabilities in Go modules, npm, pip, and other dependency lockfiles
- **Security Page**: Project-based navigation with grade badges for Checkov and OSV findings
- **Detailed Vulnerability List**: ID, description, fixed version, and reference links for each finding
- **CVE Search**: Query which projects/images contain a specific CVE
- **Timeline**: Visualize how scans change over time with an interactive legend
- **Global Dashboard**: View aggregate statistics across all projects
- **Diff Comparison**: See which vulnerabilities were fixed or newly introduced between two scans
- **Deep URL Routing**: `/projects/{projectName}` URLs are directly shareable and bookmarkable
- **Auto Cleanup**: Scan files older than 30 days are automatically deleted; at least one file per project folder is always kept

## Quick Start

### Requirements

- Docker and Docker Compose

### Installation

1. Create the `.env` file:
```bash
cp .example.env .env
```

2. Build and start the containers:
```bash
docker compose up -d --build
```

3. Access the dashboard:
- `http://localhost:3017` (or `FRONTEND_PORT` in `.env`)

> The backend is only accessible within the container network; all API requests are routed through nginx (`/api/...`). Only `FRONTEND_PORT` is exposed externally.

## Adding Trivy Scan Results

### File Format

Place Trivy JSON reports in the `export/` folder. The backend automatically extracts project, image, and tag information from the filename or from the `ArtifactName` field inside the JSON.

**Supported Formats:**

1. **Directory Structure** (Recommended):
   ```
   export/{project}/{image}-{YYYYMMDD-HHMMSS}.json
   ```
   Example: `export/dockscan/backend-20251126-182000.json`

2. **Flat Structure**:
   ```
   export/{project}-{image}-{YYYYMMDD-HHMMSS}.json
   ```
   Example: `export/dockscan-backend-20251126-182000.json`

3. **Auto Parse via ArtifactName** (Easiest):
   Automatically parsed from the `ArtifactName` field inside the JSON:
   - `ArtifactName: "dockscan_backend:latest"` → Project: `dockscan`, Image: `backend`, Tag: `latest`

### Image Naming Convention

The `project_service` format is recommended. The left side of `_` is the project name, the right side is the service name:

```
dockscan_backend:test-v1.0   → Project: dockscan  | Image: backend  | Tag: test-v1.0
dockscan_nginx:latest        → Project: dockscan  | Image: nginx    | Tag: latest
myapp_api:v2.3               → Project: myapp     | Image: api      | Tag: v2.3
```

### Scanning Local Images (Windows)

To scan locally built Docker images:

```powershell
# Prepare the export folder
New-Item -ItemType Directory -Force .\export\dockscan | Out-Null

# Scan the image (Trivy is pulled automatically)
$TS = Get-Date -Format "yyyyMMdd-HHmmss"
docker run --rm `
  -v /var/run/docker.sock:/var/run/docker.sock `
  -v "${PWD}\export\dockscan:/output" `
  aquasec/trivy:latest image `
  --format json `
  --output "/output/dockscan_backend-${TS}.json" `
  dockscan_backend:latest

# Reload the index immediately (optional — instead of waiting 60s)
Invoke-RestMethod -Method POST "http://localhost:3018/api/reload"
```

### CI/CD Integration — `trigger-nexus.sh`

> For the Jenkins Shared Library that automates Trivy scanning inside pipelines, see [devops-jenkins-library](https://github.com/murat-akpinar/devops-jenkins-library).

In a Jenkins pipeline, SSH into the server and run `trigger-nexus.sh` for each built image. The script scans only the specified image, not the entire Nexus registry.

```bash
# Scan a specific image and tag
./trigger-nexus.sh --image dockscan_backend --tag test-v1.0
./trigger-nexus.sh --image dockscan_nginx --tag test-v1.0
```

After the scan completes, the backend index is updated within ~60 seconds. The result can then be queried via `/api/grades`:

```bash
# Wait for scan to finish
sleep 70

# Check project grade
GRADE=$(curl -s "http://<host>:3017/api/grades?project=dockscan" \
  | jq -r '.projects[0].grade')

echo "Security Grade: $GRADE"

if [[ "$GRADE" == "F" ]]; then
  echo "ERROR: Security grade is critical ($GRADE), stopping pipeline."
  exit 1
fi
```

## Letter Grade System

### Trivy (image vulnerabilities)

The backend (`/api/grades`) and frontend dashboard use the same criteria:

| Grade | CRITICAL | HIGH | MEDIUM | Description |
|-------|----------|------|--------|-------------|
| **A** | 0 | ≤ 2 | ≤ 5 | Excellent |
| **B** | 0 | ≤ 5 | ≤ 10 | Good |
| **C** | ≤ 2 | ≤ 8 | ≤ 15 | Medium risk |
| **D** | ≤ 9 | — | — | High risk |
| **F** | ≥ 10 | — | — | Critical risk |

**Project grade:** If the majority of images (>50%) receive A or B, the project grade is softened by one level from the worst image. The problematic image still appears in the list with its own grade.

Example: 2×A + 1×D → project grade **C** (not D)

### Checkov (Dockerfile / IaC misconfigurations)

Grades are calculated from the `failed` check count and displayed on the Security page.

| Grade | Failed checks | Description |
|-------|---------------|-------------|
| **A** | 0 | No misconfigurations |
| **B** | 1–2 | Minor issues |
| **C** | 3–5 | Moderate risk |
| **D** | 6–10 | High risk |
| **F** | > 10 | Critical risk |

### OSV-Scanner (dependency vulnerabilities)

Grades are calculated from the total vulnerability count and displayed on the Security page.

| Grade | Total vulns | Description |
|-------|-------------|-------------|
| **A** | 0 | Clean |
| **B** | 1–2 | Minor |
| **C** | 3–5 | Moderate risk |
| **D** | 6–9 | High risk |
| **F** | ≥ 10 | Critical risk |

> Checkov and OSV grades are computed in the frontend (Security page). The `/api/grades` endpoint covers Trivy only.

## API Endpoints

All API requests are accessed via nginx at `http://<host>:<FRONTEND_PORT>/api/...`.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/api/projects` | List all projects |
| GET | `/api/projects/{projectName}` | Project details |
| GET | `/api/scans` | List all scans |
| GET | `/api/scans/{filename}` | Scan details (vulnerability list) |
| GET | `/api/compare?scan1={f}&scan2={f}` | Compare two scans |
| GET | `/api/grades` | Trivy letter grades for all projects |
| GET | `/api/grades?project={name}` | Trivy letter grade for a single project |
| GET | `/api/checkov` | Checkov results for all projects |
| GET | `/api/checkov?project={name}` | Checkov results for a specific project |
| GET | `/api/osv` | OSV-Scanner results for all projects |
| GET | `/api/osv?project={name}` | OSV-Scanner results for a specific project |
| GET | `/api/cve/{cveId}` | Query which projects contain a CVE |
| POST | `/api/reload` | Manually reload the index |

### `/api/grades` Sample Output

```json
{
  "generatedAt": "2026-06-03T10:30:00Z",
  "projects": [
    {
      "projectName": "dockscan",
      "imageCount": 2,
      "grade": "B",
      "images": [
        {
          "imageName": "backend",
          "grade": "A",
          "totalVulns": 4,
          "severityCount": { "HIGH": 2, "MEDIUM": 2 },
          "scanCount": 3,
          "lastScanDate": "2026-06-03T10:00:00Z",
          "firstScanDate": "2026-01-15T08:00:00Z"
        }
      ]
    }
  ]
}
```

### `/api/checkov?project=dockscan` Sample Output

```json
[
  {
    "project": "dockscan",
    "service": "dockscan_backend",
    "scanDate": "2026-06-07T10:00:00Z",
    "passed": 12,
    "failed": 1,
    "checks": [
      {
        "checkId": "CKV_DOCKER_2",
        "checkName": "Ensure that HEALTHCHECK instructions have been added to the container image",
        "result": "failed",
        "resource": "backend/Dockerfile"
      }
    ]
  }
]
```

### `/api/osv?project=dockscan` Sample Output

```json
[
  {
    "project": "dockscan",
    "service": "dockscan_backend",
    "scanDate": "2026-06-07T10:00:00Z",
    "totalVulns": 0,
    "results": []
  },
  {
    "project": "dockscan",
    "service": "dockscan_frontend",
    "scanDate": "2026-06-07T10:00:00Z",
    "totalVulns": 2,
    "results": [
      {
        "source": { "path": "/src/package-lock.json", "type": "lockfile" },
        "packages": [
          {
            "package": { "name": "vite", "version": "6.0.0", "ecosystem": "npm" },
            "vulnerabilities": [{ "id": "GHSA-xxxx-xxxx-xxxx", "summary": "..." }]
          }
        ]
      }
    ]
  }
]
```

## Checkov & OSV-Scanner

In addition to Trivy image scanning, DockerScan also visualizes Checkov (IaC) and OSV-Scanner (dependency) results on the **Security** page.

### File Naming Convention

Place scan output files in the same `export/{project}/` directory:

| Scanner | Pattern | Example |
|---------|---------|---------|
| Trivy | `{image}-{YYYYMMDD-HHMMSS}.json` | `dockscan_backend-20260607-120000.json` |
| Checkov | `checkov-{service}-{context}-{YYYYMMDD-HHMMSS}.json` | `checkov-dockscan_backend-local-20260607-120000.json` |
| OSV | `osv-{service}-{context}-{YYYYMMDD-HHMMSS}.json` | `osv-dockscan_backend-local-20260607-120000.json` |

### Scanning with `scan-popular.ps1`

`scan-popular.ps1` runs all three scanners in sequence: Trivy (external images), Trivy (local images), Checkov, and OSV-Scanner.

```powershell
# Scan everything (external popular images + local project images)
.\scan-popular.ps1

# Scan only the project's own Docker images (fast — skips external images)
.\scan-popular.ps1 -LocalOnly

# Limit to 2 versions per external image
.\scan-popular.ps1 -PerImage 2
```

`-LocalOnly` scans `dockscan_backend:latest` and `dockscan_nginx:latest` via Trivy, then runs Checkov on `backend/` and `nginx/` Dockerfiles, and OSV-Scanner on `backend/` and `frontend/` dependency lockfiles.

> Make sure `docker compose up --build` has been run first so the local images exist.

## Configuration

`.env` file (copy from `.example.env`):

```bash
FRONTEND_PORT=3017   # nginx port — dashboard is served here
BACKEND_PORT=3018    # only for CI/CD reload calls (optional)
EXPORT_DIR=./export  # Trivy JSON folder (relative or absolute path)
TZ=Europe/Istanbul

# If VITE_API_BASE is empty, it runs through the nginx proxy (recommended).
# If accessing from a different server, set the nginx port:
# VITE_API_BASE=http://192.168.1.x:3017
VITE_API_BASE=
```

## Project Structure

```
DockScan/
├── backend/                # Go backend (chi router)
│   ├── main.go
│   └── Dockerfile
├── frontend/               # React 18 + Vite + TypeScript + Tailwind
│   └── src/
├── nginx/                  # Single nginx — serves SPA and proxies /api/
│   ├── Dockerfile          # Multi-stage: node build → nginx:alpine
│   └── nginx.conf
├── export/                 # Scan results (Trivy, Checkov, OSV JSON files)
│   └── {project}/          # One folder per project
├── scan-popular.ps1        # Run Trivy + Checkov + OSV scans (Windows)
├── trigger-nexus.sh        # CI/CD: scan a specific image/tag
├── scan-nexus.sh           # Scan all images in Nexus (bulk)
├── .example.env
└── docker-compose.yml      # 2 services: backend + nginx
```

### Architecture

```
User (or LB)
    └─► nginx:FRONTEND_PORT
            ├─ /api/*  ──► backend:8080  (container network, not exposed to host)
            └─ /*      ──► /usr/share/nginx/html  (React SPA)
```

## Technology Stack

- **Backend**: Go 1.25 + chi router
- **Frontend**: React 18 + Vite + TypeScript + TailwindCSS + Recharts
- **Containerization**: Docker + Docker Compose
- **Web Server**: Nginx (single container — SPA serve + API proxy)

## Performance

- **In-memory index**: All JSON files are scanned at startup and loaded into the `IndexData` structure; `/api/scans`, `/api/projects`, and `/api/grades` endpoints serve responses from this index without hitting the disk again.
- **Auto index refresh**: The index is rebuilt in the background every 60 seconds; newly added JSON files become visible shortly after.
- **Auto cleanup**: Scan files older than 30 days are purged every 24 hours; the most recent file in each project folder is always preserved.
- **HTTP timeouts**: `ReadTimeout`, `WriteTimeout`, and `IdleTimeout` are configured.
- **Frontend debounce**: A 300 ms debounce is applied to the project search box.
- **Deep URL routing**: `/projects/{projectName}` URLs can be opened directly in the browser; browser back/forward navigation works correctly.

## Health Check

Docker Compose includes automatic health checks for each service:
- **Backend**: checks the `/health` endpoint
- **Nginx**: checks the `/health` endpoint
- **Restart Policy**: `unless-stopped`

```bash
docker compose ps
```
