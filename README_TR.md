# DockScan

[![License: GPL v3](https://img.shields.io/badge/license-GPLv3-1a1a1a?style=flat-square&labelColor=1a1a1a&color=8a6f3a)](LICENSE)
[![Built with Claude Code](https://img.shields.io/badge/built%20with-Claude%20Code-1a1a1a?style=flat-square&labelColor=1a1a1a&color=d8b66b)](https://claude.com/claude-code)
[![Status](https://img.shields.io/badge/status-alpha-1a1a1a?style=flat-square&labelColor=1a1a1a&color=c8302f)](https://github.com/murat-akpinar/DockScan/releases)
[![Go](https://img.shields.io/badge/Go-1.25-1a1a1a?style=flat-square&labelColor=1a1a1a&color=00ADD8&logo=go&logoColor=fff)](https://go.dev)
[![React](https://img.shields.io/badge/React-18-1a1a1a?style=flat-square&labelColor=1a1a1a&color=61DAFB&logo=react&logoColor=fff)](https://react.dev)
[![Docker](https://img.shields.io/badge/Docker-compose-1a1a1a?style=flat-square&labelColor=1a1a1a&color=2496ED&logo=docker&logoColor=fff)](https://www.docker.com)

[🇬🇧 English](README.md) | [🇹🇷 Türkçe](README_TR.md)

Trivy güvenlik tarama sonuçlarını toplayıp görselleştiren web dashboard uygulaması. CI/CD ortamlarında üretilen Trivy JSON çıktılarını tek bir merkezde toplayıp kolayca incelemenizi sağlar.

<div align="center">
  <img src="/images/dashboard.png" alt="Dashboard" width="32%" />
  <img src="/images/project.png" alt="Project" width="32%" />
  <img src="/images/comparison.png" alt="Comparison" width="32%" />
</div>

## Özellikler

- **Proje Bazlı Görünüm**: Her proje için tüm Docker imajlarının taramalarını tek sayfada görüntüleme
- **Severity Filtreleme**: CRITICAL, HIGH, MEDIUM, LOW seviyelerine göre projeleri filtreleme
- **Harf Notu Sistemi**: Trivy, Checkov ve OSV sonuçları için otomatik güvenlik notu (A–F)
- **Checkov IaC Taraması**: Dockerfile ve altyapı kodlarındaki yanlış yapılandırmaları tespit etme
- **OSV-Scanner**: Go modülleri, npm, pip ve diğer bağımlılık dosyalarındaki açıkları bulma
- **Güvenlik Sayfası**: Checkov ve OSV bulgularını harf notlarıyla gösteren proje bazlı gezinme
- **Detaylı Vulnerability Listesi**: Her açık için ID, açıklama, fixed version ve detay linkleri
- **CVE Arama**: Belirli bir CVE'yi hangi projelerde/imajlarda içerdiğini sorgulama
- **Zaman Çizelgesi**: İnteraktif legend ile taramaların zaman içindeki değişimini görselleştirme
- **Genel Dashboard**: Tüm projelerin toplam istatistiklerini görüntüleme
- **Detaylı Karşılaştırma**: İki tarama arasında hangi açıkların kapandığını/yeni eklendiğini gösteren diff görünümü
- **Derin URL Routing**: `/projects/{projectName}` URL'leri doğrudan paylaşılabilir ve bookmarklanabilir
- **Otomatik Temizlik**: 30 günden eski scan dosyaları otomatik silinir, her proje klasöründe en az bir dosya korunur

## Hızlı Başlangıç

### Gereksinimler

- Docker ve Docker Compose

### Kurulum

1. `.env` dosyasını oluşturun:
```bash
cp .example.env .env
```

2. Container'ları build edip başlatın:
```bash
docker compose up -d --build
```

3. Dashboard'a erişin:
- `http://localhost:3017` (veya `.env` içindeki `FRONTEND_PORT`)

> Backend yalnızca container ağında erişilebilir; tüm API istekleri nginx üzerinden (`/api/...`) yönlendirilir. Dışarıya yalnızca `FRONTEND_PORT` açıktır.

## Trivy Tarama Sonuçlarını Ekleme

### Dosya Formatı

Trivy JSON raporlarını `export/` klasörüne koyun. Backend, dosya adından veya JSON içindeki `ArtifactName` alanından proje, imaj ve tag bilgisini otomatik olarak çıkarır.

**Desteklenen Formatlar:**

1. **Dizin Yapısı** (Önerilen):
   ```
   export/{proje}/{imaj}-{YYYYMMDD-HHMMSS}.json
   ```
   Örnek: `export/dockscan/backend-20251126-182000.json`

2. **Düz Yapı** (Flat):
   ```
   export/{proje}-{imaj}-{YYYYMMDD-HHMMSS}.json
   ```
   Örnek: `export/dockscan-backend-20251126-182000.json`

3. **ArtifactName ile Otomatik Parse** (En Kolay):
   JSON dosyasının içindeki `ArtifactName` alanından otomatik parse edilir:
   - `ArtifactName: "dockscan_backend:latest"` → Proje: `dockscan`, İmaj: `backend`, Tag: `latest`

### İmaj İsimlendirme Kuralı

`proje_servis` formatı önerilir. `_` ayracının solu proje adı, sağı servis adıdır:

```
dockscan_backend:test-v1.0   → Proje: dockscan  | İmaj: backend  | Tag: test-v1.0
dockscan_nginx:latest        → Proje: dockscan  | İmaj: nginx    | Tag: latest
myapp_api:v2.3               → Proje: myapp     | İmaj: api      | Tag: v2.3
```

### Lokal İmajları Tarama (Windows)

Lokal olarak build edilmiş Docker imajlarını taramak için:

```powershell
# export klasörünü hazırla
New-Item -ItemType Directory -Force .\export\dockscan | Out-Null

# İmajı tara (Trivy otomatik indirilir)
$TS = Get-Date -Format "yyyyMMdd-HHmmss"
docker run --rm `
  -v /var/run/docker.sock:/var/run/docker.sock `
  -v "${PWD}\export\dockscan:/output" `
  aquasec/trivy:latest image `
  --format json `
  --output "/output/dockscan_backend-${TS}.json" `
  dockscan_backend:latest

# Index'i hemen yenile (opsiyonel, 60 sn beklemek yerine)
Invoke-RestMethod -Method POST "http://localhost:3018/api/reload"
```

### CI/CD Entegrasyonu — `trigger-nexus.sh`

> Pipeline içinde Trivy taramasını otomatikleştiren Jenkins Shared Library için [devops-jenkins-library](https://github.com/murat-akpinar/devops-jenkins-library) reposuna bakabilirsiniz.

Jenkins pipeline'ında build alınan her imaj için sunucuya SSH ile bağlanıp `trigger-nexus.sh` çalıştırılır. Script yalnızca belirtilen imajı tarar, tüm Nexus'u değil.

```bash
# Belirli bir imaj ve tag'i tara
./trigger-nexus.sh --image dockscan_backend --tag test-v1.0
./trigger-nexus.sh --image dockscan_nginx --tag test-v1.0
```

Tarama tamamlandıktan sonra backend index'i ~60 saniye içinde güncellenir. Ardından `/api/grades` ile sonuç sorgulanabilir:

```bash
# Tarama bitmesi için bekle
sleep 70

# Proje notunu kontrol et
GRADE=$(curl -s "http://<host>:3017/api/grades?project=dockscan" \
  | jq -r '.projects[0].grade')

echo "Güvenlik Notu: $GRADE"

if [[ "$GRADE" == "F" ]]; then
  echo "HATA: Güvenlik notu kritik ($GRADE), pipeline durduruluyor."
  exit 1
fi
```

## Harf Notu Sistemi

### Trivy (imaj açıkları)

Backend (`/api/grades`) ve frontend dashboard aynı kriterleri kullanır:

| Not | CRITICAL | HIGH | MEDIUM | Açıklama |
|-----|----------|------|--------|----------|
| **A** | 0 | ≤ 2 | ≤ 5 | Mükemmel |
| **B** | 0 | ≤ 5 | ≤ 10 | İyi |
| **C** | ≤ 2 | ≤ 8 | ≤ 15 | Orta risk |
| **D** | ≤ 9 | — | — | Yüksek risk |
| **F** | ≥ 10 | — | — | Kritik risk |

**Proje notu:** İmajların çoğunluğu (>%50) A veya B alıyorsa, proje notu en kötü imajdan bir kademe yumuşatılır.
Sorunlu imaj kendi notuyla listede görünmeye devam eder.

Örnek: 2×A + 1×D → proje notu **C** (D değil)

### Checkov (Dockerfile / IaC yanlış yapılandırmaları)

Notlar `failed` kontrol sayısından hesaplanır ve Güvenlik sayfasında görünür.

| Not | Başarısız kontrol | Açıklama |
|-----|-------------------|----------|
| **A** | 0 | Sorun yok |
| **B** | 1–2 | Küçük sorunlar |
| **C** | 3–5 | Orta risk |
| **D** | 6–10 | Yüksek risk |
| **F** | > 10 | Kritik risk |

### OSV-Scanner (bağımlılık açıkları)

Notlar toplam açık sayısından hesaplanır ve Güvenlik sayfasında görünür.

| Not | Toplam açık | Açıklama |
|-----|-------------|----------|
| **A** | 0 | Temiz |
| **B** | 1–2 | Küçük |
| **C** | 3–5 | Orta risk |
| **D** | 6–9 | Yüksek risk |
| **F** | ≥ 10 | Kritik risk |

> Checkov ve OSV notları frontend'de hesaplanır (Güvenlik sayfası). `/api/grades` endpoint'i yalnızca Trivy sonuçlarını kapsar.

## API Endpoints

Tüm API istekleri nginx üzerinden `http://<host>:<FRONTEND_PORT>/api/...` ile erişilir.

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| GET | `/health` | Health check |
| GET | `/api/projects` | Tüm projelerin listesi |
| GET | `/api/projects/{projectName}` | Proje detayları |
| GET | `/api/scans` | Tüm taramaların listesi |
| GET | `/api/scans/{filename}` | Tarama detayları (vulnerability listesi) |
| GET | `/api/compare?scan1={f}&scan2={f}` | İki tarama arası karşılaştırma |
| GET | `/api/grades` | Trivy harf notları — tüm projeler |
| GET | `/api/grades?project={name}` | Trivy harf notu — tek proje |
| GET | `/api/checkov` | Tüm projelerin Checkov sonuçları |
| GET | `/api/checkov?project={name}` | Belirli projenin Checkov sonuçları |
| GET | `/api/osv` | Tüm projelerin OSV-Scanner sonuçları |
| GET | `/api/osv?project={name}` | Belirli projenin OSV-Scanner sonuçları |
| GET | `/api/cve/{cveId}` | CVE'yi hangi projelerde içerdiğini sorgula |
| POST | `/api/reload` | Index'i manuel olarak yenile |

### `/api/grades` Örnek Çıktı

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

### `/api/checkov?project=dockscan` Örnek Çıktı

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

### `/api/osv?project=dockscan` Örnek Çıktı

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

DockerScan, Trivy imaj taramasına ek olarak Checkov (IaC) ve OSV-Scanner (bağımlılık) sonuçlarını da **Güvenlik** sayfasında görselleştirir.

### Dosya İsimlendirme Kuralı

Tarama çıktı dosyalarını aynı `export/{proje}/` dizinine koyun:

| Tarayıcı | Şablon | Örnek |
|----------|--------|-------|
| Trivy | `{imaj}-{YYYYMMDD-HHMMSS}.json` | `dockscan_backend-20260607-120000.json` |
| Checkov | `checkov-{servis}-{context}-{YYYYMMDD-HHMMSS}.json` | `checkov-dockscan_backend-local-20260607-120000.json` |
| OSV | `osv-{servis}-{context}-{YYYYMMDD-HHMMSS}.json` | `osv-dockscan_backend-local-20260607-120000.json` |

### `scan-popular.ps1` ile Tarama

`scan-popular.ps1`, üç tarayıcıyı sırayla çalıştırır: Trivy (harici imajlar), Trivy (yerel imajlar), Checkov ve OSV-Scanner.

```powershell
# Her şeyi tara (harici popüler imajlar + projenin kendi imajları)
.\scan-popular.ps1

# Yalnızca projenin kendi Docker imajlarını tara (hızlı — harici imajları atlar)
.\scan-popular.ps1 -LocalOnly

# Harici imajlarda imaj başına versiyon sayısını sınırla
.\scan-popular.ps1 -PerImage 2
```

`-LocalOnly` parametresiyle: Trivy ile `dockscan_backend:latest` ve `dockscan_nginx:latest` taranır; ardından `backend/` ve `nginx/` Dockerfile'larına Checkov, `backend/` ve `frontend/` bağımlılık dosyalarına OSV-Scanner uygulanır.

> Yerel imajların mevcut olması için önce `docker compose up --build` çalıştırılmış olmalıdır.

## Yapılandırma

`.env` dosyası (`.example.env`'den kopyalayın):

```bash
FRONTEND_PORT=3017   # nginx portu — dashboard bu adreste açılır
BACKEND_PORT=3018    # sadece CI/CD reload çağrısı için (opsiyonel)
EXPORT_DIR=./export  # Trivy JSON klasörü (relative veya mutlak path)
TZ=Europe/Istanbul

# VITE_API_BASE boş bırakılırsa nginx proxy üzerinden çalışır (önerilen).
# Farklı bir sunucudan erişiyorsan nginx portunu yaz:
# VITE_API_BASE=http://192.168.1.x:3017
VITE_API_BASE=
```

## Proje Yapısı

```
DockScan/
├── backend/                # Go backend (chi router)
│   ├── main.go
│   └── Dockerfile
├── frontend/               # React 18 + Vite + TypeScript + Tailwind
│   └── src/
├── nginx/                  # Tek nginx — hem SPA serve hem /api/ proxy
│   ├── Dockerfile          # Multi-stage: node build → nginx:alpine
│   └── nginx.conf
├── export/                 # Tarama sonuçları (Trivy, Checkov, OSV JSON dosyaları)
│   └── {proje}/            # Her proje için ayrı klasör
├── scan-popular.ps1        # Trivy + Checkov + OSV taraması (Windows)
├── trigger-nexus.sh        # CI/CD: belirli imaj/tag tarama scripti
├── scan-nexus.sh           # Nexus'taki tüm imajları tara (toplu)
├── .example.env
└── docker-compose.yml      # 2 servis: backend + nginx
```

### Mimari

```
Kullanıcı (veya LB)
    └─► nginx:FRONTEND_PORT
            ├─ /api/*  ──► backend:8080  (container ağı, host'a kapalı)
            └─ /*      ──► /usr/share/nginx/html  (React SPA)
```

## Teknoloji Stack

- **Backend**: Go 1.25 + chi router
- **Frontend**: React 18 + Vite + TypeScript + TailwindCSS + Recharts
- **Containerization**: Docker + Docker Compose
- **Web Server**: Nginx (tek container — SPA serve + API proxy)

## Performans

- **Bellek içi index**: Uygulama açılışında tüm JSON dosyaları taranarak `IndexData` yapısında belleğe alınır; `/api/scans`, `/api/projects`, `/api/grades` endpoint'leri diski tekrar okumadan bu index'ten cevap üretir.
- **Otomatik index yenileme**: Arka planda her 60 saniyede bir index yeniden oluşturulur; yeni eklenen JSON dosyaları kısa sürede görünür.
- **Otomatik temizlik**: Her 24 saatte bir 30 günden eski scan dosyaları temizlenir; her proje klasöründe en yeni dosya daima korunur.
- **HTTP timeout'ları**: `ReadTimeout`, `WriteTimeout`, `IdleTimeout` yapılandırılmıştır.
- **Frontend debounce**: Proje arama kutusunda 300 ms debounce uygulanır.
- **Derin URL routing**: `/projects/{projectName}` URL'leri tarayıcıda doğrudan açılabilir, geri/ileri tuşları çalışır.

## Health Check

Docker Compose her servis için otomatik health check içerir:
- **Backend**: `/health` endpoint'ini kontrol eder
- **Nginx**: `/health` endpoint'ini kontrol eder
- **Restart Policy**: `unless-stopped`

```bash
docker compose ps
```
