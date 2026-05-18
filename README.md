# VaultScan

[![License: GPL v3](https://img.shields.io/badge/license-GPLv3-1a1a1a?style=flat-square&labelColor=1a1a1a&color=8a6f3a)](LICENSE)
[![Built with Claude Code](https://img.shields.io/badge/built%20with-Claude%20Code-1a1a1a?style=flat-square&labelColor=1a1a1a&color=d8b66b)](https://claude.com/claude-code)
[![Status](https://img.shields.io/badge/status-alpha-1a1a1a?style=flat-square&labelColor=1a1a1a&color=c8302f)](https://github.com/murat-akpinar/VaultScan/releases)
[![Go](https://img.shields.io/badge/Go-1.25-1a1a1a?style=flat-square&labelColor=1a1a1a&color=00ADD8&logo=go&logoColor=fff)](https://go.dev)
[![React](https://img.shields.io/badge/React-18-1a1a1a?style=flat-square&labelColor=1a1a1a&color=61DAFB&logo=react&logoColor=fff)](https://react.dev)
[![Docker](https://img.shields.io/badge/Docker-compose-1a1a1a?style=flat-square&labelColor=1a1a1a&color=2496ED&logo=docker&logoColor=fff)](https://www.docker.com)

Trivy güvenlik tarama sonuçlarını toplayıp görselleştiren web dashboard uygulaması. CI/CD ortamlarında üretilen Trivy JSON çıktılarını tek bir merkezde toplayıp kolayca incelemenizi sağlar.

![Dashboard](/images/dashboard.png)
![Project](/images/project.png)
![Comparison](/images/comparison.png)

## Özellikler

- **Proje Bazlı Görünüm**: Her proje için tüm Docker imajlarının taramalarını tek sayfada görüntüleme
- **Severity Filtreleme**: CRITICAL, HIGH, MEDIUM, LOW seviyelerine göre projeleri filtreleme
- **Harf Notu Sistemi**: Her imaj için otomatik güvenlik notu (A–F) ve `/api/grades` REST endpoint'i
- **Detaylı Vulnerability Listesi**: Her açık için ID, açıklama, fixed version ve detay linkleri
- **CVE Arama**: Belirli bir CVE'yi hangi projelerde/imajlarda içerdiğini sorgulama
- **Zaman Çizelgesi**: Taramaların zaman içindeki değişimini görselleştirme
- **Genel Dashboard**: Tüm projelerin toplam istatistiklerini görüntüleme
- **Detaylı Karşılaştırma**: İki tarama arasında hangi açıkların kapandığını/yeni eklendiğini gösteren diff görünümü
- **Derin URL Routing**: `/projects/{projectName}` URL'leri doğrudan paylaşılabilir ve bookmarklanabilir

## Hızlı Başlangıç

### Gereksinimler

- Docker ve Docker Compose

### Kurulum

1. `.env` dosyasını oluşturun:
```bash
cp .example.env .env
# EXPORT_DIR değerini mutlak path olarak ayarlayın, örn:
# EXPORT_DIR=/home/user/vaultscan/export
```

2. Container'ları build edip başlatın:
```bash
docker compose up -d --build
```

3. Dashboard'a erişin:
- Dashboard: http://localhost:3017 (veya `.env` içindeki `FRONTEND_PORT`)
- Backend API: nginx üzerinden `http://localhost:3017/api/...` ile erişilebilir

## Trivy Tarama Sonuçlarını Ekleme

### Dosya Formatı

Trivy JSON raporlarını `export/` klasörüne koyun. Backend, dosya adından veya JSON içindeki `ArtifactName` alanından proje, imaj ve tag bilgisini otomatik olarak çıkarır.

**Desteklenen Formatlar:**

1. **Düz Yapı** (Flat):
   ```
   export/{proje}-{imaj}.json
   export/{proje}-{imaj}-{YYYYMMDD-HHMMSS}.json
   ```
   Örnek: `export/vaultscan-backend-20251126-182000.json`

2. **Dizin Yapısı** (Önerilen):
   ```
   export/{proje}/{imaj}.json
   export/{proje}/{imaj}-{YYYYMMDD-HHMMSS}.json
   ```
   Örnek: `export/vaultscan/backend-20251126-182000.json`

3. **ArtifactName ile Otomatik Parse** (En Kolay):
   JSON dosyasının içindeki `ArtifactName` alanından otomatik parse edilir:
   - `ArtifactName: "vaultscan-backend:latest"` → Proje: `vaultscan`, İmaj: `backend`, Tag: `latest`

### İmaj İsimlendirme Kuralı

Script'ler `proje-adi_servis` formatını kullanır. `_` ayracının solu proje adı, sağı servis adıdır:

```
vaultscan_backend:test-v1.0   → Proje: vaultscan  | İmaj: backend  | Tag: test-v1.0
vaultscan_frontend:test-v1.0  → Proje: vaultscan  | İmaj: frontend | Tag: test-v1.0
myapp_api:v2.3                → Proje: myapp      | İmaj: api      | Tag: v2.3
```

### CI/CD Entegrasyonu — `trigger-nexus.sh`

Jenkins pipeline'ında build alınan her imaj için sunucuya SSH ile bağlanıp `trigger-nexus.sh` çalıştırılır. Script yalnızca belirtilen imajı tarar, tüm Nexus'u değil.

```bash
# Belirli bir imaj ve tag'i tara
./trigger-nexus.sh --image vaultscan_backend --tag test-v1.0
./trigger-nexus.sh --image vaultscan_frontend --tag test-v1.0
```

Tarama tamamlandıktan sonra backend index'i ~60 saniye içinde güncellenir. Ardından `/api/grades` ile sonuç sorgulanabilir:

```bash
# Tarama bitmesi için bekle
sleep 70

# Proje notunu kontrol et
GRADE=$(curl -s "http://<host>:3017/api/grades?project=vaultscan" \
  | jq -r '.projects[0].grade')

echo "Güvenlik Notu: $GRADE"

if [[ "$GRADE" == "F" || "$GRADE" == "D" ]]; then
  echo "HATA: Güvenlik notu yetersiz ($GRADE), pipeline durduruluyor."
  exit 1
fi
```

### Manuel Tarama

```bash
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/export:/output \
  aquasec/trivy:latest image \
  --format json -o /output/vaultscan/backend-${TIMESTAMP}.json \
  vaultscan-backend:latest
```

## Harf Notu Sistemi

Backend (`/api/grades`) ve frontend dashboard aynı kriterleri kullanır:

| Not | CRITICAL | HIGH | Açıklama |
|-----|----------|------|----------|
| **A** | 0 | 0 | Mükemmel |
| **B** | 0 | ≥ 1 | İyi |
| **C** | 1–3 | — | Orta risk |
| **D** | 4–9 | — | Yüksek risk |
| **F** | ≥ 10 | — | Kritik risk |

Proje notu, o projedeki imajların en kötü notunu alır.

## API Endpoints

### Backend API (`http://<host>:FRONTEND_PORT/api`)

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| GET | `/health` | Health check |
| GET | `/api/projects` | Tüm projelerin listesi |
| GET | `/api/projects/{projectName}` | Proje detayları |
| GET | `/api/scans` | Tüm taramaların listesi |
| GET | `/api/scans/{filename}` | Tarama detayları (vulnerability listesi) |
| GET | `/api/compare?scan1={f}&scan2={f}` | İki tarama arası karşılaştırma |
| GET | `/api/grades` | Tüm projelerin harf notları |
| GET | `/api/grades?project={name}` | Tek proje harf notu |
| POST | `/api/reload` | Index'i manuel olarak yenile (`scan-nexus.sh` / `trigger-nexus.sh` tarafından çağrılır) |

### `/api/grades` Örnek Çıktı

```json
{
  "generatedAt": "2026-05-14T10:30:00Z",
  "projects": [
    {
      "projectName": "vaultscan",
      "imageCount": 2,
      "grade": "B",
      "images": [
        {
          "imageName": "backend",
          "grade": "A",
          "totalVulns": 4,
          "severityCount": { "HIGH": 2, "MEDIUM": 2 },
          "scanCount": 3,
          "lastScanDate": "2026-05-14T10:00:00Z",
          "firstScanDate": "2026-01-15T08:00:00Z"
        }
      ]
    }
  ]
}
```

## Yapılandırma

`.env` dosyası (`.example.env`'den kopyalayın):

```bash
FRONTEND_PORT=3017        # nginx portu — dashboard bu adreste açılır
EXPORT_DIR=./export       # Trivy JSON klasörü (relative veya mutlak path)
TZ=Europe/Istanbul

# Opsiyonel — private registry:
# GOPROXY=http://nexus.internal/repository/go-proxy/,direct
# NPM_REGISTRY=http://nexus.internal/repository/npm-proxy/
```

> Backend yalnızca container ağında erişilebilir; tüm API istekleri nginx üzerinden (`/api/...`) yönlendirilir. Dışarıya yalnızca `FRONTEND_PORT` açıktır.

## Proje Yapısı

```
vaultscan/
├── backend/                # Go backend (chi router)
│   ├── main.go
│   └── Dockerfile          # golang:alpine → alpine runtime (GOPROXY ARG)
├── frontend/               # React 18 + Vite + TypeScript + Tailwind
│   └── Dockerfile          # Sadece build artifact üretir (nginx yok)
├── nginx/                  # Tek nginx — hem SPA serve hem /api/ proxy
│   ├── Dockerfile          # Multi-stage: node build → nginx:alpine
│   └── nginx.conf          # Static files + /api/ → backend:8080 + LB real IP
├── export/                 # Trivy JSON raporları (buraya koyun)
├── trigger-nexus.sh        # CI/CD: belirli imaj/tag tarama scripti
├── scan-nexus.sh           # Nexus'taki tüm imajları tara (toplu)
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
