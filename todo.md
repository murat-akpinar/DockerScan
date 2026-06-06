# Checkov + OSV-Scanner Entegrasyon Planı

## Tasarım Prensibi

trigger-nexus.sh ile aynı mantık: scriptler DockScan sunucusunda çalışır, JSON doğrudan
export/ klasörüne yazılır, kopyalamaya gerek kalmaz.

Fark: trigger-nexus.sh kaynağı Nexus'tan çeker. Checkov ve OSV-Scanner kaynak kodu tarar,
bu yüzden Jenkins önce ilgili dosyaları SCP ile sunucuya gönderir, sonra script SSH ile çağrılır.

## Pipeline Akışı

```
Build & Push Services
  └── her servis için:
       ├── checkovScan(servicePath)        SCP → SSH → trigger-checkov.sh → export/
       ├── osvScan(servicePath)            SCP → SSH → trigger-osv.sh    → export/
       └── docker build + push            (mevcut, değişmiyor)

Trivy Scan                                SSH → trigger-nexus.sh → export/ (mevcut)
Trivy Quality Gate                        (mevcut, değişmiyor)
```

## Export Klasörü Yapısı

Ayrı klasör açılmaz, prefix ile ayırt edilir:

```
export/
  myproject/
    backend-20260606-120000.json           ← Trivy   (mevcut)
    checkov-backend-20260606-120001.json   ← Checkov (yeni)
    osv-backend-20260606-120002.json       ← OSV     (yeni)
```

---

## Yapılacaklar

### 1. `trigger-checkov.sh` — yeni dosya (DockScan repo, sunucuda çalışır)

trigger-nexus.sh modelinde. Jenkins'in SCP ile gönderdiği kaynak dosyaları tarar.

```bash
#!/bin/bash
set -euo pipefail

IMAGE_NAME=""
TAG=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --image) IMAGE_NAME="$2"; shift 2 ;;
        --tag)   TAG="$2";        shift 2 ;;
        *) echo "[ERROR] Bilinmeyen argüman: $1" >&2; exit 1 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
EXPORT_DIR="$SCRIPT_DIR/export/$IMAGE_NAME"
SOURCE_DIR="/tmp/checkov-input/$IMAGE_NAME"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT_FILE="$EXPORT_DIR/checkov-${IMAGE_NAME}-${TAG}-${TIMESTAMP}.json"

mkdir -p "$EXPORT_DIR"

echo "[INFO] Checkov taranıyor: $SOURCE_DIR"
docker run --rm \
    -v "$SOURCE_DIR:/project" \
    bridgecrew/checkov \
    --directory /project \
    --output json \
    --quiet > "$OUTPUT_FILE" || true

chmod 644 "$OUTPUT_FILE" 2>/dev/null || true
echo "[INFO] Tamamlandı: $OUTPUT_FILE"

DASHBOARD_API="${DASHBOARD_API:-http://localhost:3018}"
curl -sf -X POST "${DASHBOARD_API}/api/reload" -o /dev/null 2>/dev/null \
    && echo "[INFO] Dashboard index yenilendi" \
    || echo "[WARN] Dashboard reload başarısız" >&2
```

---

### 2. `trigger-osv.sh` — yeni dosya (DockScan repo, sunucuda çalışır)

```bash
#!/bin/bash
set -euo pipefail

IMAGE_NAME=""
TAG=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --image) IMAGE_NAME="$2"; shift 2 ;;
        --tag)   TAG="$2";        shift 2 ;;
        *) echo "[ERROR] Bilinmeyen argüman: $1" >&2; exit 1 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
EXPORT_DIR="$SCRIPT_DIR/export/$IMAGE_NAME"
SOURCE_DIR="/tmp/osv-input/$IMAGE_NAME"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT_FILE="$EXPORT_DIR/osv-${IMAGE_NAME}-${TAG}-${TIMESTAMP}.json"

mkdir -p "$EXPORT_DIR"

echo "[INFO] OSV-Scanner taranıyor: $SOURCE_DIR"
docker run --rm \
    -v "$SOURCE_DIR:/src" \
    ghcr.io/google/osv-scanner \
    --recursive /src \
    --format json > "$OUTPUT_FILE" || true

chmod 644 "$OUTPUT_FILE" 2>/dev/null || true
echo "[INFO] Tamamlandı: $OUTPUT_FILE"

DASHBOARD_API="${DASHBOARD_API:-http://localhost:3018}"
curl -sf -X POST "${DASHBOARD_API}/api/reload" -o /dev/null 2>/dev/null \
    && echo "[INFO] Dashboard index yenilendi" \
    || echo "[WARN] Dashboard reload başarısız" >&2
```

---

### 3. `vars/checkovScan.groovy` — yeni dosya (Jenkins Library)

```groovy
def call(String servicePath, String imageName, String tag) {
    def CFG      = globalConfig()
    def enabled  = CFG.CHECKOV_ENABLED  != false
    def softFail = CFG.CHECKOV_SOFT_FAIL == true
    def trivyHost   = CFG.TRIVY_HOST       ?: 'YOUR_TRIVY_HOST_IP'
    def sshUser     = CFG.TRIVY_SSH_USER   ?: 'your-user'
    def scriptPath  = CFG.CHECKOV_SCRIPT_PATH ?: '/app/DockScan/trigger-checkov.sh'

    if (!enabled) { echo "⏭️  Checkov devre dışı"; return }

    echo "🔎 [Checkov] ${servicePath} taranıyor..."
    sh """
        scp -r -o StrictHostKeyChecking=no \
            \${WORKSPACE}/${servicePath}/. \
            ${sshUser}@${trivyHost}:/tmp/checkov-input/${imageName}/
        ssh -o StrictHostKeyChecking=no ${sshUser}@${trivyHost} \
            '${scriptPath} --image ${imageName} --tag ${tag}'
    """
    echo "✅ [Checkov] Tamamlandı"
}
```

---

### 4. `vars/osvScan.groovy` — yeni dosya (Jenkins Library)

```groovy
def call(String servicePath, String imageName, String tag) {
    def CFG      = globalConfig()
    def enabled  = CFG.OSV_ENABLED  != false
    def softFail = CFG.OSV_SOFT_FAIL == true
    def trivyHost  = CFG.TRIVY_HOST      ?: 'YOUR_TRIVY_HOST_IP'
    def sshUser    = CFG.TRIVY_SSH_USER  ?: 'your-user'
    def scriptPath = CFG.OSV_SCRIPT_PATH ?: '/app/DockScan/trigger-osv.sh'

    if (!enabled) { echo "⏭️  OSV-Scanner devre dışı"; return }

    echo "🔎 [OSV-Scanner] ${servicePath} bağımlılıkları taranıyor..."
    sh """
        scp -r -o StrictHostKeyChecking=no \
            \${WORKSPACE}/${servicePath}/. \
            ${sshUser}@${trivyHost}:/tmp/osv-input/${imageName}/
        ssh -o StrictHostKeyChecking=no ${sshUser}@${trivyHost} \
            '${scriptPath} --image ${imageName} --tag ${tag}'
    """
    echo "✅ [OSV-Scanner] Tamamlandı"
}
```

---

### 5. `vars/buildAndPushService.groovy` — 2 satır ekleme

docker build öncesinde:

```groovy
    // mevcut: echo "🚀 [${serviceName}] Build & Push başlıyor..."
    checkovScan(servicePath, serviceName, version)   // ← EKLE
    osvScan(servicePath, serviceName, version)       // ← EKLE
    // mevcut: def useNexusAuth = ...
```

---

### 6. `vars/globalConfig.groovy` — 6 satır ekleme

```groovy
    // ── Checkov ──────────────────────────────────────────────────────────────
    CHECKOV_ENABLED     : true,
    CHECKOV_SOFT_FAIL   : false,
    CHECKOV_SCRIPT_PATH : '/app/DockScan/trigger-checkov.sh',

    // ── OSV-Scanner ──────────────────────────────────────────────────────────
    OSV_ENABLED         : true,
    OSV_SOFT_FAIL       : false,
    OSV_SCRIPT_PATH     : '/app/DockScan/trigger-osv.sh',
```

---

### 7. `backend/main.go` — prefix'e göre dosya tipi ayırt etme

Mevcut parser Trivy JSON'unu okur. Dosya adı `checkov-` veya `osv-` ile başlıyorsa
farklı struct ile parse edilecek. Yeni API endpoint'leri:

- `/api/checkov` — tüm Checkov sonuçları
- `/api/checkov?project={name}` — proje bazlı Checkov sonuçları
- `/api/osv` — tüm OSV sonuçları
- `/api/osv?project={name}` — proje bazlı OSV sonuçları

---

## Yayılım Özeti

| Dosya | Repo | İşlem |
|---|---|---|
| `trigger-checkov.sh` | DockScan | Yeni |
| `trigger-osv.sh` | DockScan | Yeni |
| `backend/main.go` | DockScan | Prefix parse + 4 endpoint |
| `vars/checkovScan.groovy` | jenkins-library | Yeni |
| `vars/osvScan.groovy` | jenkins-library | Yeni |
| `vars/buildAndPushService.groovy` | jenkins-library | 2 satır |
| `vars/globalConfig.groovy` | jenkins-library | 6 satır |
| Projelerin `Jenkinsfile`'ları | — | Sıfır değişiklik |
