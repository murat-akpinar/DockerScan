#!/bin/bash

set -euo pipefail

REGISTRY_HOST="yournexushost:8090"
REPO_PREFIX="repository/my-repo"
TRIVY_IMAGE="aquasec/trivy:latest"
TRIVY_DB_PATH="/app/DockScan/trivy-db"

# ---------------------------------------------------------------------------
# Eşzamanlı tarama kilidi
# ---------------------------------------------------------------------------
# Trivy cache dizinine (TRIVY_DB_PATH) ÖZEL kilit alıyor. Aynı anda iki tarama
# başlarsa ikincisi birkaç saniye bekleyip şu hatayla DÜŞÜYOR:
#   unable to initialize fs cache: cache may be in use by another process: timeout
# Birden fazla pipeline aynı anda build alınca ya da gecelik tarama (scan-nexus.sh)
# sürerken olur. flock ile taramalar sıraya girer: düşmek yerine beklerler. Kilit
# YALNIZ docker run süresince tutulur, bekleyen pipeline bir tarama boyu gecikir.
TRIVY_LOCK_FILE="${TRIVY_LOCK_FILE:-$(dirname "$TRIVY_DB_PATH")/.trivy-scan.lock}"
TRIVY_LOCK_WAIT="${TRIVY_LOCK_WAIT:-1800}"

trivy_lock_acquire() {
    command -v flock >/dev/null 2>&1 || {
        echo "[WARN] flock bulunamadı → kilitsiz devam ediliyor" >&2
        return 0
    }
    # Kilidi farklı kullanıcılar alabilir (CI ssh kullanıcısı, cron): hepsi aynı
    # dosyayı açabilsin diye 666 ile oluşturuluyor.
    [ -e "$TRIVY_LOCK_FILE" ] || ( umask 000; : > "$TRIVY_LOCK_FILE" ) 2>/dev/null || true
    # Yazılabilir değilse kilitsiz devam: eski davranış, kötüleşme yok.
    if [ ! -w "$TRIVY_LOCK_FILE" ]; then
        echo "[WARN] Kilit dosyası yazılamıyor ($TRIVY_LOCK_FILE) → kilitsiz devam" >&2
        return 0
    fi
    exec 9>"$TRIVY_LOCK_FILE"
    flock -n 9 && return 0
    echo "[INFO] Başka bir tarama sürüyor, sıra bekleniyor (en çok ${TRIVY_LOCK_WAIT}s)..."
    flock -w "$TRIVY_LOCK_WAIT" 9 && return 0
    echo "[ERROR] Trivy cache kilidi ${TRIVY_LOCK_WAIT}s içinde alınamadı" >&2
    return 1
}

trivy_lock_release() {
    flock -u 9 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Argüman ayrıştırma
# ---------------------------------------------------------------------------
IMAGE_NAME=""
TAG=""
IP=""
APP_NAME=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --image) IMAGE_NAME="$2"; shift 2 ;;
        --tag)   TAG="$2";        shift 2 ;;
        --ip)    IP="$2";         shift 2 ;;   # opsiyonel: deploy IP (/api/summary için)
        --app)   APP_NAME="$2";   shift 2 ;;   # opsiyonel: uygulama/proje adı
        *) echo "[ERROR] Bilinmeyen argüman: $1" >&2; exit 1 ;;
    esac
done

if [[ -z "$IMAGE_NAME" || -z "$TAG" ]]; then
    echo "Kullanım: $0 --image <imaj_adı> --tag <tag> [--ip <ip>] [--app <app_adı>]"
    echo "Örnek   : $0 --image DockScan_backend --tag test-v1.0 --ip 192.168.1.10 --app dockscan"
    echo "Örnek   : $0 --image DockScan_frontend --tag test-v1.0"
    exit 1
fi

# ---------------------------------------------------------------------------
# Dizin ve dosya hazırlığı
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
EXPORT_DIR="$SCRIPT_DIR/export/$IMAGE_NAME"

mkdir -p "$EXPORT_DIR"
chmod 755 "$EXPORT_DIR" 2>/dev/null || true

IMAGE_URL="$REGISTRY_HOST/$REPO_PREFIX/$IMAGE_NAME:$TAG"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT_FILENAME="${IMAGE_NAME}-${TAG}-${TIMESTAMP}.json"
OUTPUT_FILE="$EXPORT_DIR/$OUTPUT_FILENAME"

# ---------------------------------------------------------------------------
# Trivy taraması
# ---------------------------------------------------------------------------
echo "[INFO] İmaj taranıyor : $IMAGE_URL"
echo "[INFO] Çıktı dosyası  : $OUTPUT_FILE"

trivy_lock_acquire

docker run --rm \
    -e TRIVY_USERNAME="${NEXUS_USER:-}" \
    -e TRIVY_PASSWORD="${NEXUS_PASS:-}" \
    -v "$EXPORT_DIR:/output" \
    -v "$TRIVY_DB_PATH:/root/.cache/trivy" \
    "$TRIVY_IMAGE" image \
    --insecure \
    --format json \
    --output "/output/$OUTPUT_FILENAME" \
    "$IMAGE_URL"

trivy_lock_release

chmod 644 "$OUTPUT_FILE" 2>/dev/null || true
echo "[INFO] Tarama tamamlandı: $OUTPUT_FILE"

# ---------------------------------------------------------------------------
# Deploy metadata (IP / app) — /api/summary beslemesi için.
# Sadece --ip veya --app verildiğinde yazılır; backend bunu ArtifactName'in
# imaj kısmı (IMAGE_NAME) üzerinden tarama verisiyle eşler.
# ---------------------------------------------------------------------------
if [[ -n "$IP" || -n "$APP_NAME" ]]; then
    META_FILE="$EXPORT_DIR/meta-${IMAGE_NAME}.json"
    printf '{"image":"%s","appName":"%s","ip":"%s"}\n' "$IMAGE_NAME" "$APP_NAME" "$IP" > "$META_FILE"
    chmod 644 "$META_FILE" 2>/dev/null || true
    echo "[INFO] Metadata yazıldı: $META_FILE (ip=$IP, app=$APP_NAME)"
fi

# ---------------------------------------------------------------------------
# Index'i hemen yenile (1-2 dk'lık ticker gecikmesini önler)
# ---------------------------------------------------------------------------
DASHBOARD_API="${DASHBOARD_API:-http://localhost:3018}"
if curl -sf -X POST "${DASHBOARD_API}/api/reload" -o /dev/null 2>/dev/null; then
    echo "[INFO] Dashboard index yenilendi"
else
    echo "[WARN] Dashboard reload başarısız, periyodik yenileme beklenecek" >&2
fi
