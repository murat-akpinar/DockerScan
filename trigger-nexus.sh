#!/bin/bash

set -euo pipefail

REGISTRY_HOST="yournexushost:8090"
REPO_PREFIX="repository/my-repo"
TRIVY_IMAGE="aquasec/trivy:latest"
TRIVY_DB_PATH="/app/DockScan/trivy-db"

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
