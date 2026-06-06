#!/bin/bash

set -uo pipefail

OSV_IMAGE="ghcr.io/google/osv-scanner:latest"
DASHBOARD_API="${DASHBOARD_API:-http://localhost:3018}"

# ---------------------------------------------------------------------------
# Argüman ayrıştırma
# ---------------------------------------------------------------------------
IMAGE_NAME=""
TAG=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --image) IMAGE_NAME="$2"; shift 2 ;;
        --tag)   TAG="$2";        shift 2 ;;
        *) echo "[ERROR] Bilinmeyen argüman: $1" >&2; exit 1 ;;
    esac
done

if [[ -z "$IMAGE_NAME" || -z "$TAG" ]]; then
    echo "Kullanım: $0 --image <imaj_adı> --tag <tag>"
    echo "Örnek   : $0 --image dockscan_backend --tag test-v1.0"
    exit 1
fi

# ---------------------------------------------------------------------------
# Dizin ve dosya hazırlığı
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
EXPORT_DIR="$SCRIPT_DIR/export/$IMAGE_NAME"
SOURCE_DIR="/tmp/osv-input/$IMAGE_NAME"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT_FILENAME="osv-${IMAGE_NAME}-${TAG}-${TIMESTAMP}.json"
OUTPUT_FILE="$EXPORT_DIR/$OUTPUT_FILENAME"

if [[ ! -d "$SOURCE_DIR" ]]; then
    echo "[ERROR] Kaynak dizin bulunamadı: $SOURCE_DIR" >&2
    echo "[ERROR] Jenkins'in SCP ile dosyaları göndermesi bekleniyor." >&2
    exit 1
fi

mkdir -p "$EXPORT_DIR"
chmod 755 "$EXPORT_DIR" 2>/dev/null || true

# ---------------------------------------------------------------------------
# OSV-Scanner taraması
# ---------------------------------------------------------------------------
echo "[INFO] OSV-Scanner taraması başlatılıyor: $SOURCE_DIR"
echo "[INFO] Çıktı dosyası: $OUTPUT_FILE"

SCAN_EXIT=0
docker run --rm \
    -v "$SOURCE_DIR:/src" \
    "$OSV_IMAGE" \
    --recursive /src \
    --format json > "$OUTPUT_FILE" || SCAN_EXIT=$?

chmod 644 "$OUTPUT_FILE" 2>/dev/null || true

if [[ $SCAN_EXIT -eq 0 ]]; then
    echo "[INFO] OSV-Scanner taraması tamamlandı — zafiyet yok: $OUTPUT_FILE"
elif [[ $SCAN_EXIT -eq 1 ]]; then
    echo "[WARN] OSV-Scanner taraması tamamlandı — zafiyetler tespit edildi: $OUTPUT_FILE"
else
    echo "[ERROR] OSV-Scanner beklenmedik hata ile çıktı (kod: $SCAN_EXIT)" >&2
fi

# ---------------------------------------------------------------------------
# Temp dizini temizle
# ---------------------------------------------------------------------------
rm -rf "$SOURCE_DIR"

# ---------------------------------------------------------------------------
# Index'i hemen yenile
# ---------------------------------------------------------------------------
if curl -sf -X POST "${DASHBOARD_API}/api/reload" -o /dev/null 2>/dev/null; then
    echo "[INFO] Dashboard index yenilendi"
else
    echo "[WARN] Dashboard reload başarısız, periyodik yenileme beklenecek" >&2
fi

exit $SCAN_EXIT
