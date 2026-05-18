#!/bin/bash

set -euo pipefail

REGISTRY_IP="http://yournexushost:8090"
REGISTRY_HOST="yournexushost:8090"
REPO_PREFIX="repository/my-repo"
TRIVY_IMAGE="aquasec/trivy:latest"

# Trivy DB için local cache klasörü
TRIVY_DB_PATH="/app/VaultScan/trivy-db"

# Fonksiyon: Bir proje+tag için en son tarama zamanını bul
get_latest_scan_time() {
    local PROJECT=$1
    local TAG=$2
    local EXPORT_DIR="export/$PROJECT"
    
    if [ ! -d "$EXPORT_DIR" ]; then
        echo "0"
        return
    fi
    
    # Dosya adı formatı: {PROJECT}-{TAG}-{TIMESTAMP}.json
    # Timestamp formatı: YYYYMMDD-HHMMSS
    local LATEST_TIME=0
    
    for FILE in "$EXPORT_DIR"/${PROJECT}-${TAG}-*.json; do
        if [ ! -f "$FILE" ]; then
            continue
        fi
        
        # Dosya adından timestamp'i çıkar
        local BASENAME=$(basename "$FILE" .json)
        local TIMESTAMP_STR=$(echo "$BASENAME" | grep -oE '[0-9]{8}-[0-9]{6}$' || echo "")
        
        if [ -n "$TIMESTAMP_STR" ]; then
            # Timestamp'i epoch'a çevir (YYYYMMDD-HHMMSS formatından)
            local DATE_PART=$(echo "$TIMESTAMP_STR" | cut -d'-' -f1)
            local TIME_PART=$(echo "$TIMESTAMP_STR" | cut -d'-' -f2)
            local YEAR=${DATE_PART:0:4}
            local MONTH=${DATE_PART:4:2}
            local DAY=${DATE_PART:6:2}
            local HOUR=${TIME_PART:0:2}
            local MIN=${TIME_PART:2:2}
            local SEC=${TIME_PART:4:2}
            
            # date komutu ile epoch'a çevir
            local EPOCH=$(date -d "${YEAR}-${MONTH}-${DAY} ${HOUR}:${MIN}:${SEC}" +%s 2>/dev/null || echo "0")
            
            if [ "$EPOCH" -gt "$LATEST_TIME" ]; then
                LATEST_TIME=$EPOCH
            fi
        else
            # Timestamp yoksa dosyanın mod time'ını kullan
            local FILE_EPOCH=$(stat -c %Y "$FILE" 2>/dev/null || echo "0")
            if [ "$FILE_EPOCH" -gt "$LATEST_TIME" ]; then
                LATEST_TIME=$FILE_EPOCH
            fi
        fi
    done
    
    echo "$LATEST_TIME"
}

# Fonksiyon: Nexus registry'den imajın manifest digest'ini ve son güncelleme zamanını al
get_registry_image_info() {
    local PROJECT_FULL=$1
    local TAG=$2
    
    # Manifest'i al ve header'lardan Last-Modified ve Docker-Content-Digest'i oku
    local MANIFEST_RESPONSE=$(curl -s -I "$REGISTRY_IP/v2/$PROJECT_FULL/manifests/$TAG" 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        echo "ERROR"
        return
    fi
    
    # Last-Modified header'ını bul
    local LAST_MODIFIED=$(echo "$MANIFEST_RESPONSE" | grep -i "Last-Modified:" | cut -d' ' -f2- | tr -d '\r')
    
    # Docker-Content-Digest header'ını bul
    local DIGEST=$(echo "$MANIFEST_RESPONSE" | grep -i "Docker-Content-Digest:" | cut -d' ' -f2- | tr -d '\r')
    
    if [ -z "$LAST_MODIFIED" ]; then
        # Last-Modified yoksa şu anki zamanı kullan (yeni imaj olarak kabul et)
        echo "$(date +%s)|$DIGEST"
    else
        # Last-Modified'ı epoch'a çevir
        local REGISTRY_EPOCH=$(date -d "$LAST_MODIFIED" +%s 2>/dev/null || echo "$(date +%s)")
        echo "${REGISTRY_EPOCH}|${DIGEST}"
    fi
}

# Fonksiyon: Mevcut taramalardaki digest'i kontrol et
get_existing_digest() {
    local PROJECT=$1
    local TAG=$2
    local EXPORT_DIR="export/$PROJECT"
    
    if [ ! -d "$EXPORT_DIR" ]; then
        echo ""
        return
    fi
    
    # En son tarama dosyasını bul
    local LATEST_FILE=""
    local LATEST_TIME=0
    
    for FILE in "$EXPORT_DIR"/${PROJECT}-${TAG}-*.json; do
        if [ ! -f "$FILE" ]; then
            continue
        fi
        
        local FILE_TIME=$(stat -c %Y "$FILE" 2>/dev/null || echo "0")
        if [ "$FILE_TIME" -gt "$LATEST_TIME" ]; then
            LATEST_TIME=$FILE_TIME
            LATEST_FILE="$FILE"
        fi
    done
    
    if [ -z "$LATEST_FILE" ]; then
        echo ""
        return
    fi
    
    # JSON dosyasından ArtifactName'i oku ve digest'i çıkar
    # Trivy JSON'unda genellikle ArtifactName içinde digest bilgisi yok ama
    # imaj adı ve tag bilgisi var, bu yeterli olabilir
    # Alternatif olarak, dosya adından veya JSON içeriğinden digest'i çıkarabiliriz
    # Şimdilik boş döndürüyoruz, sadece zaman karşılaştırması yapacağız
    echo ""
}

echo "[INFO] Trivy imajı güncelleniyor: $TRIVY_IMAGE"
docker pull "$TRIVY_IMAGE"
echo "[INFO] Trivy imajı hazır."

echo "[INFO] Proje listesi alınıyor..."

# Sadece repository/my-repo/* olan docker imajlarını alıyoruz
RAW_PROJECTS=$(curl -s "$REGISTRY_IP/v2/_catalog" \
    | jq -r '.repositories[] | select(startswith("repository/my-repo/"))')

TOTAL_SCANNED=0
TOTAL_SKIPPED=0

for PROJECT_FULL in $RAW_PROJECTS; do

    # Image adı path'in son elemanıdır
    PROJECT=$(basename "$PROJECT_FULL")

    echo "----------------------------------------"
    echo "[INFO] Docker image bulundu: $PROJECT"

    mkdir -p export/$PROJECT
    # Backend container'ının (app user) erişebilmesi için permission'ları ayarla
    chmod 755 export/$PROJECT 2>/dev/null || true

    echo "[INFO] Tag listesi çekiliyor: $PROJECT"

    # /v2/repository/my-repo/<image>/tags/list
    TAGS=$(curl -s "$REGISTRY_IP/v2/$PROJECT_FULL/tags/list" \
        | jq -r '.tags[]' 2>/dev/null)

    if [ -z "$TAGS" ]; then
        echo "[WARN] Tag bulunamadı, atlanıyor: $PROJECT"
        continue
    fi

    for TAG in $TAGS; do
        echo "[INFO]   → Tag kontrol ediliyor: $TAG"

        # Mevcut tarama zamanını kontrol et
        LATEST_SCAN_TIME=$(get_latest_scan_time "$PROJECT" "$TAG")
        
        # Registry'den imaj bilgisini al
        REGISTRY_INFO=$(get_registry_image_info "$PROJECT_FULL" "$TAG")
        
        if [ "$REGISTRY_INFO" = "ERROR" ]; then
            echo "[WARN]     Registry'den imaj bilgisi alınamadı, atlanıyor: $PROJECT:$TAG"
            continue
        fi
        
        REGISTRY_TIME=$(echo "$REGISTRY_INFO" | cut -d'|' -f1)
        REGISTRY_DIGEST=$(echo "$REGISTRY_INFO" | cut -d'|' -f2)
        
        # Eğer registry'deki imaj daha yeni ise veya hiç tarama yoksa, tarama yap
        if [ "$LATEST_SCAN_TIME" -eq 0 ] || [ "$REGISTRY_TIME" -gt "$LATEST_SCAN_TIME" ]; then
            echo "[INFO]     → Yeni/güncellenmiş imaj tespit edildi, tarama başlatılıyor..."
            
            # Trivy'nin anlayacağı doğru docker image adı
            IMAGE_URL="$REGISTRY_HOST/$REPO_PREFIX/$PROJECT:$TAG"

            TIMESTAMP=$(date +%Y%m%d-%H%M%S)
            OUTPUT="export/$PROJECT/${PROJECT}-${TAG}-${TIMESTAMP}.json"

            echo "[INFO]       Tarama başlıyor: $IMAGE_URL"
            echo "[INFO]       Çıktı dosyası: $OUTPUT"

            docker run --rm \
                -v $(pwd)/export/$PROJECT:/output \
                -v $TRIVY_DB_PATH:/root/.cache/trivy \
                $TRIVY_IMAGE image \
                --insecure \
                --format json \
                --output "/output/${PROJECT}-${TAG}-${TIMESTAMP}.json" \
                "$IMAGE_URL"

            if [ $? -eq 0 ]; then
                # Backend container'ının okuyabilmesi için dosya permission'ını ayarla
                chmod 644 "export/$PROJECT/${PROJECT}-${TAG}-${TIMESTAMP}.json" 2>/dev/null || true
                echo "[INFO]       ✓ Tarama tamamlandı"
                TOTAL_SCANNED=$((TOTAL_SCANNED + 1))
            else
                echo "[ERROR]      ✗ Tarama başarısız oldu"
            fi
        else
            echo "[INFO]     → İmaj güncel, tarama atlanıyor (son tarama: $(date -d "@$LATEST_SCAN_TIME" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo 'bilinmiyor'))"
            TOTAL_SKIPPED=$((TOTAL_SKIPPED + 1))
        fi
    done

done

echo "----------------------------------------"
echo "[INFO] Trivy imajı siliniyor: $TRIVY_IMAGE"
docker rmi "$TRIVY_IMAGE" 2>/dev/null || true

echo "----------------------------------------"
echo "[INFO] Tarama tamamlandı."
echo "[INFO]   - Taranan imaj sayısı: $TOTAL_SCANNED"
echo "[INFO]   - Atlanan imaj sayısı: $TOTAL_SKIPPED"

# Index'i hemen yenile (periyodik ticker'ı beklememek için)
if [ "$TOTAL_SCANNED" -gt 0 ]; then
    DASHBOARD_API="${DASHBOARD_API:-http://localhost:3018}"
    if curl -sf -X POST "${DASHBOARD_API}/api/reload" -o /dev/null 2>/dev/null; then
        echo "[INFO] Dashboard index yenilendi"
    else
        echo "[WARN] Dashboard reload başarısız, periyodik yenileme beklenecek" >&2
    fi
fi