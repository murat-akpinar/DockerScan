#!/bin/bash

set -euo pipefail

REGISTRY_IP="http://yournexushost:8090"
REGISTRY_HOST="yournexushost:8090"
REPO_PREFIX="repository/my-repo"
TRIVY_IMAGE="aquasec/trivy:latest"

# Trivy DB için local cache klasörü
TRIVY_DB_PATH="/app/DockScan/trivy-db"

# ── Gecelik yeniden tarama ────────────────────────────────────────────────────
# İmaj değişmese bile CVE veritabanı değişiyor: Trivy DB'si 24 saatte bir yenileniyor
# (metadata.json → NextUpdate = UpdatedAt + 24s). Yalnız "registry'de imaj yenilendi mi"
# koşuluyla çalışırsak aylardır deploy edilmeyen imajlarda yeni CVE'ler HİÇ görünmez.
#
# Eşik neden 24 değil 20: cron her gece aynı saatte çalışıyor. 24 saat dersek dün
# 00:05'te taranan imaj bu gece 00:00'da 23s55d yaşında olur → atlanır, ertesi gece
# taranır. Sonuç: günaşırı tarama. Eşiği cron periyodunun altına çekmek bunu önler.
RESCAN_AFTER_HOURS="${RESCAN_AFTER_HOURS:-20}"

# İmaj başına taranacak EN YENİ tag sayısı. Her deploy registry'de yeni bir tag bırakıyor;
# hepsini her gece taramak hem saatler sürer hem de kullanılmayan eski sürümleri tarar.
# Varsayılan 2: tipik olarak bir prod + bir test tag'i. 0 = sınırsız.
MAX_TAGS_PER_IMAGE="${MAX_TAGS_PER_IMAGE:-2}"

# ---------------------------------------------------------------------------
# Eşzamanlı tarama kilidi
# ---------------------------------------------------------------------------
# Trivy cache dizinine (TRIVY_DB_PATH) ÖZEL kilit alıyor. Aynı anda iki tarama
# başlarsa ikincisi birkaç saniye bekleyip şu hatayla DÜŞÜYOR:
#   unable to initialize fs cache: cache may be in use by another process: timeout
# Birden fazla pipeline aynı anda build alınca ya da gecelik tarama sürerken olur.
# flock ile taramalar sıraya giriyor: düşmek yerine bekliyorlar. Kilit YALNIZ docker run süresince tutulur (~1-2 dk),
# dolayısıyla bekleyen pipeline bir tarama boyu gecikir, kaybetmez.
TRIVY_LOCK_FILE="${TRIVY_LOCK_FILE:-$(dirname "$TRIVY_DB_PATH")/.trivy-scan.lock}"
TRIVY_LOCK_WAIT="${TRIVY_LOCK_WAIT:-1800}"

trivy_lock_acquire() {
    command -v flock >/dev/null 2>&1 || {
        echo "[WARN] flock bulunamadı → kilitsiz devam ediliyor" >&2
        return 0
    }
    # Kilidi farklı kullanıcılar alabilir (CI ssh kullanıcısı, cron): hepsi aynı dosyayı açabilsin diye 666 ile oluşturuluyor.
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

    # Tag'leri registry zamanına göre sırala, en yeni MAX_TAGS_PER_IMAGE tanesini al.
    # get_registry_image_info zaten tag başına çağrılıyordu → ek istek maliyeti yok,
    # yalnız TARAMA sayısı sınırlanıyor.
    TAG_TIMES=""
    for TAG in $TAGS; do
        INFO=$(get_registry_image_info "$PROJECT_FULL" "$TAG")
        [ "$INFO" = "ERROR" ] && { echo "[WARN]     Registry bilgisi alınamadı: $PROJECT:$TAG"; continue; }
        TAG_TIMES="${TAG_TIMES}$(echo "$INFO" | cut -d'|' -f1)|${TAG}|$(echo "$INFO" | cut -d'|' -f2)
"
    done

    if [ "$MAX_TAGS_PER_IMAGE" -gt 0 ]; then
        SELECTED_TAGS=$(printf '%s' "$TAG_TIMES" | grep -v '^$' | sort -rn -t'|' -k1 | head -n "$MAX_TAGS_PER_IMAGE" || true)
        TOTAL_TAGS=$(printf '%s' "$TAG_TIMES" | grep -vc '^$' || true)
        if [ "$TOTAL_TAGS" -gt "$MAX_TAGS_PER_IMAGE" ]; then
            echo "[INFO]   $TOTAL_TAGS tag'den en yeni $MAX_TAGS_PER_IMAGE tanesi taranacak"
        fi
    else
        SELECTED_TAGS=$(printf '%s' "$TAG_TIMES" | grep -v '^$' | sort -rn -t'|' -k1 || true)
    fi

    while IFS='|' read -r REGISTRY_TIME TAG REGISTRY_DIGEST; do
        [ -z "$TAG" ] && continue
        echo "[INFO]   → Tag kontrol ediliyor: $TAG"

        # Mevcut tarama zamanını kontrol et
        LATEST_SCAN_TIME=$(get_latest_scan_time "$PROJECT" "$TAG")

        # Tarama gerekçesi: (1) hiç taranmamış, (2) registry'de imaj yenilenmiş,
        # (3) son tarama bayatlamış → CVE veritabanı o tarihten beri güncellendi.
        SCAN_REASON=""
        if [ "$LATEST_SCAN_TIME" -eq 0 ]; then
            SCAN_REASON="hiç taranmamış"
        elif [ "$REGISTRY_TIME" -gt "$LATEST_SCAN_TIME" ]; then
            SCAN_REASON="imaj güncellenmiş"
        elif [ $(( $(date +%s) - LATEST_SCAN_TIME )) -gt $(( RESCAN_AFTER_HOURS * 3600 )) ]; then
            SCAN_REASON="son tarama ${RESCAN_AFTER_HOURS} saatten eski (güncel CVE DB'si ile yeniden)"
        fi

        if [ -n "$SCAN_REASON" ]; then
            echo "[INFO]     → Tarama başlatılıyor: $SCAN_REASON"
            
            # Trivy'nin anlayacağı doğru docker image adı
            IMAGE_URL="$REGISTRY_HOST/$REPO_PREFIX/$PROJECT:$TAG"

            TIMESTAMP=$(date +%Y%m%d-%H%M%S)
            OUTPUT="export/$PROJECT/${PROJECT}-${TAG}-${TIMESTAMP}.json"

            echo "[INFO]       Tarama başlıyor: $IMAGE_URL"
            echo "[INFO]       Çıktı dosyası: $OUTPUT"

            # Kilit alınamazsa (başka tarama 30 dk'dır sürüyor) bu imajı atla: gecelik
            # turun tamamı tek imaj yüzünden düşmemeli, yarın yine denenir.
            if ! trivy_lock_acquire; then
                echo "[ERROR]      ✗ Kilit alınamadı, bu imaj atlanıyor"
                continue
            fi

            docker run --rm \
                -v $(pwd)/export/$PROJECT:/output \
                -v $TRIVY_DB_PATH:/root/.cache/trivy \
                $TRIVY_IMAGE image \
                --insecure \
                --format json \
                --output "/output/${PROJECT}-${TAG}-${TIMESTAMP}.json" \
                "$IMAGE_URL" && SCAN_RC=0 || SCAN_RC=$?

            trivy_lock_release

            if [ $SCAN_RC -eq 0 ]; then
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
    # Alt kabuk YOK: pipe yerine here-string → TOTAL_SCANNED/TOTAL_SKIPPED sayaçları
    # döngüden sonra da korunur (pipe kullanılsaydı sayaçlar sıfır kalırdı).
    done <<< "$SELECTED_TAGS"

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