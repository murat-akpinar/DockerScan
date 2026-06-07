#requires -Version 5.1
<#
  scan-popular.ps1
  --------------------------------------------------------------------
  Popüler Docker imajlarının birkaç versiyonunu Trivy ile tarar,
  sonuçları export/ klasörüne koyar ve dashboard'ın yükleme süresini
  ölçer. Çok sayıda tarama verisiyle açılış hızını test etmek içindir.

  Kullanim:
    .\scan-popular.ps1                 # tum imajlari tara
    .\scan-popular.ps1 -PerImage 2     # her imajdan sadece 2 versiyon
    .\scan-popular.ps1 -LocalOnly      # sadece kendi imajlari (hizli)

  Not: Trivy DB'si bir kez indirilip named volume'da saklanır. Ardışık
  taramalarda Trivy cache kilidi ("cache may be in use") nadiren çakışır;
  bu durumda tarama otomatik olarak birkaç kez tekrar denenir.
#>
param(
    [int]$PerImage    = 4,                           # her imajdan kac versiyon
    [string]$Dashboard = "http://localhost:3018",    # backend (reload + olcum)
    [switch]$LocalOnly                               # sadece kendi imajlari
)

$root       = $PSScriptRoot
$exportRoot = Join-Path $root 'export'
$trivyImage = 'aquasec/trivy:latest'
$cacheVol   = 'dockscan-trivy-cache'   # Trivy DB cache — tekrar indirmesin
$maxRetry   = 3                        # kilit hatasında tekrar deneme sayısı

# Taranacak imajlar: ref + versiyon listesi
$targets = @(
    @{ ref = 'nginx';           tags = @('1.25', '1.26', '1.27', 'alpine') }       # Nginx
    @{ ref = 'httpd';           tags = @('2.4.58', '2.4.59', '2.4.62', 'alpine') } # Apache HTTP
    @{ ref = 'php';             tags = @('8.1', '8.2', '8.3', '8.4') }             # PHP
    @{ ref = 'node';            tags = @('18', '20', '22', '24') }                 # Node.js (güncel LTS/major)
    @{ ref = 'wordpress';       tags = @('6.4', '6.5', '6.6', '6.7') }             # WordPress
    @{ ref = 'grafana/grafana'; tags = @('10.4.0', '11.0.0', '11.1.0', '11.2.0') } # Grafana
)

# DockerScan'ın kendi imajları (yerel, docker compose ile build edilmiş)
$localTargets = @(
    @{ proj = 'dockscan'; image = 'dockscan_backend'; ref = 'dockscan_backend:latest' }
    @{ proj = 'dockscan'; image = 'dockscan_nginx';   ref = 'dockscan_nginx:latest'   }
)

Write-Host "== DockScan tarama ==" -ForegroundColor Cyan
docker volume create $cacheVol | Out-Null

Write-Host "Trivy DB hazirlaniyor (bir kez indirilir)..." -ForegroundColor Cyan
docker run --rm -v "${cacheVol}:/root/.cache/trivy" $trivyImage image --download-db-only --quiet 2>&1 | Out-Null

$grandTotal = ($targets | ForEach-Object { [math]::Min($PerImage, $_.tags.Count) } | Measure-Object -Sum).Sum
$n = 0; $ok = 0; $fail = 0
$swAll = [System.Diagnostics.Stopwatch]::StartNew()

if ($LocalOnly) {
    Write-Host "  -LocalOnly: harici imaj taramasi atlandi." -ForegroundColor DarkYellow
}

foreach ($t in $targets) {
    if ($LocalOnly) { continue }
    $proj   = ($t.ref -split '/')[-1]                 # grafana/grafana -> grafana
    $outDir = Join-Path $exportRoot $proj
    New-Item -ItemType Directory -Force $outDir | Out-Null

    $tags = $t.tags | Select-Object -First $PerImage
    foreach ($tag in $tags) {
        $n++
        $imageRef = "$($t.ref):$tag"
        $safeTag  = $tag -replace '[^\w.\-]', '_'
        $ts       = Get-Date -Format 'yyyyMMdd-HHmmss'
        $outName  = "$proj-$safeTag-$ts.json"

        Write-Host ("[{0}/{1}] {2}" -f $n, $grandTotal, $imageRef) -ForegroundColor Yellow
        $sw = [System.Diagnostics.Stopwatch]::StartNew()

        # Kilit/gecici hatalara karsi birkac kez dene
        $attempt = 0
        $done = $false
        while (-not $done -and $attempt -lt $maxRetry) {
            $attempt++
            docker run --rm `
                -v "${cacheVol}:/root/.cache/trivy" `
                -v "${outDir}:/output" `
                $trivyImage image --quiet --scanners vuln --skip-db-update `
                --format json --output "/output/$outName" $imageRef
            if ($LASTEXITCODE -eq 0) {
                $done = $true
            }
            elseif ($attempt -lt $maxRetry) {
                Write-Host ("    gecici hata, {0}. deneme..." -f ($attempt + 1)) -ForegroundColor DarkYellow
                Start-Sleep -Seconds 3
            }
        }

        $sw.Stop()
        if ($done) {
            $ok++
            Write-Host ("    OK  ({0:n1} sn)" -f $sw.Elapsed.TotalSeconds) -ForegroundColor Green
        }
        else {
            $fail++
            Write-Host ("    HATA ({0} deneme sonrasi) - atlandi" -f $maxRetry) -ForegroundColor Red
        }
    }
}
$swAll.Stop()

# ---------------------------------------------------------------------------
# Trivy - DockerScan kendi yerel imajlarini tara
# ---------------------------------------------------------------------------
Write-Host "`n== DockerScan Yerel Imaj Taramasi (Trivy) ==" -ForegroundColor Cyan

foreach ($lt in $localTargets) {
    $outDir = Join-Path $exportRoot $lt.proj
    New-Item -ItemType Directory -Force $outDir | Out-Null

    $ts      = Get-Date -Format 'yyyyMMdd-HHmmss'
    $outName = "$($lt.image)-latest-$ts.json"

    Write-Host ("  [Trivy] {0}" -f $lt.ref) -ForegroundColor Yellow

    # Imajin yerelde var olup olmadigini kontrol et
    $imgExists = docker image inspect $lt.ref 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "    ATLANDI - imaj bulunamadi: $($lt.ref)  (once 'docker compose up --build' calistirin)" -ForegroundColor DarkYellow
        continue
    }

    $attempt = 0; $done = $false
    while (-not $done -and $attempt -lt $maxRetry) {
        $attempt++
        docker run --rm `
            -v "${cacheVol}:/root/.cache/trivy" `
            -v /var/run/docker.sock:/var/run/docker.sock `
            -v "${outDir}:/output" `
            $trivyImage image --quiet --scanners vuln --skip-db-update `
            --format json --output "/output/$outName" $lt.ref
        if ($LASTEXITCODE -eq 0) { $done = $true }
        elseif ($attempt -lt $maxRetry) {
            Write-Host ("    gecici hata, {0}. deneme..." -f ($attempt + 1)) -ForegroundColor DarkYellow
            Start-Sleep -Seconds 3
        }
    }

    if ($done) {
        Write-Host "    OK" -ForegroundColor Green
    } else {
        Write-Host ("    HATA ({0} deneme sonrasi) - atlandi" -f $maxRetry) -ForegroundColor Red
    }
}

# ---------------------------------------------------------------------------
# Checkov — proje Dockerfile'larını tara
# ---------------------------------------------------------------------------
Write-Host "`n== Checkov IaC Taraması ==" -ForegroundColor Cyan

$checkovImage   = 'bridgecrew/checkov:latest'
$checkovTargets = @(
    @{ proj = 'dockscan'; service = 'dockscan_backend'; path = 'backend' }
    @{ proj = 'dockscan'; service = 'dockscan_nginx';   path = 'nginx'   }
)
$checkovOk = 0; $checkovFail = 0

foreach ($t in $checkovTargets) {
    $outDir  = Join-Path $exportRoot $t.proj
    $srcPath = Join-Path $root $t.path
    New-Item -ItemType Directory -Force $outDir | Out-Null

    $ts      = Get-Date -Format 'yyyyMMdd-HHmmss'
    $outFile = Join-Path $outDir "checkov-$($t.service)-local-$ts.json"

    Write-Host ("  [Checkov] {0}" -f $t.service) -ForegroundColor Yellow

    if (-not (Test-Path $srcPath)) {
        Write-Host "    ATLANDI - imaj bulunamadi: $($lt.ref)  (once 'docker compose up --build' calistirin)" -ForegroundColor DarkYellow
        continue
    }

    $checkovOut = & docker run --rm `
        -v "${srcPath}:/project" `
        $checkovImage `
        --directory /project `
        --output json `
        --quiet
    $exit = $LASTEXITCODE
    $checkovOut | Out-File -FilePath $outFile -Encoding utf8

    if ($exit -eq 0) {
        $checkovOk++
        Write-Host "    Temiz" -ForegroundColor Green
    } elseif ($exit -eq 1) {
        $checkovOk++
        Write-Host "    Bulgular var (dashboard'da goruntulenecek)" -ForegroundColor Yellow
    } else {
        $checkovFail++
        Write-Host "    HATA (kod: $exit)" -ForegroundColor Red
    }
}

# ---------------------------------------------------------------------------
# OSV-Scanner — bağımlılık dosyalarını tara
# ---------------------------------------------------------------------------
Write-Host "`n== OSV-Scanner Bağımlılık Taraması ==" -ForegroundColor Cyan

$osvImage   = 'ghcr.io/google/osv-scanner:latest'
$osvTargets = @(
    @{ proj = 'dockscan'; service = 'dockscan_backend';  path = 'backend'  }
    @{ proj = 'dockscan'; service = 'dockscan_frontend'; path = 'frontend' }
)
$osvOk = 0; $osvFail = 0

foreach ($t in $osvTargets) {
    $outDir  = Join-Path $exportRoot $t.proj
    $srcPath = Join-Path $root $t.path
    New-Item -ItemType Directory -Force $outDir | Out-Null

    $ts      = Get-Date -Format 'yyyyMMdd-HHmmss'
    $outFile = Join-Path $outDir "osv-$($t.service)-local-$ts.json"

    Write-Host ("  [OSV] {0}" -f $t.service) -ForegroundColor Yellow

    if (-not (Test-Path $srcPath)) {
        Write-Host "    ATLANDI - imaj bulunamadi: $($lt.ref)  (once 'docker compose up --build' calistirin)" -ForegroundColor DarkYellow
        continue
    }

    $osvOut = & docker run --rm `
        -v "${srcPath}:/src" `
        $osvImage `
        --recursive /src `
        --format json
    $exit = $LASTEXITCODE
    $osvOut | Out-File -FilePath $outFile -Encoding utf8

    if ($exit -eq 0) {
        $osvOk++
        Write-Host "    Temiz" -ForegroundColor Green
    } elseif ($exit -eq 1) {
        $osvOk++
        Write-Host "    Zafiyetler var (dashboard'da goruntulenecek)" -ForegroundColor Yellow
    } else {
        $osvFail++
        Write-Host "    HATA (kod: $exit)" -ForegroundColor Red
    }
}

# Index'i hemen yenile
Write-Host "`nIndex yenileniyor..." -ForegroundColor Cyan
try { Invoke-RestMethod -Method POST "$Dashboard/api/reload" -TimeoutSec 30 | Out-Null } catch {
    Write-Host "  reload cagrisi basarisiz (backend ayakta mi?)" -ForegroundColor Red
}

function Measure-Endpoint($path) {
    $url = "$Dashboard$path"
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $r = Invoke-WebRequest -UseBasicParsing -Uri $url
    $sw.Stop()
    [pscustomobject]@{
        Endpoint    = $path
        HTTP        = $r.StatusCode
        'Sure(ms)'  = [math]::Round($sw.Elapsed.TotalMilliseconds, 0)
        'Boyut(KB)' = [math]::Round($r.RawContentLength / 1KB, 1)
    }
}

# Özet
Write-Host "`n== Tarama Ozeti ==" -ForegroundColor Cyan
Write-Host ("Trivy (harici) - Toplam: {0}  Basarili: {1}  Hata: {2}  Sure: {3:n0} sn" -f `
        $grandTotal, $ok, $fail, $swAll.Elapsed.TotalSeconds)
Write-Host ("Trivy (yerel)  - dockscan_backend + dockscan_nginx")
Write-Host ("Checkov        - Basarili: {0}  Hata: {1}" -f $checkovOk, $checkovFail)
Write-Host ("OSV            - Basarili: {0}  Hata: {1}" -f $osvOk, $osvFail)

$jsons = Get-ChildItem $exportRoot -Recurse -Filter *.json -ErrorAction SilentlyContinue
$sizeMB = [math]::Round((($jsons | Measure-Object Length -Sum).Sum / 1MB), 1)
Write-Host ("export/ icinde: {0} JSON dosyasi, {1} MB" -f $jsons.Count, $sizeMB)

Write-Host "`n== Dashboard Yukleme Sureleri ==" -ForegroundColor Cyan
@(
    Measure-Endpoint "/api/scans"
    Measure-Endpoint "/api/projects"
    Measure-Endpoint "/api/grades"
) | Format-Table -AutoSize

Write-Host "Dashboard: http://localhost:3017`n" -ForegroundColor Green

