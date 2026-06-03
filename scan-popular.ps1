#requires -Version 5.1
<#
  scan-popular.ps1
  --------------------------------------------------------------------
  Popüler Docker imajlarının birkaç versiyonunu Trivy ile tarar,
  sonuçları export/ klasörüne koyar ve dashboard'ın yükleme süresini
  ölçer. Çok sayıda tarama verisiyle açılış hızını test etmek içindir.

  Kullanım:
    .\scan-popular.ps1                 # tüm imajları tara
    .\scan-popular.ps1 -PerImage 2     # her imajdan sadece 2 versiyon

  Not: Trivy DB'si bir kez indirilip named volume'da saklanır. Ardışık
  taramalarda Trivy cache kilidi ("cache may be in use") nadiren çakışır;
  bu durumda tarama otomatik olarak birkaç kez tekrar denenir.
#>
param(
    [int]$PerImage = 4,                          # her imajdan kaç versiyon
    [string]$Dashboard = "http://localhost:3018" # backend (reload + ölçüm)
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

Write-Host "== DockScan toplu tarama ==" -ForegroundColor Cyan
docker volume create $cacheVol | Out-Null

# Trivy DB'sini bir kez indir; taramalar artik DB guncellemesi yapmayacak
# (--skip-db-update), bu da cache kilit cakismalarini buyuk olcude onler.
Write-Host "Trivy DB hazirlaniyor (bir kez indirilir)..." -ForegroundColor Cyan
docker run --rm -v "${cacheVol}:/root/.cache/trivy" $trivyImage image --download-db-only --quiet 2>&1 | Out-Null

# Toplam tarama sayısı (ilerleme için)
$grandTotal = ($targets | ForEach-Object { [math]::Min($PerImage, $_.tags.Count) } | Measure-Object -Sum).Sum
$n = 0; $ok = 0; $fail = 0
$swAll = [System.Diagnostics.Stopwatch]::StartNew()

foreach ($t in $targets) {
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
Write-Host ("Toplam: {0}  Basarili: {1}  Hata: {2}  Sure: {3:n0} sn" -f `
        $grandTotal, $ok, $fail, $swAll.Elapsed.TotalSeconds)

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
