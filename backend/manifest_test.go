package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestManifestImageKey(t *testing.T) {
	cases := []struct{ in, project, image string }{
		{"shop_nginx", "shop", "nginx"},
		{"my_shop_backend-api", "my-shop", "backend-api"},
		{"registry:5000/repo/shop_frontend:test-v1.0", "shop", "frontend"},
	}
	for _, c := range cases {
		p, i, ok := manifestImageKey(c.in)
		if !ok || p != c.project || i != c.image {
			t.Errorf("manifestImageKey(%q) = %q,%q,%v; want %q,%q", c.in, p, i, ok, c.project, c.image)
		}
	}
}

func TestSanitizeManifestSource(t *testing.T) {
	ok := map[string]string{
		"shop-test":        "shop-test",
		"shop api_service": "shop-api_service",
		"shop/prod":        "shop-prod",
	}
	for in, want := range ok {
		got, err := sanitizeManifestSource(in)
		if err != nil || got != want {
			t.Errorf("sanitizeManifestSource(%q) = %q,%v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "..", "../etc/passwd", "a..b", "$(rm)"} {
		if _, err := sanitizeManifestSource(bad); err == nil {
			t.Errorf("sanitizeManifestSource(%q) reddedilmeliydi", bad)
		}
	}
}

// Manifestler BİRLEŞİM olarak değerlendirilmeli: aynı projeyi besleyen iki
// pipeline birbirinin imajını ölü ilan etmemeli.
func TestActiveImageSetUnion(t *testing.T) {
	set := buildActiveImageSet([]Manifest{
		{Source: "shop-test", Images: []string{"shop_nginx", "shop_frontend"}},
		{Source: "shop-prod", Images: []string{"shop_backend-api"}},
	})
	for _, img := range []string{"nginx", "frontend", "backend-api"} {
		if set.isRetired("shop", img, time.Time{}) {
			t.Errorf("%s retired olmamali", img)
		}
	}
	if !set.isRetired("shop", "captcha", time.Time{}) {
		t.Error("manifest disi imaj retired olmali")
	}
	if set.isRetired("other", "captcha", time.Time{}) {
		t.Error("manifesti olmayan proje etkilenmemeli")
	}
	// Ayıraç ve harf farkı eşleşmeyi bozmamalı.
	if set.isRetired("SHOP", "NGINX", time.Time{}) {
		t.Error("ayirac/harf farki eslesmeyi bozmamali")
	}
	if buildActiveImageSet(nil).isRetired("shop", "captcha", time.Time{}) {
		t.Error("manifest yokken hicbir imaj retired olmamali")
	}
}

// Manifestten SONRA pipeline'ın taradığı imaj ölü sayılmamalı (manifest eksik).
func TestActiveImageSetKeepsRecentlyBuiltImage(t *testing.T) {
	manifestTime := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	set := buildActiveImageSet([]Manifest{{Source: "shop-test", Images: []string{"shop_nginx"}, UpdatedAt: manifestTime}})

	if !set.isRetired("shop", "captcha", time.Time{}) {
		t.Error("pipeline sinyali yoksa retired olmali")
	}
	if !set.isRetired("shop", "frontend", manifestTime.Add(-2*time.Hour)) {
		t.Error("manifestten once build alan imaj retired olmali")
	}
	if set.isRetired("shop", "backend-api", manifestTime.Add(time.Minute)) {
		t.Error("manifestten sonra build alan imaj retired olmamali")
	}
}

func TestStoreAndLoadManifest(t *testing.T) {
	exportDir := t.TempDir()
	if err := storeManifest(exportDir, Manifest{
		Source: "shop-test",
		App:    "shop",
		Images: []string{"shop_nginx", " shop_frontend ", "shop_nginx", ""},
	}); err != nil {
		t.Fatal(err)
	}
	got := loadManifests(exportDir)
	if len(got) != 1 {
		t.Fatalf("1 manifest bekleniyordu, %d geldi", len(got))
	}
	want := []string{"shop_frontend", "shop_nginx"}
	if len(got[0].Images) != 2 || got[0].Images[0] != want[0] || got[0].Images[1] != want[1] {
		t.Errorf("imajlar %v, %v bekleniyordu", got[0].Images, want)
	}
	if got[0].UpdatedAt.IsZero() {
		t.Error("UpdatedAt doldurulmali")
	}
}

func TestLoadManifestsSkipsBroken(t *testing.T) {
	exportDir := t.TempDir()
	if err := os.MkdirAll(manifestDir(exportDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(manifestDir(exportDir), "bozuk.json"), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := storeManifest(exportDir, Manifest{Source: "saglam", Images: []string{"shop_nginx"}}); err != nil {
		t.Fatal(err)
	}
	if got := loadManifests(exportDir); len(got) != 1 || got[0].Source != "saglam" {
		t.Errorf("bozuk dosya atlanmali, saglam okunmali: %+v", got)
	}
}

// Üç imajlı projede manifest iki imaj bildiriyor: rebuildIndex üçüncüsünü retired
// işaretlemeli, proje toplamlarına katmamalı; .manifests dizini de hayalet bir
// proje olarak index'e girmemeli. Temizlik de manifest dizinine dokunmamalı.
func TestRebuildIndexMarksRetired(t *testing.T) {
	exportDir := t.TempDir()
	writeScan(t, exportDir, "shop_nginx", "test-v1.0", 1)
	writeScan(t, exportDir, "shop_frontend", "test-v1.0", 2)
	writeScan(t, exportDir, "shop_captcha", "test-v1.0", 40) // registry'de kalan ölü imaj

	if err := storeManifest(exportDir, Manifest{Source: "shop-test", Images: []string{"shop_nginx", "shop_frontend"}}); err != nil {
		t.Fatal(err)
	}
	if err := rebuildIndex(exportDir); err != nil {
		t.Fatal(err)
	}

	indexMu.RLock()
	current := indexData
	indexMu.RUnlock()

	if len(current.Projects) != 1 {
		var names []string
		for _, p := range current.Projects {
			names = append(names, p.ProjectName)
		}
		t.Fatalf("1 proje bekleniyordu, %v geldi (.manifests index'e girmis olabilir)", names)
	}

	p := current.Projects[0]
	retired := map[string]bool{}
	for _, img := range p.Images {
		retired[img.ImageName] = img.Retired
	}
	if !retired["captcha"] {
		t.Error("captcha retired olmaliydi")
	}
	if retired["nginx"] || retired["frontend"] {
		t.Error("manifestteki imajlar retired olmamali")
	}
	if p.SeverityCount["CRITICAL"] != 3 {
		t.Errorf("proje CRITICAL toplami %d, 3 bekleniyordu (retired imaj sizmis)", p.SeverityCount["CRITICAL"])
	}
	if p.TotalScans != 2 {
		t.Errorf("TotalScans %d, 2 bekleniyordu", p.TotalScans)
	}
	if list := retiredImagesForManifest(Manifest{Images: []string{"shop_nginx"}}); len(list) != 1 || list[0] != "shop/captcha" {
		t.Errorf("retired listesi: %v", list)
	}

	cleanupOldExports(exportDir)
	if got := loadManifests(exportDir); len(got) != 1 {
		t.Errorf("cleanup manifest dizinine dokunmamali, %d manifest kaldi", len(got))
	}
}

// writeScan, verilen imaj/tag için CRITICAL sayısı belli en sade Trivy raporunu yazar.
func writeScan(t *testing.T, exportDir, imageName, tag string, critical int) {
	t.Helper()
	dir := filepath.Join(exportDir, imageName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	vulns := make([]map[string]string, 0, critical)
	for i := 0; i < critical; i++ {
		vulns = append(vulns, map[string]string{"VulnerabilityID": "CVE-0000-" + strconv.Itoa(i), "Severity": "CRITICAL"})
	}
	data, err := json.Marshal(map[string]interface{}{
		"ArtifactName": "registry:5000/repository/my-repo/" + imageName + ":" + tag,
		"Results":      []map[string]interface{}{{"Vulnerabilities": vulns}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, imageName+"-"+tag+"-20261104-020000.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
}
