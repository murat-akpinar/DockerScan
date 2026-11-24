package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Proje manifesti: bir pipeline'ın "bu proje şu imajlardan oluşuyor" bildirimi.
//
// Neden gerekli: dashboard projeyi export/ altında ne bulduğundan türetiyor, export'u
// da gecelik tarama registry kataloğundan dolduruyor (scan-nexus.sh). Registry
// temizlenmediği sürece projeden çıkarılmış ya da adı değiştirilmiş imajlar orada
// kalıyor, her gece yeniden taranıyor ve projenin notuna geri karışıyor.
//
// /api/grades'teki tag filtresi bunu kurtarmıyor: projeler çoğunlukla sabit tag
// (test-v1.0 / prod-v1.0) kullandığı için ölü imajın gecelik taraması da aynı tag'e
// düşüyor. Tek güvenilir kaynak build'in kendisi: pipeline aktif imaj listesini
// POST /api/manifest ile bildirir.
type Manifest struct {
	// Source: bildirimi yapan pipeline. Dosya adı olarak da kullanılır.
	Source string `json:"source"`
	// App: yalnız insan okuması için.
	App string `json:"app,omitempty"`
	// Images: tam imaj adları (ör. "dockscan_backend").
	Images    []string  `json:"images"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// ManifestInfo — /api/manifests yanıtında bir manifest ve onun hâlen indexte duran
// ama manifest dışı kalan imajları.
type ManifestInfo struct {
	Manifest
	RetiredImages []string `json:"retiredImages,omitempty"`
}

// manifestSourcePattern: dosya adı olarak kullanılacağı için yol ayracı, nokta-nokta
// ve sürpriz karakterler kabul edilmiyor. Kaynak adı pipeline'dan geliyor, yani
// güvenilmeyen girdi sayılmalı.
var manifestSourcePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,99}$`)

func manifestDir(exportDir string) string {
	return filepath.Join(exportDir, manifestDirName)
}

// sanitizeManifestSource kaynak adını dosya adı olarak kullanılabilir hale getirir.
// Boşluk ve eğik çizgi tireye çevrilir; kalan ad desene uymazsa reddedilir.
func sanitizeManifestSource(source string) (string, error) {
	s := strings.TrimSpace(source)
	// ".." temizlenmeye çalışılmıyor, doğrudan reddediliyor.
	if strings.Contains(s, "..") {
		return "", fmt.Errorf("gecersiz manifest kaynagi: %q", source)
	}
	s = strings.NewReplacer(" ", "-", "/", "-", "\\", "-", ":", "-").Replace(s)
	s = strings.Trim(s, ".-")
	if !manifestSourcePattern.MatchString(s) {
		return "", fmt.Errorf("gecersiz manifest kaynagi: %q", source)
	}
	return s, nil
}

// manifestImageKey, manifestteki tam imaj adını index'in (proje, imaj) kimliğine
// çevirir. Index de aynı ayrıştırıcıyı kullandığı için eşleşme garanti.
func manifestImageKey(fullImageName string) (projectKey, imageKey string, ok bool) {
	project, image, _ := extractProjectImageTagFromArtifactName(strings.TrimSpace(fullImageName))
	if project == "" || image == "" {
		return "", "", false
	}
	return normalizeProjectName(project), strings.ToLower(image), true
}

// storeManifest manifesti diske yazar. Yazım atomik (tmp + rename): yarım dosya
// okunup proje bir anlık "imajsız" görünmesin.
func storeManifest(exportDir string, m Manifest) error {
	name, err := sanitizeManifestSource(m.Source)
	if err != nil {
		return err
	}
	dir := manifestDir(exportDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("manifest dizini olusturulamadi: %w", err)
	}

	m.Source = name
	m.Images = normalizeManifestImages(m.Images)
	if m.UpdatedAt.IsZero() {
		m.UpdatedAt = time.Now()
	}

	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	final := filepath.Join(dir, name+".json")
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("manifest yazilamadi: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("manifest tasinamadi: %w", err)
	}
	return nil
}

// normalizeManifestImages boşlukları atar, tekrarları teker, sırayı sabitler.
func normalizeManifestImages(images []string) []string {
	seen := make(map[string]bool, len(images))
	out := make([]string, 0, len(images))
	for _, img := range images {
		img = strings.TrimSpace(img)
		if img == "" || seen[img] {
			continue
		}
		seen[img] = true
		out = append(out, img)
	}
	sort.Strings(out)
	return out
}

// loadManifests export/.manifests altındaki tüm manifestleri okur. Bozuk dosya
// turu düşürmez: loglanır, atlanır — index her dakika yeniden kuruluyor.
func loadManifests(exportDir string) []Manifest {
	entries, err := os.ReadDir(manifestDir(exportDir))
	if err != nil {
		return nil // dizin yok: hiç manifest bildirilmemiş
	}

	manifests := make([]Manifest, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		path := filepath.Join(manifestDir(exportDir), e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			log.Printf("manifest: %s okunamadi, atlaniyor: %v", path, err)
			continue
		}
		var m Manifest
		if err := json.Unmarshal(data, &m); err != nil {
			log.Printf("manifest: %s okunamadi, atlaniyor: %v", path, err)
			continue
		}
		if len(m.Images) == 0 {
			continue
		}
		if m.Source == "" {
			m.Source = strings.TrimSuffix(e.Name(), ".json")
		}
		manifests = append(manifests, m)
	}
	sort.Slice(manifests, func(i, j int) bool { return manifests[i].Source < manifests[j].Source })
	return manifests
}

// activeImageSet, manifestlerin BİRLEŞİMİ: bir imaj hiçbir manifestte geçmiyorsa
// retired sayılır. Birleşim şart, çünkü tek bir dashboard projesini birden fazla
// pipeline besleyebilir; manifest başına "projeyi sıfırla" semantiği olsaydı
// pipeline'lar birbirinin imajlarını ölü ilan ederdi.
type activeImageSet struct {
	// covered: manifesti olan projeler. Manifesti olmayan projede davranış
	// değişmez — yayılım kademeli olabilsin diye.
	covered map[string]bool
	// coveredAt: proje için en son manifest bildirimi.
	coveredAt map[string]time.Time
	active    map[string]bool // "proje/imaj"
}

func buildActiveImageSet(manifests []Manifest) *activeImageSet {
	s := &activeImageSet{covered: map[string]bool{}, coveredAt: map[string]time.Time{}, active: map[string]bool{}}
	for _, m := range manifests {
		for _, img := range m.Images {
			projectKey, imageKey, ok := manifestImageKey(img)
			if !ok {
				continue
			}
			s.covered[projectKey] = true
			s.active[projectKey+"/"+imageKey] = true
			if m.UpdatedAt.After(s.coveredAt[projectKey]) {
				s.coveredAt[projectKey] = m.UpdatedAt
			}
		}
	}
	return s
}

// isRetired: proje manifest kapsamındaysa ve imaj hiçbir manifestte yoksa true.
//
// lastBuild, imajın en son pipeline tarafından tarandığı an (trigger-nexus.sh'in
// yazdığı meta-<imaj>.json dosyasının zamanı; gecelik tarama meta yazmaz).
// Manifestten SONRA pipeline'ın derleyip taradığı imaj ölü SAYILMAZ: o imajı bir
// pipeline hâlâ derliyor, yani elimizdeki manifest eksik. Hatanın yönü bilinçli:
// ölü imajı bir süre daha saymak, canlı imajı sessizce nottan düşürmekten iyidir.
func (s *activeImageSet) isRetired(projectName, imageName string, lastBuild time.Time) bool {
	if s == nil || len(s.covered) == 0 {
		return false
	}
	projectKey := normalizeProjectName(projectName)
	if !s.covered[projectKey] {
		return false
	}
	if s.active[projectKey+"/"+strings.ToLower(imageName)] {
		return false
	}
	since := s.coveredAt[projectKey]
	return since.IsZero() || !lastBuild.After(since)
}

// retiredImagesForManifest, bu manifestin kapsadığı projelerde hâlen index'te
// duran ama manifest dışı kalan imajları "proje/imaj" biçiminde döndürür.
func retiredImagesForManifest(m Manifest) []string {
	projects := make(map[string]bool)
	for _, img := range m.Images {
		if projectKey, _, ok := manifestImageKey(img); ok {
			projects[projectKey] = true
		}
	}

	indexMu.RLock()
	current := indexData
	indexMu.RUnlock()
	if current == nil {
		return nil
	}

	var out []string
	for _, p := range current.Projects {
		if !projects[normalizeProjectName(p.ProjectName)] {
			continue
		}
		for _, img := range p.Images {
			if img.Retired {
				out = append(out, p.ProjectName+"/"+img.ImageName)
			}
		}
	}
	sort.Strings(out)
	return out
}
