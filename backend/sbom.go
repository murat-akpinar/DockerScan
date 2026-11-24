package main

import (
	"encoding/json"
	"log"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ── /api/sbom ──────────────────────────────────────────────────────────────
// Teknoloji envanteri için sadeleştirilmiş görünüm: her imajın SON taramasından
// OS, runtime sürümleri ve (varsa) kurulu paket listesi. Zafiyet DÖNMEZ.
// Trivy'nin ham yapısı buraya sızmaz: tüketici Trivy şeması değişince kırılmasın.
//
// Neden ayrı endpoint: /api/scans/{file} tüm zafiyetleri döküyor (megabaytlar),
// /api/grades ise yalnız harf notu veriyor. Envanterin ihtiyacı ikisinin arasında.

type SbomResponse struct {
	GeneratedAt time.Time     `json:"generatedAt"`
	Projects    []SbomProject `json:"projects"`
}

type SbomProject struct {
	ProjectName string      `json:"projectName"`
	Images      []SbomImage `json:"images"`
}

type SbomImage struct {
	ImageName string    `json:"imageName"`
	Tag       string    `json:"tag,omitempty"`
	ScannedAt time.Time `json:"scannedAt"`
	OS        SbomOS    `json:"os"`
	Env       []SbomEnv `json:"env"`       // yalnız *_VERSION değişkenleri
	Languages []string  `json:"languages"` // lang-pkgs Type'ları: gobinary, jar, node-pkg…
	Packages  []SbomPkg `json:"packages,omitempty"`
}

type SbomOS struct {
	Family  string `json:"family,omitempty"`
	Version string `json:"version,omitempty"`
}

type SbomEnv struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type SbomPkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"` // hangi Result'tan geldiği: gobinary, node-pkg, alpine…
}

// buildSbomImage bir Trivy raporunu envanter görünümüne indirger.
//
// Env'de yalnız "*_VERSION" ile biten değişkenler tutulur: PATH, LANG gibi
// satırlar envanter için gürültü, ayrıca imajın tüm ortam değişkenlerini dışarı
// vermek gereksiz bir bilgi sızıntısı olur.
func buildSbomImage(imageName string, scan ScanSummary, report *TrivyReport, withPackages bool) SbomImage {
	out := SbomImage{
		ImageName: imageName,
		Tag:       scan.Tag,
		ScannedAt: scan.ModifiedAt,
		OS: SbomOS{
			Family:  report.Metadata.OS.Family,
			Version: report.Metadata.OS.Name,
		},
		Env:       []SbomEnv{},
		Languages: []string{},
	}

	for _, e := range report.Metadata.ImageConfig.Config.Env {
		key, value, found := strings.Cut(e, "=")
		if !found || !strings.HasSuffix(key, "_VERSION") {
			continue
		}
		out.Env = append(out.Env, SbomEnv{Key: key, Value: value})
	}

	for _, res := range report.Results {
		if res.Class == "lang-pkgs" && res.Type != "" {
			out.Languages = append(out.Languages, res.Type)
		}
		if !withPackages {
			continue
		}
		for _, pkg := range res.Packages {
			out.Packages = append(out.Packages, SbomPkg{Name: pkg.Name, Version: pkg.Version, Type: res.Type})
		}
	}
	return out
}

// handleSbom: ?project=X → tek projeye süz, ?packages=0 → paket listesini atla.
func handleSbom(exportDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		projectFilter := r.URL.Query().Get("project")
		withPackages := r.URL.Query().Get("packages") != "0"

		indexMu.RLock()
		current := indexData
		indexMu.RUnlock()
		if current == nil {
			http.Error(w, "index not ready", http.StatusServiceUnavailable)
			return
		}

		projects := make([]SbomProject, 0, len(current.Projects))
		for _, p := range current.Projects {
			if projectFilter != "" && !projectNameMatches(p.ProjectName, projectFilter) {
				continue
			}
			images := make([]SbomImage, 0, len(p.Images))
			for _, img := range p.Images {
				// Retired imaj "şu an ne koşuyor" sorusunu yanlış yanıtlar.
				if img.Retired || len(img.Scans) == 0 {
					continue
				}
				// Scans tarihe göre yeniden eskiye sıralı → [0] son tarama.
				latest := img.Scans[0]
				report, err := parseTrivyJSON(filepath.Join(exportDir, latest.Filename))
				if err != nil {
					// Dosya silinmiş olabilir (cleanup) — o imajı atla.
					log.Printf("sbom: %s okunamadı: %v", latest.Filename, err)
					continue
				}
				images = append(images, buildSbomImage(img.ImageName, latest, report, withPackages))
			}
			if len(images) > 0 {
				projects = append(projects, SbomProject{ProjectName: p.ProjectName, Images: images})
			}
		}

		sort.Slice(projects, func(i, j int) bool { return projects[i].ProjectName < projects[j].ProjectName })

		w.Header().Set(headerContentType, mimeApplicationJSON)
		if err := json.NewEncoder(w).Encode(SbomResponse{GeneratedAt: current.GeneratedAt, Projects: projects}); err != nil {
			http.Error(w, errEncodeResponse, http.StatusInternalServerError)
		}
	}
}
