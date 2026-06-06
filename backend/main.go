package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
)

// Common constants to avoid duplicated literals and improve maintainability.
const (
	headerContentType        = "Content-Type"
	mimeTextPlainUTF8        = "text/plain; charset=utf-8"
	mimeApplicationJSON      = "application/json"
	defaultExportDir         = "/app/export"
	indexRebuildIntervalSec  = 60
	cleanupIntervalHours     = 24
	cleanupRetentionDays     = 30
	errReadExportDirectory   = "failed to read export directory"
	errEncodeResponse        = "failed to encode response"
	errInvalidFilename       = "invalid filename"
)

// IndexData holds precomputed scan and project summaries in memory.
type IndexData struct {
	Scans        []ScanSummary
	Projects     []ProjectSummary
	CheckovScans []CheckovScanRecord
	OsvScans     []OsvScanRecord
	GeneratedAt  time.Time

	// cveIndex maps a CVE ID to the indices (into Scans) of the scans that
	// contain it. Lets /api/cve answer from memory instead of re-reading disk.
	cveIndex map[string][]int

	// imageScans maps projectName -> imageName -> sorted scan history.
	// Lets the image scan-history endpoint answer from memory.
	imageScans map[string]map[string][]ScanSummary

	// etag is a content fingerprint (derived from GeneratedAt) used for
	// HTTP conditional requests (If-None-Match -> 304 Not Modified).
	etag string
}

// ── Checkov types ──────────────────────────────────────────────────────────

type CheckovFinding struct {
	CheckID  string `json:"checkId"`
	Name     string `json:"name"`
	FilePath string `json:"filePath"`
	Line     int    `json:"line"`
}

type CheckovScanRecord struct {
	Filename    string           `json:"filename"`
	ProjectName string           `json:"projectName"`
	ServiceName string           `json:"serviceName"`
	Tag         string           `json:"tag"`
	ScannedAt   time.Time        `json:"scannedAt"`
	Passed      int              `json:"passed"`
	Failed      int              `json:"failed"`
	Skipped     int              `json:"skipped"`
	Findings    []CheckovFinding `json:"findings"`
}

// ── OSV-Scanner types ──────────────────────────────────────────────────────

type OsvVuln struct {
	ID      string `json:"id"`
	Summary string `json:"summary"`
}

type OsvPackage struct {
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	Ecosystem string    `json:"ecosystem"`
	VulnCount int       `json:"vulnCount"`
	Vulns     []OsvVuln `json:"vulns"`
}

type OsvSource struct {
	Path     string       `json:"path"`
	Type     string       `json:"type"`
	Packages []OsvPackage `json:"packages"`
}

type OsvScanRecord struct {
	Filename    string      `json:"filename"`
	ProjectName string      `json:"projectName"`
	ServiceName string      `json:"serviceName"`
	Tag         string      `json:"tag"`
	ScannedAt   time.Time   `json:"scannedAt"`
	TotalVulns  int         `json:"totalVulns"`
	Sources     []OsvSource `json:"sources"`
}

// fileCacheEntry caches the parsed result of a single scan file so that
// unchanged files are not re-parsed on every index rebuild.
type fileCacheEntry struct {
	modTime time.Time
	size    int64
	summary ScanSummary
	cveIDs  []string // unique CVE IDs present in this file
}

type checkovCacheEntry struct {
	modTime time.Time
	size    int64
	record  CheckovScanRecord
}

type osvCacheEntry struct {
	modTime time.Time
	size    int64
	record  OsvScanRecord
}

var (
	indexMu   sync.RWMutex
	indexData *IndexData

	// rebuildMu serializes index rebuilds so concurrent callers (periodic
	// ticker + /api/reload) don't race on the shared file cache.
	rebuildMu sync.Mutex
	// fileCache is keyed by absolute file path; only touched inside rebuildIndex
	// (serialized by rebuildMu).
	fileCache        = make(map[string]*fileCacheEntry)
	checkovFileCache = make(map[string]*checkovCacheEntry)
	osvFileCache     = make(map[string]*osvCacheEntry)
	// cveIntern deduplicates CVE ID strings across files to limit memory use.
	cveIntern = make(map[string]string)
)

// walkJSONFiles recursively walks through directory and finds all JSON files
func walkJSONFiles(rootDir string) ([]string, error) {
	var jsonFiles []string
	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// Permission denied gibi hatalarda klasörü skip et ve devam et
			if os.IsPermission(err) {
				log.Printf("warning: skipping directory due to permission denied: %s", path)
				return filepath.SkipDir
			}
			// Diğer hatalar için de skip et (dosya silinmiş olabilir vs.)
			return nil
		}
		if !info.IsDir() && filepath.Ext(path) == ".json" {
			jsonFiles = append(jsonFiles, path)
		}
		return nil
	})
	return jsonFiles, err
}

type ScanSummary struct {
	Filename      string         `json:"filename"`
	Size          int64          `json:"size"`
	ModifiedAt    time.Time      `json:"modifiedAt"`
	ArtifactName  string         `json:"artifactName,omitempty"`
	ProjectName   string         `json:"projectName,omitempty"`
	ImageName     string         `json:"imageName,omitempty"`
	Tag           string         `json:"tag,omitempty"`
	TotalVulns    int            `json:"totalVulns"`
	SeverityCount map[string]int `json:"severityCount"`
	Grade         string         `json:"grade"`
}

type ProjectSummary struct {
	ProjectName   string         `json:"projectName"`
	TotalScans    int            `json:"totalScans"`
	TotalVulns    int            `json:"totalVulns"`
	SeverityCount map[string]int `json:"severityCount"`
	Images        []ImageSummary `json:"images"`
	LastScan      time.Time      `json:"lastScan"`
}

type ImageSummary struct {
	ImageName     string         `json:"imageName"`
	TotalVulns    int            `json:"totalVulns"`
	SeverityCount map[string]int `json:"severityCount"`
	Grade         string         `json:"grade"`
	LastScan      time.Time      `json:"lastScan"`
	ScanCount     int            `json:"scanCount"`
	Scans         []ScanSummary  `json:"scans,omitempty"` // All scans for this image
}

// Trivy JSON structures
type TrivyReport struct {
	SchemaVersion int      `json:"SchemaVersion"`
	ArtifactName  string   `json:"ArtifactName"`
	ArtifactType  string   `json:"ArtifactType"`
	Results       []Result `json:"Results"`
}

type Result struct {
	Target          string          `json:"Target"`
	Class           string          `json:"Class"`
	Type            string          `json:"Type"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
}

type Vulnerability struct {
	VulnerabilityID  string                 `json:"VulnerabilityID"`
	PkgName          string                 `json:"PkgName"`
	PkgPath          string                 `json:"PkgPath,omitempty"`
	InstalledVersion string                 `json:"InstalledVersion"`
	FixedVersion     string                 `json:"FixedVersion"`
	Severity         string                 `json:"Severity"`
	Title            string                 `json:"Title"`
	Description      string                 `json:"Description"`
	PrimaryURL       string                 `json:"PrimaryURL,omitempty"`
	PublishedDate    string                 `json:"PublishedDate,omitempty"`
	LastModifiedDate string                 `json:"LastModifiedDate,omitempty"`
	CVSS             map[string]interface{} `json:"CVSS,omitempty"`
}

// VulnDetail is the slimmed-down vulnerability shape returned by the scan
// detail endpoint — only the fields the dashboard actually renders.
type VulnDetail struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Severity         string `json:"Severity"`
	Title            string `json:"Title"`
	PrimaryURL       string `json:"PrimaryURL,omitempty"`
}

// Comparison structures
type ComparisonResult struct {
	Scan1    ScanComparisonInfo     `json:"scan1"`
	Scan2    ScanComparisonInfo     `json:"scan2"`
	Summary  ComparisonSummary      `json:"summary"`
	Added    []Vulnerability        `json:"added"`
	Removed  []Vulnerability        `json:"removed"`
	Changed  []ChangedVulnerability `json:"changed"`
}

type ScanComparisonInfo struct {
	Filename     string    `json:"filename"`
	ArtifactName string    `json:"artifactName"`
	TotalVulns   int       `json:"totalVulns"`
	ScanDate     time.Time `json:"scanDate"`
}

type ComparisonSummary struct {
	Added     int `json:"added"`
	Removed   int `json:"removed"`
	Changed   int `json:"changed"`
	Unchanged int `json:"unchanged"`
}

type ChangedVulnerability struct {
	VulnerabilityID  string                 `json:"VulnerabilityID"`
	PkgName          string                 `json:"PkgName"`
	InstalledVersion string                 `json:"InstalledVersion"`
	Changes          map[string]FieldChange `json:"changes"`
	Current          Vulnerability          `json:"current"`
}

type FieldChange struct {
	Old string `json:"old"`
	New string `json:"new"`
}

// CVE Search structures
type CVESearchResult struct {
	CVEID    string             `json:"cveId"`
	Projects []CVEProjectResult `json:"projects"`
}

type CVEProjectResult struct {
	ProjectName string           `json:"projectName"`
	Images      []CVEImageResult `json:"images"`
}

type CVEImageResult struct {
	ImageName  string      `json:"imageName"`
	Tag        string      `json:"tag,omitempty"`
	ScanCount  int         `json:"scanCount"`
	LatestScan ScanSummary `json:"latestScan"`
}

// Grades structures
type ImageGrade struct {
	ImageName     string         `json:"imageName"`
	Grade         string         `json:"grade"`
	TotalVulns    int            `json:"totalVulns"`
	SeverityCount map[string]int `json:"severityCount"`
	ScanCount     int            `json:"scanCount"`
	LastScanDate  time.Time      `json:"lastScanDate"`
	FirstScanDate time.Time      `json:"firstScanDate"`
}

type ProjectGrade struct {
	ProjectName string       `json:"projectName"`
	ImageCount  int          `json:"imageCount"`
	Grade       string       `json:"grade"`
	Images      []ImageGrade `json:"images"`
}

type GradesResponse struct {
	GeneratedAt time.Time      `json:"generatedAt"`
	Projects    []ProjectGrade `json:"projects"`
}

func main() {
	r := chi.NewRouter()

	// CORS configuration - support FQDN and environment overrides
	allowedOrigins := computeAllowedOrigins()

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   allowedOrigins,
		AllowedMethods:   []string{"GET", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		ExposedHeaders:   []string{"*"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	// Initialize export directory and build in-memory index once on startup.
	exportDir := os.Getenv("EXPORT_DIR")
	if exportDir == "" {
		exportDir = defaultExportDir
	}

	if err := rebuildIndex(exportDir); err != nil {
		log.Printf("warning: initial index rebuild failed: %v", err)
	}

	// Periodically rebuild index in the background to pick up new scan files.
	go func() {
		ticker := time.NewTicker(time.Duration(indexRebuildIntervalSec) * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if err := rebuildIndex(exportDir); err != nil {
				log.Printf("warning: periodic index rebuild failed: %v", err)
			}
		}
	}()

	// Periodically clean up old export files (every 24 hours).
	go func() {
		cleanupOldExports(exportDir)
		ticker := time.NewTicker(cleanupIntervalHours * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			cleanupOldExports(exportDir)
		}
	}()

	// Root info
	r.Get("/", handleRoot)

	// Simple health check
	r.Get("/health", handleHealth)

	// Force an immediate index rebuild (called by CI/CD after a scan completes)
	r.Post("/api/reload", func(w http.ResponseWriter, r *http.Request) {
		if err := rebuildIndex(exportDir); err != nil {
			http.Error(w, "index rebuild failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set(headerContentType, mimeApplicationJSON)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{"status":"ok","message":"index rebuilt"}`)
	})

	// List all scans with vulnerability summaries
	r.Get("/api/scans", func(w http.ResponseWriter, r *http.Request) {
		indexMu.RLock()
		current := indexData
		indexMu.RUnlock()

		if current == nil {
			http.Error(w, "index not ready", http.StatusServiceUnavailable)
			return
		}

		if notModified(w, r, current.etag) {
			return
		}

		w.Header().Set(headerContentType, mimeApplicationJSON)
		if err := json.NewEncoder(w).Encode(current.Scans); err != nil {
			http.Error(w, errEncodeResponse, http.StatusInternalServerError)
			return
		}
	})

	// List all projects with summaries
	r.Get("/api/projects", func(w http.ResponseWriter, r *http.Request) {
		indexMu.RLock()
		current := indexData
		indexMu.RUnlock()

		if current == nil {
			http.Error(w, "index not ready", http.StatusServiceUnavailable)
			return
		}

		if notModified(w, r, current.etag) {
			return
		}

		w.Header().Set(headerContentType, mimeApplicationJSON)
		if err := json.NewEncoder(w).Encode(current.Projects); err != nil {
			http.Error(w, errEncodeResponse, http.StatusInternalServerError)
			return
		}
	})

	// Get project details with all scans grouped by image
	r.Get("/api/projects/{projectName}", func(w http.ResponseWriter, r *http.Request) {
		projectName := chi.URLParam(r, "projectName")
		if projectName == "" {
			http.Error(w, "project name is required", http.StatusBadRequest)
			return
		}

		indexMu.RLock()
		current := indexData
		indexMu.RUnlock()

		if current == nil {
			http.Error(w, "index not ready", http.StatusServiceUnavailable)
			return
		}

		if notModified(w, r, current.etag) {
			return
		}

		for _, p := range current.Projects {
			if p.ProjectName == projectName {
				w.Header().Set(headerContentType, mimeApplicationJSON)
				if err := json.NewEncoder(w).Encode(p); err != nil {
					http.Error(w, errEncodeResponse, http.StatusInternalServerError)
				}
				return
			}
		}

		http.Error(w, "project not found", http.StatusNotFound)
	})

	// Get detailed vulnerability list for a specific scan
	// Use wildcard pattern to support subdirectories: /api/scans/*
	r.Get("/api/scans/*", func(w http.ResponseWriter, r *http.Request) {
		// Get the path after /api/scans/
		path := r.URL.Path
		prefix := "/api/scans/"
		if !strings.HasPrefix(path, prefix) {
			http.Error(w, "invalid path", http.StatusBadRequest)
			return
		}
		filename := strings.TrimPrefix(path, prefix)
		if filename == "" {
			http.Error(w, "filename is required", http.StatusBadRequest)
			return
		}

		// Security: prevent path traversal (but allow subdirectories)
		if strings.Contains(filename, "..") {
			http.Error(w, errInvalidFilename, http.StatusBadRequest)
			return
		}

		exportDir := os.Getenv("EXPORT_DIR")
		if exportDir == "" {
			exportDir = defaultExportDir
		}

		// Join path and clean it to prevent directory traversal
		filePath := filepath.Join(exportDir, filename)
		filePath = filepath.Clean(filePath)

		// Ensure the file is within exportDir
		if !strings.HasPrefix(filePath, filepath.Clean(exportDir)+string(os.PathSeparator)) && filePath != filepath.Clean(exportDir) {
			http.Error(w, errInvalidFilename, http.StatusBadRequest)
			return
		}

		report, err := parseTrivyJSON(filePath)
		if err != nil {
			http.Error(w, "failed to read or parse report: "+err.Error(), http.StatusNotFound)
			return
		}

		// Flatten all vulnerabilities, keeping only the fields the UI shows
		// (drops Description/CVSS etc. — the heavy part of large reports).
		var allVulns []VulnDetail
		for _, result := range report.Results {
			for _, vuln := range result.Vulnerabilities {
				allVulns = append(allVulns, VulnDetail{
					VulnerabilityID:  vuln.VulnerabilityID,
					PkgName:          vuln.PkgName,
					InstalledVersion: vuln.InstalledVersion,
					FixedVersion:     vuln.FixedVersion,
					Severity:         vuln.Severity,
					Title:            vuln.Title,
					PrimaryURL:       vuln.PrimaryURL,
				})
			}
		}

		// Sort by severity (most critical first) so a capped UI list shows
		// the important findings first.
		sort.SliceStable(allVulns, func(i, j int) bool {
			return severityRank(allVulns[i].Severity) < severityRank(allVulns[j].Severity)
		})

		w.Header().Set(headerContentType, mimeApplicationJSON)
		response := map[string]interface{}{
			"artifactName":    report.ArtifactName,
			"artifactType":    report.ArtifactType,
			"totalVulns":      len(allVulns),
			"vulnerabilities": allVulns,
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
			return
		}
	})

	// Get scan history for a specific image inside a project
	r.Get("/api/projects/{projectName}/images/{imageName}/scans", func(w http.ResponseWriter, r *http.Request) {
		projectName := chi.URLParam(r, "projectName")
		imageName := chi.URLParam(r, "imageName")

		if projectName == "" || imageName == "" {
			http.Error(w, "projectName and imageName are required", http.StatusBadRequest)
			return
		}

		indexMu.RLock()
		current := indexData
		indexMu.RUnlock()

		if current == nil {
			http.Error(w, "index not ready", http.StatusServiceUnavailable)
			return
		}

		// Served straight from the in-memory index (already sorted newest-first).
		scans := current.imageScans[projectName][imageName]
		if scans == nil {
			scans = []ScanSummary{}
		}

		w.Header().Set(headerContentType, mimeApplicationJSON)
		if err := json.NewEncoder(w).Encode(scans); err != nil {
			http.Error(w, errEncodeResponse, http.StatusInternalServerError)
			return
		}
	})

	// Compare two scans
	r.Get("/api/compare", func(w http.ResponseWriter, r *http.Request) {
		scan1Filename := r.URL.Query().Get("scan1")
		scan2Filename := r.URL.Query().Get("scan2")

		if scan1Filename == "" || scan2Filename == "" {
			http.Error(w, "scan1 and scan2 parameters are required", http.StatusBadRequest)
			return
		}

		exportDir := os.Getenv("EXPORT_DIR")
		if exportDir == "" {
			exportDir = defaultExportDir
		}

		// Security: prevent path traversal
		if strings.Contains(scan1Filename, "..") || strings.Contains(scan2Filename, "..") {
			http.Error(w, errInvalidFilename, http.StatusBadRequest)
			return
		}

		scan1Path := filepath.Join(exportDir, scan1Filename)
		scan2Path := filepath.Join(exportDir, scan2Filename)

		scan1Path = filepath.Clean(scan1Path)
		scan2Path = filepath.Clean(scan2Path)

		// Ensure files are within exportDir
		cleanExportDir := filepath.Clean(exportDir)
		if !strings.HasPrefix(scan1Path, cleanExportDir+string(os.PathSeparator)) && scan1Path != cleanExportDir {
			http.Error(w, errInvalidFilename, http.StatusBadRequest)
			return
		}
		if !strings.HasPrefix(scan2Path, cleanExportDir+string(os.PathSeparator)) && scan2Path != cleanExportDir {
			http.Error(w, errInvalidFilename, http.StatusBadRequest)
			return
		}

		comparison, err := compareScans(scan1Path, scan2Path, scan1Filename, scan2Filename)
		if err != nil {
			http.Error(w, "failed to compare scans: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set(headerContentType, mimeApplicationJSON)
		if err := json.NewEncoder(w).Encode(comparison); err != nil {
			http.Error(w, errEncodeResponse, http.StatusInternalServerError)
			return
		}
	})

	// Search for CVE across all projects and images
	r.Get("/api/cve/{cveId}", func(w http.ResponseWriter, r *http.Request) {
		cveId := chi.URLParam(r, "cveId")
		if cveId == "" {
			http.Error(w, "CVE ID is required", http.StatusBadRequest)
			return
		}

		indexMu.RLock()
		current := indexData
		indexMu.RUnlock()

		if current == nil {
			http.Error(w, "index not ready", http.StatusServiceUnavailable)
			return
		}

		if notModified(w, r, current.etag) {
			return
		}

		// Look the CVE up in the precomputed index and group the matching
		// scans by project -> image. No disk access.
		projectImageScans := make(map[string]map[string][]ScanSummary)
		for _, idx := range current.cveIndex[cveId] {
			if idx < 0 || idx >= len(current.Scans) {
				continue
			}
			s := current.Scans[idx]
			if s.ProjectName == "" || s.ImageName == "" {
				continue
			}
			if projectImageScans[s.ProjectName] == nil {
				projectImageScans[s.ProjectName] = make(map[string][]ScanSummary)
			}
			projectImageScans[s.ProjectName][s.ImageName] = append(projectImageScans[s.ProjectName][s.ImageName], s)
		}

		// Build response structure
		var projects []CVEProjectResult
		for projectName, images := range projectImageScans {
			var imageResults []CVEImageResult
			for imageName, scans := range images {
				// Sort scans by tag and date (newest first)
				sortScansByTagAndDate(scans)

				// Get latest scan
				var latestScan ScanSummary
				if len(scans) > 0 {
					latestScan = scans[0]
				}

				imageResults = append(imageResults, CVEImageResult{
					ImageName:  imageName,
					Tag:        latestScan.Tag,
					ScanCount:  len(scans),
					LatestScan: latestScan,
				})
			}

			// Sort images by latest scan date (newest first)
			for i := 0; i < len(imageResults)-1; i++ {
				for j := i + 1; j < len(imageResults); j++ {
					if imageResults[i].LatestScan.ModifiedAt.Before(imageResults[j].LatestScan.ModifiedAt) {
						imageResults[i], imageResults[j] = imageResults[j], imageResults[i]
					}
				}
			}

			projects = append(projects, CVEProjectResult{
				ProjectName: projectName,
				Images:      imageResults,
			})
		}

		// Sort projects alphabetically
		sort.Slice(projects, func(i, j int) bool {
			return projects[i].ProjectName < projects[j].ProjectName
		})

		result := CVESearchResult{
			CVEID:    cveId,
			Projects: projects,
		}

		w.Header().Set(headerContentType, mimeApplicationJSON)
		if err := json.NewEncoder(w).Encode(result); err != nil {
			http.Error(w, errEncodeResponse, http.StatusInternalServerError)
			return
		}
	})

	// Grade summary per project / image based on latest scan vulnerability counts
	r.Get("/api/grades", func(w http.ResponseWriter, r *http.Request) {
		projectFilter := r.URL.Query().Get("project")

		indexMu.RLock()
		current := indexData
		indexMu.RUnlock()

		if current == nil {
			http.Error(w, "index not ready", http.StatusServiceUnavailable)
			return
		}

		if notModified(w, r, current.etag) {
			return
		}

		var projectGrades []ProjectGrade

		for _, p := range current.Projects {
			if projectFilter != "" && p.ProjectName != projectFilter {
				continue
			}

			var imageGrades []ImageGrade
			for _, img := range p.Images {
				var firstScanDate time.Time
				if len(img.Scans) > 0 {
					firstScanDate = img.Scans[len(img.Scans)-1].ModifiedAt
				}

				imageGrades = append(imageGrades, ImageGrade{
					ImageName:     img.ImageName,
					Grade:         computeGrade(img.SeverityCount),
					TotalVulns:    img.TotalVulns,
					SeverityCount: img.SeverityCount,
					ScanCount:     img.ScanCount,
					LastScanDate:  img.LastScan,
					FirstScanDate: firstScanDate,
				})
			}

			sort.Slice(imageGrades, func(i, j int) bool {
				gi := gradeOrder(imageGrades[i].Grade)
				gj := gradeOrder(imageGrades[j].Grade)
				if gi != gj {
					return gi > gj
				}
				return imageGrades[i].ImageName < imageGrades[j].ImageName
			})

			worstGrade := "A"
			goodCount := 0
			for _, ig := range imageGrades {
				if gradeOrder(ig.Grade) > gradeOrder(worstGrade) {
					worstGrade = ig.Grade
				}
				if ig.Grade == "A" || ig.Grade == "B" {
					goodCount++
				}
			}

			// Çoğunluk imaj iyi (A/B) ise proje notunu bir kademe yumuşat.
			// Böylece tek sorunlu imaj tüm projeyi aşağı çekmez; sorunlu
			// imaj kendi notuyla listede görünmeye devam eder.
			projectGrade := worstGrade
			if goodCount > len(imageGrades)/2 {
				projectGrade = softenGrade(worstGrade)
			}

			projectGrades = append(projectGrades, ProjectGrade{
				ProjectName: p.ProjectName,
				ImageCount:  len(p.Images),
				Grade:       projectGrade,
				Images:      imageGrades,
			})
		}

		if projectFilter != "" && len(projectGrades) == 0 {
			http.Error(w, "project not found", http.StatusNotFound)
			return
		}

		sort.Slice(projectGrades, func(i, j int) bool {
			return projectGrades[i].ProjectName < projectGrades[j].ProjectName
		})

		resp := GradesResponse{
			GeneratedAt: current.GeneratedAt,
			Projects:    projectGrades,
		}

		w.Header().Set(headerContentType, mimeApplicationJSON)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, errEncodeResponse, http.StatusInternalServerError)
		}
	})

	// Checkov scan results
	r.Get("/api/checkov", func(w http.ResponseWriter, r *http.Request) {
		projectFilter := r.URL.Query().Get("project")

		indexMu.RLock()
		current := indexData
		indexMu.RUnlock()

		if current == nil {
			http.Error(w, "index not ready", http.StatusServiceUnavailable)
			return
		}

		result := current.CheckovScans
		if projectFilter != "" {
			var filtered []CheckovScanRecord
			for _, s := range result {
				if s.ProjectName == projectFilter {
					filtered = append(filtered, s)
				}
			}
			result = filtered
		}
		if result == nil {
			result = []CheckovScanRecord{}
		}

		w.Header().Set(headerContentType, mimeApplicationJSON)
		if err := json.NewEncoder(w).Encode(result); err != nil {
			http.Error(w, errEncodeResponse, http.StatusInternalServerError)
		}
	})

	// OSV-Scanner scan results
	r.Get("/api/osv", func(w http.ResponseWriter, r *http.Request) {
		projectFilter := r.URL.Query().Get("project")

		indexMu.RLock()
		current := indexData
		indexMu.RUnlock()

		if current == nil {
			http.Error(w, "index not ready", http.StatusServiceUnavailable)
			return
		}

		result := current.OsvScans
		if projectFilter != "" {
			var filtered []OsvScanRecord
			for _, s := range result {
				if s.ProjectName == projectFilter {
					filtered = append(filtered, s)
				}
			}
			result = filtered
		}
		if result == nil {
			result = []OsvScanRecord{}
		}

		w.Header().Set(headerContentType, mimeApplicationJSON)
		if err := json.NewEncoder(w).Encode(result); err != nil {
			http.Error(w, errEncodeResponse, http.StatusInternalServerError)
		}
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Backend listening on :%s\n", port)
	server := &http.Server{
		Addr:         ":" + port,
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

// sortScansByTagAndDate sorts scans in-place:
// - newer semantic version tags first (using compareVersionTags),
// - for same tag, newer ModifiedAt first,
// - scans without tag come after tagged ones.
func sortScansByTagAndDate(scans []ScanSummary) {
	sort.Slice(scans, func(i, j int) bool {
		tagI := scans[i].Tag
		tagJ := scans[j].Tag

		if tagI != "" && tagJ != "" {
			cmp := compareVersionTags(tagI, tagJ)
			if cmp < 0 {
				return false
			} else if cmp > 0 {
				return true
			}
			return scans[i].ModifiedAt.After(scans[j].ModifiedAt)
		} else if tagI == "" && tagJ == "" {
			return scans[i].ModifiedAt.After(scans[j].ModifiedAt)
		} else if tagI == "" {
			return false
		}
		return true
	})
}

// computeAllowedOrigins builds the CORS allowed origins list based on env vars.
func computeAllowedOrigins() []string {
	// Default for local development
	allowedOrigins := []string{
		"http://localhost:3000",
		"http://localhost:80",
		"http://localhost",
	}

	// ALLOWED_ORIGINS manuel olarak belirtilmişse onu kullan (en yüksek öncelik)
	if origin := os.Getenv("ALLOWED_ORIGINS"); origin != "" {
		origins := strings.Split(origin, ",")
		custom := make([]string, 0, len(origins))
		for _, o := range origins {
			o = strings.TrimSpace(o)
			if o != "" {
				custom = append(custom, o)
			}
		}
		if len(custom) > 0 {
			return custom
		}
	}

	// ALLOWED_ORIGINS yoksa FQDN'den otomatik türet (production)
	if fqdn := strings.TrimSpace(os.Getenv("FQDN")); fqdn != "" {
		viteBase := os.Getenv("VITE_API_BASE")
		if strings.HasPrefix(viteBase, "http://") {
			// HTTP ise (local test)
			return []string{"http://" + fqdn}
		}
		// HTTPS ise (production)
		return []string{"https://" + fqdn}
	}

	// ALLOWED_ORIGINS ve FQDN yoksa FRONTEND_PORT'tan otomatik oluştur (local development)
	if frontendPort := strings.TrimSpace(os.Getenv("FRONTEND_PORT")); frontendPort != "" {
		return []string{
			"http://localhost:" + frontendPort,
			"http://localhost",
		}
	}

	return allowedOrigins
}

type rootStrings struct {
	htmlLang    string
	subtitle    string
	thMethod    string
	thEndpoint  string
	thDesc      string
	health      string
	reload      string
	scans       string
	scanDetail  string
	projects    string
	projectDet  string
	imageScans  string
	grades      string
	compare     string
	cve         string
	checkov     string
	osv         string
}

var rootTR = rootStrings{
	htmlLang:   "tr",
	subtitle:   "Tüm endpoint'ler aşağıda listelenmiştir.",
	thMethod:   "Metod",
	thEndpoint: "Endpoint",
	thDesc:     "Açıklama",
	health:     "Backend sağlık kontrolü",
	reload:     "Export klasörünü yeniden tara, index'i güncelle",
	scans:      "Tüm Trivy tarama özetleri",
	scanDetail: "Belirli bir taramanın zafiyet detayları",
	projects:   "Tüm projelerin özet listesi",
	projectDet: "Projeye ait imaj ve tarama detayları",
	imageScans: "İmaja ait tarama geçmişi",
	grades:     "Proje/imaj bazlı güvenlik notu (A–F)",
	compare:    "İki taramayı karşılaştır",
	cve:        "CVE ID'ye göre hangi taramalarda geçtiğini göster",
	checkov:    "Checkov IaC tarama sonuçları",
	osv:        "OSV-Scanner bağımlılık zafiyet sonuçları",
}

var rootEN = rootStrings{
	htmlLang:   "en",
	subtitle:   "All endpoints are listed below.",
	thMethod:   "Method",
	thEndpoint: "Endpoint",
	thDesc:     "Description",
	health:     "Backend health check",
	reload:     "Rescan export directory and rebuild the index",
	scans:      "All Trivy scan summaries",
	scanDetail: "Vulnerability details for a specific scan",
	projects:   "Summary list of all projects",
	projectDet: "Images and scan details for a project",
	imageScans: "Scan history for a specific image",
	grades:     "Security grade per project/image (A–F)",
	compare:    "Compare two scans",
	cve:        "Show which scans contain a given CVE ID",
	checkov:    "Checkov IaC scan results",
	osv:        "OSV-Scanner dependency vulnerability results",
}

func detectLang(r *http.Request) string {
	if l := r.URL.Query().Get("lang"); l == "en" || l == "tr" {
		return l
	}
	accept := r.Header.Get("Accept-Language")
	if strings.HasPrefix(accept, "en") {
		return "en"
	}
	return "tr"
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	lang := detectLang(r)
	s := rootTR
	altLang := "en"
	altLabel := "EN"
	if lang == "en" {
		s = rootEN
		altLang = "tr"
		altLabel = "TR"
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="%s">
<head>
<meta charset="UTF-8">
<title>DockScan API</title>
<style>
  body { font-family: monospace; background: #1e1e2e; color: #cdd6f4; margin: 2rem; }
  h1   { color: #89b4fa; margin-bottom: 0.25rem; }
  p    { color: #6c7086; margin-top: 0; }
  table { border-collapse: collapse; width: 100%%; max-width: 800px; margin-top: 1.5rem; }
  th   { text-align: left; color: #a6adc8; font-size: 0.75rem; text-transform: uppercase;
         letter-spacing: 0.05em; padding: 0.4rem 0.75rem; border-bottom: 1px solid #313244; }
  td   { padding: 0.4rem 0.75rem; border-bottom: 1px solid #1e1e2e; font-size: 0.875rem; }
  tr:hover td { background: #313244; }
  a    { color: #89dceb; text-decoration: none; }
  a:hover { text-decoration: underline; }
  .badge { display: inline-block; padding: 0.1rem 0.4rem; border-radius: 0.25rem;
           font-size: 0.7rem; margin-right: 0.5rem; }
  .bg-get  { background: #a6e3a1; color: #1e1e2e; }
  .bg-post { background: #fab387; color: #1e1e2e; }
  .lang-toggle { float: right; display: flex; gap: 0.4rem; margin-top: 0.2rem; }
  .lang-btn { padding: 0.2rem 0.6rem; border-radius: 0.25rem; font-size: 0.75rem;
              border: 1px solid #313244; background: #313244; color: #cdd6f4;
              cursor: pointer; text-decoration: none; }
  .lang-btn.active { background: #89b4fa; color: #1e1e2e; border-color: #89b4fa; }
</style>
</head>
<body>
<div class="lang-toggle">
  <a class="lang-btn%s" href="/?lang=tr">TR</a>
  <a class="lang-btn%s" href="/?lang=en">EN</a>
</div>
<h1>DockScan Backend API</h1>
<p>%s</p>
<table>
  <thead>
    <tr><th>%s</th><th>%s</th><th>%s</th></tr>
  </thead>
  <tbody>
    <tr>
      <td><span class="badge bg-get">GET</span></td>
      <td><a href="/health">/health</a></td>
      <td>%s</td>
    </tr>
    <tr>
      <td><span class="badge bg-post">POST</span></td>
      <td>/api/reload</td>
      <td>%s</td>
    </tr>
    <tr>
      <td><span class="badge bg-get">GET</span></td>
      <td><a href="/api/scans">/api/scans</a></td>
      <td>%s</td>
    </tr>
    <tr>
      <td><span class="badge bg-get">GET</span></td>
      <td>/api/scans/{path}</td>
      <td>%s</td>
    </tr>
    <tr>
      <td><span class="badge bg-get">GET</span></td>
      <td><a href="/api/projects">/api/projects</a></td>
      <td>%s</td>
    </tr>
    <tr>
      <td><span class="badge bg-get">GET</span></td>
      <td>/api/projects/{project}</td>
      <td>%s</td>
    </tr>
    <tr>
      <td><span class="badge bg-get">GET</span></td>
      <td>/api/projects/{project}/images/{image}/scans</td>
      <td>%s</td>
    </tr>
    <tr>
      <td><span class="badge bg-get">GET</span></td>
      <td><a href="/api/grades">/api/grades</a></td>
      <td>%s &nbsp;<code>?project=</code></td>
    </tr>
    <tr>
      <td><span class="badge bg-get">GET</span></td>
      <td>/api/compare</td>
      <td>%s &nbsp;<code>?scan1=&amp;scan2=</code></td>
    </tr>
    <tr>
      <td><span class="badge bg-get">GET</span></td>
      <td>/api/cve/{cveId}</td>
      <td>%s</td>
    </tr>
    <tr>
      <td><span class="badge bg-get">GET</span></td>
      <td><a href="/api/checkov">/api/checkov</a></td>
      <td>%s &nbsp;<code>?project=</code></td>
    </tr>
    <tr>
      <td><span class="badge bg-get">GET</span></td>
      <td><a href="/api/osv">/api/osv</a></td>
      <td>%s &nbsp;<code>?project=</code></td>
    </tr>
  </tbody>
</table>
</body>
</html>`,
		s.htmlLang,
		trActiveClass(lang == "tr"), trActiveClass(lang == "en"),
		s.subtitle,
		s.thMethod, s.thEndpoint, s.thDesc,
		s.health,
		s.reload,
		s.scans,
		s.scanDetail,
		s.projects,
		s.projectDet,
		s.imageScans,
		s.grades,
		s.compare,
		s.cve,
		s.checkov,
		s.osv,
	)
	_ = altLang
	_ = altLabel
}

func trActiveClass(active bool) string {
	if active {
		return " active"
	}
	return ""
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(headerContentType, mimeApplicationJSON)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// notModified sets the ETag from the current index and, when the client's
// If-None-Match already matches, writes 304 Not Modified and returns true.
// This lets the browser reuse its cached copy when scan data is unchanged.
func notModified(w http.ResponseWriter, r *http.Request, etag string) bool {
	if etag == "" {
		return false
	}
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-cache") // revalidate, but allow 304
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return true
	}
	return false
}

func parseTrivyJSON(filePath string) (*TrivyReport, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	var report TrivyReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, err
	}

	return &report, nil
}

// getVulnKey creates a unique key for a vulnerability
func getVulnKey(vuln Vulnerability) string {
	return fmt.Sprintf("%s|%s|%s", vuln.VulnerabilityID, vuln.PkgName, vuln.InstalledVersion)
}

// hasChanges checks if two vulnerabilities have differences
func hasChanges(v1, v2 Vulnerability) bool {
	return v1.Severity != v2.Severity ||
		v1.FixedVersion != v2.FixedVersion ||
		v1.Title != v2.Title ||
		v1.Description != v2.Description
}

// createChangedVuln creates a ChangedVulnerability from two vulnerabilities
func createChangedVuln(oldVuln, newVuln Vulnerability) ChangedVulnerability {
	changes := make(map[string]FieldChange)

	if oldVuln.Severity != newVuln.Severity {
		changes["severity"] = FieldChange{
			Old: oldVuln.Severity,
			New: newVuln.Severity,
		}
	}

	if oldVuln.FixedVersion != newVuln.FixedVersion {
		changes["fixedVersion"] = FieldChange{
			Old: oldVuln.FixedVersion,
			New: newVuln.FixedVersion,
		}
	}

	if oldVuln.Title != newVuln.Title {
		changes["title"] = FieldChange{
			Old: oldVuln.Title,
			New: newVuln.Title,
		}
	}

	if oldVuln.Description != newVuln.Description {
		changes["description"] = FieldChange{
			Old: oldVuln.Description,
			New: newVuln.Description,
		}
	}

	return ChangedVulnerability{
		VulnerabilityID:  newVuln.VulnerabilityID,
		PkgName:          newVuln.PkgName,
		InstalledVersion: newVuln.InstalledVersion,
		Changes:          changes,
		Current:          newVuln,
	}
}

// compareScans compares two scan files and returns comparison results
func compareScans(scan1Path, scan2Path, scan1Filename, scan2Filename string) (ComparisonResult, error) {
	report1, err := parseTrivyJSON(scan1Path)
	if err != nil {
		return ComparisonResult{}, err
	}

	report2, err := parseTrivyJSON(scan2Path)
	if err != nil {
		return ComparisonResult{}, err
	}

	// Get scan dates
	info1, err := os.Stat(scan1Path)
	var scanDate1 time.Time
	if err == nil {
		scanDate1 = extractTimestampFromPath(filepath.Base(scan1Filename), info1.ModTime())
	}

	info2, err := os.Stat(scan2Path)
	var scanDate2 time.Time
	if err == nil {
		scanDate2 = extractTimestampFromPath(filepath.Base(scan2Filename), info2.ModTime())
	}

	// Build vulnerability maps
	vulns1 := make(map[string]Vulnerability)
	vulns2 := make(map[string]Vulnerability)

	for _, result := range report1.Results {
		for _, vuln := range result.Vulnerabilities {
			key := getVulnKey(vuln)
			vulns1[key] = vuln
		}
	}

	for _, result := range report2.Results {
		for _, vuln := range result.Vulnerabilities {
			key := getVulnKey(vuln)
			vulns2[key] = vuln
		}
	}

	// Compare
	var added []Vulnerability
	var removed []Vulnerability
	var changed []ChangedVulnerability
	var unchanged []Vulnerability

	// Find added (in scan2 but not in scan1)
	for key, vuln := range vulns2 {
		if _, exists := vulns1[key]; !exists {
			added = append(added, vuln)
		}
	}

	// Find removed (in scan1 but not in scan2)
	for key, vuln := range vulns1 {
		if _, exists := vulns2[key]; !exists {
			removed = append(removed, vuln)
		}
	}

	// Find changed and unchanged (in both)
	for key, vuln1 := range vulns1 {
		if vuln2, exists := vulns2[key]; exists {
			if hasChanges(vuln1, vuln2) {
				changed = append(changed, createChangedVuln(vuln1, vuln2))
			} else {
				unchanged = append(unchanged, vuln2)
			}
		}
	}

	return ComparisonResult{
		Scan1: ScanComparisonInfo{
			Filename:     scan1Filename,
			ArtifactName: report1.ArtifactName,
			TotalVulns:   len(vulns1),
			ScanDate:     scanDate1,
		},
		Scan2: ScanComparisonInfo{
			Filename:     scan2Filename,
			ArtifactName: report2.ArtifactName,
			TotalVulns:   len(vulns2),
			ScanDate:     scanDate2,
		},
		Summary: ComparisonSummary{
			Added:     len(added),
			Removed:   len(removed),
			Changed:   len(changed),
			Unchanged: len(unchanged),
		},
		Added:   added,
		Removed: removed,
		Changed: changed,
	}, nil
}

// extractProjectAndImageFromPath extracts project and image name from file path
// Supports multiple formats:
// 1. {project-name}-{image-name}.json (flat structure)
// 2. {project-name}-{image-name}-{timestamp}.json (flat with timestamp)
// 3. {project-name}/{image-name}.json (directory structure)
// 4. {project-name}/{image-name}-{timestamp}.json (directory with timestamp)
// Example: "dockscan-backend.json" -> project: "dockscan", image: "backend"
// Example: "dockscan/backend.json" -> project: "dockscan", image: "backend"
func extractProjectAndImageFromPath(relPath, exportDir string) (projectName, imageName string) {
	// Normalize path separators
	relPath = filepath.ToSlash(relPath)

	// Remove .json extension
	basePath := strings.TrimSuffix(relPath, ".json")
	if basePath == "" {
		return "", ""
	}

	// Check if path contains directory separator (directory structure)
	dir, fileName := filepath.Split(basePath)
	if dir != "" {
		// Directory structure: {project-name}/{image-name} or {project-name}/{image-name}-{timestamp}
		// Also supports: {project-name}/tags/{tag-name} or {project-name}/manifests/{tag-name}
		dir = strings.TrimSuffix(dir, "/")
		dir = strings.TrimSuffix(dir, string(os.PathSeparator))

		// Split directory path to handle nested structures like "odenek-talep/tags"
		pathParts := strings.Split(dir, "/")

		// If the last part is "tags" or "manifests", skip it and use the parent as project name
		// Example: "odenek-talep/tags" -> project: "odenek-talep"
		if len(pathParts) > 1 && (pathParts[len(pathParts)-1] == "tags" || pathParts[len(pathParts)-1] == "manifests") {
			projectName = strings.Join(pathParts[:len(pathParts)-1], "/")
		} else {
			projectName = dir
		}

		// Remove timestamp from filename if present
		imageName = removeTimestampFromFilename(fileName)
		return projectName, imageName
	}

	// Flat structure: {project-name}-{image-name} or {project-name}-{image-name}-{timestamp}
	baseName := fileName

	// Remove timestamp if present
	baseName = removeTimestampFromFilename(baseName)

	// Find last dash to split project and image
	lastDash := strings.LastIndex(baseName, "-")
	if lastDash == -1 || lastDash == 0 || lastDash == len(baseName)-1 {
		// No dash found, or dash at start/end - treat whole name as project
		return baseName, ""
	}

	projectName = baseName[:lastDash]
	imageName = baseName[lastDash+1:]

	return projectName, imageName
}

// removeTimestampFromFilename removes timestamp pattern from filename
// Pattern: -YYYYMMDD-HHMMSS (16 characters)
func removeTimestampFromFilename(filename string) string {
	if tsStr, ok := extractTimestampSuffix(filename); ok {
		// tsStr includes the leading dash and timestamp: "-YYYYMMDD-HHMMSS" (16 chars)
		return filename[:len(filename)-len(tsStr)]
	}
	return filename
}

// extractTimestampFromPath tries to read timestamp from filename and convert it to time.Time.
// If no valid timestamp pattern exists, it falls back to the provided defaultTime (usually file ModTime).
func extractTimestampFromPath(relPath string, defaultTime time.Time) time.Time {
	// Normalize and strip extension
	relPath = filepath.ToSlash(relPath)
	basePath := strings.TrimSuffix(relPath, ".json")
	if basePath == "" {
		return defaultTime
	}

	_, fileName := filepath.Split(basePath)

	// Timestamp pattern: -YYYYMMDD-HHMMSS (16 chars)
	if tsStr, ok := extractTimestampSuffix(fileName); ok {
		// tsStr is "-YYYYMMDD-HHMMSS" without validation error
		// Skip leading dash when parsing
		if t, err := time.ParseInLocation("20060102-150405", tsStr[1:], time.Local); err == nil {
			return t
		}
	}

	return defaultTime
}

// extractTimestampSuffix validates and extracts the timestamp suffix from a filename.
// It returns the suffix including the leading dash (e.g. "-20251130-151752") and true if valid.
func extractTimestampSuffix(name string) (string, bool) {
	if len(name) <= 16 {
		return "", false
	}
	lastPart := name[len(name)-16:]
	if len(lastPart) != 16 || lastPart[0] != '-' || strings.Count(lastPart, "-") != 2 {
		return "", false
	}
	parts := strings.Split(lastPart[1:], "-") // Skip first dash
	if len(parts) != 2 || len(parts[0]) != 8 || len(parts[1]) != 6 {
		return "", false
	}
	// Validate that parts are numeric
	for _, part := range parts {
		for _, r := range part {
			if r < '0' || r > '9' {
				return "", false
			}
		}
	}
	return lastPart, true
}

// compareVersionTags compares two version tags (e.g., "6.7.1" vs "6.6.2")
// Returns: -1 if tag1 < tag2, 0 if equal, 1 if tag1 > tag2
// Handles semantic versioning properly by comparing numeric parts
func compareVersionTags(tag1, tag2 string) int {
	if tag1 == tag2 {
		return 0
	}
	if tag1 == "" {
		return -1 // Empty tag is considered older
	}
	if tag2 == "" {
		return 1 // Empty tag is considered older
	}

	// Remove "v" prefix if present
	tag1 = strings.TrimPrefix(tag1, "v")
	tag2 = strings.TrimPrefix(tag2, "v")

	// Split by dots to compare numeric parts
	parts1 := strings.Split(tag1, ".")
	parts2 := strings.Split(tag2, ".")

	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	// Compare each part numerically
	for i := 0; i < maxLen; i++ {
		var num1, num2 int64
		var err1, err2 error

		if i < len(parts1) {
			// Try to parse as number, if fails treat as string
			num1, err1 = strconv.ParseInt(parts1[i], 10, 64)
		}
		if i < len(parts2) {
			num2, err2 = strconv.ParseInt(parts2[i], 10, 64)
		}

		// Both are numbers
		if err1 == nil && err2 == nil {
			if num1 < num2 {
				return -1
			} else if num1 > num2 {
				return 1
			}
		} else {
			// At least one is not a number, do string comparison
			str1 := ""
			str2 := ""
			if i < len(parts1) {
				str1 = parts1[i]
			}
			if i < len(parts2) {
				str2 = parts2[i]
			}
			if str1 < str2 {
				return -1
			} else if str1 > str2 {
				return 1
			}
		}
	}

	return 0
}

// extractProjectImageTagFromArtifactName extracts project, image, and tag from ArtifactName
// Format: {project-name}_{image-name}:{tag}
// Example: "dockscan_backend:latest" -> project: "dockscan", image: "backend", tag: "latest"
// Example: "my-service_api:v1.0.0" -> project: "my-service", image: "api", tag: "v1.0.0"
// Returns empty strings if parsing fails
func extractProjectImageTagFromArtifactName(artifactName string) (projectName, imageName, tag string) {
	if artifactName == "" {
		return "", "", ""
	}

	// Split by colon to get tag.
	// ArtifactName genelde şu formatlarda gelir:
	//  - "dockscan_backend:latest"
	//  - "yournexushost:8090/repository/my-repo/myapp_frontend:test-v1.0"
	// Bizim için önemli olan kısım, registry ve path'ten sonraki image adı ve tag'dir.
	parts := strings.Split(artifactName, ":")
	var namePart string
	if len(parts) == 2 {
		namePart = parts[0]
		tag = parts[1]
	} else if len(parts) == 1 {
		namePart = parts[0]
		tag = "" // No tag specified
	} else {
		// Multiple colons? Use last one as tag
		lastColon := strings.LastIndex(artifactName, ":")
		if lastColon > 0 && lastColon < len(artifactName)-1 {
			namePart = artifactName[:lastColon]
			tag = artifactName[lastColon+1:]
		} else {
			return "", "", ""
		}
	}

	// Registry formatlarında (örn: "yournexushost:8090/repository/my-repo/myapp_frontend")
	// ArtifactName, tam image path'ini içerir. Bizim için önemli olan son segmenttir.
	if strings.Contains(namePart, "/") {
		parts := strings.Split(namePart, "/")
		namePart = parts[len(parts)-1]
	}

	// Önce projeyi ve imajı ayırmak için öncelikli olarak alt çizgi (_) kullan.
	// Örnek:
	//   "hafizlik-takip_backend"  -> project: "hafizlik-takip", image: "backend"
	//   "myapp_frontend"          -> project: "myapp",          image: "frontend"
	underscore := strings.LastIndex(namePart, "_")
	if underscore > 0 && underscore < len(namePart)-1 {
		projectName = namePart[:underscore]
		imageName = namePart[underscore+1:]
		return projectName, imageName, tag
	}

	// Alt çizgi yoksa, bazı yaygın suffix'lere göre bölmeye çalış.
	// Örnekler:
	//   "superapp-backend"       -> project: "superapp", image: "backend"
	//   "superapp-backend-api"   -> project: "superapp", image: "backend-api"
	//   "superapp-auth"          -> project: "superapp", image: "auth"
	commonSuffixes := []string{
		"backend",
		"frontend",
		"backend-api",
		"backend-auth",
		"api",
		"auth",
		"mikrotalk",
	}
	for _, suf := range commonSuffixes {
		suffix := "-" + suf
		if strings.HasSuffix(namePart, suffix) && len(namePart) > len(suffix) {
			projectName = strings.TrimSuffix(namePart, suffix)
			imageName = suf
			return projectName, imageName, tag
		}
	}

	// Hiçbir özel kural uymuyorsa, tek imajlı monolith projeler olarak ele al.
	// Örnekler:
	//   "goruntulu-fetvalar" -> project: "goruntulu-fetvalar", image: "goruntulu-fetvalar"
	//   "ajanda"            -> project: "ajanda",             image: "ajanda"
	lastDash := strings.LastIndex(namePart, "-")
	if lastDash == -1 || lastDash == 0 || lastDash == len(namePart)-1 {
		return namePart, namePart, tag
	}

	return namePart, namePart, tag
}

// extractProjectAndImage is kept for backward compatibility
// It now calls extractProjectAndImageFromPath with empty exportDir
func extractProjectAndImage(filename string) (projectName, imageName string) {
	return extractProjectAndImageFromPath(filename, "")
}

// internCVE deduplicates CVE ID strings so the same ID appearing in many files
// shares a single backing string. Only called from rebuildIndex (serialized).
func internCVE(id string) string {
	if s, ok := cveIntern[id]; ok {
		return s
	}
	cveIntern[id] = id
	return id
}

// parseScanFile reads and summarizes a single Trivy JSON scan file.
// It returns the per-file ScanSummary and the unique CVE IDs it contains.
func parseScanFile(filePath, relPath, exportDir string, info os.FileInfo) (ScanSummary, []string) {
	scanTime := extractTimestampFromPath(relPath, info.ModTime())

	summary := ScanSummary{
		Filename:      relPath,
		Size:          info.Size(),
		ModifiedAt:    scanTime,
		SeverityCount: make(map[string]int),
	}

	var projectName, imageName, tag string
	var cveIDs []string
	if report, err := parseTrivyJSON(filePath); err == nil {
		summary.ArtifactName = report.ArtifactName

		projectName, imageName, tag = extractProjectImageTagFromArtifactName(report.ArtifactName)
		summary.Tag = tag

		seen := make(map[string]struct{})
		total := 0
		for _, result := range report.Results {
			for _, vuln := range result.Vulnerabilities {
				total++
				severity := strings.ToUpper(vuln.Severity)
				if severity == "" {
					severity = "UNKNOWN"
				}
				summary.SeverityCount[severity]++
				if id := vuln.VulnerabilityID; id != "" {
					if _, ok := seen[id]; !ok {
						seen[id] = struct{}{}
						cveIDs = append(cveIDs, internCVE(id))
					}
				}
			}
		}
		summary.TotalVulns = total
		summary.Grade = computeGrade(summary.SeverityCount)
	}

	// Fallback to filename parsing if ArtifactName parsing failed
	if projectName != "" && imageName == "" {
		projectName, imageName = extractProjectAndImageFromPath(relPath, exportDir)
	} else if projectName == "" {
		projectName, imageName = extractProjectAndImageFromPath(relPath, exportDir)
	}

	summary.ProjectName = projectName
	summary.ImageName = imageName
	return summary, cveIDs
}

func rebuildIndex(exportDir string) error {
	// Serialize rebuilds so concurrent callers don't race on fileCache.
	rebuildMu.Lock()
	defer rebuildMu.Unlock()

	jsonFiles, err := walkJSONFiles(exportDir)
	if err != nil {
		return fmt.Errorf("%s: %w", errReadExportDirectory, err)
	}

	scans := make([]ScanSummary, 0, len(jsonFiles))
	// scanCVEs[i] holds the CVE IDs of scans[i] (kept aligned).
	scanCVEs := make([][]string, 0, len(jsonFiles))
	checkovScans := make([]CheckovScanRecord, 0)
	osvScans := make([]OsvScanRecord, 0)

	seenPaths := make(map[string]struct{}, len(jsonFiles))
	parsed, reused := 0, 0
	// fingerprint is a content-stable hash of the file set (path + modTime +
	// size). It stays constant across rebuilds when nothing changed, so the
	// ETag — and thus browser 304 caching — survives the periodic rebuild.
	var fingerprint uint64

	for _, filePath := range jsonFiles {
		info, err := os.Stat(filePath)
		if err != nil || info.IsDir() {
			continue
		}
		seenPaths[filePath] = struct{}{}

		relPath, err := filepath.Rel(exportDir, filePath)
		if err != nil {
			continue
		}

		h := fnv.New64a()
		fmt.Fprintf(h, "%s|%d|%d", relPath, info.ModTime().UnixNano(), info.Size())
		fingerprint ^= h.Sum64()

		base := filepath.Base(filePath)

		if strings.HasPrefix(base, "checkov-") {
			if c, ok := checkovFileCache[filePath]; ok && c.modTime.Equal(info.ModTime()) && c.size == info.Size() {
				checkovScans = append(checkovScans, c.record)
				reused++
				continue
			}
			record, err := parseCheckovFile(filePath, info, relPath)
			if err != nil {
				log.Printf("warning: failed to parse checkov file %s: %v", relPath, err)
				continue
			}
			checkovFileCache[filePath] = &checkovCacheEntry{modTime: info.ModTime(), size: info.Size(), record: record}
			checkovScans = append(checkovScans, record)
			parsed++
			continue
		}

		if strings.HasPrefix(base, "osv-") {
			if c, ok := osvFileCache[filePath]; ok && c.modTime.Equal(info.ModTime()) && c.size == info.Size() {
				osvScans = append(osvScans, c.record)
				reused++
				continue
			}
			record, err := parseOsvFile(filePath, info, relPath)
			if err != nil {
				log.Printf("warning: failed to parse osv file %s: %v", relPath, err)
				continue
			}
			osvFileCache[filePath] = &osvCacheEntry{modTime: info.ModTime(), size: info.Size(), record: record}
			osvScans = append(osvScans, record)
			parsed++
			continue
		}

		// Trivy file — existing logic.
		if c, ok := fileCache[filePath]; ok && c.modTime.Equal(info.ModTime()) && c.size == info.Size() {
			scans = append(scans, c.summary)
			scanCVEs = append(scanCVEs, c.cveIDs)
			reused++
			continue
		}

		summary, cveIDs := parseScanFile(filePath, relPath, exportDir, info)
		fileCache[filePath] = &fileCacheEntry{
			modTime: info.ModTime(),
			size:    info.Size(),
			summary: summary,
			cveIDs:  cveIDs,
		}
		scans = append(scans, summary)
		scanCVEs = append(scanCVEs, cveIDs)
		parsed++
	}

	// Forget cache entries for files that no longer exist (e.g. cleaned up).
	for path := range fileCache {
		if _, ok := seenPaths[path]; !ok {
			delete(fileCache, path)
		}
	}
	for path := range checkovFileCache {
		if _, ok := seenPaths[path]; !ok {
			delete(checkovFileCache, path)
		}
	}
	for path := range osvFileCache {
		if _, ok := seenPaths[path]; !ok {
			delete(osvFileCache, path)
		}
	}

	// Build project summaries from scans
	projectsMap := make(map[string]*ProjectSummary)
	imagesMap := make(map[string]map[string]*ImageSummary)

	for _, scanSummary := range scans {
		projectName := scanSummary.ProjectName
		imageName := scanSummary.ImageName
		if projectName == "" || imageName == "" {
			continue
		}

		if projectsMap[projectName] == nil {
			projectsMap[projectName] = &ProjectSummary{
				ProjectName:   projectName,
				SeverityCount: make(map[string]int),
				Images:        []ImageSummary{},
			}
			imagesMap[projectName] = make(map[string]*ImageSummary)
		}

		project := projectsMap[projectName]
		project.TotalScans++

		if imagesMap[projectName][imageName] == nil {
			imagesMap[projectName][imageName] = &ImageSummary{
				ImageName:     imageName,
				SeverityCount: make(map[string]int),
				Scans:         []ScanSummary{},
			}
		}

		imageSummary := imagesMap[projectName][imageName]
		imageSummary.Scans = append(imageSummary.Scans, scanSummary)
	}

	// imageScans: projectName -> imageName -> sorted scan history (for the
	// image scan-history endpoint, served straight from memory).
	imageScans := make(map[string]map[string][]ScanSummary, len(projectsMap))

	var projects []ProjectSummary
	for projectName, project := range projectsMap {
		project.TotalVulns = 0
		project.SeverityCount = make(map[string]int)
		imageScans[projectName] = make(map[string][]ScanSummary, len(imagesMap[projectName]))

		for imageName, imageSummary := range imagesMap[projectName] {
			imgScans := imageSummary.Scans
			sortScansByTagAndDate(imgScans)

			imageSummary.ScanCount = len(imgScans)

			if len(imgScans) > 0 {
				latestScan := imgScans[0]
				imageSummary.LastScan = latestScan.ModifiedAt
				imageSummary.TotalVulns = latestScan.TotalVulns
				imageSummary.SeverityCount = make(map[string]int)
				for k, v := range latestScan.SeverityCount {
					imageSummary.SeverityCount[k] = v
				}
				imageSummary.Grade = computeGrade(imageSummary.SeverityCount)
			}

			project.TotalVulns += imageSummary.TotalVulns
			for severity, count := range imageSummary.SeverityCount {
				project.SeverityCount[severity] += count
			}

			imageScans[projectName][imageName] = imgScans
			project.Images = append(project.Images, *imageSummary)

			if imageSummary.LastScan.After(project.LastScan) {
				project.LastScan = imageSummary.LastScan
			}
		}

		// Sort images by last scan date (newest first)
		for i := 0; i < len(project.Images)-1; i++ {
			for j := i + 1; j < len(project.Images); j++ {
				if project.Images[i].LastScan.Before(project.Images[j].LastScan) {
					project.Images[i], project.Images[j] = project.Images[j], project.Images[i]
				}
			}
		}

		projects = append(projects, *project)
	}

	// Build CVE index: cveID -> indices into scans.
	cveIndex := make(map[string][]int)
	for i, ids := range scanCVEs {
		for _, id := range ids {
			cveIndex[id] = append(cveIndex[id], i)
		}
	}

	generatedAt := time.Now()
	newIndex := &IndexData{
		Scans:        scans,
		Projects:     projects,
		CheckovScans: checkovScans,
		OsvScans:     osvScans,
		GeneratedAt:  generatedAt,
		cveIndex:     cveIndex,
		imageScans:   imageScans,
		etag:         fmt.Sprintf(`"%x-%d"`, fingerprint, len(scans)),
	}

	indexMu.Lock()
	indexData = newIndex
	indexMu.Unlock()

	log.Printf("index rebuilt: %d trivy, %d checkov, %d osv, %d projects (%d parsed, %d cached)",
		len(scans), len(checkovScans), len(osvScans), len(projects), parsed, reused)
	return nil
}

// computeGrade returns a letter grade based on CRITICAL, HIGH and MEDIUM vulnerability counts.
// A: CRITICAL=0, HIGH≤2,  MEDIUM≤5
// B: CRITICAL=0, HIGH≤5,  MEDIUM≤10
// C: CRITICAL≤2, HIGH≤8,  MEDIUM≤15
// D: CRITICAL≤9  (fails C thresholds)
// F: CRITICAL≥10
func computeGrade(severityCount map[string]int) string {
	critical := severityCount["CRITICAL"]
	high := severityCount["HIGH"]
	medium := severityCount["MEDIUM"]
	switch {
	case critical == 0 && high <= 2 && medium <= 5:
		return "A"
	case critical == 0 && high <= 5 && medium <= 10:
		return "B"
	case critical <= 2 && high <= 8 && medium <= 15:
		return "C"
	case critical <= 9:
		return "D"
	default:
		return "F"
	}
}

// exportFile pairs a scan file path with its modification time.
type exportFile struct {
	path    string
	modTime time.Time
}

// collectJSONFiles returns the .json scan files directly under projectDir,
// each with its modification time.
func collectJSONFiles(projectDir string, dirEntries []os.DirEntry) []exportFile {
	var files []exportFile
	for _, de := range dirEntries {
		if de.IsDir() || filepath.Ext(de.Name()) != ".json" {
			continue
		}
		info, err := de.Info()
		if err != nil {
			continue
		}
		files = append(files, exportFile{
			path:    filepath.Join(projectDir, de.Name()),
			modTime: info.ModTime(),
		})
	}
	return files
}

// newestFile returns the file with the most recent modification time.
// files must be non-empty.
func newestFile(files []exportFile) exportFile {
	newest := files[0]
	for _, f := range files[1:] {
		if f.modTime.After(newest.modTime) {
			newest = f
		}
	}
	return newest
}

// cleanupProjectDir removes JSON scan files older than cutoff from projectDir,
// always keeping the newest file. It returns the number of files deleted and kept.
func cleanupProjectDir(projectDir string, cutoff time.Time) (deleted, kept int) {
	dirEntries, err := os.ReadDir(projectDir)
	if err != nil {
		return 0, 0
	}

	files := collectJSONFiles(projectDir, dirEntries)
	if len(files) == 0 {
		return 0, 0
	}

	newest := newestFile(files)
	for _, f := range files {
		if f.path == newest.path || !f.modTime.Before(cutoff) {
			kept++
			continue
		}
		if err := os.Remove(f.path); err != nil {
			log.Printf("cleanup: failed to remove %s: %v", f.path, err)
			kept++
			continue
		}
		log.Printf("cleanup: removed %s", f.path)
		deleted++
	}
	return deleted, kept
}

// cleanupOldExports removes scan files older than cleanupRetentionDays from each project
// subdirectory under exportDir. At least one file (the newest) is always kept per directory,
// regardless of its age.
func cleanupOldExports(exportDir string) {
	cutoff := time.Now().AddDate(0, 0, -cleanupRetentionDays)

	entries, err := os.ReadDir(exportDir)
	if err != nil {
		log.Printf("cleanup: failed to read export dir: %v", err)
		return
	}

	deleted := 0
	kept := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		d, k := cleanupProjectDir(filepath.Join(exportDir, entry.Name()), cutoff)
		deleted += d
		kept += k
	}

	log.Printf("cleanup: done — %d removed, %d kept", deleted, kept)
}

// softenGrade returns the grade one tier better (less severe). A stays A.
// F->D->C->B->A. Used to relax a project grade when most images are healthy.
func softenGrade(grade string) string {
	switch grade {
	case "F":
		return "D"
	case "D":
		return "C"
	case "C":
		return "B"
	case "B":
		return "A"
	default:
		return "A"
	}
}

// severityRank orders severities most-critical-first for sorting.
func severityRank(severity string) int {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return 0
	case "HIGH":
		return 1
	case "MEDIUM":
		return 2
	case "LOW":
		return 3
	default:
		return 4
	}
}

// gradeOrder maps a letter grade to a numeric weight for comparison (higher = worse).
func gradeOrder(grade string) int {
	switch grade {
	case "A":
		return 0
	case "B":
		return 1
	case "C":
		return 2
	case "D":
		return 3
	case "F":
		return 4
	default:
		return -1
	}
}

// parseSecurityScanFilename extracts projectName, serviceName, tag, and scannedAt
// from a checkov/osv relative path like "dockscan/checkov-dockscan_backend-local-20260606-120000.json".
func parseSecurityScanFilename(relPath, prefix string, fallback time.Time) (projectName, serviceName, tag string, scannedAt time.Time) {
	relPath = filepath.ToSlash(relPath)
	lastSlash := strings.LastIndex(relPath, "/")
	var base string
	if lastSlash >= 0 {
		projectName = relPath[:lastSlash]
		base = relPath[lastSlash+1:]
	} else {
		base = relPath
	}

	base = strings.TrimSuffix(base, ".json")
	base = strings.TrimPrefix(base, prefix)

	scannedAt = fallback
	if tsStr, ok := extractTimestampSuffix(base); ok {
		if t, err := time.ParseInLocation("20060102-150405", tsStr[1:], time.Local); err == nil {
			scannedAt = t
		}
		base = base[:len(base)-len(tsStr)]
	}

	// base is now "{IMAGE_NAME}-{tag}", e.g. "dockscan_backend-local"
	us := strings.Index(base, "_")
	if us < 0 {
		dash := strings.Index(base, "-")
		if dash > 0 && dash < len(base)-1 {
			serviceName = base[:dash]
			tag = base[dash+1:]
		} else {
			serviceName = base
		}
		return
	}
	right := base[us+1:] // e.g. "backend-local"
	dash := strings.Index(right, "-")
	if dash > 0 && dash < len(right)-1 {
		serviceName = right[:dash]
		tag = right[dash+1:]
	} else {
		serviceName = right
	}
	return
}

// parseCheckovFile parses a Checkov JSON output file (array or single object).
func parseCheckovFile(filePath string, info os.FileInfo, relPath string) (CheckovScanRecord, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return CheckovScanRecord{}, err
	}
	data = bytes.TrimSpace(data)
	// Strip UTF-8 BOM (PowerShell Out-File adds it)
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return CheckovScanRecord{}, fmt.Errorf("empty checkov file")
	}

	var entries []json.RawMessage
	if data[0] == '[' {
		if err := json.Unmarshal(data, &entries); err != nil {
			return CheckovScanRecord{}, err
		}
	} else {
		entries = []json.RawMessage{json.RawMessage(data)}
	}

	type rawCheck struct {
		CheckID       string `json:"check_id"`
		CheckName     string `json:"check_name"`
		FilePath      string `json:"file_path"`
		FileLineRange []int  `json:"file_line_range"`
	}
	type rawEntry struct {
		Results struct {
			FailedChecks []rawCheck `json:"failed_checks"`
		} `json:"results"`
		Summary struct {
			Passed  int `json:"passed"`
			Failed  int `json:"failed"`
			Skipped int `json:"skipped"`
		} `json:"summary"`
	}

	var totalPassed, totalFailed, totalSkipped int
	var findings []CheckovFinding

	for _, raw := range entries {
		var e rawEntry
		if err := json.Unmarshal(raw, &e); err != nil {
			continue
		}
		totalPassed += e.Summary.Passed
		totalFailed += e.Summary.Failed
		totalSkipped += e.Summary.Skipped

		for _, fc := range e.Results.FailedChecks {
			line := 0
			if len(fc.FileLineRange) > 0 {
				line = fc.FileLineRange[0]
			}
			findings = append(findings, CheckovFinding{
				CheckID:  fc.CheckID,
				Name:     fc.CheckName,
				FilePath: strings.TrimPrefix(fc.FilePath, "/project/"),
				Line:     line,
			})
		}
	}

	projectName, serviceName, tag, scannedAt := parseSecurityScanFilename(relPath, "checkov-", info.ModTime())
	if findings == nil {
		findings = []CheckovFinding{}
	}
	return CheckovScanRecord{
		Filename:    relPath,
		ProjectName: projectName,
		ServiceName: serviceName,
		Tag:         tag,
		ScannedAt:   scannedAt,
		Passed:      totalPassed,
		Failed:      totalFailed,
		Skipped:     totalSkipped,
		Findings:    findings,
	}, nil
}

// parseOsvFile parses an OSV-Scanner JSON output file.
func parseOsvFile(filePath string, info os.FileInfo, relPath string) (OsvScanRecord, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return OsvScanRecord{}, err
	}
	// Strip UTF-8 BOM (PowerShell Out-File adds it)
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	data = bytes.TrimSpace(data)

	var raw struct {
		Results []struct {
			Source struct {
				Path string `json:"path"`
				Type string `json:"type"`
			} `json:"source"`
			Packages []struct {
				Package struct {
					Name      string `json:"name"`
					Version   string `json:"version"`
					Ecosystem string `json:"ecosystem"`
				} `json:"package"`
				Vulnerabilities []struct {
					ID      string `json:"id"`
					Summary string `json:"summary"`
				} `json:"vulnerabilities"`
			} `json:"packages"`
		} `json:"results"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return OsvScanRecord{}, fmt.Errorf("not valid osv json: %w", err)
	}

	var sources []OsvSource
	totalVulns := 0

	for _, result := range raw.Results {
		var pkgs []OsvPackage
		for _, p := range result.Packages {
			var vulns []OsvVuln
			for _, v := range p.Vulnerabilities {
				vulns = append(vulns, OsvVuln{ID: v.ID, Summary: v.Summary})
			}
			if len(vulns) == 0 {
				continue
			}
			totalVulns += len(vulns)
			pkgs = append(pkgs, OsvPackage{
				Name:      p.Package.Name,
				Version:   p.Package.Version,
				Ecosystem: p.Package.Ecosystem,
				VulnCount: len(vulns),
				Vulns:     vulns,
			})
		}
		if len(pkgs) > 0 {
			sources = append(sources, OsvSource{
				Path:     strings.TrimPrefix(result.Source.Path, "/src/"),
				Type:     result.Source.Type,
				Packages: pkgs,
			})
		}
	}

	projectName, serviceName, tag, scannedAt := parseSecurityScanFilename(relPath, "osv-", info.ModTime())
	if sources == nil {
		sources = []OsvSource{}
	}
	return OsvScanRecord{
		Filename:    relPath,
		ProjectName: projectName,
		ServiceName: serviceName,
		Tag:         tag,
		ScannedAt:   scannedAt,
		TotalVulns:  totalVulns,
		Sources:     sources,
	}, nil
}
