package main

import (
	"encoding/json"
	"fmt"
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
	errReadExportDirectory   = "failed to read export directory"
	errEncodeResponse        = "failed to encode response"
	errInvalidFilename       = "invalid filename"
)

// IndexData holds precomputed scan and project summaries in memory.
type IndexData struct {
	Scans       []ScanSummary
	Projects    []ProjectSummary
	GeneratedAt time.Time
}

var (
	indexMu   sync.RWMutex
	indexData *IndexData
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

// Comparison structures
type ComparisonResult struct {
	Scan1    ScanComparisonInfo   `json:"scan1"`
	Scan2    ScanComparisonInfo   `json:"scan2"`
	Summary  ComparisonSummary    `json:"summary"`
	Added    []Vulnerability      `json:"added"`
	Removed  []Vulnerability      `json:"removed"`
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
	VulnerabilityID   string                 `json:"VulnerabilityID"`
	PkgName           string                 `json:"PkgName"`
	InstalledVersion  string                 `json:"InstalledVersion"`
	Changes           map[string]FieldChange `json:"changes"`
	Current           Vulnerability          `json:"current"`
}

type FieldChange struct {
	Old string `json:"old"`
	New string `json:"new"`
}

// CVE Search structures
type CVESearchResult struct {
	CVEID    string            `json:"cveId"`
	Projects []CVEProjectResult `json:"projects"`
}

type CVEProjectResult struct {
	ProjectName string           `json:"projectName"`
	Images      []CVEImageResult `json:"images"`
}

type CVEImageResult struct {
	ImageName string      `json:"imageName"`
	Tag       string      `json:"tag,omitempty"`
	ScanCount int         `json:"scanCount"`
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
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
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

	// Root info
	r.Get("/", handleRoot)

	// Simple health check
	r.Get("/health", handleHealth)

	// List all scans with vulnerability summaries
	r.Get("/api/scans", func(w http.ResponseWriter, r *http.Request) {
		indexMu.RLock()
		current := indexData
		indexMu.RUnlock()

		if current == nil {
			http.Error(w, "index not ready", http.StatusServiceUnavailable)
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

		// Flatten all vulnerabilities from all results
		var allVulns []Vulnerability
		for _, result := range report.Results {
			for _, vuln := range result.Vulnerabilities {
				allVulns = append(allVulns, vuln)
			}
		}

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

		exportDir := os.Getenv("EXPORT_DIR")
		if exportDir == "" {
			exportDir = defaultExportDir
		}

		jsonFiles, err := walkJSONFiles(exportDir)
		if err != nil {
			http.Error(w, errReadExportDirectory, http.StatusInternalServerError)
			return
		}

		var scans []ScanSummary

		for _, filePath := range jsonFiles {
			relPath, err := filepath.Rel(exportDir, filePath)
			if err != nil {
				continue
			}

			info, err := os.Stat(filePath)
			if err != nil {
				continue
			}

			scanTime := extractTimestampFromPath(relPath, info.ModTime())

			scanSummary := ScanSummary{
				Filename:      relPath,
				Size:          info.Size(),
				ModifiedAt:    scanTime,
				SeverityCount: make(map[string]int),
			}

			var fileProjectName, fileImageName, tag string
			if report, err := parseTrivyJSON(filePath); err == nil {
				scanSummary.ArtifactName = report.ArtifactName

				// Extract project, image and tag from ArtifactName
				fileProjectName, fileImageName, tag = extractProjectImageTagFromArtifactName(report.ArtifactName)
				scanSummary.Tag = tag

				total := 0
				for _, result := range report.Results {
					for _, vuln := range result.Vulnerabilities {
						total++
						severity := strings.ToUpper(vuln.Severity)
						if severity == "" {
							severity = "UNKNOWN"
						}
						scanSummary.SeverityCount[severity]++
					}
				}
				scanSummary.TotalVulns = total
			}

			// Fallback to filename parsing if ArtifactName parsing failed
			if fileProjectName != "" && fileImageName == "" {
				fileProjectName, fileImageName = extractProjectAndImageFromPath(relPath, exportDir)
			} else if fileProjectName == "" {
				fileProjectName, fileImageName = extractProjectAndImageFromPath(relPath, exportDir)
			}

			if fileProjectName != projectName || fileImageName != imageName {
				continue
			}

			scanSummary.ProjectName = fileProjectName
			scanSummary.ImageName = fileImageName

			scans = append(scans, scanSummary)
		}

		// Sort scans for this image: newest version/date first
		sortScansByTagAndDate(scans)

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

		exportDir := os.Getenv("EXPORT_DIR")
		if exportDir == "" {
			exportDir = defaultExportDir
		}

		// Get all scan files
		jsonFiles, err := walkJSONFiles(exportDir)
		if err != nil {
			http.Error(w, errReadExportDirectory, http.StatusInternalServerError)
			return
		}

		// Map to store results: projectName -> imageName -> scans with this CVE
		projectImageScans := make(map[string]map[string][]ScanSummary)

		// Iterate through all scan files
		for _, filePath := range jsonFiles {
			relPath, err := filepath.Rel(exportDir, filePath)
			if err != nil {
				continue
			}

			info, err := os.Stat(filePath)
			if err != nil {
				continue
			}

			scanTime := extractTimestampFromPath(relPath, info.ModTime())

			// Parse the scan file
			report, err := parseTrivyJSON(filePath)
			if err != nil {
				continue
			}

			// Check if this scan contains the CVE
			hasCVE := false
			for _, result := range report.Results {
				for _, vuln := range result.Vulnerabilities {
					if vuln.VulnerabilityID == cveId {
						hasCVE = true
						break
					}
				}
				if hasCVE {
					break
				}
			}

			if !hasCVE {
				continue
			}

			// Extract project, image and tag from ArtifactName
			projectName, imageName, tag := extractProjectImageTagFromArtifactName(report.ArtifactName)

			// Fallback to filename parsing if ArtifactName parsing failed
			if projectName != "" && imageName == "" {
				projectName, imageName = extractProjectAndImageFromPath(relPath, exportDir)
			} else if projectName == "" {
				projectName, imageName = extractProjectAndImageFromPath(relPath, exportDir)
			}

			if projectName == "" || imageName == "" {
				continue
			}

			// Build scan summary
			scanSummary := ScanSummary{
				Filename:      relPath,
				Size:          info.Size(),
				ModifiedAt:    scanTime,
				ArtifactName:  report.ArtifactName,
				ProjectName:   projectName,
				ImageName:     imageName,
				Tag:           tag,
				SeverityCount: make(map[string]int),
			}

			// Count vulnerabilities and severity for this scan
			total := 0
			for _, result := range report.Results {
				for _, vuln := range result.Vulnerabilities {
					total++
					severity := strings.ToUpper(vuln.Severity)
					if severity == "" {
						severity = "UNKNOWN"
					}
					scanSummary.SeverityCount[severity]++
				}
			}
			scanSummary.TotalVulns = total

			// Add to results map
			if projectImageScans[projectName] == nil {
				projectImageScans[projectName] = make(map[string][]ScanSummary)
			}
			projectImageScans[projectName][imageName] = append(projectImageScans[projectName][imageName], scanSummary)
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
					ImageName: imageName,
					Tag:       latestScan.Tag,
					ScanCount: len(scans),
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
			for _, ig := range imageGrades {
				if gradeOrder(ig.Grade) > gradeOrder(worstGrade) {
					worstGrade = ig.Grade
				}
			}

			projectGrades = append(projectGrades, ProjectGrade{
				ProjectName: p.ProjectName,
				ImageCount:  len(p.Images),
				Grade:       worstGrade,
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

func handleRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(headerContentType, mimeTextPlainUTF8)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Trivy Dashboard backend is running.\nTry /health or /api/scans\n"))
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(headerContentType, mimeApplicationJSON)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
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
		Added:    added,
		Removed:  removed,
		Changed:  changed,
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
// Format: {project-name}-{image-name}:{tag}
// Example: "dockscan-backend:latest" -> project: "dockscan", image: "backend", tag: "latest"
// Example: "my-service-api:v1.0.0" -> project: "my-service", image: "api", tag: "v1.0.0"
// Returns empty strings if parsing fails
func extractProjectImageTagFromArtifactName(artifactName string) (projectName, imageName, tag string) {
	if artifactName == "" {
		return "", "", ""
	}

	// Split by colon to get tag.
	// ArtifactName genelde şu formatlarda gelir:
	//  - "dockscan-backend:latest"
	//  - "yournexushost:8090/repository/my-repo/acme-app_frontend:test-v1.0"
	// Bizim için önemli olan kısım, registry ve path'ten sonraki image adı ve tag'dir.
	parts := strings.Split(artifactName, ":")
	var namePart string
	if len(parts) == 2 {
		namePart = parts[0] // örn: "yournexushost:8090/repository/my-repo/acme-app_frontend"
		tag = parts[1]      // örn: "test-v1.0"
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

	// Bazı registry formatlarında (örn: "yournexushost:8090/repository/my-repo/acme-app_frontend")
	// ArtifactName, tam image path'ini içerir. Bizim için önemli olan son segmenttir.
	// Örnek:
	//  - "yournexushost:8090/repository/my-repo/acme-app_frontend" -> "acme-app_frontend"
	if strings.Contains(namePart, "/") {
		parts := strings.Split(namePart, "/")
		namePart = parts[len(parts)-1]
	}

	// Önce projeyi ve imajı ayırmak için öncelikli olarak alt çizgi (_) kullan.
	// Örnek:
	//   "hafizlik-takip_backend"  -> project: "hafizlik-takip", image: "backend"
	//   "acme-app_frontend"  -> project: "acme-app",   image: "frontend"
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
			// Örn: "superapp-backend-api" -> project: "superapp", image: "backend-api"
			projectName = strings.TrimSuffix(namePart, suffix)
			imageName = suf // suffix'in kendisi imaj adı olarak kullanılır ("backend", "frontend", "backend-api" vb.)
			return projectName, imageName, tag
		}
	}

	// Hiçbir özel kural uymuyorsa, son tireye göre böl.
	// Daha önce burada son tireye göre genel bir bölme yapılıyordu:
	//   "dockscan-backend" -> project: "dockscan", image: "backend"
	// Ancak artık backend/frontend/api gibi bilinen suffix'ler zaten yukarıdaki
	// commonSuffixes listesi ile yakalandığı için, geriye kalan isimler tekil
	// projeler olarak ele alınır.
	// Örnekler (tek imajlı monolith projeler):
	//   "goruntulu-fetvalar" -> project: "goruntulu-fetvalar", image: "goruntulu-fetvalar"
	//   "avrasya-fetva"      -> project: "avrasya-fetva",      image: "avrasya-fetva"
	lastDash := strings.LastIndex(namePart, "-")
	if lastDash == -1 || lastDash == 0 || lastDash == len(namePart)-1 {
		// Tire yoksa veya başta/sonda ise, isim tek parça kabul edilir.
		// Örnek: "wordpress:6.6.2" veya "ajanda:prod-v1.0"
		return namePart, namePart, tag
	}

	// Eski davranış: son tireye göre bölme
	// Bu genel kural, bazı projelerde istenmeyen bölünmelere sebep oluyordu
	// (örn. "goruntulu-fetvalar" -> "goruntulu" + "fetvalar").
	// Bu nedenle, eğer yukarıdaki özel suffix kurallarına girmiyorsa
	// projeyi tek parça olarak ele alıyoruz.
	return namePart, namePart, tag
}

// extractProjectAndImage is kept for backward compatibility
// It now calls extractProjectAndImageFromPath with empty exportDir
func extractProjectAndImage(filename string) (projectName, imageName string) {
	return extractProjectAndImageFromPath(filename, "")
}

// rebuildIndex (ilk adım olarak) ileride kullanacağımız bellek içi index yapısını
// oluşturmak için çağrılacak. Şu an için mevcut davranışı bozmayacak şekilde
// sadece iskelet olarak tanımlanmıştır.
// NOT: İlerleyen aşamada /api/scans ve /api/projects endpoint'leri bu index'ten
// beslenecek şekilde güncellenecektir.
func rebuildIndex(exportDir string) error {
	jsonFiles, err := walkJSONFiles(exportDir)
	if err != nil {
		return fmt.Errorf("%s: %w", errReadExportDirectory, err)
	}

	var scans []ScanSummary
	scans = make([]ScanSummary, 0, len(jsonFiles))

	for _, filePath := range jsonFiles {
		info, err := os.Stat(filePath)
		if err != nil || info.IsDir() {
			continue
		}

		relPath, err := filepath.Rel(exportDir, filePath)
		if err != nil {
			continue
		}

		scanTime := extractTimestampFromPath(relPath, info.ModTime())

		summary := ScanSummary{
			Filename:      relPath,
			Size:          info.Size(),
			ModifiedAt:    scanTime,
			SeverityCount: make(map[string]int),
		}

		var projectName, imageName, tag string
		if report, err := parseTrivyJSON(filePath); err == nil {
			summary.ArtifactName = report.ArtifactName

			projectName, imageName, tag = extractProjectImageTagFromArtifactName(report.ArtifactName)
			summary.Tag = tag

			total := 0
			for _, result := range report.Results {
				for _, vuln := range result.Vulnerabilities {
					total++
					severity := strings.ToUpper(vuln.Severity)
					if severity == "" {
						severity = "UNKNOWN"
					}
					summary.SeverityCount[severity]++
				}
			}
			summary.TotalVulns = total
		}

		// Fallback to filename parsing if ArtifactName parsing failed
		if projectName != "" && imageName == "" {
			projectName, imageName = extractProjectAndImageFromPath(relPath, exportDir)
		} else if projectName == "" {
			projectName, imageName = extractProjectAndImageFromPath(relPath, exportDir)
		}

		summary.ProjectName = projectName
		summary.ImageName = imageName

		scans = append(scans, summary)
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

	var projects []ProjectSummary
	for projectName, project := range projectsMap {
		project.TotalVulns = 0
		project.SeverityCount = make(map[string]int)

		for _, imageSummary := range imagesMap[projectName] {
			scans := imageSummary.Scans
			sortScansByTagAndDate(scans)

			imageSummary.ScanCount = len(scans)

			if len(scans) > 0 {
				latestScan := scans[0]
				imageSummary.LastScan = latestScan.ModifiedAt
				imageSummary.TotalVulns = latestScan.TotalVulns
				imageSummary.SeverityCount = make(map[string]int)
				for k, v := range latestScan.SeverityCount {
					imageSummary.SeverityCount[k] = v
				}
			}

			project.TotalVulns += imageSummary.TotalVulns
			for severity, count := range imageSummary.SeverityCount {
				project.SeverityCount[severity] += count
			}

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

	newIndex := &IndexData{
		Scans:       scans,
		Projects:    projects,
		GeneratedAt: time.Now(),
	}

	indexMu.Lock()
	indexData = newIndex
	indexMu.Unlock()

	log.Printf("index rebuilt: %d scans, %d projects", len(scans), len(projects))
	return nil
}

// computeGrade returns a letter grade based on CRITICAL and HIGH vulnerability counts
// from the latest scan of an image.
// A: 0 CRITICAL, 0 HIGH
// B: 0 CRITICAL, ≥1 HIGH
// C: 1–3 CRITICAL
// D: 4–9 CRITICAL
// F: ≥10 CRITICAL
func computeGrade(severityCount map[string]int) string {
	critical := severityCount["CRITICAL"]
	high := severityCount["HIGH"]
	switch {
	case critical == 0 && high == 0:
		return "A"
	case critical == 0:
		return "B"
	case critical <= 3:
		return "C"
	case critical <= 9:
		return "D"
	default:
		return "F"
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
