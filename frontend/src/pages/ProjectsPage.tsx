import React, { useState, useEffect } from 'react';

type ProjectSummary = {
  projectName: string;
  totalScans: number;
  totalVulns: number;
  severityCount: Record<string, number>;
  lastScan: string;
};

type ScanSummary = {
  filename?: string;
  artifactName?: string;
  projectName?: string;
  imageName?: string;
  tag?: string;
  modifiedAt: string;
  totalVulns: number;
  severityCount: Record<string, number>;
};

type ProjectAggregatedStats = {
  totalVulns: number;
  severityCount: Record<string, number>;
};

type CVESearchResult = {
  cveId: string;
  projects: CVEProjectResult[];
};

type CVEProjectResult = {
  projectName: string;
  images: CVEImageResult[];
};

type CVEImageResult = {
  imageName: string;
  tag?: string;
  scanCount: number;
  latestScan: ScanSummary;
};

type ProjectsPageProps = {
  projects: ProjectSummary[];
  filteredProjects: ProjectSummary[];
  loading: boolean;
  error: string | null;
  allScans: ScanSummary[];
  projectListStats: Record<string, ProjectAggregatedStats>;
  searchQuery: string;
  setSearchQuery: (value: string) => void;
  onSelectProject: (projectName: string) => void;
  goDashboard: () => void;
  apiBase: string;
  onRefresh?: () => void;
  refreshing?: boolean;
};

const ProjectsPage: React.FC<ProjectsPageProps> = ({
  projects,
  filteredProjects,
  loading,
  error,
  allScans,
  projectListStats,
  searchQuery,
  setSearchQuery,
  onSelectProject,
  goDashboard,
  apiBase,
  onRefresh,
  refreshing,
}) => {
  // Debounced search input to avoid filtering on every keystroke
  const [inputValue, setInputValue] = useState(searchQuery);
  
  // CVE search state
  const [cveSearchQuery, setCveSearchQuery] = useState('');
  const [cveSearchResults, setCveSearchResults] = useState<CVESearchResult | null>(null);
  const [cveSearchLoading, setCveSearchLoading] = useState(false);
  const [cveSearchError, setCveSearchError] = useState<string | null>(null);

  useEffect(() => {
    setInputValue(searchQuery);
  }, [searchQuery]);

  useEffect(() => {
    const handle = setTimeout(() => {
      if (inputValue !== searchQuery) {
        setSearchQuery(inputValue);
      }
    }, 300);

    return () => clearTimeout(handle);
  }, [inputValue, searchQuery, setSearchQuery]);

  // CVE search function
  const handleCVESearch = async () => {
    if (!cveSearchQuery.trim()) {
      setCveSearchResults(null);
      return;
    }

    setCveSearchLoading(true);
    setCveSearchError(null);

    try {
      const response = await fetch(`${apiBase}/api/cve/${encodeURIComponent(cveSearchQuery.trim())}`);
      if (!response.ok) {
        if (response.status === 404) {
          setCveSearchResults({ cveId: cveSearchQuery.trim(), projects: [] });
        } else {
          throw new Error(`API error: ${response.status}`);
        }
      } else {
        const data: CVESearchResult = await response.json();
        // Ensure data structure is valid
        if (data && typeof data === 'object') {
          setCveSearchResults({
            cveId: data.cveId || cveSearchQuery.trim(),
            projects: Array.isArray(data.projects) ? data.projects : []
          });
        } else {
          setCveSearchResults({ cveId: cveSearchQuery.trim(), projects: [] });
        }
      }
    } catch (err) {
      console.error('Failed to search CVE:', err);
      setCveSearchError(err instanceof Error ? err.message : 'CVE araması başarısız oldu');
      setCveSearchResults(null);
    } finally {
      setCveSearchLoading(false);
    }
  };

  // Handle Enter key in CVE search
  const handleCVEKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      handleCVESearch();
    }
  };

  // Clear CVE search results when switching back to project search
  useEffect(() => {
    if (inputValue && !cveSearchQuery) {
      setCveSearchResults(null);
    }
  }, [inputValue, cveSearchQuery]);

  return (
    <div className="min-h-screen bg-catppuccin-base text-catppuccin-text">
      <header className="border-b border-catppuccin-surface0 bg-catppuccin-mantle/70 backdrop-blur">
        <div className="mx-auto flex max-w-5xl items-center justify-between px-4 py-3">
          <div className="flex items-center gap-3">
            <button
              onClick={goDashboard}
              className="px-3 py-1.5 rounded border border-catppuccin-surface1 hover:bg-catppuccin-surface0 hover:border-catppuccin-teal text-catppuccin-text transition-colors font-medium"
            >
              ← Ana Sayfa
            </button>
            <span className="rounded bg-catppuccin-teal/10 px-2 py-1 text-xs font-semibold uppercase tracking-wide text-catppuccin-teal">
              Trivy
            </span>
            <span className="text-lg font-semibold">Projeler</span>
          </div>
          <div className="flex items-center gap-3">
            {onRefresh && (
              <button
                onClick={onRefresh}
                disabled={refreshing}
                className="px-3 py-1.5 rounded border border-catppuccin-surface1 hover:bg-catppuccin-surface0 hover:border-catppuccin-teal text-catppuccin-text transition-colors font-medium disabled:opacity-50"
                title="Tarama verilerini yenile"
              >
                {refreshing ? '⟳ Yenileniyor...' : '⟳ Yenile'}
              </button>
            )}
            <span className="text-xs text-catppuccin-overlay1">Prototype UI</span>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-5xl px-4 py-6 space-y-6">
        <section className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-catppuccin-text">Projeler</h2>
            <span className="text-xs text-catppuccin-overlay0">
              {cveSearchResults
                ? `${Array.isArray(cveSearchResults.projects) ? cveSearchResults.projects.length : 0} proje (CVE: ${cveSearchResults.cveId})`
                : `${Array.isArray(filteredProjects) ? filteredProjects.length : 0} / ${Array.isArray(projects) ? projects.length : 0} proje`}
            </span>
          </div>

          <div className="mb-4 space-y-3">
            <div className="flex gap-2">
              <input
                type="text"
                placeholder="Proje ara..."
                value={inputValue}
                onChange={(e) => {
                  setInputValue(e.target.value);
                  setCveSearchQuery('');
                  setCveSearchResults(null);
                }}
                className="flex-1 px-4 py-2 rounded-lg border border-catppuccin-surface1 bg-catppuccin-base text-catppuccin-text placeholder-catppuccin-overlay0 focus:outline-none focus:ring-2 focus:ring-catppuccin-teal focus:border-transparent"
              />
            </div>
            <div className="flex gap-2">
              <input
                type="text"
                placeholder="CVE kodu ara (örn: CVE-2025-59466)"
                value={cveSearchQuery}
                onChange={(e) => setCveSearchQuery(e.target.value)}
                onKeyDown={handleCVEKeyDown}
                className="flex-1 px-4 py-2 rounded-lg border border-catppuccin-surface1 bg-catppuccin-base text-catppuccin-text placeholder-catppuccin-overlay0 focus:outline-none focus:ring-2 focus:ring-catppuccin-teal focus:border-transparent"
              />
              <button
                onClick={handleCVESearch}
                disabled={cveSearchLoading || !cveSearchQuery.trim()}
                className="px-4 py-2 rounded-lg border border-catppuccin-surface1 bg-catppuccin-teal/20 hover:bg-catppuccin-teal/30 text-catppuccin-teal font-medium disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {cveSearchLoading ? 'Aranıyor...' : 'CVE Ara'}
              </button>
            </div>
          </div>

          {cveSearchError && (
            <div className="mb-4 p-3 rounded-lg border border-catppuccin-red/30 bg-catppuccin-red/10 text-sm text-catppuccin-red">
              Hata: {cveSearchError}
            </div>
          )}

          {/* CVE Search Results */}
          {cveSearchResults && (
            <div className="space-y-4">
              {!Array.isArray(cveSearchResults.projects) || cveSearchResults.projects.length === 0 ? (
                <div className="flex h-40 items-center justify-center text-sm text-catppuccin-overlay0">
                  CVE {cveSearchResults.cveId} hiçbir projede bulunamadı.
                </div>
              ) : (
                (Array.isArray(cveSearchResults.projects) ? cveSearchResults.projects : []).map((project) => (
                  <div
                    key={project.projectName}
                    className="border border-catppuccin-surface0 rounded-lg p-4 bg-catppuccin-base/60"
                  >
                    <div className="flex items-center justify-between mb-3">
                      <h3 className="text-lg font-semibold text-catppuccin-text">
                        {project.projectName}
                      </h3>
                      <button
                        onClick={() => onSelectProject(project.projectName)}
                        className="px-3 py-1 text-xs rounded border border-catppuccin-surface1 hover:bg-catppuccin-surface0 hover:border-catppuccin-teal text-catppuccin-text transition-colors"
                      >
                        Detayları Gör
                      </button>
                    </div>
                    <div className="space-y-2">
                      {(Array.isArray(project.images) ? project.images : []).map((image) => (
                        <div
                          key={`${image.imageName}-${image.tag || 'notag'}`}
                          className="pl-4 py-2 border-l-2 border-catppuccin-surface1 hover:border-catppuccin-teal transition-colors"
                        >
                          <div className="flex items-center justify-between">
                            <div>
                              <span className="font-medium text-catppuccin-text">
                                {image.imageName}
                              </span>
                              {image.tag && (
                                <span className="ml-2 text-xs text-catppuccin-overlay1">
                                  ({image.tag})
                                </span>
                              )}
                              <p className="text-xs text-catppuccin-overlay1 mt-1">
                                {image.scanCount} tarama • Son tarama:{' '}
                                {new Date(image.latestScan.modifiedAt).toLocaleString()}
                              </p>
                            </div>
                            <div className="flex items-center gap-3">
                              {image.latestScan.severityCount['CRITICAL'] > 0 && (
                                <div className="text-center">
                                  <p className="text-xs text-catppuccin-overlay1">CRITICAL</p>
                                  <p className="text-sm font-semibold text-catppuccin-red">
                                    {image.latestScan.severityCount['CRITICAL']}
                                  </p>
                                </div>
                              )}
                              {image.latestScan.severityCount['HIGH'] > 0 && (
                                <div className="text-center">
                                  <p className="text-xs text-catppuccin-overlay1">HIGH</p>
                                  <p className="text-sm font-semibold text-catppuccin-peach">
                                    {image.latestScan.severityCount['HIGH']}
                                  </p>
                                </div>
                              )}
                              {image.latestScan.severityCount['MEDIUM'] > 0 && (
                                <div className="text-center">
                                  <p className="text-xs text-catppuccin-overlay1">MEDIUM</p>
                                  <p className="text-sm font-semibold text-catppuccin-yellow">
                                    {image.latestScan.severityCount['MEDIUM']}
                                  </p>
                                </div>
                              )}
                              {image.latestScan.severityCount['LOW'] > 0 && (
                                <div className="text-center">
                                  <p className="text-xs text-catppuccin-overlay1">LOW</p>
                                  <p className="text-sm font-semibold text-catppuccin-blue">
                                    {image.latestScan.severityCount['LOW']}
                                  </p>
                                </div>
                              )}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                ))
              )}
            </div>
          )}

          {/* Regular Project List (when no CVE search) */}
          {!cveSearchResults && (!Array.isArray(filteredProjects) || filteredProjects.length === 0) && !loading && !error && (
            <div className="flex h-40 items-center justify-center text-sm text-catppuccin-overlay0">
              {searchQuery
                ? 'Arama kriterlerine uygun proje bulunamadı.'
                : 'Henüz proje bulunamadı. export klasörüne JSON dosyası koyduktan sonra sayfayı yenile.'}
            </div>
          )}

          {!cveSearchResults && Array.isArray(filteredProjects) && filteredProjects.length > 0 && (
            <div className="space-y-3">
              {filteredProjects.map((project) => {
                if (!project) return null;
                const agg = projectListStats[project.projectName];
                const latestTotalVulns = agg?.totalVulns ?? project.totalVulns;
                const latestSeverity = agg?.severityCount ?? project.severityCount;

                return (
                  <div
                    key={project.projectName}
                    role="button"
                    tabIndex={0}
                    className="border border-catppuccin-surface0 rounded-lg p-4 bg-catppuccin-base/60 hover:bg-catppuccin-mantle/40 cursor-pointer transition-colors"
                    onClick={() => onSelectProject(project.projectName)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        onSelectProject(project.projectName);
                      }
                    }}
                  >
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="text-lg font-semibold text-catppuccin-text">
                          {project.projectName}
                        </h3>
                        <p className="text-xs text-catppuccin-overlay1 mt-1">
                          {project.totalScans} tarama • Son tarama:{' '}
                          {new Date(project.lastScan).toLocaleString()}
                        </p>
                      </div>
                      <div className="flex items-center gap-4">
                        <div className="text-right">
                          <span className="text-xs text-catppuccin-overlay1">Toplam Açık</span>
                          <p className="text-2xl font-semibold text-catppuccin-text">
                            {latestTotalVulns}
                          </p>
                        </div>
                        <div className="flex gap-3 text-sm">
                          {latestSeverity['CRITICAL'] > 0 && (
                            <div className="text-center">
                              <p className="text-xs text-catppuccin-overlay1">CRITICAL</p>
                              <p className="text-lg font-semibold text-catppuccin-red">
                                {latestSeverity['CRITICAL']}
                              </p>
                            </div>
                          )}
                          {latestSeverity['HIGH'] > 0 && (
                            <div className="text-center">
                              <p className="text-xs text-catppuccin-overlay1">HIGH</p>
                              <p className="text-lg font-semibold text-catppuccin-peach">
                                {latestSeverity['HIGH']}
                              </p>
                            </div>
                          )}
                          {latestSeverity['MEDIUM'] > 0 && (
                            <div className="text-center">
                              <p className="text-xs text-catppuccin-overlay1">MEDIUM</p>
                              <p className="text-lg font-semibold text-catppuccin-yellow">
                                {latestSeverity['MEDIUM']}
                              </p>
                            </div>
                          )}
                          {latestSeverity['LOW'] > 0 && (
                            <div className="text-center">
                              <p className="text-xs text-catppuccin-overlay1">LOW</p>
                              <p className="text-lg font-semibold text-catppuccin-blue">
                                {latestSeverity['LOW']}
                              </p>
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </section>
      </main>
    </div>
  );
};

export default ProjectsPage;


