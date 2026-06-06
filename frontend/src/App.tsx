import React, { useEffect, useState, useMemo } from 'react';
import { createPortal } from 'react-dom';
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Legend,
  Tooltip,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
} from 'recharts';
import ProjectsPage from './pages/ProjectsPage';
import DashboardPage from './pages/DashboardPage';
import SecurityPage from './pages/SecurityPage';
import TimelineTooltip from './components/TimelineTooltip';

type ProjectSummary = {
  projectName: string;
  totalScans: number;
  totalVulns: number;
  severityCount: Record<string, number>;
  images: ImageSummary[];
  lastScan: string;
};

type ScanSummary = {
  filename: string;
  size: number;
  modifiedAt: string;
  artifactName?: string;
  projectName?: string;
  imageName?: string;
  tag?: string;
  totalVulns: number;
  severityCount: Record<string, number>;
  grade: string;
};

// Bir tarama için zaman çizelgesi seri anahtarını üretir.
// separateVersions false ise tüm tag'ler birleşik (proje + imaj);
// true ise prod/test gibi ortamlar ayrı seri olarak gruplanır.
const getTimelineSeriesKey = (scan: ScanSummary, separateVersions: boolean): string | null => {
  if (!scan.projectName) return null;
  const proj = scan.projectName;
  const img = scan.imageName;
  if (!img) return proj;

  if (!separateVersions) {
    // Tüm tag'ler birleşik, sadece proje + imaj
    return `${proj} - ${img}`;
  }

  // Versiyonları ayır: özellikle prod/test gibi ortamlar için grupla
  const tag = scan.tag || '';
  let envLabel: string | null = null;
  if (tag.startsWith('prod-')) envLabel = 'prod';
  else if (tag.startsWith('test-')) envLabel = 'test';

  if (envLabel) {
    // Örn: "backend (prod)" / "backend (test)"
    return `${proj} - ${img} (${envLabel})`;
  }

  // Diğer tag'ler için tam tag'i göster
  if (tag) {
    return `${proj} - ${img}:${tag}`;
  }

  return `${proj} - ${img}`;
};

type ImageSummary = {
  imageName: string;
  totalVulns: number;
  severityCount: Record<string, number>;
  grade: string;
  lastScan: string;
  scans: ScanSummary[];
};

type Vulnerability = {
  VulnerabilityID: string;
  PkgName: string;
  InstalledVersion: string;
  FixedVersion: string;
  Severity: string;
  Title: string;
  Description: string;
  PrimaryURL?: string;
};

type ComparisonResult = {
  scan1: {
    filename: string;
    artifactName: string;
    totalVulns: number;
    scanDate: string;
  };
  scan2: {
    filename: string;
    artifactName: string;
    totalVulns: number;
    scanDate: string;
  };
  summary: {
    added: number;
    removed: number;
    changed: number;
    unchanged: number;
  };
  added: Vulnerability[];
  removed: Vulnerability[];
  changed: {
    VulnerabilityID: string;
    PkgName: string;
    InstalledVersion: string;
    changes: Record<string, { old: string; new: string }>;
    current: Vulnerability;
  }[];
};

const API_BASE =
  import.meta.env.VITE_API_BASE || (import.meta.env.DEV ? 'http://localhost:8180' : '');

type Page = 'dashboard' | 'projects' | 'project-detail' | 'project-comparison' | 'security' | 'not-found';

type ProjectAggregatedStats = {
  totalVulns: number;
  severityCount: Record<string, number>;
};

function aggregateProjectStats(
  latestMap: Record<string, Record<string, ScanSummary>>
): Record<string, ProjectAggregatedStats> {
  const result: Record<string, ProjectAggregatedStats> = {};

  for (const [projectName, images] of Object.entries(latestMap)) {
    let totalVulns = 0;
    const severityCount: Record<string, number> = {};

    for (const scan of Object.values(images)) {
      totalVulns += scan.totalVulns;
      for (const [sev, count] of Object.entries(scan.severityCount)) {
        severityCount[sev] = (severityCount[sev] || 0) + count;
      }
    }

    result[projectName] = { totalVulns, severityCount };
  }

  return result;
}

// Helper: build latest scan per project/image map once and reuse it.
function buildProjectImageLatestScan(allScans: ScanSummary[]) {
  const projectImageLatestScan: Record<string, Record<string, ScanSummary>> = {};

  if (!Array.isArray(allScans)) {
    return projectImageLatestScan;
  }

  allScans.forEach((scan) => {
    if (!scan?.projectName || !scan.imageName) return;
    const proj = scan.projectName;
    const img = scan.imageName;

    if (!projectImageLatestScan[proj]) {
      projectImageLatestScan[proj] = {};
    }

    const existing = projectImageLatestScan[proj][img];
    if (
      !existing ||
      (scan.modifiedAt && new Date(scan.modifiedAt).getTime() > new Date(existing.modifiedAt).getTime())
    ) {
      projectImageLatestScan[proj][img] = scan;
    }
  });

  return projectImageLatestScan;
}

function gradeColor(grade: string): string {
  if (grade === 'A') return 'catppuccin-green';
  if (grade === 'B') return 'catppuccin-blue';
  if (grade === 'C') return 'catppuccin-yellow';
  return 'catppuccin-red'; // D, F
}

// Helper function to determine initial page from URL
function getInitialPage(): Page {
  try {
    if (typeof window === 'undefined' || !window.location) {
      return 'dashboard';
    }

    const path = window.location.pathname || '/';

    // Skip API routes - they're handled by backend
    if (path.startsWith('/api/') || path === '/index.html') {
      return 'dashboard';
    }

    if (path === '/' || path === '') {
      return 'dashboard';
    } else if (path === '/projects') {
      return 'projects';
    } else if (path.startsWith('/projects/')) {
      return 'project-detail';
    } else if (path === '/security') {
      return 'security';
    } else {
      return 'not-found';
    }
  } catch (error) {
    console.error('Error determining initial page:', error);
    return 'dashboard';
  }
}

function getInitialSelectedProject(): string | null {
  try {
    const path = window.location?.pathname || '/';
    if (path.startsWith('/projects/')) {
      return decodeURIComponent(path.slice('/projects/'.length)) || null;
    }
  } catch {}
  return null;
}

function App() {
  const [projects, setProjects] = useState<ProjectSummary[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [currentPage, setCurrentPage] = useState<Page>(getInitialPage);
  const [selectedProject, setSelectedProject] = useState<string | null>(getInitialSelectedProject);
  const [projectDetails, setProjectDetails] = useState<ProjectSummary | null>(null);
  const [loadingDetails, setLoadingDetails] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string | null>(null);
  const [expandedImages, setExpandedImages] = useState<Set<string>>(new Set());
  const [imageVulnDetails, setImageVulnDetails] = useState<Record<string, Vulnerability[]>>({});
  const [loadingImageDetails, setLoadingImageDetails] = useState<Record<string, boolean>>({});
  const [allScans, setAllScans] = useState<ScanSummary[]>([]);
  const [scansLoaded, setScansLoaded] = useState(false);
  const [separateVersions, setSeparateVersions] = useState<boolean>(false); // Varsayılan: tag'siz grupla
  const [comparisonData, setComparisonData] = useState<ComparisonResult | null>(null);
  const [selectedScan1, setSelectedScan1] = useState<string>('');
  const [selectedScan2, setSelectedScan2] = useState<string>('');
  const [comparisonLoading, setComparisonLoading] = useState(false);
  const [comparisonError, setComparisonError] = useState<string | null>(null);

  // Listen for browser back/forward buttons
  useEffect(() => {
    const handlePopState = () => {
      const newPath = window.location.pathname;
      if (newPath === '/' || newPath === '') {
        setCurrentPage('dashboard');
        setSelectedProject(null);
      } else if (newPath === '/projects') {
        setCurrentPage('projects');
        setSelectedProject(null);
      } else if (newPath.startsWith('/projects/')) {
        const projectName = decodeURIComponent(newPath.slice('/projects/'.length));
        setSelectedProject(projectName);
        setCurrentPage('project-detail');
      } else if (newPath === '/security') {
        setCurrentPage('security');
      } else if (!newPath.startsWith('/api/') && newPath !== '/index.html') {
        setCurrentPage('not-found');
      }
    };

    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  // Update URL when page changes (for bookmarking/sharing)
  useEffect(() => {
    if (currentPage === 'dashboard') {
      if (window.location.pathname !== '/') {
        window.history.pushState({}, '', '/');
      }
    } else if (currentPage === 'projects') {
      if (window.location.pathname !== '/projects') {
        window.history.pushState({}, '', '/projects');
      }
    } else if (currentPage === 'project-detail' && selectedProject) {
      const target = `/projects/${encodeURIComponent(selectedProject)}`;
      if (window.location.pathname !== target) {
        window.history.pushState({}, '', target);
      }
    } else if (currentPage === 'security') {
      if (window.location.pathname !== '/security') {
        window.history.pushState({}, '', '/security');
      }
    }
  }, [currentPage, selectedProject]);

  useEffect(() => {
    const loadProjects = async () => {
      setLoading(true);
      try {
        const res = await fetch(`${API_BASE}/api/projects`);
        if (!res.ok) {
          throw new Error(`API error: ${res.status}`);
        }
        const data: ProjectSummary[] = await res.json();
        setProjects(Array.isArray(data) ? data : []);
        setError(null);
      } catch (err: any) {
        setError(err.message);
        setProjects([]);
      } finally {
        setLoading(false);
      }
    };

    loadProjects();
  }, []);

  // Fetch all scans for timeline chart and project stats.
  useEffect(() => {
    if (scansLoaded) return;

    const loadScans = async () => {
      try {
        const res = await fetch(`${API_BASE}/api/scans`);
        if (!res.ok) {
          throw new Error(`API error: ${res.status}`);
        }
        const data: ScanSummary[] = await res.json();
        setAllScans(Array.isArray(data) ? data : []);
        setScansLoaded(true);
      } catch (err) {
        console.error('Failed to load scans:', err);
        setAllScans([]);
      }
    };

    loadScans();
  }, [API_BASE, scansLoaded]);

  useEffect(() => {
    if (!selectedProject) return;

    const loadProjectDetails = async () => {
      setLoadingDetails(true);
      try {
        const res = await fetch(`${API_BASE}/api/projects/${selectedProject}`);
        if (!res.ok) {
          throw new Error(`API error: ${res.status}`);
        }
        const data: ProjectSummary = await res.json();
        setProjectDetails(data);
      } catch (err) {
        console.error('Failed to load project details:', err);
        setProjectDetails(null);
      } finally {
        setLoadingDetails(false);
      }
    };

    loadProjectDetails();
  }, [selectedProject]);

  // Compare scans function
  const compareScans = async () => {
    if (!selectedScan1 || !selectedScan2) return;
    setComparisonLoading(true);
    setComparisonError(null);
    setComparisonData(null);
    try {
      const response = await fetch(
        `${API_BASE}/api/compare?scan1=${encodeURIComponent(selectedScan1)}&scan2=${encodeURIComponent(selectedScan2)}`
      );
      if (!response.ok) {
        const errorText = await response.text().catch(() => '');
        throw new Error(`API hatası (${response.status}): ${errorText || 'Sunucu hatası'}`);
      }
      const data: ComparisonResult = await response.json();

      // Validate response structure
      if (!data || !data.scan1 || !data.scan2 || !data.summary) {
        throw new Error('Geçersiz API yanıtı');
      }

      // Ensure arrays exist (for 0 vulnerability cases)
      if (!data.added) data.added = [];
      if (!data.removed) data.removed = [];
      if (!data.changed) data.changed = [];

      setComparisonData(data);
      setComparisonError(null);
    } catch (error) {
      console.error('Comparison failed:', error);
      const errorMessage = error instanceof Error ? error.message : 'Bilinmeyen bir hata oluştu';
      setComparisonError(errorMessage);
      setComparisonData(null);
    } finally {
      setComparisonLoading(false);
    }
  };

  // Load vulnerabilities for expanded scans (only for .json filenames)
  useEffect(() => {
    if (!projectDetails) return;

    expandedImages.forEach((identifier) => {
      // Only load if it's a filename (contains .json), not an image name
      if (!identifier.includes('.json')) return;

      // Skip if already loaded
      if (imageVulnDetails[identifier] || loadingImageDetails[identifier]) return;

      setLoadingImageDetails((prev) => ({ ...prev, [identifier]: true }));

      // URL encode the path to handle subdirectories
      const encodedPath = identifier
        .split('/')
        .map(segment => encodeURIComponent(segment))
        .join('/');

      // Load vulnerability details for this scan
      const loadVulnDetails = async () => {
        try {
          const res = await fetch(`${API_BASE}/api/scans/${encodedPath}`);
          if (!res.ok) {
            throw new Error(`API error: ${res.status}`);
          }
          const data: { vulnerabilities: Vulnerability[] } = await res.json();
          setImageVulnDetails((prev) => ({
            ...prev,
            [identifier]: data.vulnerabilities || []
          }));
        } catch (err) {
          console.error('Failed to load details:', err);
          setImageVulnDetails((prev) => ({ ...prev, [identifier]: [] }));
        } finally {
          setLoadingImageDetails((prev) => ({ ...prev, [identifier]: false }));
        }
      };

      loadVulnDetails();
    });
  }, [expandedImages, API_BASE, projectDetails]);

  // Calculate overall statistics - aggregate from backend project summaries
  const overallStats = useMemo(() => {
    const safeProjects = Array.isArray(projects) ? projects : [];
    const safeAllScans = Array.isArray(allScans) ? allScans : [];

    const totalProjects = safeProjects.length;
    const totalScans = safeProjects.reduce((sum, p) => sum + (p?.totalScans || 0), 0);

    // En güncel açık sayılarını, her proje için her imajın "son taraması"na göre hesapla
    const projectImageLatestScan = buildProjectImageLatestScan(safeAllScans);

    const severityCount: Record<string, number> = {};
    let totalVulns = 0;

    safeProjects.forEach((p) => {
      if (!p?.projectName) return;
      const perImage = projectImageLatestScan[p.projectName];
      if (!perImage) {
        return;
      }

      Object.values(perImage).forEach((scan) => {
        if (!scan) return;
        totalVulns += scan.totalVulns || 0;
        if (scan.severityCount) {
          Object.keys(scan.severityCount).forEach((severity) => {
            severityCount[severity] =
              (severityCount[severity] || 0) + (scan.severityCount[severity] || 0);
          });
        }
      });
    });

    return { totalProjects, totalScans, totalVulns, severityCount };
  }, [projects, allScans]);

  // Filter projects based on search query
  const filteredProjects = useMemo(() => {
    const safeProjects = Array.isArray(projects) ? projects : [];
    if (!searchQuery.trim()) return safeProjects;
    const query = searchQuery.toLowerCase();
    return safeProjects.filter((p) => p?.projectName?.toLowerCase().includes(query));
  }, [projects, searchQuery]);

  // Filter projects by selected severity (for dashboard)
  const projectsBySeverity = useMemo(() => {
    if (!selectedSeverity) return [];

    const safeProjects = Array.isArray(projects) ? projects : [];
    const safeAllScans = Array.isArray(allScans) ? allScans : [];

    const projectImageLatestScan = buildProjectImageLatestScan(safeAllScans);

    return safeProjects.filter((p) => {
      if (!p?.projectName) return false;
      const perImage = projectImageLatestScan[p.projectName];
      if (!perImage) return false;

      let totalForSeverity = 0;
      Object.values(perImage).forEach((scan) => {
        if (scan?.severityCount) {
          totalForSeverity += scan.severityCount[selectedSeverity] || 0;
        }
      });
      return totalForSeverity > 0;
    });
  }, [projects, selectedSeverity, allScans]);

  // Prepare pie chart data for severity distribution
  const pieChartData = useMemo(() => {
    const data = [
      { name: 'CRITICAL', value: overallStats.severityCount['CRITICAL'] || 0, color: '#f38ba8' },
      { name: 'HIGH', value: overallStats.severityCount['HIGH'] || 0, color: '#fab387' },
      { name: 'MEDIUM', value: overallStats.severityCount['MEDIUM'] || 0, color: '#f9e2af' },
      { name: 'LOW', value: overallStats.severityCount['LOW'] || 0, color: '#89b4fa' },
    ].filter(item => item.value > 0);
    return data;
  }, [overallStats.severityCount]);

  // Prepare unified timeline chart data
  const unifiedTimelineData = useMemo(() => {
    const MAX_PROJECTS = 5; // En son taranan 5 proje

    const getSeriesKey = (scan: ScanSummary) => getTimelineSeriesKey(scan, separateVersions);

    // Her proje için en son tarama zamanını bul
    const projectLastScanTime = new Map<string, number>();
    allScans.forEach((scan) => {
      if (!scan.projectName) return;
      const scanTime = new Date(scan.modifiedAt).getTime();
      const currentLast = projectLastScanTime.get(scan.projectName) || 0;
      if (scanTime > currentLast) {
        projectLastScanTime.set(scan.projectName, scanTime);
      }
    });

    // Projeleri en son tarama zamanına göre sırala (en yeni önce)
    const sortedProjects = Array.from(projectLastScanTime.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, MAX_PROJECTS)
      .map(([projectName]) => projectName);

    // Seçilen projelerin tüm serilerini topla
    const seriesNameSet = new Set<string>();
    allScans.forEach((s) => {
      if (s.projectName && sortedProjects.includes(s.projectName)) {
        const key = getSeriesKey(s);
        if (key) seriesNameSet.add(key);
      }
    });
    const seriesNames = Array.from(seriesNameSet);
    const projectColors = [
      '#89b4fa', // blue
      '#f38ba8', // red
      '#a6e3a1', // green
      '#fab387', // peach
      '#cba6f7', // mauve
      '#f9e2af', // yellow
      '#94e2d5', // teal
      '#f5c2e7', // pink
    ];

    if (allScans.length === 0 || seriesNames.length === 0) {
      return { data: [], projectNames: seriesNames, projectColors };
    }

    const sortedScans = [...allScans].sort(
      (a, b) => new Date(a.modifiedAt).getTime() - new Date(b.modifiedAt).getTime()
    );

    const dataMap = new Map<string, Record<string, string | number | null>>();

    sortedScans.forEach((scan) => {
      const seriesKey = getSeriesKey(scan);
      if (!seriesKey) return;

      const d = new Date(scan.modifiedAt);
      const key = d.toISOString();

      if (!dataMap.has(key)) {
        const entry: Record<string, string | number | null> = {
          date: d.toLocaleString('tr-TR', {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
          }),
        };
        seriesNames.forEach((name) => {
          entry[name] = null;
        });
        dataMap.set(key, entry);
      }

      const entry = dataMap.get(key)!;
      entry[seriesKey] = scan.totalVulns;
    });

    const data = Array.from(dataMap.entries())
      .sort(([a], [b]) => (a < b ? -1 : 1))
      .map(([, value]) => value);

    return { data, projectNames: seriesNames, projectColors };
  }, [allScans, separateVersions]);

  // Project-specific timeline data (only for selected project on detail page)
  const projectTimelineData = useMemo(() => {
    if (!selectedProject) {
      return { data: [], seriesNames: [] as string[] };
    }

    const projectScans = allScans.filter((s) => s.projectName === selectedProject);
    if (projectScans.length === 0) {
      return { data: [], seriesNames: [] as string[] };
    }

    const getSeriesKey = (scan: ScanSummary) => getTimelineSeriesKey(scan, separateVersions);

    const seriesNameSet = new Set<string>();
    projectScans.forEach((s) => {
      const key = getSeriesKey(s);
      if (key) seriesNameSet.add(key);
    });
    const seriesNames = Array.from(seriesNameSet);

    const sortedScans = [...projectScans].sort(
      (a, b) => new Date(a.modifiedAt).getTime() - new Date(b.modifiedAt).getTime()
    );

    const dataMap = new Map<string, Record<string, string | number | null>>();

    sortedScans.forEach((scan) => {
      const seriesKey = getSeriesKey(scan);
      if (!seriesKey) return;

      const d = new Date(scan.modifiedAt);
      const key = d.toISOString();

      if (!dataMap.has(key)) {
        const entry: Record<string, string | number | null> = {
          date: d.toLocaleString('tr-TR', {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
          }),
        };
        seriesNames.forEach((name) => {
          entry[name] = null;
        });
        dataMap.set(key, entry);
      }

      const entry = dataMap.get(key)!;
      entry[seriesKey] = scan.totalVulns;
    });

    const data = Array.from(dataMap.entries())
      .sort(([a], [b]) => (a < b ? -1 : 1))
      .map(([, value]) => value);

    return { data, seriesNames };
  }, [allScans, selectedProject, separateVersions]);

  // Aggregated stats per project for ProjectsPage (latest scan per image)
  const projectListStats: Record<string, ProjectAggregatedStats> = useMemo(() => {
    const latestMap = buildProjectImageLatestScan(allScans);
    return aggregateProjectStats(latestMap);
  }, [allScans]);

  // Show loading or project detail page
  if (currentPage === 'project-detail') {
    if (loadingDetails || !projectDetails) {
      return (
        <div className="min-h-screen bg-catppuccin-base text-catppuccin-text">
          <header className="border-b border-catppuccin-surface0 bg-catppuccin-mantle/70 backdrop-blur">
            <div className="mx-auto flex max-w-5xl items-center justify-between px-4 py-3">
              <div className="flex items-center gap-3">
                <button
                  onClick={() => {
                    setCurrentPage('dashboard');
                    setSelectedProject(null);
                    setProjectDetails(null);
                  }}
                  className="px-3 py-1.5 rounded border border-catppuccin-surface1 hover:bg-catppuccin-surface0 hover:border-catppuccin-teal text-catppuccin-text transition-colors font-medium"
                >
                  ← Ana Sayfa
                </button>
              </div>
            </div>
          </header>
          <main className="mx-auto max-w-5xl px-4 py-6">
            <div className="flex items-center justify-center h-64">
              <p className="text-catppuccin-overlay1">Yükleniyor...</p>
            </div>
          </main>
        </div>
      );
    }
    return (
      <div className="min-h-screen bg-catppuccin-base text-catppuccin-text">
        <header className="border-b border-catppuccin-surface0 bg-catppuccin-mantle/70 backdrop-blur">
          <div className="mx-auto flex max-w-5xl items-center justify-between px-4 py-3">
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-2 text-sm">
                <button
                  onClick={() => {
                    setCurrentPage('dashboard');
                    setSelectedProject(null);
                    setProjectDetails(null);
                    setExpandedImages(new Set());
                    setImageVulnDetails({});
                    setLoadingImageDetails({});
                  }}
                  className="px-3 py-1.5 rounded border border-catppuccin-surface1 hover:bg-catppuccin-surface0 hover:border-catppuccin-teal text-catppuccin-text transition-colors font-medium"
                >
                  Ana Sayfa
                </button>
                <span className="text-catppuccin-overlay1">/</span>
                <button
                  onClick={() => {
                    setCurrentPage('projects');
                    setSelectedProject(null);
                    setProjectDetails(null);
                    setExpandedImages(new Set());
                    setImageVulnDetails({});
                    setLoadingImageDetails({});
                  }}
                  className="px-3 py-1.5 rounded border border-catppuccin-surface1 hover:bg-catppuccin-surface0 hover:border-catppuccin-teal text-catppuccin-text transition-colors font-medium"
                >
                  Projeler
                </button>
                <span className="text-catppuccin-overlay1">/</span>
                <span className="px-3 py-1.5 rounded bg-catppuccin-teal/10 text-catppuccin-teal font-semibold">
                  {projectDetails.projectName}
                </span>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <button
                onClick={() => {
                  setCurrentPage('project-comparison');
                  setSelectedScan1('');
                  setSelectedScan2('');
                  setComparisonData(null);
                  setComparisonError(null);
                }}
                className="px-4 py-2 rounded-lg border border-catppuccin-blue bg-catppuccin-blue/10 hover:bg-catppuccin-blue/20 text-catppuccin-blue font-medium transition-colors"
              >
                Karşılaştırma
              </button>
              <span className="text-xs text-catppuccin-overlay1">DockerScan</span>
            </div>
          </div>
        </header>

        <main className="mx-auto max-w-5xl px-4 py-6 space-y-6">
          <section className="grid gap-4 md:grid-cols-4">
            <div className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
              <p className="text-xs font-medium uppercase tracking-wide text-catppuccin-overlay1">
                Toplam Tarama
              </p>
              <p className="mt-2 text-3xl font-semibold">{projectDetails.totalScans}</p>
            </div>
            <div className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
              <p className="text-xs font-medium uppercase tracking-wide text-catppuccin-overlay1">
                Toplam Açık
              </p>
              <p className="mt-2 text-3xl font-semibold">{projectDetails.totalVulns}</p>
            </div>
            <div className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
              <p className="text-xs font-medium uppercase tracking-wide text-catppuccin-overlay1">
                CRITICAL
              </p>
              <p className="mt-2 text-3xl font-semibold text-catppuccin-red">
                {projectDetails.severityCount['CRITICAL'] || 0}
              </p>
            </div>
            <div className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
              <p className="text-xs font-medium uppercase tracking-wide text-catppuccin-overlay1">HIGH</p>
              <p className="mt-2 text-3xl font-semibold text-catppuccin-peach">
                {projectDetails.severityCount['HIGH'] || 0}
              </p>
            </div>
          </section>

          {/* Project-specific timeline chart */}
          <section className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-semibold text-catppuccin-text">
                {projectDetails.projectName} – Açık Sayısı Zaman Çizelgesi
              </h2>
              <button
                onClick={() => setSeparateVersions(!separateVersions)}
                className="text-xs px-3 py-1.5 rounded border border-catppuccin-surface1 hover:bg-catppuccin-surface0 text-catppuccin-subtext0 transition-colors"
                title={separateVersions ? 'Versiyonları birleştir (genel trend)' : 'Versiyonları ayrı göster'}
              >
                {separateVersions ? '📊 Birleştirilmiş' : '🔀 Versiyonları Ayrı'}
              </button>
            </div>
            {projectTimelineData.data.length > 0 ? (
              <>
                <ResponsiveContainer width="100%" height={260}>
                  <LineChart data={projectTimelineData.data}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#313244" />
                    <XAxis
                      dataKey="date"
                      stroke="#6c7086"
                      style={{ fontSize: '10px' }}
                      angle={-35}
                      textAnchor="end"
                      height={70}
                    />
                    <YAxis
                      stroke="#6c7086"
                      style={{ fontSize: '11px' }}
                      label={{
                        value: 'Açık Sayısı',
                        angle: -90,
                        position: 'insideLeft',
                        style: { fontSize: '11px', fill: '#6c7086' },
                      }}
                    />
                    <Tooltip content={<TimelineTooltip />} />
                    {projectTimelineData.seriesNames.map((seriesName, index) => (
                      <Line
                        key={seriesName}
                        type="monotone"
                        dataKey={seriesName}
                        stroke={
                          unifiedTimelineData.projectColors[
                            index % unifiedTimelineData.projectColors.length
                          ]
                        }
                        strokeWidth={2}
                        dot={{
                          fill:
                            unifiedTimelineData.projectColors[
                              index % unifiedTimelineData.projectColors.length
                            ],
                          r: 4,
                        }}
                        activeDot={{ r: 6 }}
                        connectNulls
                        name={seriesName}
                      />
                    ))}
                  </LineChart>
                </ResponsiveContainer>
                <div className="mt-3 flex flex-wrap gap-3 text-xs text-catppuccin-overlay1">
                  {projectTimelineData.seriesNames.map((seriesName, index) => (
                    <div key={seriesName} className="flex items-center gap-2">
                      <div
                        className="w-3 h-3 rounded"
                        style={{
                          backgroundColor:
                            unifiedTimelineData.projectColors[
                              index % unifiedTimelineData.projectColors.length
                            ],
                        }}
                      ></div>
                      <span>{seriesName}</span>
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <div className="flex items-center justify-center h-[260px] text-catppuccin-overlay1 text-sm">
                Bu proje için henüz zaman çizelgesi oluşturulacak tarama verisi yok.
              </div>
            )}
          </section>

          <section className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
            <h2 className="text-sm font-semibold text-catppuccin-text mb-4">İmajlar ve Taramalar</h2>

            {projectDetails.images.length === 0 ? (
              <div className="text-center py-8 text-catppuccin-overlay1">Henüz tarama bulunamadı.</div>
            ) : (
              <div className="space-y-4">
                {projectDetails.images.map((image) => {
                  const isExpanded = expandedImages.has(image.imageName);
                  const grade = image.grade;
                  const color = gradeColor(grade);
                  const toggleExpand = (e?: React.MouseEvent) => {
                    e?.stopPropagation();
                    setExpandedImages((prev) => {
                      const newSet = new Set(prev);
                      if (newSet.has(image.imageName)) {
                        newSet.delete(image.imageName);
                      } else {
                        newSet.add(image.imageName);
                      }
                      return newSet;
                    });
                  };

                  return (
                    <div key={image.imageName} className="space-y-0">
                      <div
                        role="button"
                        tabIndex={0}
                        onClick={toggleExpand}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter' || e.key === ' ') {
                            e.preventDefault();
                            toggleExpand();
                          }
                        }}
                        aria-expanded={isExpanded}
                        className={`border rounded-lg p-4 cursor-pointer hover:opacity-90 transition-all focus:outline-none focus-visible:ring-2 focus-visible:ring-catppuccin-blue ${
                          color === 'catppuccin-green'
                            ? 'border-catppuccin-green bg-catppuccin-green/10'
                            : color === 'catppuccin-blue'
                              ? 'border-catppuccin-blue bg-catppuccin-blue/10'
                              : color === 'catppuccin-yellow'
                                ? 'border-catppuccin-yellow bg-catppuccin-yellow/10'
                                : 'border-catppuccin-red bg-catppuccin-red/10'
                        }`}
                      >
                        <div className="flex items-center justify-between mb-3">
                          <div className="flex items-center gap-3">
                            <div
                              className={`w-16 h-16 rounded-lg flex items-center justify-center text-2xl font-bold ${
                                color === 'catppuccin-green'
                                  ? 'bg-catppuccin-green/20 text-catppuccin-green'
                                  : color === 'catppuccin-blue'
                                    ? 'bg-catppuccin-blue/20 text-catppuccin-blue'
                                    : color === 'catppuccin-yellow'
                                      ? 'bg-catppuccin-yellow/20 text-catppuccin-yellow'
                                      : 'bg-catppuccin-red/20 text-catppuccin-red'
                              }`}
                            >
                              {grade}
                            </div>
                            <div>
                              <h3 className="text-base font-semibold text-catppuccin-text">
                                {image.imageName}
                              </h3>
                              <p className="text-xs text-catppuccin-overlay1 mt-1">
                                {image.scans.length} tarama • Son tarama:{' '}
                                {new Date(image.lastScan).toLocaleString()}
                              </p>
                            </div>
                          </div>
                          <div className="flex items-center gap-6 text-sm">
                            <div className="text-right">
                              <span className="text-catppuccin-overlay1 text-xs">Toplam: </span>
                              <span className="font-bold text-lg text-catppuccin-text">
                                {image.totalVulns}
                              </span>
                            </div>
                            <div className="flex gap-3">
                              {image.severityCount['CRITICAL'] > 0 && (
                                <span className="text-catppuccin-red font-bold text-base">
                                  C:{image.severityCount['CRITICAL']}
                                </span>
                              )}
                              {image.severityCount['HIGH'] > 0 && (
                                <span className="text-catppuccin-peach font-bold text-base">
                                  H:{image.severityCount['HIGH']}
                                </span>
                              )}
                              {image.severityCount['MEDIUM'] > 0 && (
                                <span className="text-catppuccin-yellow font-bold text-base">
                                  M:{image.severityCount['MEDIUM']}
                                </span>
                              )}
                              {image.severityCount['LOW'] > 0 && (
                                <span className="text-catppuccin-blue font-bold text-base">
                                  L:{image.severityCount['LOW']}
                                </span>
                              )}
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center gap-1 text-xs text-catppuccin-subtext0 select-none">
                          <span>{isExpanded ? 'Tarama Geçmişini Gizle' : 'Tarama Geçmişini Göster'}</span>
                          <span
                            className={`inline-block transition-transform ${isExpanded ? 'rotate-180' : ''}`}
                            aria-hidden="true"
                          >
                            ▾
                          </span>
                        </div>
                      </div>

                      {isExpanded && (
                        <div className="mt-2 border border-catppuccin-surface0 rounded-lg p-4 bg-catppuccin-mantle/60">
                          <h4 className="text-sm font-semibold text-catppuccin-text mb-3">
                            Tarama Geçmişi ({image.scans.length} tarama)
                          </h4>
                          <div className="space-y-2">
                            {image.scans.map((scan) => {
                              const scanGrade = { grade: scan.grade, color: gradeColor(scan.grade) };
                              const isScanExpanded = expandedImages.has(scan.filename);
                              const toggleScanExpand = (e?: React.MouseEvent) => {
                                e?.stopPropagation();
                                setExpandedImages((prev) => {
                                  const newSet = new Set(prev);
                                  if (newSet.has(scan.filename)) {
                                    newSet.delete(scan.filename);
                                  } else {
                                    newSet.add(scan.filename);
                                  }
                                  return newSet;
                                });
                              };

                              return (
                                <div key={scan.filename} className="space-y-0">
                                  <div
                                    role="button"
                                    tabIndex={0}
                                    onClick={toggleScanExpand}
                                    onKeyDown={(e) => {
                                      if (e.key === 'Enter' || e.key === ' ') {
                                        e.preventDefault();
                                        toggleScanExpand();
                                      }
                                    }}
                                    aria-expanded={isScanExpanded}
                                    className="border border-catppuccin-surface0 rounded-lg p-3 bg-catppuccin-base/60 hover:bg-catppuccin-base/80 transition-colors cursor-pointer focus:outline-none focus-visible:ring-2 focus-visible:ring-catppuccin-blue"
                                  >
                                    <div className="flex items-center justify-between">
                                      <div className="flex items-center gap-3">
                                        <div
                                          className={`w-10 h-10 rounded flex items-center justify-center text-sm font-bold ${
                                            scanGrade.color === 'catppuccin-green'
                                              ? 'bg-catppuccin-green/20 text-catppuccin-green'
                                              : scanGrade.color === 'catppuccin-blue'
                                                ? 'bg-catppuccin-blue/20 text-catppuccin-blue'
                                                : scanGrade.color === 'catppuccin-yellow'
                                                  ? 'bg-catppuccin-yellow/20 text-catppuccin-yellow'
                                                  : 'bg-catppuccin-red/20 text-catppuccin-red'
                                          }`}
                                        >
                                          {scanGrade.grade}
                                        </div>
                                        <div>
                                          <p className="text-sm font-semibold text-catppuccin-text">
                                            {scan.imageName
                                               ? `${scan.imageName}${scan.tag ? ':' + scan.tag : ''}`
                                              : (scan.artifactName || scan.filename)
                                            }
                                          </p>
                                          <p className="text-xs text-catppuccin-overlay1 mt-0.5">
                                            {new Date(scan.modifiedAt).toLocaleString()}
                                          </p>
                                          <button
                                            type="button"
                                            onClick={(e) => {
                                              e.preventDefault();
                                              e.stopPropagation();
                                              setSelectedScan1(scan.filename);
                                              setSelectedScan2('');
                                              setComparisonData(null);
                                              setComparisonError(null);
                                              setCurrentPage('project-comparison');
                                            }}
                                            className="text-xs text-catppuccin-blue hover:text-catppuccin-sapphire mt-1 underline cursor-pointer relative z-10 bg-transparent border-none p-0"
                                            style={{ position: 'relative', zIndex: 10 }}
                                          >
                                            Karşılaştır
                                          </button>
                                        </div>
                                      </div>
                                      <div className="flex items-center gap-4 text-xs">
                                        <div className="text-right">
                                          <span className="text-catppuccin-overlay1">Toplam: </span>
                                          <span className="font-semibold text-catppuccin-text">
                                            {scan.totalVulns}
                                          </span>
                                        </div>
                                        <div className="flex gap-2">
                                          {scan.severityCount['CRITICAL'] > 0 && (
                                            <span className="text-catppuccin-red font-semibold">
                                              C:{scan.severityCount['CRITICAL']}
                                            </span>
                                          )}
                                          {scan.severityCount['HIGH'] > 0 && (
                                            <span className="text-catppuccin-peach font-semibold">
                                              H:{scan.severityCount['HIGH']}
                                            </span>
                                          )}
                                          {scan.severityCount['MEDIUM'] > 0 && (
                                            <span className="text-catppuccin-yellow font-semibold">
                                              M:{scan.severityCount['MEDIUM']}
                                            </span>
                                          )}
                                          {scan.severityCount['LOW'] > 0 && (
                                            <span className="text-catppuccin-blue font-semibold">
                                              L:{scan.severityCount['LOW']}
                                            </span>
                                          )}
                                        </div>
                                        <span
                                          className={`inline-block text-catppuccin-subtext0 transition-transform select-none ${isScanExpanded ? 'rotate-180' : ''}`}
                                          aria-hidden="true"
                                        >
                                          ▾
                                        </span>
                                      </div>
                                    </div>
                                  </div>

                                  {isScanExpanded && (
                                    <div className="mt-1 ml-4 border-l-2 border-catppuccin-surface0 pl-3">
                                      {loadingImageDetails[scan.filename] ? (
                                        <div className="text-center py-4 text-catppuccin-overlay1 text-xs">
                                          Yükleniyor...
                                        </div>
                                      ) : (imageVulnDetails[scan.filename] || []).length === 0 ? (
                                        <div className="text-center py-4 text-catppuccin-overlay1 text-xs">
                                          Bu raporda açık bulunamadı.
                                        </div>
                                      ) : (
                                        <div className="space-y-2 max-h-[400px] overflow-y-auto">
                                          {(imageVulnDetails[scan.filename] || []).map((vuln, idx) => {
                                            const severityColor =
                                              vuln.Severity === 'CRITICAL'
                                                ? 'text-catppuccin-red'
                                                : vuln.Severity === 'HIGH'
                                                  ? 'text-catppuccin-peach'
                                                  : vuln.Severity === 'MEDIUM'
                                                    ? 'text-catppuccin-yellow'
                                                    : vuln.Severity === 'LOW'
                                                      ? 'text-catppuccin-blue'
                                                      : 'text-catppuccin-overlay1';
                                            return (
                                              <div
                                                key={`${vuln.VulnerabilityID}-${idx}`}
                                                className="border border-catppuccin-surface0 rounded p-3 bg-catppuccin-base/40"
                                              >
                                                <div className="flex items-start justify-between mb-1">
                                                  <div>
                                                    <span className="font-mono text-xs text-catppuccin-teal">
                                                      {vuln.VulnerabilityID}
                                                    </span>
                                                    <span className={`ml-2 text-xs font-semibold ${severityColor}`}>
                                                      {vuln.Severity}
                                                    </span>
                                                  </div>
                                                  {vuln.PrimaryURL && (
                                                    <a
                                                      href={vuln.PrimaryURL}
                                                      target="_blank"
                                                      rel="noopener noreferrer"
                                                      className="text-xs text-catppuccin-blue hover:underline"
                                                    >
                                                      Detay →
                                                    </a>
                                                  )}
                                                </div>
                                                <h4 className="text-xs font-semibold text-catppuccin-text mb-1">
                                                  {vuln.Title || vuln.VulnerabilityID}
                                                </h4>
                                                <div className="text-xs text-catppuccin-overlay1">
                                                  <span className="font-mono">{vuln.PkgName}</span>
                                                  {vuln.InstalledVersion && (
                                                    <span className="ml-2">
                                                      v{vuln.InstalledVersion}
                                                      {vuln.FixedVersion && (
                                                        <span className="text-catppuccin-teal ml-1">
                                                          → v{vuln.FixedVersion}
                                                        </span>
                                                      )}
                                                    </span>
                                                  )}
                                                </div>
                                              </div>
                                            );
                                          })}
                                        </div>
                                      )}
                                    </div>
                                  )}
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </section>
        </main>
      </div>
    );
  }

  // Project Comparison Page
  if (currentPage === 'project-comparison') {
    if (!selectedProject || !projectDetails) {
      return (
        <div className="min-h-screen bg-catppuccin-base text-catppuccin-text">
          <header className="border-b border-catppuccin-surface0 bg-catppuccin-mantle/70 backdrop-blur">
            <div className="mx-auto flex max-w-5xl items-center justify-between px-4 py-3">
              <div className="flex items-center gap-3">
                <button
                  onClick={() => {
                    setCurrentPage('dashboard');
                    setSelectedProject(null);
                    setProjectDetails(null);
                  }}
                  className="px-3 py-1.5 rounded border border-catppuccin-surface1 hover:bg-catppuccin-surface0 hover:border-catppuccin-teal text-catppuccin-text transition-colors font-medium"
                >
                  ← Ana Sayfa
                </button>
              </div>
            </div>
          </header>
          <main className="mx-auto max-w-5xl px-4 py-6">
            <div className="flex items-center justify-center h-64">
              <p className="text-catppuccin-overlay1">Proje seçilmedi veya yükleniyor...</p>
            </div>
          </main>
        </div>
      );
    }

    // Filter scans for selected project only
    const projectScans = allScans.filter((scan) => scan.projectName === selectedProject);

    return (
      <div className="min-h-screen bg-catppuccin-base text-catppuccin-text">
        <header className="border-b border-catppuccin-surface0 bg-catppuccin-mantle/70 backdrop-blur">
          <div className="mx-auto flex max-w-5xl items-center justify-between px-4 py-3">
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-2 text-sm">
                <button
                  onClick={() => {
                    setCurrentPage('dashboard');
                    setSelectedProject(null);
                    setProjectDetails(null);
                    setComparisonData(null);
                    setSelectedScan1('');
                    setSelectedScan2('');
                  }}
                  className="px-3 py-1.5 rounded border border-catppuccin-surface1 hover:bg-catppuccin-surface0 hover:border-catppuccin-teal text-catppuccin-text transition-colors font-medium"
                >
                  Ana Sayfa
                </button>
                <span className="text-catppuccin-overlay1">/</span>
                <button
                  onClick={() => {
                    setCurrentPage('projects');
                    setSelectedProject(null);
                    setProjectDetails(null);
                  }}
                  className="px-3 py-1.5 rounded border border-catppuccin-surface1 hover:bg-catppuccin-surface0 hover:border-catppuccin-teal text-catppuccin-text transition-colors font-medium"
                >
                  Projeler
                </button>
                <span className="text-catppuccin-overlay1">/</span>
                <button
                  onClick={() => {
                    setCurrentPage('project-detail');
                    setComparisonData(null);
                    setSelectedScan1('');
                    setSelectedScan2('');
                    setComparisonError(null);
                  }}
                  className="px-3 py-1.5 rounded border border-catppuccin-surface1 hover:bg-catppuccin-surface0 hover:border-catppuccin-teal text-catppuccin-text transition-colors font-medium"
                >
                  {projectDetails.projectName}
                </button>
                <span className="text-catppuccin-overlay1">/</span>
                <span className="px-3 py-1.5 rounded bg-catppuccin-teal/10 text-catppuccin-teal font-semibold">
                  Karşılaştırma
                </span>
              </div>
            </div>
            <span className="text-xs text-catppuccin-overlay1">DockerScan</span>
          </div>
        </header>

        <main className="mx-auto max-w-6xl px-4 py-6 space-y-6">
          {/* Scan Selection */}
          <section className="bg-catppuccin-mantle/60 border border-catppuccin-surface0 rounded-xl p-6">
            <h2 className="text-xl font-semibold text-catppuccin-text mb-4">Tarama Seçimi - {projectDetails.projectName}</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-catppuccin-text mb-2">
                  Scan 1 (İlk Scan / Eski)
                </label>
                <select
                  value={selectedScan1}
                  onChange={(e) => {
                    setSelectedScan1(e.target.value);
                    setComparisonError(null);
                    setComparisonData(null);
                  }}
                  className="w-full px-3 py-2 bg-catppuccin-base border border-catppuccin-surface0 rounded text-catppuccin-text"
                >
                  <option value="">Scan seçin...</option>
                  {projectScans.map((scan) => (
                    <option key={scan.filename} value={scan.filename}>
                      {scan.imageName
                         ? `${scan.imageName}${scan.tag ? ':' + scan.tag : ''}`
                        : (scan.artifactName || scan.filename)
                      } - {new Date(scan.modifiedAt).toLocaleString()}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-catppuccin-text mb-2">
                  Scan 2 (İkinci Scan / Yeni)
                </label>
                <select
                  value={selectedScan2}
                  onChange={(e) => {
                    setSelectedScan2(e.target.value);
                    setComparisonError(null);
                    setComparisonData(null);
                  }}
                  className="w-full px-3 py-2 bg-catppuccin-base border border-catppuccin-surface0 rounded text-catppuccin-text"
                >
                  <option value="">Scan seçin...</option>
                  {projectScans
                    .filter(scan => scan.filename !== selectedScan1)
                    .map((scan) => (
                    <option key={scan.filename} value={scan.filename}>
                        {scan.imageName
                         ? `${scan.imageName}${scan.tag ? ':' + scan.tag : ''}`
                          : (scan.artifactName || scan.filename)
                        } - {new Date(scan.modifiedAt).toLocaleString()}
                    </option>
                  ))}
                </select>
              </div>
              <button
                onClick={compareScans}
                disabled={!selectedScan1 || !selectedScan2 || comparisonLoading}
                className="w-full px-4 py-2 bg-catppuccin-blue text-catppuccin-base rounded hover:bg-catppuccin-sapphire disabled:opacity-50 disabled:cursor-not-allowed font-medium"
              >
                {comparisonLoading ? 'Karşılaştırılıyor...' : 'Karşılaştır'}
              </button>
              {comparisonError && (
                <div className="mt-4 p-4 bg-catppuccin-red/20 border border-catppuccin-red/30 rounded-lg">
                  <p className="text-sm text-catppuccin-red font-medium">Hata:</p>
                  <p className="text-xs text-catppuccin-red/80 mt-1">{comparisonError}</p>
                </div>
              )}
            </div>
          </section>

          {/* Comparison Results */}
          {comparisonData && (
            <section className="space-y-6">
              {/* Summary Cards */}
              <div className="grid grid-cols-4 gap-4">
                <div className="bg-catppuccin-green/20 border border-catppuccin-green/30 rounded-lg p-4">
                  <div className="text-2xl font-bold text-catppuccin-green">+{comparisonData.summary.added}</div>
                  <div className="text-xs text-catppuccin-overlay1 mt-1">Yeni Eklenen</div>
                </div>
                <div className="bg-catppuccin-red/20 border border-catppuccin-red/30 rounded-lg p-4">
                  <div className="text-2xl font-bold text-catppuccin-red">-{comparisonData.summary.removed}</div>
                  <div className="text-xs text-catppuccin-overlay1 mt-1">Kapatılan</div>
                </div>
                <div className="bg-catppuccin-yellow/20 border border-catppuccin-yellow/30 rounded-lg p-4">
                  <div className="text-2xl font-bold text-catppuccin-yellow">~{comparisonData.summary.changed}</div>
                  <div className="text-xs text-catppuccin-overlay1 mt-1">Değişen</div>
                </div>
                <div className="bg-catppuccin-surface0 border border-catppuccin-surface1 rounded-lg p-4">
                  <div className="text-2xl font-bold text-catppuccin-text">={comparisonData.summary.unchanged}</div>
                  <div className="text-xs text-catppuccin-overlay1 mt-1">Değişmeyen</div>
                </div>
              </div>

              {/* Diff/Meld Style View */}
              <div className="bg-catppuccin-mantle/60 border border-catppuccin-surface0 rounded-xl p-6">
                <h2 className="text-xl font-semibold text-catppuccin-text mb-4">Karşılaştırma Detayları (Diff/Meld Görünümü)</h2>
                <div className="grid grid-cols-2 gap-4">
                  {/* Left: Scan 1 (Removed - Red) */}
                  <div className="border border-catppuccin-red/30 rounded-lg p-4 bg-catppuccin-red/5">
                    <div className="text-sm font-semibold text-catppuccin-red mb-3">
                      Scan 1 - Kaldırılanlar ({comparisonData.summary.removed})
                    </div>
                    <div className="text-xs text-catppuccin-overlay1 mb-2">
                      {comparisonData.scan1.artifactName} - {new Date(comparisonData.scan1.scanDate).toLocaleString()}
                    </div>
                    <div className="space-y-2 max-h-96 overflow-y-auto">
                      {(comparisonData.removed || []).map((vuln, idx) => (
                        <div key={idx} className="bg-catppuccin-red/10 border-l-4 border-catppuccin-red p-2 rounded">
                          <div className="text-xs font-mono text-catppuccin-teal">{vuln.VulnerabilityID}</div>
                          <div className="text-xs text-catppuccin-text mt-1">{vuln.Title || vuln.VulnerabilityID}</div>
                          <div className="text-xs text-catppuccin-overlay1 mt-1">
                            {vuln.PkgName} {vuln.InstalledVersion}
                          </div>
                        </div>
                      ))}
                      {(!comparisonData.removed || comparisonData.removed.length === 0) && (
                        <div className="text-xs text-catppuccin-overlay1 text-center py-4">Kaldırılan vulnerability yok</div>
                      )}
                    </div>
                  </div>

                  {/* Right: Scan 2 (Added - Green) */}
                  <div className="border border-catppuccin-green/30 rounded-lg p-4 bg-catppuccin-green/5">
                    <div className="text-sm font-semibold text-catppuccin-green mb-3">
                      Scan 2 - Yeni Eklenenler ({comparisonData.summary.added})
                    </div>
                    <div className="text-xs text-catppuccin-overlay1 mb-2">
                      {comparisonData.scan2.artifactName} - {new Date(comparisonData.scan2.scanDate).toLocaleString()}
                    </div>
                    <div className="space-y-2 max-h-96 overflow-y-auto">
                      {(comparisonData.added || []).map((vuln, idx) => (
                        <div key={idx} className="bg-catppuccin-green/10 border-l-4 border-catppuccin-green p-2 rounded">
                          <div className="text-xs font-mono text-catppuccin-teal">{vuln.VulnerabilityID}</div>
                          <div className="text-xs text-catppuccin-text mt-1">{vuln.Title || vuln.VulnerabilityID}</div>
                          <div className="text-xs text-catppuccin-overlay1 mt-1">
                            {vuln.PkgName} {vuln.InstalledVersion}
                          </div>
                        </div>
                      ))}
                      {(!comparisonData.added || comparisonData.added.length === 0) && (
                        <div className="text-xs text-catppuccin-overlay1 text-center py-4">Yeni eklenen vulnerability yok</div>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            </section>
          )}
        </main>
      </div>
    );
  }

  if (currentPage === 'security') {
    return (
      <SecurityPage
        apiBase={API_BASE}
        goDashboard={() => setCurrentPage('dashboard')}
      />
    );
  }

  if (currentPage === 'projects') {
    return (
      <ProjectsPage
        projects={projects}
        filteredProjects={filteredProjects}
        loading={loading}
        error={error}
        allScans={allScans}
        projectListStats={projectListStats}
        searchQuery={searchQuery}
        setSearchQuery={setSearchQuery}
        onSelectProject={(projectName) => {
          setSelectedProject(projectName);
          setCurrentPage('project-detail');
        }}
        goDashboard={() => setCurrentPage('dashboard')}
        apiBase={API_BASE}
      />
    );
  }

  // 404 Not Found page
  if (currentPage === 'not-found') {
    return (
      <div className="min-h-screen bg-catppuccin-base text-catppuccin-text">
        <header className="border-b border-catppuccin-surface0 bg-catppuccin-mantle/70 backdrop-blur">
          <div className="mx-auto flex max-w-5xl items-center justify-between px-4 py-3">
            <div className="flex items-center gap-3">
              <button
                onClick={() => setCurrentPage('dashboard')}
                className="px-3 py-1.5 rounded border border-catppuccin-surface1 hover:bg-catppuccin-surface0 hover:border-catppuccin-teal text-catppuccin-text transition-colors font-medium"
              >
                ← Ana Sayfa
              </button>
            </div>
            <span className="text-xs text-catppuccin-overlay1">DockerScan</span>
          </div>
        </header>

        <main className="mx-auto max-w-5xl px-4 py-6">
          <div className="flex flex-col items-center justify-center min-h-[60vh] text-center space-y-6">
            <div className="text-9xl font-bold text-catppuccin-overlay1">404</div>
            <div className="space-y-2">
              <h1 className="text-3xl font-semibold text-catppuccin-text">Sayfa Bulunamadı</h1>
              <p className="text-catppuccin-overlay1">
                Aradığınız sayfa mevcut değil veya taşınmış olabilir.
              </p>
            </div>
            <div className="flex gap-4 mt-6">
              <button
                onClick={() => setCurrentPage('dashboard')}
                className="px-6 py-3 rounded-lg border border-catppuccin-blue bg-catppuccin-blue/10 hover:bg-catppuccin-blue/20 text-catppuccin-blue font-medium transition-colors"
              >
                Ana Sayfaya Dön
              </button>
              <button
                onClick={() => setCurrentPage('projects')}
                className="px-6 py-3 rounded-lg border border-catppuccin-surface1 hover:bg-catppuccin-surface0 text-catppuccin-text font-medium transition-colors"
              >
                Projeleri Görüntüle
              </button>
            </div>
          </div>
        </main>
      </div>
    );
  }

  // Dashboard page
  return (
    <DashboardPage
      apiBase={API_BASE}
      overallStats={overallStats}
      selectedSeverity={selectedSeverity}
      setSelectedSeverity={setSelectedSeverity}
      separateVersions={separateVersions}
      setSeparateVersions={setSeparateVersions}
      pieChartData={pieChartData}
      unifiedTimelineData={unifiedTimelineData}
      projectsBySeverity={projectsBySeverity}
      loading={loading}
      error={error}
      onGoProjects={() => setCurrentPage('projects')}
      onGoSecurity={() => setCurrentPage('security')}
      onOpenProject={(projectName) => {
        setSelectedProject(projectName);
        setCurrentPage('project-detail');
      }}
    />
  );
}

export default App;
