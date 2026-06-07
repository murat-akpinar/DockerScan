import React, { useEffect, useState, useMemo } from 'react';
import { useLanguage, LangToggle } from '../i18n/LanguageContext';

type CheckovFinding = {
  checkId: string;
  name: string;
  filePath: string;
  line: number;
};

type CheckovScan = {
  filename: string;
  projectName: string;
  serviceName: string;
  tag: string;
  scannedAt: string;
  passed: number;
  failed: number;
  skipped: number;
  findings: CheckovFinding[];
};

type OsvVuln = {
  id: string;
  summary: string;
};

type OsvPackage = {
  name: string;
  version: string;
  ecosystem: string;
  vulnCount: number;
  vulns: OsvVuln[];
};

type OsvSource = {
  path: string;
  type: string;
  packages: OsvPackage[];
};

type OsvScan = {
  filename: string;
  projectName: string;
  serviceName: string;
  tag: string;
  scannedAt: string;
  totalVulns: number;
  sources: OsvSource[];
};

type Tab = 'checkov' | 'osv';

type SecurityPageProps = {
  apiBase: string;
  goDashboard: () => void;
};

// ── Grade helpers ─────────────────────────────────────────────────────────────
// Checkov: IaC miskonfigürasyon sayısına göre
// A: 0  B: ≤2  C: ≤5  D: ≤10  F: >10
function checkovGrade(failed: number): string {
  if (failed === 0) return 'A';
  if (failed <= 2)  return 'B';
  if (failed <= 5)  return 'C';
  if (failed <= 10) return 'D';
  return 'F';
}

// OSV: bağımlılık zafiyet sayısına göre (Trivy ile aynı eşikler)
// A: 0  B: ≤2  C: ≤5  D: ≤9  F: ≥10
function osvGrade(totalVulns: number): string {
  if (totalVulns === 0) return 'A';
  if (totalVulns <= 2)  return 'B';
  if (totalVulns <= 5)  return 'C';
  if (totalVulns <= 9)  return 'D';
  return 'F';
}

const GRADE_ORDER: Record<string, number> = { A: 0, B: 1, C: 2, D: 3, F: 4 };

function worstGrade(grades: string[]): string {
  return grades.reduce((w, g) => (GRADE_ORDER[g] ?? 0) > (GRADE_ORDER[w] ?? 0) ? g : w, 'A');
}

function gradeColorClass(grade: string): string {
  if (grade === 'A') return 'catppuccin-green';
  if (grade === 'B') return 'catppuccin-blue';
  if (grade === 'C') return 'catppuccin-yellow';
  return 'catppuccin-red';
}

// ── Grade badge (birebir App.tsx ile aynı) ────────────────────────────────────
const GradeBadge: React.FC<{ grade: string; size?: 'lg' | 'sm' }> = ({ grade, size = 'lg' }) => {
  const color = gradeColorClass(grade);
  const dim = size === 'lg' ? 'w-16 h-16 text-2xl' : 'w-10 h-10 text-sm';
  const bg =
    color === 'catppuccin-green'  ? 'bg-catppuccin-green/20  text-catppuccin-green'  :
    color === 'catppuccin-blue'   ? 'bg-catppuccin-blue/20   text-catppuccin-blue'   :
    color === 'catppuccin-yellow' ? 'bg-catppuccin-yellow/20 text-catppuccin-yellow' :
                                    'bg-catppuccin-red/20    text-catppuccin-red';
  return (
    <div className={`${dim} rounded-lg flex items-center justify-center font-bold shrink-0 ${bg}`}>
      {grade}
    </div>
  );
};

// ── Card border class based on grade ─────────────────────────────────────────
function gradeBorderClass(grade: string): string {
  const color = gradeColorClass(grade);
  if (color === 'catppuccin-green')  return 'border-catppuccin-green  bg-catppuccin-green/10';
  if (color === 'catppuccin-blue')   return 'border-catppuccin-blue   bg-catppuccin-blue/10';
  if (color === 'catppuccin-yellow') return 'border-catppuccin-yellow bg-catppuccin-yellow/10';
  return 'border-catppuccin-red bg-catppuccin-red/10';
}

// ── Main component ────────────────────────────────────────────────────────────
const SecurityPage: React.FC<SecurityPageProps> = ({ apiBase, goDashboard }) => {
  const [activeTab, setActiveTab] = useState<Tab>('checkov');
  const [checkovScans, setCheckovScans] = useState<CheckovScan[]>([]);
  const [osvScans, setOsvScans] = useState<OsvScan[]>([]);
  const { t } = useLanguage();
  const [loading, setLoading] = useState(true);
  const [expandedScans, setExpandedScans] = useState<Set<string>>(new Set());
  const [selectedProject, setSelectedProject] = useState<string | null>(null);

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      try {
        const [cRes, oRes] = await Promise.all([
          fetch(`${apiBase}/api/checkov`),
          fetch(`${apiBase}/api/osv`),
        ]);
        if (cRes.ok) setCheckovScans(await cRes.json());
        if (oRes.ok) setOsvScans(await oRes.json());
      } catch (e) {
        console.error('Failed to load security scans:', e);
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [apiBase]);

  const toggle = (key: string) => {
    setExpandedScans((prev) => {
      const next = new Set(prev);
      next.has(key) ? next.delete(key) : next.add(key);
      return next;
    });
  };

  const projectNames = useMemo(() => {
    const names = new Set<string>();
    checkovScans.forEach((s) => names.add(s.projectName));
    osvScans.forEach((s) => names.add(s.projectName));
    return Array.from(names).sort();
  }, [checkovScans, osvScans]);

  const projectStats = useMemo(() => {
    const stats: Record<string, {
      checkovFailed: number;
      osvVulns: number;
      lastScan: string;
      grade: string;
    }> = {};
    for (const name of projectNames) {
      const checkov = checkovScans.filter((s) => s.projectName === name);
      const osv = osvScans.filter((s) => s.projectName === name);
      const failed = checkov.reduce((sum, s) => sum + s.failed, 0);
      const vulns  = osv.reduce((sum, s) => sum + s.totalVulns, 0);
      const allDates = [
        ...checkov.map((s) => s.scannedAt),
        ...osv.map((s) => s.scannedAt),
      ].filter(Boolean).sort().reverse();

      const grades = [
        ...checkov.map((s) => checkovGrade(s.failed)),
        ...osv.map((s) => osvGrade(s.totalVulns)),
      ];
      stats[name] = {
        checkovFailed: failed,
        osvVulns: vulns,
        lastScan: allDates[0] || '',
        grade: grades.length > 0 ? worstGrade(grades) : 'A',
      };
    }
    return stats;
  }, [projectNames, checkovScans, osvScans]);

  // ── Project detail view ────────────────────────────────────────────────────
  if (selectedProject) {
    const filteredCheckov = checkovScans.filter((s) => s.projectName === selectedProject);
    const filteredOsv     = osvScans.filter((s) => s.projectName === selectedProject);
    const checkovTotal    = filteredCheckov.reduce((s, c) => s + c.failed, 0);
    const osvTotal        = filteredOsv.reduce((s, o) => s + o.totalVulns, 0);

    return (
      <div className="min-h-screen bg-catppuccin-base text-catppuccin-text">
        <header className="border-b border-catppuccin-surface0 bg-catppuccin-mantle/70 backdrop-blur">
          <div className="mx-auto flex max-w-5xl items-center justify-between px-4 py-3">
            <div className="flex items-center gap-2 text-sm">
              <button
                onClick={goDashboard}
                className="px-3 py-1.5 rounded border border-catppuccin-surface1 hover:bg-catppuccin-surface0 hover:border-catppuccin-teal text-catppuccin-text transition-colors font-medium"
              >
                {t.nav.home}
              </button>
              <span className="text-catppuccin-overlay1">/</span>
              <button
                onClick={() => setSelectedProject(null)}
                className="px-3 py-1.5 rounded border border-catppuccin-surface1 hover:bg-catppuccin-surface0 hover:border-catppuccin-teal text-catppuccin-text transition-colors font-medium"
              >
                {t.security.title}
              </button>
              <span className="text-catppuccin-overlay1">/</span>
              <span className="px-3 py-1.5 rounded bg-catppuccin-teal/10 text-catppuccin-teal font-semibold">
                {selectedProject}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <LangToggle />
              <span className="text-xs text-catppuccin-overlay1">{t.common.dockscan}</span>
            </div>
          </div>
        </header>

        <main className="mx-auto max-w-5xl px-4 py-6 space-y-6">
          <section className="grid gap-4 md:grid-cols-2">
            <div className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
              <p className="text-xs font-medium uppercase tracking-wide text-catppuccin-overlay1">
                {t.security.checkovCard}
              </p>
              <p className="mt-2 text-3xl font-semibold text-catppuccin-peach">{checkovTotal}</p>
              <p className="text-xs text-catppuccin-overlay1 mt-1">
                {filteredCheckov.length} {t.security.scanFiles}
              </p>
            </div>
            <div className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
              <p className="text-xs font-medium uppercase tracking-wide text-catppuccin-overlay1">
                {t.security.osvCard}
              </p>
              <p className="mt-2 text-3xl font-semibold text-catppuccin-red">{osvTotal}</p>
              <p className="text-xs text-catppuccin-overlay1 mt-1">
                {filteredOsv.length} {t.security.scanFiles}
              </p>
            </div>
          </section>

          <div className="flex gap-2 border-b border-catppuccin-surface0">
            <button
              onClick={() => setActiveTab('checkov')}
              className={`px-4 py-2 text-sm font-medium transition-colors border-b-2 -mb-px ${
                activeTab === 'checkov'
                  ? 'border-catppuccin-teal text-catppuccin-teal'
                  : 'border-transparent text-catppuccin-overlay1 hover:text-catppuccin-text'
              }`}
            >
              Checkov
              {checkovTotal > 0 && (
                <span className="ml-2 px-1.5 py-0.5 rounded text-xs bg-catppuccin-peach/20 text-catppuccin-peach">
                  {checkovTotal}
                </span>
              )}
            </button>
            <button
              onClick={() => setActiveTab('osv')}
              className={`px-4 py-2 text-sm font-medium transition-colors border-b-2 -mb-px ${
                activeTab === 'osv'
                  ? 'border-catppuccin-teal text-catppuccin-teal'
                  : 'border-transparent text-catppuccin-overlay1 hover:text-catppuccin-text'
              }`}
            >
              OSV-Scanner
              {osvTotal > 0 && (
                <span className="ml-2 px-1.5 py-0.5 rounded text-xs bg-catppuccin-red/20 text-catppuccin-red">
                  {osvTotal}
                </span>
              )}
            </button>
          </div>

          {activeTab === 'checkov' ? (
            <CheckovTab scans={filteredCheckov} expandedScans={expandedScans} toggle={toggle} />
          ) : (
            <OsvTab scans={filteredOsv} expandedScans={expandedScans} toggle={toggle} />
          )}
        </main>
      </div>
    );
  }

  // ── Project list view ──────────────────────────────────────────────────────
  return (
    <div className="min-h-screen bg-catppuccin-base text-catppuccin-text">
      <header className="border-b border-catppuccin-surface0 bg-catppuccin-mantle/70 backdrop-blur">
        <div className="mx-auto flex max-w-5xl items-center justify-between px-4 py-3">
          <div className="flex items-center gap-3">
            <button
              onClick={goDashboard}
              className="px-3 py-1.5 rounded border border-catppuccin-surface1 hover:bg-catppuccin-surface0 hover:border-catppuccin-teal text-catppuccin-text transition-colors font-medium"
            >
              ← {t.nav.home}
            </button>
            <span className="rounded bg-catppuccin-teal/10 px-2 py-1 text-xs font-semibold uppercase tracking-wide text-catppuccin-teal">
              Security
            </span>
            <span className="text-lg font-semibold">{t.security.title}</span>
          </div>
          <div className="flex items-center gap-2">
            <LangToggle />
            <span className="text-xs text-catppuccin-overlay1">{t.common.dockscan}</span>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-5xl px-4 py-6 space-y-6">
        <section className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-catppuccin-text">{t.security.title}</h2>
            <span className="text-xs text-catppuccin-overlay0">
              {t.security.projectCount(projectNames.length)}
            </span>
          </div>

          {loading ? (
            <div className="flex items-center justify-center h-40 text-catppuccin-overlay1">
              {t.common.loading}
            </div>
          ) : projectNames.length === 0 ? (
            <div className="flex h-40 items-center justify-center text-sm text-catppuccin-overlay0">
              {t.security.noProjects}
            </div>
          ) : (
            <div className="space-y-3">
              {projectNames.map((name) => {
                const stats = projectStats[name];
                return (
                  <div
                    key={name}
                    role="button"
                    tabIndex={0}
                    className={`border rounded-lg p-4 cursor-pointer hover:opacity-90 transition-all focus:outline-none focus-visible:ring-2 focus-visible:ring-catppuccin-blue ${gradeBorderClass(stats.grade)}`}
                    onClick={() => setSelectedProject(name)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        setSelectedProject(name);
                      }
                    }}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <GradeBadge grade={stats.grade} size="lg" />
                        <div>
                          <h3 className="text-base font-semibold text-catppuccin-text">{name}</h3>
                          {stats.lastScan && (
                            <p className="text-xs text-catppuccin-overlay1 mt-1">
                              {t.common.lastScan}: {new Date(stats.lastScan).toLocaleString()}
                            </p>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center gap-6">
                        {stats.checkovFailed > 0 && (
                          <div className="text-center">
                            <p className="text-xs text-catppuccin-overlay1">{t.security.checkovFailed}</p>
                            <p className="text-2xl font-semibold text-catppuccin-peach">
                              {stats.checkovFailed}
                            </p>
                          </div>
                        )}
                        {stats.osvVulns > 0 && (
                          <div className="text-center">
                            <p className="text-xs text-catppuccin-overlay1">{t.security.osvVulns}</p>
                            <p className="text-2xl font-semibold text-catppuccin-red">
                              {stats.osvVulns}
                            </p>
                          </div>
                        )}
                        {stats.checkovFailed === 0 && stats.osvVulns === 0 && (
                          <span className="text-sm text-catppuccin-green font-medium">✓ Clean</span>
                        )}
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

// ── Checkov Tab ───────────────────────────────────────────────────────────────
const CheckovTab: React.FC<{
  scans: CheckovScan[];
  expandedScans: Set<string>;
  toggle: (key: string) => void;
}> = ({ scans, expandedScans, toggle }) => {
  const { t } = useLanguage();
  if (scans.length === 0) {
    return (
      <div className="text-center py-12 text-catppuccin-overlay1">
        {t.security.noCheckov}
        <p className="text-xs mt-2">{t.security.scanHint}</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {scans.map((scan) => {
        const isExpanded = expandedScans.has(scan.filename);
        const grade = checkovGrade(scan.failed);
        return (
          <div key={scan.filename} className="space-y-0">
            <div
              role="button"
              tabIndex={0}
              onClick={() => toggle(scan.filename)}
              onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') toggle(scan.filename); }}
              aria-expanded={isExpanded}
              className={`border rounded-lg p-4 cursor-pointer hover:opacity-90 transition-all focus:outline-none focus-visible:ring-2 focus-visible:ring-catppuccin-blue ${gradeBorderClass(grade)}`}
            >
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-3">
                  <GradeBadge grade={grade} size="lg" />
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-base font-semibold text-catppuccin-text">
                        {scan.serviceName}
                      </span>
                      {scan.tag && (
                        <span className="text-xs px-2 py-0.5 rounded bg-catppuccin-surface0 text-catppuccin-overlay1">
                          {scan.tag}
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-catppuccin-overlay1 mt-0.5">
                      {new Date(scan.scannedAt).toLocaleString()}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-4 text-sm">
                  <div className="text-right">
                    <span className="text-catppuccin-overlay1 text-xs">{t.common.total}: </span>
                    <span className="font-bold text-lg text-catppuccin-text">{scan.failed}</span>
                  </div>
                  <div className="flex gap-3">
                    <span className="text-catppuccin-green font-semibold">✓ {scan.passed}</span>
                    <span className={`font-semibold ${scan.failed > 0 ? 'text-catppuccin-red' : 'text-catppuccin-overlay1'}`}>
                      ✗ {scan.failed}
                    </span>
                    <span className="text-catppuccin-overlay1 text-xs">~ {scan.skipped}</span>
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-1 text-xs text-catppuccin-subtext0 select-none">
                <span>{isExpanded ? t.projectDetail.hideScanHistory : t.projectDetail.showScanHistory}</span>
                <span className={`inline-block transition-transform ${isExpanded ? 'rotate-180' : ''}`} aria-hidden="true">▾</span>
              </div>
            </div>

            {isExpanded && (
              <div className="mt-2 border border-catppuccin-surface0 rounded-lg p-4 bg-catppuccin-mantle/60">
                {scan.findings.length === 0 ? (
                  <p className="text-sm text-catppuccin-overlay1 text-center py-4">
                    {t.security.noFindings}
                  </p>
                ) : (
                  <div className="space-y-2 max-h-80 overflow-y-auto">
                    {scan.findings.map((f, i) => (
                      <div key={i} className="border border-catppuccin-red/30 rounded-lg p-3 bg-catppuccin-red/5">
                        <div className="flex items-start justify-between gap-2">
                          <span className="font-mono text-xs text-catppuccin-teal">{f.checkId}</span>
                          <span className="text-xs text-catppuccin-overlay1 shrink-0">
                            {f.filePath}{f.line > 0 ? `:${f.line}` : ''}
                          </span>
                        </div>
                        {f.name && <p className="text-xs text-catppuccin-text mt-1">{f.name}</p>}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
};

// ── OSV Tab ───────────────────────────────────────────────────────────────────
const OsvTab: React.FC<{
  scans: OsvScan[];
  expandedScans: Set<string>;
  toggle: (key: string) => void;
}> = ({ scans, expandedScans, toggle }) => {
  const { t } = useLanguage();
  if (scans.length === 0) {
    return (
      <div className="text-center py-12 text-catppuccin-overlay1">
        {t.security.noOsv}
        <p className="text-xs mt-2">{t.security.scanHint}</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {scans.map((scan) => {
        const isExpanded = expandedScans.has(scan.filename);
        const grade = osvGrade(scan.totalVulns);
        return (
          <div key={scan.filename} className="space-y-0">
            <div
              role="button"
              tabIndex={0}
              onClick={() => toggle(scan.filename)}
              onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') toggle(scan.filename); }}
              aria-expanded={isExpanded}
              className={`border rounded-lg p-4 cursor-pointer hover:opacity-90 transition-all focus:outline-none focus-visible:ring-2 focus-visible:ring-catppuccin-blue ${gradeBorderClass(grade)}`}
            >
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-3">
                  <GradeBadge grade={grade} size="lg" />
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-base font-semibold text-catppuccin-text">
                        {scan.serviceName}
                      </span>
                      {scan.tag && (
                        <span className="text-xs px-2 py-0.5 rounded bg-catppuccin-surface0 text-catppuccin-overlay1">
                          {scan.tag}
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-catppuccin-overlay1 mt-0.5">
                      {new Date(scan.scannedAt).toLocaleString()}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-4 text-sm">
                  <div className="text-right">
                    <span className="text-catppuccin-overlay1 text-xs">{t.common.total}: </span>
                    <span className={`font-bold text-lg ${scan.totalVulns > 0 ? 'text-catppuccin-red' : 'text-catppuccin-green'}`}>
                      {scan.totalVulns}
                    </span>
                  </div>
                  <span className={`font-semibold text-xs ${scan.totalVulns > 0 ? 'text-catppuccin-red' : 'text-catppuccin-green'}`}>
                    {t.security.vulns}
                  </span>
                </div>
              </div>
              <div className="flex items-center gap-1 text-xs text-catppuccin-subtext0 select-none">
                <span>{isExpanded ? t.projectDetail.hideScanHistory : t.projectDetail.showScanHistory}</span>
                <span className={`inline-block transition-transform ${isExpanded ? 'rotate-180' : ''}`} aria-hidden="true">▾</span>
              </div>
            </div>

            {isExpanded && (
              <div className="mt-2 border border-catppuccin-surface0 rounded-lg p-4 bg-catppuccin-mantle/60 space-y-4">
                {scan.sources.length === 0 ? (
                  <p className="text-sm text-catppuccin-overlay1 text-center py-4">
                    {t.security.noVulns}
                  </p>
                ) : (
                  scan.sources.map((source, si) => (
                    <div key={si}>
                      <p className="text-xs font-semibold text-catppuccin-subtext0 mb-2">
                        {source.path}{' '}
                        <span className="text-catppuccin-overlay1">({source.type})</span>
                      </p>
                      <div className="space-y-2 max-h-80 overflow-y-auto">
                        {source.packages.map((pkg, pi) => (
                          <div key={pi} className="border border-catppuccin-surface0 rounded-lg p-3 bg-catppuccin-base/40">
                            <div className="flex items-start justify-between gap-2">
                              <div>
                                <span className="font-mono text-xs text-catppuccin-teal">{pkg.name}</span>
                                <span className="text-xs text-catppuccin-overlay1 ml-2">v{pkg.version}</span>
                                <span className="text-xs px-1.5 py-0.5 rounded bg-catppuccin-surface0 text-catppuccin-overlay1 ml-2">
                                  {pkg.ecosystem}
                                </span>
                              </div>
                              <span className="text-xs text-catppuccin-red font-semibold shrink-0">
                                {pkg.vulnCount} {t.security.vulns}
                              </span>
                            </div>
                            <div className="mt-2 space-y-1">
                              {pkg.vulns.map((v, vi) => (
                                <div key={vi} className="flex items-start gap-2 text-xs">
                                  <span className="font-mono text-catppuccin-blue shrink-0">{v.id}</span>
                                  {v.summary && (
                                    <span className="text-catppuccin-overlay1 truncate">{v.summary}</span>
                                  )}
                                </div>
                              ))}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
};

export default SecurityPage;
