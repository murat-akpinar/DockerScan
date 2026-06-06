import React, { useEffect, useState } from 'react';
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

const SecurityPage: React.FC<SecurityPageProps> = ({ apiBase, goDashboard }) => {
  const [activeTab, setActiveTab] = useState<Tab>('checkov');
  const [checkovScans, setCheckovScans] = useState<CheckovScan[]>([]);
  const [osvScans, setOsvScans] = useState<OsvScan[]>([]);
  const { t } = useLanguage();
  const [loading, setLoading] = useState(true);
  const [expandedScans, setExpandedScans] = useState<Set<string>>(new Set());

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

  const checkovTotal = checkovScans.reduce((s, c) => s + c.failed, 0);
  const osvTotal = osvScans.reduce((s, o) => s + o.totalVulns, 0);

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
            <span className="px-3 py-1.5 rounded bg-catppuccin-teal/10 text-catppuccin-teal font-semibold">
              {t.security.title}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <LangToggle />
            <span className="text-xs text-catppuccin-overlay1">{t.common.dockscan}</span>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-5xl px-4 py-6 space-y-6">
        {/* Özet kartları */}
        <section className="grid gap-4 md:grid-cols-2">
          <div className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
            <p className="text-xs font-medium uppercase tracking-wide text-catppuccin-overlay1">
              {t.security.checkovCard}
            </p>
            <p className="mt-2 text-3xl font-semibold text-catppuccin-peach">{checkovTotal}</p>
            <p className="text-xs text-catppuccin-overlay1 mt-1">{checkovScans.length} {t.security.scanFiles}</p>
          </div>
          <div className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
            <p className="text-xs font-medium uppercase tracking-wide text-catppuccin-overlay1">
              {t.security.osvCard}
            </p>
            <p className="mt-2 text-3xl font-semibold text-catppuccin-red">{osvTotal}</p>
            <p className="text-xs text-catppuccin-overlay1 mt-1">{osvScans.length} {t.security.scanFiles}</p>
          </div>
        </section>

        {/* Sekmeler */}
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

        {loading ? (
          <div className="flex items-center justify-center h-40 text-catppuccin-overlay1">
            {t.common.loading}
          </div>
        ) : activeTab === 'checkov' ? (
          <CheckovTab scans={checkovScans} expandedScans={expandedScans} toggle={toggle} />
        ) : (
          <OsvTab scans={osvScans} expandedScans={expandedScans} toggle={toggle} />
        )}
      </main>
    </div>
  );
};

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
    <div className="space-y-3">
      {scans.map((scan) => {
        const isExpanded = expandedScans.has(scan.filename);
        const hasFindings = scan.failed > 0;
        return (
          <div key={scan.filename} className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 overflow-hidden">
            <div
              role="button"
              tabIndex={0}
              onClick={() => toggle(scan.filename)}
              onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') toggle(scan.filename); }}
              className="flex items-center justify-between p-4 cursor-pointer hover:bg-catppuccin-surface0/30 transition-colors"
            >
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-sm font-semibold text-catppuccin-text">
                    {scan.projectName} / {scan.serviceName}
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
              <div className="flex items-center gap-4 text-sm">
                <span className="text-catppuccin-green font-medium">✓ {scan.passed}</span>
                <span className={`font-medium ${hasFindings ? 'text-catppuccin-red' : 'text-catppuccin-overlay1'}`}>
                  ✗ {scan.failed}
                </span>
                <span className="text-catppuccin-overlay1 text-xs">~ {scan.skipped}</span>
                <span className={`text-catppuccin-subtext0 transition-transform select-none ${isExpanded ? 'rotate-180' : ''}`}>▾</span>
              </div>
            </div>

            {isExpanded && (
              <div className="border-t border-catppuccin-surface0 p-4">
                {scan.findings.length === 0 ? (
                  <p className="text-sm text-catppuccin-overlay1 text-center py-4">{t.security.noFindings}</p>
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
                        {f.name && (
                          <p className="text-xs text-catppuccin-text mt-1">{f.name}</p>
                        )}
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
    <div className="space-y-3">
      {scans.map((scan) => {
        const isExpanded = expandedScans.has(scan.filename);
        return (
          <div key={scan.filename} className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 overflow-hidden">
            <div
              role="button"
              tabIndex={0}
              onClick={() => toggle(scan.filename)}
              onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') toggle(scan.filename); }}
              className="flex items-center justify-between p-4 cursor-pointer hover:bg-catppuccin-surface0/30 transition-colors"
            >
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-sm font-semibold text-catppuccin-text">
                    {scan.projectName} / {scan.serviceName}
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
              <div className="flex items-center gap-3 text-sm">
                <span className={`font-semibold ${scan.totalVulns > 0 ? 'text-catppuccin-red' : 'text-catppuccin-green'}`}>
                  {scan.totalVulns} {t.security.vulns}
                </span>
                <span className={`text-catppuccin-subtext0 transition-transform select-none ${isExpanded ? 'rotate-180' : ''}`}>▾</span>
              </div>
            </div>

            {isExpanded && (
              <div className="border-t border-catppuccin-surface0 p-4 space-y-4">
                {scan.sources.length === 0 ? (
                  <p className="text-sm text-catppuccin-overlay1 text-center py-4">{t.security.noVulns}</p>
                ) : (
                  scan.sources.map((source, si) => (
                    <div key={si}>
                      <p className="text-xs font-semibold text-catppuccin-subtext0 mb-2">
                        {source.path} <span className="text-catppuccin-overlay1">({source.type})</span>
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
