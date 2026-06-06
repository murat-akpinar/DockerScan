import React from 'react';
import { useLanguage, LangToggle } from '../i18n/LanguageContext';
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
import TimelineTooltip from '../components/TimelineTooltip';

type OverallStats = {
  totalProjects: number;
  totalScans: number;
  totalImages: number;
  totalVulns: number;
  severityCount: Record<string, number>;
};

type UnifiedTimelineData = {
  data: any[];
  projectNames: string[];
  projectColors: string[];
};

type ProjectBySeverity = {
  projectName: string;
  totalScans: number;
  totalVulns: number;
  lastScan: string | Date;
  severityCount: Record<string, number>;
};

type PieChartItem = {
  name: string;
  value: number;
  color: string;
};

type DashboardPageProps = {
  apiBase: string | undefined;
  overallStats: OverallStats;
  selectedSeverity: string | null;
  setSelectedSeverity: (value: string | null) => void;
  separateVersions: boolean;
  setSeparateVersions: (value: boolean) => void;
  pieChartData: PieChartItem[];
  unifiedTimelineData: UnifiedTimelineData;
  projectsBySeverity: ProjectBySeverity[];
  loading: boolean;
  error: string | null;
  onGoProjects: () => void;
  onGoSecurity: () => void;
  onOpenProject: (projectName: string) => void;
  onRefresh?: () => void;
  refreshing?: boolean;
};

const DashboardPage: React.FC<DashboardPageProps> = ({
  apiBase,
  overallStats,
  selectedSeverity,
  setSelectedSeverity,
  separateVersions,
  setSeparateVersions,
  pieChartData,
  unifiedTimelineData,
  projectsBySeverity,
  loading,
  error,
  onGoProjects,
  onGoSecurity,
  onOpenProject,
  onRefresh,
  refreshing,
}) => {
  const { t } = useLanguage();
  const [activeSeries, setActiveSeries] = React.useState<string | null>(null);
  const [hiddenSeries, setHiddenSeries] = React.useState<Set<string>>(new Set());

  const toggleSeries = (name: string) => {
    setHiddenSeries((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  };

  return (
    <div className="min-h-screen bg-catppuccin-base text-catppuccin-text">
      <header className="border-b border-catppuccin-surface0 bg-catppuccin-mantle/70 backdrop-blur">
        <div className="mx-auto flex max-w-5xl items-center justify-between px-4 py-3">
          <div className="flex items-center gap-3">
            <button
              onClick={onGoProjects}
              className="px-3 py-1.5 rounded border border-catppuccin-surface1 hover:bg-catppuccin-surface0 hover:border-catppuccin-teal text-catppuccin-text transition-colors font-medium"
            >
              {t.dashboard.goProjects}
            </button>
            <button
              onClick={onGoSecurity}
              className="px-3 py-1.5 rounded border border-catppuccin-surface1 hover:bg-catppuccin-surface0 hover:border-catppuccin-teal text-catppuccin-text transition-colors font-medium"
            >
              {t.dashboard.goSecurity}
            </button>
            <span className="rounded bg-catppuccin-teal/10 px-2 py-1 text-xs font-semibold uppercase tracking-wide text-catppuccin-teal">
              Trivy
            </span>
            <span className="text-lg font-semibold">{t.dashboard.title}</span>
          </div>
          <div className="flex items-center gap-3">
            {onRefresh && (
              <button
                onClick={onRefresh}
                disabled={refreshing}
                className="px-3 py-1.5 rounded border border-catppuccin-surface1 hover:bg-catppuccin-surface0 hover:border-catppuccin-teal text-catppuccin-text transition-colors font-medium disabled:opacity-50"
              >
                {refreshing ? t.common.refreshing : t.common.refresh}
              </button>
            )}
            <LangToggle />
            <span className="text-xs text-catppuccin-overlay1">{t.common.dockscan}</span>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-5xl px-4 py-6 space-y-6">
        <section className="grid gap-4 md:grid-cols-4">
          <div className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
            <p className="text-xs font-medium uppercase tracking-wide text-catppuccin-overlay1">
              {t.dashboard.totalProjects}
            </p>
            <p className="mt-2 text-3xl font-semibold">{overallStats.totalProjects}</p>
          </div>
          <div className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
            <p className="text-xs font-medium uppercase tracking-wide text-catppuccin-overlay1">
              {t.dashboard.totalScans}
            </p>
            <p className="mt-2 text-3xl font-semibold">{overallStats.totalScans}</p>
          </div>
          <div className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
            <p className="text-xs font-medium uppercase tracking-wide text-catppuccin-overlay1">
              {t.dashboard.totalVulns}
            </p>
            <p className="mt-2 text-3xl font-semibold">{overallStats.totalVulns}</p>
          </div>
          <div className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
            <p className="text-xs font-medium uppercase tracking-wide text-catppuccin-overlay1">
              {t.dashboard.totalImages}
            </p>
            <p className="mt-2 text-3xl font-semibold">{overallStats.totalImages}</p>
          </div>
        </section>

        <section className="grid gap-4 md:grid-cols-4">
          {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => {
            const colorClass =
              sev === 'CRITICAL'
                ? 'border-catppuccin-red bg-catppuccin-red/10'
                : sev === 'HIGH'
                  ? 'border-catppuccin-peach bg-catppuccin-peach/10'
                  : sev === 'MEDIUM'
                    ? 'border-catppuccin-yellow bg-catppuccin-yellow/10'
                    : 'border-catppuccin-blue bg-catppuccin-blue/10';

            const value = overallStats.severityCount[sev] || 0;

            return (
              <div
                key={sev}
                role="button"
                tabIndex={0}
                className={`rounded-xl border p-4 cursor-pointer transition-all ${
                  selectedSeverity === sev
                    ? colorClass
                    : 'border-catppuccin-surface0 bg-catppuccin-mantle/60 hover:bg-catppuccin-mantle/80'
                }`}
                onClick={() => setSelectedSeverity(selectedSeverity === sev ? null : sev)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    setSelectedSeverity(selectedSeverity === sev ? null : sev);
                  }
                }}
              >
                <p className="text-xs font-medium uppercase tracking-wide text-catppuccin-overlay1">
                  {sev}
                </p>
                <p
                  className={`mt-2 text-3xl font-semibold ${
                    sev === 'CRITICAL'
                      ? 'text-catppuccin-red'
                      : sev === 'HIGH'
                        ? 'text-catppuccin-peach'
                        : sev === 'MEDIUM'
                          ? 'text-catppuccin-yellow'
                          : 'text-catppuccin-blue'
                  }`}
                >
                  {value}
                </p>
              </div>
            );
          })}
        </section>

        {/* Charts Section */}
        <section className="grid gap-4 md:grid-cols-2">
          {/* Pie Chart - Severity Distribution */}
          <div className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
            <h2 className="text-sm font-semibold text-catppuccin-text mb-4">
              {t.dashboard.severityDist}
            </h2>
            {pieChartData.length > 0 ? (
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={pieChartData}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {pieChartData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#eff1f5',
                      border: '1px solid #313244',
                      borderRadius: '8px',
                      color: '#11111b',
                    }}
                    labelStyle={{
                      color: '#1e1e2e',
                      fontWeight: 600,
                    }}
                    wrapperStyle={{ outline: 'none' }}
                  />
                  <Legend wrapperStyle={{ color: '#cdd6f4', fontSize: '12px' }} />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-[300px] text-catppuccin-overlay1">
                {t.dashboard.noSeverityData}
              </div>
            )}
          </div>

          {/* Unified Timeline Chart - All Projects */}
          <div className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-semibold text-catppuccin-text">
                {t.dashboard.timeline}
              </h2>
              <button
                onClick={() => setSeparateVersions(!separateVersions)}
                className="text-xs px-3 py-1.5 rounded border border-catppuccin-surface1 hover:bg-catppuccin-surface0 text-catppuccin-subtext0 transition-colors"
              >
                {separateVersions ? t.dashboard.mergedVersions : t.dashboard.separateVersions}
              </button>
            </div>
            {unifiedTimelineData.data.length > 0 ? (
              <>
                <ResponsiveContainer width="100%" height={340}>
                  <LineChart data={unifiedTimelineData.data}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#313244" />
                    <XAxis
                      dataKey="date"
                      stroke="#6c7086"
                      style={{ fontSize: '10px' }}
                      angle={-35}
                      textAnchor="end"
                      height={80}
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
                    {unifiedTimelineData.projectNames.map((projectName, index) => {
                      const color =
                        unifiedTimelineData.projectColors[
                          index % unifiedTimelineData.projectColors.length
                        ];
                      if (hiddenSeries.has(projectName)) return null;
                      const isActive = activeSeries === projectName;
                      const dimmed = activeSeries !== null && !isActive;
                      return (
                        <Line
                          key={projectName}
                          type="monotone"
                          dataKey={projectName}
                          stroke={color}
                          strokeWidth={isActive ? 3.5 : 2}
                          strokeOpacity={dimmed ? 0.15 : 1}
                          dot={dimmed ? false : { fill: color, r: isActive ? 4 : 3, strokeWidth: 0 }}
                          activeDot={{ r: 6 }}
                          connectNulls
                          name={projectName}
                          isAnimationActive={false}
                        />
                      );
                    })}
                  </LineChart>
                </ResponsiveContainer>
                <div className="mt-3 flex flex-wrap gap-2 text-xs">
                  {unifiedTimelineData.projectNames.map((projectName, index) => {
                    const color =
                      unifiedTimelineData.projectColors[
                        index % unifiedTimelineData.projectColors.length
                      ];
                    const isHidden = hiddenSeries.has(projectName);
                    const isActive = activeSeries === projectName;
                    return (
                      <button
                        key={projectName}
                        type="button"
                        onMouseEnter={() => setActiveSeries(projectName)}
                        onMouseLeave={() => setActiveSeries(null)}
                        onClick={() => toggleSeries(projectName)}
                        title={isHidden ? 'Göstermek için tıkla' : 'Gizlemek için tıkla'}
                        className={`flex items-center gap-2 rounded px-2 py-1 border transition-all ${
                          isActive
                            ? 'border-catppuccin-surface2 bg-catppuccin-surface0/60'
                            : 'border-transparent hover:bg-catppuccin-surface0/40'
                        } ${isHidden ? 'opacity-40' : ''}`}
                      >
                        <span
                          className="w-3 h-3 rounded shrink-0"
                          style={{ backgroundColor: color }}
                        ></span>
                        <span
                          className={
                            isHidden
                              ? 'line-through text-catppuccin-overlay0'
                              : 'text-catppuccin-subtext0'
                          }
                        >
                          {projectName}
                        </span>
                      </button>
                    );
                  })}
                </div>
              </>
            ) : (
              <div className="flex items-center justify-center h-[300px] text-catppuccin-overlay1">
                {t.dashboard.timelineEmpty}
              </div>
            )}
          </div>
        </section>

        <section className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-catppuccin-text">{t.dashboard.title}</h2>
          </div>

          <div className="text-sm text-catppuccin-subtext0 space-y-2">
            <p>
              <span className="text-catppuccin-overlay1">{t.dashboard.totalProjects}:</span>{' '}
              {overallStats.totalProjects}
            </p>
            <p>
              <span className="text-catppuccin-overlay1">{t.dashboard.totalScans}:</span>{' '}
              {overallStats.totalScans}
            </p>
            <p>
              <span className="text-catppuccin-overlay1">{t.dashboard.totalVulns}:</span>{' '}
              {overallStats.totalVulns}
            </p>
          </div>

          <div className="mt-4">
            <button
              onClick={onGoProjects}
              className="px-4 py-2 rounded-lg border border-catppuccin-teal bg-catppuccin-teal/10 hover:bg-catppuccin-teal/20 text-catppuccin-teal font-medium transition-colors"
            >
              {t.dashboard.goProjects}
            </button>
          </div>
        </section>

        {selectedSeverity && projectsBySeverity.length > 0 && (
          <section className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-semibold text-catppuccin-text">
                {selectedSeverity} {t.dashboard.filteredBy} ({projectsBySeverity.length})
              </h2>
              <button
                onClick={() => setSelectedSeverity(null)}
                className="px-3 py-1 text-xs rounded border border-catppuccin-surface1 hover:bg-catppuccin-surface0 text-catppuccin-subtext0"
              >
                Kapat
              </button>
            </div>

            <div className="space-y-3">
              {projectsBySeverity.map((project) => (
                <div
                  key={project.projectName}
                  role="button"
                  tabIndex={0}
                  className="border border-catppuccin-surface0 rounded-lg p-4 bg-catppuccin-base/60 hover:bg-catppuccin-mantle/40 cursor-pointer transition-colors"
                  onClick={() => onOpenProject(project.projectName)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      onOpenProject(project.projectName);
                    }
                  }}
                >
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="text-lg font-semibold text-catppuccin-text">
                        {project.projectName}
                      </h3>
                      <p className="text-xs text-catppuccin-overlay1 mt-1">
                        {project.totalScans} {t.common.scans} • {t.common.lastScan}:{' '}
                        {new Date(project.lastScan).toLocaleString()}
                      </p>
                    </div>
                    <div className="flex items-center gap-4">
                      <div className="text-right">
                        <span className="text-xs text-catppuccin-overlay1">{t.common.totalVulns}</span>
                        <p className="text-2xl font-semibold text-catppuccin-text">
                          {project.totalVulns}
                        </p>
                      </div>
                      <div className="flex gap-3 text-sm">
                        {project.severityCount['CRITICAL'] > 0 && (
                          <div className="text-center">
                            <p className="text-xs text-catppuccin-overlay1">CRITICAL</p>
                            <p className="text-lg font-semibold text-catppuccin-red">
                              {project.severityCount['CRITICAL']}
                            </p>
                          </div>
                        )}
                        {project.severityCount['HIGH'] > 0 && (
                          <div className="text-center">
                            <p className="text-xs text-catppuccin-overlay1">HIGH</p>
                            <p className="text-lg font-semibold text-catppuccin-peach">
                              {project.severityCount['HIGH']}
                            </p>
                          </div>
                        )}
                        {project.severityCount['MEDIUM'] > 0 && (
                          <div className="text-center">
                            <p className="text-xs text-catppuccin-overlay1">MEDIUM</p>
                            <p className="text-lg font-semibold text-catppuccin-yellow">
                              {project.severityCount['MEDIUM']}
                            </p>
                          </div>
                        )}
                        {project.severityCount['LOW'] > 0 && (
                          <div className="text-center">
                            <p className="text-xs text-catppuccin-overlay1">LOW</p>
                            <p className="text-lg font-semibold text-catppuccin-blue">
                              {project.severityCount['LOW']}
                            </p>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </section>
        )}

        {selectedSeverity && projectsBySeverity.length === 0 && (
          <section className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-semibold text-catppuccin-text">
                {selectedSeverity} Severity'ye Sahip Projeler
              </h2>
              <button
                onClick={() => setSelectedSeverity(null)}
                className="px-3 py-1 text-xs rounded border border-catppuccin-surface1 hover:bg-catppuccin-surface0 text-catppuccin-subtext0"
              >
                Kapat
              </button>
            </div>
            <div className="text-center py-8 text-catppuccin-overlay1">
              {selectedSeverity} severity'sine sahip proje bulunamadı.
            </div>
          </section>
        )}
      </main>
    </div>
  );
};

export default DashboardPage;


