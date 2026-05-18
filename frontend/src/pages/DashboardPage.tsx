import React from 'react';
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
  onOpenProject,
  onRefresh,
  refreshing,
}) => {
  return (
    <div className="min-h-screen bg-catppuccin-base text-catppuccin-text">
      <header className="border-b border-catppuccin-surface0 bg-catppuccin-mantle/70 backdrop-blur">
        <div className="mx-auto flex max-w-5xl items-center justify-between px-4 py-3">
          <div className="flex items-center gap-3">
            <button
              onClick={onGoProjects}
              className="px-3 py-1.5 rounded border border-catppuccin-surface1 hover:bg-catppuccin-surface0 hover:border-catppuccin-teal text-catppuccin-text transition-colors font-medium"
            >
              Projeler →
            </button>
            <span className="rounded bg-catppuccin-teal/10 px-2 py-1 text-xs font-semibold uppercase tracking-wide text-catppuccin-teal">
              Trivy
            </span>
            <span className="text-lg font-semibold">Dashboard</span>
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
        <section className="grid gap-4 md:grid-cols-4">
          <div className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
            <p className="text-xs font-medium uppercase tracking-wide text-catppuccin-overlay1">
              Toplam Proje
            </p>
            <p className="mt-2 text-3xl font-semibold">{overallStats.totalProjects}</p>
          </div>
          <div className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
            <p className="text-xs font-medium uppercase tracking-wide text-catppuccin-overlay1">
              Toplam Tarama
            </p>
            <p className="mt-2 text-3xl font-semibold">{overallStats.totalScans}</p>
          </div>
          <div className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
            <p className="text-xs font-medium uppercase tracking-wide text-catppuccin-overlay1">
              Toplam Açık
            </p>
            <p className="mt-2 text-3xl font-semibold">{overallStats.totalVulns}</p>
          </div>
          <div className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
            <p className="text-xs font-medium uppercase tracking-wide text-catppuccin-overlay1">
              Backend URL
            </p>
            <p className="mt-2 text-xs text-catppuccin-subtext0 break-all">
              {apiBase || 'Tanımlı değil'}
            </p>
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
              Severity Dağılımı (En Son Taramalar)
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
                Henüz veri yok
              </div>
            )}
          </div>

          {/* Unified Timeline Chart - All Projects */}
          <div className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-semibold text-catppuccin-text">
                Tüm Projeler - Günlük Açık Sayısı Zaman Çizelgesi
              </h2>
              <button
                onClick={() => setSeparateVersions(!separateVersions)}
                className="text-xs px-3 py-1.5 rounded border border-catppuccin-surface1 hover:bg-catppuccin-surface0 text-catppuccin-subtext0 transition-colors"
                title={
                  separateVersions ? 'Versiyonları birleştir (genel trend)' : 'Versiyonları ayrı göster'
                }
              >
                {separateVersions ? '📊 Birleştirilmiş' : '🔀 Versiyonları Ayrı'}
              </button>
            </div>
            {unifiedTimelineData.data.length > 0 ? (
              <>
                <ResponsiveContainer width="100%" height={300}>
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
                    {unifiedTimelineData.projectNames.map((projectName, index) => (
                      <Line
                        key={projectName}
                        type="monotone"
                        dataKey={projectName}
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
                        name={projectName}
                      />
                    ))}
                  </LineChart>
                </ResponsiveContainer>
                <div className="mt-3 flex flex-wrap gap-3 text-xs text-catppuccin-overlay1">
                  {unifiedTimelineData.projectNames.map((projectName, index) => (
                    <div key={projectName} className="flex items-center gap-2">
                      <div
                        className="w-3 h-3 rounded"
                        style={{
                          backgroundColor:
                            unifiedTimelineData.projectColors[
                              index % unifiedTimelineData.projectColors.length
                            ],
                        }}
                      ></div>
                      <span>{projectName}</span>
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <div className="flex items-center justify-center h-[300px] text-catppuccin-overlay1">
                Henüz veri yok
              </div>
            )}
          </div>
        </section>

        <section className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-catppuccin-text">Genel Özet</h2>
            <span className="text-xs text-catppuccin-overlay0">
              Tüm projelerin toplam istatistikleri
            </span>
          </div>

          <div className="text-sm text-catppuccin-subtext0 space-y-2">
            <p>
              <span className="text-catppuccin-overlay1">Durum:</span>{' '}
              {loading ? 'Yükleniyor...' : error ? `Hata: ${error}` : 'Hazır'}
            </p>
            <p>
              <span className="text-catppuccin-overlay1">Toplam Proje:</span>{' '}
              {overallStats.totalProjects}
            </p>
            <p>
              <span className="text-catppuccin-overlay1">Toplam Tarama:</span>{' '}
              {overallStats.totalScans}
            </p>
            <p>
              <span className="text-catppuccin-overlay1">Toplam Açık:</span>{' '}
              {overallStats.totalVulns}
            </p>
          </div>

          <div className="mt-4">
            <button
              onClick={onGoProjects}
              className="px-4 py-2 rounded-lg border border-catppuccin-teal bg-catppuccin-teal/10 hover:bg-catppuccin-teal/20 text-catppuccin-teal font-medium transition-colors"
            >
              Tüm Projeleri Görüntüle →
            </button>
          </div>
        </section>

        {selectedSeverity && projectsBySeverity.length > 0 && (
          <section className="rounded-xl border border-catppuccin-surface0 bg-catppuccin-mantle/60 p-4">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-semibold text-catppuccin-text">
                {selectedSeverity} Severity'ye Sahip Projeler ({projectsBySeverity.length})
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
                        {project.totalScans} tarama • Son tarama:{' '}
                        {new Date(project.lastScan).toLocaleString()}
                      </p>
                    </div>
                    <div className="flex items-center gap-4">
                      <div className="text-right">
                        <span className="text-xs text-catppuccin-overlay1">Toplam Açık</span>
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


