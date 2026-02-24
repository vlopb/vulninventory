import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { EmptyState } from "../components/common/EmptyState";
import { DashboardSkeleton } from "../components/dashboard/DashboardSkeleton";
import { useAuth } from "../context/AuthContext";
import { useProject } from "../context/ProjectContext";
import { useTheme } from "../context/ThemeContext";
import { API_BASE, authFetch, unwrapItems } from "../utils/api";
import { buildChartTheme } from "../utils/chartTheme";
import { summarizeBySeverity, groupFindings } from "../utils/findingsHelpers";
import { getCSSVar, toRgba } from "../utils/formatters";
import { severityRank, severityLabels, statusLabels, statusOptions } from "../utils/constants";
import "../Dashboard.css";

export default function DashboardPage() {
  const { user } = useAuth();
  const { orgId, projectId } = useProject();
  const { theme } = useTheme();
  const chartTheme = useMemo(() => buildChartTheme(), [theme]);
  const [findings, setFindings] = useState([]);
  const [assets, setAssets] = useState([]);
  const [scans, setScans] = useState([]);
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [assetsLoading, setAssetsLoading] = useState(false);
  const [scansLoading, setScansLoading] = useState(false);
  const [error, setError] = useState("");
  const [reloadToken, setReloadToken] = useState(0);
  const [dashboardFilters, setDashboardFilters] = useState({
    asset: "all",
    owner: "all",
    severity: "all",
    status: "all",
    tool: "all",
    vuln: "",
  });
  const [dashboardFiltersOpen, setDashboardFiltersOpen] = useState(true);
  const [trendGranularity, setTrendGranularity] = useState("month");

  const handleRetry = useCallback(() => {
    setError("");
    setReloadToken((prev) => prev + 1);
  }, []);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        if (!cancelled) {
          setFindingsLoading(true);
          setAssetsLoading(true);
          setScansLoading(true);
        }
        if (!user || !projectId) {
          if (!cancelled) {
            setFindings([]);
            setAssets([]);
            setScans([]);
            setFindingsLoading(false);
            setAssetsLoading(false);
            setScansLoading(false);
          }
          return;
        }
        const [findingsResponse, assetsResponse, scansResponse] = await Promise.all([
          authFetch(`${API_BASE}/findings?project_id=${projectId}`),
          authFetch(`${API_BASE}/assets?project_id=${projectId}`),
          authFetch(`${API_BASE}/scans?project_id=${projectId}`),
        ]);
        if (!findingsResponse.ok || !assetsResponse.ok || !scansResponse.ok) {
          throw new Error("API no disponible");
        }
        const [findingsData, assetsData, scansData] = await Promise.all([
          findingsResponse.json(),
          assetsResponse.json(),
          scansResponse.json(),
        ]);
        if (!cancelled) {
          setFindings(unwrapItems(findingsData));
          setAssets(unwrapItems(assetsData));
          setScans(unwrapItems(scansData));
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message || "No se pudieron cargar los datos");
        }
      } finally {
        if (!cancelled) {
          setFindingsLoading(false);
          setAssetsLoading(false);
          setScansLoading(false);
        }
      }
    }

    load();
    return () => {
      cancelled = true;
    };
  }, [projectId, user, reloadToken]);

  const assetMap = useMemo(() => new Map(assets.map((asset) => [asset.id, asset])), [assets]);
  const scanToolMap = useMemo(() => new Map(scans.map((scan) => [scan.id, scan.tool])), [scans]);
  const groupedFindings = useMemo(() => {
    return groupFindings(findings).sort((a, b) => {
      const rankDiff = (severityRank[a.severity] ?? 99) - (severityRank[b.severity] ?? 99);
      if (rankDiff !== 0) {
        return rankDiff;
      }
      return b.occurrences - a.occurrences;
    });
  }, [findings]);

  const dashboardFindings = useMemo(() => {
    const query = dashboardFilters.vuln.trim().toLowerCase();
    return findings.filter((finding) => {
      if (dashboardFilters.asset !== "all" && String(finding.asset_id) !== dashboardFilters.asset) {
        return false;
      }
      if (dashboardFilters.owner !== "all") {
        const owner = assetMap.get(finding.asset_id)?.owner_email || "";
        if (owner !== dashboardFilters.owner) {
          return false;
        }
      }
      if (dashboardFilters.severity !== "all" && finding.severity !== dashboardFilters.severity) {
        return false;
      }
      if (dashboardFilters.status !== "all" && finding.status !== dashboardFilters.status) {
        return false;
      }
      if (dashboardFilters.tool !== "all") {
        const tool = scanToolMap.get(finding.scan_id) || "";
        if (tool !== dashboardFilters.tool) {
          return false;
        }
      }
      if (query) {
        const haystack = [finding.title, finding.cwe, finding.owasp, finding.rule_id]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        if (!haystack.includes(query)) {
          return false;
        }
      }
      return true;
    });
  }, [findings, dashboardFilters, assetMap, scanToolMap]);

  const dashboardGroupedFindings = useMemo(
    () => groupFindings(dashboardFindings),
    [dashboardFindings]
  );

  const dashboardSeverityCounts = useMemo(
    () => summarizeBySeverity(dashboardGroupedFindings),
    [dashboardGroupedFindings]
  );

  const statusCounts = useMemo(() => {
    const counts = { open: 0, triaged: 0, accepted: 0, fixed: 0, false_positive: 0 };
    dashboardFindings.forEach((finding) => {
      const key = finding.status || "open";
      if (counts[key] === undefined) {
        counts[key] = 0;
      }
      counts[key] += 1;
    });
    return counts;
  }, [dashboardFindings]);

  const scanToolCounts = useMemo(() => {
    const counts = {};
    const scanIds = new Set(dashboardFindings.map((finding) => finding.scan_id).filter(Boolean));
    scans.forEach((scan) => {
      if (scanIds.size > 0 && !scanIds.has(scan.id)) {
        return;
      }
      counts[scan.tool] = (counts[scan.tool] || 0) + 1;
    });
    return counts;
  }, [scans, dashboardFindings]);

  const activeDashboardFilterCount = useMemo(() => {
    let count = 0;
    if (dashboardFilters.asset !== "all") {
      count += 1;
    }
    if (dashboardFilters.owner !== "all") {
      count += 1;
    }
    if (dashboardFilters.severity !== "all") {
      count += 1;
    }
    if (dashboardFilters.status !== "all") {
      count += 1;
    }
    if (dashboardFilters.tool !== "all") {
      count += 1;
    }
    if (dashboardFilters.vuln.trim()) {
      count += 1;
    }
    return count;
  }, [dashboardFilters]);

  const topAssets = useMemo(() => {
    const counts = new Map();
    const maxSeverities = new Map();
    dashboardFindings.forEach((finding) => {
      counts.set(finding.asset_id, (counts.get(finding.asset_id) || 0) + 1);
      const current = maxSeverities.get(finding.asset_id);
      const severity = finding.severity || "info";
      if (!current || severityRank[severity] < severityRank[current]) {
        maxSeverities.set(finding.asset_id, severity);
      }
    });
    return Array.from(counts.entries())
      .map(([assetId, total]) => ({
        assetId,
        total,
        name: assetMap.get(assetId)?.name || `Activo ${assetId}`,
        owner: assetMap.get(assetId)?.owner_email || "-",
        maxSeverity: maxSeverities.get(assetId) || "info",
      }))
      .sort((a, b) => b.total - a.total)
      .slice(0, 5);
  }, [dashboardFindings, assetMap]);

  const severityChartData = useMemo(() => {
    return Object.entries(dashboardSeverityCounts)
      .filter(([, value]) => value > 0)
      .map(([key, value]) => ({
        name: severityLabels[key] || key,
        value,
        key,
      }));
  }, [dashboardSeverityCounts]);

  const statusChartData = useMemo(() => {
    return Object.entries(statusCounts)
      .filter(([, value]) => value > 0)
      .map(([key, value]) => ({
        name: statusLabels[key] || key,
        value,
        key,
      }));
  }, [statusCounts]);

  const toolChartData = useMemo(() => {
    return Object.entries(scanToolCounts).map(([key, value]) => ({
      name: key,
      count: value,
    }));
  }, [scanToolCounts]);

  const trendData = useMemo(() => {
    const grouped = {};
    const monthNames = ["Ene", "Feb", "Mar", "Abr", "May", "Jun", "Jul", "Ago", "Sep", "Oct", "Nov", "Dic"];
    const getWeekKey = (date) => {
      const temp = new Date(Date.UTC(date.getFullYear(), date.getMonth(), date.getDate()));
      const day = temp.getUTCDay() || 7;
      temp.setUTCDate(temp.getUTCDate() + 4 - day);
      const yearStart = new Date(Date.UTC(temp.getUTCFullYear(), 0, 1));
      const week = Math.ceil(((temp - yearStart) / 86400000 + 1) / 7);
      return `${temp.getUTCFullYear()}-W${String(week).padStart(2, "0")}`;
    };

    dashboardGroupedFindings.forEach((finding) => {
      if (!finding.created_at) {
        return;
      }
      const date = new Date(finding.created_at);
      if (Number.isNaN(date.getTime())) {
        return;
      }
      let key = "";
      if (trendGranularity === "day") {
        key = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")}`;
      } else if (trendGranularity === "week") {
        key = getWeekKey(date);
      } else {
        key = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}`;
      }
      grouped[key] = (grouped[key] || 0) + 1;
    });

    return Object.entries(grouped)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, count]) => {
        if (trendGranularity === "day") {
          const [year, month, day] = key.split("-");
          return {
            name: `${day}/${month}`,
            hallazgos: count,
          };
        }
        if (trendGranularity === "week") {
          const [year, week] = key.split("-W");
          return {
            name: `Sem ${week} ${year.slice(2)}`,
            hallazgos: count,
          };
        }
        const [year, monthNumber] = key.split("-");
        return {
          name: `${monthNames[Number(monthNumber) - 1]} ${year.slice(2)}`,
          hallazgos: count,
        };
      });
  }, [dashboardGroupedFindings, trendGranularity]);

  const heatmapData = useMemo(() => {
    const matrix = {};
    dashboardGroupedFindings.forEach((finding) => {
      const assetName = assetMap.get(finding.asset_id)?.name || `Activo ${finding.asset_id}`;
      if (!matrix[assetName]) {
        matrix[assetName] = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      }
      const severity = finding.severity || "info";
      matrix[assetName][severity] = (matrix[assetName][severity] || 0) + 1;
    });
    return Object.entries(matrix).map(([asset, severities]) => ({
      asset,
      ...severities,
    }));
  }, [dashboardGroupedFindings, assetMap]);

  const totalSeverityFindings = useMemo(() => {
    return severityChartData.reduce((sum, item) => sum + item.value, 0);
  }, [severityChartData]);

  const totalStatusFindings = useMemo(() => {
    return statusChartData.reduce((sum, item) => sum + item.value, 0);
  }, [statusChartData]);

  if (!orgId) {
    return (
      <EmptyState
        icon="default"
        title="Crea tu primer cliente"
        description="Comienza creando un cliente en el panel lateral para registrar activos y ejecutar escaneos."
      />
    );
  }

  return (
    <section className="dashboard-grid">
      {error ? (
        <EmptyState
          icon="error"
          title="No pudimos cargar el dashboard"
          description={`Verifica la conexión y vuelve a intentar. ${error}`}
          action={{ label: "Reintentar", onClick: handleRetry }}
          secondaryAction={{ label: "Cerrar", onClick: () => setError("") }}
        />
      ) : findingsLoading || assetsLoading || scansLoading ? (
        <DashboardSkeleton />
      ) : (
        <>
          <div className="dashboard-header">
            <div>
              <h2 className="dashboard-title">Dashboard</h2>
              <p className="dashboard-subtitle">Centro de mando para el inventario de vulnerabilidades</p>
            </div>
          </div>

          <div className="dashboard-kpis">
            <div className="kpi-card">
              <div className="kpi-icon kpi-icon--findings">
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <path
                    d="M12 3l7 3v5c0 4.4-3 8.4-7 10-4-1.6-7-5.6-7-10V6l7-3Z"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.5"
                  />
                  <path
                    d="M9 12h6"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.5"
                    strokeLinecap="round"
                  />
                </svg>
              </div>
              <div className="kpi-content">
                <span className="kpi-value">{dashboardGroupedFindings.length}</span>
                <span className="kpi-label">Hallazgos totales</span>
              </div>
            </div>
            <div className="kpi-card kpi-card--critical">
              <div className="kpi-icon kpi-icon--critical">
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <path
                    d="M12 3l9 16H3L12 3Z"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.5"
                    strokeLinejoin="round"
                  />
                  <path
                    d="M12 9v4"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.5"
                    strokeLinecap="round"
                  />
                  <circle cx="12" cy="16.5" r="1" fill="currentColor" />
                </svg>
              </div>
              <div className="kpi-content">
                <span className="kpi-value">{dashboardSeverityCounts.critical || 0}</span>
                <span className="kpi-label">Críticos</span>
              </div>
            </div>
            <div className="kpi-card">
              <div className="kpi-icon kpi-icon--open">
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" strokeWidth="1.5" />
                  <path
                    d="M12 7v5l3 2"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.5"
                    strokeLinecap="round"
                  />
                </svg>
              </div>
              <div className="kpi-content">
                <span className="kpi-value">{statusCounts.open || 0}</span>
                <span className="kpi-label">Abiertos</span>
              </div>
            </div>
            <div className="kpi-card">
              <div className="kpi-icon kpi-icon--fixed">
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" strokeWidth="1.5" />
                  <path
                    d="M9 12.5 11 14l4-5"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.5"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
              </div>
              <div className="kpi-content">
                <span className="kpi-value">{statusCounts.fixed || 0}</span>
                <span className="kpi-label">Cerrados</span>
              </div>
            </div>
            <div className="kpi-card">
              <div className="kpi-icon kpi-icon--assets">
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <rect x="4" y="5" width="16" height="6" rx="2" fill="none" stroke="currentColor" strokeWidth="1.5" />
                  <rect x="4" y="13" width="16" height="6" rx="2" fill="none" stroke="currentColor" strokeWidth="1.5" />
                </svg>
              </div>
              <div className="kpi-content">
                <span className="kpi-value">{assets.length}</span>
                <span className="kpi-label">Activos</span>
              </div>
            </div>
            <div className="kpi-card">
              <div className="kpi-icon kpi-icon--scans">
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <path
                    d="M12 3a9 9 0 1 1-9 9"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.5"
                    strokeLinecap="round"
                  />
                  <path
                    d="M12 7v5l4 2"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.5"
                    strokeLinecap="round"
                  />
                </svg>
              </div>
              <div className="kpi-content">
                <span className="kpi-value">{scans.length}</span>
                <span className="kpi-label">Escaneos</span>
              </div>
            </div>
          </div>

          <div className="card dashboard-filters-card">
            <button
              className="dashboard-filters-toggle"
              type="button"
              onClick={() => setDashboardFiltersOpen((prev) => !prev)}
            >
              <span>Filtros</span>
              <span className="dashboard-filters-count">
                {activeDashboardFilterCount > 0 ? `${activeDashboardFilterCount} activos` : "Sin filtros"}
              </span>
              <svg
                className={`dashboard-filters-icon ${dashboardFiltersOpen ? "rotated" : ""}`}
                viewBox="0 0 24 24"
                aria-hidden="true"
              >
                <path
                  d="m6 9 6 6 6-6"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </svg>
            </button>
            {dashboardFiltersOpen && (
              <div className="dashboard-filters-body">
                <div className="form-group">
                  <label className="form-label">Activo</label>
                  <select
                    className="form-select"
                    value={dashboardFilters.asset}
                    onChange={(event) =>
                      setDashboardFilters((prev) => ({ ...prev, asset: event.target.value }))
                    }
                  >
                    <option value="all">Todos</option>
                    {assets.map((asset) => (
                      <option key={asset.id} value={String(asset.id)}>
                        {asset.name}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="form-group">
                  <label className="form-label">Responsable</label>
                  <select
                    className="form-select"
                    value={dashboardFilters.owner}
                    onChange={(event) =>
                      setDashboardFilters((prev) => ({ ...prev, owner: event.target.value }))
                    }
                  >
                    <option value="all">Todos</option>
                    {Array.from(new Set(assets.map((asset) => asset.owner_email).filter(Boolean))).map(
                      (owner) => (
                        <option key={owner} value={owner}>
                          {owner}
                        </option>
                      ),
                    )}
                  </select>
                </div>
                <div className="form-group">
                  <label className="form-label">Severidad</label>
                  <select
                    className="form-select"
                    value={dashboardFilters.severity}
                    onChange={(event) =>
                      setDashboardFilters((prev) => ({ ...prev, severity: event.target.value }))
                    }
                  >
                    <option value="all">Todas</option>
                    <option value="critical">Crítica</option>
                    <option value="high">Alta</option>
                    <option value="medium">Media</option>
                    <option value="low">Baja</option>
                    <option value="info">Info</option>
                  </select>
                </div>
                <div className="form-group">
                  <label className="form-label">Estado</label>
                  <select
                    className="form-select"
                    value={dashboardFilters.status}
                    onChange={(event) =>
                      setDashboardFilters((prev) => ({ ...prev, status: event.target.value }))
                    }
                  >
                    <option value="all">Todos</option>
                    {statusOptions.map((status) => (
                      <option key={status} value={status}>
                        {statusLabels[status] || status}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="form-group">
                  <label className="form-label">Herramienta</label>
                  <select
                    className="form-select"
                    value={dashboardFilters.tool}
                    onChange={(event) =>
                      setDashboardFilters((prev) => ({ ...prev, tool: event.target.value }))
                    }
                  >
                    <option value="all">Todas</option>
                    {Array.from(new Set(scans.map((scan) => scan.tool))).map((tool) => (
                      <option key={tool} value={tool}>
                        {tool}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="form-group">
                  <label className="form-label">Vulnerabilidad</label>
                  <input
                    className="form-input"
                    type="text"
                    placeholder="título, CWE, OWASP"
                    value={dashboardFilters.vuln}
                    onChange={(event) =>
                      setDashboardFilters((prev) => ({ ...prev, vuln: event.target.value }))
                    }
                  />
                </div>
                <div className="form-group dashboard-filters-action">
                  <label className="form-label">&nbsp;</label>
                  <button
                    className="btn btn-secondary"
                    type="button"
                    onClick={() =>
                      setDashboardFilters({
                        asset: "all",
                        owner: "all",
                        severity: "all",
                        status: "all",
                        tool: "all",
                        vuln: "",
                      })
                    }
                  >
                    Limpiar
                  </button>
                </div>
              </div>
            )}
          </div>

          <div className="dashboard-charts">
            <div className="chart-card">
              <h3 className="chart-title">Distribución por Severidad</h3>
              <div className="chart-wrapper" style={{ height: 280 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={severityChartData}
                      cx="50%"
                      cy="50%"
                      innerRadius={65}
                      outerRadius={95}
                      paddingAngle={3}
                      dataKey="value"
                      stroke="none"
                    >
                      {severityChartData.map((entry) => (
                        <Cell key={entry.key} fill={chartTheme.colors.severity[entry.key]} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={chartTheme.tooltip.contentStyle} />
                    <Legend
                      verticalAlign="bottom"
                      iconType="circle"
                      iconSize={8}
                      wrapperStyle={{ fontSize: "12px", color: chartTheme.axis.tick.fill }}
                    />
                  </PieChart>
                </ResponsiveContainer>
                <div className="donut-center">
                  <span className="donut-center-value">{totalSeverityFindings}</span>
                  <span className="donut-center-label">Total</span>
                </div>
              </div>
            </div>

            <div className="chart-card">
              <h3 className="chart-title">Hallazgos por Herramienta</h3>
              <div className="chart-wrapper" style={{ height: 280 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={toolChartData} layout="vertical" margin={{ left: 20 }}>
                    <CartesianGrid
                      strokeDasharray={chartTheme.grid.strokeDasharray}
                      stroke={chartTheme.grid.stroke}
                      horizontal={false}
                    />
                    <XAxis
                      type="number"
                      tick={chartTheme.axis.tick}
                      axisLine={chartTheme.axis.axisLine}
                    />
                    <YAxis
                      type="category"
                      dataKey="name"
                      tick={{
                        ...chartTheme.axis.tick,
                        fontFamily: "'JetBrains Mono', monospace",
                      }}
                      axisLine={false}
                      tickLine={false}
                      width={90}
                    />
                    <Tooltip
                      contentStyle={chartTheme.tooltip.contentStyle}
                      cursor={{ fill: getCSSVar("--accent-primary-subtle") }}
                    />
                    <Bar dataKey="count" fill={chartTheme.colors.accent} radius={[0, 4, 4, 0]} barSize={24} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div className="chart-card chart-card--wide">
              <div className="chart-title-row" style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "12px" }}>
                <h3 className="chart-title">Tendencia de Hallazgos</h3>
                <select
                  className="form-select"
                  value={trendGranularity}
                  onChange={(event) => setTrendGranularity(event.target.value)}
                  style={{ maxWidth: "160px", fontSize: "12px", padding: "6px 10px" }}
                >
                  <option value="day">Dia</option>
                  <option value="week">Semana</option>
                  <option value="month">Mes</option>
                </select>
              </div>
              <div className="chart-wrapper" style={{ height: 300 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={trendData} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
                    <defs>
                      <linearGradient id="colorHallazgos" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor={chartTheme.colors.accent} stopOpacity={0.3} />
                        <stop offset="95%" stopColor={chartTheme.colors.accent} stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid
                      strokeDasharray={chartTheme.grid.strokeDasharray}
                      stroke={chartTheme.grid.stroke}
                      vertical={false}
                    />
                    <XAxis
                      dataKey="name"
                      tick={chartTheme.axis.tick}
                      axisLine={chartTheme.axis.axisLine}
                      tickLine={false}
                    />
                    <YAxis
                      tick={chartTheme.axis.tick}
                      axisLine={false}
                      tickLine={false}
                      allowDecimals={false}
                    />
                    <Tooltip
                      contentStyle={chartTheme.tooltip.contentStyle}
                      cursor={{
                        stroke: chartTheme.colors.accent,
                        strokeWidth: 1,
                        strokeDasharray: "4 4",
                      }}
                    />
                    <Area
                      type="monotone"
                      dataKey="hallazgos"
                      stroke={chartTheme.colors.accent}
                      strokeWidth={2}
                      fill="url(#colorHallazgos)"
                      dot={{ r: 4, fill: chartTheme.colors.accent, stroke: getCSSVar("--bg-secondary"), strokeWidth: 2 }}
                      activeDot={{ r: 6, fill: chartTheme.colors.accentHover, stroke: getCSSVar("--bg-secondary"), strokeWidth: 2 }}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div className="chart-card">
              <h3 className="chart-title">Distribución por Estado</h3>
              <div className="chart-wrapper" style={{ height: 280 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={statusChartData}
                      cx="50%"
                      cy="50%"
                      innerRadius={65}
                      outerRadius={95}
                      paddingAngle={3}
                      dataKey="value"
                      stroke="none"
                    >
                      {statusChartData.map((entry) => (
                        <Cell key={entry.key} fill={chartTheme.colors.status[entry.key]} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={chartTheme.tooltip.contentStyle} />
                    <Legend
                      verticalAlign="bottom"
                      iconType="circle"
                      iconSize={8}
                      wrapperStyle={{ fontSize: "12px", color: chartTheme.axis.tick.fill }}
                    />
                  </PieChart>
                </ResponsiveContainer>
                <div className="donut-center">
                  <span className="donut-center-value">{totalStatusFindings}</span>
                  <span className="donut-center-label">Total</span>
                </div>
              </div>
            </div>

            <div className="chart-card">
              <h3 className="chart-title">Activos con más hallazgos</h3>
              <div className="table-container">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Activo</th>
                      <th>Severidad máx.</th>
                      <th>Responsable</th>
                      <th>Total</th>
                    </tr>
                  </thead>
                  <tbody>
                    {topAssets.map((asset) => (
                      <tr key={asset.assetId}>
                        <td>
                          <span className="file-path">{asset.name}</span>
                        </td>
                        <td>
                          <span className={`badge badge-${asset.maxSeverity || "info"}`}>
                            {severityLabels[asset.maxSeverity] || "Info"}
                          </span>
                        </td>
                        <td>{asset.owner || "—"}</td>
                        <td className="findings-occurrences">{asset.total}</td>
                      </tr>
                    ))}
                    {topAssets.length === 0 && (
                      <tr>
                        <td colSpan={4}>
                          <div className="empty-state">
                            <p>Sin datos disponibles</p>
                          </div>
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="chart-card chart-card--wide">
              <h3 className="chart-title">Mapa de Calor: Activos × Severidad</h3>
              <div className="heatmap">
                <div className="heatmap-header">
                  <span className="heatmap-corner" />
                  {["Crítica", "Alta", "Media", "Baja", "Info"].map((label) => (
                    <span key={label} className="heatmap-col-label">{label}</span>
                  ))}
                </div>
                {heatmapData.map((row) => {
                  const values = Object.values(row).filter((value) => typeof value === "number");
                  const maxVal = Math.max(1, ...values);
                  return (
                    <div key={row.asset} className="heatmap-row">
                      <span className="heatmap-row-label">{row.asset}</span>
                      {["critical", "high", "medium", "low", "info"].map((sev) => {
                        const value = row[sev] || 0;
                        const intensity = value / maxVal;
                        const alpha = intensity * 0.6 + 0.15;
                        const baseColor = chartTheme.colors.severity[sev];
                        const heatColor = toRgba(baseColor, alpha);
                        return (
                          <span
                            key={sev}
                            className="heatmap-cell"
                            style={{
                              backgroundColor: value > 0
                                ? heatColor
                                : "var(--bg-tertiary)",
                            }}
                            title={`${row.asset}: ${value} ${sev}`}
                          >
                            {value > 0 ? value : ""}
                          </span>
                        );
                      })}
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </>
      )}
    </section>
  );
}
