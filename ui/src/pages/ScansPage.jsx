import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { EmptyState } from "../components/common/EmptyState";
import { ScansTableSkeleton } from "../components/scans/ScansTableSkeleton";
import { useKeyboardShortcut } from "../hooks/useKeyboardShortcut";
import { useAuth } from "../context/AuthContext";
import { useProject } from "../context/ProjectContext";
import { API_BASE, authFetch, unwrapItems } from "../utils/api";
import { scanStatusLabels } from "../utils/constants";
import { formatDuration } from "../utils/formatters";
import "../Scans.css";

const assetTypeLabels = {
  web_app: "web",
  api: "api",
  repo: "repo",
  host: "host",
  container: "contenedor",
  network_range: "rango",
};

const scanToolOptions = [
  { value: "vulnapi", label: "VulnAPI", types: ["web_app", "api"] },
  { value: "wapiti", label: "Wapiti", types: ["web_app"] },
  { value: "nuclei", label: "Nuclei", types: ["web_app", "api"] },
  { value: "osv", label: "OSV", types: ["repo"] },
  { value: "sarif", label: "SARIF", types: ["repo"] },
];

export default function ScansPage() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const { projectId } = useProject();
  const [scans, setScans] = useState([]);
  const [scansLoading, setScansLoading] = useState(false);
  const [scanFilters, setScanFilters] = useState({ tool: "all", status: "all", search: "" });
  const [showAllScans, setShowAllScans] = useState(false);
  const [selectedScan, setSelectedScan] = useState(null);
  const [scanLogs, setScanLogs] = useState([]);
  const [showFullLogs, setShowFullLogs] = useState(false);
  const [showScanWizard, setShowScanWizard] = useState(false);
  const [wizardStep, setWizardStep] = useState(1);
  const [scanForm, setScanForm] = useState({
    assetId: "",
    tool: "vulnapi",
    targetUrl: "",
    targetPath: "",
    reportPath: "/tmp/report.json",
  });
  const [assets, setAssets] = useState([]);
  const [findings, setFindings] = useState([]);
  const [error, setError] = useState("");
  const [reloadToken, setReloadToken] = useState(0);

  const handleRetry = useCallback(() => {
    setError("");
    setReloadToken((prev) => prev + 1);
  }, []);

  const selectedScanAsset = useMemo(
    () => assets.find((asset) => String(asset.id) === scanForm.assetId) || null,
    [assets, scanForm.assetId]
  );

  const allowedScanTools = useMemo(() => {
    if (!selectedScanAsset) {
      return new Set();
    }
    return new Set(
      scanToolOptions
        .filter((option) => option.types.includes(selectedScanAsset.type))
        .map((option) => option.value)
    );
  }, [selectedScanAsset]);

  useEffect(() => {
    if (!selectedScanAsset) {
      return;
    }
    if (!allowedScanTools.has(scanForm.tool)) {
      const fallback = scanToolOptions.find((option) =>
        option.types.includes(selectedScanAsset.type)
      );
      setScanForm((prev) => ({ ...prev, tool: fallback ? fallback.value : "vulnapi" }));
    }
  }, [allowedScanTools, scanForm.tool, selectedScanAsset]);

  useEffect(() => {
    if (!scanForm.assetId && assets.length > 0) {
      setScanForm((prev) => ({ ...prev, assetId: String(assets[0].id) }));
    }
  }, [assets, scanForm.assetId]);

  useEffect(() => {
    let cancelled = false;

    async function loadScans() {
      if (!user || !projectId) {
        if (!cancelled) {
          setScans([]);
          setScansLoading(false);
        }
        return;
      }
      try {
        if (!cancelled) {
          setScansLoading(true);
        }
        const response = await authFetch(`${API_BASE}/scans?project_id=${projectId}`);
        if (!response.ok) {
          return;
        }
        const data = await response.json();
        if (!cancelled) {
          setScans(unwrapItems(data));
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message || "No se pudieron cargar los escaneos");
        }
      } finally {
        if (!cancelled) {
          setScansLoading(false);
        }
      }
    }

    loadScans();
    return () => {
      cancelled = true;
    };
  }, [projectId, user, reloadToken]);

  useEffect(() => {
    const onEscape = () => {
      setShowScanWizard(false);
      setSelectedScan(null);
    };
    document.addEventListener("shortcut:escape", onEscape);
    return () => document.removeEventListener("shortcut:escape", onEscape);
  }, []);

  useEffect(() => {
    if (!user || !projectId) {
      return undefined;
    }
    const hasRunning = scans.some((scan) => scan.status === "running" || scan.status === "queued");
    if (!hasRunning) {
      return undefined;
    }
    let cancelled = false;
    const interval = setInterval(async () => {
      try {
        const response = await authFetch(`${API_BASE}/scans?project_id=${projectId}`);
        if (!response.ok) {
          return;
        }
        const data = await response.json();
        if (!cancelled) {
          setScans(unwrapItems(data));
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message || "No se pudieron actualizar los escaneos");
        }
      }
    }, 5000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [scans, user, projectId]);

  useEffect(() => {
    let cancelled = false;

    async function loadLogs() {
      if (!user || !selectedScan) {
        setScanLogs([]);
        return;
      }
      try {
        const response = await authFetch(`${API_BASE}/scans/${selectedScan}/logs`);
        if (!response.ok) {
          return;
        }
        const data = await response.json();
        if (!cancelled) {
          setScanLogs(data);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message || "No se pudieron cargar los logs del escaneo");
        }
      }
    }

    loadLogs();
    return () => {
      cancelled = true;
    };
  }, [selectedScan, user]);

  useEffect(() => {
    let cancelled = false;

    async function loadAssetsAndFindings() {
      if (!user || !projectId) {
        if (!cancelled) {
          setAssets([]);
          setFindings([]);
        }
        return;
      }
      try {
        const [findingsResponse, assetsResponse] = await Promise.all([
          authFetch(`${API_BASE}/findings?project_id=${projectId}`),
          authFetch(`${API_BASE}/assets?project_id=${projectId}`),
        ]);
        if (!findingsResponse.ok || !assetsResponse.ok) {
          throw new Error("API no disponible");
        }
        const [findingsData, assetsData] = await Promise.all([
          findingsResponse.json(),
          assetsResponse.json(),
        ]);
        if (!cancelled) {
          setFindings(unwrapItems(findingsData));
          setAssets(unwrapItems(assetsData));
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message || "No se pudieron cargar los datos");
        }
      }
    }

    loadAssetsAndFindings();
    return () => {
      cancelled = true;
    };
  }, [projectId, user, reloadToken]);

  const scanLogLines = useMemo(() => {
    const text = scanLogs.map((log) => log.message).join("\n");
    return text ? text.split("\n") : [];
  }, [scanLogs]);

  const scanLogPreview = useMemo(() => {
    if (showFullLogs) {
      return scanLogLines.join("\n");
    }
    return scanLogLines.slice(-200).join("\n");
  }, [scanLogLines, showFullLogs]);

  const scanStatusCounts = useMemo(() => {
    const counts = { queued: 0, running: 0, finished: 0, failed: 0 };
    scans.forEach((scan) => {
      if (counts[scan.status] !== undefined) {
        counts[scan.status] += 1;
      }
    });
    return counts;
  }, [scans]);

  const filteredScans = useMemo(() => {
    const search = scanFilters.search.trim().toLowerCase();
    const list = scans.filter((scan) => {
      if (scanFilters.tool !== "all" && scan.tool !== scanFilters.tool) {
        return false;
      }
      if (scanFilters.status !== "all" && scan.status !== scanFilters.status) {
        return false;
      }
      if (!search) {
        return true;
      }
      const metadata = scan.metadata || scan.scan_metadata || {};
      const target = metadata.target_url || metadata.target_path || metadata.report_path || "";
      return [String(scan.id), scan.tool, scan.status, target]
        .join(" ")
        .toLowerCase()
        .includes(search);
    });
    return list.sort((a, b) => new Date(b.started_at) - new Date(a.started_at));
  }, [scans, scanFilters]);

  const visibleScans = useMemo(() => {
    if (showAllScans) {
      return filteredScans;
    }
    return filteredScans.slice(0, 20);
  }, [filteredScans, showAllScans]);

  const scanFiltersActive = useMemo(() => {
    return (
      scanFilters.tool !== "all" ||
      scanFilters.status !== "all" ||
      scanFilters.search.trim() !== ""
    );
  }, [scanFilters]);

  async function handleScanSubmit(event) {
    event.preventDefault();
    if (!projectId) {
      return;
    }
    if (!selectedScanAsset) {
      setError("Selecciona un activo antes de ejecutar un escaneo");
      return;
    }
    if (!allowedScanTools.has(scanForm.tool)) {
      setError("La herramienta seleccionada no es compatible con el tipo de activo");
      return;
    }
    const args = { project_id: Number(projectId), report_path: scanForm.reportPath };
    if (scanForm.tool === "vulnapi" || scanForm.tool === "wapiti" || scanForm.tool === "nuclei") {
      args.target_url = selectedScanAsset.uri || scanForm.targetUrl;
    } else {
      args.target_path = selectedScanAsset.uri || scanForm.targetPath;
    }
    const response = await authFetch(`${API_BASE}/scans/run`, {
      method: "POST",
      body: JSON.stringify({ tool: scanForm.tool, args }),
    });
    if (response.ok) {
      const data = await response.json();
      setScans((prev) => [data, ...prev]);
    }
  }

  async function handleRerunScan(scan) {
    if (!projectId) {
      return;
    }
    const metadata = { ...(scan.metadata || scan.scan_metadata || {}) };
    if (!metadata.project_id) {
      metadata.project_id = Number(projectId);
    }
    const response = await authFetch(`${API_BASE}/scans/run`, {
      method: "POST",
      body: JSON.stringify({ tool: scan.tool, args: metadata }),
    });
    if (response.ok) {
      const data = await response.json();
      setScans((prev) => [data, ...prev]);
    }
  }

  async function handleDeleteScan(scanId) {
    const response = await authFetch(`${API_BASE}/scans/${scanId}`, {
      method: "DELETE",
    });
    if (response.ok) {
      setScans((prev) => prev.filter((scan) => scan.id !== scanId));
      if (selectedScan === scanId) {
        setSelectedScan(null);
      }
    }
  }

  function handleViewFindings(scanId) {
    navigate(`/findings?scan_id=${scanId}`);
  }

  useKeyboardShortcut("n", () => {
    setShowScanWizard(true);
    setWizardStep(1);
  }, {
    enabled: Boolean(projectId),
  });

  if (!projectId) {
    return (
      <EmptyState
        icon="scans"
        title="Selecciona un proyecto"
        description="Elige un cliente y proyecto en el panel lateral para acceder a los escaneos."
      />
    );
  }

  return (
    <section className="scans-section">
      <div className="scans-header">
        <div className="scans-header-info">
          <h2 className="scans-title">
            <svg className="scans-title-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
            </svg>
            Escaneos
          </h2>
          <p className="scans-subtitle">Monitoreo de herramientas de seguridad</p>
        </div>
        <div className="scans-header-actions">
          <span className="badge badge-accent">{filteredScans.length} scans</span>
          <button
            className="btn btn-primary"
            type="button"
            onClick={() => {
              setShowScanWizard(true);
              setWizardStep(1);
            }}
            disabled={assets.length === 0}
            title="Nuevo escaneo (N)"
          >
            ▸ Nuevo scan
            <kbd className="btn-shortcut-hint">N</kbd>
          </button>
        </div>
      </div>

      {assets.length === 0 && (
        <div className="scans-notice">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="12" cy="12" r="10" />
            <line x1="12" y1="8" x2="12" y2="12" />
            <line x1="12" y1="16" x2="12.01" y2="16" />
          </svg>
          <span>Registra al menos un activo antes de ejecutar escaneos.</span>
        </div>
      )}

      <div className="scans-kpis">
        <div className="scans-kpi scans-kpi--queued" onClick={() => setScanFilters((prev) => ({ ...prev, status: "queued" }))}>
          <div className="scans-kpi-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="10" />
              <path d="M12 6v6l4 2" />
            </svg>
          </div>
          <span className="scans-kpi-value">{scanStatusCounts.queued}</span>
          <span className="scans-kpi-label">En cola</span>
        </div>

        <div
          className={`scans-kpi scans-kpi--running ${scanStatusCounts.running > 0 ? "scans-kpi--pulse" : ""}`}
          onClick={() => setScanFilters((prev) => ({ ...prev, status: "running" }))}
        >
          <div className="scans-kpi-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M21 12a9 9 0 11-6.219-8.56" />
            </svg>
          </div>
          <span className="scans-kpi-value">{scanStatusCounts.running}</span>
          <span className="scans-kpi-label">Ejecutando</span>
        </div>

        <div className="scans-kpi scans-kpi--finished" onClick={() => setScanFilters((prev) => ({ ...prev, status: "finished" }))}>
          <div className="scans-kpi-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M22 11.08V12a10 10 0 11-5.93-9.14" />
              <path d="M22 4L12 14.01l-3-3" />
            </svg>
          </div>
          <span className="scans-kpi-value">{scanStatusCounts.finished}</span>
          <span className="scans-kpi-label">Finalizados</span>
        </div>

        <div className="scans-kpi scans-kpi--failed" onClick={() => setScanFilters((prev) => ({ ...prev, status: "failed" }))}>
          <div className="scans-kpi-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="10" />
              <path d="M15 9l-6 6M9 9l6 6" />
            </svg>
          </div>
          <span className="scans-kpi-value">{scanStatusCounts.failed}</span>
          <span className="scans-kpi-label">Fallidos</span>
        </div>
      </div>

      <div className="scans-filters">
        <div className="form-group">
          <label className="form-label">Herramienta</label>
          <select
            className="form-select"
            value={scanFilters.tool}
            onChange={(event) => setScanFilters((prev) => ({ ...prev, tool: event.target.value }))}
          >
            <option value="all">Todas</option>
            {scanToolOptions.map((option) => (
              <option key={option.value} value={option.value}>{option.label}</option>
            ))}
          </select>
        </div>
        <div className="form-group">
          <label className="form-label">Estado</label>
          <select
            className="form-select"
            value={scanFilters.status}
            onChange={(event) => setScanFilters((prev) => ({ ...prev, status: event.target.value }))}
          >
            <option value="all">Todos</option>
            <option value="queued">En cola</option>
            <option value="running">Ejecutando</option>
            <option value="finished">Finalizado</option>
            <option value="failed">Fallido</option>
          </select>
        </div>
        <div className="form-group scans-filter-search">
          <label className="form-label">Buscar</label>
          <div className="search-input-wrapper">
            <input
              className="form-input"
              type="text"
              placeholder="id, herramienta, objetivo..."
              value={scanFilters.search}
              onChange={(event) => setScanFilters((prev) => ({ ...prev, search: event.target.value }))}
              data-shortcut-search
            />
            <kbd className="search-shortcut-hint">/</kbd>
          </div>
        </div>
        <label className="scans-filter-toggle">
          <input type="checkbox" checked={showAllScans} onChange={() => setShowAllScans((prev) => !prev)} />
          <span>Mostrar todos</span>
        </label>
      </div>

      {error ? (
        <EmptyState
          icon="error"
          title="No pudimos cargar los escaneos"
          description={`Reintenta para ver el historial de scans. ${error}`}
          action={{ label: "Reintentar", onClick: handleRetry }}
          secondaryAction={{ label: "Cerrar", onClick: () => setError("") }}
        />
      ) : scansLoading ? (
        <ScansTableSkeleton />
      ) : visibleScans.length === 0 ? (
        scanFiltersActive ? (
          <EmptyState
            icon="search"
            title="Sin resultados"
            description="No se encontraron escaneos con los filtros actuales. Ajusta herramienta, estado o búsqueda."
            action={{
              label: "Limpiar filtros",
              onClick: () => setScanFilters({ tool: "all", status: "all", search: "" }),
            }}
          />
        ) : (
          <EmptyState
            icon="scans"
            title="No hay escaneos"
            description="Ejecuta un escaneo automatizado sobre tus activos con Wapiti, Nuclei, OSV Scanner, o VulnAPI."
            action={{
              label: "Nuevo escaneo",
              onClick: () => {
                setShowScanWizard(true);
                setWizardStep(1);
              },
            }}
          />
        )
      ) : (
        <div className="scans-table-wrap">
          <table className="scans-table">
            <thead>
              <tr>
                <th>#</th>
                <th>Herramienta</th>
                <th>Estado</th>
                <th>Activo</th>
                <th>Objetivo</th>
                <th>Inicio</th>
                <th>Duración</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {visibleScans.map((scan) => {
                const meta = scan.metadata || scan.scan_metadata || {};
                const target = meta.target_url || meta.target_path || meta.report_path || "—";
                const scanAsset = assets.find((asset) => String(asset.id) === String(scan.asset_id));
                const started = scan.started_at ? new Date(scan.started_at).toLocaleString() : "—";
                const duration = scan.started_at && scan.finished_at
                  ? formatDuration(new Date(scan.finished_at) - new Date(scan.started_at))
                  : scan.status === "running" ? "..." : "—";
                return (
                  <tr
                    key={scan.id}
                    className={`scans-row ${selectedScan === scan.id ? "scans-row--selected" : ""} scans-row--${scan.status}`}
                    onClick={() => setSelectedScan(selectedScan === scan.id ? null : scan.id)}
                  >
                    <td className="scans-cell-id">{scan.id}</td>
                    <td className="scans-cell-tool">{scan.tool}</td>
                    <td>
                      <span className={`scans-badge scans-badge--${scan.status}`}>
                        <span className="scans-badge-dot" />
                        {scanStatusLabels[scan.status]}
                      </span>
                      {scan.status === "running" && (
                        <div className="scans-minibar">
                          <div className="scans-minibar-fill" />
                        </div>
                      )}
                    </td>
                    <td className="scans-cell-asset">{scanAsset?.name || "—"}</td>
                    <td className="scans-cell-target">{target}</td>
                    <td className="scans-cell-date">{started}</td>
                    <td className="scans-cell-duration">{duration}</td>
                    <td className="scans-cell-actions" onClick={(event) => event.stopPropagation()}>
                      <button
                        className="scans-action-btn"
                        type="button"
                        title="Ver hallazgos"
                        onClick={() => handleViewFindings(scan.id)}
                      >
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <circle cx="11" cy="11" r="8" />
                          <path d="M21 21l-4.35-4.35" />
                        </svg>
                      </button>
                      <button
                        className="scans-action-btn"
                        type="button"
                        title="Re-ejecutar"
                        onClick={() => handleRerunScan(scan)}
                      >
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <path d="M21 12a9 9 0 11-6.219-8.56" />
                        </svg>
                      </button>
                      <button
                        className="scans-action-btn scans-action-btn--danger"
                        type="button"
                        title="Eliminar"
                        onClick={() => {
                          if (window.confirm("¿Eliminar este escaneo?")) {
                            handleDeleteScan(scan.id);
                          }
                        }}
                      >
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <path d="M3 6h18" />
                          <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
                        </svg>
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {selectedScan && (() => {
        const scan = scans.find((item) => item.id === selectedScan);
        if (!scan) {
          return null;
        }
        const scanFindings = findings.filter((finding) => finding.scan_id === scan.id);
        return (
          <div className="scans-detail-panel">
            <div className="scans-detail-header">
              <h3>
                Scan <span className="mono">#{scan.id}</span> — {scan.tool}
              </h3>
              <button className="btn btn-ghost btn-sm" type="button" onClick={() => setSelectedScan(null)}>✕</button>
            </div>

            <div className="scans-detail-body">
              <div className="scans-detail-meta">
                <div className="scans-detail-meta-item">
                  <span className="label">Hallazgos</span>
                  <div className="scans-detail-findings">
                    {scanFindings.length === 0 ? (
                      <span className="muted">Ninguno</span>
                    ) : (
                      <>
                        <strong>{scanFindings.length}</strong>
                        {["critical", "high", "medium", "low", "info"].map((severity) => {
                          const count = scanFindings.filter((finding) => finding.severity === severity).length;
                          return count > 0 ? (
                            <span key={severity} className={`badge badge-${severity}`}>{count}</span>
                          ) : null;
                        })}
                      </>
                    )}
                  </div>
                </div>
              </div>

              <div className="scans-terminal">
                <div className="scans-terminal-bar">
                  <span className="dot red" />
                  <span className="dot yellow" />
                  <span className="dot green" />
                  <span className="scans-terminal-name">scan-{scan.id}.log</span>
                  {scanLogLines.length > 0 && (
                    <button
                      className="scans-terminal-toggle"
                      type="button"
                      onClick={() => setShowFullLogs((prev) => !prev)}
                    >
                      {showFullLogs ? "Recientes" : "Completos"}
                    </button>
                  )}
                </div>
                <pre className="scans-terminal-output">
                  {scanLogPreview || "$ esperando logs..."}
                </pre>
              </div>
            </div>
          </div>
        );
      })()}

      {showScanWizard && (
        <div className="wizard-overlay" onClick={() => { setShowScanWizard(false); setWizardStep(1); }}>
          <div className="wizard-modal" onClick={(event) => event.stopPropagation()}>
            <div className="wizard-header">
              <h3>▸ Nuevo escaneo</h3>
              <button className="btn btn-ghost" type="button" onClick={() => { setShowScanWizard(false); setWizardStep(1); }}>✕</button>
            </div>

            <div className="wizard-stepper">
              <div className={`wizard-step ${wizardStep >= 1 ? "wizard-step--active" : ""} ${wizardStep > 1 ? "wizard-step--done" : ""}`}>
                <span className="wizard-step-number">1</span>
                <span className="wizard-step-label">Activo</span>
              </div>
              <div className="wizard-step-line" />
              <div className={`wizard-step ${wizardStep >= 2 ? "wizard-step--active" : ""} ${wizardStep > 2 ? "wizard-step--done" : ""}`}>
                <span className="wizard-step-number">2</span>
                <span className="wizard-step-label">Herramienta</span>
              </div>
              <div className="wizard-step-line" />
              <div className={`wizard-step ${wizardStep >= 3 ? "wizard-step--active" : ""}`}>
                <span className="wizard-step-number">3</span>
                <span className="wizard-step-label">Confirmar</span>
              </div>
            </div>

            <div className="wizard-body">
              {wizardStep === 1 && (
                <div className="wizard-panel">
                  <p className="wizard-instruction">Selecciona el activo que deseas escanear:</p>
                  <div className="wizard-asset-list">
                    {assets.map((asset) => (
                      <div
                        key={asset.id}
                        className={`wizard-asset-card ${scanForm.assetId === String(asset.id) ? "wizard-asset-card--selected" : ""}`}
                        onClick={() => setScanForm((prev) => ({ ...prev, assetId: String(asset.id) }))}
                      >
                        <div className="wizard-asset-icon">
                          {asset.type === "web_app" && "🌐"}
                          {asset.type === "api" && "🔌"}
                          {asset.type === "host" && "🖥"}
                          {asset.type === "repo" && "📦"}
                          {asset.type === "container" && "🐳"}
                          {asset.type === "network_range" && "🔗"}
                        </div>
                        <div className="wizard-asset-info">
                          <span className="wizard-asset-name">{asset.name}</span>
                          <span className="wizard-asset-meta">
                            {asset.uri} · {assetTypeLabels[asset.type] || asset.type}
                            {asset.environment ? ` · ${asset.environment}` : ""}
                          </span>
                        </div>
                        <div className="wizard-asset-check">
                          {scanForm.assetId === String(asset.id) && (
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3">
                              <path d="M20 6L9 17l-5-5" />
                            </svg>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {wizardStep === 2 && (
                <div className="wizard-panel">
                  <p className="wizard-instruction">
                    Selecciona la herramienta para escanear
                    <strong> {assets.find((asset) => String(asset.id) === scanForm.assetId)?.name}</strong>:
                  </p>
                  <div className="wizard-tool-grid">
                    {scanToolOptions.map((option) => {
                      const isDisabled = !allowedScanTools.has(option.value);
                      const isSelected = scanForm.tool === option.value;
                      return (
                        <div
                          key={option.value}
                          className={`wizard-tool-card ${isSelected ? "wizard-tool-card--selected" : ""} ${isDisabled ? "wizard-tool-card--disabled" : ""}`}
                          onClick={() => !isDisabled && setScanForm((prev) => ({ ...prev, tool: option.value }))}
                        >
                          <span className="wizard-tool-icon">
                            {option.value === "nuclei" && "☢"}
                            {option.value === "wapiti" && "🦊"}
                            {option.value === "vulnapi" && "🔌"}
                            {option.value === "osv" && "📦"}
                            {option.value === "sarif" && "📄"}
                          </span>
                          <span className="wizard-tool-name">{option.label}</span>
                          <span className="wizard-tool-types">
                            {option.types.map((type) => assetTypeLabels[type] || type).join(", ")}
                          </span>
                          {isDisabled && (
                            <span className="wizard-tool-incompatible">No compatible</span>
                          )}
                          {isSelected && (
                            <div className="wizard-tool-check">
                              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3">
                                <path d="M20 6L9 17l-5-5" />
                              </svg>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>

                  <div className="wizard-extra-fields">
                    {(scanForm.tool === "vulnapi" || scanForm.tool === "wapiti" || scanForm.tool === "nuclei") && (
                      <div className="form-group">
                        <label className="form-label">URL objetivo</label>
                        <input
                          className="form-input"
                          type="text"
                          placeholder="https://target.com"
                          value={selectedScanAsset?.uri || scanForm.targetUrl}
                          onChange={(event) => setScanForm((prev) => ({ ...prev, targetUrl: event.target.value }))}
                          disabled={Boolean(scanForm.assetId)}
                        />
                        <span className="form-hint">Auto-completado desde el activo</span>
                      </div>
                    )}
                    {(scanForm.tool === "osv" || scanForm.tool === "sarif") && (
                      <div className="form-group">
                        <label className="form-label">Ruta objetivo</label>
                        <input
                          className="form-input"
                          type="text"
                          placeholder="/path/to/project"
                          value={selectedScanAsset?.uri || scanForm.targetPath}
                          onChange={(event) => setScanForm((prev) => ({ ...prev, targetPath: event.target.value }))}
                          disabled={Boolean(scanForm.assetId)}
                        />
                      </div>
                    )}
                    <div className="form-group">
                      <label className="form-label">Ruta del reporte</label>
                      <input
                        className="form-input"
                        type="text"
                        placeholder="/tmp/report.json"
                        value={scanForm.reportPath}
                        onChange={(event) => setScanForm((prev) => ({ ...prev, reportPath: event.target.value }))}
                      />
                    </div>
                  </div>
                </div>
              )}

              {wizardStep === 3 && (() => {
                const selectedAsset = assets.find((asset) => String(asset.id) === scanForm.assetId);
                const selectedTool = scanToolOptions.find((tool) => tool.value === scanForm.tool);
                const meta = scanForm.targetUrl || scanForm.targetPath || selectedAsset?.uri || "—";
                return (
                  <div className="wizard-panel">
                    <p className="wizard-instruction">Confirma la configuración del escaneo:</p>
                    <div className="wizard-summary">
                      <div className="wizard-summary-row">
                        <span className="wizard-summary-label">Activo</span>
                        <span className="wizard-summary-value">
                          {selectedAsset?.name}
                          <span className="badge badge-accent" style={{ marginLeft: "8px" }}>
                            {assetTypeLabels[selectedAsset?.type] || selectedAsset?.type}
                          </span>
                        </span>
                      </div>
                      <div className="wizard-summary-row">
                        <span className="wizard-summary-label">Herramienta</span>
                        <span className="wizard-summary-value mono">{selectedTool?.label || scanForm.tool}</span>
                      </div>
                      <div className="wizard-summary-row">
                        <span className="wizard-summary-label">Objetivo</span>
                        <span className="wizard-summary-value mono">{meta}</span>
                      </div>
                      <div className="wizard-summary-row">
                        <span className="wizard-summary-label">Reporte</span>
                        <span className="wizard-summary-value mono">{scanForm.reportPath || "/tmp/report.json"}</span>
                      </div>
                    </div>
                    <div className="wizard-confirm-notice">
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <circle cx="12" cy="12" r="10" />
                        <line x1="12" y1="8" x2="12" y2="12" />
                        <line x1="12" y1="16" x2="12.01" y2="16" />
                      </svg>
                      <span>El scan se añadirá a la cola y el worker lo ejecutará automáticamente.</span>
                    </div>
                  </div>
                );
              })()}
            </div>

            <div className="wizard-footer">
              {wizardStep > 1 && (
                <button className="btn btn-secondary" type="button" onClick={() => setWizardStep((prev) => prev - 1)}>
                  ← Atrás
                </button>
              )}
              <div className="wizard-footer-right">
                <button className="btn btn-ghost" type="button" onClick={() => { setShowScanWizard(false); setWizardStep(1); }}>
                  Cancelar
                </button>
                {wizardStep < 3 && (
                  <button
                    className="btn btn-primary"
                    type="button"
                    disabled={
                      (wizardStep === 1 && !scanForm.assetId) ||
                      (wizardStep === 2 && (!scanForm.tool || (scanForm.assetId && allowedScanTools.size > 0 && !allowedScanTools.has(scanForm.tool))))
                    }
                    onClick={() => setWizardStep((prev) => prev + 1)}
                  >
                    Siguiente →
                  </button>
                )}
                {wizardStep === 3 && (
                  <button
                    className="btn btn-primary"
                    type="button"
                    onClick={(event) => {
                      handleScanSubmit(event);
                      setShowScanWizard(false);
                      setWizardStep(1);
                    }}
                  >
                    ▸ Ejecutar scan
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
