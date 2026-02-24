import { useCallback, useEffect, useMemo, useState } from "react";
import { EmptyState } from "../components/common/EmptyState";
import { SkeletonTable } from "../components/common/LoadingSkeleton";
import { useAuth } from "../context/AuthContext";
import { useProject } from "../context/ProjectContext";
import { API_BASE, authFetch, unwrapItems } from "../utils/api";
import "../Audit.css";

export default function AuditPage() {
  const { user } = useAuth();
  const { projectId } = useProject();
  const [auditLogs, setAuditLogs] = useState([]);
  const [auditLoading, setAuditLoading] = useState(false);
  const [auditFilters, setAuditFilters] = useState({
    user: "",
    action: "all",
    from: "",
    to: "",
    search: "",
  });
  const [selectedAudit, setSelectedAudit] = useState(null);
  const [showAllAudit, setShowAllAudit] = useState(false);
  const [error, setError] = useState("");
  const [reloadToken, setReloadToken] = useState(0);

  const handleRetry = useCallback(() => {
    setError("");
    setReloadToken((prev) => prev + 1);
  }, []);

  useEffect(() => {
    let cancelled = false;

    async function loadAuditLogs() {
      if (!user) {
        if (!cancelled) {
          setAuditLogs([]);
          setAuditLoading(false);
        }
        return;
      }
      try {
        if (!cancelled) {
          setAuditLoading(true);
        }
        const response = await authFetch(`${API_BASE}/audit-logs`);
        if (!response.ok) {
          return;
        }
        const data = await response.json();
        if (!cancelled) {
          setAuditLogs(unwrapItems(data));
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message || "No se pudieron cargar los logs de auditoría");
        }
      } finally {
        if (!cancelled) {
          setAuditLoading(false);
        }
      }
    }

    loadAuditLogs();
    return () => {
      cancelled = true;
    };
  }, [user, reloadToken]);

  useEffect(() => {
    const onEscape = () => {
      setSelectedAudit(null);
    };
    document.addEventListener("shortcut:escape", onEscape);
    return () => document.removeEventListener("shortcut:escape", onEscape);
  }, []);

  const filteredAuditLogs = useMemo(() => {
    const search = auditFilters.search.trim().toLowerCase();
    const userFilter = auditFilters.user.trim();
    const fromDate = auditFilters.from ? new Date(`${auditFilters.from}T00:00:00`) : null;
    const toDate = auditFilters.to ? new Date(`${auditFilters.to}T23:59:59`) : null;
    return auditLogs.filter((log) => {
      if (auditFilters.action !== "all" && log.method !== auditFilters.action) {
        return false;
      }
      if (userFilter && String(log.user_id || "") !== userFilter) {
        return false;
      }
      if (fromDate && new Date(log.created_at) < fromDate) {
        return false;
      }
      if (toDate && new Date(log.created_at) > toDate) {
        return false;
      }
      if (search) {
        const haystack = [log.method, log.path, log.status_code, log.ip, log.user_id]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        if (!haystack.includes(search)) {
          return false;
        }
      }
      return true;
    });
  }, [auditLogs, auditFilters]);

  const auditSummary = useMemo(() => {
    const total = filteredAuditLogs.length;
    const since = Date.now() - 24 * 60 * 60 * 1000;
    const errors24h = filteredAuditLogs.filter(
      (log) => log.status_code >= 400 && new Date(log.created_at).getTime() >= since
    ).length;
    return { total, errors24h };
  }, [filteredAuditLogs]);

  const auditMetrics = useMemo(() => {
    const now = new Date();
    const h24 = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    const recent = filteredAuditLogs.filter((log) => new Date(log.created_at) >= h24);
    const ok24h = recent.filter((log) => log.status_code >= 200 && log.status_code < 400).length;
    const uniqueUsers = new Set(filteredAuditLogs.map((log) => log.user_id).filter(Boolean)).size;
    return {
      total: filteredAuditLogs.length,
      errors24h: auditSummary.errors24h,
      ok24h,
      uniqueUsers,
    };
  }, [auditSummary.errors24h, filteredAuditLogs]);

  const visibleAuditLogs = useMemo(() => {
    const sorted = [...filteredAuditLogs].sort(
      (a, b) => new Date(b.created_at) - new Date(a.created_at)
    );
    if (showAllAudit) {
      return sorted;
    }
    return sorted.slice(0, 50);
  }, [filteredAuditLogs, showAllAudit]);

  if (!projectId) {
    return (
      <EmptyState
        icon="audit"
        title="Selecciona un proyecto"
        description="Elige un cliente y proyecto en el panel lateral para acceder a la auditoría."
      />
    );
  }

  return (
    <section className={`audit-section ${selectedAudit ? "has-drawer" : ""}`}>
      <div className="audit-header">
        <div className="audit-header-info">
          <h2 className="audit-title">
            <svg
              className="audit-title-icon"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" />
              <polyline points="14 2 14 8 20 8" />
              <line x1="16" y1="13" x2="8" y2="13" />
              <line x1="16" y1="17" x2="8" y2="17" />
              <polyline points="10 9 9 9 8 9" />
            </svg>
            Auditoría
          </h2>
          <p className="audit-subtitle">Registro de actividad y requests del sistema</p>
        </div>
        <div className="audit-header-actions">
          <span className="badge badge-accent">{filteredAuditLogs.length} entradas</span>
        </div>
      </div>

      <div className="audit-kpis">
        <div className="audit-kpi">
          <div className="audit-kpi-icon audit-kpi-icon--total">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
            </svg>
          </div>
          <span className="audit-kpi-value">{auditMetrics.total}</span>
          <span className="audit-kpi-label">Eventos totales</span>
        </div>
        <div className="audit-kpi">
          <div className="audit-kpi-icon audit-kpi-icon--errors">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="10" />
              <path d="M15 9l-6 6M9 9l6 6" />
            </svg>
          </div>
          <span className="audit-kpi-value">{auditMetrics.errors24h}</span>
          <span className="audit-kpi-label">Errores (24h)</span>
        </div>
        <div className="audit-kpi">
          <div className="audit-kpi-icon audit-kpi-icon--ok">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M22 11.08V12a10 10 0 11-5.93-9.14" />
              <path d="M22 4L12 14.01l-3-3" />
            </svg>
          </div>
          <span className="audit-kpi-value">{auditMetrics.ok24h}</span>
          <span className="audit-kpi-label">Exitosos (24h)</span>
        </div>
        <div className="audit-kpi">
          <div className="audit-kpi-icon audit-kpi-icon--users">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4-4v2" />
              <circle cx="9" cy="7" r="4" />
            </svg>
          </div>
          <span className="audit-kpi-value">{auditMetrics.uniqueUsers}</span>
          <span className="audit-kpi-label">Usuarios activos</span>
        </div>
      </div>

      <div className="audit-filters">
        <div className="form-group">
          <label className="form-label">Usuario</label>
          <input
            className="form-input"
            type="text"
            placeholder="ID o email"
            value={auditFilters.user}
            onChange={(event) =>
              setAuditFilters((prev) => ({ ...prev, user: event.target.value }))
            }
          />
        </div>
        <div className="form-group">
          <label className="form-label">Método</label>
          <select
            className="form-select"
            value={auditFilters.action}
            onChange={(event) =>
              setAuditFilters((prev) => ({ ...prev, action: event.target.value }))
            }
          >
            <option value="all">Todos</option>
            <option value="GET">GET</option>
            <option value="POST">POST</option>
            <option value="PATCH">PATCH</option>
            <option value="DELETE">DELETE</option>
            <option value="OPTIONS">OPTIONS</option>
          </select>
        </div>
        <div className="form-group">
          <label className="form-label">Desde</label>
          <input
            className="form-input"
            type="date"
            value={auditFilters.from}
            onChange={(event) =>
              setAuditFilters((prev) => ({ ...prev, from: event.target.value }))
            }
          />
        </div>
        <div className="form-group">
          <label className="form-label">Hasta</label>
          <input
            className="form-input"
            type="date"
            value={auditFilters.to}
            onChange={(event) =>
              setAuditFilters((prev) => ({ ...prev, to: event.target.value }))
            }
          />
        </div>
        <div className="form-group audit-filter-search">
          <label className="form-label">Buscar</label>
          <div className="search-input-wrapper">
            <input
              className="form-input"
              type="text"
              placeholder="ruta, IP, estado..."
              value={auditFilters.search}
              onChange={(event) =>
                setAuditFilters((prev) => ({ ...prev, search: event.target.value }))
              }
              data-shortcut-search
            />
            <kbd className="search-shortcut-hint">/</kbd>
          </div>
        </div>
        <label className="audit-filter-toggle">
          <input
            type="checkbox"
            checked={showAllAudit}
            onChange={() => setShowAllAudit((prev) => !prev)}
          />
          <span>Todo</span>
        </label>
      </div>

      {error ? (
        <EmptyState
          icon="error"
          title="No pudimos cargar la auditoría"
          description={`No se pudieron obtener los registros. ${error}`}
          action={{ label: "Reintentar", onClick: handleRetry }}
          secondaryAction={{ label: "Cerrar", onClick: () => setError("") }}
        />
      ) : auditLoading ? (
        <SkeletonTable rows={6} columns={6} />
      ) : visibleAuditLogs.length === 0 ? (
        <EmptyState
          icon="audit"
          title="Sin registros de auditoría"
          description="Los registros de actividad aparecerán aquí conforme los usuarios interactúen con la plataforma."
        />
      ) : (
        <div className="audit-table-wrap">
          <table className="audit-table">
            <thead>
              <tr>
                <th>Hora</th>
                <th>Usuario</th>
                <th>Método</th>
                <th>Ruta</th>
                <th>Estado</th>
                <th>IP</th>
              </tr>
            </thead>
            <tbody>
              {visibleAuditLogs.map((log) => {
                const isError = log.status_code >= 400;
                const isSelected = selectedAudit?.id === log.id;
                return (
                  <tr
                    key={log.id}
                    className={`audit-row ${isSelected ? "audit-row--selected" : ""} ${isError ? "audit-row--error" : ""}`}
                    onClick={() => setSelectedAudit(isSelected ? null : log)}
                  >
                    <td className="audit-cell-time">
                      {new Date(log.created_at).toLocaleTimeString()}
                      <span className="audit-cell-date">
                        {new Date(log.created_at).toLocaleDateString()}
                      </span>
                    </td>
                    <td className="audit-cell-user">
                      {log.user_id ? (
                        <span className="audit-user-badge">
                          <span className="audit-user-avatar">{String(log.user_id).charAt(0)}</span>
                          {log.user_id}
                        </span>
                      ) : (
                        <span className="audit-system-badge">Sistema</span>
                      )}
                    </td>
                    <td>
                      <span className={`audit-method audit-method--${log.method.toLowerCase()}`}>
                        {log.method}
                      </span>
                    </td>
                    <td className="audit-cell-path">{log.path}</td>
                    <td>
                      <span className={`audit-status ${isError ? "audit-status--error" : "audit-status--ok"}`}>
                        {log.status_code}
                      </span>
                    </td>
                    <td className="audit-cell-ip">{log.ip || "—"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {selectedAudit && (
        <aside className="audit-drawer">
          <div className="audit-drawer-header">
            <div>
              <span className={`audit-method audit-method--${selectedAudit.method.toLowerCase()}`}>
                {selectedAudit.method}
              </span>
              <h3 className="audit-drawer-title">{selectedAudit.path}</h3>
            </div>
            <button className="btn btn-ghost" onClick={() => setSelectedAudit(null)}>✕</button>
          </div>

          <div className="audit-drawer-body">
            <div className={`audit-drawer-status ${selectedAudit.status_code >= 400 ? "audit-drawer-status--error" : "audit-drawer-status--ok"}`}>
              <span className="audit-drawer-status-code">{selectedAudit.status_code}</span>
              <span className="audit-drawer-status-text">
                {selectedAudit.status_code >= 500
                  ? "Server Error"
                  : selectedAudit.status_code >= 400
                    ? "Client Error"
                    : selectedAudit.status_code >= 300
                      ? "Redirection"
                      : selectedAudit.status_code >= 200
                        ? "Success"
                        : "Info"}
              </span>
            </div>

            <div className="audit-meta-grid">
              <div className="audit-meta-item">
                <span className="audit-meta-label">Timestamp</span>
                <span>{new Date(selectedAudit.created_at).toLocaleString()}</span>
              </div>
              <div className="audit-meta-item">
                <span className="audit-meta-label">Usuario</span>
                <span>{selectedAudit.user_id ?? "Sistema"}</span>
              </div>
              <div className="audit-meta-item">
                <span className="audit-meta-label">Dirección IP</span>
                <span className="mono">{selectedAudit.ip || "—"}</span>
              </div>
              <div className="audit-meta-item">
                <span className="audit-meta-label">Método</span>
                <span className={`audit-method audit-method--${selectedAudit.method.toLowerCase()}`}>
                  {selectedAudit.method}
                </span>
              </div>
            </div>

            <div className="audit-request-block">
              <h4>Request</h4>
              <div className="audit-terminal">
                <div className="audit-terminal-bar">
                  <span className="dot red"></span>
                  <span className="dot yellow"></span>
                  <span className="dot green"></span>
                  <span className="audit-terminal-name">request</span>
                </div>
                <pre className="audit-terminal-output">{`${selectedAudit.method} ${selectedAudit.path} HTTP/1.1\nStatus: ${selectedAudit.status_code}\nUser: ${selectedAudit.user_id ?? "Sistema"}\nIP: ${selectedAudit.ip || "—"}\nTime: ${new Date(selectedAudit.created_at).toISOString()}`}</pre>
              </div>
            </div>
          </div>
        </aside>
      )}
    </section>
  );
}
