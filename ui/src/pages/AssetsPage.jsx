import { useCallback, useEffect, useMemo, useState } from "react";
import { EmptyState } from "../components/common/EmptyState";
import { AssetsTableSkeleton } from "../components/assets/AssetsTableSkeleton";
import { useKeyboardShortcut } from "../hooks/useKeyboardShortcut";
import { useAuth } from "../context/AuthContext";
import { useProject } from "../context/ProjectContext";
import { API_BASE, authFetch, unwrapItems } from "../utils/api";
import {
  EMPTY_ASSET_FORM,
  assetTypeLabels,
  envLabels,
  severityLabels,
} from "../utils/constants";
import { criticalityToBadge } from "../utils/formatters";
import "../Assets.css";

export default function AssetsPage() {
  const { user } = useAuth();
  const { projectId } = useProject();
  const [assets, setAssets] = useState([]);
  const [findings, setFindings] = useState([]);
  const [assetsLoading, setAssetsLoading] = useState(false);
  const [assetSearch, setAssetSearch] = useState("");
  const [assetTypeFilter, setAssetTypeFilter] = useState("all");
  const [assetEnvFilter, setAssetEnvFilter] = useState("all");
  const [assetCritFilter, setAssetCritFilter] = useState("all");
  const [selectedAsset, setSelectedAsset] = useState(null);
  const [showAssetModal, setShowAssetModal] = useState(false);
  const [assetEditTarget, setAssetEditTarget] = useState(null);
  const [assetForm, setAssetForm] = useState({ ...EMPTY_ASSET_FORM });
  const [error, setError] = useState("");
  const [reloadToken, setReloadToken] = useState(0);

  const handleRetry = useCallback(() => {
    setError("");
    setReloadToken((prev) => prev + 1);
  }, []);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        if (!cancelled) {
          setAssetsLoading(true);
        }
        if (!user || !projectId) {
          if (!cancelled) {
            setAssets([]);
            setFindings([]);
            setAssetsLoading(false);
          }
          return;
        }
        const findingsResponse = await authFetch(`${API_BASE}/findings?project_id=${projectId}`);
        const assetsResponse = await authFetch(`${API_BASE}/assets?project_id=${projectId}`);
        if (!findingsResponse.ok || !assetsResponse.ok) {
          throw new Error("API no disponible");
        }
        const findingsData = await findingsResponse.json();
        const assetsData = await assetsResponse.json();
        if (!cancelled) {
          setFindings(unwrapItems(findingsData));
          setAssets(unwrapItems(assetsData));
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message || "No se pudieron cargar los datos");
        }
      } finally {
        if (!cancelled) {
          setAssetsLoading(false);
        }
      }
    }

    load();
    return () => {
      cancelled = true;
    };
  }, [projectId, user, reloadToken]);

  useEffect(() => {
    const onEscape = () => {
      setShowAssetModal(false);
      setSelectedAsset(null);
    };
    document.addEventListener("shortcut:escape", onEscape);
    return () => document.removeEventListener("shortcut:escape", onEscape);
  }, []);

  const filteredAssets = useMemo(() => {
    const query = assetSearch.trim().toLowerCase();
    return assets.filter((asset) => {
      if (assetTypeFilter !== "all" && asset.type !== assetTypeFilter) {
        return false;
      }
      if (assetEnvFilter !== "all" && asset.environment !== assetEnvFilter) {
        return false;
      }
      if (assetCritFilter !== "all" && asset.criticality !== assetCritFilter) {
        return false;
      }
      if (!query) {
        return true;
      }
      const tags = Array.isArray(asset.tags) ? asset.tags : [];
      const haystack = [
        asset.name,
        asset.uri,
        asset.owner_email,
        asset.environment,
        asset.criticality,
        asset.type,
        ...tags,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return haystack.includes(query);
    });
  }, [assets, assetSearch, assetTypeFilter, assetEnvFilter, assetCritFilter]);

  const assetFiltersActive = useMemo(() => {
    return (
      assetTypeFilter !== "all" ||
      assetEnvFilter !== "all" ||
      assetCritFilter !== "all" ||
      assetSearch.trim() !== ""
    );
  }, [assetTypeFilter, assetEnvFilter, assetCritFilter, assetSearch]);

  async function handleCreateAsset(event) {
    event.preventDefault();
    if (!projectId) {
      return;
    }
    const payload = {
      project_id: Number(projectId),
      name: assetForm.name,
      uri: assetForm.uri,
      type: assetForm.type,
      owner_email: assetForm.ownerEmail,
      environment: assetForm.environment,
      criticality: assetForm.criticality,
      tags: assetForm.tags
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean),
    };
    const response = await authFetch(`${API_BASE}/assets`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
    if (response.ok) {
      const data = await response.json();
      setAssets((prev) => [...prev, data]);
      setAssetForm({ ...EMPTY_ASSET_FORM });
      setShowAssetModal(false);
      setAssetEditTarget(null);
    }
  }

  async function handleUpdateAsset(event) {
    event.preventDefault();
    if (!assetEditTarget) {
      return;
    }
    const payload = {
      name: assetForm.name,
      uri: assetForm.uri,
      type: assetForm.type,
      owner_email: assetForm.ownerEmail,
      environment: assetForm.environment,
      criticality: assetForm.criticality,
      tags: assetForm.tags
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean),
    };
    const response = await authFetch(`${API_BASE}/assets/${assetEditTarget.id}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    });
    if (response.ok) {
      const data = await response.json();
      setAssets((prev) => prev.map((asset) => (asset.id === data.id ? data : asset)));
      setSelectedAsset((prev) => (prev?.id === data.id ? data : prev));
      setShowAssetModal(false);
      setAssetEditTarget(null);
      setAssetForm({ ...EMPTY_ASSET_FORM });
    }
  }

  function handleEditAsset(asset) {
    setAssetEditTarget(asset);
    setAssetForm({
      name: asset.name || "",
      type: asset.type || "web_app",
      uri: asset.uri || "",
      ownerEmail: asset.owner_email || "",
      environment: asset.environment || "prod",
      criticality: asset.criticality || "media",
      tags: Array.isArray(asset.tags) ? asset.tags.join(", ") : "",
    });
    setShowAssetModal(true);
  }

  async function handleDeleteAsset(assetId) {
    if (!assetId || !user) {
      return;
    }
    if (!window.confirm("¿Eliminar este activo?")) {
      return;
    }
    const response = await authFetch(`${API_BASE}/assets/${assetId}`, {
      method: "DELETE",
    });
    if (response.ok) {
      setAssets((prev) => prev.filter((asset) => asset.id !== assetId));
      setSelectedAsset((prev) => (prev?.id === assetId ? null : prev));
      return;
    }
    const errorPayload = await response.json().catch(() => ({}));
    setError(errorPayload.detail || "No se pudo eliminar el activo");
  }

  function openNewAssetModal() {
    setAssetEditTarget(null);
    setAssetForm({ ...EMPTY_ASSET_FORM });
    setShowAssetModal(true);
  }

  function closeAssetModal() {
    setShowAssetModal(false);
    setAssetEditTarget(null);
    setAssetForm({ ...EMPTY_ASSET_FORM });
  }

  function renderAssetTypeIcon(type) {
    switch (type) {
      case "web_app":
        return (
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" strokeWidth="1.5" />
            <path
              d="M3 12h18M12 3c2.5 2.6 2.5 14.4 0 18M12 3c-2.5 2.6-2.5 14.4 0 18"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
            />
          </svg>
        );
      case "api":
        return (
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <path
              d="M8 12h8M12 8v8"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
            />
            <circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" strokeWidth="1.5" />
          </svg>
        );
      case "repo":
        return (
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <path
              d="M7 4h10a2 2 0 0 1 2 2v12l-5-3-5 3-5-3V6a2 2 0 0 1 2-2Z"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinejoin="round"
            />
          </svg>
        );
      case "host":
        return (
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <rect x="3" y="4" width="18" height="12" rx="2" fill="none" stroke="currentColor" strokeWidth="1.5" />
            <path d="M8 20h8" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
          </svg>
        );
      case "container":
        return (
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <rect x="3" y="7" width="18" height="10" rx="2" fill="none" stroke="currentColor" strokeWidth="1.5" />
            <path d="M7 7v10M12 7v10M17 7v10" fill="none" stroke="currentColor" strokeWidth="1.5" />
          </svg>
        );
      case "network_range":
        return (
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <path
              d="M4 12a8 8 0 0 1 16 0"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
            />
            <circle cx="12" cy="12" r="2" fill="none" stroke="currentColor" strokeWidth="1.5" />
            <path d="M12 14v5" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
          </svg>
        );
      default:
        return (
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" strokeWidth="1.5" />
          </svg>
        );
    }
  }

  useKeyboardShortcut("n", () => openNewAssetModal(), {
    enabled: Boolean(projectId),
  });

  if (!projectId) {
    return (
      <EmptyState
        icon="assets"
        title="Selecciona un proyecto"
        description="Elige un cliente y proyecto en el panel lateral para gestionar activos."
      />
    );
  }

  return (
    <section className={`assets ${selectedAsset ? "has-drawer" : ""}`}>
      <div className="assets-header">
        <div>
          <div className="assets-title">
            <svg className="assets-title-icon" viewBox="0 0 24 24" aria-hidden="true">
              <rect x="3" y="4" width="18" height="12" rx="2" fill="none" stroke="currentColor" strokeWidth="1.5" />
              <path d="M8 20h8" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
            </svg>
            <h2 className="page-title">Activos</h2>
          </div>
          <p className="page-description">Inventario de activos del proyecto</p>
        </div>
        <div className="assets-header-actions">
          <span className="badge badge-accent">{filteredAssets.length} registrados</span>
          <button
            className="btn btn-primary"
            type="button"
            onClick={openNewAssetModal}
            title="Nuevo activo (N)"
          >
            + Nuevo activo
            <kbd className="btn-shortcut-hint">N</kbd>
          </button>
        </div>
      </div>

      <div className="card assets-filters">
        <div className="form-group">
          <label className="form-label">Tipo</label>
          <select
            className="form-select"
            value={assetTypeFilter}
            onChange={(event) => setAssetTypeFilter(event.target.value)}
          >
            <option value="all">Todos</option>
            <option value="web_app">Web</option>
            <option value="api">API</option>
            <option value="repo">Repositorio</option>
            <option value="host">Host</option>
            <option value="container">Contenedor</option>
            <option value="network_range">Rango de red</option>
          </select>
        </div>
        <div className="form-group">
          <label className="form-label">Entorno</label>
          <select
            className="form-select"
            value={assetEnvFilter}
            onChange={(event) => setAssetEnvFilter(event.target.value)}
          >
            <option value="all">Todos</option>
            <option value="prod">Producción</option>
            <option value="stage">Staging</option>
            <option value="dev">Desarrollo</option>
          </select>
        </div>
        <div className="form-group">
          <label className="form-label">Criticidad</label>
          <select
            className="form-select"
            value={assetCritFilter}
            onChange={(event) => setAssetCritFilter(event.target.value)}
          >
            <option value="all">Todas</option>
            <option value="alta">Alta</option>
            <option value="media">Media</option>
            <option value="baja">Baja</option>
          </select>
        </div>
        <div className="form-group">
          <label className="form-label">Buscar</label>
          <div className="search-input-wrapper">
            <input
              className="form-input"
              type="text"
              placeholder="nombre, URL, tags, responsable"
              value={assetSearch}
              onChange={(event) => setAssetSearch(event.target.value)}
              data-shortcut-search
            />
            <kbd className="search-shortcut-hint">/</kbd>
          </div>
        </div>
      </div>

      {error ? (
        <EmptyState
          icon="error"
          title="No pudimos cargar los activos"
          description={`No logramos traer el inventario. ${error}`}
          action={{ label: "Reintentar", onClick: handleRetry }}
          secondaryAction={{ label: "Cerrar", onClick: () => setError("") }}
        />
      ) : assetsLoading ? (
        <AssetsTableSkeleton />
      ) : filteredAssets.length === 0 ? (
        assetFiltersActive ? (
          <EmptyState
            icon="search"
            title="Sin resultados"
            description="No se encontraron activos con los filtros actuales. Ajusta el tipo, entorno o criticidad."
            action={{
              label: "Limpiar filtros",
              onClick: () => {
                setAssetTypeFilter("all");
                setAssetEnvFilter("all");
                setAssetCritFilter("all");
                setAssetSearch("");
              },
            }}
          />
        ) : (
          <EmptyState
            icon="assets"
            title="No hay activos"
            description="Agrega los activos que vas a evaluar en este proyecto: aplicaciones web, APIs, servidores, redes."
            action={{ label: "+ Nuevo activo", onClick: openNewAssetModal }}
          />
        )
      ) : (
        <div className="table-container">
          <table className="table assets-table">
            <thead>
              <tr>
                <th>Nombre</th>
                <th>Tipo</th>
                <th>URI</th>
                <th>Responsable</th>
                <th>Entorno</th>
                <th>Criticidad</th>
                <th>Tags</th>
              </tr>
            </thead>
            <tbody>
              {filteredAssets.map((asset) => {
                const tags = Array.isArray(asset.tags) ? asset.tags : [];
                return (
                  <tr
                    key={asset.id}
                    className={`assets-row ${selectedAsset?.id === asset.id ? "assets-row--active" : ""}`}
                    onClick={() => setSelectedAsset(asset)}
                  >
                    <td className="assets-name">
                      <span className="assets-name-icon">{renderAssetTypeIcon(asset.type)}</span>
                      <span className="assets-name-text">{asset.name}</span>
                    </td>
                    <td>
                      <span className="badge badge-accent">
                        {assetTypeLabels[asset.type] || asset.type}
                      </span>
                    </td>
                    <td className="assets-uri">
                      <span className="file-path">{asset.uri}</span>
                    </td>
                    <td>{asset.owner_email || "—"}</td>
                    <td>
                      <span className={`assets-env assets-env--${asset.environment}`}>
                        {envLabels[asset.environment] || asset.environment || "—"}
                      </span>
                    </td>
                    <td>
                      <span className={`badge badge-${criticalityToBadge(asset.criticality)}`}>
                        {asset.criticality || "—"}
                      </span>
                    </td>
                    <td className="assets-tags">
                      {tags.slice(0, 3).map((tag) => (
                        <span key={tag} className="assets-tag">{tag}</span>
                      ))}
                      {tags.length > 3 && (
                        <span className="assets-tag assets-tag--more">+{tags.length - 3}</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {selectedAsset && (
        <aside className="assets-drawer">
          <div className="assets-drawer-header">
            <div>
              <span className="assets-drawer-type-icon">
                {renderAssetTypeIcon(selectedAsset.type)}
              </span>
              <h3 className="assets-drawer-title">{selectedAsset.name}</h3>
              <span className={`badge badge-${criticalityToBadge(selectedAsset.criticality)}`}>
                {selectedAsset.criticality || "Sin clasificar"}
              </span>
            </div>
            <button className="btn btn-ghost btn-sm" type="button" onClick={() => setSelectedAsset(null)}>✕</button>
          </div>

          <div className="assets-drawer-body">
            <div className="assets-meta-grid">
              <div className="assets-meta-item">
                <span className="assets-meta-label">Tipo</span>
                <span className="badge badge-accent">
                  {assetTypeLabels[selectedAsset.type] || selectedAsset.type}
                </span>
              </div>
              <div className="assets-meta-item">
                <span className="assets-meta-label">Entorno</span>
                <span className={`assets-env assets-env--${selectedAsset.environment}`}>
                  {envLabels[selectedAsset.environment] || "—"}
                </span>
              </div>
              <div className="assets-meta-item assets-meta-item--full">
                <span className="assets-meta-label">URI</span>
                <span className="file-path">{selectedAsset.uri}</span>
              </div>
              <div className="assets-meta-item assets-meta-item--full">
                <span className="assets-meta-label">Responsable</span>
                <span>{selectedAsset.owner_email || "—"}</span>
              </div>
              <div className="assets-meta-item assets-meta-item--full">
                <span className="assets-meta-label">Tags</span>
                <div className="assets-tags">
                  {Array.isArray(selectedAsset.tags) && selectedAsset.tags.length > 0 ? (
                    selectedAsset.tags.map((tag) => (
                      <span key={tag} className="assets-tag">{tag}</span>
                    ))
                  ) : (
                    <span className="assets-text-muted">Sin tags</span>
                  )}
                </div>
              </div>
            </div>

            <div className="assets-findings-summary">
              <h4>Hallazgos vinculados</h4>
              {(() => {
                const assetFindings = findings.filter((finding) => finding.asset_id === selectedAsset.id);
                if (assetFindings.length === 0) {
                  return <p className="assets-text-muted">Sin hallazgos registrados</p>;
                }
                const bySeverity = {};
                assetFindings.forEach((finding) => {
                  const key = finding.severity || "info";
                  bySeverity[key] = (bySeverity[key] || 0) + 1;
                });
                return (
                  <div className="assets-findings-badges">
                    <span className="assets-findings-total">{assetFindings.length} total</span>
                    {Object.entries(bySeverity).map(([severity, count]) => (
                      <span key={severity} className={`badge badge-${severity}`}>
                        {count} {severityLabels[severity] || severity}
                      </span>
                    ))}
                  </div>
                );
              })()}
            </div>

            <div className="assets-drawer-actions">
              <button className="btn btn-secondary" type="button" onClick={() => handleEditAsset(selectedAsset)}>
                Editar activo
              </button>
              <button
                className="btn btn-danger"
                type="button"
                onClick={() => handleDeleteAsset(selectedAsset.id)}
              >
                Eliminar
              </button>
            </div>
          </div>
        </aside>
      )}

      {showAssetModal && (
        <div className="modal-overlay" onClick={closeAssetModal}>
          <div className="modal" onClick={(event) => event.stopPropagation()}>
            <div className="modal-header">
              <h3>{assetEditTarget ? "Editar activo" : "Nuevo activo"}</h3>
              <button className="btn btn-ghost" type="button" onClick={closeAssetModal}>✕</button>
            </div>
            <form className="modal-form" onSubmit={assetEditTarget ? handleUpdateAsset : handleCreateAsset}>
              <div className="form-group">
                <label className="form-label">Nombre del activo *</label>
                <input
                  className="form-input"
                  type="text"
                  placeholder="ej: api-produccion, web-corporativa"
                  value={assetForm.name}
                  onChange={(event) => setAssetForm({ ...assetForm, name: event.target.value })}
                  required
                />
              </div>
              <div className="form-group">
                <label className="form-label">Tipo *</label>
                <select
                  className="form-select"
                  value={assetForm.type}
                  onChange={(event) => setAssetForm({ ...assetForm, type: event.target.value })}
                >
                  <option value="web_app">Web App</option>
                  <option value="api">API</option>
                  <option value="repo">Repositorio</option>
                  <option value="host">Host</option>
                  <option value="container">Contenedor</option>
                  <option value="network_range">Rango de red</option>
                </select>
              </div>
              <div className="form-group full">
                <label className="form-label">URL/URI principal *</label>
                <input
                  className="form-input"
                  type="text"
                  placeholder="https://api.empresa.com o 192.168.1.0/24"
                  value={assetForm.uri}
                  onChange={(event) => setAssetForm({ ...assetForm, uri: event.target.value })}
                  required
                />
              </div>
              <div className="form-group full">
                <label className="form-label">Correo responsable *</label>
                <input
                  className="form-input"
                  type="email"
                  placeholder="responsable@empresa.com"
                  value={assetForm.ownerEmail}
                  onChange={(event) => setAssetForm({ ...assetForm, ownerEmail: event.target.value })}
                  required
                />
              </div>
              <div className="form-group">
                <label className="form-label">Entorno</label>
                <select
                  className="form-select"
                  value={assetForm.environment}
                  onChange={(event) => setAssetForm({ ...assetForm, environment: event.target.value })}
                >
                  <option value="prod">Producción</option>
                  <option value="stage">Staging</option>
                  <option value="dev">Desarrollo</option>
                </select>
              </div>
              <div className="form-group">
                <label className="form-label">Criticidad</label>
                <select
                  className="form-select"
                  value={assetForm.criticality}
                  onChange={(event) => setAssetForm({ ...assetForm, criticality: event.target.value })}
                >
                  <option value="alta">Alta</option>
                  <option value="media">Media</option>
                  <option value="baja">Baja</option>
                </select>
              </div>
              <div className="form-group full">
                <label className="form-label">Tags</label>
                <input
                  className="form-input"
                  type="text"
                  placeholder="frontend, legacy, cloud (separados por coma)"
                  value={assetForm.tags}
                  onChange={(event) => setAssetForm({ ...assetForm, tags: event.target.value })}
                />
                <span className="form-hint">Etiquetas para organizar y filtrar activos</span>
              </div>
              <div className="modal-form-actions full">
                <button className="btn btn-secondary" type="button" onClick={closeAssetModal}>
                  Cancelar
                </button>
                <button className="btn btn-primary" type="submit">
                  {assetEditTarget ? "Guardar cambios" : "Guardar activo"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </section>
  );
}
