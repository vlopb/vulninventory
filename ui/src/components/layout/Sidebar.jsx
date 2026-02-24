import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../../context/AuthContext";
import { useProject } from "../../context/ProjectContext";
import { useTheme } from "../../context/ThemeContext";
import { ThemeToggle } from "../common/ThemeToggle";
import "../../Sidebar.css";

const sectionRoutes = {
  dashboard: "/dashboard",
  hallazgos: "/findings",
  activos: "/assets",
  escaneos: "/scans",
  equipo: "/team",
  auditoria: "/audit",
  perfil: "/profile",
};

export function Sidebar({ sidebarOpen, setSidebarOpen, sidebarMobileOpen, setSidebarMobileOpen }) {
  const navigate = useNavigate();
  const { logout, user } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const {
    orgs,
    projects,
    orgId,
    projectId,
    setOrgId,
    setProjectId,
    createOrg,
    createProject,
  } = useProject();
  const [expandedClients, setExpandedClients] = useState({});
  const [showNewClientModal, setShowNewClientModal] = useState(false);
  const [showNewProjectModal, setShowNewProjectModal] = useState(false);
  const [newClientName, setNewClientName] = useState("");
  const [newProjectName, setNewProjectName] = useState("");

  useEffect(() => {
    if (orgId) {
      setExpandedClients((prev) => ({ ...prev, [orgId]: true }));
    }
  }, [orgId]);

  const selectedOrgName = useMemo(
    () => orgs.find((org) => String(org.id) === String(orgId))?.name,
    [orgs, orgId]
  );

  function toggleClientExpanded(orgIdValue) {
    setExpandedClients((prev) => ({ ...prev, [orgIdValue]: !prev[orgIdValue] }));
  }

  async function handleCreateOrg() {
    if (!newClientName.trim()) {
      return;
    }
    try {
      await createOrg(newClientName.trim());
      setNewClientName("");
    } catch (error) {
      console.error(error);
    }
  }

  async function handleCreateProject() {
    if (!orgId || !newProjectName.trim()) {
      return;
    }
    try {
      await createProject(orgId, newProjectName.trim());
      setNewProjectName("");
    } catch (error) {
      console.error(error);
    }
  }

  function handleNavigate(section) {
    const route = sectionRoutes[section];
    if (!route) {
      return;
    }
    navigate(route);
    if (window.innerWidth <= 768) {
      setSidebarMobileOpen(false);
    }
  }

  return (
    <>
      {sidebarMobileOpen && (
        <div className="sidebar-overlay" onClick={() => setSidebarMobileOpen(false)} />
      )}
      <aside
        className={`sidebar ${sidebarOpen ? "" : "sidebar--collapsed"} ${sidebarMobileOpen ? "sidebar--mobile-open" : ""}`}
      >
        <div className="sidebar-section">
          <div className="sidebar-section-header">
            <span className="sidebar-section-title">{sidebarOpen ? "Clientes" : ""}</span>
            <button
              className="sidebar-add-btn"
              type="button"
              title="Nuevo cliente"
              onClick={() => {
                setNewClientName("");
                setShowNewClientModal(true);
              }}
            >
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <line x1="12" y1="5" x2="12" y2="19" />
                <line x1="5" y1="12" x2="19" y2="12" />
              </svg>
            </button>
          </div>

          <div className="sidebar-tree">
            {orgs.map((org) => {
              const isActive = String(orgId) === String(org.id);
              const isExpanded = expandedClients[org.id];
              const orgProjects = projects.filter(
                (project) => String(project.organization_id) === String(org.id)
              );

              return (
                <div key={org.id} className="sidebar-tree-client">
                  <div
                    className={`sidebar-tree-item sidebar-tree-item--client ${
                      isActive && !projectId ? "sidebar-tree-item--active" : ""
                    }`}
                    onClick={() => {
                      setOrgId(String(org.id));
                      setProjectId("");
                      toggleClientExpanded(org.id);
                      handleNavigate("dashboard");
                    }}
                  >
                    <button
                      className="sidebar-tree-toggle"
                      type="button"
                      onClick={(event) => {
                        event.stopPropagation();
                        toggleClientExpanded(org.id);
                      }}
                    >
                      <svg
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="2"
                        className={`sidebar-tree-arrow ${isExpanded ? "sidebar-tree-arrow--open" : ""}`}
                      >
                        <polyline points="9 18 15 12 9 6" />
                      </svg>
                    </button>
                    <span className="sidebar-tree-icon">🏢</span>
                    {sidebarOpen && <span className="sidebar-tree-name">{org.name}</span>}
                    {sidebarOpen && orgProjects.length > 0 && (
                      <span className="sidebar-tree-count">{orgProjects.length}</span>
                    )}
                  </div>

                  {isExpanded && sidebarOpen && (
                    <div className="sidebar-tree-projects">
                      {orgProjects.map((project) => {
                        const isProjectActive = String(projectId) === String(project.id);
                        return (
                          <div
                            key={project.id}
                            className={`sidebar-tree-item sidebar-tree-item--project ${
                              isProjectActive ? "sidebar-tree-item--active" : ""
                            }`}
                            onClick={() => {
                              setOrgId(String(org.id));
                              setProjectId(String(project.id));
                              handleNavigate("dashboard");
                            }}
                          >
                            <span className="sidebar-tree-icon">📁</span>
                            <span className="sidebar-tree-name">{project.name}</span>
                          </div>
                        );
                      })}
                      <div
                        className="sidebar-tree-item sidebar-tree-item--add"
                        onClick={() => {
                          setOrgId(String(org.id));
                          setNewProjectName("");
                          setShowNewProjectModal(true);
                        }}
                      >
                        <span className="sidebar-tree-icon">+</span>
                        {sidebarOpen && <span className="sidebar-tree-name">Nuevo proyecto</span>}
                      </div>
                    </div>
                  )}
                </div>
              );
            })}

            {orgs.length === 0 && sidebarOpen && (
              <div className="sidebar-tree-empty">
                <p>Sin clientes aún</p>
              </div>
            )}
          </div>
        </div>

        <div className="sidebar-divider"></div>

        <nav className="sidebar-nav">
          {[
            {
              key: "dashboard",
              label: "Dashboard",
              icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>',
            },
            {
              key: "hallazgos",
              label: "Hallazgos",
              icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg>',
            },
            {
              key: "activos",
              label: "Activos",
              icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>',
            },
            {
              key: "escaneos",
              label: "Escaneos",
              icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>',
            },
            {
              key: "equipo",
              label: "Usuarios",
              icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4-4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87"/><path d="M16 3.13a4 4 0 010 7.75"/></svg>',
            },
            {
              key: "auditoria",
              label: "Auditoría",
              icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>',
            },
          ].map((item) => (
            <button
              key={item.key}
              type="button"
              className="sidebar-link"
              onClick={() => handleNavigate(item.key)}
              disabled={!projectId && item.key !== "dashboard"}
              title={!sidebarOpen ? item.label : undefined}
            >
              <span className="sidebar-link-icon" dangerouslySetInnerHTML={{ __html: item.icon }} />
              {sidebarOpen && <span className="sidebar-link-label">{item.label}</span>}
              {!projectId && item.key !== "dashboard" && sidebarOpen && (
                <span className="sidebar-link-lock">🔒</span>
              )}
            </button>
          ))}
        </nav>

        <div className="sidebar-divider"></div>

        <div className="sidebar-footer">
          <ThemeToggle theme={theme} onToggle={toggleTheme} />
          <button
            type="button"
            className="sidebar-link"
            onClick={() => handleNavigate("perfil")}
          >
            <span className="sidebar-link-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4-4v2" />
                <circle cx="12" cy="7" r="4" />
              </svg>
            </span>
            {sidebarOpen && <span className="sidebar-link-label">Perfil</span>}
          </button>
          <button
            type="button"
            className="sidebar-link"
            onClick={() => {
              logout();
              localStorage.removeItem("vi_selectedOrg");
              localStorage.removeItem("vi_selectedProject");
              setOrgId("");
              setProjectId("");
            }}
          >
            <span className="sidebar-link-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4" />
                <polyline points="16 17 21 12 16 7" />
                <line x1="21" y1="12" x2="9" y2="12" />
              </svg>
            </span>
            {sidebarOpen && <span className="sidebar-link-label">Cerrar sesión</span>}
          </button>
        </div>
      </aside>

      {showNewClientModal && (
        <div className="wizard-overlay" onClick={() => setShowNewClientModal(false)}>
          <div className="wizard-modal" onClick={(event) => event.stopPropagation()} style={{ maxWidth: "440px" }}>
            <div className="wizard-header">
              <h3>🏢 Nuevo cliente</h3>
              <button className="btn btn-ghost" type="button" onClick={() => setShowNewClientModal(false)}>✕</button>
            </div>
            <form
              className="sidebar-modal-body"
              onSubmit={(event) => {
                event.preventDefault();
                handleCreateOrg();
                setShowNewClientModal(false);
              }}
            >
              <div className="form-group">
                <label className="form-label">Nombre del cliente</label>
                <input
                  className="form-input"
                  type="text"
                  placeholder="Ej: Telefonica Colombia, Banco XYZ"
                  value={newClientName}
                  onChange={(event) => setNewClientName(event.target.value)}
                  required
                  autoFocus
                />
                <span className="form-hint">Nombre de la empresa o cliente</span>
              </div>
              <div className="sidebar-modal-footer">
                <button className="btn btn-ghost" type="button" onClick={() => setShowNewClientModal(false)}>
                  Cancelar
                </button>
                <button className="btn btn-primary" type="submit" disabled={!newClientName.trim()}>
                  Crear cliente
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {showNewProjectModal && (
        <div className="wizard-overlay" onClick={() => setShowNewProjectModal(false)}>
          <div className="wizard-modal" onClick={(event) => event.stopPropagation()} style={{ maxWidth: "440px" }}>
            <div className="wizard-header">
              <h3>📁 Nuevo proyecto</h3>
              <button className="btn btn-ghost" type="button" onClick={() => setShowNewProjectModal(false)}>✕</button>
            </div>
            <form
              className="sidebar-modal-body"
              onSubmit={(event) => {
                event.preventDefault();
                handleCreateProject();
                setShowNewProjectModal(false);
              }}
            >
              <div className="form-group">
                <label className="form-label">Cliente</label>
                <input
                  className="form-input"
                  type="text"
                  disabled
                  value={selectedOrgName || ""}
                />
              </div>
              <div className="form-group">
                <label className="form-label">Nombre del proyecto</label>
                <input
                  className="form-input"
                  type="text"
                  placeholder="Ej: Pentest Web Q1 2026"
                  value={newProjectName}
                  onChange={(event) => setNewProjectName(event.target.value)}
                  required
                  autoFocus
                />
                <span className="form-hint">Nombre del ejercicio o engagement</span>
              </div>
              <div className="sidebar-modal-footer">
                <button className="btn btn-ghost" type="button" onClick={() => setShowNewProjectModal(false)}>
                  Cancelar
                </button>
                <button className="btn btn-primary" type="submit" disabled={!orgId || !newProjectName.trim()}>
                  Crear proyecto
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </>
  );
}
