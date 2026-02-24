import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Outlet } from "react-router-dom";
import { Sidebar } from "./Sidebar";
import { ShortcutsHelp } from "../common/ShortcutsHelp";
import { useGlobalShortcuts } from "../../hooks/useGlobalShortcuts";
import { useAuth } from "../../context/AuthContext";
import { useProject } from "../../context/ProjectContext";

export function AppLayout({ children }) {
  const { user, loading, logout } = useAuth();
  const { orgs, projects, orgId, projectId, setOrgId, setProjectId } = useProject();
  const { showShortcutsHelp, setShowShortcutsHelp } = useGlobalShortcuts();
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [sidebarMobileOpen, setSidebarMobileOpen] = useState(false);
  const [showIdleWarning, setShowIdleWarning] = useState(false);
  const idleWarningRef = useRef(false);
  const idleWarningTimeoutRef = useRef(null);
  const idleLogoutTimeoutRef = useRef(null);

  const selectedOrgName = useMemo(
    () => orgs.find((org) => String(org.id) === String(orgId))?.name,
    [orgs, orgId]
  );
  const selectedProjectName = useMemo(
    () => projects.find((project) => String(project.id) === String(projectId))?.name,
    [projects, projectId]
  );

  const isAuthenticated = Boolean(user);

  const handleIdleLogout = useCallback(() => {
    logout();
    localStorage.removeItem("vi_selectedOrg");
    localStorage.removeItem("vi_selectedProject");
    setOrgId("");
    setProjectId("");
  }, [logout, setOrgId, setProjectId]);

  const resetIdleTimers = useCallback(() => {
    clearTimeout(idleWarningTimeoutRef.current);
    clearTimeout(idleLogoutTimeoutRef.current);
    idleWarningTimeoutRef.current = setTimeout(() => {
      setShowIdleWarning(true);
    }, 13 * 60 * 1000);
    idleLogoutTimeoutRef.current = setTimeout(() => {
      handleIdleLogout();
    }, 15 * 60 * 1000);
  }, [handleIdleLogout]);

  useEffect(() => {
    if (!isAuthenticated) {
      return undefined;
    }
    idleWarningRef.current = showIdleWarning;
    resetIdleTimers();
    const events = ["mousemove", "mousedown", "keydown", "scroll", "touchstart"];
    const resetTimer = () => {
      if (idleWarningRef.current) {
        return;
      }
      resetIdleTimers();
    };
    events.forEach((eventName) => {
      window.addEventListener(eventName, resetTimer, { passive: true });
    });
    const handleVisibility = () => {
      if (document.visibilityState === "visible") {
        resetTimer();
      }
    };
    document.addEventListener("visibilitychange", handleVisibility);
    return () => {
      clearTimeout(idleWarningTimeoutRef.current);
      clearTimeout(idleLogoutTimeoutRef.current);
      events.forEach((eventName) => {
        window.removeEventListener(eventName, resetTimer);
      });
      document.removeEventListener("visibilitychange", handleVisibility);
    };
  }, [isAuthenticated, resetIdleTimers, showIdleWarning]);

  useEffect(() => {
    const onEscape = () => {
      setShowShortcutsHelp(false);
    };
    document.addEventListener("shortcut:escape", onEscape);
    return () => document.removeEventListener("shortcut:escape", onEscape);
  }, [setShowShortcutsHelp]);

  if (loading) {
    return (
      <div className="auth-loading">
        <div className="spinner" />
        <p>Verificando sesión...</p>
      </div>
    );
  }

  return (
    <div className="app">
      {isAuthenticated && (
        <header className="topbar">
          <div className="topbar-left">
            <button
              className="topbar-menu-btn"
              type="button"
              onClick={() => {
                if (window.innerWidth <= 768) {
                  setSidebarMobileOpen((prev) => !prev);
                } else {
                  setSidebarOpen((prev) => !prev);
                }
              }}
            >
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <line x1="3" y1="12" x2="21" y2="12" />
                <line x1="3" y1="6" x2="21" y2="6" />
                <line x1="3" y1="18" x2="21" y2="18" />
              </svg>
            </button>
            <span className="topbar-logo">🔒 VulnInventory</span>
          </div>

          <div className="topbar-context">
            {orgId ? (
              <>
                <span className="topbar-context-client">{selectedOrgName || "Cliente"}</span>
                {projectId ? (
                  <>
                    <span className="topbar-context-sep">/</span>
                    <span className="topbar-context-project">{selectedProjectName || "Proyecto"}</span>
                  </>
                ) : null}
              </>
            ) : (
              <span className="topbar-context-empty">Selecciona un cliente</span>
            )}
          </div>

          <div className="topbar-right">
            <span className="topbar-user">{user?.email || "Usuario"}</span>
            <button
              className="btn btn-ghost btn-sm"
              type="button"
              onClick={() => {
                logout();
                localStorage.removeItem("vi_selectedOrg");
                localStorage.removeItem("vi_selectedProject");
                setOrgId("");
                setProjectId("");
              }}
            >
              Cerrar sesión
            </button>
          </div>
        </header>
      )}

      <Sidebar
        sidebarOpen={sidebarOpen}
        setSidebarOpen={setSidebarOpen}
        sidebarMobileOpen={sidebarMobileOpen}
        setSidebarMobileOpen={setSidebarMobileOpen}
      />

      <div
        className={`app-layout ${isAuthenticated ? "" : "app-layout--no-topbar"} ${
          isAuthenticated && !sidebarOpen ? "app-layout--collapsed" : ""
        }`}
      >
        <main className={`main-content ${isAuthenticated ? "" : "main-content--full"}`}>
          {children || <Outlet />}
        </main>
      </div>

      {showIdleWarning && isAuthenticated && (
        <div className="wizard-overlay">
          <div className="wizard-modal" style={{ maxWidth: "420px" }}>
            <div className="wizard-header">
              <h3>Sesión por inactividad</h3>
            </div>
            <div className="wizard-body">
              <p className="wizard-instruction">
                Llevas 13 minutos sin actividad. Tu sesión se cerrará en 2 minutos si no confirmas.
              </p>
            </div>
            <div className="wizard-footer">
              <div className="wizard-footer-right">
                <button
                  className="btn btn-primary"
                  type="button"
                  onClick={() => {
                    setShowIdleWarning(false);
                    resetIdleTimers();
                  }}
                >
                  Seguir en sesión
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {showShortcutsHelp && (
        <ShortcutsHelp onClose={() => setShowShortcutsHelp(false)} />
      )}
    </div>
  );
}
