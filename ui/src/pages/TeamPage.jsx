import { useCallback, useEffect, useMemo, useState } from "react";
import { EmptyState } from "../components/common/EmptyState";
import { SkeletonTable } from "../components/common/LoadingSkeleton";
import { useKeyboardShortcut } from "../hooks/useKeyboardShortcut";
import { useAuth } from "../context/AuthContext";
import { useProject } from "../context/ProjectContext";
import { API_BASE, authFetch, unwrapItems } from "../utils/api";
import { roleColors, roleOptions } from "../utils/constants";
import "../Users.css";

export default function TeamPage() {
  const { user } = useAuth();
  const { orgId, projectId } = useProject();
  const [members, setMembers] = useState([]);
  const [membersLoading, setMembersLoading] = useState(false);
  const [invites, setInvites] = useState([]);
  const [invitesLoading, setInvitesLoading] = useState(false);
  const [users, setUsers] = useState([]);
  const [usersLoading, setUsersLoading] = useState(false);
  const [memberFilters, setMemberFilters] = useState({ role: "all", search: "" });
  const [inviteFilters, setInviteFilters] = useState({ search: "", showDisabled: false });
  const [showUserModal, setShowUserModal] = useState(false);
  const [userModalTab, setUserModalTab] = useState("existing");
  const [usersTab, setUsersTab] = useState("members");
  const [existingSearch, setExistingSearch] = useState("");
  const [selectedUser, setSelectedUser] = useState(null);
  const [newMemberRole, setNewMemberRole] = useState("member");
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState("member");
  const [error, setError] = useState("");
  const [reloadToken, setReloadToken] = useState(0);

  const handleRetry = useCallback(() => {
    setError("");
    setReloadToken((prev) => prev + 1);
  }, []);

  useEffect(() => {
    let cancelled = false;

    async function loadMembers() {
      if (!user || !orgId) {
        if (!cancelled) {
          setMembers([]);
          setMembersLoading(false);
        }
        return;
      }
      try {
        if (!cancelled) {
          setMembersLoading(true);
        }
        const response = await authFetch(`${API_BASE}/orgs/${orgId}/members`);
        if (!response.ok) {
          return;
        }
        const data = await response.json();
        if (!cancelled) {
          setMembers(unwrapItems(data));
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message || "No se pudieron cargar los miembros");
        }
      } finally {
        if (!cancelled) {
          setMembersLoading(false);
        }
      }
    }

    loadMembers();
    return () => {
      cancelled = true;
    };
  }, [orgId, user, reloadToken]);

  useEffect(() => {
    const onEscape = () => {
      setShowUserModal(false);
    };
    document.addEventListener("shortcut:escape", onEscape);
    return () => document.removeEventListener("shortcut:escape", onEscape);
  }, []);

  useEffect(() => {
    let cancelled = false;

    async function loadInvites() {
      if (!user || !orgId) {
        if (!cancelled) {
          setInvites([]);
          setInvitesLoading(false);
        }
        return;
      }
      try {
        if (!cancelled) {
          setInvitesLoading(true);
        }
        const response = await authFetch(`${API_BASE}/orgs/${orgId}/invites`);
        if (!response.ok) {
          return;
        }
        const data = await response.json();
        if (!cancelled) {
          setInvites(unwrapItems(data));
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message || "No se pudieron cargar las invitaciones");
        }
      } finally {
        if (!cancelled) {
          setInvitesLoading(false);
        }
      }
    }

    loadInvites();
    return () => {
      cancelled = true;
    };
  }, [orgId, user, reloadToken]);

  useEffect(() => {
    let cancelled = false;

    async function loadUsers() {
      if (!user || !orgId) {
        if (!cancelled) {
          setUsers([]);
        }
        return;
      }
      try {
        if (!cancelled) {
          setUsersLoading(true);
        }
        const response = await authFetch(`${API_BASE}/users?org_id=${orgId}`);
        if (!response.ok) {
          return;
        }
        const data = await response.json();
        if (!cancelled) {
          setUsers(unwrapItems(data));
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message || "No se pudieron cargar los usuarios");
        }
      } finally {
        if (!cancelled) {
          setUsersLoading(false);
        }
      }
    }

    loadUsers();
    return () => {
      cancelled = true;
    };
  }, [orgId, user, reloadToken]);

  const filteredMembers = useMemo(() => {
    const search = memberFilters.search.trim().toLowerCase();
    return members.filter((member) => {
      if (memberFilters.role !== "all" && member.role !== memberFilters.role) {
        return false;
      }
      if (!search) {
        return true;
      }
      return member.email.toLowerCase().includes(search);
    });
  }, [members, memberFilters]);

  const filteredInvites = useMemo(() => {
    const search = inviteFilters.search.trim().toLowerCase();
    return invites.filter((invite) => {
      if (!inviteFilters.showDisabled && invite.disabled) {
        return false;
      }
      if (!search) {
        return true;
      }
      return invite.email.toLowerCase().includes(search);
    });
  }, [invites, inviteFilters]);

  const availableUsers = useMemo(() => {
    const memberEmails = new Set(members.map((member) => member.email?.toLowerCase()));
    return users.filter((member) => !memberEmails.has(member.email?.toLowerCase()));
  }, [users, members]);

  const filteredAvailableUsers = useMemo(() => {
    const search = existingSearch.trim().toLowerCase();
    return availableUsers.filter((member) => {
      if (!search) {
        return true;
      }
      return (
        member.email?.toLowerCase().includes(search) ||
        member.full_name?.toLowerCase().includes(search) ||
        member.title?.toLowerCase().includes(search)
      );
    });
  }, [availableUsers, existingSearch]);

  useEffect(() => {
    if (selectedUser && availableUsers.length > 0) {
      const stillAvailable = availableUsers.some((member) => member.id === selectedUser.id);
      if (!stillAvailable) {
        setSelectedUser(null);
      }
    }
  }, [availableUsers, selectedUser]);

  async function handleAddMember(event) {
    event.preventDefault();
    if (!orgId || !selectedUser) {
      return false;
    }
    const response = await authFetch(`${API_BASE}/orgs/${orgId}/members`, {
      method: "POST",
      body: JSON.stringify({ email: selectedUser.email, role: newMemberRole }),
    });
    if (response.ok) {
      const data = await response.json();
      setMembers((prev) => [...prev, data]);
      setSelectedUser(null);
      return true;
    }
    const errorPayload = await response.json().catch(() => ({}));
    setError(errorPayload.detail || "No se pudo agregar el miembro");
    return false;
  }

  async function handleInvite(event) {
    event.preventDefault();
    if (!orgId || !inviteEmail) {
      return;
    }
    const response = await authFetch(`${API_BASE}/orgs/${orgId}/invites`, {
      method: "POST",
      body: JSON.stringify({ email: inviteEmail, role: inviteRole }),
    });
    if (response.ok) {
      const data = await response.json();
      setInvites((prev) => [...prev, data]);
      setInviteEmail("");
      return;
    }
    const errorPayload = await response.json().catch(() => ({}));
    setError(errorPayload.detail || "No se pudo crear la invitación");
  }

  async function handleDisableInvite(inviteId, disabled) {
    if (!orgId) {
      return;
    }
    const response = await authFetch(`${API_BASE}/orgs/${orgId}/invites/${inviteId}`, {
      method: "PATCH",
      body: JSON.stringify({ disabled }),
    });
    if (response.ok) {
      const data = await response.json();
      setInvites((prev) => prev.map((invite) => (invite.id === inviteId ? data : invite)));
    }
  }

  function handleCopyInviteLink(invite) {
    const url = `${window.location.origin}?invite=${invite.token}`;
    navigator.clipboard.writeText(url);
  }

  async function handleUpdateMemberRole(memberId, role) {
    if (!orgId) {
      return;
    }
    const response = await authFetch(`${API_BASE}/orgs/${orgId}/members/${memberId}`, {
      method: "PATCH",
      body: JSON.stringify({ role }),
    });
    if (response.ok) {
      const data = await response.json();
      setMembers((prev) => prev.map((member) => (member.id === memberId ? data : member)));
    }
  }

  async function handleRemoveMember(memberId) {
    if (!orgId) {
      return;
    }
    const response = await authFetch(`${API_BASE}/orgs/${orgId}/members/${memberId}`, {
      method: "DELETE",
    });
    if (response.ok) {
      setMembers((prev) => prev.filter((member) => member.id !== memberId));
    }
  }

  useKeyboardShortcut("n", () => {
    setShowUserModal(true);
    setUserModalTab("invite");
  }, {
    enabled: Boolean(projectId),
  });

  if (!projectId) {
    return (
      <EmptyState
        icon="team"
        title="Selecciona un proyecto"
        description="Elige un cliente y proyecto en el panel lateral para gestionar usuarios."
      />
    );
  }

  return (
    <section className="users-section">
      <div className="users-header">
        <div className="users-header-info">
          <h2 className="users-title">
            <svg
              className="users-title-icon"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4-4v2" />
              <circle cx="9" cy="7" r="4" />
              <path d="M23 21v-2a4 4 0 00-3-3.87" />
              <path d="M16 3.13a4 4 0 010 7.75" />
            </svg>
            Usuarios
          </h2>
          <p className="users-subtitle">Gestión de accesos y permisos del proyecto</p>
        </div>
        <div className="users-header-actions">
          <span className="badge badge-accent">{members.length} miembros</span>
          <button
            className="btn btn-primary"
            onClick={() => {
              setShowUserModal(true);
              setUserModalTab("existing");
            }}
            title="Nueva invitación (N)"
          >
            + Añadir usuario
            <kbd className="btn-shortcut-hint">N</kbd>
          </button>
        </div>
      </div>

      <div className="users-kpis">
        <div className="users-kpi">
          <span className="users-kpi-icon">👥</span>
          <span className="users-kpi-value">{members.length}</span>
          <span className="users-kpi-label">Miembros</span>
        </div>
        <div className="users-kpi">
          <span className="users-kpi-icon">🛡</span>
          <span className="users-kpi-value">
            {members.filter((member) => member.role === "admin" || member.role === "owner").length}
          </span>
          <span className="users-kpi-label">Admins</span>
        </div>
        <div className="users-kpi">
          <span className="users-kpi-icon">📧</span>
          <span className="users-kpi-value">{invites.filter((invite) => !invite.disabled).length}</span>
          <span className="users-kpi-label">Invitaciones</span>
        </div>
        <div className="users-kpi">
          <span className="users-kpi-icon">📊</span>
          <span className="users-kpi-value">
            {members.filter((member) => member.role === "analyst").length}
          </span>
          <span className="users-kpi-label">Analistas</span>
        </div>
      </div>

      <div className="users-tabs">
        <button
          className={`users-tab ${usersTab === "members" ? "users-tab--active" : ""}`}
          onClick={() => setUsersTab("members")}
        >
          Miembros
          <span className="users-tab-count">{members.length}</span>
        </button>
        <button
          className={`users-tab ${usersTab === "invites" ? "users-tab--active" : ""}`}
          onClick={() => setUsersTab("invites")}
        >
          Invitaciones
          <span className="users-tab-count">{invites.filter((invite) => !invite.disabled).length}</span>
        </button>
        <button
          className={`users-tab ${usersTab === "roles" ? "users-tab--active" : ""}`}
          onClick={() => setUsersTab("roles")}
        >
          Roles y permisos
        </button>
      </div>

      {usersTab === "members" && (
        <div className="users-panel">
          <div className="users-filters">
            <div className="form-group">
              <label className="form-label">Rol</label>
              <select
                className="form-select"
                value={memberFilters.role}
                onChange={(event) =>
                  setMemberFilters((prev) => ({ ...prev, role: event.target.value }))
                }
              >
                <option value="all">Todos</option>
                <option value="owner">Propietario</option>
                <option value="admin">Admin</option>
                <option value="analyst">Analista</option>
                <option value="auditor">Auditor</option>
                <option value="viewer">Viewer</option>
                <option value="member">Miembro</option>
              </select>
            </div>
            <div className="form-group users-filter-search">
              <label className="form-label">Buscar</label>
              <div className="search-input-wrapper">
                <input
                  className="form-input"
                  type="text"
                  placeholder="correo electrónico..."
                  value={memberFilters.search}
                  onChange={(event) =>
                    setMemberFilters((prev) => ({ ...prev, search: event.target.value }))
                  }
                  data-shortcut-search
                />
                <kbd className="search-shortcut-hint">/</kbd>
              </div>
            </div>
          </div>

          {error ? (
            <EmptyState
              icon="error"
              title="No pudimos cargar los miembros"
              description={`Intenta nuevamente en unos segundos. ${error}`}
              action={{ label: "Reintentar", onClick: handleRetry }}
              secondaryAction={{ label: "Cerrar", onClick: () => setError("") }}
              compact
            />
          ) : membersLoading ? (
            <SkeletonTable rows={6} columns={4} />
          ) : filteredMembers.length === 0 ? (
            <EmptyState
              icon="team"
              title="Sin miembros"
              description="Invita a tu equipo para colaborar en los proyectos de esta organización."
              action={{
                label: "Invitar miembro",
                onClick: () => {
                  setShowUserModal(true);
                  setUserModalTab("invite");
                },
              }}
            />
          ) : (
            <div className="users-table-wrap">
              <table className="users-table">
                <thead>
                  <tr>
                    <th>Usuario</th>
                    <th>Rol</th>
                    <th>Cambiar rol</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {filteredMembers.map((member) => {
                    const roleInfo = roleOptions.find((role) => role.value === member.role) || {
                      icon: "👤",
                      label: member.role,
                    };
                    return (
                      <tr key={member.id} className="users-row">
                        <td className="users-cell-user">
                          <div className="users-avatar">
                            {member.email.charAt(0).toUpperCase()}
                          </div>
                          <div className="users-user-info">
                            <span className="users-user-email">{member.email}</span>
                            <span className="users-user-id">ID: {member.user_id}</span>
                          </div>
                        </td>
                        <td>
                          <span
                            className="users-role-badge"
                            style={{
                              color: roleColors[member.role]?.color || "var(--text-secondary)",
                              background: roleColors[member.role]?.bg || "var(--bg-badge)",
                            }}
                          >
                            {roleInfo.icon} {roleInfo.label}
                          </span>
                        </td>
                        <td>
                          <select
                            className="form-select users-role-select"
                            value={member.role}
                            onChange={(event) => handleUpdateMemberRole(member.id, event.target.value)}
                          >
                            <option value="owner">Propietario</option>
                            <option value="admin">Admin</option>
                            <option value="analyst">Analista</option>
                            <option value="auditor">Auditor</option>
                            <option value="viewer">Viewer</option>
                            <option value="member">Miembro</option>
                          </select>
                        </td>
                        <td className="users-cell-actions">
                          <button
                            className="users-action-btn users-action-btn--danger"
                            title="Eliminar miembro"
                            onClick={() => {
                              if (window.confirm(`¿Eliminar a ${member.email} del proyecto?`)) {
                                handleRemoveMember(member.id);
                              }
                            }}
                          >
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                              <path d="M3 6h18M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2" />
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
        </div>
      )}

      {usersTab === "invites" && (
        <div className="users-panel">
          <div className="users-filters">
            <div className="form-group users-filter-search">
              <label className="form-label">Buscar</label>
              <div className="search-input-wrapper">
                <input
                  className="form-input"
                  type="text"
                  placeholder="correo electrónico..."
                  value={inviteFilters.search}
                  onChange={(event) =>
                    setInviteFilters((prev) => ({ ...prev, search: event.target.value }))
                  }
                  data-shortcut-search
                />
                <kbd className="search-shortcut-hint">/</kbd>
              </div>
            </div>
            <label className="users-filter-toggle">
              <input
                type="checkbox"
                checked={inviteFilters.showDisabled}
                onChange={() =>
                  setInviteFilters((prev) => ({ ...prev, showDisabled: !prev.showDisabled }))
                }
              />
              <span>Mostrar deshabilitadas</span>
            </label>
          </div>

          {error ? (
            <EmptyState
              icon="error"
              title="No pudimos cargar las invitaciones"
              description={`No logramos traer las invitaciones. ${error}`}
              action={{ label: "Reintentar", onClick: handleRetry }}
              secondaryAction={{ label: "Cerrar", onClick: () => setError("") }}
              compact
            />
          ) : invitesLoading ? (
            <SkeletonTable rows={4} columns={5} />
          ) : filteredInvites.length === 0 ? (
            <EmptyState
              icon="team"
              title="Sin invitaciones pendientes"
              description="Las invitaciones enviadas aparecerán aquí mientras no sean aceptadas o expiren."
              compact
              action={{
                label: "Crear invitación",
                onClick: () => {
                  setShowUserModal(true);
                  setUserModalTab("invite");
                },
              }}
            />
          ) : (
            <div className="users-table-wrap">
              <table className="users-table">
                <thead>
                  <tr>
                    <th>Correo</th>
                    <th>Rol</th>
                    <th>Estado</th>
                    <th>Link</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {filteredInvites.map((invite) => (
                    <tr key={invite.id} className={`users-row ${invite.disabled ? "users-row--disabled" : ""}`}>
                      <td className="users-cell-user">
                        <div className="users-avatar users-avatar--invite">
                          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" />
                            <polyline points="22,6 12,13 2,6" />
                          </svg>
                        </div>
                        <span className="users-user-email">{invite.email}</span>
                      </td>
                      <td>
                        <span
                          className="users-role-badge"
                          style={{
                            color: roleColors[invite.role]?.color || "var(--text-secondary)",
                            background: roleColors[invite.role]?.bg || "var(--bg-badge)",
                          }}
                        >
                          {(roleOptions.find((role) => role.value === invite.role) || {}).icon || "👤"}{" "}
                          {(roleOptions.find((role) => role.value === invite.role) || {}).label || invite.role}
                        </span>
                      </td>
                      <td>
                        <span
                          className={`users-invite-status ${
                            invite.disabled ? "users-invite-status--disabled" : "users-invite-status--active"
                          }`}
                        >
                          <span className="users-invite-dot"></span>
                          {invite.disabled ? "Inactiva" : "Activa"}
                        </span>
                      </td>
                      <td>
                        <button
                          className="btn btn-ghost btn-sm"
                          onClick={() => handleCopyInviteLink(invite)}
                          title="Copiar link de invitación"
                        >
                          📋 Copiar
                        </button>
                      </td>
                      <td className="users-cell-actions">
                        <button
                          className={`users-action-btn ${invite.disabled ? "" : "users-action-btn--warning"}`}
                          title={invite.disabled ? "Habilitar invitación" : "Deshabilitar invitación"}
                          onClick={() => handleDisableInvite(invite.id, !invite.disabled)}
                        >
                          {invite.disabled ? (
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                              <polygon points="5 3 19 12 5 21 5 3" />
                            </svg>
                          ) : (
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                              <rect x="6" y="4" width="4" height="16" />
                              <rect x="14" y="4" width="4" height="16" />
                            </svg>
                          )}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {usersTab === "roles" && (
        <div className="users-panel">
          <p className="users-roles-description">
            Matriz de permisos por rol. Define qué puede hacer cada tipo de usuario en el proyecto.
          </p>
          <div className="users-table-wrap">
            <table className="users-table users-roles-table">
              <thead>
                <tr>
                  <th>Rol</th>
                  <th>Hallazgos</th>
                  <th>Activos</th>
                  <th>Escaneos</th>
                  <th>Usuarios</th>
                  <th>Auditoría</th>
                </tr>
              </thead>
              <tbody>
                <tr className="users-row">
                  <td>
                    <span
                      className="users-role-badge"
                      style={{ color: roleColors.owner.color, background: roleColors.owner.bg }}
                    >
                      👑 Propietario
                    </span>
                  </td>
                  <td><span className="users-perm users-perm--full">✓ Total</span></td>
                  <td><span className="users-perm users-perm--full">✓ Total</span></td>
                  <td><span className="users-perm users-perm--full">✓ Total</span></td>
                  <td><span className="users-perm users-perm--full">✓ Total</span></td>
                  <td><span className="users-perm users-perm--full">✓ Total</span></td>
                </tr>
                <tr className="users-row">
                  <td>
                    <span
                      className="users-role-badge"
                      style={{ color: roleColors.admin.color, background: roleColors.admin.bg }}
                    >
                      🛡 Admin
                    </span>
                  </td>
                  <td><span className="users-perm users-perm--full">✓ Total</span></td>
                  <td><span className="users-perm users-perm--full">✓ Total</span></td>
                  <td><span className="users-perm users-perm--full">✓ Total</span></td>
                  <td><span className="users-perm users-perm--full">✓ Total</span></td>
                  <td><span className="users-perm users-perm--full">✓ Total</span></td>
                </tr>
                <tr className="users-row">
                  <td>
                    <span
                      className="users-role-badge"
                      style={{ color: roleColors.analyst.color, background: roleColors.analyst.bg }}
                    >
                      📊 Analista
                    </span>
                  </td>
                  <td><span className="users-perm users-perm--full">✓ Total</span></td>
                  <td><span className="users-perm users-perm--full">✓ Total</span></td>
                  <td><span className="users-perm users-perm--full">✓ Total</span></td>
                  <td><span className="users-perm users-perm--read">👁 Ver</span></td>
                  <td><span className="users-perm users-perm--read">👁 Ver</span></td>
                </tr>
                <tr className="users-row">
                  <td>
                    <span
                      className="users-role-badge"
                      style={{ color: roleColors.auditor.color, background: roleColors.auditor.bg }}
                    >
                      🔍 Auditor
                    </span>
                  </td>
                  <td><span className="users-perm users-perm--read">👁 Ver</span></td>
                  <td><span className="users-perm users-perm--read">👁 Ver</span></td>
                  <td><span className="users-perm users-perm--read">👁 Ver</span></td>
                  <td><span className="users-perm users-perm--none">✗ No</span></td>
                  <td><span className="users-perm users-perm--full">✓ Total</span></td>
                </tr>
                <tr className="users-row">
                  <td>
                    <span
                      className="users-role-badge"
                      style={{ color: roleColors.viewer.color, background: roleColors.viewer.bg }}
                    >
                      👁 Viewer
                    </span>
                  </td>
                  <td><span className="users-perm users-perm--read">👁 Ver</span></td>
                  <td><span className="users-perm users-perm--read">👁 Ver</span></td>
                  <td><span className="users-perm users-perm--read">👁 Ver</span></td>
                  <td><span className="users-perm users-perm--none">✗ No</span></td>
                  <td><span className="users-perm users-perm--none">✗ No</span></td>
                </tr>
              </tbody>
            </table>
          </div>
          <div className="users-roles-note">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="10" />
              <line x1="12" y1="8" x2="12" y2="12" />
              <line x1="12" y1="16" x2="12.01" y2="16" />
            </svg>
            <span>Los permisos se aplican a nivel de proyecto. El propietario del cliente siempre tiene acceso total.</span>
          </div>
        </div>
      )}

      {showUserModal && (
        <div className="wizard-overlay" onClick={() => setShowUserModal(false)}>
          <div className="wizard-modal" onClick={(event) => event.stopPropagation()} style={{ maxWidth: "520px" }}>
            <div className="wizard-header">
              <h3>Añadir usuario</h3>
              <button className="btn btn-ghost" onClick={() => setShowUserModal(false)}>✕</button>
            </div>

            <div className="users-modal-tabs">
              <button
                className={`users-modal-tab ${userModalTab === "existing" ? "users-modal-tab--active" : ""}`}
                onClick={() => setUserModalTab("existing")}
              >
                Agregar existente
              </button>
              <button
                className={`users-modal-tab ${userModalTab === "invite" ? "users-modal-tab--active" : ""}`}
                onClick={() => setUserModalTab("invite")}
              >
                Invitar por correo
              </button>
            </div>

            {userModalTab === "existing" && (
              <form
                className="users-modal-body"
                onSubmit={async (event) => {
                  const added = await handleAddMember(event);
                  if (added) {
                    setShowUserModal(false);
                  }
                }}
              >
                <div className="search-input-wrapper">
                  <input
                    className="form-input"
                    type="text"
                    placeholder="Buscar por nombre o email..."
                    value={existingSearch}
                    onChange={(event) => setExistingSearch(event.target.value)}
                    data-shortcut-search
                  />
                  <kbd className="search-shortcut-hint">/</kbd>
                </div>
                {usersLoading ? (
                  <SkeletonTable rows={4} columns={2} />
                ) : filteredAvailableUsers.length === 0 ? (
                  <EmptyState
                    icon="team"
                    title={existingSearch ? "Sin resultados" : "No hay usuarios disponibles"}
                    description={
                      existingSearch
                        ? "No se encontraron usuarios con ese criterio."
                        : "Todos los usuarios de la plataforma ya son miembros. Usa 'Invitar por correo' para agregar personas nuevas."
                    }
                    compact
                  />
                ) : (
                  <>
                    <div className="user-select-list">
                      {filteredAvailableUsers.map((member) => (
                        <div
                          key={member.id}
                          className={`user-select-item ${selectedUser?.id === member.id ? "user-select-item--active" : ""}`}
                          onClick={() => setSelectedUser(member)}
                        >
                          <div className="user-select-radio">
                            <input
                              type="radio"
                              name="selectedUser"
                              checked={selectedUser?.id === member.id}
                              onChange={() => setSelectedUser(member)}
                            />
                          </div>
                          <div className="user-select-info">
                            <span className="user-select-email">{member.email}</span>
                            <span className="user-select-meta">
                              {member.full_name || "(sin nombre)"} · {member.title || "(sin cargo)"}
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                    <div className="user-select-role">
                      <label>Rol:</label>
                      <select className="form-select" value={newMemberRole} onChange={(event) => setNewMemberRole(event.target.value)}>
                        {roleOptions.map((role) => (
                          <option key={role.value} value={role.value}>
                            {role.icon} {role.label}
                          </option>
                        ))}
                      </select>
                    </div>
                  </>
                )}
                <div className="users-modal-footer">
                  <button className="btn btn-ghost" type="button" onClick={() => setShowUserModal(false)}>
                    Cancelar
                  </button>
                  <button className="btn btn-primary" type="submit" disabled={!selectedUser || filteredAvailableUsers.length === 0}>
                    Agregar al proyecto
                  </button>
                </div>
              </form>
            )}

            {userModalTab === "invite" && (
              <form className="users-modal-body" onSubmit={(event) => { handleInvite(event); setShowUserModal(false); }}>
                <div className="form-group">
                  <label className="form-label">Correo electrónico</label>
                  <input
                    className="form-input"
                    type="email"
                    placeholder="usuario@empresa.com"
                    value={inviteEmail}
                    onChange={(event) => setInviteEmail(event.target.value)}
                    required
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Rol</label>
                  <select className="form-select" value={inviteRole} onChange={(event) => setInviteRole(event.target.value)}>
                    {roleOptions.map((role) => (
                      <option key={role.value} value={role.value}>
                        {role.icon} {role.label}
                      </option>
                    ))}
                  </select>
                  <span className="form-hint">
                    {roleOptions.find((role) => role.value === inviteRole)?.description}
                  </span>
                </div>
                <div className="users-modal-notice">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" />
                    <polyline points="22,6 12,13 2,6" />
                  </svg>
                  <span>Se generará un link de invitación único para compartir con el usuario.</span>
                </div>
                <div className="users-modal-footer">
                  <button className="btn btn-ghost" type="button" onClick={() => setShowUserModal(false)}>
                    Cancelar
                  </button>
                  <button className="btn btn-primary" type="submit">📧 Crear invitación</button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}
    </section>
  );
}
