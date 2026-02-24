import { useEffect, useMemo, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { API_BASE, authFetch } from "../utils/api";

export default function AuthScreen({ mode = "login", resetMode = false, forcePassword = false }) {
  const navigate = useNavigate();
  const location = useLocation();
  const { user, setUser } = useAuth();
  const [authMode, setAuthMode] = useState(mode);
  const [authError, setAuthError] = useState("");
  const [authForm, setAuthForm] = useState({ email: "", password: "", organization: "" });
  const [resetEmail, setResetEmail] = useState("");
  const [resetToken, setResetToken] = useState("");
  const [resetNewPassword, setResetNewPassword] = useState("");
  const [resetStatus, setResetStatus] = useState("");
  const [resetModeEnabled, setResetModeEnabled] = useState(resetMode);
  const [forcePasswordMode, setForcePasswordMode] = useState(forcePassword);
  const [forcePasswordForm, setForcePasswordForm] = useState({
    email: "",
    current_password: "",
    new_password: "",
  });
  const [inviteToken, setInviteToken] = useState("");
  const [inviteInfo, setInviteInfo] = useState(null);
  const [inviteAcceptStatus, setInviteAcceptStatus] = useState("");

  useEffect(() => {
    if (user) {
      navigate("/dashboard", { replace: true });
    }
  }, [user, navigate]);

  useEffect(() => {
    setAuthMode(mode);
    setResetModeEnabled(resetMode);
    setForcePasswordMode(forcePassword);
  }, [mode, resetMode, forcePassword]);

  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const invite = params.get("invite");
    if (invite) {
      setInviteToken(invite);
    }
  }, [location.search]);

  useEffect(() => {
    let cancelled = false;

    async function loadInviteInfo() {
      if (!inviteToken) {
        setInviteInfo(null);
        return;
      }
      try {
        const response = await authFetch(`${API_BASE}/invites/${inviteToken}`);
        if (!response.ok) {
          return;
        }
        const data = await response.json();
        if (!cancelled) {
          setInviteInfo(data);
        }
      } catch {
        if (!cancelled) {
          setInviteInfo(null);
        }
      }
    }

    loadInviteInfo();
    return () => {
      cancelled = true;
    };
  }, [inviteToken]);

  async function handleAuthSubmit(event) {
    event.preventDefault();
    setAuthError("");
    const endpoint = authMode === "register" ? "/auth/register" : "/auth/login";
    const payload =
      authMode === "register"
        ? authForm
        : { email: authForm.email, password: authForm.password };
    try {
      const response = await authFetch(`${API_BASE}${endpoint}`, {
        method: "POST",
        body: JSON.stringify(payload),
      });
      if (!response.ok) {
        const errorPayload = await response.json().catch(() => ({}));
        if (errorPayload?.detail?.code === "password_expired") {
          setForcePasswordMode(true);
          setForcePasswordForm((prev) => ({
            ...prev,
            email: authForm.email,
            current_password: "",
            new_password: "",
          }));
          setAuthError(errorPayload?.detail?.message || "Debe actualizar su contraseña");
          return;
        }
        throw new Error(errorPayload.detail || "Autenticación fallida");
      }
      const data = await response.json();
      setUser(data.user || null);
    } catch (err) {
      setAuthError(err.message || "Autenticación fallida");
    }
  }

  async function handleInviteAccept(event) {
    event.preventDefault();
    if (!inviteToken || !authForm.email || !authForm.password) {
      return;
    }
    const response = await authFetch(`${API_BASE}/invites/${inviteToken}/accept`, {
      method: "POST",
      body: JSON.stringify({ email: authForm.email, password: authForm.password }),
    });
    if (response.ok) {
      const data = await response.json();
      setUser(data.user || null);
      setInviteToken("");
      setInviteAcceptStatus("Invitación aceptada");
    } else {
      setInviteAcceptStatus("La invitación falló");
    }
  }

  async function handleForcePasswordChange(event) {
    event.preventDefault();
    setAuthError("");
    try {
      const response = await authFetch(`${API_BASE}/auth/rotate-password`, {
        method: "POST",
        body: JSON.stringify(forcePasswordForm),
      });
      if (!response.ok) {
        const errorPayload = await response.json().catch(() => ({}));
        throw new Error(errorPayload.detail || "No se pudo actualizar la contraseña");
      }
      const data = await response.json();
      setUser(data.user || null);
      setForcePasswordMode(false);
    } catch (err) {
      setAuthError(err.message || "No se pudo actualizar la contraseña");
    }
  }

  async function handleForgotPassword(event) {
    event.preventDefault();
    setResetStatus("");
    if (!resetEmail) {
      return;
    }
    try {
      const response = await authFetch(`${API_BASE}/auth/forgot-password`, {
        method: "POST",
        body: JSON.stringify({ email: resetEmail }),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || "No se pudo generar el token");
      }
      setResetStatus(data.message || "Revisa tu correo para el token de recuperación");
    } catch (err) {
      setResetStatus(err.message || "No se pudo generar el token");
    }
  }

  async function handleResetPassword(event) {
    event.preventDefault();
    setResetStatus("");
    if (!resetToken || !resetNewPassword) {
      return;
    }
    try {
      const response = await authFetch(`${API_BASE}/auth/reset-password`, {
        method: "POST",
        body: JSON.stringify({ token: resetToken, new_password: resetNewPassword }),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || "No se pudo restablecer la contraseña");
      }
      setUser(data.user || null);
      setResetModeEnabled(false);
      setResetToken("");
      setResetNewPassword("");
      setResetStatus("Contraseña restablecida");
    } catch (err) {
      setResetStatus(err.message || "No se pudo restablecer la contraseña");
    }
  }

  const showResetForms = useMemo(() => resetModeEnabled, [resetModeEnabled]);

  return (
    <section className="auth">
      <div className="auth-card">
        {inviteToken && (
          <div className="invite-banner">
            <strong>Invitación detectada.</strong>{" "}
            {inviteInfo
              ? `Cliente ${inviteInfo.organization_id} · Rol ${inviteInfo.role}`
              : "Crea una contraseña para aceptar la invitación."}
          </div>
        )}
        {forcePasswordMode ? (
          <form onSubmit={handleForcePasswordChange} className="force-password">
            <h3>Actualiza tu contraseña</h3>
            <input className="form-input" type="email" value={forcePasswordForm.email} readOnly />
            <input
              className="form-input"
              type="password"
              placeholder="contraseña actual"
              value={forcePasswordForm.current_password}
              onChange={(event) =>
                setForcePasswordForm((prev) => ({
                  ...prev,
                  current_password: event.target.value,
                }))
              }
              required
            />
            <input
              className="form-input"
              type="password"
              placeholder="nueva contraseña"
              value={forcePasswordForm.new_password}
              onChange={(event) =>
                setForcePasswordForm((prev) => ({
                  ...prev,
                  new_password: event.target.value,
                }))
              }
              required
            />
            <button className="btn btn-primary" type="submit">Actualizar contraseña</button>
          </form>
        ) : showResetForms ? (
          <form onSubmit={handleForgotPassword} className="force-password">
            <h3>Recuperar contraseña</h3>
            <input
              className="form-input"
              type="email"
              placeholder="correo"
              value={resetEmail}
              onChange={(event) => setResetEmail(event.target.value)}
              required
            />
            <button className="btn btn-primary" type="submit">Generar token</button>
            {resetStatus ? <p className="status">{resetStatus}</p> : null}
          </form>
        ) : (
          <>
            <div className="auth-toggle">
              <button
                type="button"
                className={`btn btn-secondary ${authMode === "login" ? "active" : ""}`}
                onClick={() => setAuthMode("login")}
              >
                Iniciar sesión
              </button>
              <button
                type="button"
                className={`btn btn-secondary ${authMode === "register" ? "active" : ""}`}
                onClick={() => setAuthMode("register")}
              >
                Registrarse
              </button>
            </div>
            <form onSubmit={handleAuthSubmit}>
              <input
                className="form-input"
                type="email"
                placeholder="correo"
                value={authForm.email}
                onChange={(event) =>
                  setAuthForm({ ...authForm, email: event.target.value })
                }
                required
              />
              <input
                className="form-input"
                type="password"
                placeholder="contraseña"
                value={authForm.password}
                onChange={(event) =>
                  setAuthForm({ ...authForm, password: event.target.value })
                }
                required
              />
              {authMode === "register" && (
                <input
                  className="form-input"
                  type="text"
                  placeholder="cliente"
                  value={authForm.organization}
                  onChange={(event) =>
                    setAuthForm({ ...authForm, organization: event.target.value })
                  }
                  required
                />
              )}
              <button className="btn btn-primary" type="submit">Continuar</button>
            </form>
            {authMode === "login" ? (
              <button
                type="button"
                className="btn btn-ghost link-button"
                onClick={() => {
                  setResetModeEnabled(true);
                  setResetEmail(authForm.email);
                  setResetStatus("");
                }}
              >
                Olvidé mi contraseña
              </button>
            ) : null}
          </>
        )}
        {showResetForms ? (
          <form onSubmit={handleResetPassword} className="force-password">
            <h3>Restablecer contraseña</h3>
            <input
              className="form-input"
              type="text"
              placeholder="token de recuperación"
              value={resetToken}
              onChange={(event) => setResetToken(event.target.value)}
              required
            />
            <input
              className="form-input"
              type="password"
              placeholder="nueva contraseña"
              value={resetNewPassword}
              onChange={(event) => setResetNewPassword(event.target.value)}
              required
            />
            <button className="btn btn-primary" type="submit">Restablecer</button>
            <button
              type="button"
              className="link-button"
              onClick={() => {
                setResetModeEnabled(false);
                setResetToken("");
                setResetNewPassword("");
                setResetStatus("");
              }}
            >
              Volver
            </button>
            {resetStatus ? <p className="status">{resetStatus}</p> : null}
          </form>
        ) : null}
        <form onSubmit={handleInviteAccept} className="invite-accept">
          <input
            className="form-input"
            type="text"
            placeholder="token de invitación"
            value={inviteToken}
            onChange={(event) => setInviteToken(event.target.value)}
          />
          <button className="btn btn-primary" type="submit">Aceptar invitación</button>
        </form>
        {inviteAcceptStatus && <p className="status">{inviteAcceptStatus}</p>}
        {authError && <p className="status">{authError}</p>}
      </div>
    </section>
  );
}
