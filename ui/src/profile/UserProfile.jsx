import { useCallback, useEffect, useMemo, useState } from "react";
import { useAuth } from "../context/AuthContext";
import { API_BASE, authFetch } from "../utils/api";
import ProfileHeader from "./ProfileHeader";
import PersonalInfo from "./PersonalInfo";
import EditProfile from "./EditProfile";
import ChangePassword from "./ChangePassword";
import ActivityHistory from "./ActivityHistory";
import NotificationPreferences from "./NotificationPreferences";
import "./UserProfile.css";

export default function UserProfile({
  requiresProfile = false,
}) {
  const { user: authUser, checkSession } = useAuth();
  const [toast, setToast] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [profile, setProfile] = useState(null);
  const [notifications, setNotifications] = useState(null);
  const [activityLog, setActivityLog] = useState([]);

  const profileData = useMemo(() => {
    const name = profile?.full_name || authUser?.full_name || "";
    return {
      name: name || authUser?.email || "",
      email: profile?.email || authUser?.email || "",
      phone: profile?.phone || "",
      position: profile?.title || "",
      role: "Miembro",
      avatar: null,
      activityLog,
      notifications: notifications || {
        criticalVulns: true,
        assignedVulns: true,
        statusUpdates: false,
        reports: true,
        systemAlerts: true,
        channel: "email",
      },
    };
  }, [profile, authUser, activityLog, notifications]);

  function showToast(message) {
    setToast(message);
    window.setTimeout(() => setToast(""), 2400);
  }

  const loadProfile = useCallback(async () => {
    const response = await authFetch(`${API_BASE}/users/me`);
    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      throw new Error(data.detail || "No se pudo cargar el perfil.");
    }
    const data = await response.json();
    setProfile(data);
  }, []);

  const loadNotifications = useCallback(async () => {
    const response = await authFetch(`${API_BASE}/users/me/notifications`);
    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      throw new Error(data.detail || "No se pudieron cargar las notificaciones.");
    }
    const data = await response.json();
    setNotifications(data);
  }, []);

  const loadActivities = useCallback(async () => {
    const response = await authFetch(`${API_BASE}/users/me/activities?limit=10`);
    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      throw new Error(data.detail || "No se pudo cargar el historial.");
    }
    const data = await response.json();
    const mapped = data.map((item) => ({
      action: item.action,
      timestamp: item.created_at,
      ip: item.ip,
    }));
    setActivityLog(mapped);
  }, []);

  const reloadAll = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      await Promise.all([loadProfile(), loadNotifications(), loadActivities()]);
    } catch (err) {
      setError(err.message || "No se pudo cargar tu perfil.");
    } finally {
      setLoading(false);
    }
  }, [loadProfile, loadNotifications, loadActivities]);

  useEffect(() => {
    reloadAll();
  }, [reloadAll]);

  const handleProfileSave = useCallback(async (payload) => {
    const response = await authFetch(`${API_BASE}/users/me/profile`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(data.detail || "No se pudo actualizar.");
    }
    setProfile(data);
    await checkSession();
  }, [checkSession]);

  const handlePasswordSave = useCallback(async (payload) => {
    const response = await authFetch(`${API_BASE}/users/me/password`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(data.detail || "No se pudo actualizar la contraseña.");
    }
    setProfile(data);
    await checkSession();
  }, [checkSession]);

  const handleNotificationSave = useCallback(async (payload) => {
    const response = await authFetch(`${API_BASE}/users/me/notifications`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(data.detail || "No se pudieron guardar las preferencias.");
    }
    setNotifications(data);
  }, []);

  if (loading) {
    return (
      <div className="auth-loading">
        <div className="spinner" />
        <p>Cargando perfil...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="auth-loading">
        <p>{error}</p>
      </div>
    );
  }

  return (
    <section className="profile-page" aria-live="polite">
      {toast ? <div className="profile-page__toast">{toast}</div> : null}
      {requiresProfile ? (
        <div className="profile-page__banner">
          Completa tu perfil para comenzar a crear proyectos y gestionar vulnerabilidades.
        </div>
      ) : null}
      <ProfileHeader user={profileData} onAvatarChange={() => showToast("Avatar actualizado")} />
      <div className="profile-page__grid">
        <div className="profile-page__column">
          <PersonalInfo user={profileData} />
          <EditProfile
            user={profileData}
            onSave={handleProfileSave}
            onSuccess={() => showToast("Perfil actualizado")}
            requireName={requiresProfile && !profile?.full_name}
          />
        </div>
        <div className="profile-page__column">
          <ChangePassword
            onSave={handlePasswordSave}
            onSuccess={() => showToast("Contraseña actualizada")}
          />
          <NotificationPreferences
            notifications={profileData.notifications}
            onSave={handleNotificationSave}
            onSuccess={() => showToast("Preferencias guardadas")}
          />
        </div>
      </div>
      <ActivityHistory activityLog={profileData.activityLog} />
    </section>
  );
}
