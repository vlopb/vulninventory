export const API_BASE =
  import.meta.env.VITE_API_BASE_URL || import.meta.env.VITE_API_URL || "http://localhost:8001";

export function getCookie(name) {
  const match = document.cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

export function authHeaders() {
  const csrf = getCookie("csrf_token");
  return csrf ? { "X-CSRF-Token": csrf } : {};
}

export async function authFetch(url, options = {}) {
  const defaults = {
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...authHeaders(),
      ...(options.headers || {}),
    },
  };
  const merged = {
    ...defaults,
    ...options,
    headers: { ...defaults.headers, ...(options.headers || {}) },
  };
  const response = await window.fetch(url, merged);
  if (response.status === 401) {
    window.location.href = "/login";
    throw new Error("Sesión expirada");
  }
  return response;
}

export function unwrapItems(data) {
  if (data && typeof data === "object" && Array.isArray(data.items)) {
    return data.items;
  }
  return Array.isArray(data) ? data : [];
}
