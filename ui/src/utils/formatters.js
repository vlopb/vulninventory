export function formatDuration(ms) {
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) {
    return `${seconds}s`;
  }
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = seconds % 60;
  if (minutes < 60) {
    return `${minutes}m ${remainingSeconds}s`;
  }
  const hours = Math.floor(minutes / 60);
  return `${hours}h ${minutes % 60}m`;
}

export function criticalityToBadge(criticality) {
  const map = { alta: "high", media: "medium", baja: "low" };
  return map[criticality] || "info";
}

export function getCSSVar(name, fallback = "") {
  if (typeof window === "undefined") {
    return fallback;
  }
  const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return value || fallback;
}

export function toRgba(color, alpha) {
  if (!color) {
    return color;
  }
  if (color.startsWith("#")) {
    const hex = color.replace("#", "");
    const normalized = hex.length === 3 ? hex.split("").map((c) => c + c).join("") : hex;
    const int = parseInt(normalized, 16);
    const r = (int >> 16) & 255;
    const g = (int >> 8) & 255;
    const b = int & 255;
    return `rgba(${r}, ${g}, ${b}, ${alpha})`;
  }
  if (color.startsWith("rgb(")) {
    const values = color.replace("rgb(", "").replace(")", "");
    return `rgba(${values}, ${alpha})`;
  }
  if (color.startsWith("rgba(")) {
    const values = color.replace("rgba(", "").replace(")", "").split(",");
    return `rgba(${values[0]}, ${values[1]}, ${values[2]}, ${alpha})`;
  }
  return color;
}
