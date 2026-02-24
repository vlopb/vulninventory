export const severityRank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export const severityLabels = {
  critical: "Crítica",
  high: "Alta",
  medium: "Media",
  low: "Baja",
  info: "Info",
};

export const statusLabels = {
  open: "Abierto",
  triaged: "Triado",
  accepted: "Aceptado",
  fixed: "Cerrado",
  false_positive: "Falso positivo",
};

export const statusOptions = ["open", "triaged", "accepted", "fixed", "false_positive"];

export const scanStatusLabels = {
  queued: "En cola",
  running: "Ejecutando",
  finished: "Finalizado",
  failed: "Fallido",
};

export const assetTypeLabels = {
  web_app: "Web",
  api: "API",
  repo: "Repo",
  host: "Host",
  container: "Container",
  network_range: "Red",
};

export const envLabels = {
  prod: "Producción",
  stage: "Staging",
  dev: "Desarrollo",
};

export const roleOptions = [
  {
    value: "owner",
    label: "Propietario",
    icon: "👑",
    description: "Acceso total y administración del cliente",
  },
  {
    value: "admin",
    label: "Admin",
    icon: "🛡",
    description: "Acceso total a todas las funcionalidades del proyecto",
  },
  {
    value: "analyst",
    label: "Analista",
    icon: "📊",
    description: "Gestiona hallazgos, activos y ejecuta escaneos",
  },
  {
    value: "auditor",
    label: "Auditor",
    icon: "🔍",
    description: "Acceso de solo lectura + auditoría completa",
  },
  {
    value: "viewer",
    label: "Viewer",
    icon: "👁",
    description: "Visualización de hallazgos y activos sin edición",
  },
  {
    value: "member",
    label: "Miembro",
    icon: "👤",
    description: "Acceso estándar según permisos del proyecto",
  },
];

export const roleColors = {
  admin: { color: "var(--severity-critical)", bg: "var(--severity-critical-bg)" },
  analyst: { color: "var(--accent-primary)", bg: "var(--accent-primary-subtle)" },
  auditor: { color: "var(--severity-medium)", bg: "var(--severity-medium-bg)" },
  viewer: { color: "var(--text-secondary)", bg: "var(--bg-badge)" },
  owner: { color: "var(--accent-secondary)", bg: "var(--accent-secondary-subtle)" },
  member: { color: "var(--severity-low)", bg: "var(--severity-low-bg)" },
};

export const EMPTY_ASSET_FORM = {
  name: "",
  type: "web_app",
  uri: "",
  ownerEmail: "",
  environment: "prod",
  criticality: "media",
  tags: "",
};

export const manualTemplates = [
  {
    id: "owasp-web-a01",
    group: "OWASP Web Top 10",
    title: "A01: Broken Access Control",
    owasp: "A01:2021",
    cwe: "CWE-284",
    severity: "high",
    description: "Controles de acceso insuficientes permiten acceder a recursos no autorizados.",
  },
  {
    id: "owasp-web-a02",
    group: "OWASP Web Top 10",
    title: "A02: Cryptographic Failures",
    owasp: "A02:2021",
    cwe: "CWE-319",
    severity: "high",
    description: "Datos sensibles expuestos por cifrado inadecuado o ausente.",
  },
  {
    id: "owasp-web-a03",
    group: "OWASP Web Top 10",
    title: "A03: Injection",
    owasp: "A03:2021",
    cwe: "CWE-89",
    severity: "critical",
    description: "Entradas no validadas permiten inyección de comandos o SQL.",
  },
  {
    id: "owasp-web-a05",
    group: "OWASP Web Top 10",
    title: "A05: Security Misconfiguration",
    owasp: "A05:2021",
    cwe: "CWE-16",
    severity: "medium",
    description: "Configuraciones inseguras o por defecto expuestas.",
  },
  {
    id: "owasp-web-a07",
    group: "OWASP Web Top 10",
    title: "A07: Identification and Authentication Failures",
    owasp: "A07:2021",
    cwe: "CWE-287",
    severity: "high",
    description: "Errores en autenticación o sesiones.",
  },
  {
    id: "owasp-api-api1",
    group: "OWASP API Top 10",
    title: "API1: Broken Object Level Authorization",
    owasp: "API1:2023",
    cwe: "CWE-639",
    severity: "critical",
    description: "Acceso a objetos sin validar propiedad o permisos.",
  },
  {
    id: "owasp-api-api2",
    group: "OWASP API Top 10",
    title: "API2: Broken Authentication",
    owasp: "API2:2023",
    cwe: "CWE-287",
    severity: "high",
    description: "Autenticación débil o mal implementada en APIs.",
  },
  {
    id: "owasp-api-api4",
    group: "OWASP API Top 10",
    title: "API4: Unrestricted Resource Consumption",
    owasp: "API4:2023",
    cwe: "CWE-400",
    severity: "medium",
    description: "Falta de límites en recursos o rate limit.",
  },
  {
    id: "cwe-79",
    group: "Top CWE",
    title: "XSS (CWE-79)",
    cwe: "CWE-79",
    severity: "high",
    description: "Entrada no sanitizada permite ejecución de scripts.",
  },
  {
    id: "cwe-89",
    group: "Top CWE",
    title: "SQL Injection (CWE-89)",
    cwe: "CWE-89",
    severity: "critical",
    description: "Entrada controlada permite inyección SQL.",
  },
  {
    id: "cwe-287",
    group: "Top CWE",
    title: "Improper Authentication (CWE-287)",
    cwe: "CWE-287",
    severity: "high",
    description: "Autenticación insuficiente o incorrecta.",
  },
  {
    id: "cwe-200",
    group: "Top CWE",
    title: "Information Exposure (CWE-200)",
    cwe: "CWE-200",
    severity: "medium",
    description: "Exposición de información sensible.",
  },
];

export const IMPORT_FIELDS = {
  title: { label: "Titulo *", required: true, group: "hallazgo" },
  severity: { label: "Severidad *", required: true, group: "hallazgo" },
  status: { label: "Estado", required: false, group: "hallazgo", default: "open" },
  description: { label: "Descripcion", required: false, group: "hallazgo" },
  cwe: { label: "CWE", required: false, group: "hallazgo" },
  owasp_category: { label: "OWASP", required: false, group: "hallazgo" },
  cvss_score: { label: "CVSS Score", required: false, group: "hallazgo" },
  occurrences: { label: "Ocurrencias", required: false, group: "hallazgo", default: 1 },
  tags: { label: "Tags", required: false, group: "hallazgo" },
  asset_name: { label: "Nombre del activo *", required: true, group: "activo" },
  asset_uri: { label: "URI del activo", required: false, group: "activo" },
  asset_type: { label: "Tipo de activo", required: false, group: "activo", default: "web_app" },
  owner_email: { label: "Responsable", required: false, group: "persona" },
  pentester_email: { label: "Pentester", required: false, group: "persona" },
};

export const AUTO_MAP_ALIASES = {
  title: [
    "title",
    "titulo",
    "nombre",
    "name",
    "vulnerability",
    "vuln_name",
    "finding",
    "plugin_name",
    "issue_name",
    "advisory_name",
    "cve",
    "cve_id",
  ],
  severity: [
    "severity",
    "severidad",
    "risk",
    "riesgo",
    "risk_level",
    "criticidad",
    "level",
    "threat",
    "base_score_level",
  ],
  status: ["status", "estado", "state"],
  description: [
    "description",
    "descripcion",
    "desc",
    "details",
    "synopsis",
    "detalle",
    "issue_detail",
    "summary",
    "overview",
  ],
  cwe: ["cwe", "cwe_id", "cwe-id", "weakness", "cwe_name", "weakness_id"],
  owasp_category: ["owasp", "owasp_category", "owasp_top_10", "category", "categoria"],
  cvss_score: [
    "cvss",
    "cvss_score",
    "cvss_v3",
    "cvss3",
    "score",
    "cvss_base_score",
    "base_score",
    "cvss_base",
    "cvss_v3_score",
  ],
  occurrences: ["occurrences", "ocurrencias", "count", "instances"],
  tags: ["tags", "etiquetas", "labels"],
  asset_name: ["asset", "asset_name", "activo", "host", "hostname", "target", "objetivo", "ip", "server"],
  asset_uri: ["uri", "url", "asset_uri", "endpoint", "address", "target_url", "ip_address"],
  asset_type: ["type", "asset_type", "tipo", "service"],
  owner_email: ["owner", "responsable", "owner_email", "assigned_to", "assignee"],
  pentester_email: ["pentester", "tester", "pentester_email", "reporter", "found_by"],
};
