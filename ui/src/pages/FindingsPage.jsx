import { useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { EmptyState } from "../components/common/EmptyState";
import { FindingsTableSkeleton } from "../components/findings/FindingsTableSkeleton";
import { useKeyboardShortcut } from "../hooks/useKeyboardShortcut";
import { useAuth } from "../context/AuthContext";
import { useProject } from "../context/ProjectContext";
import { API_BASE, authFetch, unwrapItems } from "../utils/api";
import {
  IMPORT_FIELDS,
  manualTemplates,
  severityLabels,
  severityRank,
  statusLabels,
  statusOptions,
} from "../utils/constants";
import {
  downloadImportTemplate,
  exportCSV,
  exportJSON,
  parseImportFile,
} from "../utils/importHelpers";
import { groupFindings } from "../utils/findingsHelpers";
import "../Findings.css";
import "../Import.css";

export default function FindingsPage() {
  const { user } = useAuth();
  const { orgId, projectId, projects } = useProject();
  const [searchParams, setSearchParams] = useSearchParams();
  const [findings, setFindings] = useState([]);
  const [assets, setAssets] = useState([]);
  const [scans, setScans] = useState([]);
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [assetsLoading, setAssetsLoading] = useState(false);
  const [scansLoading, setScansLoading] = useState(false);
  const [error, setError] = useState("");
  const [reloadToken, setReloadToken] = useState(0);
  const [severityFilter, setSeverityFilter] = useState("all");
  const [assetFilter, setAssetFilter] = useState("all");
  const [findingScanFilter, setFindingScanFilter] = useState("all");
  const [ownerFilter, setOwnerFilter] = useState("all");
  const [findingSearch, setFindingSearch] = useState("");
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [selectedFindingStatus, setSelectedFindingStatus] = useState("open");
  const [selectedFindingAssignee, setSelectedFindingAssignee] = useState("");
  const [findingComments, setFindingComments] = useState([]);
  const [newFindingComment, setNewFindingComment] = useState("");
  const [showFindingModal, setShowFindingModal] = useState(false);
  const [showExportMenu, setShowExportMenu] = useState(false);
  const [showImportWizard, setShowImportWizard] = useState(false);
  const [importStep, setImportStep] = useState(1);
  const [importFile, setImportFile] = useState(null);
  const [importFormat, setImportFormat] = useState("auto");
  const [importRawData, setImportRawData] = useState([]);
  const [importColumnMap, setImportColumnMap] = useState({});
  const [importPreview, setImportPreview] = useState({ assets: [], findings: [] });
  const [importResult, setImportResult] = useState(null);
  const [importLoading, setImportLoading] = useState(false);
  const [importErrors, setImportErrors] = useState([]);
  const [importDefaultAssetId, setImportDefaultAssetId] = useState("");
  const [showCatalogModal, setShowCatalogModal] = useState(false);
  const [catalogTab, setCatalogTab] = useState("explore");
  const [vulnSearchQuery, setVulnSearchQuery] = useState("");
  const [vulnSearchResults, setVulnSearchResults] = useState([]);
  const [vulnSearchLoading, setVulnSearchLoading] = useState(false);
  const [showVulnDropdown, setShowVulnDropdown] = useState(false);
  const [selectedCatalogEntry, setSelectedCatalogEntry] = useState(null);
  const [catalogQuery, setCatalogQuery] = useState("");
  const [catalogResults, setCatalogResults] = useState([]);
  const [catalogLoading, setCatalogLoading] = useState(false);
  const [catalogStats, setCatalogStats] = useState(null);
  const [catalogDetail, setCatalogDetail] = useState(null);
  const [catalogImportFile, setCatalogImportFile] = useState(null);
  const [catalogImportLoading, setCatalogImportLoading] = useState(false);
  const [catalogImportResult, setCatalogImportResult] = useState(null);
  const [catalogImportError, setCatalogImportError] = useState("");
  const [catalogTemplateForm, setCatalogTemplateForm] = useState({
    name: "",
    cve_id: "",
    severity: "medium",
    base_score: "",
    cvss_vector: "",
    cwe_id: "",
    cwe_name: "",
    description: "",
    recommendation: "",
    references: "",
    exploit_available: false,
  });
  const [findingModalTab, setFindingModalTab] = useState("manual");
  const [findingTemplateQuery, setFindingTemplateQuery] = useState("");
  const [customTemplates, setCustomTemplates] = useState([]);
  const [templateForm, setTemplateForm] = useState({
    title: "",
    severity: "medium",
    cwe: "",
    owasp: "",
    description: "",
  });
  const [manualFindingForm, setManualFindingForm] = useState({
    asset_id: "",
    title: "",
    severity: "medium",
    status: "open",
    cwe: "",
    owasp: "",
    description: "",
    recommendation: "",
    references: "",
    rule_id: "manual",
    assignee_user_id: "",
  });
  const [members, setMembers] = useState([]);

  const handleRetry = useCallback(() => {
    setError("");
    setReloadToken((prev) => prev + 1);
  }, []);

  useEffect(() => {
    const scanId = searchParams.get("scan_id");
    if (scanId) {
      setFindingScanFilter(String(scanId));
      setSearchParams({}, { replace: true });
    }
  }, [searchParams, setSearchParams]);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        if (!cancelled) {
          setFindingsLoading(true);
          setAssetsLoading(true);
          setScansLoading(true);
        }
        if (!user || !projectId) {
          if (!cancelled) {
            setFindings([]);
            setAssets([]);
            setScans([]);
            setFindingsLoading(false);
            setAssetsLoading(false);
            setScansLoading(false);
          }
          return;
        }
        const [findingsResponse, assetsResponse, scansResponse] = await Promise.all([
          authFetch(`${API_BASE}/findings?project_id=${projectId}`),
          authFetch(`${API_BASE}/assets?project_id=${projectId}`),
          authFetch(`${API_BASE}/scans?project_id=${projectId}`),
        ]);
        if (!findingsResponse.ok || !assetsResponse.ok || !scansResponse.ok) {
          throw new Error("API no disponible");
        }
        const [findingsData, assetsData, scansData] = await Promise.all([
          findingsResponse.json(),
          assetsResponse.json(),
          scansResponse.json(),
        ]);
        if (!cancelled) {
          setFindings(unwrapItems(findingsData));
          setAssets(unwrapItems(assetsData));
          setScans(unwrapItems(scansData));
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message || "No se pudieron cargar los datos");
        }
      } finally {
        if (!cancelled) {
          setFindingsLoading(false);
          setAssetsLoading(false);
          setScansLoading(false);
        }
      }
    }

    load();
    return () => {
      cancelled = true;
    };
  }, [projectId, user, reloadToken]);

  useEffect(() => {
    let cancelled = false;
    async function loadFindingComments() {
      if (!selectedFinding || !user) {
        return;
      }
      try {
        const response = await authFetch(
          `${API_BASE}/findings/${selectedFinding.id}/comments`
        );
        if (!response.ok) {
          throw new Error("No se pudieron cargar los comentarios");
        }
        const data = await response.json();
        if (!cancelled) {
          setFindingComments(data);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message || "No se pudieron cargar los comentarios");
        }
      }
    }
    loadFindingComments();
    return () => {
      cancelled = true;
    };
  }, [selectedFinding, user]);

  useEffect(() => {
    let cancelled = false;
    async function loadTemplates() {
      if (!orgId || !user) {
        return;
      }
      try {
        const response = await authFetch(`${API_BASE}/templates?org_id=${orgId}`);
        if (!response.ok) {
          return;
        }
        const data = await response.json();
        if (!cancelled) {
          setCustomTemplates(data);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err.message || "No se pudieron cargar las plantillas");
        }
      }
    }
    loadTemplates();
    return () => {
      cancelled = true;
    };
  }, [orgId, user]);

  useEffect(() => {
    let cancelled = false;
    async function loadMembers() {
      if (!orgId || !user) {
        return;
      }
      try {
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
      }
    }
    loadMembers();
    return () => {
      cancelled = true;
    };
  }, [orgId, user]);

  useEffect(() => {
    if (selectedFinding?.status) {
      setSelectedFindingStatus(selectedFinding.status);
    }
    if (selectedFinding?.assignee_user_id) {
      setSelectedFindingAssignee(String(selectedFinding.assignee_user_id));
    } else {
      setSelectedFindingAssignee("");
    }
  }, [selectedFinding]);

  useEffect(() => {
    const handle = setTimeout(() => {
      if (!user) {
        return;
      }
      fetchVulnSearch(vulnSearchQuery, setVulnSearchResults, setVulnSearchLoading);
    }, 300);
    return () => clearTimeout(handle);
  }, [vulnSearchQuery, user]);

  useEffect(() => {
    const handle = setTimeout(() => {
      if (!user || !showCatalogModal) {
        return;
      }
      fetchVulnSearch(catalogQuery, setCatalogResults, setCatalogLoading);
    }, 300);
    return () => clearTimeout(handle);
  }, [catalogQuery, showCatalogModal, user]);

  useEffect(() => {
    if (!showCatalogModal || !user) {
      return;
    }
    loadCatalogStats();
  }, [showCatalogModal, user]);

  useEffect(() => {
    const onEscape = () => {
      setShowFindingModal(false);
      setShowImportWizard(false);
      setShowCatalogModal(false);
      setShowExportMenu(false);
      setSelectedFinding(null);
      setShowVulnDropdown(false);
    };
    document.addEventListener("shortcut:escape", onEscape);
    return () => document.removeEventListener("shortcut:escape", onEscape);
  }, []);

  const assetMap = useMemo(() => new Map(assets.map((asset) => [asset.id, asset])), [assets]);
  const scanFilterOptions = useMemo(() => {
    return [...scans].sort((a, b) => b.id - a.id);
  }, [scans]);

  const groupedFindings = useMemo(() => {
    return groupFindings(findings).sort((a, b) => {
      const rankDiff = (severityRank[a.severity] ?? 99) - (severityRank[b.severity] ?? 99);
      if (rankDiff !== 0) {
        return rankDiff;
      }
      return b.occurrences - a.occurrences;
    });
  }, [findings]);

  const filteredFindings = useMemo(() => {
    return groupedFindings.filter((finding) => {
      if (severityFilter !== "all" && finding.severity !== severityFilter) {
        return false;
      }
      if (assetFilter !== "all" && String(finding.asset_id) !== assetFilter) {
        return false;
      }
      if (findingScanFilter !== "all") {
        const scanIds = finding.scan_ids?.length ? finding.scan_ids : [finding.scan_id];
        if (!scanIds?.map(String).includes(String(findingScanFilter))) {
          return false;
        }
      }
      if (ownerFilter !== "all") {
        const owner = assetMap.get(finding.asset_id)?.owner_email || "";
        if (owner !== ownerFilter) {
          return false;
        }
      }
      if (findingSearch.trim()) {
        const query = findingSearch.toLowerCase();
        const haystack = [
          finding.title,
          finding.rule_id,
          finding.owasp,
          finding.cwe,
          assetMap.get(finding.asset_id)?.name,
          assetMap.get(finding.asset_id)?.owner_email,
        ]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        if (!haystack.includes(query)) {
          return false;
        }
      }
      return true;
    });
  }, [groupedFindings, severityFilter, assetFilter, findingScanFilter, ownerFilter, findingSearch, assetMap]);

  const findingsFiltersActive = useMemo(() => {
    return (
      severityFilter !== "all" ||
      assetFilter !== "all" ||
      findingScanFilter !== "all" ||
      ownerFilter !== "all" ||
      findingSearch.trim() !== ""
    );
  }, [severityFilter, assetFilter, findingScanFilter, ownerFilter, findingSearch]);

  const allTemplates = useMemo(() => {
    return [
      ...manualTemplates,
      ...customTemplates.map((item) => ({ ...item, group: "Personalizadas" })),
    ];
  }, [customTemplates]);

  const filteredTemplates = useMemo(() => {
    const query = findingTemplateQuery.trim().toLowerCase();
    if (!query) {
      return allTemplates;
    }
    return allTemplates.filter((template) => {
      return [template.title, template.cwe, template.owasp, template.group]
        .filter(Boolean)
        .join(" ")
        .toLowerCase()
        .includes(query);
    });
  }, [findingTemplateQuery, allTemplates]);

  useKeyboardShortcut("n", () => setShowFindingModal(true), {
    enabled: Boolean(projectId),
  });
  useKeyboardShortcut("i", () => {
    setShowImportWizard(true);
    setImportStep(1);
  }, {
    enabled: Boolean(projectId),
  });
  useKeyboardShortcut("e", () => {
    const exportBtn = document.querySelector("[data-shortcut-export]");
    if (exportBtn) exportBtn.click();
  }, {
    enabled: Boolean(projectId),
  });

  async function handleFindingStatusSave() {
    if (!selectedFinding || !user) {
      return;
    }
    const ids = selectedFinding.ids?.length ? selectedFinding.ids : [selectedFinding.id];
    try {
      await Promise.all(
        ids.map((id) =>
          authFetch(`${API_BASE}/findings/${id}`, {
            method: "PATCH",
            body: JSON.stringify({ status: selectedFindingStatus }),
          })
        )
      );
      setFindings((prev) =>
        prev.map((finding) =>
          ids.includes(finding.id) ? { ...finding, status: selectedFindingStatus } : finding
        )
      );
      setSelectedFinding((prev) => (prev ? { ...prev, status: selectedFindingStatus } : prev));
    } catch (err) {
      setError(err.message || "No se pudo actualizar el estado");
    }
  }

  async function handleFindingAssigneeSave() {
    if (!selectedFinding || !user) {
      return;
    }
    const assigneeId = selectedFindingAssignee ? Number(selectedFindingAssignee) : null;
    const response = await authFetch(`${API_BASE}/findings/${selectedFinding.id}`, {
      method: "PATCH",
      body: JSON.stringify({ assignee_user_id: assigneeId }),
    });
    if (response.ok) {
      const data = await response.json();
      setFindings((prev) =>
        prev.map((finding) => (finding.id === data.id ? { ...finding, ...data } : finding))
      );
      setSelectedFinding((prev) => (prev ? { ...prev, assignee_user_id: data.assignee_user_id } : prev));
      return;
    }
    const errorPayload = await response.json().catch(() => ({}));
    setError(errorPayload.detail || "No se pudo asignar el hallazgo");
  }

  async function handleFindingCommentSubmit(event) {
    event.preventDefault();
    if (!selectedFinding || !user || !newFindingComment.trim()) {
      return;
    }
    const response = await authFetch(`${API_BASE}/findings/${selectedFinding.id}/comments`, {
      method: "POST",
      body: JSON.stringify({ message: newFindingComment.trim() }),
    });
    if (response.ok) {
      const data = await response.json();
      setFindingComments((prev) => [...prev, data]);
      setNewFindingComment("");
      return;
    }
    const errorPayload = await response.json().catch(() => ({}));
    setError(errorPayload.detail || "No se pudo agregar el comentario");
  }

  async function handleManualFindingSubmit(event) {
    event.preventDefault();
    if (!manualFindingForm.asset_id || !manualFindingForm.title || !manualFindingForm.severity) {
      setError("Completa activo, titulo y severidad");
      return;
    }
    const payload = {
      asset_id: Number(manualFindingForm.asset_id),
      title: manualFindingForm.title,
      severity: manualFindingForm.severity,
      status: manualFindingForm.status,
      cwe: manualFindingForm.cwe || undefined,
      owasp: manualFindingForm.owasp || undefined,
      description: manualFindingForm.description || undefined,
      recommendation: manualFindingForm.recommendation || undefined,
      references: manualFindingForm.references || undefined,
      rule_id: manualFindingForm.rule_id || "manual",
      assignee_user_id: manualFindingForm.assignee_user_id
        ? Number(manualFindingForm.assignee_user_id)
        : undefined,
    };
    const response = await authFetch(`${API_BASE}/findings/manual`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
    if (response.ok) {
      const data = await response.json();
      setFindings((prev) => [...prev, data]);
      setShowFindingModal(false);
      setManualFindingForm({
        asset_id: "",
        title: "",
        severity: "medium",
        status: "open",
        cwe: "",
        owasp: "",
        description: "",
        recommendation: "",
        references: "",
        rule_id: "manual",
        assignee_user_id: "",
      });
      return;
    }
    const errorPayload = await response.json().catch(() => ({}));
    setError(errorPayload.detail || "No se pudo crear el hallazgo manual");
  }

  async function handleTemplateCreate(event) {
    event.preventDefault();
    if (!orgId || !templateForm.title || !templateForm.severity) {
      setError("Completa titulo y severidad para la plantilla");
      return;
    }
    const payload = {
      org_id: Number(orgId),
      title: templateForm.title,
      severity: templateForm.severity,
      cwe: templateForm.cwe || undefined,
      owasp: templateForm.owasp || undefined,
      description: templateForm.description || undefined,
    };
    const response = await authFetch(`${API_BASE}/templates`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
    if (response.ok) {
      const data = await response.json();
      setCustomTemplates((prev) => [data, ...prev]);
      setTemplateForm({ title: "", severity: "medium", cwe: "", owasp: "", description: "" });
      return;
    }
    const errorPayload = await response.json().catch(() => ({}));
    setError(errorPayload.detail || "No se pudo crear la plantilla");
  }

  function applyTemplate(template) {
    setManualFindingForm((prev) => ({
      ...prev,
      title: template.title,
      severity: template.severity,
      cwe: template.cwe || "",
      owasp: template.owasp || "",
      description: template.description || "",
      rule_id: template.cwe || template.owasp || "manual",
    }));
    setFindingModalTab("manual");
  }

  function generatePreview() {
    const errors = [];
    const assetMapLocal = new Map();
    const findingsList = [];
    const mappedFields = Object.values(importColumnMap);
    if (!mappedFields.includes("title")) errors.push('El campo "Titulo" es obligatorio');
    if (!mappedFields.includes("severity")) errors.push('El campo "Severidad" es obligatorio');
    const hasAssetNameMapped = mappedFields.includes("asset_name");
    if (errors.length > 0) {
      setImportErrors(errors);
      return;
    }

    const reverseMap = {};
    Object.entries(importColumnMap).forEach(([fileCol, sysField]) => {
      reverseMap[sysField] = fileCol;
    });

    importRawData.forEach((row, index) => {
      const getValue = (field) => {
        const col = reverseMap[field];
        return col ? String(row[col] || "").trim() : IMPORT_FIELDS[field]?.default || "";
      };

      let assetName = getValue("asset_name");
      let assetUri = getValue("asset_uri") || assetName;
      if (!hasAssetNameMapped) {
        if (importDefaultAssetId) {
          const existingAsset = assets.find(
            (asset) => String(asset.id) === String(importDefaultAssetId)
          );
          assetName = existingAsset?.name || "Importacion";
          assetUri = existingAsset?.uri || assetName;
        } else {
          const today = new Date().toISOString().split("T")[0];
          assetName = `Importacion ${today}`;
          assetUri = assetName;
        }
      }
      const assetKey = `${assetName}||${assetUri}`;
      let severity = getValue("severity").toLowerCase();
      const numericScore = Number.parseFloat(severity);
      if (!Number.isNaN(numericScore)) {
        if (numericScore >= 9.0) severity = "critical";
        else if (numericScore >= 7.0) severity = "high";
        else if (numericScore >= 4.0) severity = "medium";
        else if (numericScore > 0) severity = "low";
        else severity = "info";
      }
      const sevNormalize = {
        critica: "critical",
        alta: "high",
        media: "medium",
        baja: "low",
        informativa: "info",
        critical: "critical",
        high: "high",
        medium: "medium",
        low: "low",
        info: "info",
      };
      severity = sevNormalize[severity] || "medium";

      if (assetName && !assetMapLocal.has(assetKey)) {
        const existingAsset = assets.find(
          (asset) => asset.name === assetName && (asset.uri === assetUri || !assetUri)
        );
        assetMapLocal.set(assetKey, {
          name: assetName,
          uri: assetUri,
          type: getValue("asset_type") || "web_app",
          owner_email: getValue("owner_email") || "",
          exists: Boolean(existingAsset) || Boolean(importDefaultAssetId),
          existingId: importDefaultAssetId ? Number(importDefaultAssetId) : existingAsset?.id || null,
        });
      }

      findingsList.push({
        _row: index + 1,
        title: getValue("title"),
        severity,
        status: getValue("status") || "open",
        description: getValue("description"),
        cwe: getValue("cwe"),
        owasp_category: getValue("owasp_category"),
        cvss_score: getValue("cvss_score"),
        occurrences: Number(getValue("occurrences")) || 1,
        tags: getValue("tags"),
        pentester_email: getValue("pentester_email"),
        _assetKey: assetKey,
        _assetName: assetName,
      });
    });

    const invalidRows = findingsList.filter((finding) => !finding.title);
    if (invalidRows.length > 0) {
      errors.push(`${invalidRows.length} filas sin titulo (seran omitidas)`);
    }

    setImportErrors(errors);
    setImportPreview({
      assets: Array.from(assetMapLocal.values()),
      findings: findingsList.filter((finding) => finding.title),
    });
  }

  async function executeImportFallback() {
    const results = { assetsCreated: 0, assetsReused: 0, findingsCreated: 0, errors: [] };
    const assetIdMap = new Map();
    for (const asset of importPreview.assets) {
      if (asset.exists && asset.existingId) {
        assetIdMap.set(`${asset.name}||${asset.uri}`, asset.existingId);
        results.assetsReused += 1;
        continue;
      }
      try {
        const resp = await authFetch(`${API_BASE}/assets`, {
          method: "POST",
          body: JSON.stringify({
            project_id: projectId,
            name: asset.name,
            uri: asset.uri,
            type: asset.type,
            owner_email: asset.owner_email || "",
            environment: "prod",
            criticality: "media",
          }),
        });
        if (!resp.ok) {
          throw new Error(await resp.text());
        }
        const newAsset = await resp.json();
        assetIdMap.set(`${asset.name}||${asset.uri}`, newAsset.id);
        results.assetsCreated += 1;
      } catch (err) {
        results.errors.push(`Error creando activo "${asset.name}": ${err.message}`);
      }
    }

    for (const finding of importPreview.findings) {
      const assetId = assetIdMap.get(finding._assetKey);
      if (!assetId) {
        results.errors.push(`Fila ${finding._row}: No se pudo vincular al activo "${finding._assetName}"`);
        continue;
      }
      try {
        const resp = await authFetch(`${API_BASE}/findings/manual`, {
          method: "POST",
          body: JSON.stringify({
            asset_id: assetId,
            title: finding.title,
            severity: finding.severity,
            status: finding.status,
            description: finding.description,
            cwe: finding.cwe,
            owasp: finding.owasp_category,
          }),
        });
        if (!resp.ok) {
          throw new Error(await resp.text());
        }
        results.findingsCreated += 1;
      } catch (err) {
        results.errors.push(`Fila ${finding._row}: Error creando "${finding.title}": ${err.message}`);
      }
    }
    return results;
  }

  async function reloadAssetsAndFindings() {
    if (!projectId) {
      return;
    }
    try {
      const [assetsResponse, findingsResponse] = await Promise.all([
        authFetch(`${API_BASE}/assets?project_id=${projectId}`),
        authFetch(`${API_BASE}/findings?project_id=${projectId}`),
      ]);
      if (!assetsResponse.ok || !findingsResponse.ok) {
        return;
      }
      const [assetsData, findingsData] = await Promise.all([
        assetsResponse.json(),
        findingsResponse.json(),
      ]);
      setAssets(unwrapItems(assetsData));
      setFindings(unwrapItems(findingsData));
    } catch (err) {
      setError(err.message || "No se pudieron actualizar los datos");
    }
  }

  async function executeImport() {
    setImportLoading(true);
    try {
      const payload = {
        project_id: Number(projectId),
        assets: importPreview.assets.map((asset) => ({
          name: asset.name,
          uri: asset.uri,
          type: asset.type,
          owner_email: asset.owner_email,
          environment: "prod",
          criticality: "media",
        })),
        findings: importPreview.findings.map((finding) => ({
          title: finding.title,
          severity: finding.severity,
          status: finding.status,
          description: finding.description,
          cwe: finding.cwe,
          owasp: finding.owasp_category,
          cvss_score: finding.cvss_score ? Number(finding.cvss_score) : null,
          asset_ref: finding._assetName,
          pentester_email: finding.pentester_email,
          occurrences: finding.occurrences,
          tags: finding.tags ? finding.tags.split(",").map((tag) => tag.trim()) : [],
        })),
      };

      const response = await authFetch(`${API_BASE}/import/bulk`, {
        method: "POST",
        body: JSON.stringify(payload),
      });

      let results;
      if (!response.ok) {
        results = await executeImportFallback();
      } else {
        const data = await response.json();
        results = {
          assetsCreated: data.assets_created,
          assetsReused: data.assets_reused,
          findingsCreated: data.findings_created,
          errors: data.errors || [],
        };
      }

      setImportResult(results);
      setImportStep(4);
      reloadAssetsAndFindings();
    } catch (err) {
      setImportResult({
        assetsCreated: 0,
        assetsReused: 0,
        findingsCreated: 0,
        errors: [`Error general: ${err.message}`],
      });
      setImportStep(4);
    } finally {
      setImportLoading(false);
    }
  }

  function resetImportWizard() {
    setShowImportWizard(false);
    setImportStep(1);
    setImportFile(null);
    setImportRawData([]);
    setImportColumnMap({});
    setImportPreview({ assets: [], findings: [] });
    setImportResult(null);
    setImportErrors([]);
    setImportDefaultAssetId("");
  }

  async function fetchVulnSearch(query, setResults, setLoading) {
    if (!query.trim()) {
      setResults([]);
      return;
    }
    setLoading(true);
    try {
      const response = await authFetch(
        `${API_BASE}/vulndb/search?q=${encodeURIComponent(query)}&limit=15`
      );
      if (!response.ok) {
        setResults([]);
        return;
      }
      const data = await response.json();
      setResults(unwrapItems(data));
    } catch (err) {
      setResults([]);
      setError(err.message || "No se pudo buscar en el catalogo");
    } finally {
      setLoading(false);
    }
  }

  async function handleCatalogSelect(entryId) {
    try {
      const response = await authFetch(`${API_BASE}/vulndb/${entryId}`);
      if (!response.ok) {
        return;
      }
      const entry = await response.json();
      setCatalogDetail(entry);
      if (showFindingModal) {
        setSelectedCatalogEntry(entry);
        setVulnSearchQuery(entry.cve_id || entry.name || "");
        setShowVulnDropdown(false);
        const extraDetails = [
          entry.recommendation ? `Recomendacion: ${entry.recommendation}` : "",
          entry.references ? `Referencias:\n${entry.references}` : "",
        ]
          .filter(Boolean)
          .join("\n\n");
        setManualFindingForm((prev) => ({
          ...prev,
          title: entry.name || prev.title,
          severity: entry.severity || prev.severity,
          cwe: entry.cwe_name || entry.cwe_id || prev.cwe,
          owasp: prev.owasp,
          description: [entry.description || "", extraDetails].filter(Boolean).join("\n\n"),
          recommendation: entry.recommendation || prev.recommendation,
          references: entry.references || prev.references,
          rule_id: entry.cve_id || prev.rule_id,
        }));
      }
    } catch (err) {
      setError(err.message || "No se pudo cargar la vulnerabilidad");
    }
  }

  async function loadCatalogStats() {
    try {
      const response = await authFetch(`${API_BASE}/vulndb/stats`);
      if (!response.ok) {
        return;
      }
      const data = await response.json();
      setCatalogStats(data);
    } catch (err) {
      setError(err.message || "No se pudieron cargar las metricas del catalogo");
    }
  }

  async function handleCatalogImport() {
    if (!catalogImportFile) {
      return;
    }
    setCatalogImportLoading(true);
    setCatalogImportError("");
    setCatalogImportResult(null);
    try {
      const formData = new FormData();
      formData.append("file", catalogImportFile);
      const response = await authFetch(`${API_BASE}/vulndb/import`, {
        method: "POST",
        body: formData,
      });
      if (!response.ok) {
        const payload = await response.json().catch(() => ({}));
        throw new Error(payload.detail || "Error importando catalogo");
      }
      const data = await response.json();
      setCatalogImportResult(data);
      loadCatalogStats();
    } catch (err) {
      setCatalogImportError(err.message || "Error importando catalogo");
    } finally {
      setCatalogImportLoading(false);
    }
  }

  async function handleCatalogTemplateSubmit(event) {
    event.preventDefault();
    if (!catalogTemplateForm.name) {
      return;
    }
    try {
      const response = await authFetch(`${API_BASE}/vulndb`, {
        method: "POST",
        body: JSON.stringify({
          ...catalogTemplateForm,
          base_score: catalogTemplateForm.base_score
            ? Number(catalogTemplateForm.base_score)
            : null,
          cwe_id: catalogTemplateForm.cwe_id ? Number(catalogTemplateForm.cwe_id) : null,
          source: "manual",
          is_template: true,
        }),
      });
      if (!response.ok) {
        const payload = await response.json().catch(() => ({}));
        throw new Error(payload.detail || "No se pudo crear la plantilla");
      }
      setCatalogTemplateForm({
        name: "",
        cve_id: "",
        severity: "medium",
        base_score: "",
        cvss_vector: "",
        cwe_id: "",
        cwe_name: "",
        description: "",
        recommendation: "",
        references: "",
        exploit_available: false,
      });
      loadCatalogStats();
    } catch (err) {
      setError(err.message || "No se pudo crear la plantilla");
    }
  }

  function resetCatalogModal() {
    setShowCatalogModal(false);
    setCatalogTab("explore");
    setCatalogQuery("");
    setCatalogResults([]);
    setCatalogDetail(null);
    setCatalogImportFile(null);
    setCatalogImportResult(null);
    setCatalogImportError("");
  }

  function handleExport(format) {
    setShowExportMenu(false);
    if (!projectId) {
      return;
    }
    const exportData = filteredFindings.map((finding) => {
      const asset = assets.find((item) => item.id === finding.asset_id);
      return {
        title: finding.title,
        severity: finding.severity,
        status: finding.status,
        description: finding.description || "",
        cwe: finding.cwe || "",
        owasp_category: finding.owasp || "",
        cvss_score: finding.cvss_score || "",
        asset_name: asset?.name || "",
        asset_uri: asset?.uri || "",
        asset_type: asset?.type || "",
        owner_email: asset?.owner_email || "",
        pentester_email: "",
        occurrences: finding.occurrences || 1,
        tags: "",
        created_at: "",
        updated_at: "",
      };
    });
    const projectName =
      projects.find((project) => String(project.id) === String(projectId))?.name || "proyecto";
    const timestamp = new Date().toISOString().split("T")[0];
    const filename = `vulninventory_${projectName}_${timestamp}`;
    if (format === "csv") {
      exportCSV(exportData, filename);
    } else if (format === "json") {
      exportJSON(exportData, filename);
    }
  }

  if (!projectId) {
    return (
      <EmptyState
        icon="findings"
        title="Selecciona un proyecto"
        description="Elige un cliente y proyecto en el panel lateral para acceder a hallazgos."
      />
    );
  }

  return (
    <section className={`findings-detail ${selectedFinding ? "has-drawer" : ""}`}>
      <div className="findings-header">
        <div>
          <div className="findings-title-row">
            <svg className="findings-title-icon" viewBox="0 0 24 24" aria-hidden="true">
              <path
                d="M12 3l7 3v5c0 4.4-3 8.4-7 10-4-1.6-7-5.6-7-10V6l7-3Z"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.5"
                strokeLinejoin="round"
              />
              <path
                d="M9.5 12.5 11 14l3.5-4"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.5"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
            <h2 className="findings-title-heading">Hallazgos</h2>
          </div>
          <p className="findings-subtitle">Inventario de vulnerabilidades del proyecto</p>
        </div>
        <div className="findings-header-actions">
          <span className="badge badge-accent">{filteredFindings.length} total</span>
          <div className="dropdown">
            <button
              className="btn btn-secondary"
              type="button"
              onClick={() => setShowExportMenu((prev) => !prev)}
              title="Exportar (E)"
              data-shortcut-export
            >
              📤 Exportar
              <kbd className="btn-shortcut-hint">E</kbd>
            </button>
            {showExportMenu && (
              <div className="dropdown-menu">
                <button className="dropdown-item" type="button" onClick={() => handleExport("csv")}>
                  📄 CSV (.csv)
                </button>
                <button className="dropdown-item" type="button" onClick={() => handleExport("json")}>
                  📋 JSON (.json)
                </button>
              </div>
            )}
          </div>
          <button
            className="btn btn-secondary"
            type="button"
            onClick={() => {
              setShowImportWizard(true);
              setImportStep(1);
            }}
            title="Importar (I)"
          >
            📥 Importar
            <kbd className="btn-shortcut-hint">I</kbd>
          </button>
          <button
            className="btn btn-secondary"
            type="button"
            onClick={() => setShowCatalogModal(true)}
          >
            📚 Catalogo
          </button>
          <button
            className="btn btn-primary"
            type="button"
            onClick={() => setShowFindingModal(true)}
            title="Nuevo hallazgo (N)"
          >
            + Nuevo hallazgo
            <kbd className="btn-shortcut-hint">N</kbd>
          </button>
        </div>
      </div>

      <div className="card findings-filters">
        <div className="form-group">
          <label className="form-label">Severidad</label>
          <select className="form-select" value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}>
            <option value="all">Todas</option>
            <option value="critical">Crítica</option>
            <option value="high">Alta</option>
            <option value="medium">Media</option>
            <option value="low">Baja</option>
            <option value="info">Info</option>
          </select>
        </div>
        <div className="form-group">
          <label className="form-label">Activo</label>
          <select className="form-select" value={assetFilter} onChange={(event) => setAssetFilter(event.target.value)}>
            <option value="all">Todos</option>
            {assets.map((asset) => (
              <option key={asset.id} value={String(asset.id)}>{asset.name}</option>
            ))}
          </select>
        </div>
        <div className="form-group">
          <label className="form-label">Responsable</label>
          <select className="form-select" value={ownerFilter} onChange={(event) => setOwnerFilter(event.target.value)}>
            <option value="all">Todos</option>
            {Array.from(new Set(assets.map((asset) => asset.owner_email).filter(Boolean))).map(
              (owner) => (
                <option key={owner} value={owner}>{owner}</option>
              ),
            )}
          </select>
        </div>
        <div className="form-group">
          <label className="form-label">Escaneo</label>
          <select className="form-select" value={findingScanFilter} onChange={(event) => setFindingScanFilter(event.target.value)}>
            <option value="all">Todos</option>
            {scanFilterOptions.map((scan) => (
              <option key={scan.id} value={String(scan.id)}>#{scan.id} {scan.tool}</option>
            ))}
          </select>
        </div>
        <div className="form-group findings-search">
          <label className="form-label">Buscar</label>
          <div className="findings-search-input search-input-wrapper">
            <svg className="findings-search-icon" viewBox="0 0 24 24" aria-hidden="true">
              <circle cx="11" cy="11" r="7" fill="none" stroke="currentColor" strokeWidth="1.5" />
              <path d="M20 20l-3.5-3.5" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
            </svg>
            <input
              className="form-input"
              type="text"
              placeholder="título, regla, activo, responsable"
              value={findingSearch}
              onChange={(event) => setFindingSearch(event.target.value)}
              data-shortcut-search
            />
            <kbd className="search-shortcut-hint">/</kbd>
          </div>
        </div>
      </div>

      {error ? (
        <EmptyState
          icon="error"
          title="No pudimos cargar los hallazgos"
          description={`Reintenta la consulta del proyecto. ${error}`}
          action={{ label: "Reintentar", onClick: handleRetry }}
          secondaryAction={{ label: "Cerrar", onClick: () => setError("") }}
        />
      ) : findingsLoading ? (
        <FindingsTableSkeleton />
      ) : filteredFindings.length === 0 ? (
        findingsFiltersActive ? (
          <EmptyState
            icon="search"
            title="Sin resultados"
            description="No se encontraron hallazgos con los filtros seleccionados. Prueba ajustando los criterios de búsqueda."
            action={{
              label: "Limpiar filtros",
              onClick: () => {
                setSeverityFilter("all");
                setAssetFilter("all");
                setOwnerFilter("all");
                setFindingScanFilter("all");
                setFindingSearch("");
              },
            }}
          />
        ) : (
          <EmptyState
            icon="findings"
            title="No hay hallazgos"
            description="Este proyecto aún no tiene hallazgos registrados. Crea uno manualmente, importa desde un archivo, o ejecuta un escaneo."
            action={{ label: "+ Nuevo hallazgo", onClick: () => setShowFindingModal(true) }}
            secondaryAction={{ label: "Importar", onClick: () => { setShowImportWizard(true); setImportStep(1); } }}
          />
        )
      ) : (
        <div className="table-container">
          <table className="table findings-table">
            <thead>
              <tr>
                <th>Severidad</th>
                <th>Título</th>
                <th>Activo</th>
                <th>Responsable</th>
                <th>Pentester</th>
                <th>Estado</th>
                <th>Ocurrencias</th>
              </tr>
            </thead>
            <tbody>
              {filteredFindings.map((finding) => (
                <tr
                  key={finding.id}
                  className={`findings-row ${selectedFinding?.id === finding.id ? "findings-row--active" : ""}`}
                  onClick={() => setSelectedFinding(finding)}
                >
                  <td>
                    <span className={`badge badge-${finding.severity}`}>
                      {severityLabels[finding.severity] || finding.severity}
                    </span>
                  </td>
                  <td className="findings-title">
                    <span className="findings-title-text">{finding.title}</span>
                    {finding.cwe && (
                      <span className="cve-id">{finding.cwe}</span>
                    )}
                  </td>
                  <td>
                    <span className="findings-asset-name">
                      {assetMap.get(finding.asset_id)?.name || finding.asset_id}
                    </span>
                  </td>
                  <td>{assetMap.get(finding.asset_id)?.owner_email || "—"}</td>
                  <td>{members.find((m) => m.user_id === finding.assignee_user_id)?.email || "—"}</td>
                  <td>
                    <span className={`findings-status findings-status--${finding.status}`}>
                      {statusLabels[finding.status] || finding.status}
                    </span>
                  </td>
                  <td className="findings-occurrences">{finding.occurrences}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {selectedFinding && (
        <aside className="findings-drawer">
          <div className="findings-drawer-header">
            <div>
              <span className={`badge badge-${selectedFinding.severity}`}>
                {severityLabels[selectedFinding.severity] || selectedFinding.severity}
              </span>
              <h3 className="findings-drawer-title">{selectedFinding.title}</h3>
            </div>
            <button className="btn btn-ghost btn-sm" onClick={() => setSelectedFinding(null)}>✕</button>
          </div>

          <div className="findings-drawer-body">
            {selectedFinding.description && (
              <p className="findings-description">{selectedFinding.description}</p>
            )}
            {(selectedFinding.recommendation || selectedFinding.references) && (
              <div className="findings-recommendations">
                {selectedFinding.recommendation && (
                  <div className="findings-recommendation-block">
                    <span className="findings-meta-label">Recomendación</span>
                    <p>{selectedFinding.recommendation}</p>
                  </div>
                )}
                {selectedFinding.references && (
                  <div className="findings-recommendation-block">
                    <span className="findings-meta-label">Referencias</span>
                    <pre className="findings-references">{selectedFinding.references}</pre>
                  </div>
                )}
              </div>
            )}
            <div className="findings-meta-grid">
              <div className="findings-meta-item">
                <span className="findings-meta-label">OWASP</span>
                <span className="cve-id">{selectedFinding.owasp || "—"}</span>
              </div>
              <div className="findings-meta-item">
                <span className="findings-meta-label">CWE</span>
                <span className="cve-id">{selectedFinding.cwe || "—"}</span>
              </div>
              <div className="findings-meta-item">
                <span className="findings-meta-label">Activo</span>
                <span>{assetMap.get(selectedFinding.asset_id)?.name || "—"}</span>
              </div>
              <div className="findings-meta-item">
                <span className="findings-meta-label">URI</span>
                <span className="file-path">{assetMap.get(selectedFinding.asset_id)?.uri || "—"}</span>
              </div>
              <div className="findings-meta-item">
                <span className="findings-meta-label">Ocurrencias</span>
                <span className="findings-occurrences">{selectedFinding.occurrences}</span>
              </div>
            </div>

            <div className="findings-actions">
              <div className="findings-action-row">
                <div className="form-group">
                  <label className="form-label">Estado</label>
                  <select className="form-select" value={selectedFindingStatus}
                    onChange={(event) => setSelectedFindingStatus(event.target.value)}>
                    {statusOptions.map((status) => (
                      <option key={status} value={status}>
                        {statusLabels[status] || status}
                      </option>
                    ))}
                  </select>
                </div>
                <button className="btn btn-primary btn-sm" onClick={handleFindingStatusSave}>
                  Guardar
                </button>
              </div>
              <div className="findings-action-row">
                <div className="form-group">
                  <label className="form-label">Pentester</label>
                  <select className="form-select" value={selectedFindingAssignee}
                    onChange={(event) => setSelectedFindingAssignee(event.target.value)}>
                    <option value="">Sin asignar</option>
                    {members.map((member) => (
                      <option key={member.user_id} value={String(member.user_id)}>
                        {member.email}
                      </option>
                    ))}
                  </select>
                </div>
                <button className="btn btn-secondary btn-sm" onClick={handleFindingAssigneeSave}>
                  Asignar
                </button>
              </div>
            </div>

            <div className="findings-comments">
              <h4>Comentarios</h4>
              {findingComments.map((comment) => (
                <div key={comment.id} className="comment-item">
                  <span className="comment-meta">
                    {members.find((member) => member.user_id === comment.user_id)?.email || "Sistema"} ·{" "}
                    {new Date(comment.created_at).toLocaleString()}
                  </span>
                  <p>{comment.message}</p>
                </div>
              ))}
              {findingComments.length === 0 && (
                <p className="comment-empty">Sin comentarios todavía.</p>
              )}
              <form onSubmit={handleFindingCommentSubmit} className="comment-form">
                <input
                  className="form-input"
                  type="text"
                  placeholder="Agregar comentario"
                  value={newFindingComment}
                  onChange={(event) => setNewFindingComment(event.target.value)}
                />
                <button className="btn btn-primary btn-sm" type="submit">Guardar</button>
              </form>
            </div>
          </div>
        </aside>
      )}

      {showFindingModal && (
        <div className="modal-backdrop" onClick={() => setShowFindingModal(false)}>
          <div className="modal" onClick={(event) => event.stopPropagation()}>
            <div className="modal-header">
              <h3>Nuevo hallazgo</h3>
              <button className="btn btn-secondary" type="button" onClick={() => setShowFindingModal(false)}>Cerrar</button>
            </div>
            <div className="modal-tabs">
              <button
                type="button"
                className={findingModalTab === "manual" ? "active" : ""}
                onClick={() => setFindingModalTab("manual")}
              >
                Manual
              </button>
              <button
                type="button"
                className={findingModalTab === "templates" ? "active" : ""}
                onClick={() => setFindingModalTab("templates")}
              >
                Plantillas
              </button>
            </div>
            {findingModalTab === "manual" && (
              <form className="modal-form" onSubmit={handleManualFindingSubmit}>
                <div className="form-group full findings-catalog-search">
                  <label className="form-label">Buscar en catalogo</label>
                  <input
                    className="form-input"
                    type="text"
                    placeholder="🔍 Buscar CVE, CWE, nombre..."
                    value={vulnSearchQuery}
                    onChange={(event) => {
                      setVulnSearchQuery(event.target.value);
                      setShowVulnDropdown(true);
                    }}
                    onFocus={() => setShowVulnDropdown(true)}
                    onBlur={() => {
                      setTimeout(() => setShowVulnDropdown(false), 150);
                    }}
                    onKeyDown={(event) => {
                      if (event.key === "Escape") {
                        setShowVulnDropdown(false);
                      }
                    }}
                  />
                  {vulnSearchQuery && showVulnDropdown && (
                    <div className="catalog-dropdown">
                      {vulnSearchLoading && <p className="catalog-dropdown-item">Buscando...</p>}
                      {!vulnSearchLoading && vulnSearchResults.length === 0 && (
                        <p className="catalog-dropdown-item">Sin resultados</p>
                      )}
                      {!vulnSearchLoading &&
                        vulnSearchResults.map((entry) => (
                          <button
                            key={entry.id}
                            type="button"
                            className="catalog-dropdown-item"
                            onClick={() => handleCatalogSelect(entry.id)}
                          >
                            <span className="catalog-item-title">
                              {entry.cve_id || entry.name}
                            </span>
                            <span className={`badge badge-${entry.severity || "info"}`}>
                              {entry.severity || "info"}
                            </span>
                            {entry.base_score ? (
                              <span className="catalog-item-score">{entry.base_score}</span>
                            ) : null}
                            {entry.exploit_available && <span className="catalog-item-flag">⚡</span>}
                          </button>
                        ))}
                    </div>
                  )}
                  {selectedCatalogEntry && (
                    <div className="catalog-selected-banner">
                      <span>✓ Datos cargados desde {selectedCatalogEntry.cve_id || selectedCatalogEntry.name}</span>
                      <button
                        className="btn btn-ghost btn-sm"
                        type="button"
                        onClick={() => setSelectedCatalogEntry(null)}
                      >
                        Desvincular
                      </button>
                    </div>
                  )}
                </div>
                <div className="form-group">
                  <label className="form-label">Activo</label>
                  <select className="form-select"
                    value={manualFindingForm.asset_id}
                    onChange={(event) =>
                      setManualFindingForm((prev) => ({ ...prev, asset_id: event.target.value }))
                    }
                    required
                  >
                    <option value="">Selecciona un activo</option>
                    {assets.map((asset) => (
                      <option key={asset.id} value={String(asset.id)}>
                        {asset.name}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="form-group">
                  <label className="form-label">Severidad</label>
                  <select className="form-select"
                    value={manualFindingForm.severity}
                    onChange={(event) =>
                      setManualFindingForm((prev) => ({ ...prev, severity: event.target.value }))
                    }
                    required
                  >
                    <option value="critical">Crítica</option>
                    <option value="high">Alta</option>
                    <option value="medium">Media</option>
                    <option value="low">Baja</option>
                    <option value="info">Info</option>
                  </select>
                </div>
                <div className="form-group">
                  <label className="form-label">Estado</label>
                  <select className="form-select"
                    value={manualFindingForm.status}
                    onChange={(event) =>
                      setManualFindingForm((prev) => ({ ...prev, status: event.target.value }))
                    }
                  >
                    {statusOptions.map((status) => (
                      <option key={status} value={status}>
                        {statusLabels[status] || status}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="form-group full">
                  <label className="form-label">Titulo</label>
                  <input className="form-input"
                    type="text"
                    placeholder="SQL Injection en login"
                    value={manualFindingForm.title}
                    onChange={(event) =>
                      setManualFindingForm((prev) => ({ ...prev, title: event.target.value }))
                    }
                    required
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">CWE</label>
                  <input className="form-input"
                    type="text"
                    placeholder="CWE-89"
                    value={manualFindingForm.cwe}
                    onChange={(event) =>
                      setManualFindingForm((prev) => ({ ...prev, cwe: event.target.value }))
                    }
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">OWASP</label>
                  <input className="form-input"
                    type="text"
                    placeholder="A03:2021"
                    value={manualFindingForm.owasp}
                    onChange={(event) =>
                      setManualFindingForm((prev) => ({ ...prev, owasp: event.target.value }))
                    }
                  />
                </div>
                <div className="form-group full">
                  <label className="form-label">Descripcion</label>
                  <textarea className="form-input"
                    placeholder="Describe el hallazgo..."
                    value={manualFindingForm.description}
                    onChange={(event) =>
                      setManualFindingForm((prev) => ({ ...prev, description: event.target.value }))
                    }
                  />
                </div>
                <div className="form-group full">
                  <label className="form-label">Recomendacion</label>
                  <textarea className="form-input"
                    placeholder="Mitigaciones sugeridas..."
                    value={manualFindingForm.recommendation}
                    onChange={(event) =>
                      setManualFindingForm((prev) => ({ ...prev, recommendation: event.target.value }))
                    }
                  />
                </div>
                <div className="form-group full">
                  <label className="form-label">Referencias</label>
                  <textarea className="form-input"
                    placeholder="Links o fuentes..."
                    value={manualFindingForm.references}
                    onChange={(event) =>
                      setManualFindingForm((prev) => ({ ...prev, references: event.target.value }))
                    }
                  />
                </div>
                <div className="modal-form-actions full">
                  <button className="btn btn-secondary" type="button" onClick={() => setShowFindingModal(false)}>
                    Cancelar
                  </button>
                  <button className="btn btn-primary" type="submit">Guardar hallazgo</button>
                </div>
              </form>
            )}
            {findingModalTab === "templates" && (
              <form className="modal-form" onSubmit={handleTemplateCreate}>
                <div className="form-group full">
                  <label className="form-label">Buscar plantilla</label>
                  <input
                    className="form-input"
                    type="text"
                    placeholder="Buscar por titulo, CWE, OWASP..."
                    value={findingTemplateQuery}
                    onChange={(event) => setFindingTemplateQuery(event.target.value)}
                  />
                </div>
                <div className="template-grid">
                  {filteredTemplates.map((template) => (
                    <div key={template.id} className="template-card">
                      <div>
                        <span className="template-group">{template.group}</span>
                        <h4>{template.title}</h4>
                        <div className="template-meta">
                          {template.cwe && <span className="cve-id">{template.cwe}</span>}
                          {template.owasp && <span className="cve-id">{template.owasp}</span>}
                        </div>
                        <p>{template.description}</p>
                      </div>
                      <div className="template-actions">
                        <span className={`badge badge-${template.severity}`}>
                          {severityLabels[template.severity] || template.severity}
                        </span>
                        <button className="btn btn-secondary btn-sm" type="button" onClick={() => applyTemplate(template)}>
                          Usar
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
                <div className="template-divider">Crear nueva plantilla</div>
                <div className="form-group full">
                  <label className="form-label">Titulo</label>
                  <input
                    className="form-input"
                    type="text"
                    value={templateForm.title}
                    onChange={(event) => setTemplateForm((prev) => ({ ...prev, title: event.target.value }))}
                    required
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Severidad</label>
                  <select
                    className="form-select"
                    value={templateForm.severity}
                    onChange={(event) => setTemplateForm((prev) => ({ ...prev, severity: event.target.value }))}
                  >
                    <option value="critical">Crítica</option>
                    <option value="high">Alta</option>
                    <option value="medium">Media</option>
                    <option value="low">Baja</option>
                    <option value="info">Info</option>
                  </select>
                </div>
                <div className="form-group">
                  <label className="form-label">CWE</label>
                  <input
                    className="form-input"
                    type="text"
                    value={templateForm.cwe}
                    onChange={(event) => setTemplateForm((prev) => ({ ...prev, cwe: event.target.value }))}
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">OWASP</label>
                  <input
                    className="form-input"
                    type="text"
                    value={templateForm.owasp}
                    onChange={(event) => setTemplateForm((prev) => ({ ...prev, owasp: event.target.value }))}
                  />
                </div>
                <div className="form-group full">
                  <label className="form-label">Descripcion</label>
                  <textarea
                    className="form-input"
                    value={templateForm.description}
                    onChange={(event) => setTemplateForm((prev) => ({ ...prev, description: event.target.value }))}
                  />
                </div>
                <div className="modal-form-actions full">
                  <button className="btn btn-secondary" type="button" onClick={() => setShowFindingModal(false)}>
                    Cancelar
                  </button>
                  <button className="btn btn-primary" type="submit">Guardar plantilla</button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}

      {showImportWizard && (
        <div className="wizard-overlay" onClick={resetImportWizard}>
          <div className="wizard-modal" onClick={(event) => event.stopPropagation()}>
            <div className="wizard-header">
              <h3>Importar hallazgos</h3>
              <button className="btn btn-ghost" type="button" onClick={resetImportWizard}>✕</button>
            </div>
            <div className="wizard-stepper">
              <div className={`wizard-step ${importStep >= 1 ? "wizard-step--active" : ""} ${importStep > 1 ? "wizard-step--done" : ""}`}>
                <span className="wizard-step-number">1</span>
                <span className="wizard-step-label">Archivo</span>
              </div>
              <div className="wizard-step-line" />
              <div className={`wizard-step ${importStep >= 2 ? "wizard-step--active" : ""} ${importStep > 2 ? "wizard-step--done" : ""}`}>
                <span className="wizard-step-number">2</span>
                <span className="wizard-step-label">Mapeo</span>
              </div>
              <div className="wizard-step-line" />
              <div className={`wizard-step ${importStep >= 3 ? "wizard-step--active" : ""} ${importStep > 3 ? "wizard-step--done" : ""}`}>
                <span className="wizard-step-number">3</span>
                <span className="wizard-step-label">Resumen</span>
              </div>
              <div className="wizard-step-line" />
              <div className={`wizard-step ${importStep >= 4 ? "wizard-step--active" : ""}`}>
                <span className="wizard-step-number">4</span>
                <span className="wizard-step-label">Resultado</span>
              </div>
            </div>

            <div className="wizard-body">
              {importStep === 1 && (
                <div className="wizard-panel">
                  <p className="wizard-instruction">Selecciona un archivo CSV, JSON, SARIF o XML</p>
                  <div className="wizard-file-area">
                    <input
                      className="form-input"
                      type="file"
                      accept=".csv,.json,.sarif,.nessus,.xml"
                      onChange={async (event) => {
                        const file = event.target.files?.[0];
                        if (!file) return;
                        setImportFile(file);
                        const rows = await parseImportFile(file, {
                          setImportFormat,
                          setImportErrors,
                          setImportRawData,
                          setImportColumnMap,
                        });
                        if (rows.length > 0) {
                          setImportStep(2);
                        }
                      }}
                    />
                    {importFile && <p className="wizard-file-name">Archivo: {importFile.name}</p>}
                  </div>
                  <div className="wizard-template-actions">
                    <button
                      className="btn btn-secondary"
                      type="button"
                      onClick={() => downloadImportTemplate("csv")}
                    >
                      Descargar plantilla CSV
                    </button>
                    <button
                      className="btn btn-secondary"
                      type="button"
                      onClick={() => downloadImportTemplate("json")}
                    >
                      Descargar plantilla JSON
                    </button>
                  </div>
                </div>
              )}

              {importStep === 2 && (
                <div className="wizard-panel">
                  <p className="wizard-instruction">Mapea columnas del archivo al sistema</p>
                  <div className="import-map-grid">
                    {Object.keys(importRawData[0] || {}).map((col) => (
                      <div key={col} className="import-map-row">
                        <span className="import-map-col">{col}</span>
                        <select
                          className="form-select"
                          value={importColumnMap[col] || ""}
                          onChange={(event) =>
                            setImportColumnMap((prev) => ({
                              ...prev,
                              [col]: event.target.value,
                            }))
                          }
                        >
                          <option value="">Ignorar</option>
                          {Object.entries(IMPORT_FIELDS).map(([field, info]) => (
                            <option key={field} value={field}>
                              {info.label}
                            </option>
                          ))}
                        </select>
                      </div>
                    ))}
                  </div>
                  <div className="wizard-actions">
                    <button className="btn btn-secondary" type="button" onClick={() => setImportStep(1)}>
                      ← Atrás
                    </button>
                    <button
                      className="btn btn-primary"
                      type="button"
                      onClick={() => {
                        generatePreview();
                        setImportStep(3);
                      }}
                    >
                      Continuar →
                    </button>
                  </div>
                </div>
              )}

              {importStep === 3 && (
                <div className="wizard-panel">
                  <p className="wizard-instruction">Resumen de importación</p>
                  {importErrors.length > 0 && (
                    <div className="import-errors">
                      {importErrors.map((err) => (
                        <p key={err}>⚠ {err}</p>
                      ))}
                    </div>
                  )}
                  <div className="import-summary">
                    <div className="import-summary-item">
                      <span className="import-summary-label">Activos</span>
                      <span className="import-summary-value">{importPreview.assets.length}</span>
                    </div>
                    <div className="import-summary-item">
                      <span className="import-summary-label">Hallazgos</span>
                      <span className="import-summary-value">{importPreview.findings.length}</span>
                    </div>
                  </div>
                  <div className="import-preview">
                    <h4>Vista previa</h4>
                    <div className="import-preview-table">
                      <table>
                        <thead>
                          <tr>
                            <th>Titulo</th>
                            <th>Severidad</th>
                            <th>Activo</th>
                          </tr>
                        </thead>
                        <tbody>
                          {importPreview.findings.slice(0, 15).map((finding, idx) => (
                            <tr key={idx}>
                              <td>{finding.title}</td>
                              <td>{finding.severity}</td>
                              <td>{finding._assetName}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                      {importPreview.findings.length > 15 && (
                        <p className="import-preview-more">
                          ... y {importPreview.findings.length - 15} hallazgos mas
                        </p>
                      )}
                    </div>
                  </div>
                  <div className="wizard-actions">
                    <button className="btn btn-secondary" type="button" onClick={() => setImportStep(2)}>
                      ← Atrás
                    </button>
                    <button
                      className="btn btn-primary"
                      type="button"
                      disabled={importLoading || importPreview.findings.length === 0}
                      onClick={executeImport}
                    >
                      {importLoading ? "⏳ Importando..." : `📥 Importar ${importPreview.findings.length} hallazgos`}
                    </button>
                  </div>
                </div>
              )}

              {importStep === 4 && (
                <div className="wizard-panel">
                  <p className="wizard-instruction">Resultado</p>
                  <div className="import-result">
                    <div className="import-result-stat">
                      <span className="import-result-stat-label">Activos creados</span>
                      <span className="import-result-stat-value">{importResult?.assetsCreated || 0}</span>
                    </div>
                    <div className="import-result-stat">
                      <span className="import-result-stat-label">Activos reutilizados</span>
                      <span className="import-result-stat-value">{importResult?.assetsReused || 0}</span>
                    </div>
                    <div className="import-result-stat">
                      <span className="import-result-stat-label">Hallazgos creados</span>
                      <span className="import-result-stat-value">{importResult?.findingsCreated || 0}</span>
                    </div>
                  </div>
                  {importResult?.errors?.length > 0 && (
                    <div className="import-errors">
                      {importResult.errors.map((err) => (
                        <p key={err}>⚠ {err}</p>
                      ))}
                    </div>
                  )}
                  <div className="wizard-actions">
                    <button className="btn btn-primary" type="button" onClick={resetImportWizard}>
                      Finalizar
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {showCatalogModal && (
        <div className="wizard-overlay" onClick={resetCatalogModal}>
          <div className="wizard-modal wizard-modal--wide" onClick={(event) => event.stopPropagation()}>
            <div className="wizard-header">
              <h3>Catálogo de Vulnerabilidades</h3>
              <button className="btn btn-ghost" type="button" onClick={resetCatalogModal}>✕</button>
            </div>

            <div className="catalog-tabs">
              <button
                className={`catalog-tab ${catalogTab === "explore" ? "active" : ""}`}
                onClick={() => setCatalogTab("explore")}
              >
                Explorar
              </button>
              <button
                className={`catalog-tab ${catalogTab === "import" ? "active" : ""}`}
                onClick={() => setCatalogTab("import")}
              >
                Importar
              </button>
              <button
                className={`catalog-tab ${catalogTab === "template" ? "active" : ""}`}
                onClick={() => setCatalogTab("template")}
              >
                Plantillas
              </button>
            </div>

            <div className="catalog-body">
              {catalogTab === "explore" && (
                <div className="catalog-panel">
                  <div className="catalog-search">
                    <input
                      className="form-input"
                      type="text"
                      placeholder="Buscar CVE, CWE, nombre..."
                      value={catalogQuery}
                      onChange={(event) => setCatalogQuery(event.target.value)}
                    />
                  </div>
                  {catalogLoading && <p>Buscando...</p>}
                  {!catalogLoading && catalogResults.length === 0 && (
                    <p className="catalog-empty">Sin resultados</p>
                  )}
                  {!catalogLoading && catalogResults.length > 0 && (
                    <div className="catalog-results">
                      {catalogResults.map((entry) => (
                        <button
                          key={entry.id}
                          type="button"
                          className="catalog-result-card"
                          onClick={() => handleCatalogSelect(entry.id)}
                        >
                          <div>
                            <strong>{entry.cve_id || entry.name}</strong>
                            <p>{entry.description?.slice(0, 120)}...</p>
                          </div>
                          <span className={`badge badge-${entry.severity || "info"}`}>
                            {entry.severity || "info"}
                          </span>
                        </button>
                      ))}
                    </div>
                  )}
                  {catalogDetail && (
                    <div className="catalog-detail">
                      <h4>{catalogDetail.cve_id || catalogDetail.name}</h4>
                      <p>{catalogDetail.description}</p>
                      {catalogDetail.recommendation && (
                        <>
                          <h5>Recomendación</h5>
                          <p>{catalogDetail.recommendation}</p>
                        </>
                      )}
                      {catalogDetail.references && (
                        <>
                          <h5>Referencias</h5>
                          <pre>{catalogDetail.references}</pre>
                        </>
                      )}
                    </div>
                  )}
                </div>
              )}

              {catalogTab === "import" && (
                <div className="catalog-panel">
                  <p>Importa tu catalogo en CSV o JSONL</p>
                  <input
                    className="form-input"
                    type="file"
                    accept=".jsonl,.csv,.json"
                    onChange={(event) => setCatalogImportFile(event.target.files?.[0] || null)}
                  />
                  {catalogImportError && <p className="catalog-error">{catalogImportError}</p>}
                  {catalogImportResult && (
                    <div className="catalog-result">
                      <p>Importados: {catalogImportResult.imported}</p>
                      <p>Actualizados: {catalogImportResult.updated}</p>
                      <p>Omitidos: {catalogImportResult.skipped}</p>
                    </div>
                  )}
                  <button
                    className="btn btn-primary"
                    type="button"
                    disabled={!catalogImportFile || catalogImportLoading}
                    onClick={handleCatalogImport}
                  >
                    {catalogImportLoading ? "⏳ Importando..." : "Importar"}
                  </button>
                </div>
              )}

              {catalogTab === "template" && (
                <div className="catalog-panel">
                  <div className="catalog-stats">
                    <div className="catalog-stat">
                      <span className="catalog-stat-label">Total</span>
                      <span className="catalog-stat-value">{catalogStats?.total || 0}</span>
                    </div>
                    <div className="catalog-stat">
                      <span className="catalog-stat-label">Plantillas</span>
                      <span className="catalog-stat-value">{catalogStats?.manual_templates || 0}</span>
                    </div>
                    <div className="catalog-stat">
                      <span className="catalog-stat-label">CVE</span>
                      <span className="catalog-stat-value">{catalogStats?.cves || 0}</span>
                    </div>
                  </div>
                  <form className="catalog-template-form" onSubmit={handleCatalogTemplateSubmit}>
                    <div className="form-group">
                      <label className="form-label">Nombre</label>
                      <input
                        className="form-input"
                        value={catalogTemplateForm.name}
                        onChange={(event) => setCatalogTemplateForm((prev) => ({ ...prev, name: event.target.value }))}
                        required
                      />
                    </div>
                    <div className="form-group">
                      <label className="form-label">CVE</label>
                      <input
                        className="form-input"
                        value={catalogTemplateForm.cve_id}
                        onChange={(event) => setCatalogTemplateForm((prev) => ({ ...prev, cve_id: event.target.value }))}
                      />
                    </div>
                    <div className="form-group">
                      <label className="form-label">Severidad</label>
                      <select
                        className="form-select"
                        value={catalogTemplateForm.severity}
                        onChange={(event) => setCatalogTemplateForm((prev) => ({ ...prev, severity: event.target.value }))}
                      >
                        <option value="critical">Crítica</option>
                        <option value="high">Alta</option>
                        <option value="medium">Media</option>
                        <option value="low">Baja</option>
                        <option value="info">Info</option>
                      </select>
                    </div>
                    <div className="form-group">
                      <label className="form-label">CVSS Score</label>
                      <input
                        className="form-input"
                        value={catalogTemplateForm.base_score}
                        onChange={(event) => setCatalogTemplateForm((prev) => ({ ...prev, base_score: event.target.value }))}
                      />
                    </div>
                    <div className="form-group">
                      <label className="form-label">CWE ID</label>
                      <input
                        className="form-input"
                        value={catalogTemplateForm.cwe_id}
                        onChange={(event) => setCatalogTemplateForm((prev) => ({ ...prev, cwe_id: event.target.value }))}
                      />
                    </div>
                    <div className="form-group">
                      <label className="form-label">CWE Nombre</label>
                      <input
                        className="form-input"
                        value={catalogTemplateForm.cwe_name}
                        onChange={(event) => setCatalogTemplateForm((prev) => ({ ...prev, cwe_name: event.target.value }))}
                      />
                    </div>
                    <div className="form-group full">
                      <label className="form-label">Descripcion</label>
                      <textarea
                        className="form-input"
                        value={catalogTemplateForm.description}
                        onChange={(event) => setCatalogTemplateForm((prev) => ({ ...prev, description: event.target.value }))}
                      />
                    </div>
                    <div className="form-group full">
                      <label className="form-label">Recomendacion</label>
                      <textarea
                        className="form-input"
                        value={catalogTemplateForm.recommendation}
                        onChange={(event) => setCatalogTemplateForm((prev) => ({ ...prev, recommendation: event.target.value }))}
                      />
                    </div>
                    <div className="form-group full">
                      <label className="form-label">Referencias</label>
                      <textarea
                        className="form-input"
                        value={catalogTemplateForm.references}
                        onChange={(event) => setCatalogTemplateForm((prev) => ({ ...prev, references: event.target.value }))}
                      />
                    </div>
                    <div className="modal-form-actions full">
                      <button className="btn btn-secondary" type="button" onClick={resetCatalogModal}>
                        Cancelar
                      </button>
                      <button className="btn btn-primary" type="submit">Guardar plantilla</button>
                    </div>
                  </form>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
