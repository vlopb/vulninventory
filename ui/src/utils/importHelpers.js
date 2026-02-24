import { AUTO_MAP_ALIASES } from "./constants";

export function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

export async function downloadImportTemplate(format) {
  const headers = [
    "title",
    "severity",
    "status",
    "description",
    "cwe",
    "owasp_category",
    "cvss_score",
    "occurrences",
    "tags",
    "asset_name",
    "asset_uri",
    "asset_type",
    "owner_email",
    "pentester_email",
  ];
  const sampleRow = {
    title: "SQL Injection",
    severity: "critical",
    status: "open",
    description: "Parametro id vulnerable a inyeccion SQL.",
    cwe: "CWE-89",
    owasp_category: "A03:2021",
    cvss_score: "9.1",
    occurrences: "1",
    tags: "owasp,sqli",
    asset_name: "api-prod",
    asset_uri: "https://api.example.com",
    asset_type: "api",
    owner_email: "owner@example.com",
    pentester_email: "pentester@example.com",
  };
  const emptyRow = Object.fromEntries(headers.map((header) => [header, ""]));

  if (format === "json") {
    const blob = new Blob([JSON.stringify([sampleRow, emptyRow], null, 2)], {
      type: "application/json",
    });
    downloadBlob(blob, "vulninventory_import_template.json");
    return;
  }

  const csvContent = [
    headers.join(","),
    headers.map((header) => `"${String(sampleRow[header] || "").replace(/"/g, '""')}"`).join(","),
    headers.map(() => "\"\"").join(","),
  ].join("\n");
  const blob = new Blob(["\ufeff" + csvContent], { type: "text/csv;charset=utf-8;" });
  downloadBlob(blob, "vulninventory_import_template.csv");
}

export function exportCSV(data, filename) {
  if (!data.length) {
    return;
  }
  const headers = Object.keys(data[0]);
  const csvContent = [
    headers.join(","),
    ...data.map((row) =>
      headers
        .map((header) => {
          const value = String(row[header] ?? "").replace(/"/g, '""');
          return `"${value}"`;
        })
        .join(",")
    ),
  ].join("\n");
  const blob = new Blob(["\ufeff" + csvContent], { type: "text/csv;charset=utf-8;" });
  downloadBlob(blob, `${filename}.csv`);
}

export function exportJSON(data, filename) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  downloadBlob(blob, `${filename}.json`);
}

export async function exportXLSX() {
  // XLSX export removed for security reasons.
  return;
}

export function detectFormat(file) {
  const name = file.name.toLowerCase();
  if (name.endsWith(".csv")) return "csv";
  if (name.endsWith(".json")) return "json";
  if (name.endsWith(".nessus") || name.endsWith(".xml")) return "xml";
  if (name.endsWith(".sarif")) return "sarif";
  return "csv";
}

export function autoMapColumns(fileColumns) {
  const map = {};
  fileColumns.forEach((col) => {
    const normalized = col.toLowerCase().trim().replace(/[\s-]/g, "_");
    for (const [field, aliases] of Object.entries(AUTO_MAP_ALIASES)) {
      if (aliases.includes(normalized)) {
        map[col] = field;
        break;
      }
    }
  });
  return map;
}

export function mapSarifLevel(level) {
  const map = { error: "high", warning: "medium", note: "low", none: "info" };
  return map[level] || "medium";
}

export function parseNessusXML(doc) {
  const rows = [];
  doc.querySelectorAll("ReportHost").forEach((host) => {
    const hostName = host.getAttribute("name");
    host.querySelectorAll("ReportItem").forEach((item) => {
      const severity = Number(item.getAttribute("severity") || "0");
      const sevMap = { 0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical" };
      rows.push({
        title: item.getAttribute("pluginName") || "Sin titulo",
        severity: sevMap[severity] || "info",
        description: item.querySelector("description")?.textContent || "",
        cwe: item.querySelector("cwe")?.textContent || "",
        cvss_score:
          item.querySelector("cvss3_base_score")?.textContent ||
          item.querySelector("cvss_base_score")?.textContent ||
          "",
        asset_name: hostName,
        asset_uri: hostName,
        asset_type: "host",
        port: item.getAttribute("port") || "",
        protocol: item.getAttribute("protocol") || "",
      });
    });
  });
  return rows;
}

export function parseBurpXML(doc) {
  const rows = [];
  doc.querySelectorAll("issue").forEach((issue) => {
    const severityText = issue.querySelector("severity")?.textContent?.toLowerCase() || "";
    const sevMap = {
      high: "high",
      medium: "medium",
      low: "low",
      information: "info",
      critical: "critical",
    };
    rows.push({
      title: issue.querySelector("name")?.textContent || "Sin titulo",
      severity: sevMap[severityText] || "medium",
      description: issue.querySelector("issueDetail")?.textContent || "",
      asset_name: issue.querySelector("host")?.textContent || "",
      asset_uri: issue.querySelector("host")?.getAttribute("ip") || issue.querySelector("path")?.textContent || "",
      asset_type: "web_app",
    });
  });
  return rows;
}

export function parseCsvLine(line, delimiter) {
  const values = [];
  let current = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i += 1) {
    const char = line[i];
    if (char === "\"") {
      const nextChar = line[i + 1];
      if (inQuotes && nextChar === "\"") {
        current += "\"";
        i += 1;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (char === delimiter && !inQuotes) {
      values.push(current);
      current = "";
    } else {
      current += char;
    }
  }
  values.push(current);
  return values.map((value) => value.trim());
}

export function detectCsvDelimiter(headerLine) {
  const commaCount = (headerLine.match(/,/g) || []).length;
  const semicolonCount = (headerLine.match(/;/g) || []).length;
  return semicolonCount > commaCount ? ";" : ",";
}

export async function parseImportFile(
  file,
  { setImportFormat, setImportErrors, setImportRawData, setImportColumnMap }
) {
  const format = detectFormat(file);
  setImportFormat(format);
  setImportErrors([]);
  try {
    let rows = [];
    if (format === "csv") {
      const text = await file.text();
      const rawLines = text.split(/\r?\n/).filter((line) => line.trim());
      if (rawLines.length === 0) {
        setImportRawData([]);
        return [];
      }
      const headerLine = rawLines[0].replace(/^\uFEFF/, "");
      const delimiter = detectCsvDelimiter(headerLine);
      const headers = parseCsvLine(headerLine, delimiter).map((header) =>
        header.replace(/^"|"$/g, "").trim()
      );
      rows = rawLines.slice(1).map((line) => {
        const values = parseCsvLine(line, delimiter);
        const obj = {};
        headers.forEach((header, index) => {
          const raw = values[index] ?? "";
          obj[header] = raw.replace(/^"|"$/g, "").trim();
        });
        return obj;
      });
    } else if (format === "json") {
      const text = await file.text();
      const parsed = JSON.parse(text);
      rows = Array.isArray(parsed)
        ? parsed
        : parsed.findings || parsed.vulnerabilities || parsed.data || [parsed];
      rows = rows.map((row) => {
        const flat = {};
        Object.entries(row).forEach(([key, val]) => {
          if (val && typeof val === "object" && !Array.isArray(val)) {
            flat[key] = val.default || val.en || Object.values(val)[0] || JSON.stringify(val);
          } else if (Array.isArray(val)) {
            flat[key] = val.join(", ");
          } else {
            flat[key] = val;
          }
        });
        return flat;
      });
    } else if (format === "sarif") {
      const text = await file.text();
      const sarif = JSON.parse(text);
      rows = [];
      (sarif.runs || []).forEach((run) => {
        const tool = run.tool?.driver?.name || "unknown";
        (run.results || []).forEach((result) => {
          const rule = (run.tool?.driver?.rules || []).find((item) => item.id === result.ruleId);
          rows.push({
            title: result.message?.text || result.ruleId || "Sin titulo",
            severity: mapSarifLevel(result.level),
            description: rule?.fullDescription?.text || rule?.shortDescription?.text || "",
            cwe: rule?.properties?.tags?.find((tag) => tag.startsWith("CWE-")) || "",
            asset_name: result.locations?.[0]?.physicalLocation?.artifactLocation?.uri || tool,
            asset_uri: result.locations?.[0]?.physicalLocation?.artifactLocation?.uri || "",
            asset_type: "repo",
            tool,
          });
        });
      });
    } else if (format === "xml") {
      const text = await file.text();
      const parser = new DOMParser();
      const doc = parser.parseFromString(text, "text/xml");
      if (doc.querySelector("NessusClientData_v2") || doc.querySelector("Report")) {
        rows = parseNessusXML(doc);
        setImportFormat("nessus");
      } else if (doc.querySelector("issues") && doc.querySelector("issue")) {
        rows = parseBurpXML(doc);
        setImportFormat("burp");
      }
    }

    setImportRawData(rows);
    if (rows.length > 0) {
      const columns = Object.keys(rows[0]);
      const autoMap = autoMapColumns(columns);
      const missingRequired = ["title", "severity"].filter(
        (field) => !Object.values(autoMap).includes(field)
      );
      if (missingRequired.length > 0) {
        setImportErrors([
          `Faltan encabezados requeridos o no reconocidos: ${missingRequired.join(", ")}`,
          "Puedes continuar con mapeo manual en el paso 2.",
        ]);
      }
      setImportColumnMap(autoMap);
    }
    return rows;
  } catch (err) {
    setImportErrors([`Error al parsear archivo: ${err.message}`]);
    return [];
  }
}
