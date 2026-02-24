export function summarizeBySeverity(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) {
    const key = finding.severity || "info";
    if (!counts[key]) {
      counts[key] = 0;
    }
    counts[key] += 1;
  }
  return counts;
}

export function groupFindings(findings) {
  const grouped = new Map();
  for (const finding of findings) {
    const key = [
      finding.rule_id || "",
      finding.title || "",
      finding.asset_id || "",
      finding.severity || "",
      finding.owasp || "",
      finding.cwe || "",
    ].join("|");
    if (grouped.has(key)) {
      const existing = grouped.get(key);
      existing.occurrences += 1;
      existing.ids.push(finding.id);
      if (finding.scan_id && !existing.scan_ids.includes(finding.scan_id)) {
        existing.scan_ids.push(finding.scan_id);
      }
      continue;
    }
    grouped.set(key, {
      ...finding,
      occurrences: 1,
      ids: [finding.id],
      scan_ids: finding.scan_id ? [finding.scan_id] : [],
    });
  }
  return Array.from(grouped.values());
}
