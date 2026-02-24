import { getCSSVar } from "./formatters";

export function buildChartTheme() {
  return {
    tooltip: {
      contentStyle: {
        background: getCSSVar("--bg-tooltip"),
        border: `1px solid ${getCSSVar("--border-secondary")}`,
        borderRadius: "8px",
        color: getCSSVar("--text-primary"),
        fontSize: "13px",
        boxShadow: getCSSVar("--shadow-md"),
      },
    },
    grid: {
      strokeDasharray: "3 3",
      stroke: getCSSVar("--border-card"),
    },
    axis: {
      tick: { fill: getCSSVar("--text-secondary"), fontSize: 12 },
      axisLine: { stroke: getCSSVar("--border-primary") },
    },
    colors: {
      severity: {
        critical: getCSSVar("--severity-critical"),
        high: getCSSVar("--severity-high"),
        medium: getCSSVar("--severity-medium"),
        low: getCSSVar("--severity-low"),
        info: getCSSVar("--severity-info"),
      },
      status: {
        open: getCSSVar("--severity-high"),
        triaged: getCSSVar("--severity-medium"),
        fixed: getCSSVar("--success"),
        accepted: getCSSVar("--severity-info"),
        false_positive: getCSSVar("--text-muted"),
      },
      accent: getCSSVar("--accent-primary"),
      accentHover: getCSSVar("--accent-primary-hover"),
    },
  };
}
