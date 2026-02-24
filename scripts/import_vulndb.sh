#!/bin/sh
set -eu

INPUT_FILE=${1:-}
if [ -z "$INPUT_FILE" ]; then
  echo "Uso: $0 <archivo.jsonl|archivo.csv>" >&2
  exit 1
fi

if [ ! -f "$INPUT_FILE" ]; then
  echo "Archivo no encontrado: $INPUT_FILE" >&2
  exit 1
fi

API_BASE_URL=${API_BASE_URL:-http://localhost:8001}
if [ -z "${API_KEY:-}" ]; then
  echo "API_KEY no definido. Exporta API_KEY para autenticar." >&2
  exit 1
fi

TMP_FILE=""
case "$INPUT_FILE" in
  *.jsonl)
    TMP_FILE="$INPUT_FILE"
    ;;
  *.csv)
    TMP_FILE=$(mktemp)
    python3 - <<'PY'
import csv
import json
import os
import sys

input_file = sys.argv[1]
output_file = sys.argv[2]

with open(input_file, newline="", encoding="utf-8") as f, open(output_file, "w", encoding="utf-8") as out:
    reader = csv.DictReader(f)
    for row in reader:
        payload = {
            "short_id": row.get("short_id") or row.get("cve_id") or "",
            "name": row.get("name") or row.get("short_id") or row.get("cve_id") or "",
            "base_score": float(row["base_score"]) if row.get("base_score") else None,
            "details": row.get("details") or None,
            "recommendations": row.get("recommendations") or None,
            "ext_references": row.get("ext_references") or None,
            "cpe": row.get("cpe") or None,
        }
        out.write(json.dumps(payload, ensure_ascii=False) + "\n")
PY
    "$INPUT_FILE" "$TMP_FILE"
    ;;
  *)
    echo "Formato no soportado. Usa .jsonl o .csv" >&2
    exit 1
    ;;
esac

curl -sS -X POST \
  -H "X-API-Key: ${API_KEY}" \
  -F "file=@${TMP_FILE}" \
  "${API_BASE_URL}/vulndb/import"

echo ""

if [ "$TMP_FILE" != "$INPUT_FILE" ]; then
  rm -f "$TMP_FILE"
fi
