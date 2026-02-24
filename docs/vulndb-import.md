# Importar catalogo de vulnerabilidades (VulnDB)

El catalogo se carga desde una fuente externa mediante el endpoint `POST /vulndb/import`.
Este endpoint espera **JSONL** (un JSON por linea). Si tienes CSV, conviertelo antes de subirlo.

## Formato JSONL esperado
Cada linea debe ser un objeto JSON con estas claves (las que no uses se pueden omitir):

- `short_id` o `name` (obligatorio): identificador (ej. CVE-2024-1234)
- `name`: nombre legible
- `base_score`: numero (float)
- `details`: texto o lista de textos
- `recommendations`: texto o lista de textos
- `ext_references`: texto o lista de textos
- `cpe`: string o lista/dict (se serializa)
- `hidden`: `true` para omitir la entrada

El backend calcula `severity` desde `base_score` y normaliza `details`, `recommendations` y `ext_references`.

Ejemplo minimo (JSONL):

```json
{"short_id":"CVE-2024-1234","name":"Example RCE","base_score":9.8,"details":"Remote code execution in example library.","recommendations":"Actualizar a la version 1.2.3","ext_references":["https://example.com/advisory"]}
{"short_id":"CVE-2023-9999","name":"Example XSS","base_score":6.1,"details":"Reflected XSS in search endpoint.","recommendations":"Escapar salida en HTML","ext_references":["https://example.com/xss"]}
```

## CSV
Si tu fuente esta en CSV, conviertelo a JSONL.
Columnas recomendadas:

- `short_id` o `name`
- `base_score`
- `details`
- `recommendations`
- `ext_references`
- `cpe`

Puedes usar el script de ejemplo en `scripts/import_vulndb.sh` que acepta **JSONL o CSV**.

## Script de importacion

```bash
API_BASE_URL=http://localhost:8001 \
API_KEY=TU_API_KEY \
./scripts/import_vulndb.sh docs/examples/vulndb_sample.jsonl
```

Si usas CSV:

```bash
API_BASE_URL=http://localhost:8001 \
API_KEY=TU_API_KEY \
./scripts/import_vulndb.sh docs/examples/vulndb_sample.csv
```

Nota: el endpoint usa autenticacion. Para automatizar, crea un API key y pasalo en `API_KEY`.
