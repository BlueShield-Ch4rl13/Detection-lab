# Elastic — instalacion

## Que hay en esta carpeta

| Carpeta | Contenido | Se regenera |
|---|---|---|
| `reglas/*-lucene.txt` | 124 consultas Lucene por dominio | Sí, con `tools/build.py` |
| `reglas/*-esql.txt` | 127 consultas ES\|QL por dominio | Sí, con `tools/build.py` |
| `indicadores/` | Indicadores de News CTI en NDJSON con esquema ECS | Sí, con `tools/sync_cti.py` |
| `consultas/` | Caza e inteligencia | No, escritas a mano |

## Lucene y ES|QL no son lo mismo

| | Para qué sirve |
|---|---|
| **Lucene** | Caza en el Discover, y también en el indexador de Wazuh, que es OpenSearch |
| **ES\|QL** | Reglas de detección de Elastic Security y consultas con agregación |

Si tu destino es el indexador de Wazuh, usa **solo** los `-lucene.txt`: OpenSearch
no tiene ES|QL.

## 1. Reglas de detección

*Security → Rules → Detection rules → Create new rule → Custom query*

Pega una consulta de `reglas/<dominio>-esql.txt` por regla. El comentario de
encima lleva el título y la severidad.

Para cargar en bloque hay que envolverlas en el NDJSON que espera la API:

```bash
curl -k -u elastic:$PASS -XPOST "https://localhost:5601/api/detection_engine/rules/_import" \
  -H 'kbn-xsrf: true' -H 'Content-Type: multipart/form-data' \
  --form "file=@reglas.ndjson"
```

## 2. Indicadores de inteligencia

```bash
# Crear el índice con el mapeo de amenazas de ECS
curl -XPUT 'localhost:9200/logs-ti_newscti-default' -H 'Content-Type: application/json' -d '{
  "mappings": { "properties": {
    "@timestamp": { "type": "date" },
    "threat.indicator.type": { "type": "keyword" },
    "threat.indicator.ip": { "type": "ip" },
    "threat.indicator.url.domain": { "type": "keyword" },
    "threat.indicator.url.original": { "type": "keyword" },
    "threat.indicator.file.hash.sha256": { "type": "keyword" },
    "threat.indicator.file.hash.md5": { "type": "keyword" },
    "threat.indicator.description": { "type": "keyword" },
    "threat.indicator.confidence": { "type": "keyword" },
    "threat.indicator.provider": { "type": "keyword" }
  }}}'

# Cargar. El NDJSON de sync_cti.py son documentos sueltos, así que hay que
# intercalar la línea de acción que espera el _bulk:
for f in deploy/elastic/indicadores/*.ndjson; do
  awk '{print "{\"index\":{}}"; print}' "$f" \
  | curl -s -XPOST 'localhost:9200/logs-ti_newscti-default/_bulk' \
         -H 'Content-Type: application/x-ndjson' --data-binary @- > /dev/null
done
```

## 3. Regla de tipo Indicator Match

Es la que convierte los indicadores en alertas. Solo para hashes:

*Security → Rules → Create new rule → **Indicator Match***

| Campo | Valor |
|---|---|
| Index patterns | `logs-endpoint.events.*`, `winlogbeat-*` |
| Custom query | `*:*` |
| Indicator index patterns | `logs-ti_newscti-default` |
| Indicator index query | `threat.indicator.type: "file"` |
| Indicator mapping | `process.hash.sha256` ↔ `threat.indicator.file.hash.sha256` |
| | `file.hash.sha256` ↔ `threat.indicator.file.hash.sha256` |
| | `process.hash.md5` ↔ `threat.indicator.file.hash.md5` |

**Solo el hash.** Para IP y dominio usa las consultas de caza con umbral de
`consultas/cti_y_caza.txt`: una coincidencia suelta de reputación casi siempre
es una CDN compartida o un dominio reciclado, y desplegarla como alerta llena la
cola de eventos que se cierran sin acción.

## 4. Refresco

```cron
0 6 * * * cd /opt/detection-lab && python3 tools/sync_cti.py --max-dias 30 && ./scripts/cargar_indicadores.sh
```

Los indicadores viejos hay que purgarlos, o el índice crece sin fin y las
coincidencias empiezan a ser de infraestructura ya reasignada:

```bash
curl -XPOST 'localhost:9200/logs-ti_newscti-default/_delete_by_query' \
  -H 'Content-Type: application/json' \
  -d '{"query":{"range":{"@timestamp":{"lt":"now-30d"}}}}'
```

## 5. Comprobar que funciona

```bash
curl -s 'localhost:9200/logs-ti_newscti-default/_count' | jq .count
curl -s 'localhost:9200/logs-ti_newscti-default/_search?size=0' -H 'Content-Type: application/json' \
  -d '{"aggs":{"tipos":{"terms":{"field":"threat.indicator.type"}}}}' | jq '.aggregations'
```
