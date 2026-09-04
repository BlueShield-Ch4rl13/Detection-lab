# Listas de inteligencia

<!-- Generado por tools/sync_cti.py desde ScriptNewsCTI - no editar a mano -->

**Origen:** [ScriptNewsCTI](https://github.com/BlueShield-Ch4rl13/ScriptNewsCTI)  
**Feed generado:** 2026-09-04 04:06 UTC  
**Listas generadas:** 2026-09-04T10:17:04Z  
**Filtro aplicado:** nivel minimo `media`, maximo `30` dias de antiguedad

## Que hay en cada lista

| Indicador | Entradas | Uso previsto |
|---|---:|---|
| IP | 102 | Caza programada, no alerta directa |
| Dominio | 225 | Caza programada, no alerta directa |
| URL | 209 | Caza programada, no alerta directa |
| Hash | 112 | **Alerta directa**: un hash coincide o no |
| CVE en KEV | 21 | Priorizacion de parcheo y caza de explotacion |

## Por que las IP y los dominios no alertan

Un indicador de reputacion coincide muchas veces por motivos aburridos:
sinkholes de investigadores, CDN compartidas, dominios reciclados, rangos
de proveedores de nube. Desplegarlos como alerta directa llena la cola de
eventos que se cierran sin accion, y eso entrena al turno a cerrar sin
mirar. Se despliegan como **consultas de caza programadas con umbral**, en
`deploy/<siem>/consultas/`.

El hash es distinto: no comparte infraestructura con nada legitimo, asi que
va como alerta y ademas sin caducidad.

## Que se descarto del feed (171 de 853)

| Motivo | Descartados |
|---|---:|
| nivel bajo | 86 |
| tipo no usado | 85 |

## Familias mas presentes

| Amenaza | Indicadores |
|---|---:|
| malware_download | 100 |
| ClearFake | 96 |
| IClickFix | 74 |
| Unknown malware | 61 |
| Node.js: Old Technique Makes a Comeback | 53 |
| ScreenConnect RMM Abuse  Cloudflare Tunnels  and Trusted Software Lures Threat Intelligence  Threat Research  Threat Security | 46 |
| Vidar | 39 |
| VShell | 15 |
| Aisuru | 14 |
| Mozi | 14 |
| Remcos | 13 |
| Unknown Loader | 12 |

## Ficheros generados

| Fichero | Entradas |
|---|---:|
| `wazuh/cti_ip` | 102 |
| `wazuh/cti_dominio` | 225 |
| `wazuh/cti_url` | 209 |
| `wazuh/cti_hash` | 112 |
| `wazuh/cti_cve_kev` | 21 |
| `splunk/cti_ip.csv` | 102 |
| `splunk/cti_dominio.csv` | 225 |
| `splunk/cti_url.csv` | 209 |
| `splunk/cti_hash.csv` | 112 |
| `splunk/cti_cve_kev.csv` | 21 |
| `sentinel/CTI_Ip.csv` | 102 |
| `sentinel/CTI_Dominio.csv` | 225 |
| `sentinel/CTI_Url.csv` | 209 |
| `sentinel/CTI_Hash.csv` | 112 |
| `elastic/cti_ip.ndjson` | 102 |
| `elastic/cti_dominio.ndjson` | 225 |
| `elastic/cti_url.ndjson` | 209 |
| `elastic/cti_hash.ndjson` | 112 |

## Como se instala cada una

Ver `deploy/<siem>/INSTALAR.md`. En resumen:

```bash
# Wazuh: copiar, declarar en ossec.conf y compilar
sudo cp intel/listas/wazuh/*.cdb /var/ossec/etc/lists/
sudo /var/ossec/bin/ossec-makelists

# Splunk: como lookups de la app
cp intel/listas/splunk/*.csv $SPLUNK_HOME/etc/apps/TA-detection-lab/lookups/

# Sentinel: Watchlists > New > importar el CSV, alias sin el prefijo CTI_
# Elastic: bulk al indice de indicadores
curl -XPOST 'localhost:9200/logs-ti_newscti-default/_bulk' \
     -H 'Content-Type: application/x-ndjson' \
     --data-binary @intel/listas/elastic/cti_ip.ndjson
```
