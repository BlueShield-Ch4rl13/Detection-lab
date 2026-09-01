# Listas de inteligencia

<!-- Generado por tools/sync_cti.py desde ScriptNewsCTI - no editar a mano -->

**Origen:** [ScriptNewsCTI](https://github.com/BlueShield-Ch4rl13/ScriptNewsCTI)  
**Feed generado:** 2026-09-01 11:37 UTC  
**Listas generadas:** 2026-09-01T14:43:00Z  
**Filtro aplicado:** nivel minimo `media`, maximo `30` dias de antiguedad

## Que hay en cada lista

| Indicador | Entradas | Uso previsto |
|---|---:|---|
| IP | 154 | Caza programada, no alerta directa |
| Dominio | 199 | Caza programada, no alerta directa |
| URL | 135 | Caza programada, no alerta directa |
| Hash | 69 | **Alerta directa**: un hash coincide o no |
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

## Que se descarto del feed (314 de 916)

| Motivo | Descartados |
|---|---:|
| tipo no usado | 189 |
| nivel bajo | 125 |

## Familias mas presentes

| Amenaza | Indicadores |
|---|---:|
| malware_download | 100 |
| php.shin_webshell | 98 |
| ClearFake | 76 |
| Anatomy of BraZetsu: How Cybercriminals Fuel the Underground Ecosystem | 26 |
| Aisuru | 25 |
| Vidar | 23 |
| Financially Motivated Threat Actor Targets Brazil | 22 |
| IClickFix | 17 |
| PureRAT | 16 |
| VShell | 15 |
| Unknown malware | 13 |
| AsyncRAT | 13 |

## Ficheros generados

| Fichero | Entradas |
|---|---:|
| `wazuh/cti_ip` | 154 |
| `wazuh/cti_dominio` | 199 |
| `wazuh/cti_url` | 135 |
| `wazuh/cti_hash` | 69 |
| `wazuh/cti_cve_kev` | 21 |
| `splunk/cti_ip.csv` | 154 |
| `splunk/cti_dominio.csv` | 199 |
| `splunk/cti_url.csv` | 135 |
| `splunk/cti_hash.csv` | 69 |
| `splunk/cti_cve_kev.csv` | 21 |
| `sentinel/CTI_Ip.csv` | 154 |
| `sentinel/CTI_Dominio.csv` | 199 |
| `sentinel/CTI_Url.csv` | 135 |
| `sentinel/CTI_Hash.csv` | 69 |
| `elastic/cti_ip.ndjson` | 154 |
| `elastic/cti_dominio.ndjson` | 199 |
| `elastic/cti_url.ndjson` | 135 |
| `elastic/cti_hash.ndjson` | 69 |

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
