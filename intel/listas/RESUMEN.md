# Listas de inteligencia

<!-- Generado por tools/sync_cti.py desde ScriptNewsCTI - no editar a mano -->

**Origen:** [ScriptNewsCTI](https://github.com/BlueShield-Ch4rl13/ScriptNewsCTI)  
**Feed generado:** 2026-09-02 04:06 UTC  
**Listas generadas:** 2026-09-02T10:19:17Z  
**Filtro aplicado:** nivel minimo `media`, maximo `30` dias de antiguedad

## Que hay en cada lista

| Indicador | Entradas | Uso previsto |
|---|---:|---|
| IP | 206 | Caza programada, no alerta directa |
| Dominio | 184 | Caza programada, no alerta directa |
| URL | 165 | Caza programada, no alerta directa |
| Hash | 85 | **Alerta directa**: un hash coincide o no |
| CVE en KEV | 17 | Priorizacion de parcheo y caza de explotacion |

## Por que las IP y los dominios no alertan

Un indicador de reputacion coincide muchas veces por motivos aburridos:
sinkholes de investigadores, CDN compartidas, dominios reciclados, rangos
de proveedores de nube. Desplegarlos como alerta directa llena la cola de
eventos que se cierran sin accion, y eso entrena al turno a cerrar sin
mirar. Se despliegan como **consultas de caza programadas con umbral**, en
`deploy/<siem>/consultas/`.

El hash es distinto: no comparte infraestructura con nada legitimo, asi que
va como alerta y ademas sin caducidad.

## Que se descarto del feed (262 de 961)

| Motivo | Descartados |
|---|---:|
| tipo no usado | 150 |
| nivel bajo | 112 |

## Familias mas presentes

| Amenaza | Indicadores |
|---|---:|
| malware_download | 100 |
| php.shin_webshell | 100 |
| ClearFake | 63 |
| Sliver | 53 |
| Unknown malware | 35 |
| Anatomy of BraZetsu: How Cybercriminals Fuel the Underground Ecosystem | 26 |
| Vidar | 23 |
| Financially Motivated Threat Actor Targets Brazil | 22 |
| PureRAT | 20 |
| Aisuru | 20 |
| Remus | 19 |
| Switches to Node.js and JavaScript malware | 16 |

## Ficheros generados

| Fichero | Entradas |
|---|---:|
| `wazuh/cti_ip` | 206 |
| `wazuh/cti_dominio` | 184 |
| `wazuh/cti_url` | 165 |
| `wazuh/cti_hash` | 85 |
| `wazuh/cti_cve_kev` | 17 |
| `splunk/cti_ip.csv` | 206 |
| `splunk/cti_dominio.csv` | 184 |
| `splunk/cti_url.csv` | 165 |
| `splunk/cti_hash.csv` | 85 |
| `splunk/cti_cve_kev.csv` | 17 |
| `sentinel/CTI_Ip.csv` | 206 |
| `sentinel/CTI_Dominio.csv` | 184 |
| `sentinel/CTI_Url.csv` | 165 |
| `sentinel/CTI_Hash.csv` | 85 |
| `elastic/cti_ip.ndjson` | 206 |
| `elastic/cti_dominio.ndjson` | 184 |
| `elastic/cti_url.ndjson` | 165 |
| `elastic/cti_hash.ndjson` | 85 |

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
