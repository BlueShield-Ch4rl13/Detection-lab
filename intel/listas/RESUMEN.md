# Listas de inteligencia

<!-- Generado por tools/sync_cti.py desde ScriptNewsCTI - no editar a mano -->

**Origen:** [ScriptNewsCTI](https://github.com/BlueShield-Ch4rl13/ScriptNewsCTI)  
**Feed generado:** 2026-09-03 04:04 UTC  
**Listas generadas:** 2026-09-03T10:28:46Z  
**Filtro aplicado:** nivel minimo `media`, maximo `30` dias de antiguedad

## Que hay en cada lista

| Indicador | Entradas | Uso previsto |
|---|---:|---|
| IP | 133 | Caza programada, no alerta directa |
| Dominio | 465 | Caza programada, no alerta directa |
| URL | 160 | Caza programada, no alerta directa |
| Hash | 115 | **Alerta directa**: un hash coincide o no |
| CVE en KEV | 23 | Priorizacion de parcheo y caza de explotacion |

## Por que las IP y los dominios no alertan

Un indicador de reputacion coincide muchas veces por motivos aburridos:
sinkholes de investigadores, CDN compartidas, dominios reciclados, rangos
de proveedores de nube. Desplegarlos como alerta directa llena la cola de
eventos que se cierran sin accion, y eso entrena al turno a cerrar sin
mirar. Se despliegan como **consultas de caza programadas con umbral**, en
`deploy/<siem>/consultas/`.

El hash es distinto: no comparte infraestructura con nada legitimo, asi que
va como alerta y ademas sin caducidad.

## Que se descarto del feed (212 de 1112)

| Motivo | Descartados |
|---|---:|
| tipo no usado | 127 |
| nivel bajo | 85 |

## Familias mas presentes

| Amenaza | Indicadores |
|---|---:|
| MacSync | 222 |
| IClickFix | 102 |
| malware_download | 100 |
| Gaming the system: how a Chinese-speaking actor turned Brazilian government sites into an SEO weapon | 89 |
| ClearFake | 67 |
| php.shin_webshell | 48 |
| Unknown malware | 46 |
| Remcos | 16 |
| Aisuru | 16 |
| Vidar | 16 |
| Mozi | 15 |
| Cobalt Strike | 14 |

## Ficheros generados

| Fichero | Entradas |
|---|---:|
| `wazuh/cti_ip` | 133 |
| `wazuh/cti_dominio` | 465 |
| `wazuh/cti_url` | 160 |
| `wazuh/cti_hash` | 115 |
| `wazuh/cti_cve_kev` | 23 |
| `splunk/cti_ip.csv` | 133 |
| `splunk/cti_dominio.csv` | 465 |
| `splunk/cti_url.csv` | 160 |
| `splunk/cti_hash.csv` | 115 |
| `splunk/cti_cve_kev.csv` | 23 |
| `sentinel/CTI_Ip.csv` | 133 |
| `sentinel/CTI_Dominio.csv` | 465 |
| `sentinel/CTI_Url.csv` | 160 |
| `sentinel/CTI_Hash.csv` | 115 |
| `elastic/cti_ip.ndjson` | 133 |
| `elastic/cti_dominio.ndjson` | 465 |
| `elastic/cti_url.ndjson` | 160 |
| `elastic/cti_hash.ndjson` | 115 |

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
