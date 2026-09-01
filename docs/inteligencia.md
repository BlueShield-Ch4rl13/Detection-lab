# Inteligencia: de News CTI a los cuatro SIEM

`tools/sync_cti.py` toma el feed de
[ScriptNewsCTI](https://github.com/BlueShield-Ch4rl13/ScriptNewsCTI) y produce
listas de indicadores en el formato que cada SIEM sabe leer.

```
ScriptNewsCTI                          detection-lab
─────────────                          ─────────────
ThreatFox  ┐
URLhaus    ├─► enrich.py ─► iocs_latest.json ─► sync_cti.py ─┬─► wazuh/*.cdb
OTX        ┘   (scoring)                                     ├─► splunk/*.csv
CISA KEV   ────────────────────────────────────────────────► ├─► sentinel/*.csv
                                                             └─► elastic/*.ndjson
```

---

## Las tres decisiones que definen el módulo

### 1. Se filtra por puntuación, no se vuelca todo

El feed trae unos 700 indicadores por ejecución. La mayoría son de nivel bajo y
tienen vida útil de horas. Cargarlos todos convierte el SIEM en un generador de
ruido, y el ruido no es neutro: entrena al turno a cerrar sin mirar.

Por defecto entran los de nivel **alto y medio**. En la última ejecución eso
dejó fuera 96 de 716, un 13 %.

**Los hashes entran siempre**, sea cual sea su nivel. Un hash no caduca como
caduca una IP y no comparte infraestructura con nada legítimo.

### 2. Las IP y los dominios generan caza, no alerta

Ésta es la decisión que más cambia el resultado en producción.

Un indicador de reputación coincide muchas veces por motivos aburridos:
sinkholes de investigadores que se quedan con el dominio caído, CDN compartidas
donde el atacante alquiló una IP que ahora sirve a mil sitios legítimos,
dominios reciclados, rangos de proveedores de nube. Desplegar esas listas como
alerta directa llena la cola de eventos que se cierran sin acción.

Por eso el reparto es:

| Indicador | Cómo se despliega | Por qué |
|---|---|---|
| Hash | **Alerta directa** | Coincide o no coincide. No hay término medio. |
| IP | Caza con umbral | Una coincidencia es ruido; tres desde el mismo equipo, no |
| Dominio | Caza con umbral | Igual |
| URL | Caza con umbral | Igual |
| CVE (KEV) | Caza y priorización | No detecta la vulnerabilidad: detecta el intento |

Las consultas de caza están en `deploy/<siem>/consultas/` y todas exigen
**repetición, indicadores distintos o nivel alto** antes de sacar una fila.

En Wazuh esto se traduce en niveles: las reglas de hash son `level 12`
(notifican), las de IP y dominio `level 4` (se indexan sin notificar), y encima
hay dos reglas `<frequency>` que sí alertan cuando un mismo origen acumula cinco
coincidencias en diez minutos. Ahí `<frequency>` hace exactamente lo que sabe
hacer: contar disparos de una regla.

### 3. Todo indicador lleva su fecha

Sin fecha no se puede caducar la lista, y una lista de reputación que no caduca
acaba disparando por una IP que hoy sirve a un servicio legítimo. El campo
`visto` va en las cuatro salidas y `--max-dias` (30 por defecto) descarta lo
viejo.

`tools/validate.py` avisa si las listas tienen más de 7 días.

---

## Qué produce cada SIEM

| SIEM | Formato | Cómo se consume |
|---|---|---|
| **Wazuh** | `.cdb` — `clave:valor` por línea | `<list field="..." lookup="match_key">` tras `ossec-makelists` |
| **Splunk** | `.csv` | `\| lookup cti_hash valor OUTPUT amenaza nivel` |
| **Sentinel** | `.csv` | Watchlist importada, `_GetWatchlist('Hash')` |
| **Elastic** | `.ndjson` con esquema ECS de amenazas | Índice de indicadores + regla *Indicator Match* |

### Detalle del formato CDB

`ossec-makelists` trata **cada línea como una entrada**, comentarios incluidos.
Por eso los `.cdb` generados no llevan cabecera: una línea de comentario se
convertiría en un indicador con clave `#`. El valor de la derecha sale en la
alerta, así que ahí va la amenaza y el nivel:

```
176.65.139.206:Mirai|alta
```

El analista ve «Mirai» en la alerta sin abrir nada. Ese es el punto.

### Detalle del `ip:port`

El feed emite las IP de ThreatFox como `176.65.139.206:1999`, con el puerto
pegado. `sync_cti.py` lo parte antes de escribir la lista, porque compararlo tal
cual contra un campo de dirección de destino nunca casaría.

---

## Las reglas que consumen las listas

No salen de ninguna regla Sigma, y por eso están escritas a mano en cada SIEM:
**Sigma no expresa «este campo está en una lista externa»**. Es la misma
limitación honesta que con las correlaciones.

| SIEM | Fichero |
|---|---|
| Wazuh | `deploy/wazuh/reglas/0980-cti_indicadores.xml` (serie 101300-101399) |
| Splunk | `deploy/splunk/consultas/cti_y_caza.conf` |
| Sentinel | `deploy/sentinel/consultas/cti_y_caza.kql` |
| Elastic | `deploy/elastic/consultas/cti_y_caza.txt` + regla *Indicator Match* |

---

## Refresco automático

`.github/workflows/inteligencia.yml` sincroniza a diario a las 06:00 UTC y hace
commit sólo si algo cambió. No toca reglas ni consultas: sólo `intel/listas/` y
las copias en `deploy/*/`.

Para el refresco en el SIEM, cada `INSTALAR.md` lleva su línea de cron. El de
Wazuh es el único que necesita recompilar:

```cron
0 6 * * * cd /opt/detection-lab && python3 tools/sync_cti.py --max-dias 30 \
          && cp intel/listas/wazuh/*.cdb /var/ossec/etc/lists/ \
          && /var/ossec/bin/ossec-makelists \
          && systemctl reload wazuh-manager
```

---

## Uso

```bash
python3 tools/sync_cti.py                              # descarga y genera
python3 tools/sync_cti.py --local ruta/iocs.json       # desde una copia
python3 tools/sync_cti.py --min-nivel alta             # sólo lo más fiable
python3 tools/sync_cti.py --max-dias 7                 # sólo lo muy reciente
```

`intel/listas/RESUMEN.md` se regenera en cada ejecución con lo que entró, lo que
se descartó y por qué, y las familias de malware más presentes.

---

## Lo que este módulo no hace

- **No enriquece por sí mismo.** El scoring, la geolocalización y el cruce con
  VirusTotal y AbuseIPDB los hace News CTI en `enrich.py`. Aquí sólo se filtra y
  se traduce de formato.
- **No mide eficacia.** Cuántos de estos indicadores acabaron en un incidente
  real es una pregunta que sólo puede responder el registro de casos del SOC.
- **No sustituye a un TIP.** Con varias fuentes, deduplicación entre ellas y
  ciclo de vida por indicador, lo que toca es MISP u OpenCTI. Esto cubre el caso
  de un SOC pequeño con un feed propio, que es el caso real de este laboratorio.
