# Splunk — instalacion

## Que hay en esta carpeta

| Carpeta | Contenido | Se regenera |
|---|---|---|
| `reglas/savedsearches.conf` | 127 búsquedas programadas con cadencia, severidad y notables | Sí, con `tools/build.py` |
| `lookups/` | Indicadores de News CTI como CSV | Sí, con `tools/sync_cti.py` |
| `consultas/` | Caza e inteligencia: cruces contra lookup y agregaciones | No, escritas a mano |

## 1. Crear la app

Nunca en `search`. Una app propia se versiona, se despliega y se revierte
entera; en `search` las búsquedas se mezclan con las de todo el mundo.

```bash
export APP=$SPLUNK_HOME/etc/apps/TA-detection-lab
mkdir -p $APP/{default,local,lookups,metadata}

cat > $APP/default/app.conf <<'CONF'
[install]
is_configured = 1
[ui]
is_visible = 1
label = Detection Lab
[package]
id = TA-detection-lab
CONF

cat > $APP/metadata/default.meta <<'CONF'
[]
access = read : [ * ], write : [ admin, sc_admin ]
export = system
CONF
```

## 2. Reglas y consultas

```bash
cp deploy/splunk/reglas/savedsearches.conf   $APP/default/
cp deploy/splunk/consultas/cti_y_caza.conf   $APP/local/savedsearches.conf
cp deploy/splunk/lookups/*.csv               $APP/lookups/
```

Los lookups hay que declararlos para poder usar `| lookup`:

```bash
cat > $APP/default/transforms.conf <<'CONF'
[cti_ip]
filename = cti_ip.csv
case_sensitive_match = false

[cti_dominio]
filename = cti_dominio.csv
case_sensitive_match = false

[cti_url]
filename = cti_url.csv
case_sensitive_match = false

[cti_hash]
filename = cti_hash.csv
case_sensitive_match = false

[cti_cve_kev]
filename = cti_cve_kev.csv
case_sensitive_match = false
CONF
```

Comprobar antes de reiniciar:

```bash
$SPLUNK_HOME/bin/splunk btool savedsearches list --debug 2>&1 | grep TA-detection-lab | head
$SPLUNK_HOME/bin/splunk btool transforms list --debug 2>&1 | grep cti_
$SPLUNK_HOME/bin/splunk restart
```

## 3. Índices

Las búsquedas no llevan el índice escrito a mano: sale de
`tools/pipelines/splunk.yml`. Estos son los que espera:

| Índice | Contenido |
|---|---|
| `endpoint` | Sysmon, auditd/Falco, ESF de macOS |
| `idp` | Entra ID: `azure:aad:signin`, `azure:aad:audit` |
| `email` | Proofpoint TAP |
| `casb` | Netskope |
| `k8s` | Auditoría del API server |
| `proxy` | Proxy de salida |
| `web` | Servidor web y WAF |
| `network` | Firewall, NetFlow, Suricata |

Si los tuyos se llaman de otra forma, **edita el pipeline y regenera**; no
edites `savedsearches.conf`, que se sobrescribe:

```bash
$EDITOR tools/pipelines/splunk.yml
python3 tools/build.py
```

## 4. Cadencia y supresión

La cadencia sale del nivel de la regla Sigma:

| Nivel | Cron | Ventana | Severidad |
|---|---|---|---|
| critical | `*/5 * * * *` | -10m | 6 |
| high | `*/15 * * * *` | -20m | 5 |
| medium | `*/30 * * * *` | -35m | 4 |
| low | `15 * * * *` | -1h | 3 |
| informational | `30 * * * *` | -1h | 2 |

Las 127 búsquedas juntas son carga real. Si el search head va justo, escalona
los minutos de arranque en vez de subir los intervalos: mantiene la latencia de
detección y reparte el pico.

Todas llevan `alert.suppress = 1` con ventana de 60 minutos. Es lo que evita que
un proceso en bucle genere doscientos notables del mismo hecho.

## 5. Refresco de la inteligencia

```cron
0 6 * * * cd /opt/detection-lab && python3 tools/sync_cti.py --max-dias 30 \
          && cp intel/listas/splunk/*.csv $SPLUNK_HOME/etc/apps/TA-detection-lab/lookups/
```

No hace falta reiniciar: los lookups se releen en cada búsqueda.

## 6. Comprobar que funciona

```spl
| rest /services/saved/searches | search title="DL*" | stats count
```

Deben salir 127 más las de `consultas/`. Y para ver si alguna está fallando:

```spl
index=_internal sourcetype=scheduler status=skipped OR status=continued
| search savedsearch_name="DL*"
| stats count BY savedsearch_name, reason
```

`skipped` repetido significa que la anterior aún no había terminado: esa
búsqueda necesita una ventana más corta o un índice mejor acotado.
