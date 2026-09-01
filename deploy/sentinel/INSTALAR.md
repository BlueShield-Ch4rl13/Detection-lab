# Microsoft Sentinel — instalacion

## Que hay en esta carpeta

| Carpeta | Contenido | Se regenera |
|---|---|---|
| `reglas/` | 124 consultas KQL por dominio, listas para regla de analítica | Sí, con `tools/build.py` |
| `watchlists/` | Indicadores de News CTI en CSV | Sí, con `tools/sync_cti.py` |
| `consultas/` | Las 3 correlaciones a mano y el paquete de caza | No, escritas a mano |

## 1. Antes de pegar nada: los bloques `extend`

**Esto es lo que más se olvida y lo que peor falla.** Varias consultas asumen
columnas que hay que crear antes del `where`, porque el dato viaja dentro de una
columna dinámica. Sin el `extend`, la consulta es **sintácticamente válida y no
casa nunca** — que es peor que un error, porque el error se ve y la consulta se
despliega.

Cada fichero `.kql` lleva su bloque en la cabecera. Los tres casos:

**`windows.kql` y `xdr.kql`** — telemetría de `DeviceEvents`:

```kusto
DeviceEvents
| extend af = parse_json(AdditionalFields)
| extend PipeName      = tostring(af.PipeName),
         GrantedAccess = tostring(af.DesiredAccess),
         CallTrace     = tostring(af.CallTrace),
         Signature     = tostring(af.Signature),
         SignatureStatus = tostring(af.SignatureStatus)
```

**`cloud.kql`** — `DeviceDetail` es dinámica en `SigninLogs`:

```kusto
SigninLogs
| extend DeviceIsCompliant = tostring(DeviceDetail.isCompliant),
         DeviceTrustType   = tostring(DeviceDetail.trustType)
```

**`contenedores.kql`** — en AKS el evento entero viaja en `log_s`:

```kusto
AzureDiagnostics
| where Category == "kube-audit"
| extend e = parse_json(log_s)
| extend verb = tostring(e.verb), username = tostring(e.user.username),
         namespace = tostring(e.objectRef.namespace),
         resource = tostring(e.objectRef.resource),
         subresource = tostring(e.objectRef.subresource),
         apiGroup = tostring(e.objectRef.apiGroup)
```

## 2. Tablas que hay que ajustar

Tres dependen de cómo esté conectado el producto. Se cambian en **un solo
sitio**, `tools/pipelines/sentinel.yml`, y se regenera:

| Producto | Valor por defecto | Alternativa |
|---|---|---|
| Proofpoint TAP | `ProofpointTAPMessagesBlocked_CL` | `CommonSecurityLog` si llega por CEF |
| Netskope | `NetskopeAlerts_CL` | `CommonSecurityLog` si llega por CEF |
| Kubernetes | `AzureDiagnostics` | Tabla propia si usas Fluent Bit |

```bash
$EDITOR tools/pipelines/sentinel.yml
python3 tools/build.py
```

## 3. Crear las reglas de analítica

Cada bloque de un `.kql` es el cuerpo de una regla. Manualmente:

*Microsoft Sentinel → Analytics → Create → Scheduled query rule*

| Campo | Qué poner |
|---|---|
| Name | El título del comentario `//` de la consulta |
| Tactics | Las que dice la línea `ATT&CK:` |
| Rule query | El bloque `extend` + la consulta |
| Run every | 5 min si es critical, 15 si high, 1 h si medium |
| Lookup data from | El mismo valor o algo más |
| Alert grouping | Activado, agrupar por entidad, 5 horas |

Para desplegar en bloque, exporta una regla a ARM desde el portal y usa esa
plantilla parametrizando `query`, `severity` y `queryFrequency`.

## 4. Watchlists de inteligencia

*Microsoft Sentinel → Watchlists → New → Import CSV*

| Fichero | Alias | Columna de búsqueda |
|---|---|---|
| `CTI_Ip.csv` | `Ip` | `valor` |
| `CTI_Dominio.csv` | `Dominio` | `valor` |
| `CTI_Url.csv` | `Url` | `valor` |
| `CTI_Hash.csv` | `Hash` | `valor` |

**El alias va sin el prefijo `CTI_`**: las consultas usan `_GetWatchlist('Hash')`,
no `_GetWatchlist('CTI_Hash')`.

Las watchlists no se refrescan solas. Con `az` desde el mismo cron que
`sync_cti.py`:

```bash
az sentinel watchlist-item create --resource-group RG --workspace-name WS \
   --watchlist-alias Hash --watchlist-item-id "$(uuidgen)" \
   --properties-item-values-json @fila.json
```

Para volúmenes como éste (575 indicadores) sale más a cuenta borrar la
watchlist y reimportar el CSV que actualizar fila a fila.

## 5. Las tres correlaciones

`consultas/correlaciones.kql` lleva password spraying, reutilización de sesión y
envío masivo interno. El backend de Kusto **no convierte correlaciones Sigma**
(un `dcount` en ventana), así que están escritas a mano.

`tools/validate.py` comprueba en cada ejecución que sus umbrales y ventanas
siguen cuadrando con los de la regla Sigma de origen, en las dos direcciones.
Si cambias uno, cambia el otro o el CI falla.

## 6. Comprobar que funciona

Antes de crear la regla, ejecuta la consulta en *Logs* con ventana de 7 días:

- **0 resultados** → o no hay actividad, o falta el `extend`, o la tabla está
  vacía. Comprueba lo segundo y lo tercero antes de dar por buena la consulta.
- **Miles de resultados** → esa regla no puede ser una alerta en tu entorno.
  Ajusta el filtro o déjala como caza.

```kusto
// ¿Tengo la tabla y tiene datos?
union withsource=Tabla imProcessCreate, DeviceProcessEvents, SecurityEvent, SigninLogs
| where TimeGenerated > ago(1d)
| summarize Eventos = count() by Tabla
```
