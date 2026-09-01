# Las reglas: qué detecta cada una y por qué

Este documento tiene dos partes:

1. **[El registro de la fusión](#criterio)** — qué reglas se retiraron al unir
   dos bibliotecas, cuáles sobrevivieron y con qué criterio. Se escribe a mano.
2. **[Las 127 reglas, una por una](#las-127-reglas-una-por-una)** — qué detecta
   cada una, por qué importa y qué hay que descartar antes de escalarla. Se
   **genera** desde `rules/` con `tools/generar_catalogo.py`.

## Índice de la biblioteca

| Dominio | Reglas | Qué cubre |
|---|---:|---|
| [Correo](#correo) | 8 | La entrega: phishing, suplantación, reglas de buzón |
| [Aplicaciones web](#aplicaciones-web) | 13 | Lo publicado: OWASP, explotación, escaneo |
| [Identidad y nube](#identidad-y-nube) | 10 | Entra ID, M365, CASB |
| [Windows y AD](#windows-y-active-directory) | 43 | Ejecución, persistencia, credenciales, dominio |
| [Linux](#linux) | 10 | Servidores: auditd y Falco |
| [macOS](#macos) | 8 | launchd, TCC, Gatekeeper, llavero |
| [Contenedores](#contenedores-y-kubernetes) | 8 | Auditoría del API server y escape del contenedor |
| [Red](#red) | 5 | Proxy, DNS, NetFlow |
| [Exfiltración](#exfiltracion) | 8 | El final de la cadena |
| [Evasión de EDR](#evasion-del-propio-edr) | 6 | El atacante atacando la vigilancia |
| [Zero Trust](#arquitectura-zero-trust) | 8 | Desviaciones de arquitectura |

---

# El registro de la fusión

Este repositorio nació con **28 reglas Sigma** propias. Se le ha incorporado una
segunda biblioteca de **48 reglas** procedente del paquete de detecciones
ZTA/SOC, más reglas nuevas de web, exfiltración, XDR, credenciales, macOS,
contenedores y marcos regulatorios.

Sumar `28 + 48` habría dado 76 reglas con **13 pares que disparan a la vez sobre
el mismo evento**. Eso no es cobertura: es ruido con dos identificadores. Este
documento es el registro de las decisiones de fusión, para que cualquiera pueda
auditar por qué falta una regla que antes estaba.

## Criterio

Para cada par solapado se comparó la **lógica de detección**, no el título:

| Situación | Decisión |
|---|---|
| La regla A es un subconjunto estricto de B | Se conserva **B**. A se retira y sus etiquetas ATT&CK se trasladan a B. |
| A y B miran el mismo evento desde ángulos distintos (origen/destino, telemetrías distintas) | **Se conservan las dos**. |
| A es más amplia pero con peor fidelidad | Se conserva la de mayor fidelidad y se anota la pérdida de amplitud abajo. |

---

## Reglas retiradas (13)

Todas eran de `rules/windows/`. En los 13 casos la regla superviviente contiene
la lógica de la retirada **de forma literal o más amplia**.

| Regla retirada | Superviviente | Por qué |
|---|---|---|
| `proc_lsass_comsvcs_minidump` | `soc_edr_001_volcado_lsass` | La retirada **es** la primera selección de la superviviente, carácter por carácter. La superviviente añade procdump, dumpert, nanodump y `MiniDumpWriteDump` vía rundll32. |
| `proc_vssadmin_delete_shadows` | `soc_edr_003_borrado_copias_sombra` | La superviviente cubre vssadmin, wmic, wbadmin, bcdedit y PowerShell, y **ancla en `Image`** en vez de buscar la cadena en cualquier línea de comandos. |
| `proc_powershell_encoded` | `soc_edr_006_powershell_ofuscado` | La retirada buscaba `-enc` sin delimitar, lo que casa también con `-Encoding` y `-EncodedArguments`: falso positivo garantizado. La superviviente delimita con espacios y añade 8 patrones de ofuscación más, incluido `pwsh.exe`. |
| `proc_certutil_download_decode` | `soc_edr_005_lolbins_descarga` | Selección `selection_certutil` equivalente. |
| `proc_bitsadmin_transfer` | `soc_edr_005_lolbins_descarga` | Selección `selection_bitsadmin` idéntica. |
| `proc_mshta_execution` | `soc_edr_005_lolbins_descarga` | Selección `selection_mshta` idéntica. |
| `proc_regsvr32_scriptlet` | `soc_edr_005_lolbins_descarga` | Selección `selection_regsvr32` idéntica. |
| `proc_powershell_download_cradle` | `soc_edr_005_lolbins_descarga` | Selección `selection_ps_metodo` equivalente. |
| `proc_defender_tamper` | `soc_edr_004_defensas_deshabilitadas` | La superviviente cubre además firewall, parada de servicios (WinDefend, Sense, wazuh) y `auditpol`. |
| `proc_wevtutil_clear_logs` | `soc_edr_004_defensas_deshabilitadas` | `wevtutil cl` y `wevtutil sl` están en `selection_auditoria`. Se trasladó la etiqueta `attack.t1070.001`. |
| `proc_mimikatz_cmdline` | `soc_ad_005_herramientas_kerberos` | La superviviente cubre los mismos argumentos **y** el nombre de imagen / `OriginalFileName`, que sobrevive al renombrado del binario. |
| `proc_scheduled_task_create` | `soc_edr_008_persistencia_tarea` | Ver «pérdidas conocidas». |
| `reg_run_key_persistence` | `soc_edr_009_persistencia_registro` | Ver «pérdidas conocidas». |

### Pérdidas conocidas de amplitud

Dos retiradas **sí reducen** lo que se ve, y conviene decirlo:

- `proc_scheduled_task_create` alertaba de **cualquier** `schtasks /create`.
  `soc_edr_008` exige además intérprete, ruta escribible, URL o `/ru system`.
  Una tarea programada creada para lanzar un `.exe` legítimo desde
  `C:\Program Files\` ya no alerta.
- `reg_run_key_persistence` alertaba de **cualquier** escritura en `Run`/`RunOnce`.
  `soc_edr_009` exige además que el valor apunte a un intérprete o a una ruta
  escribible por el usuario.

La decisión es deliberada: ambas versiones amplias generan decenas de eventos
diarios por instalaciones y actualizaciones legítimas, y en un turno de 24×7 eso
se traduce en cierre por fatiga. La amplitud sigue disponible como **consulta de
caza** — no como alerta — en `deploy/*/`, filtrando por técnica T1053.005 y
T1547.001 sin la condición de sospecha.

---

## Reglas conservadas pese a compartir técnica (5)

| Regla | Coincide en | Se conserva porque |
|---|---|---|
| `proc_wmic_process_call_create` | T1047 con `soc_ad_009_wmi_winrm_remoto` | Miran **lados opuestos** del movimiento lateral: la primera ve el `wmic` que lanza el atacante en el equipo origen; la segunda ve a `WmiPrvSE.exe` pariendo una shell en el equipo destino. En un incidente real quieres las dos, y correlacionarlas da el par origen-destino. |
| `proc_net_user_add` | T1136 con `soc_ad_011_cuenta_equipo_creada` | Telemetría distinta: línea de comandos local frente a evento 4741 del controlador de dominio. Y técnicas distintas: cuenta local frente a cuenta de equipo. |
| `proc_office_spawning_shell` | T1204/T1566 con las reglas de correo | Las de correo detectan la **entrega**; ésta detecta la **ejecución**. Son dos puntos distintos de la cadena. |
| `net_rare_process_external_conn` | T1071 con `soc_net_001_beaconing` | Una mira el proceso que abre la conexión (endpoint); la otra el patrón temporal del tráfico (red). |
| `proc_service_create_scexe` | T1543.003, sin equivalente | Sin solapamiento real. |

---

## Correcciones aplicadas a las 28 reglas originales

Durante la fusión se validaron las reglas originales contra pySigma y aparecieron
dos defectos que ya estaban en `main`:

1. **Etiquetas de táctica no canónicas.** Las 28 reglas usaban la forma antigua
   con guion bajo (`attack.credential_access`). La taxonomía oficial de ATT&CK
   —el campo `x_mitre_shortname` del STIX de MITRE, que es de donde pySigma saca
   la lista de valores válidos— usa **guion**: `attack.credential-access`.
   `ATTACKTagValidator` rechaza la forma con guion bajo. Normalizadas las 14
   tácticas en los 7 ficheros afectados.

2. **Referencias ATT&CK rotas en las 14 reglas que las llevaban.** Todas
   apuntaban a `https://attack.mitre.org/techniques/001`, `/002`, `/003`…
   El generador original había hecho `tag.split(".")[-1]` sobre
   `attack.t1003.001`, quedándose con el sufijo de subtécnica y perdiendo la
   técnica base. La URL correcta de una subtécnica es
   `https://attack.mitre.org/techniques/T1003/001/`. Regeneradas desde las
   etiquetas de cada regla.

Ninguna de las dos afectaba a la detección, pero la primera habría hecho fallar
el CI en cuanto se activara el validador de etiquetas, y la segunda mandaba al
analista a una página inexistente justo cuando está triando.

---

## Resultado

| | Antes | Después |
|---|---|---|
| Reglas Sigma | 28 | **87** |
| Pares que disparaban a la vez | 13 | 0 |
| Técnicas ATT&CK base | 20 | **55** |
| Tácticas cubiertas | 7 | **12** |
| Plataformas | Windows, Linux | Windows, Linux, macOS, contenedores, nube, correo, red |
| SIEM de destino | Lucene, Splunk, ES\|QL | Splunk, Sentinel, **Wazuh nativo**, Elastic |
| Reglas con etiquetas inválidas | 28 | 0 |
| Referencias rotas | 14 | 0 |

Desglose del recorrido: 28 originales − 13 retiradas = 15, + 48 del paquete
ZTA/SOC + 8 de macOS + 8 de contenedores + 8 de arquitectura Zero Trust = **87**.

<!-- INICIO:CATALOGO -->

# Las 141 reglas, una por una

Generado por `tools/generar_catalogo.py` desde `rules/`. Cada entrada sale
de la propia regla, asi que anadir una la mete aqui y cambiarle la logica
cambia lo que este documento dice. No se edita a mano.

En cada regla:

- **Que detecta y por que importa** - el razonamiento, no la sintaxis.
- **Que la distingue del ruido** - el primer falso positivo esperado, que es
  lo que hay que descartar antes de escalar.
- Severidad, tecnicas ATT&CK, origen de log y los controles NIST/ISO que
  evidencia.

Severidad: 🔴 critica · 🟠 alta · 🟡 media · ⚪ informativa (base de correlacion).

---

## Correo

**8 reglas** · Proofpoint TAP y Exchange Online

La entrega. Casi toda intrusion que no explota algo publicado empieza aqui.

### 🟡 Correo desde un dominio recien registrado

`soc_mail_001_dominio_reciente.yml`

Los dominios usados en campanas de phishing suelen tener dias de vida. Esta regla marca el correo entrante cuyo dominio remitente aparece en la lista de dominios recien registrados que alimenta el equipo de inteligencia. Sin esa lista la regla no dispara: es una deteccion basada en contexto, no en contenido.

**Lo que hay que descartar primero:** Proveedores nuevos y campanas de marketing con dominio propio recien creado

**Origen:** `proofpoint / tap` · **ATT&CK:** [T1566.002](https://attack.mitre.org/techniques/T1566/002/) · **NIST:** AT-2, SI-8 · **ISO 27001:** A.6.3, A.8.23

### 🟠 Suplantacion de directivo en el nombre para mostrar

`soc_mail_002_suplantacion_directivo.yml`

Fraude del CEO o BEC: el atacante escribe el nombre de un directivo en el campo display name pero envia desde un dominio externo. Es la variante que mas dinero mueve y la que menos firmas tecnicas deja, porque el correo no lleva adjunto ni URL.

**Lo que hay que descartar primero:** Correo legitimo de directivos desde una cuenta personal, situacion que conviene prohibir por politica

**Origen:** `proofpoint / tap` · **ATT&CK:** [T1534](https://attack.mitre.org/techniques/T1534/) · **NIST:** SI-8 · **ISO 27001:** A.6.3

### 🟠 Fallo de autenticacion de correo en el dominio propio

`soc_mail_003_fallo_dmarc.yml`

Correo que dice venir del dominio corporativo y falla SPF, DKIM o DMARC. Es suplantacion directa del dominio, no de un parecido. Con DMARC en modo reject deberia estar bloqueado; que llegue significa que la politica esta en none o que la excepcion de un proveedor esta siendo abusada.

**Lo que hay que descartar primero:** Proveedores que envian en nombre del dominio sin estar en el SPF, que hay que registrar

**Origen:** `proofpoint / tap` · **ATT&CK:** [T1566.002](https://attack.mitre.org/techniques/T1566/002/) · **NIST:** AT-2, SI-8 · **ISO 27001:** A.6.3, A.8.23

### 🟠 Adjunto con formato usado para entrega de malware

`soc_mail_004_adjunto_sospechoso.yml`

Contenedores y formatos que se usan para saltarse la marca de zona y los controles de macro: ISO, IMG, VHD, LNK dentro de ZIP, OneNote con adjunto incrustado y ficheros con doble extension.

**Lo que hay que descartar primero:** Imagenes ISO enviadas por el equipo de sistemas, que deberian ir por otro canal

**Origen:** `proofpoint / tap` · **ATT&CK:** [T1566.001](https://attack.mitre.org/techniques/T1566/001/) · **NIST:** AT-2, SI-8 · **ISO 27001:** A.6.3, A.8.23

### 🟠 Usuario pulsa una URL de phishing bloqueada o permitida

`soc_mail_005_url_pulsada.yml`

El clic es el momento en que un correo deja de ser un riesgo y pasa a ser un incidente. Detecta los eventos de clic sobre URL reescritas por el gateway, tanto los bloqueados (que confirman el intento) como los permitidos (que exigen revisar el puesto).

**Lo que hay que descartar primero:** Reclasificaciones posteriores del proveedor, que conviene revisar antes de cerrar el caso

**Origen:** `proofpoint / tap` · **ATT&CK:** [T1566.002](https://attack.mitre.org/techniques/T1566/002/) · **NIST:** AT-2, SI-8 · **ISO 27001:** A.6.3, A.8.23

### 🟠 Regla de buzon con reenvio externo creada

`soc_mail_006_regla_buzon_externa.yml`

Tras comprometer un buzon, el atacante crea una regla que reenvia el correo fuera o que mueve a la papelera los avisos de seguridad y las respuestas de la victima. Es el indicador mas fiable de compromiso de cuenta de correo y suele preceder al fraude del pago desviado.

**Lo que hay que descartar primero:** Reglas de reenvio creadas por el propio usuario hacia otra cuenta corporativa

**Origen:** `m365 / exchange` · **ATT&CK:** [T1114.003](https://attack.mitre.org/techniques/T1114/003/), [T1564.008](https://attack.mitre.org/techniques/T1564/008/) · **NIST:** AC-3, AU-9 · **ISO 27001:** A.8.12, A.8.15, A.8.3

### ⚪ Correo entregado desde una cuenta interna

`soc_mail_007_envio_masivo_interno.yml` · correlacion Sigma

Regla base para detectar el uso de una cuenta comprometida como plataforma de envio. Aisla el correo saliente originado en el propio dominio.

**Lo que hay que descartar primero:** {'Todas': 'es una regla base sin valor de alerta por si sola'}

**Origen:** `proofpoint / tap` · **ATT&CK:** [T1534](https://attack.mitre.org/techniques/T1534/)

### 🟠 HTML smuggling en adjunto

`soc_mail_008_html_smuggling.yml`

El adjunto es un HTML aparentemente inofensivo que reconstruye el binario en el navegador con JavaScript, de modo que el fichero nunca cruza el perimetro como ejecutable. Detecta los patrones de construccion de blob y de descarga automatica.

**Lo que hay que descartar primero:** Boletines HTML complejos, que rara vez incluyen construccion de blob

**Origen:** `proofpoint / tap` · **ATT&CK:** [T1027.006](https://attack.mitre.org/techniques/T1027/006/) · **NIST:** SI-3 · **ISO 27001:** A.8.7

---

## Aplicaciones web

**13 reglas** · Registros de servidor web y WAF

La otra puerta de entrada: lo que esta publicado y por tanto es alcanzable sin credenciales.

### 🟠 Inyeccion SQL en parametros de la peticion HTTP

`web_001_inyeccion_sql.yml`

Una cadena de consulta normal lleva identificadores, fechas y texto de busqueda: no lleva la gramatica de un motor SQL. Lo que separa el ataque del trafico legitimo no es la palabra suelta sino la combinacion de un parametro con construcciones que solo tienen sentido si el valor se concatena dentro de la sentencia: union de conjuntos, condiciones siempre ciertas, funciones de espera y lectura del catalogo interno.

**Lo que hay que descartar primero:** Consolas de administracion de base de datos publicadas en la intranet, donde la sentencia viaja en el parametro por diseno; las tres mas comunes ya salen por ruta, ampliar la lista si hay otras

**Origen:** `webserver` · **ATT&CK:** [T1190](https://attack.mitre.org/techniques/T1190/) · **NIST:** RA-5, SC-7, SI-10 · **ISO 27001:** A.8.28, A.8.8

### 🟠 Cross-site scripting reflejado en la peticion

`web_002_xss_reflejado.yml`

En el XSS reflejado el payload viaja en la peticion y la aplicacion lo devuelve dentro de la respuesta, de modo que se ejecuta en el navegador de la victima con su sesion. Marcar una etiqueta HTML suelta llena la cola de ruido: lo que no aparece en trafico normal es la etiqueta acompanada de un vector de ejecucion, sea manejador de evento, esquema javascript o acceso a la cookie. Se exige 200 porque lo reflejado en una pagina servida es lo explotable.

**Lo que hay que descartar primero:** Editores enriquecidos y paneles de contenido que envian HTML del propio autor; se excluyen las rutas mas comunes y conviene anadir las del gestor que use el sitio

**Origen:** `webserver` · **ATT&CK:** [T1059.007](https://attack.mitre.org/techniques/T1059/007/), [T1189](https://attack.mitre.org/techniques/T1189/) · **NIST:** CM-7, SC-18, SI-3 · **ISO 27001:** A.8.23, A.8.7

### 🟠 Salto de directorio hacia ficheros fuera de la raiz web

`web_003_salto_de_directorio.yml`

El servidor solo deberia servir lo que cuelga de su raiz. Una peticion que sube niveles con secuencias de punto-punto busca lo que hay fuera: credenciales, claves y ficheros de configuracion. La variante que de verdad se escapa de los filtros es la codificada dos veces, porque el proxy la normaliza una vez y la aplicacion la vuelve a decodificar, asi que el ataque solo se ve entero en el punto donde se registra la URI cruda.

**Lo que hay que descartar primero:** Mapas de codigo y paquetes de front-end que conservan rutas relativas con ../ dentro del propio fichero; se filtran por extension y ademas responden 200 de forma constante

**Origen:** `webserver` · **ATT&CK:** [T1083](https://attack.mitre.org/techniques/T1083/), [T1190](https://attack.mitre.org/techniques/T1190/) · **NIST:** AC-3, RA-5, SC-7, SI-10 · **ISO 27001:** A.8.28, A.8.3, A.8.8

### 🔴 Peticion falsificada desde el servidor hacia metadatos de nube

`web_004_ssrf_metadatos_nube.yml`

El servicio de metadatos de la instancia solo es alcanzable desde la propia maquina y entrega credenciales temporales del rol asignado, asi que quien consigue que la aplicacion lo consulte por el se lleva las llaves de la cuenta de nube. Ningun cliente legitimo pide desde fuera una direccion de enlace local: si aparece dentro de un parametro, alguien apunta la descarga del servidor contra si mismo. Se cubren las formas ofuscadas de la direccion.

**Lo que hay que descartar primero:** Portales internos de documentacion de nube que enlazan la URL del servicio de metadatos como ejemplo; se distinguen porque la cadena viaja en la ruta de un documento y no dentro de un parametro

**Origen:** `webserver` · **ATT&CK:** [T1190](https://attack.mitre.org/techniques/T1190/), [T1552.005](https://attack.mitre.org/techniques/T1552/005/) · **NIST:** IA-5, RA-5, SC-28, SC-7, SI-10 · **ISO 27001:** A.5.17, A.8.28, A.8.8

### 🔴 Deserializacion insegura de datos controlados por el cliente

`web_005_deserializacion_insegura.yml`

Deserializar es reconstruir objetos, y reconstruir un objeto ejecuta codigo del propio lenguaje antes de que la aplicacion valide nada: por eso una cadena serializada que llega del cliente vale como ejecucion remota sin vulnerabilidad de memoria. La ventaja para la deteccion es que cada formato tiene cabecera fija: el flujo Java empieza por los mismos cuatro bytes, PHP declara tipo y longitud, y el binario de .NET tiene prologo constante.

**Lo que hay que descartar primero:** Portales Java antiguos que serializan el estado de paginacion o el token de vista en un parametro y envian rO0AB en cada peticion; se reconocen porque siempre es el mismo endpoint y la estructura del valor no cambia, y se excluyen por esa ruta concreta

**Origen:** `webserver` · **ATT&CK:** [T1190](https://attack.mitre.org/techniques/T1190/) · **NIST:** RA-5, SC-7, SI-10 · **ISO 27001:** A.8.28, A.8.8

### 🟠 Subida de fichero con extension ejecutable al directorio publicado

`web_006_subida_fichero_ejecutable.yml`

Una aplicacion que acepta adjuntos debe guardarlos como datos. Cuando el fichero que entra termina en una extension que el motor del servidor interpreta y ademas cae bajo la raiz web, deja de ser un adjunto y pasa a ser codigo invocable: es el paso previo a la webshell. Se exige metodo de escritura y respuesta de exito, porque un 403 no cambia el estado, y se vigilan la extension doble y el corte con byte nulo, que solo existen para burlar el filtro.

**Lo que hay que descartar primero:** Despliegues por WebDAV y sincronizacion de contenido con PUT contra el directorio publicado, que son legitimos pero deben venir de la IP del sistema de despliegue y en ventana de cambio; fuera de eso son el mismo evento que un ataque

**Origen:** `webserver` · **ATT&CK:** [T1190](https://attack.mitre.org/techniques/T1190/), [T1505.003](https://attack.mitre.org/techniques/T1505/003/) · **NIST:** CM-5, RA-5, SC-7, SI-10, SI-7 · **ISO 27001:** A.8.28, A.8.8, A.8.9

### 🟠 Inyeccion de comandos del sistema operativo en un parametro

`web_007_inyeccion_de_comandos.yml`

Cuando la aplicacion pasa un parametro a una llamada de sistema sin sanear, al atacante le basta con cerrar el argumento y encadenar otro comando. El separador solo no sirve como deteccion, porque el punto y coma y la barra vertical aparecen en filtros y en listas de valores; lo que no aparece en un parametro legitimo es el separador seguido del nombre de un binario del sistema, y por eso se exigen las dos mitades dentro de la misma peticion.

**Lo que hay que descartar primero:** Paneles de administracion de equipos de red y de hosting que ofrecen ping, traceroute o nslookup como funcion; se excluyen por ruta y ademas solo son alcanzables tras autenticacion

**Origen:** `webserver` · **ATT&CK:** [T1059.004](https://attack.mitre.org/techniques/T1059/004/), [T1190](https://attack.mitre.org/techniques/T1190/) · **NIST:** CM-7, RA-5, SC-7, SI-10, SI-3 · **ISO 27001:** A.8.28, A.8.7, A.8.8

### 🔴 Inyeccion JNDI en peticion HTTP tipo Log4Shell

`web_008_inyeccion_jndi_log4shell.yml`

La familia Log4Shell no explota la aplicacion sino la biblioteca que escribe sus registros: cualquier dato que acabe en una linea de log se interpreta como plantilla y provoca una consulta JNDI al servidor del atacante, que devuelve la clase a ejecutar. Eso cambia donde mirar, porque el payload rara vez va en la ruta: llega en User-Agent o en Referer, campos que casi nadie inspecciona. Esa sintaxis no existe en trafico normal, ni siquiera troceada.

**Lo que hay que descartar primero:** Escaneres de superficie de ataque y servicios de bug bounty que envian sondas JNDI con dominio de interaccion propio; se reconocen por el dominio de la sonda y por proceder de rangos publicados, y siguen mereciendo revision porque confirman que el campo llega al log

**Origen:** `webserver` · **ATT&CK:** [T1059](https://attack.mitre.org/techniques/T1059/), [T1190](https://attack.mitre.org/techniques/T1190/) · **NIST:** CM-7, RA-5, SC-7, SI-10, SI-3 · **ISO 27001:** A.8.28, A.8.7, A.8.8

### 🟠 Contrabando de peticiones HTTP entre proxy y servidor final

`web_009_contrabando_peticiones.yml`

El contrabando aprovecha que el proxy delantero y el servidor de origen no se ponen de acuerdo sobre donde termina una peticion: uno hace caso a Content-Length y el otro a Transfer-Encoding. Lo que sobra del cuerpo se pega al principio de la peticion del siguiente usuario, lo que permite saltarse los controles del proxy y robar sesiones ajenas. En el log solo quedan los restos: cabeceras dentro de la ruta, saltos de linea y metodos imposibles.

**Lo que hay que descartar primero:** Clientes rotos y bots que envian peticiones mal formadas y generan 400 con un metodo basura; se separan porque llegan de una sola c-ip y no van seguidos de trafico con exito hacia rutas privilegiadas

**Origen:** `webserver` · **ATT&CK:** [T1190](https://attack.mitre.org/techniques/T1190/) · **NIST:** RA-5, SC-7, SI-10 · **ISO 27001:** A.8.28, A.8.8

### 🟡 Escaneo automatizado del servidor web por herramienta conocida

`web_010_escaneo_automatizado.yml`

Antes de explotar hay que enumerar, y esa fase deja una huella distinta a la de un usuario: cientos de rutas que no existen, sin referer y a ritmo constante. Muchas herramientas se anuncian en el User-Agent porque no esperan resistencia; cuando el operador lo cambia, queda el agente ausente junto a 404 en cadena. El recuento por c-ip que convierte eso en veredicto de escaneo se hace en el SIEM, porque Sigma no expresa proporciones de estado en una regla.

**Lo que hay que descartar primero:** Pruebas de intrusion y analisis de vulnerabilidades contratados, que producen exactamente esta senal; deben excluirse por c-ip de origen y por ventana pactada, nunca desactivando la regla

**Origen:** `webserver` · **ATT&CK:** [T1595.002](https://attack.mitre.org/techniques/T1595/002/), [T1595.003](https://attack.mitre.org/techniques/T1595/003/) · **NIST:** RA-5, SC-7 · **ISO 27001:** A.8.8

### 🟠 Abuso de token JWT con algoritmo nulo o cabecera manipulada

`web_011_abuso_de_token_jwt.yml`

Un JWT solo vale lo que vale su firma. Si el verificador acepta el algoritmo que le dice la cabecera del propio token, el atacante pone none y se emite el usuario que quiera; el mismo error de confianza aparece cuando kid apunta a un fichero del sistema para forzar una clave conocida, o cuando jku y x5u traen la clave publica desde un servidor ajeno. La cabecera va en base64url sin cifrar, asi que el prefijo delata el algoritmo, y nadie legitimo pone none.

**Lo que hay que descartar primero:** Portales de pruebas y depuradores de token alojados internamente, donde alguien pega un JWT de ejemplo con alg none para ensenar el fallo; se distinguen por la ruta de la herramienta y por venir de un puesto de desarrollo

**Origen:** `webserver` · **ATT&CK:** [T1550.001](https://attack.mitre.org/techniques/T1550/001/), [T1606](https://attack.mitre.org/techniques/T1606/) · **NIST:** AC-3, IA-2, IA-5, SC-23 · **ISO 27001:** A.8.5

### 🔴 Shell lanzada por el proceso del servidor web tras explotacion

`web_012_shell_tras_explotacion.yml`

Aqui termina la cadena que empieza en una peticion maliciosa: el proceso que atiende HTTP deja de servir contenido y engendra un interprete. Un servidor sano ejecuta muy pocos hijos y siempre los mismos, asi que la senal esta en el parentesco, no en el comando. El matiz que evita ahogar la cola es que php-fpm si llama al shell para enviar correo o convertir imagenes: por eso solo alertan la herramienta de red, la shell interactiva y el reconocimiento.

**Lo que hay que descartar primero:** Aplicaciones PHP que envian correo o convierten ficheros llamando al shell, motivo por el que el interprete solo no basta y hay que anadir a filtro_mantenimiento las rutas propias del sitio

**Origen:** `process_creation / linux` · **ATT&CK:** [T1059.004](https://attack.mitre.org/techniques/T1059/004/), [T1190](https://attack.mitre.org/techniques/T1190/), [T1505.003](https://attack.mitre.org/techniques/T1505/003/) · **NIST:** CM-5, CM-7, RA-5, SC-7, SI-10, SI-3, SI-7 · **ISO 27001:** A.8.28, A.8.7, A.8.8, A.8.9

### 🔴 Inyeccion en plantillas del lado servidor

`web_013_inyeccion_plantillas_ssti.yml`

Cuando la entrada del usuario acaba dentro de una plantilla en vez de dentro de los datos que la plantilla pinta, el motor la evalua como codigo. De ahi a ejecucion remota hay un paso corto y bien documentado en Jinja2, Freemarker, Velocity, Twig y Spring EL. Lo que distingue el ataque del texto normal es que la carga util nunca es una expresion suelta: siempre lleva el delimitador del motor rodeando una operacion o una clase del entorno de ejecucion.

**Lo que hay que descartar primero:** Formularios donde alguien pega documentacion o un fragmento de plantilla; llega de usuario autenticado, con referer propio y sin repeticion desde la misma IP

**Origen:** `webserver` · **ATT&CK:** [T1190](https://attack.mitre.org/techniques/T1190/) · **NIST:** RA-5, SC-7, SI-10 · **ISO 27001:** A.8.28, A.8.8

---

## Identidad y nube

**10 reglas** · Entra ID, Microsoft 365, Netskope

Donde el atacante ya no necesita malware: con una credencial valida entra por la puerta.

### 🟠 Consentimiento concedido a una aplicacion no verificada

`soc_cld_001_consentimiento_oauth.yml`

El illicit consent grant no roba la contrasena: convence al usuario de dar permisos a una aplicacion controlada por el atacante, que a partir de ahi lee correo y ficheros sin necesitar credenciales ni MFA. Sobrevive a un cambio de contrasena, lo que lo hace especialmente incomodo en respuesta a incidentes.

**Lo que hay que descartar primero:** Aplicaciones corporativas aprobadas, que deben estar en el inventario de aplicaciones empresariales

**Origen:** `azure / auditlogs` · **ATT&CK:** [T1550.001](https://attack.mitre.org/techniques/T1550/001/) · **NIST:** AC-3, IA-2 · **ISO 27001:** A.8.5

### 🟡 Metodo MFA registrado tras un inicio de sesion de riesgo

`soc_cld_002_metodo_mfa_registrado.yml`

Registrar un segundo factor propio es como el atacante convierte un acceso puntual en persistencia. Detecta el alta de un metodo de autenticacion en la ventana posterior a un inicio de sesion marcado como de riesgo. La correlacion temporal la aporta el SIEM sobre esta regla base.

**Lo que hay que descartar primero:** Altas de empleado y renovacion de dispositivo, que son frecuentes y obligan a correlar con la senal de riesgo

**Origen:** `azure / auditlogs` · **ATT&CK:** [T1098.005](https://attack.mitre.org/techniques/T1098/005/) · **NIST:** AC-2, AC-6 · **ISO 27001:** A.5.16, A.5.18

### ⚪ Fallo de autenticacion en Entra ID por credencial invalida

`soc_cld_003_password_spraying.yml` · correlacion Sigma

Regla base del password spraying. Aisla los codigos de resultado que corresponden a credencial invalida (50126), cuenta bloqueada (50053) y cuenta deshabilitada (50055). Por si sola no alerta: la senal esta en la correlacion posterior.

**Lo que hay que descartar primero:** Errores puntuales de usuario, que es la razon de no alertar sobre esta regla base

**Origen:** `azure / signinlogs` · **ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003/)

### ⚪ Inicio de sesion correcto en Entra ID

`soc_cld_004_token_robado.yml` · correlacion Sigma

Regla base para la deteccion de reutilizacion de sesion. Aisla las autenticaciones correctas para que la correlacion pueda contar desde cuantos sistemas autonomos distintos se usa una misma sesion.

**Lo que hay que descartar primero:** {'Todas': 'es una regla base sin valor de alerta por si sola'}

**Origen:** `azure / signinlogs` · **ATT&CK:** [T1539](https://attack.mitre.org/techniques/T1539/)

### 🟠 Alta en un rol privilegiado de Entra ID

`soc_cld_005_rol_privilegiado.yml`

La concesion de un rol de administrador es el objetivo final de la mayoria de los ataques de identidad en la nube. Debe generar alerta siempre, incluso cuando es legitima, porque el coste de revisarla es minimo y el de perderla es total.

**Lo que hay que descartar primero:** Activacion planificada por PIM, que conviene distinguir del alta permanente

**Origen:** `azure / auditlogs` · **ATT&CK:** [T1098.003](https://attack.mitre.org/techniques/T1098/003/) · **NIST:** AC-2, AC-6 · **ISO 27001:** A.5.16, A.5.18

### 🟠 Politica de acceso condicional modificada o deshabilitada

`soc_cld_006_acceso_condicional.yml`

El acceso condicional es el punto de aplicacion de politica de la arquitectura Zero Trust en la nube. Deshabilitar una politica, o anadirse a su lista de exclusion, es la forma limpia de saltarse el MFA sin dejar rastro de un fallo de autenticacion.

**Lo que hay que descartar primero:** Mantenimiento planificado de politicas, que debe pasar por gestion de cambios

**Origen:** `azure / auditlogs` · **ATT&CK:** [T1556.009](https://attack.mitre.org/techniques/T1556/009/) · **NIST:** AC-2, IA-2 · **ISO 27001:** A.8.5

### 🟠 Credencial anadida a una aplicacion o service principal

`soc_cld_007_credencial_service_principal.yml`

Anadir un secreto o un certificado a una aplicacion existente da acceso permanente con los permisos de esa aplicacion, sin usuario y sin MFA. Es una de las persistencias mas dificiles de detectar despues del hecho y de las mas usadas en intrusiones avanzadas en la nube.

**Lo que hay que descartar primero:** Rotacion planificada de secretos, que conviene concentrar en ventanas conocidas

**Origen:** `azure / auditlogs` · **ATT&CK:** [T1098.001](https://attack.mitre.org/techniques/T1098/001/) · **NIST:** AC-2, AC-6 · **ISO 27001:** A.5.16, A.5.18

### 🟠 Inicio de sesion desde una red de anonimizacion

`soc_cld_008_origen_anonimizado.yml`

Autenticacion correcta desde Tor, una VPN comercial o un proveedor de proxy residencial. En un entorno corporativo con VPN propia no hay motivo para que un usuario entre por esa via, y es el origen habitual del uso de credenciales robadas.

**Lo que hay que descartar primero:** Usuarios en itinerancia con VPN personal, situacion que conviene regular por politica

**Origen:** `azure / signinlogs` · **ATT&CK:** [T1090.003](https://attack.mitre.org/techniques/T1090/003/) · **NIST:** SC-7 · **ISO 27001:** A.8.20, A.8.22

### 🟡 Dispositivo no conforme accediendo a un recurso corporativo

`soc_cld_009_dispositivo_no_conforme.yml`

Acceso concedido desde un equipo que Intune marca como no conforme o no gestionado. Es la traduccion directa a la nube del principio Zero Trust de que la postura del dispositivo condiciona el acceso, y complementa la deteccion ZTA-DEV-003 del lado del endpoint.

**Lo que hay que descartar primero:** Dispositivos personales autorizados por politica BYOD, que deben distinguirse de los no gestionados

**Origen:** `azure / signinlogs` · **ATT&CK:** [T1078.004](https://attack.mitre.org/techniques/T1078/004/) · **NIST:** AC-2, AC-6 · **ISO 27001:** A.5.15, A.8.2

### 🟡 Subida de datos a un servicio SaaS no aprobado

`soc_cld_010_saas_no_aprobado.yml`

Shadow IT con dato dentro. Detecta la carga de ficheros hacia aplicaciones en la nube que no estan en el catalogo aprobado, que es a la vez un riesgo de fuga y, si hay datos personales, una posible transferencia internacional sin base juridica.

**Lo que hay que descartar primero:** Uso puntual autorizado de un servicio externo por peticion de un cliente

**Origen:** `netskope / alerts` · **ATT&CK:** [T1567.002](https://attack.mitre.org/techniques/T1567/002/) · **NIST:** AC-4, SC-7 · **ISO 27001:** A.8.12, A.8.23

---

## Windows y Active Directory

**56 reglas** · Sysmon, canal Security, Defender XDR

El grueso de la biblioteca. Ejecucion, persistencia, credenciales y movimiento lateral en dominio.

### 🔴 DCShadow - registro de un controlador de dominio falso

`ad_013_dcshadow.yml`

DCShadow no lee el directorio, lo escribe: el atacante da de alta temporalmente un DC falso y empuja cambios por el canal de replicacion, que casi ningun SOC audita. Es la via para sembrar SID history o reescribir un descriptor de seguridad sin generar los eventos de modificacion de objeto que se vigilan. La promocion legitima de un DC la realiza la propia cuenta de equipo durante dcpromo, nunca una cuenta de usuario.

**Lo que hay que descartar primero:** Promocion o degradacion planificada de un controlador de dominio, que debe coincidir con una ventana de cambio aprobada y con un alta o baja en el inventario de DC

**Origen:** `windows / security` · **ATT&CK:** [T1207](https://attack.mitre.org/techniques/T1207/) · **NIST:** AC-6, CM-5 · **ISO 27001:** A.8.2

### 🔴 Inyeccion de SID history en una cuenta del dominio

`ad_014_sid_history.yml`

Un SID de grupo privilegiado escrito en el atributo sIDHistory concede esa pertenencia sin que la cuenta figure como miembro del grupo: la escalada no aparece en una revision de miembros ni en el informe de permisos, y sobrevive al cambio de contrasena. Es una puerta trasera silenciosa que solo se ve mirando el atributo. Fuera de una migracion de dominio con ADMT en curso, sIDHistory no deberia cambiar jamas.

**Lo que hay que descartar primero:** Migracion de cuentas entre dominios con ADMT, que debe acotarse al periodo del proyecto y a la lista de cuentas del lote en curso

**Origen:** `windows / security` · **ATT&CK:** [T1134.005](https://attack.mitre.org/techniques/T1134/005/) · **NIST:** AC-3, AC-6 · **ISO 27001:** A.8.2

### 🔴 Abuso de delegacion Kerberos - constrained, unconstrained y RBCD

`ad_015_delegacion_kerberos.yml`

Quien controla la delegacion de una cuenta puede pedir tickets en nombre de cualquier usuario, incluido un administrador de dominio, sin conocer su contrasena. La delegacion basada en recursos es la peor de las tres porque se configura escribiendo un solo atributo sobre el equipo destino, algo que puede hacer quien creo esa cuenta de equipo. En un dominio maduro estos atributos se fijan al dar de alta el servicio y no se tocan.

**Lo que hay que descartar primero:** Alta de un servicio que necesita delegacion, como un frontal web o un cluster de SQL Server, que debe quedar registrado con su cuenta y su SPN destino en el inventario de delegaciones

**Origen:** `windows / security` · **ATT&CK:** [T1098](https://attack.mitre.org/techniques/T1098/), [T1550.003](https://attack.mitre.org/techniques/T1550/003/) · **NIST:** AC-2, AC-3, AC-6, IA-2 · **ISO 27001:** A.5.16, A.5.18, A.8.5

### 🔴 Modificacion de AdminSDHolder o del descriptor de seguridad de un objeto de directorio

`ad_016_adminsdholder.yml`

La ACL de AdminSDHolder se propaga cada hora a todos los grupos protegidos, asi que una entrada anadida ahi devuelve el control sobre Domain Admins aunque el defensor limpie el grupo una y otra vez. Lo mismo vale para el descriptor de seguridad del objeto raiz del dominio, donde un WriteDacl basta para habilitar DCSync. Son objetos que en produccion solo cambian al extender el esquema o al desplegar un producto de directorio.

**Lo que hay que descartar primero:** Despliegue de Exchange u otro producto que extiende el esquema y reescribe descriptores de seguridad en masa, que debe coincidir con una ventana de cambio aprobada

**Origen:** `windows / security` · **ATT&CK:** [T1098](https://attack.mitre.org/techniques/T1098/), [T1222](https://attack.mitre.org/techniques/T1222/) · **NIST:** AC-2, AC-3, AC-6 · **ISO 27001:** A.5.16, A.5.18, A.8.3

### 🟠 Lectura de contrasenas de administrador local gestionadas por LAPS

`ad_017_lectura_laps.yml`

La contrasena de LAPS es la ultima llave del administrador local y solo unas pocas cuentas deberian poder leerla, de una en una y para un equipo concreto. Una consulta LDAP que pide el atributo para todo el dominio, o una utilidad de volcado, entrega de golpe el administrador local de todo el parque y con el, movimiento lateral inmediato. El soporte legitimo usa la consola o el portal de autoservicio, que no dejan esta traza.

**Lo que hay que descartar primero:** Script de inventario del equipo de puesto que audita la rotacion del atributo, que debe ejecutarse desde un host de administracion conocido y con una cuenta de servicio en lista de excepciones

**Origen:** `process_creation / windows` · **ATT&CK:** [T1087.002](https://attack.mitre.org/techniques/T1087/002/), [T1555](https://attack.mitre.org/techniques/T1555/) · **NIST:** AC-2, IA-5 · **ISO 27001:** A.5.16, A.5.17, A.8.5

### 🔴 Extraccion de la base de datos ntds.dit del controlador de dominio

`ad_018_extraccion_ntds.yml`

ntds.dit guarda el hash de todas las cuentas del dominio, krbtgt incluida: quien se lleva una copia se lleva el dominio entero y ya no necesita volver a entrar. Como el servicio de directorio mantiene el fichero bloqueado, el atacante tiene que pasar por ntdsutil, por una instantanea de volumen o por diskshadow para sacarlo en frio. Solo el agente de copia de seguridad tiene motivo para tocar ese fichero, y siempre programado.

**Lo que hay que descartar primero:** Copia de seguridad del estado del sistema en un DC, que crea instantaneas de forma programada y siempre desde el proceso del agente de respaldo, no desde un interprete de comandos

**Origen:** `process_creation / windows` · **ATT&CK:** [T1003.003](https://attack.mitre.org/techniques/T1003/003/) · **NIST:** AC-6, IA-5 · **ISO 27001:** A.5.17, A.8.5

### 🟠 Coercion de autenticacion y relay NTLM contra el controlador de dominio

`ad_019_coercion_ntlm.yml`

PetitPotam, PrinterBug y DFSCoerce obligan a un servidor, normalmente un DC, a autenticarse contra la maquina del atacante; ese NTLM se retransmite a AD CS o a LDAP y sale un certificado o un DCSync sin haber robado ninguna contrasena. Lo caracteristico es el enlace a las tuberias EFSRPC, spoolss o netdfs sobre IPC$, y despues un logon de red NTLM de la cuenta de equipo del DC, que en un dominio sano habla siempre Kerberos.

**Lo que hay que descartar primero:** Servidores de impresion y agentes de copia antiguos que siguen negociando NTLM entre si, que se identifican con una linea base de dos semanas sobre selection_relay_ntlm y se pasan a lista de excepciones por cuenta de equipo y direccion de origen

**Origen:** `windows / security` · **ATT&CK:** [T1187](https://attack.mitre.org/techniques/T1187/), [T1557.001](https://attack.mitre.org/techniques/T1557/001/) · **NIST:** IA-2, SC-8 · **ISO 27001:** A.8.24, A.8.5

### 🔴 Volcado de las colmenas SAM, SYSTEM y SECURITY

`cred_001_volcado_colmenas_registro.yml`

Con SAM y SYSTEM se obtienen los hashes de las cuentas locales sin tocar LSASS, y con SECURITY salen los secretos LSA: contrasenas de cuentas de servicio en claro y la clave que descifra las credenciales cacheadas. Es la via silenciosa cuando el EDR protege lsass.exe, porque solo intervienen binarios firmados de Windows. Ninguna tarea de administracion normal exporta esas tres colmenas concretas a un fichero.

**Lo que hay que descartar primero:** Exportacion de una rama del registro para diagnosticar una aplicacion, que apunta a HKLM\Software o a HKCU y no a las colmenas de seguridad, por lo que basta con revisar la rama de destino

**Origen:** `process_creation / windows` · **ATT&CK:** [T1003.002](https://attack.mitre.org/techniques/T1003/002/), [T1003.004](https://attack.mitre.org/techniques/T1003/004/) · **NIST:** AC-6, IA-5 · **ISO 27001:** A.5.17, A.8.5

### 🟠 Acceso a los almacenes de credenciales del navegador

`cred_002_credenciales_navegador.yml`

El navegador concentra en unos pocos ficheros conocidos las contrasenas guardadas, las cookies de sesion y los tokens de acceso. Robar la cookie vale mas que robar la contrasena, porque la sesion ya paso el segundo factor y se reutiliza tal cual desde otro equipo. El propio navegador abre esos ficheros con su proceso y nunca por linea de comandos, asi que copiarlos o comprimirlos desde una shell no tiene lectura legitima.

**Lo que hay que descartar primero:** Herramientas de migracion de perfil de usuario que copian la carpeta User Data completa durante una renovacion de equipo, que se distinguen por el proceso padre y deben ir a lista de excepciones por ruta del binario

**Origen:** `process_creation / windows` · **ATT&CK:** [T1539](https://attack.mitre.org/techniques/T1539/), [T1555.003](https://attack.mitre.org/techniques/T1555/003/) · **NIST:** IA-2, IA-5, SC-23 · **ISO 27001:** A.5.17, A.8.5

### 🔴 Abuso de DPAPI - masterkeys y clave de respaldo del dominio

`cred_003_abuso_dpapi.yml`

DPAPI cifra las credenciales guardadas de navegadores, RDP, Wi-Fi y del Administrador de credenciales. Con la masterkey del usuario se abre su boveda; con la clave de respaldo del dominio, que se extrae una sola vez de un DC, se abre la de cualquier usuario del dominio y para siempre, porque esa clave no rota ni se puede revocar. Ninguna aplicacion legitima la exporta, y las masterkeys las lee el propio LSASS, no una linea de comandos.

**Lo que hay que descartar primero:** Herramientas de migracion de perfil o de recuperacion de contrasenas del propio equipo de puesto, que deben ejecutarse con una cuenta de servicio conocida y desde una ruta firmada en lista de excepciones

**Origen:** `process_creation / windows` · **ATT&CK:** [T1003.004](https://attack.mitre.org/techniques/T1003/004/), [T1555](https://attack.mitre.org/techniques/T1555/) · **NIST:** AC-6, IA-5 · **ISO 27001:** A.5.17, A.8.5

### 🟠 Descenso de version a WDigest para cachear credenciales en claro

`cred_004_descenso_wdigest.yml`

Desde Windows 8.1 WDigest ya no guarda la contrasena en claro en memoria, salvo que UseLogonCredential valga 1. Escribir ese valor no roba nada por si solo: prepara el terreno para que el siguiente inicio de sesion, idealmente el de un administrador, deje la contrasena legible en LSASS, asi que la alerta llega antes que el volcado. Lo mismo vale para apagar RunAsPPL o Credential Guard: ningun producto vigente lo necesita.

**Lo que hay que descartar primero:** Aplicacion antigua que exige autenticacion digest y cuenta con una excepcion documentada, que debe acotarse a los servidores concretos que la publican y revisarse en cada renovacion

**Origen:** `registry_event / windows` · **ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/), [T1112](https://attack.mitre.org/techniques/T1112/) · **NIST:** AC-6, CM-5, CM-6, IA-5 · **ISO 27001:** A.5.17, A.8.5, A.8.9

### 🟠 Robo de ficheros de credenciales de nube y de SSH

`cred_005_credenciales_nube_ssh.yml`

Las claves de AWS, Azure, GCP, Kubernetes y SSH viven en ficheros de texto dentro del perfil del usuario, casi nunca caducan y no pasan por el segundo factor. Un solo fichero copiado convierte un puesto comprometido en acceso persistente a la infraestructura, y ese acceso ya se ejerce fuera del alcance del EDR. Los clientes legitimos leen esos ficheros desde su propio proceso, no con type, copy ni Compress-Archive.

**Lo que hay que descartar primero:** Scripts de despliegue y agentes de integracion continua que copian el fichero de credenciales al espacio de trabajo, que se identifican por proceso padre y cuenta de servicio y deben ir a lista de excepciones por host

**Origen:** `process_creation / windows` · **ATT&CK:** [T1552.001](https://attack.mitre.org/techniques/T1552/001/), [T1552.004](https://attack.mitre.org/techniques/T1552/004/) · **NIST:** IA-5, SC-28 · **ISO 27001:** A.5.17

### 🟠 Acceso a bases de datos de gestores de contrasenas

`cred_006_gestores_contrasenas.yml`

Una base de KeePass o el almacen local de 1Password o Bitwarden concentra en un unico fichero las credenciales que el usuario considera mas sensibles, casi siempre las de administracion. El atacante no necesita romper nada en el equipo: se lleva el fichero y ataca la clave maestra fuera de la red, sin ruido y sin limite de intentos. El gestor abre su base desde su propio proceso, nunca por copia ni por busqueda recursiva.

**Lo que hay que descartar primero:** Copia de seguridad del perfil del usuario o sincronizacion de la base a una carpeta de red, que siempre la hace el mismo proceso de respaldo y no un interprete de comandos, por lo que se filtra por ruta del binario padre

**Origen:** `process_creation / windows` · **ATT&CK:** [T1555.005](https://attack.mitre.org/techniques/T1555/005/) · **NIST:** IA-5 · **ISO 27001:** A.5.17, A.8.5

### 🟠 Volcado de credenciales cacheadas y del Administrador de credenciales de Windows

`cred_007_credenciales_cacheadas_vault.yml`

Windows conserva los ultimos inicios de sesion de dominio como hashes MSCache y las credenciales guardadas del usuario en la boveda, que se descifra con DPAPI dentro de esa misma sesion. Es a lo que recurre el atacante cuando no hay ninguna sesion privilegiada viva que volcar de LSASS: le permite seguir moviendose aunque el administrador ya se haya desconectado. Enumerar la boveda entera no es algo que haga un usuario normal.

**Lo que hay que descartar primero:** Diagnostico de soporte sobre un acceso fallido a un recurso de red, donde cmdkey /list se usa de forma puntual y siempre asociado a un ticket abierto en ese equipo

**Origen:** `process_creation / windows` · **ATT&CK:** [T1003.005](https://attack.mitre.org/techniques/T1003/005/), [T1555.004](https://attack.mitre.org/techniques/T1555/004/) · **NIST:** AC-6, IA-5 · **ISO 27001:** A.5.17, A.8.5

### 🟡 Proceso del sistema con conexion saliente inusual

`net_rare_process_external_conn.yml`

Binarios que no suelen hacer red (rundll32/regsvr32/mshta) conectando fuera.

**Lo que hay que descartar primero:** Casos legitimos puntuales

**Origen:** `network_connection / windows` · **ATT&CK:** [T1071.001](https://attack.mitre.org/techniques/T1071/001/) · **NIST:** SC-7, SI-4 · **ISO 27001:** A.8.20, A.8.23

### 🟡 Descarga con BITSAdmin

`proc_bitsadmin_transfer.yml`

bitsadmin /transfer para descargar ficheros (LOLBin de C2).

**Lo que hay que descartar primero:** Actualizaciones legitimas via BITS

**Origen:** `process_creation / windows` · **ATT&CK:** [T1197](https://attack.mitre.org/techniques/T1197/)

### 🟠 Certutil usado para descargar o decodificar

`proc_certutil_download_decode.yml`

certutil -urlcache (descarga) o -decode (LOLBin de descarga/ofuscacion).

**Lo que hay que descartar primero:** Uso administrativo legitimo de certutil (poco comun)

**Origen:** `process_creation / windows` · **ATT&CK:** [T1105](https://attack.mitre.org/techniques/T1105/), [T1140](https://attack.mitre.org/techniques/T1140/)

### 🟠 Manipulacion de Windows Defender

`proc_defender_tamper.yml`

Set-MpPreference -Disable... o exclusiones, evasion de defensas.

**Lo que hay que descartar primero:** Administradores que ajustan Defender puntualmente

**Origen:** `process_creation / windows` · **ATT&CK:** [T1562.001](https://attack.mitre.org/techniques/T1562/001/)

### 🔴 Volcado de LSASS via comsvcs MiniDump

`proc_lsass_comsvcs_minidump.yml`

rundll32 comsvcs.dll MiniDump sobre LSASS para robar credenciales.

**Lo que hay que descartar primero:** Ninguno esperado

**Origen:** `process_creation / windows` · **ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/)

### 🔴 Indicadores de Mimikatz en linea de comandos

`proc_mimikatz_cmdline.yml`

Comandos tipicos de Mimikatz (sekurlsa, logonpasswords, etc.).

**Lo que hay que descartar primero:** Ninguno esperado

**Origen:** `process_creation / windows` · **ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/)

### 🟠 Ejecucion sospechosa de mshta

`proc_mshta_execution.yml`

mshta ejecutando HTA remoto o javascript/vbscript inline.

**Lo que hay que descartar primero:** Aplicaciones legacy que usan HTA

**Origen:** `process_creation / windows` · **ATT&CK:** [T1218.005](https://attack.mitre.org/techniques/T1218/005/)

### 🟡 Creacion de cuenta local

`proc_net_user_add.yml`

net user /add y net localgroup administrators /add.

**Lo que hay que descartar primero:** Alta legitima de usuarios por IT

**Origen:** `process_creation / windows` · **ATT&CK:** [T1136.001](https://attack.mitre.org/techniques/T1136/001/) · **NIST:** AC-2 · **ISO 27001:** A.5.16

### 🟠 Documento de Office lanzando shell

`proc_office_spawning_shell.yml`

Word/Excel/Outlook creando cmd/powershell/wscript: tipico de phishing con macros.

**Lo que hay que descartar primero:** Plantillas corporativas con macros legitimas

**Origen:** `process_creation / windows` · **ATT&CK:** [T1204.002](https://attack.mitre.org/techniques/T1204/002/), [T1566.001](https://attack.mitre.org/techniques/T1566/001/) · **NIST:** AT-2, SI-3, SI-8 · **ISO 27001:** A.6.3, A.8.23, A.8.7

### 🟠 Cradle de descarga en PowerShell

`proc_powershell_download_cradle.yml`

PowerShell descargando y ejecutando codigo desde red (DownloadString/IEX).

**Lo que hay que descartar primero:** Instaladores legitimos que usan PowerShell

**Origen:** `process_creation / windows` · **ATT&CK:** [T1059.001](https://attack.mitre.org/techniques/T1059/001/), [T1105](https://attack.mitre.org/techniques/T1105/)

### 🟠 PowerShell con comando codificado

`proc_powershell_encoded.yml`

Detecta powershell.exe con -EncodedCommand/-enc, comun en cargas ofuscadas.

**Lo que hay que descartar primero:** Scripts de administracion codificados (raro)

**Origen:** `process_creation / windows` · **ATT&CK:** [T1059.001](https://attack.mitre.org/techniques/T1059/001/)

### 🟠 Regsvr32 ejecutando scriptlet remoto (Squiblydoo)

`proc_regsvr32_scriptlet.yml`

regsvr32 /i:http ... scrobj.dll para ejecutar codigo remoto evadiendo controles.

**Lo que hay que descartar primero:** Ninguno esperado

**Origen:** `process_creation / windows` · **ATT&CK:** [T1218.010](https://attack.mitre.org/techniques/T1218/010/)

### 🟡 Creacion de tarea programada via schtasks

`proc_scheduled_task_create.yml`

schtasks /create, tecnica comun de persistencia y ejecucion.

**Lo que hay que descartar primero:** Software legitimo que crea tareas

**Origen:** `process_creation / windows` · **ATT&CK:** [T1053.005](https://attack.mitre.org/techniques/T1053/005/)

### 🟡 Creacion de servicio via sc.exe

`proc_service_create_scexe.yml`

sc.exe create, usado para persistencia y movimiento lateral.

**Lo que hay que descartar primero:** Instalacion legitima de servicios

**Origen:** `process_creation / windows` · **ATT&CK:** [T1543.003](https://attack.mitre.org/techniques/T1543/003/) · **NIST:** CM-5, CM-6 · **ISO 27001:** A.8.9

### 🔴 Borrado de instantaneas (anti-recuperacion)

`proc_vssadmin_delete_shadows.yml`

vssadmin/wmic delete shadows, tipico de ransomware antes de cifrar.

**Lo que hay que descartar primero:** Mantenimiento legitimo (muy raro)

**Origen:** `process_creation / windows` · **ATT&CK:** [T1490](https://attack.mitre.org/techniques/T1490/)

### 🟠 Borrado de registros de eventos

`proc_wevtutil_clear_logs.yml`

wevtutil cl / Clear-EventLog, anti-forense (T1070.001).

**Lo que hay que descartar primero:** Ninguno esperado en produccion

**Origen:** `process_creation / windows` · **ATT&CK:** [T1070.001](https://attack.mitre.org/techniques/T1070/001/)

### 🟡 Ejecucion via WMIC process call create

`proc_wmic_process_call_create.yml`

wmic process call create, ejecucion y a veces movimiento lateral.

**Lo que hay que descartar primero:** Scripts de administracion

**Origen:** `process_creation / windows` · **ATT&CK:** [T1047](https://attack.mitre.org/techniques/T1047/) · **NIST:** AC-17, CM-7 · **ISO 27001:** A.8.20

### 🟡 Persistencia por clave Run (registro)

`reg_run_key_persistence.yml`

Escritura en CurrentVersion\Run/RunOnce para autoarranque.

**Lo que hay que descartar primero:** Software legitimo que se registra para autoarranque

**Origen:** `registry_set / windows` · **ATT&CK:** [T1547.001](https://attack.mitre.org/techniques/T1547/001/)

### 🟠 Kerberoasting - solicitud masiva de tickets de servicio con RC4

`soc_ad_001_kerberoasting.yml`

Detecta solicitudes de ticket de servicio (TGS) cifradas con RC4 contra cuentas de servicio. Un atacante pide el TGS de cuentas con SPN para crackear su contrasena fuera de linea. El cifrado RC4 (0x17) es la senal: los clientes modernos negocian AES, asi que un RC4 solicitado por un puesto de usuario es anomalo.

**Lo que hay que descartar primero:** Aplicaciones antiguas que solo soportan RC4

**Origen:** `windows / security` · **ATT&CK:** [T1558.003](https://attack.mitre.org/techniques/T1558/003/) · **NIST:** IA-2, IA-5 · **ISO 27001:** A.8.5

### 🟠 AS-REP Roasting - peticion sin preautenticacion Kerberos

`soc_ad_002_asrep_roasting.yml`

Detecta peticiones de autenticacion Kerberos (AS-REQ) sobre cuentas que tienen deshabilitada la preautenticacion. El atacante recibe material cifrado con la contrasena del usuario y lo craquea sin tocar el dominio. Se apoya en el evento 4768 con PreAuthType 0.

**Lo que hay que descartar primero:** Cuentas de servicio antiguas con la preautenticacion deshabilitada de forma legitima

**Origen:** `windows / security` · **ATT&CK:** [T1558.004](https://attack.mitre.org/techniques/T1558/004/) · **NIST:** IA-2, IA-5 · **ISO 27001:** A.8.5

### 🔴 DCSync - replicacion de directorio desde un equipo que no es DC

`soc_ad_003_dcsync.yml`

Detecta el uso de los permisos de replicacion de Active Directory para extraer hashes de contrasena, la tecnica que usa mimikatz lsadump::dcsync. Se identifica por el acceso a los GUID de extended right de replicacion en el evento 4662. Si el solicitante no es una cuenta de equipo controlador de dominio, es un ataque.

**Lo que hay que descartar primero:** Herramientas de sincronizacion de directorio como Entra Connect, que deben estar en la lista de excepciones

**Origen:** `windows / security` · **ATT&CK:** [T1003.006](https://attack.mitre.org/techniques/T1003/006/) · **NIST:** AC-6, IA-5 · **ISO 27001:** A.5.17, A.8.5

### 🔴 Indicio de Golden Ticket - TGS de krbtgt con cifrado degradado

`soc_ad_004_golden_ticket.yml`

Un Golden Ticket es un TGT forjado con el hash de krbtgt. Mimikatz lo genera por defecto con RC4, asi que una peticion de servicio que involucra a krbtgt con cifrado 0x17 desde un equipo que no es DC es sospechosa. Complementar siempre con revision del ticket lifetime, que en los tickets forjados suele ser de 10 anos.

**Lo que hay que descartar primero:** Entornos con nivel funcional de dominio anterior a 2008

**Origen:** `windows / security` · **ATT&CK:** [T1558.001](https://attack.mitre.org/techniques/T1558/001/) · **NIST:** IA-2, IA-5 · **ISO 27001:** A.8.5

### 🔴 Herramienta de abuso de Kerberos ejecutada

`soc_ad_005_herramientas_kerberos.yml`

Deteccion por linea de comandos de las utilidades habituales de abuso de Kerberos: Rubeus, mimikatz, kekeo e impacket. Complementa las detecciones basadas en eventos de seguridad, que se pueden evadir con implementaciones propias, y cubre el caso en que el binario se ha renombrado gracias a OriginalFileName.

**Lo que hay que descartar primero:** Ejercicios de red team autorizados, que deben estar documentados y acotados en el tiempo

**Origen:** `process_creation / windows` · **ATT&CK:** [T1003](https://attack.mitre.org/techniques/T1003/), [T1558](https://attack.mitre.org/techniques/T1558/) · **NIST:** AC-6, IA-2, IA-5 · **ISO 27001:** A.5.17, A.8.5

### 🟠 Pass-the-Hash y Overpass-the-Hash

`soc_ad_006_pass_the_hash.yml`

El logon de tipo 9 (NewCredentials) generado por el proceso seclogo con paquete Negotiate es la firma clasica de "runas /netonly" usado por mimikatz sekurlsa::pth. Tambien se cubre el logon de red con NTLM desde una cuenta privilegiada, que en un dominio con Kerberos disponible no deberia producirse.

**Lo que hay que descartar primero:** Uso legitimo de runas /netonly por parte de administradores, que conviene inventariar

**Origen:** `windows / security` · **ATT&CK:** [T1550.002](https://attack.mitre.org/techniques/T1550/002/) · **NIST:** AC-3, IA-2 · **ISO 27001:** A.8.5

### 🟡 Enumeracion de Active Directory - BloodHound y comandos de reconocimiento

`soc_ad_007_enumeracion_dominio.yml`

Detecta el reconocimiento de dominio previo al movimiento lateral: ejecucion de SharpHound o AzureHound, y las secuencias de comandos net y dsquery que un atacante usa para mapear grupos privilegiados, equipos y relaciones de confianza.

**Lo que hay que descartar primero:** Scripts de inventario y auditoria del propio equipo de sistemas

**Origen:** `process_creation / windows` · **ATT&CK:** [T1069.002](https://attack.mitre.org/techniques/T1069/002/), [T1087.002](https://attack.mitre.org/techniques/T1087/002/) · **NIST:** AC-2 · **ISO 27001:** A.5.16, A.5.18

### 🟠 Ejecucion remota tipo PsExec

`soc_ad_008_psexec_remoto.yml`

Detecta la instalacion del servicio que crean PsExec y sus clones (paexec, csexec, remcom, impacket smbexec) para ejecutar codigo en un equipo remoto. Se apoya en el evento 7045 del log de sistema, que registra el alta del servicio.

**Lo que hay que descartar primero:** Uso administrativo de PsExec por parte del equipo de sistemas, que conviene restringir a equipos bastion

**Origen:** `windows / system` · **ATT&CK:** [T1569.002](https://attack.mitre.org/techniques/T1569/002/) · **NIST:** CM-7 · **ISO 27001:** A.8.9

### 🟠 Ejecucion remota por WMI o WinRM

`soc_ad_009_wmi_winrm_remoto.yml`

Detecta procesos hijos de WmiPrvSE.exe o de wsmprovhost.exe, que son los procesos servidores de WMI y WinRM. Un interprete de comandos naciendo de ellos significa que alguien esta ejecutando codigo en el equipo desde la red.

**Lo que hay que descartar primero:** Herramientas de gestion como SCCM o Ansible sobre WinRM, que deben inventariarse

**Origen:** `process_creation / windows` · **ATT&CK:** [T1021.006](https://attack.mitre.org/techniques/T1021/006/), [T1047](https://attack.mitre.org/techniques/T1047/) · **NIST:** AC-17, CM-7, SC-7 · **ISO 27001:** A.6.7, A.8.20

### 🟠 Modificacion sospechosa de directiva de grupo

`soc_ad_010_abuso_gpo.yml`

Un atacante con control sobre una GPO puede ejecutar codigo en todos los equipos que la aplican. Detecta la ejecucion de herramientas de abuso de GPO y la modificacion de los ficheros de scripts y tareas programadas dentro de SYSVOL.

**Lo que hay que descartar primero:** Administracion legitima de GPO, que deberia hacerse desde la consola y no por linea de comandos

**Origen:** `process_creation / windows` · **ATT&CK:** [T1484.001](https://attack.mitre.org/techniques/T1484/001/) · **NIST:** AC-6, CM-5 · **ISO 27001:** A.8.9

### 🟡 Cuenta de equipo creada por un usuario no administrador

`soc_ad_011_cuenta_equipo_creada.yml`

Por defecto cualquier usuario del dominio puede dar de alta hasta diez equipos (MachineAccountQuota). Esa cuota es el punto de partida de ataques como noPac, sAMAccountName spoofing y la escalada por delegacion basada en recursos. El alta de una cuenta de equipo por un usuario que no es del equipo de sistemas merece revision.

**Lo que hay que descartar primero:** Altas de equipo realizadas por el equipo de sistemas, que deben ir a una lista de excepciones por cuenta

**Origen:** `windows / security` · **ATT&CK:** [T1136.002](https://attack.mitre.org/techniques/T1136/002/) · **NIST:** AC-2 · **ISO 27001:** A.5.16

### 🔴 Abuso de servicios de certificados de Active Directory

`soc_ad_012_abuso_adcs.yml`

Los ataques ESC1 a ESC8 sobre AD CS permiten obtener un certificado que autentica como cualquier usuario, incluido un administrador de dominio. Detecta la ejecucion de las herramientas de abuso y la solicitud de certificados con un SAN que no corresponde al solicitante.

**Lo que hay que descartar primero:** Emision legitima de certificados, que normalmente se hace desde la consola de la CA y no por linea de comandos

**Origen:** `process_creation / windows` · **ATT&CK:** [T1649](https://attack.mitre.org/techniques/T1649/) · **NIST:** IA-5, SC-12 · **ISO 27001:** A.8.24

### 🔴 Volcado de memoria de LSASS

`soc_edr_001_volcado_lsass.yml`

LSASS guarda las credenciales de las sesiones activas. Su volcado es el paso previo casi obligado al movimiento lateral. Detecta las tres vias habituales: herramientas conocidas, el uso de comsvcs.dll MiniDump via rundll32, y el acceso al proceso con permisos de lectura de memoria registrado por Sysmon.

**Lo que hay que descartar primero:** Recogida de volcados por parte de soporte para diagnosticar cuelgues, que deberia ir acompanada de un ticket

**Origen:** `process_creation / windows` · **ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/) · **NIST:** AC-6, IA-5 · **ISO 27001:** A.5.17, A.8.5

### 🟠 Acceso a memoria de LSASS con permisos de lectura

`soc_edr_002_acceso_lsass_sysmon.yml`

Complemento de la deteccion por linea de comandos. Sysmon registra en el evento 10 todo acceso a un proceso; un GrantedAccess de 0x1010, 0x1410 o 0x1438 sobre lsass.exe corresponde a los permisos que necesita un volcado de memoria. Detecta tambien las implementaciones propias que no usan herramientas conocidas.

**Lo que hay que descartar primero:** Agentes de EDR y de inventario que inspeccionan procesos, que deben ir a la lista de excepciones por ruta firmada

**Origen:** `process_access / windows` · **ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/) · **NIST:** AC-6, IA-5 · **ISO 27001:** A.5.17, A.8.5

### 🔴 Destruccion de copias de seguridad y puntos de restauracion

`soc_edr_003_borrado_copias_sombra.yml`

Paso previo al cifrado en practicamente toda familia de ransomware: eliminar las instantaneas de volumen, el catalogo de copias y la recuperacion de arranque para que la victima no pueda recuperarse sin pagar. En un equipo de produccion esto no tiene ningun uso legitimo fuera de una ventana de mantenimiento documentada.

**Lo que hay que descartar primero:** Mantenimiento de disco planificado, que debe estar en ventana y aprobado

**Origen:** `process_creation / windows` · **ATT&CK:** [T1490](https://attack.mitre.org/techniques/T1490/) · **NIST:** CP-10, CP-9 · **ISO 27001:** A.8.13

### 🟠 Defensas de seguridad deshabilitadas

`soc_edr_004_defensas_deshabilitadas.yml`

Detecta la desactivacion de Microsoft Defender, del cortafuegos local, de la auditoria del sistema o de agentes de seguridad. Cubre las tres vias: cmdlets de PowerShell, modificacion de registro y parada de servicio.

**Lo que hay que descartar primero:** Instalacion de otro producto antivirus, que desactiva Defender de forma legitima

**Origen:** `process_creation / windows` · **ATT&CK:** [T1070.001](https://attack.mitre.org/techniques/T1070/001/), [T1562.001](https://attack.mitre.org/techniques/T1562/001/) · **NIST:** AU-11, AU-9, CM-7, SI-3 · **ISO 27001:** A.8.15, A.8.7

### 🟠 LOLBin usado para descargar y ejecutar

`soc_edr_005_lolbins_descarga.yml`

Binarios firmados por Microsoft usados para traer contenido de Internet y ejecutarlo, evitando controles de aplicacion. Cubre certutil, bitsadmin, mshta, regsvr32, curl y el cradle clasico de PowerShell.

**Lo que hay que descartar primero:** Scripts de despliegue y de instalacion internos, que conviene mover a un repositorio firmado

**Origen:** `process_creation / windows` · **ATT&CK:** [T1105](https://attack.mitre.org/techniques/T1105/), [T1140](https://attack.mitre.org/techniques/T1140/), [T1197](https://attack.mitre.org/techniques/T1197/), [T1218](https://attack.mitre.org/techniques/T1218/), [T1218.005](https://attack.mitre.org/techniques/T1218/005/), [T1218.010](https://attack.mitre.org/techniques/T1218/010/) · **NIST:** CM-7, SC-7, SI-3 · **ISO 27001:** A.8.7

### 🟠 PowerShell codificado u ofuscado

`soc_edr_006_powershell_ofuscado.yml`

Detecta las tecnicas habituales de ofuscacion en PowerShell: comando codificado en base64, reconstruccion de cadenas, ejecucion desde memoria y bypass de politica de ejecucion. Rara vez hay una razon legitima para lanzar PowerShell con -enc en un puesto de usuario.

**Lo que hay que descartar primero:** Herramientas de gestion que invocan PowerShell codificado, como algunas tareas de SCCM

**Origen:** `process_creation / windows` · **ATT&CK:** [T1027](https://attack.mitre.org/techniques/T1027/), [T1059.001](https://attack.mitre.org/techniques/T1059/001/) · **NIST:** CM-7, SI-3 · **ISO 27001:** A.8.7

### 🔴 Cifrado masivo de ficheros por ransomware

`soc_edr_007_cifrado_masivo.yml`

Detecta la fase de impacto: la creacion o renombrado de un gran numero de ficheros con extensiones de ransomware conocidas, o la aparicion de una nota de rescate. Requiere agregacion por equipo, que es lo que aporta el bloque de correlacion del SIEM sobre esta regla base.

**Lo que hay que descartar primero:** Herramientas de cifrado legitimo que usan la extension .encrypted

**Origen:** `file_event / windows` · **ATT&CK:** [T1486](https://attack.mitre.org/techniques/T1486/) · **NIST:** CP-10, CP-9, IR-4 · **ISO 27001:** A.5.26, A.8.13

### 🟠 Tarea programada sospechosa

`soc_edr_008_persistencia_tarea.yml`

Detecta el alta de tareas programadas cuyo comando apunta a un interprete, a una ruta de escritura de usuario o a una descarga. Es una de las formas de persistencia mas usadas porque sobrevive al reinicio y pasa desapercibida entre las tareas del sistema.

**Lo que hay que descartar primero:** Instaladores de software que crean tareas de actualizacion, que conviene inventariar por editor

**Origen:** `process_creation / windows` · **ATT&CK:** [T1053.005](https://attack.mitre.org/techniques/T1053/005/) · **NIST:** CM-5, CM-7 · **ISO 27001:** A.8.9

### 🟠 Persistencia por claves de arranque del registro

`soc_edr_009_persistencia_registro.yml`

Escritura en las claves Run, RunOnce, Winlogon y de servicios que se ejecutan al iniciar sesion. Se filtra por rutas de escritura de usuario e interpretes, que es donde se concentra el abuso.

**Lo que hay que descartar primero:** Software legitimo que arranca desde AppData, como algunos clientes de mensajeria y navegadores

**Origen:** `registry_event / windows` · **ATT&CK:** [T1547.001](https://attack.mitre.org/techniques/T1547/001/) · **NIST:** CM-5, CM-6 · **ISO 27001:** A.8.9

### 🟠 Inyeccion de codigo en proceso remoto

`soc_edr_010_inyeccion_procesos.yml`

Detecta la creacion de hilos remotos hacia procesos de confianza, tecnica que usan los cargadores de malware y los frameworks de C2 para ejecutar en un proceso legitimo y evadir el control de aplicaciones.

**Lo que hay que descartar primero:** Depuradores y herramientas de perfilado, poco habituales en un puesto de usuario

**Origen:** `create_remote_thread / windows` · **ATT&CK:** [T1055](https://attack.mitre.org/techniques/T1055/) · **NIST:** SI-3, SI-7 · **ISO 27001:** A.8.7

### 🔴 Named pipe caracteristico de framework de C2

`soc_edr_011_pipe_c2.yml`

Cobalt Strike, Sliver y otros frameworks usan named pipes con patrones reconocibles para la comunicacion entre el beacon y sus modulos. Detecta los nombres por defecto, que siguen apareciendo en una parte importante de los despliegues reales.

**Lo que hay que descartar primero:** Muy pocos, pero conviene revisar los pipes de software propio antes de dar la regla por buena

**Origen:** `pipe_created / windows` · **ATT&CK:** [T1071](https://attack.mitre.org/techniques/T1071/) · **NIST:** SC-7, SI-4 · **ISO 27001:** A.8.20, A.8.23

### 🟡 Ejecucion de binario desde una ruta de escritura de usuario

`soc_edr_012_ejecucion_desde_temp.yml`

Un ejecutable lanzado desde Temp, AppData, la papelera o un directorio publico es una senal de bajo nivel pero de alta cobertura: es el patron de casi toda entrega inicial, desde el adjunto de correo hasta el instalador troyanizado. Pensada para correlar, no para alertar sola.

**Lo que hay que descartar primero:** Instaladores que se descomprimen en Temp antes de ejecutarse, que es el motivo de tratar esta regla como senal de correlacion

**Origen:** `process_creation / windows` · **ATT&CK:** [T1204.002](https://attack.mitre.org/techniques/T1204/002/) · **NIST:** AT-2, SI-3 · **ISO 27001:** A.8.7

---

## Linux

**10 reglas** · auditd y Falco

Servidores. Menos poblado que Windows, y por eso lo que salta suele ser mas significativo.

### 🟠 Ejecucion de payload codificado en base64

`lin_base64_decode_exec.yml`

base64 -d tuberia a shell, ofuscacion de comandos.

**Lo que hay que descartar primero:** Scripts legitimos que decodifican datos

**Origen:** `process_creation / linux` · **ATT&CK:** [T1059.004](https://attack.mitre.org/techniques/T1059/004/), [T1140](https://attack.mitre.org/techniques/T1140/) · **NIST:** CM-7, SI-3 · **ISO 27001:** A.8.7

### 🟡 Permisos de ejecucion en /tmp o /dev/shm

`lin_chmod_tmp_exec.yml`

chmod +x sobre binarios soltados en directorios de escritura mundial.

**Lo que hay que descartar primero:** Compilacion/instalacion legitima en /tmp

**Origen:** `process_creation / linux` · **ATT&CK:** [T1222.002](https://attack.mitre.org/techniques/T1222/002/) · **NIST:** AC-3 · **ISO 27001:** A.8.3

### 🟡 Persistencia por cron

`lin_cron_persistence.yml`

Edicion de crontab o escritura en /etc/cron*.

**Lo que hay que descartar primero:** Tareas programadas legitimas

**Origen:** `process_creation / linux` · **ATT&CK:** [T1053.003](https://attack.mitre.org/techniques/T1053/003/) · **NIST:** CM-5, CM-7 · **ISO 27001:** A.8.9

### 🟡 Deshabilitar historial de shell (anti-forense)

`lin_disable_history.yml`

unset HISTFILE / HISTSIZE=0 / ln -sf /dev/null ~/.bash_history.

**Lo que hay que descartar primero:** Preferencias legitimas de usuarios avanzados

**Origen:** `process_creation / linux` · **ATT&CK:** [T1070.003](https://attack.mitre.org/techniques/T1070/003/) · **NIST:** AU-11, AU-9 · **ISO 27001:** A.8.15

### 🟠 Descarga tuberia a shell (curl|bash)

`lin_download_pipe_shell.yml`

curl/wget de un script ejecutado directamente por la shell.

**Lo que hay que descartar primero:** Instaladores oficiales que usan este patron (evaluar contexto)

**Origen:** `process_creation / linux` · **ATT&CK:** [T1059.004](https://attack.mitre.org/techniques/T1059/004/), [T1105](https://attack.mitre.org/techniques/T1105/) · **NIST:** CM-7, SC-7, SI-3 · **ISO 27001:** A.8.7

### 🔴 Modificacion de ld.so.preload (rootkit)

`lin_ld_preload.yml`

Escritura en /etc/ld.so.preload, secuestro del enlazador dinamico.

**Lo que hay que descartar primero:** Ninguno esperado

**Origen:** `process_creation / linux` · **ATT&CK:** [T1574.006](https://attack.mitre.org/techniques/T1574/006/) · **NIST:** CM-5, SI-7 · **ISO 27001:** A.8.9

### 🟠 Lectura de /etc/shadow

`lin_read_shadow.yml`

Acceso al fichero de hashes de contrasenas (credential access).

**Lo que hay que descartar primero:** Herramientas de auditoria autorizadas

**Origen:** `process_creation / linux` · **ATT&CK:** [T1003.008](https://attack.mitre.org/techniques/T1003/008/) · **NIST:** AC-6, IA-5 · **ISO 27001:** A.5.17, A.8.5

### 🟠 Shell inversa (bash /dev/tcp)

`lin_reverse_shell.yml`

Patron de reverse shell: bash -i >& /dev/tcp/host/port.

**Lo que hay que descartar primero:** Diagnostico de red muy puntual

**Origen:** `process_creation / linux` · **ATT&CK:** [T1059.004](https://attack.mitre.org/techniques/T1059/004/) · **NIST:** CM-7, SI-3 · **ISO 27001:** A.8.7

### 🟠 Adicion de clave SSH (authorized_keys)

`lin_ssh_authorized_keys.yml`

Escritura en authorized_keys para acceso persistente.

**Lo que hay que descartar primero:** Aprovisionamiento legitimo de claves

**Origen:** `process_creation / linux` · **ATT&CK:** [T1098.004](https://attack.mitre.org/techniques/T1098/004/) · **NIST:** AC-2, AC-6 · **ISO 27001:** A.5.16, A.5.18

### 🟡 Creacion o modificacion de cuenta

`lin_useradd.yml`

useradd/usermod para persistencia o escalada.

**Lo que hay que descartar primero:** Alta legitima de usuarios

**Origen:** `process_creation / linux` · **ATT&CK:** [T1136.001](https://attack.mitre.org/techniques/T1136/001/) · **NIST:** AC-2 · **ISO 27001:** A.5.16

---

## macOS

**8 reglas** · Endpoint Security Framework

Parque pequeno y mecanismos propios: launchd, TCC, Gatekeeper, llavero.

### 🟠 Borrado de registros del sistema en macOS

`mac_borrado_de_registros.yml`

Borrado del Unified Log, de los ASL heredados o del historial de shell. Es actividad anti-forense: se ejecuta despues del objetivo, no antes, asi que verlo suele significar que ya ha pasado algo.

**Lo que hay que descartar primero:** Limpieza de disco por scripts de mantenimiento, que deberian estar inventariados

**Origen:** `process_creation / macos` · **ATT&CK:** [T1070.002](https://attack.mitre.org/techniques/T1070/002/), [T1070.003](https://attack.mitre.org/techniques/T1070/003/) · **NIST:** AU-11, AU-9 · **ISO 27001:** A.8.15

### 🟠 Descarga y ejecucion directa en macOS

`mac_descarga_y_ejecucion.yml`

Patron curl o wget encadenado a un interprete sin escribir el codigo en disco. Evita la deteccion basada en fichero y es la primera fase de casi todos los instaladores maliciosos de macOS distribuidos por publicidad enganosa.

**Lo que hay que descartar primero:** Instaladores de herramientas de desarrollo como Homebrew o rustup

**Origen:** `process_creation / macos` · **ATT&CK:** [T1059.004](https://attack.mitre.org/techniques/T1059/004/), [T1105](https://attack.mitre.org/techniques/T1105/) · **NIST:** CM-7, SC-7, SI-3 · **ISO 27001:** A.8.7

### 🟠 Gatekeeper deshabilitado o cuarentena eliminada

`mac_gatekeeper_deshabilitado.yml`

Gatekeeper bloquea binarios sin firmar o sin notarizar. Desactivarlo por completo, o quitar el atributo com.apple.quarantine a un fichero descargado, es el paso previo habitual para ejecutar un binario que el sistema rechazaria.

**Lo que hay que descartar primero:** Equipos de desarrollo con politica propia, que deberian estar en una UO aparte

**Origen:** `process_creation / macos` · **ATT&CK:** [T1553.001](https://attack.mitre.org/techniques/T1553/001/), [T1562.001](https://attack.mitre.org/techniques/T1562/001/) · **NIST:** AU-9, CM-14, CM-7, SI-3, SI-7 · **ISO 27001:** A.8.7

### 🟠 AppleScript ejecutando shell o descargando codigo

`mac_osascript_sospechoso.yml`

osascript permite ejecutar shell desde AppleScript y es la via habitual por la que un instalador malicioso de macOS pide credenciales al usuario o lanza la segunda fase. Se buscan las combinaciones que no aparecen en automatizacion legitima: do shell script, descargas y peticiones de contrasena de administrador.

**Lo que hay que descartar primero:** Scripts de automatizacion internos, que deberian estar firmados y en rutas conocidas

**Origen:** `process_creation / macos` · **ATT&CK:** [T1059.002](https://attack.mitre.org/techniques/T1059/002/) · **NIST:** CM-7, SI-3 · **ISO 27001:** A.8.7

### 🟡 Persistencia por LaunchAgent o LaunchDaemon

`mac_persistencia_launchagent.yml`

Detecta la escritura de un fichero .plist en las rutas que launchd carga automaticamente al arrancar el sistema o al iniciar sesion el usuario. Es el mecanismo de persistencia mas usado en macOS, tanto por adware como por implantes de acceso remoto.

**Lo que hay que descartar primero:** Instaladores .pkg legitimos, que normalmente van precedidos de un evento de installer

**Origen:** `file_event / macos` · **ATT&CK:** [T1543.001](https://attack.mitre.org/techniques/T1543/001/), [T1543.004](https://attack.mitre.org/techniques/T1543/004/) · **NIST:** CM-5, CM-6 · **ISO 27001:** A.8.9

### 🟠 Manipulacion de la base de datos TCC

`mac_tcc_manipulacion.yml`

TCC es el control de acceso a camara, microfono, disco completo y grabacion de pantalla. Escribir directamente en TCC.db o resetear permisos con tccutil deja al atacante conceder a su propio binario permisos que el usuario nunca aprobo.

**Lo que hay que descartar primero:** Depuracion de permisos por parte de soporte, que deberia ir con ticket

**Origen:** `process_creation / macos` · **ATT&CK:** [T1548.006](https://attack.mitre.org/techniques/T1548/006/) · **NIST:** AC-6 · **ISO 27001:** A.8.2

### 🟠 Creacion de usuario local u oculto en macOS

`mac_usuario_oculto_creado.yml`

Alta de una cuenta local con dscl o sysadminctl. El indicador de mayor valor es IsHidden, que oculta la cuenta de la pantalla de inicio de sesion: no hay razon administrativa habitual para crear una cuenta invisible.

**Lo que hay que descartar primero:** Aprovisionamiento por MDM, que deberia venir de un proceso de Jamf o similar

**Origen:** `process_creation / macos` · **ATT&CK:** [T1136.001](https://attack.mitre.org/techniques/T1136/001/) · **NIST:** AC-2 · **ISO 27001:** A.5.16

### 🔴 Acceso o volcado del llavero de macOS

`mac_volcado_llavero.yml`

El llavero guarda credenciales de navegador, wifi, certificados y tokens. Un volcado con la utilidad security, o la lectura directa del fichero login.keychain-db, es un indicador claro de robo de credenciales.

**Lo que hay que descartar primero:** Copias de seguridad o migraciones asistidas, poco frecuentes y en ventana

**Origen:** `process_creation / macos` · **ATT&CK:** [T1555.001](https://attack.mitre.org/techniques/T1555/001/) · **NIST:** IA-5 · **ISO 27001:** A.5.17, A.8.5

---

## Contenedores y Kubernetes

**8 reglas** · Auditoria del API server y runtime

Superficie nueva con reglas propias: el escape del contenedor no se parece a la escalada clasica.

### 🔴 Escape de contenedor hacia los namespaces del host

`cont_escape_a_namespaces_host.yml`

nsenter contra el PID 1, chroot sobre un /host montado o la escritura de release_agent en cgroups son las tres rutas clasicas para salir de un contenedor privilegiado y ejecutar en el nodo.

**Lo que hay que descartar primero:** Herramientas de depuracion de nodos como kubectl debug, que deberian ser puntuales y trazables

**Origen:** `process_creation / linux` · **ATT&CK:** [T1611](https://attack.mitre.org/techniques/T1611/) · **NIST:** AC-6, SC-39 · **ISO 27001:** A.8.2

### 🔴 Acceso al socket del runtime de contenedores

`cont_socket_runtime_accedido.yml`

Quien puede hablar con /var/run/docker.sock o con el socket de containerd puede crear un contenedor privilegiado y montar el disco del host. Es el escape de contenedor mas comun y no requiere ningun exploit.

**Lo que hay que descartar primero:** Runners de CI que construyen imagenes montando el socket, practica desaconsejada pero habitual

**Origen:** `process_creation / linux` · **ATT&CK:** [T1610](https://attack.mitre.org/techniques/T1610/), [T1611](https://attack.mitre.org/techniques/T1611/) · **NIST:** AC-6, CM-7, SC-39 · **ISO 27001:** A.8.2, A.8.9

### 🟠 Contenedor con capacidades de kernel peligrosas

`k8s_capacidades_peligrosas.yml`

Anadir SYS_ADMIN, SYS_PTRACE, SYS_MODULE o NET_ADMIN a un contenedor le da parte de lo que tendria en modo privilegiado sin marcar la bandera privileged, que es justo lo que se busca al evadir una politica que solo mira esa bandera.

**Lo que hay que descartar primero:** Cargas de trabajo de red o de perfilado que documentan la capacidad que necesitan

**Origen:** `kubernetes / audit` · **ATT&CK:** [T1611](https://attack.mitre.org/techniques/T1611/) · **NIST:** AC-6, SC-39 · **ISO 27001:** A.8.2

### 🟠 Enlace a un rol con privilegios de administrador del cluster

`k8s_escalada_por_rolebinding.yml`

Crear un ClusterRoleBinding hacia cluster-admin concede control total del cluster al sujeto enlazado. Es la forma mas limpia de persistir en Kubernetes: no toca ningun nodo y sobrevive al borrado de los pods del atacante.

**Lo que hay que descartar primero:** Despliegue inicial del cluster o de un operador, acotado en el tiempo

**Origen:** `kubernetes / audit` · **ATT&CK:** [T1078.003](https://attack.mitre.org/techniques/T1078/003/) · **NIST:** AC-2, AC-6 · **ISO 27001:** A.5.15, A.8.2

### 🟡 Ejecucion interactiva dentro de un pod

`k8s_exec_en_pod.yml`

kubectl exec abre una shell dentro de un contenedor en ejecucion. En un cluster gestionado por GitOps no deberia hacer falta: cualquier exec sobre produccion es, como minimo, una desviacion del procedimiento, y en un compromiso es la via habitual de movimiento lateral.

**Lo que hay que descartar primero:** Depuracion autorizada en entornos de no produccion

**Origen:** `kubernetes / audit` · **ATT&CK:** [T1609](https://attack.mitre.org/techniques/T1609/) · **NIST:** AC-6, AU-12 · **ISO 27001:** A.8.2

### 🟡 Lectura de secretos de Kubernetes

`k8s_lectura_masiva_secretos.yml`

Los secretos del cluster contienen tokens de service account, credenciales de registro y claves de aplicacion. Un list sobre todos los secretos de un namespace es enumeracion, no uso normal: las cargas legitimas leen el suyo, montado por el kubelet, no consultan la API.

**Lo que hay que descartar primero:** Operadores y controladores propios, que deben reconocerse por su service account

**Origen:** `kubernetes / audit` · **ATT&CK:** [T1552.007](https://attack.mitre.org/techniques/T1552/007/) · **NIST:** IA-5, SC-28 · **ISO 27001:** A.5.17

### 🔴 Pod que monta una ruta sensible del nodo

`k8s_montaje_hostpath.yml`

Un volumen hostPath expone el sistema de ficheros del nodo dentro del contenedor. Montar la raiz, /etc, /var/run o el socket del runtime equivale a dar control del nodo a quien controle el pod.

**Lo que hay que descartar primero:** DaemonSets de observabilidad o de seguridad, que deben estar en una lista aprobada

**Origen:** `kubernetes / audit` · **ATT&CK:** [T1611](https://attack.mitre.org/techniques/T1611/) · **NIST:** AC-6, SC-39 · **ISO 27001:** A.8.2

### 🟠 Creacion de pod privilegiado

`k8s_pod_privilegiado.yml`

Un contenedor con privileged true comparte los dispositivos y capacidades del nodo. Desde ahi el salto al host es trivial: montar el disco del nodo, cargar modulos o entrar en los namespaces del PID 1. Salvo agentes de infraestructura conocidos, no deberia crearse ninguno.

**Lo que hay que descartar primero:** Agentes de red o de almacenamiento (CNI, CSI) que si necesitan privilegios; deben ir en su propio namespace

**Origen:** `kubernetes / audit` · **ATT&CK:** [T1610](https://attack.mitre.org/techniques/T1610/), [T1611](https://attack.mitre.org/techniques/T1611/) · **NIST:** AC-6, CM-7, SC-39 · **ISO 27001:** A.8.2, A.8.9

---

## Red

**6 reglas** · Proxy, DNS y NetFlow

Lo que se ve del trafico cuando el endpoint no dice nada.

### 🟡 Patron de beaconing hacia un destino externo

`soc_net_001_beaconing.yml`

Un beacon de C2 se delata por la regularidad: intervalos casi constantes y tamano de respuesta parecido, sostenido durante horas. La regla Sigma marca el flujo saliente candidato; el calculo de desviacion tipica del intervalo lo hace la busqueda del SIEM, porque Sigma no expresa agregacion temporal de ese tipo.

**Lo que hay que descartar primero:** Telemetria de producto y comprobaciones periodicas de actualizacion, que tambien son regulares

**Origen:** `proxy` · **ATT&CK:** [T1071.001](https://attack.mitre.org/techniques/T1071/001/) · **NIST:** SC-7, SI-4 · **ISO 27001:** A.8.20, A.8.23

### 🟠 Canal de mando sobre un servicio legitimo

`soc_net_002_c2_servicio_legitimo.yml`

Uso de plataformas de confianza como canal de C2 o de exfiltracion: webhooks de Discord y Slack, la API de Telegram, pastebin y servicios de tunel. Pasan el filtro de reputacion porque el dominio es legitimo, asi que hay que mirar la ruta.

**Lo que hay que descartar primero:** Integraciones internas legitimas con Slack o Teams, que conviene registrar por origen

**Origen:** `proxy` · **ATT&CK:** [T1102](https://attack.mitre.org/techniques/T1102/) · **NIST:** SC-7 · **ISO 27001:** A.8.23

### 🟠 Tunelizacion o exfiltracion por DNS

`soc_net_003_dns_tunel.yml`

El DNS sale de casi cualquier red, lo que lo convierte en canal de reserva para C2 y exfiltracion. Las senales son la longitud de la etiqueta, el uso de tipos TXT y NULL y un numero de subdominios unicos desproporcionado para un mismo dominio padre.

**Lo que hay que descartar primero:** Listas de reputacion y antispam que consultan por TXT, y algunos productos de seguridad

**Origen:** `dns` · **ATT&CK:** [T1071.004](https://attack.mitre.org/techniques/T1071/004/) · **NIST:** SC-7, SI-4 · **ISO 27001:** A.8.20, A.8.23

### 🟠 Explotacion de vulnerabilidad web contra un servicio publicado

`soc_net_004_explotacion_web.yml`

Patrones de explotacion en la peticion HTTP: inyeccion SQL, traversal, deserializacion, JNDI y ejecucion de plantilla. Pensada para el log del WAF o del proxy inverso, que es donde llega la peticion completa.

**Lo que hay que descartar primero:** Escaneres de vulnerabilidad autorizados, que deben estar acotados por IP origen y ventana

**Origen:** `webserver` · **ATT&CK:** [T1190](https://attack.mitre.org/techniques/T1190/)

### 🔴 Interaccion con webshell

`soc_net_005_webshell.yml`

Peticiones a ficheros de script en el directorio publicado con parametros que contienen comandos. Detecta el uso de la webshell despues de que se haya conseguido colocar, que es cuando produce trafico observable.

**Lo que hay que descartar primero:** Aplicaciones que aceptan un parametro llamado cmd de forma legitima, poco habitual

**Origen:** `webserver` · **ATT&CK:** [T1505.003](https://attack.mitre.org/techniques/T1505/003/) · **NIST:** CM-5, SI-7 · **ISO 27001:** A.8.9

### 🟡 Volumen de subida anomalo hacia el exterior

`soc_net_006_exfiltracion_volumen.yml`

Marca el trafico saliente candidato a exfiltracion por volumen. El umbral y la comparacion con la linea base del propio equipo se resuelven en la busqueda del SIEM, ya que Sigma no expresa agregacion sobre ventanas moviles.

**Lo que hay que descartar primero:** Copias a servicios corporativos no incluidos en el filtro, que hay que anadir al desplegar

**Origen:** `proxy` · **ATT&CK:** [T1048](https://attack.mitre.org/techniques/T1048/) · **NIST:** AC-4, SC-7 · **ISO 27001:** A.8.12

---

## Exfiltracion

**8 reglas** · Endpoint, proxy y correo

El final de la cadena. Cuando esto salta, los datos probablemente ya salieron: el objetivo cambia de contener a medir el alcance.

### 🟡 Archivado masivo previo a la exfiltracion

`exf_001_archivado_previo_exfiltracion.yml`

El paso que casi nunca falta antes de sacar datos: comprimir lo recolectado en un solo fichero, ponerle contrasena para que el DLP no lo lea y partirlo en volumenes para que pase por el proxy sin destacar por tamano. La regla exige la combinacion de un archivador con una opcion de cifrado o troceado, o con una ruta de documentos, para no disparar con cada descompresion normal de un adjunto.

**Lo que hay que descartar primero:** Copias de seguridad de usuario hechas a mano antes de renovar el equipo, que se distinguen porque el destino es la unidad local y no hay subida posterior

**Origen:** `process_creation / windows` · **ATT&CK:** [T1074.001](https://attack.mitre.org/techniques/T1074/001/), [T1560.001](https://attack.mitre.org/techniques/T1560/001/) · **NIST:** AC-4 · **ISO 27001:** A.8.12

### 🟠 Subida a almacenamiento personal en la nube

`exf_002_subida_nube_personal.yml`

Salida de datos por el canal mas comodo que tiene el usuario: su cuenta personal de almacenamiento o un servicio de envio anonimo. La regla no se conforma con ver el dominio, exige que el metodo sea POST o PUT, que es lo que separa la subida de la simple navegacion o del anuncio incrustado en otra pagina. Frente a la deteccion por volumen, aqui basta un fichero pequeno si el destino es una cuenta personal.

**Lo que hay que descartar primero:** Recepcion de material de un cliente o proveedor que solo trabaja con enlaces de transferencia, que hay que documentar y excluir por usuario

**Origen:** `proxy` · **ATT&CK:** [T1567.002](https://attack.mitre.org/techniques/T1567/002/) · **NIST:** AC-4, SC-7 · **ISO 27001:** A.8.12, A.8.23

### 🟡 Copia masiva de documentos a unidad extraible

`exf_003_copia_masiva_extraible.yml`

La via de salida que no pasa por el proxy ni por el correo. Como el evento de escritura en disco es de los mas ruidosos que existe, la regla exige cuatro cosas a la vez: destino fuera de la unidad de sistema, extension de documento o de contenedor, un proceso de copia o de archivado como origen, y que la ruta no sea de copia de seguridad. Completa a la regla de montaje de almacenamiento extraible, que ve el USB conectarse pero no ve que se lleva.

**Lo que hay que descartar primero:** Unidades de red mapeadas con letra, que escriben igual que un USB; hay que fijar las letras realmente extraibles del parque antes de desplegar

**Origen:** `file_event / windows` · **ATT&CK:** [T1005](https://attack.mitre.org/techniques/T1005/), [T1052.001](https://attack.mitre.org/techniques/T1052/001/) · **NIST:** AC-19, AC-3, MP-7 · **ISO 27001:** A.7.10, A.8.12, A.8.3

### 🟠 Exfiltracion por protocolo alternativo

`exf_004_protocolo_alternativo.yml`

Cuando el proxy filtra la salida web, el dato se va por donde nadie mira: ICMP con carga util llena, FTP en claro o un recurso SMB hacia una direccion de fuera. Para el ICMP se pide la herramienta y un tamano de paquete grande a la vez, porque un ping suelto es trafico normal y un ping de 65500 bytes repetido es un canal. El FTP y el SMB salientes se marcan siempre: en una red corporativa moderna no tienen uso legitimo hacia Internet.

**Lo que hay que descartar primero:** Diagnostico de MTU con ping de tamano fijo por parte de redes, acotado a equipos de administracion y a una ventana corta

**Origen:** `process_creation / windows` · **ATT&CK:** [T1048](https://attack.mitre.org/techniques/T1048/), [T1048.003](https://attack.mitre.org/techniques/T1048/003/) · **NIST:** AC-4, SC-7 · **ISO 27001:** A.8.12

### 🔴 Reenvio automatico de correo a dominio personal

`exf_005_reenvio_correo_personal.yml`

Exfiltracion continua y sin esfuerzo: una vez puesta la regla, cada correo que llegue al buzon sale solo hacia una cuenta que la empresa no controla. Se diferencia de la deteccion generica de reglas de buzon en que aqui se exige que el destino sea un proveedor de correo de consumo, lo que descarta el reenvio entre buzones corporativos y convierte el aviso en algo accionable: o es cuenta comprometida o es un empleado sacando informacion antes de irse.

**Lo que hay que descartar primero:** Directivo que reenvia a su cuenta personal por comodidad, que sigue siendo una fuga de datos y debe tratarse como incidencia de politica, no cerrarse como falso positivo

**Origen:** `m365 / exchange` · **ATT&CK:** [T1020](https://attack.mitre.org/techniques/T1020/), [T1114.003](https://attack.mitre.org/techniques/T1114/003/) · **NIST:** AC-3, AC-4 · **ISO 27001:** A.8.12, A.8.3

### 🟠 Subida de codigo o secretos a repositorio publico

`exf_006_repositorio_publico_codigo.yml`

Un git push a una cuenta personal de GitHub saca codigo, claves de API y ficheros de configuracion sin tocar el proxy de ficheros ni el correo, y ademas queda publicado. El caso mas grave no es el push sino el remote add previo hacia un servidor que no es el corporativo, porque revela intencion. La regla exige herramienta, accion y destino publico a la vez, y excluye la plataforma interna, que es donde ocurre el trabajo legitimo.

**Lo que hay que descartar primero:** Contribucion aprobada a proyectos de codigo abierto, que debe salir de equipos y cuentas registradas y puede excluirse por usuario

**Origen:** `process_creation / windows` · **ATT&CK:** [T1567.001](https://attack.mitre.org/techniques/T1567/001/) · **NIST:** AC-4, SC-7 · **ISO 27001:** A.8.12, A.8.23

### 🟠 Volcado de base de datos a ruta de usuario

`exf_007_volcado_base_datos.yml`

Un volcado completo concentra en un fichero lo que de otro modo costaria meses sacar consulta a consulta, y es el paso previo obligado de casi toda extorsion por filtracion de datos. Lo que separa el volcado del atacante del respaldo del administrador es el destino: la copia legitima va al almacen de respaldo, no al escritorio ni al perfil del usuario. Por eso se exige herramienta de volcado y ruta de perfil o carpeta temporal a la vez.

**Lo que hay que descartar primero:** Volcado puntual de un administrador de base de datos para depurar, que debe hacerse desde el servidor y hacia el almacen de respaldo, no desde un puesto

**Origen:** `process_creation / windows` · **ATT&CK:** [T1005](https://attack.mitre.org/techniques/T1005/), [T1074.001](https://attack.mitre.org/techniques/T1074/001/) · **NIST:** AC-3, AC-4 · **ISO 27001:** A.8.12, A.8.3

### 🟡 Impresion o captura masiva de documentos

`exf_008_impresion_captura_masiva.yml`

Salida analogica de datos: lo que se imprime o se fotografia de la pantalla no lo ve el DLP de red ni el de correo. Como imprimir es una accion normal de oficina, la regla nunca dispara con la herramienta sola: pide herramienta de impresion o de captura mas un objetivo, sea un documento, una carpeta de perfil o una impresora remota. La segunda via cubre la copia directa de los ficheros de cola de impresion, que reconstruyen el documento sin abrirlo.

**Lo que hay que descartar primero:** Impresion normal de oficina desde la linea de comandos en aplicaciones de gestion que lanzan print.exe por lote, que hay que excluir por proceso padre o por equipo

**Origen:** `process_creation / windows` · **ATT&CK:** [T1052](https://attack.mitre.org/techniques/T1052/), [T1113](https://attack.mitre.org/techniques/T1113/) · **NIST:** AC-19, AC-3, MP-7 · **ISO 27001:** A.7.10, A.8.12, A.8.3

---

## Evasion del propio EDR

**6 reglas** · Sysmon, registro y carga de drivers

El atacante atacando la vigilancia. Si el sensor esta manipulado, la telemetria de ese equipo deja de ser fiable, incluida la que dice que todo va bien.

### 🔴 Desinstalacion o parada del sensor EDR

`xdr_001_desinstalacion_sensor_edr.yml`

El atacante con privilegios locales no pelea contra el EDR: lo quita. La regla exige la combinacion de un nombre de agente de seguridad con una accion de borrado de servicio, desinstalacion por MSI o WMI, o parada del proceso. Se distingue de la regla de defensas deshabilitadas en que alli se apagan funciones de Defender y aqui desaparece el agente entero, y con el toda la telemetria posterior del equipo.

**Lo que hay que descartar primero:** Migracion planificada de EDR, que debe llegar con ventana de cambio y desde la consola de despliegue

**Origen:** `process_creation / windows` · **ATT&CK:** [T1489](https://attack.mitre.org/techniques/T1489/), [T1562.001](https://attack.mitre.org/techniques/T1562/001/) · **NIST:** AU-9, CM-7, CP-10, IR-4, SI-3 · **ISO 27001:** A.5.29, A.8.7

### 🟠 Exclusion anadida al antivirus

`xdr_002_exclusiones_antivirus.yml`

Una exclusion es la forma mas silenciosa de cegar al antivirus: no apaga nada, no genera error y deja un hueco permanente donde el malware se ejecuta sin analisis. Se mira el registro y no la linea de comandos porque Add-MpPreference con -ExclusionPath, -ExclusionProcess o -ExclusionExtension aterriza en esta misma clave, igual que la exclusion empujada por GPO o por la API, y asi se ven las tres vias.

**Lo que hay que descartar primero:** Exclusiones de producto documentadas, como las de servidores de base de datos o de correo, que deben estar en una lista de rutas aprobadas

**Origen:** `registry_event / windows` · **ATT&CK:** [T1112](https://attack.mitre.org/techniques/T1112/), [T1562.001](https://attack.mitre.org/techniques/T1562/001/) · **NIST:** AU-9, CM-5, CM-6, CM-7, SI-3 · **ISO 27001:** A.8.7, A.8.9

### 🟠 Reglas ASR desactivadas o puestas en auditoria

`xdr_003_reglas_asr_desactivadas.yml`

Las reglas de reduccion de superficie de ataque son las que cortan el patron de Office lanzando interpretes, las macros que descargan y el robo de credenciales de LSASS. Pasarlas a Disabled o a AuditMode las deja registrando sin bloquear, que es peor que apagarlas porque el panel sigue en verde. El cambio legitimo llega por Intune o GPO sobre el parque entero; aqui se ve un equipo suelto cambiando su propia politica.

**Lo que hay que descartar primero:** Paso a modo auditoria durante el despliegue inicial de ASR, que se reconoce porque afecta a muchos equipos a la vez y sale de la consola de gestion

**Origen:** `process_creation / windows` · **ATT&CK:** [T1112](https://attack.mitre.org/techniques/T1112/), [T1562.001](https://attack.mitre.org/techniques/T1562/001/) · **NIST:** AU-9, CM-5, CM-6, CM-7, SI-3 · **ISO 27001:** A.8.7, A.8.9

### 🔴 Carga de driver vulnerable conocido

`xdr_004_driver_vulnerable_byovd.yml`

BYOVD: el atacante trae un driver firmado y legitimo con una vulnerabilidad que le da lectura y escritura en memoria de kernel, y desde ahi mata los procesos protegidos del EDR sin tocar ni un servicio. Filtrar por firma no sirve, porque estos ficheros estan correctamente firmados; lo que los delata es el nombre y el hecho de que ningun equipo del parque tiene motivo para cargarlos.

**Lo que hay que descartar primero:** Utilidades de diagnostico de hardware o de overclocking instaladas por el fabricante del portatil, que hay que inventariar y bloquear por politica

**Origen:** `driver_load / windows` · **ATT&CK:** [T1068](https://attack.mitre.org/techniques/T1068/), [T1562.001](https://attack.mitre.org/techniques/T1562/001/) · **NIST:** AU-9, CM-7, RA-5, SI-2, SI-3 · **ISO 27001:** A.8.7, A.8.8

### 🟠 Manipulacion del canal de telemetria ETW

`xdr_005_telemetria_etw_manipulada.yml`

Antes de actuar, el atacante corta la fuente en lugar de borrar el resultado: para DiagTrack, desactiva el autologger que alimenta al sensor o apaga un canal concreto con wevtutil. El ataque es mas limpio que borrar registros porque no deja el evento 1102 ni un hueco evidente, simplemente el equipo deja de contar cosas. La regla exige que wevtutil venga con /e:false, para no repetir la deteccion generica ya existente sobre wevtutil.

**Lo que hay que descartar primero:** Bastionado de privacidad que desactiva DiagTrack por politica, que debe verse en el despliegue completo y no en un equipo aislado

**Origen:** `process_creation / windows` · **ATT&CK:** [T1562.002](https://attack.mitre.org/techniques/T1562/002/), [T1562.006](https://attack.mitre.org/techniques/T1562/006/) · **NIST:** AU-9, CM-7, SI-3 · **ISO 27001:** A.8.7

### 🔴 Arranque en modo seguro forzado por bcdedit

`xdr_006_arranque_modo_seguro.yml`

En modo seguro solo arrancan los servicios registrados bajo la clave SafeBoot, y la mayoria de los EDR no estan ahi: el equipo levanta ciego. Es la maniobra previa tipica del ransomware, que anade su propio servicio a SafeBoot\Minimal y reinicia para cifrar sin vigilancia. Un cambio de configuracion de arranque en un puesto de usuario no tiene explicacion operativa; en soporte se hace desde el menu de recuperacion, no con bcdedit.

**Lo que hay que descartar primero:** Reparacion de un equipo por soporte tras un fallo de arranque, que deberia ir acompanada de un ticket y del bcdedit /deletevalue posterior

**Origen:** `process_creation / windows` · **ATT&CK:** [T1112](https://attack.mitre.org/techniques/T1112/), [T1562.009](https://attack.mitre.org/techniques/T1562/009/) · **NIST:** AU-9, CM-5, CM-6, CM-7, SI-3 · **ISO 27001:** A.8.7, A.8.9

---

## Arquitectura Zero Trust

**8 reglas** · Varias, segun el pilar

Desviaciones de arquitectura mas que incidentes: cosas que no deberian poder pasar si la arquitectura se cumple.

### 🟡 Montaje de almacenamiento extraible

`zta_dev_001_almacenamiento_extraible.yml`

Pilar de dispositivos y de datos. Un USB conectado a un equipo con acceso a recursos corporativos es a la vez via de entrada de codigo y via de salida de datos. En un entorno Zero Trust maduro el almacenamiento extraible esta bloqueado por politica; verlo montado significa que la politica no se aplica en ese equipo.

**Lo que hay que descartar primero:** Soportes cifrados y aprobados, que deberian identificarse por numero de serie en una lista

**Origen:** `windows / security` · **ATT&CK:** [T1052.001](https://attack.mitre.org/techniques/T1052/001/), [T1091](https://attack.mitre.org/techniques/T1091/) · **NIST:** AC-19, MP-7 · **ISO 27001:** A.7.10, A.8.12

### 🟠 Uso de protocolo de autenticacion heredado

`zta_id_001_autenticacion_heredada.yml`

Pilar de identidad. Los protocolos heredados (IMAP, POP3, SMTP AUTH, ActiveSync basico) no soportan MFA ni acceso condicional: una credencial valida basta para entrar. Son la puerta que queda abierta despues de desplegar MFA, y la que usan casi todos los rociados de contrasenas que tienen exito.

**Lo que hay que descartar primero:** Multifuncionales y aplicaciones que envian correo por SMTP autenticado, que hay que inventariar y excluir por cuenta

**Origen:** `azure / signinlogs` · **ATT&CK:** [T1078.004](https://attack.mitre.org/techniques/T1078/004/), [T1556.006](https://attack.mitre.org/techniques/T1556/006/) · **NIST:** AC-2, AC-6, IA-2 · **ISO 27001:** A.5.15, A.8.2, A.8.5

### 🟠 Cuenta de servicio con inicio de sesion interactivo

`zta_id_002_cuenta_servicio_interactiva.yml`

Pilar de identidad. Una cuenta de servicio existe para que la use un proceso, no una persona. Un inicio de sesion interactivo o por escritorio remoto con una de ellas significa que alguien tiene su contrasena, y esas contrasenas casi nunca caducan ni llevan MFA.

**Lo que hay que descartar primero:** Mantenimiento con la cuenta de servicio, practica desaconsejada que deberia dejar ticket

**Origen:** `windows / security` · **ATT&CK:** [T1078.002](https://attack.mitre.org/techniques/T1078/002/) · **NIST:** AC-2, AC-6 · **ISO 27001:** A.5.15, A.8.2

### 🟡 Protocolo en claro hacia un recurso que exige cifrado

`zta_net_001_protocolo_en_claro.yml`

Pilar de redes. El cifrado extremo a extremo es uno de los siete principios de NIST SP 800-207: la red interna no se considera de confianza, asi que el trafico interno tambien va cifrado. Telnet, FTP, LDAP simple o HTTP hacia un servicio de negocio son a la vez una desviacion de la arquitectura y una oportunidad de captura de credenciales.

**Lo que hay que descartar primero:** Equipamiento heredado sin alternativa cifrada, que debe estar inventariado y segmentado

**Origen:** `network_connection` · **ATT&CK:** [T1040](https://attack.mitre.org/techniques/T1040/) · **NIST:** SC-8 · **ISO 27001:** A.8.20, A.8.24

### 🟠 Carga de libreria desde una ruta no estandar

`zta_sup_001_libreria_ruta_no_estandar.yml`

Pilar de cadena de suministro software. Un proceso del sistema cargando una DLL desde una ruta escribible por el usuario es secuestro de orden de busqueda o sideloading: el binario es legitimo y esta firmado, la libreria no. Es la tecnica que mas veces sobrevive a un antivirus, porque lo que se ejecuta esta en la lista blanca.

**Lo que hay que descartar primero:** Instaladores que descomprimen en Temp antes de registrar, normalmente acompanados de un evento de msiexec

**Origen:** `image_load / windows` · **ATT&CK:** [T1574.001](https://attack.mitre.org/techniques/T1574/001/), [T1574.002](https://attack.mitre.org/techniques/T1574/002/) · **NIST:** CM-5, SI-7 · **ISO 27001:** A.8.9

### 🟡 Instalacion de paquete desde un repositorio no aprobado

`zta_sup_002_paquete_repositorio_no_aprobado.yml`

Pilar de cadena de suministro software. Instalar directamente desde un indice publico o desde una URL salta el repositorio interno, y con el se saltan el escaneo de vulnerabilidades, la firma y el inventario. Es tambien la via por la que entra un paquete con nombre confundible (typosquatting).

**Lo que hay que descartar primero:** Equipos de desarrollo con permiso explicito, que deberian estar en su propia unidad organizativa

**Origen:** `process_creation / linux` · **ATT&CK:** [T1195.001](https://attack.mitre.org/techniques/T1195/001/), [T1195.002](https://attack.mitre.org/techniques/T1195/002/) · **NIST:** CM-14, SR-11, SR-3 · **ISO 27001:** A.5.19, A.8.30

### 🟡 Modificacion de un fichero de dependencias o lockfile

`zta_sup_003_fichero_dependencias_modificado.yml`

Pilar de cadena de suministro software. El lockfile es lo que garantiza que lo que se compila hoy es lo mismo que se auditó ayer. Modificarlo fuera de un commit revisado, sobre todo en un servidor de compilacion, es la forma limpia de introducir una dependencia maliciosa sin tocar el codigo fuente.

**Lo que hay que descartar primero:** Edicion manual por una persona desarrolladora en su propio equipo

**Origen:** `file_event` · **ATT&CK:** [T1195.001](https://attack.mitre.org/techniques/T1195/001/) · **NIST:** CM-14, SR-11, SR-3 · **ISO 27001:** A.5.19, A.8.30

### 🔴 Borrado o reduccion del registro de auditoria

`zta_vis_001_borrado_registro_auditoria.yml`

Capacidad transversal de visibilidad y analitica del modelo CISA. Sin registro no hay deteccion, y por eso su manipulacion es uno de los primeros movimientos tras conseguir privilegios. Cubre el borrado del canal, la desactivacion de categorias de auditoria y la reduccion del tamano de retencion, que es la version silenciosa del borrado.

**Lo que hay que descartar primero:** Apagado ordenado del equipo, que genera 1100 de forma legitima y se distingue por ir seguido del arranque

**Origen:** `windows / security` · **ATT&CK:** [T1070.001](https://attack.mitre.org/techniques/T1070/001/), [T1562.002](https://attack.mitre.org/techniques/T1562/002/) · **NIST:** AU-11, AU-9, CM-7, SI-3 · **ISO 27001:** A.8.15, A.8.7

<!-- FIN:CATALOGO -->
