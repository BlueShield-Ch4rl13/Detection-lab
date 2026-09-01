# 🟣 Mapeo Purple Team — Atomic Red Team ↔ Detecciones

<!-- Generado por tools/build.py — no editar a mano · fuente: rules/ -->

El bucle: **emular** una técnica con Atomic Red Team → comprobar que **salta**
la regla en el SIEM → si no salta, **afinar** la regla → volver a medir la
cobertura.

Este fichero **se genera** desde `rules/` con `python tools/build.py`. No se
edita a mano: un mapa que cita reglas que ya no existen manda a emular una
técnica y luego a buscar una detección que nadie va a disparar.

> Ejecuta las pruebas **solo en el laboratorio aislado**. Limpia siempre con
> `-Cleanup`.

```powershell
Install-Module -Name Invoke-AtomicRedTeam -Scope CurrentUser
Import-Module Invoke-AtomicRedTeam
Invoke-AtomicTest T1003.001                 # ejecuta la tecnica
Invoke-AtomicTest T1003.001 -Cleanup        # revierte
```

## Windows — Sysmon y canal Security

| Técnica ATT&CK | Atomic Red Team | Regla(s) Sigma | Telemetría |
|---|---|---|---|
| T1003 | `Invoke-AtomicTest T1003` | `soc_ad_005_herramientas_kerberos` | Sysmon EID 1 |
| T1003.001 | `Invoke-AtomicTest T1003.001` | `soc_edr_001_volcado_lsass` · `soc_edr_002_acceso_lsass_sysmon` | Sysmon EID 1 |
| T1003.006 | `Invoke-AtomicTest T1003.006` | `soc_ad_003_dcsync` | Canal Security / System de Windows |
| T1021.006 | `Invoke-AtomicTest T1021.006` | `soc_ad_009_wmi_winrm_remoto` | Sysmon EID 1 |
| T1027 | `Invoke-AtomicTest T1027` | `soc_edr_006_powershell_ofuscado` | Sysmon EID 1 |
| T1047 | `Invoke-AtomicTest T1047` | `proc_wmic_process_call_create` · `soc_ad_009_wmi_winrm_remoto` | Sysmon EID 1 |
| T1053.005 | `Invoke-AtomicTest T1053.005` | `soc_edr_008_persistencia_tarea` | Sysmon EID 1 |
| T1055 | `Invoke-AtomicTest T1055` | `soc_edr_010_inyeccion_procesos` | Sysmon EID 8 |
| T1059.001 | `Invoke-AtomicTest T1059.001` | `soc_edr_006_powershell_ofuscado` | Sysmon EID 1 |
| T1069.002 | `Invoke-AtomicTest T1069.002` | `soc_ad_007_enumeracion_dominio` | Sysmon EID 1 |
| T1070.001 | `Invoke-AtomicTest T1070.001` | `soc_edr_004_defensas_deshabilitadas` | Sysmon EID 1 |
| T1071 | `Invoke-AtomicTest T1071` | `soc_edr_011_pipe_c2` | Sysmon EID 17/18 |
| T1071.001 | `Invoke-AtomicTest T1071.001` | `net_rare_process_external_conn` | Sysmon EID 3 |
| T1087.002 | `Invoke-AtomicTest T1087.002` | `soc_ad_007_enumeracion_dominio` | Sysmon EID 1 |
| T1105 | `Invoke-AtomicTest T1105` | `soc_edr_005_lolbins_descarga` | Sysmon EID 1 |
| T1136.001 | `Invoke-AtomicTest T1136.001` | `proc_net_user_add` | Sysmon EID 1 |
| T1136.002 | `Invoke-AtomicTest T1136.002` | `soc_ad_011_cuenta_equipo_creada` | Canal Security / System de Windows |
| T1140 | `Invoke-AtomicTest T1140` | `soc_edr_005_lolbins_descarga` | Sysmon EID 1 |
| T1197 | `Invoke-AtomicTest T1197` | `soc_edr_005_lolbins_descarga` | Sysmon EID 1 |
| T1204.002 | `Invoke-AtomicTest T1204.002` | `proc_office_spawning_shell` · `soc_edr_012_ejecucion_desde_temp` | Sysmon EID 1 |
| T1218 | `Invoke-AtomicTest T1218` | `soc_edr_005_lolbins_descarga` | Sysmon EID 1 |
| T1218.005 | `Invoke-AtomicTest T1218.005` | `soc_edr_005_lolbins_descarga` | Sysmon EID 1 |
| T1218.010 | `Invoke-AtomicTest T1218.010` | `soc_edr_005_lolbins_descarga` | Sysmon EID 1 |
| T1484.001 | `Invoke-AtomicTest T1484.001` | `soc_ad_010_abuso_gpo` | Sysmon EID 1 |
| T1486 | `Invoke-AtomicTest T1486` | `soc_edr_007_cifrado_masivo` | Sysmon EID 11 |
| T1490 | `Invoke-AtomicTest T1490` | `soc_edr_003_borrado_copias_sombra` | Sysmon EID 1 |
| T1543.003 | `Invoke-AtomicTest T1543.003` | `proc_service_create_scexe` | Sysmon EID 1 |
| T1547.001 | `Invoke-AtomicTest T1547.001` | `soc_edr_009_persistencia_registro` | Sysmon EID 12/13/14 |
| T1550.002 | `Invoke-AtomicTest T1550.002` | `soc_ad_006_pass_the_hash` | Canal Security / System de Windows |
| T1558 | `Invoke-AtomicTest T1558` | `soc_ad_005_herramientas_kerberos` | Sysmon EID 1 |
| T1558.001 | `Invoke-AtomicTest T1558.001` | `soc_ad_004_golden_ticket` | Canal Security / System de Windows |
| T1558.003 | `Invoke-AtomicTest T1558.003` | `soc_ad_001_kerberoasting` | Canal Security / System de Windows |
| T1558.004 | `Invoke-AtomicTest T1558.004` | `soc_ad_002_asrep_roasting` | Canal Security / System de Windows |
| T1562.001 | `Invoke-AtomicTest T1562.001` | `soc_edr_004_defensas_deshabilitadas` | Sysmon EID 1 |
| T1566.001 | — Entrega de phishing: se emula enviando un correo de prueba al tenant | `proc_office_spawning_shell` | Sysmon EID 1 |
| T1569.002 | `Invoke-AtomicTest T1569.002` | `soc_ad_008_psexec_remoto` | Canal Security / System de Windows |
| T1649 | `Invoke-AtomicTest T1649` | `soc_ad_012_abuso_adcs` | Sysmon EID 1 |

## Linux — auditd / Falco

| Técnica ATT&CK | Atomic Red Team | Regla(s) Sigma | Telemetría |
|---|---|---|---|
| T1003.008 | `Invoke-AtomicTest T1003.008` | `lin_read_shadow` | execve (auditd / Falco) |
| T1053.003 | `Invoke-AtomicTest T1053.003` | `lin_cron_persistence` | execve (auditd / Falco) |
| T1059.004 | `Invoke-AtomicTest T1059.004` | `lin_base64_decode_exec` · `lin_download_pipe_shell` · `lin_reverse_shell` | execve (auditd / Falco) |
| T1070.003 | `Invoke-AtomicTest T1070.003` | `lin_disable_history` | execve (auditd / Falco) |
| T1098.004 | `Invoke-AtomicTest T1098.004` | `lin_ssh_authorized_keys` | execve (auditd / Falco) |
| T1105 | `Invoke-AtomicTest T1105` | `lin_download_pipe_shell` | execve (auditd / Falco) |
| T1136.001 | `Invoke-AtomicTest T1136.001` | `lin_useradd` | execve (auditd / Falco) |
| T1140 | `Invoke-AtomicTest T1140` | `lin_base64_decode_exec` | execve (auditd / Falco) |
| T1222.002 | `Invoke-AtomicTest T1222.002` | `lin_chmod_tmp_exec` | execve (auditd / Falco) |
| T1574.006 | `Invoke-AtomicTest T1574.006` | `lin_ld_preload` | execve (auditd / Falco) |

## macOS — Endpoint Security Framework

| Técnica ATT&CK | Atomic Red Team | Regla(s) Sigma | Telemetría |
|---|---|---|---|
| T1059.002 | `Invoke-AtomicTest T1059.002` | `mac_osascript_sospechoso` | ESF exec |
| T1059.004 | `Invoke-AtomicTest T1059.004` | `mac_descarga_y_ejecucion` | ESF exec |
| T1070.002 | `Invoke-AtomicTest T1070.002` | `mac_borrado_de_registros` | ESF exec |
| T1070.003 | `Invoke-AtomicTest T1070.003` | `mac_borrado_de_registros` | ESF exec |
| T1105 | `Invoke-AtomicTest T1105` | `mac_descarga_y_ejecucion` | ESF exec |
| T1136.001 | `Invoke-AtomicTest T1136.001` | `mac_usuario_oculto_creado` | ESF exec |
| T1543.001 | `Invoke-AtomicTest T1543.001` | `mac_persistencia_launchagent` | ESF create |
| T1543.004 | `Invoke-AtomicTest T1543.004` | `mac_persistencia_launchagent` | ESF create |
| T1548.006 | `Invoke-AtomicTest T1548.006` | `mac_tcc_manipulacion` | ESF exec |
| T1553.001 | `Invoke-AtomicTest T1553.001` | `mac_gatekeeper_deshabilitado` | ESF exec |
| T1555.001 | `Invoke-AtomicTest T1555.001` | `mac_volcado_llavero` | ESF exec |
| T1562.001 | `Invoke-AtomicTest T1562.001` | `mac_gatekeeper_deshabilitado` | ESF exec |

## Contenedores — auditoría de Kubernetes y runtime

| Técnica ATT&CK | Atomic Red Team | Regla(s) Sigma | Telemetría |
|---|---|---|---|
| T1078.003 | `Invoke-AtomicTest T1078.003` | `k8s_escalada_por_rolebinding` | Auditoria del API server |
| T1552.007 | `Invoke-AtomicTest T1552.007` | `k8s_lectura_masiva_secretos` | Auditoria del API server |
| T1609 | `Invoke-AtomicTest T1609` | `k8s_exec_en_pod` | Auditoria del API server |
| T1610 | `Invoke-AtomicTest T1610` | `cont_socket_runtime_accedido` · `k8s_pod_privilegiado` | execve (auditd / Falco) |
| T1611 | `Invoke-AtomicTest T1611` | `cont_escape_a_namespaces_host` · `cont_socket_runtime_accedido` · `k8s_capacidades_peligrosas` · y 2 mas | execve (auditd / Falco) |

## Nube e identidad — Entra ID, M365, CASB

| Técnica ATT&CK | Atomic Red Team | Regla(s) Sigma | Telemetría |
|---|---|---|---|
| T1078.004 | `Invoke-AtomicTest T1078.004` | `soc_cld_009_dispositivo_no_conforme` | Entra ID (SigninLogs / AuditLogs) |
| T1090.003 | `Invoke-AtomicTest T1090.003` | `soc_cld_008_origen_anonimizado` | Entra ID (SigninLogs / AuditLogs) |
| T1098.001 | `Invoke-AtomicTest T1098.001` | `soc_cld_007_credencial_service_principal` | Entra ID (SigninLogs / AuditLogs) |
| T1098.003 | `Invoke-AtomicTest T1098.003` | `soc_cld_005_rol_privilegiado` | Entra ID (SigninLogs / AuditLogs) |
| T1098.005 | `Invoke-AtomicTest T1098.005` | `soc_cld_002_metodo_mfa_registrado` | Entra ID (SigninLogs / AuditLogs) |
| T1110.003 | — Rociado de contrasenas contra el IdP: usar una prueba controlada del propio tenant | `soc_cld_003_password_spraying` | Entra ID (SigninLogs / AuditLogs) |
| T1539 | — Robo de token de sesion: requiere un proxy AitM tipo Evilginx en laboratorio aislado | `soc_cld_004_token_robado` | Entra ID (SigninLogs / AuditLogs) |
| T1550.001 | `Invoke-AtomicTest T1550.001` | `soc_cld_001_consentimiento_oauth` | Entra ID (SigninLogs / AuditLogs) |
| T1556.009 | `Invoke-AtomicTest T1556.009` | `soc_cld_006_acceso_condicional` | Entra ID (SigninLogs / AuditLogs) |
| T1567.002 | `Invoke-AtomicTest T1567.002` | `soc_cld_010_saas_no_aprobado` | Alertas de Netskope |

## Correo — Proofpoint TAP y Exchange Online

| Técnica ATT&CK | Atomic Red Team | Regla(s) Sigma | Telemetría |
|---|---|---|---|
| T1027.006 | `Invoke-AtomicTest T1027.006` | `soc_mail_008_html_smuggling` | Proofpoint TAP |
| T1114.003 | `Invoke-AtomicTest T1114.003` | `soc_mail_006_regla_buzon_externa` | Registro de auditoria de M365 |
| T1534 | — Envio interno masivo: se emula desde el propio buzon, no con Atomic | `soc_mail_002_suplantacion_directivo` · `soc_mail_007_envio_masivo_interno` | Proofpoint TAP |
| T1564.008 | `Invoke-AtomicTest T1564.008` | `soc_mail_006_regla_buzon_externa` | Registro de auditoria de M365 |
| T1566.001 | — Entrega de phishing: se emula enviando un correo de prueba al tenant | `soc_mail_004_adjunto_sospechoso` | Proofpoint TAP |
| T1566.002 | `Invoke-AtomicTest T1566.002` | `soc_mail_001_dominio_reciente` · `soc_mail_003_fallo_dmarc` · `soc_mail_005_url_pulsada` | Proofpoint TAP |

## Red — proxy, DNS y servidor web

| Técnica ATT&CK | Atomic Red Team | Regla(s) Sigma | Telemetría |
|---|---|---|---|
| T1048 | `Invoke-AtomicTest T1048` | `soc_net_006_exfiltracion_volumen` | Registro del proxy |
| T1071.001 | `Invoke-AtomicTest T1071.001` | `soc_net_001_beaconing` | Registro del proxy |
| T1071.004 | `Invoke-AtomicTest T1071.004` | `soc_net_003_dns_tunel` | Suricata eve / DNS del resolutor |
| T1102 | `Invoke-AtomicTest T1102` | `soc_net_002_c2_servicio_legitimo` | Registro del proxy |
| T1190 | `Invoke-AtomicTest T1190` | `soc_net_004_explotacion_web` | Acceso de nginx / apache |
| T1505.003 | `Invoke-AtomicTest T1505.003` | `soc_net_005_webshell` | Acceso de nginx / apache |

## Arquitectura Zero Trust

| Técnica ATT&CK | Atomic Red Team | Regla(s) Sigma | Telemetría |
|---|---|---|---|
| T1040 | `Invoke-AtomicTest T1040` | `zta_net_001_protocolo_en_claro` | network_connection |
| T1052.001 | `Invoke-AtomicTest T1052.001` | `zta_dev_001_almacenamiento_extraible` | Canal Security / System de Windows |
| T1070.001 | `Invoke-AtomicTest T1070.001` | `zta_vis_001_borrado_registro_auditoria` | Canal Security / System de Windows |
| T1078.002 | `Invoke-AtomicTest T1078.002` | `zta_id_002_cuenta_servicio_interactiva` | Canal Security / System de Windows |
| T1078.004 | `Invoke-AtomicTest T1078.004` | `zta_id_001_autenticacion_heredada` | Entra ID (SigninLogs / AuditLogs) |
| T1091 | `Invoke-AtomicTest T1091` | `zta_dev_001_almacenamiento_extraible` | Canal Security / System de Windows |
| T1195.001 | `Invoke-AtomicTest T1195.001` | `zta_sup_002_paquete_repositorio_no_aprobado` · `zta_sup_003_fichero_dependencias_modificado` | execve (auditd / Falco) |
| T1195.002 | `Invoke-AtomicTest T1195.002` | `zta_sup_002_paquete_repositorio_no_aprobado` | execve (auditd / Falco) |
| T1556.006 | `Invoke-AtomicTest T1556.006` | `zta_id_001_autenticacion_heredada` | Entra ID (SigninLogs / AuditLogs) |
| T1562.002 | `Invoke-AtomicTest T1562.002` | `zta_vis_001_borrado_registro_auditoria` | Canal Security / System de Windows |
| T1574.001 | `Invoke-AtomicTest T1574.001` | `zta_sup_001_libreria_ruta_no_estandar` | Sysmon EID 7 |
| T1574.002 | `Invoke-AtomicTest T1574.002` | `zta_sup_001_libreria_ruta_no_estandar` | Sysmon EID 7 |

## Registro de resultados

Rellena una fila por ronda de validación. Es lo que convierte la cobertura
declarada en cobertura comprobada: una regla sin probar no es cobertura, es
una hipótesis.

| Fecha | Técnica | ¿Detectó? | Regla | Notas |
|---|---|---|---|---|
|  |  | ⬜ |  |  |
|  |  | ⬜ |  |  |
|  |  | ⬜ |  |  |

Tras cada ronda: actualiza el registro, ajusta las reglas con falsos
positivos y vuelve a correr `python tools/validate.py` para regenerar el
mapa de cobertura.
