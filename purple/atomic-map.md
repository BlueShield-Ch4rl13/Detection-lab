# 🟣 Mapeo Purple Team — Atomic Red Team ↔ Detecciones

El bucle: **emular** una técnica con Atomic Red Team → comprobar que **salta** la
regla en el SIEM → si no salta, **afinar** la regla → volver a medir cobertura.

Cada fila enlaza una técnica MITRE ATT&CK con su prueba de Atomic Red Team, la
regla Sigma de este repo que debe detectarla, y la telemetría donde se ve.

> Ejecuta las pruebas **solo en el laboratorio aislado** (endpoints de
> Infra-SocAnalyst con Sysmon/Wazuh o Falco). Limpia siempre con `-Cleanup`.

## Cómo se ejecuta un test

```powershell
# Windows (PowerShell, como admin, en la VM de laboratorio)
Install-Module -Name Invoke-AtomicRedTeam -Scope CurrentUser
Import-Module Invoke-AtomicRedTeam
Invoke-AtomicTest T1059.001                 # ejecuta la técnica
Invoke-AtomicTest T1059.001 -Cleanup        # revierte
```

```bash
# Linux (endpoint con Falco/auditd del lab)
Invoke-AtomicTest T1059.004 -ShowDetailsBrief
```

## Windows (telemetría Sysmon → Wazuh)

| Técnica ATT&CK | Atomic Red Team | Regla Sigma | Telemetría |
|---|---|---|---|
| T1059.001 PowerShell | `Invoke-AtomicTest T1059.001` | proc_powershell_encoded / _download_cradle | Sysmon EID 1 |
| T1003.001 LSASS | `Invoke-AtomicTest T1003.001` | proc_mimikatz_cmdline / proc_lsass_comsvcs_minidump | Sysmon EID 1 / EID 10 |
| T1105 Ingress Tool Transfer | `Invoke-AtomicTest T1105` | proc_certutil_download_decode / proc_bitsadmin_transfer | Sysmon EID 1 |
| T1218.010 Regsvr32 | `Invoke-AtomicTest T1218.010` | proc_regsvr32_scriptlet | Sysmon EID 1 |
| T1218.005 Mshta | `Invoke-AtomicTest T1218.005` | proc_mshta_execution | Sysmon EID 1 |
| T1197 BITS Jobs | `Invoke-AtomicTest T1197` | proc_bitsadmin_transfer | Sysmon EID 1 |
| T1053.005 Scheduled Task | `Invoke-AtomicTest T1053.005` | proc_scheduled_task_create | Sysmon EID 1 |
| T1543.003 Windows Service | `Invoke-AtomicTest T1543.003` | proc_service_create_scexe | Sysmon EID 1 |
| T1547.001 Run Keys | `Invoke-AtomicTest T1547.001` | reg_run_key_persistence | Sysmon EID 13 |
| T1047 WMI | `Invoke-AtomicTest T1047` | proc_wmic_process_call_create | Sysmon EID 1 |
| T1490 Inhibit Recovery | `Invoke-AtomicTest T1490` | proc_vssadmin_delete_shadows | Sysmon EID 1 |
| T1562.001 Disable Defender | `Invoke-AtomicTest T1562.001` | proc_defender_tamper | Sysmon EID 1 |
| T1070.001 Clear Event Logs | `Invoke-AtomicTest T1070.001` | proc_wevtutil_clear_logs | Sysmon EID 1 |
| T1136.001 Create Account | `Invoke-AtomicTest T1136.001` | proc_net_user_add | Sysmon EID 1 |
| T1204.002 / T1566.001 Phishing | `Invoke-AtomicTest T1204.002` | proc_office_spawning_shell | Sysmon EID 1 (parent-child) |
| T1071.001 App Layer C2 | `Invoke-AtomicTest T1071.001` | net_rare_process_external_conn | Sysmon EID 3 |

## Linux (telemetría auditd/Falco → Wazuh)

| Técnica ATT&CK | Atomic Red Team | Regla Sigma | Telemetría |
|---|---|---|---|
| T1059.004 Unix Shell | `Invoke-AtomicTest T1059.004` | lin_reverse_shell / lin_download_pipe_shell | execve (auditd/Falco) |
| T1003.008 /etc/shadow | `Invoke-AtomicTest T1003.008` | lin_read_shadow | open/execve |
| T1053.003 Cron | `Invoke-AtomicTest T1053.003` | lin_cron_persistence | execve / file |
| T1098.004 SSH Keys | `Invoke-AtomicTest T1098.004` | lin_ssh_authorized_keys | file write |
| T1574.006 ld.so.preload | `Invoke-AtomicTest T1574.006` | lin_ld_preload | file write |
| T1070.003 Clear History | `Invoke-AtomicTest T1070.003` | lin_disable_history | execve |
| T1136.001 Create Account | `Invoke-AtomicTest T1136.001` | lin_useradd | execve |
| T1140 Deobfuscate | `Invoke-AtomicTest T1140` | lin_base64_decode_exec | execve |
| T1222.002 Linux File Perms | `Invoke-AtomicTest T1222.002` | lin_chmod_tmp_exec | execve |

## Registro de resultados (rellena al validar)

| Fecha | Técnica | ¿Detectó? | Regla | Notas |
|---|---|---|---|---|
| | T1059.001 | ⬜ | proc_powershell_encoded | |
| | T1003.001 | ⬜ | proc_lsass_comsvcs_minidump | |
| | T1490 | ⬜ | proc_vssadmin_delete_shadows | |

> Tras cada ronda: actualiza este registro, ajusta reglas con falsos positivos y
> vuelve a correr `python tools/validate.py` para regenerar el heatmap de cobertura.
