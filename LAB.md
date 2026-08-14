# 🧪 Lab Purple Team — bucle de detección sobre Wazuh

Esta guía monta el **bucle purple team** (emular → detectar → afinar) encima de la
infraestructura que ya tienes en **Infra-SocAnalyst** (Wazuh + sensores). Aquí no
se repite el SOC: se le añade el **contenido de detección** y la **validación con
adversary emulation** que tu propio "trabajo futuro" pedía.

```
   Atomic Red Team (emula T####)         ← ejecuta la técnica
              │
              ▼
   Sysmon / Falco / auditd               ← genera telemetría
              │
              ▼
   Wazuh (indexer OpenSearch)            ← donde buscan las reglas Sigma
              │
              ▼
   ¿Saltó la detección?  ── no ─► afinar la regla Sigma ─┐
              │ sí                                        │
              ▼                                           │
   tools/validate.py → heatmap ATT&CK  ◄──────────────────┘
```

## Requisitos previos (ya los tienes en Infra-SocAnalyst)

- **Wazuh Manager + Indexer** funcionando (VLAN SOC).
- Endpoints con **agente Wazuh**. En Linux ya tienes **Falco/auditd**.

## Paso 1 — Telemetría Windows: Sysmon

Tu demo actual es Linux; para detección Windows necesitas **Sysmon**.

```powershell
# En la VM Windows de laboratorio (endpoints, VLAN 10)
# Descarga Sysmon (Sysinternals) y una config de referencia (SwiftOnSecurity)
sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

Reenvía el canal de Sysmon a Wazuh añadiendo al `ossec.conf` del agente:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Reinicia el agente. Ya tienes EID 1 (proceso), 3 (red), 10 (acceso), 13 (registro)
llegando a Wazuh — que es justo lo que consumen las reglas.

## Paso 2 — Cargar las detecciones

Las reglas viven en **Sigma** (formato portable). Dos formas de usarlas en Wazuh:

**A) Hunting en el indexer (rápido):** usa las consultas ya convertidas a Lucene
   en `deploy/windows-wazuh-lucene.txt` y `deploy/linux-wazuh-lucene.txt`
   directamente en Discover de Wazuh/OpenSearch.

**B) Reglas nativas de Wazuh (alerta):** traduce las de mayor valor a reglas XML
   de Wazuh en la serie **100xxx** (para no chocar con tus 110xxx de
   Infra-SocAnalyst). Ejemplo para "PowerShell codificado":

```xml
<group name="sysmon,sigma,detection_lab,">
  <rule id="100201" level="12">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image">powershell\.exe$</field>
    <field name="win.eventdata.commandLine">-enc|-EncodedCommand</field>
    <description>Detection-lab: PowerShell con comando codificado (T1059.001)</description>
    <mitre><id>T1059.001</id></mitre>
  </rule>
</group>
```

Regenera todas las conversiones cuando cambies reglas:

```bash
sigma convert -t lucene  -p sysmon rules/windows/ > deploy/windows-wazuh-lucene.txt
sigma convert -t splunk  -p sysmon rules/windows/ > deploy/windows-splunk.txt
sigma convert -t esql    -p sysmon rules/windows/ > deploy/windows-esql.txt
sigma convert -t lucene  --without-pipeline rules/linux/ > deploy/linux-wazuh-lucene.txt
```

## Paso 3 — Emular con Atomic Red Team

```powershell
Install-Module -Name Invoke-AtomicRedTeam -Scope CurrentUser
Import-Module Invoke-AtomicRedTeam
Invoke-AtomicTest T1059.001            # ejecuta la técnica en el endpoint
Invoke-AtomicTest T1059.001 -Cleanup   # revierte SIEMPRE al terminar
```

Consulta `purple/atomic-map.md`: dice qué test corresponde a cada regla y qué
telemetría esperar.

## Paso 4 — Verificar y afinar

1. Tras lanzar el test, busca en Wazuh la regla/consulta correspondiente.
2. **¿Saltó?** Anótalo en la tabla de resultados de `purple/atomic-map.md`.
3. **¿No saltó?** Ajusta la regla Sigma (campos, condición) y vuelve a convertir.
4. **¿Falso positivo en el día a día?** Añade una exclusión y documenta el tuning.

## Paso 5 — Medir la cobertura

```bash
python tools/validate.py
```

Valida todas las reglas, imprime la cobertura por táctica y genera
`navigator/coverage-layer.json`. Súbelo a **https://mitre-attack.github.io/attack-navigator/**
(Open Existing Layer) para ver el **heatmap** de lo que detectas y dónde tienes huecos.

## Encaje con el resto del portfolio

- **News CTI** aporta IOCs → se pueden convertir en reglas de detección.
- **detection-lab** (este repo) escribe y valida las detecciones.
- **Infra-SocAnalyst** es donde corren (Wazuh + SOAR).
- **ftriage** investiga el host cuando una detección salta.

Un ciclo completo CTI → detección → SOC → DFIR.
