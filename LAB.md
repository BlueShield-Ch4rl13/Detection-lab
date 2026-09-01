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

**A) Reglas nativas de Wazuh — es lo que alerta.** `tools/sigma_to_wazuh.py`
   convierte las 87 reglas Sigma en 139 reglas XML. Las genera en la serie
   **101xxx**, que no choca ni con las 100xxx de marco de este repositorio ni
   con las 110xxx de Infra-SocAnalyst.

```bash
python tools/build.py                     # regenera los cuatro SIEM

sudo cp deploy/wazuh/0970-detection_lab_sigma.xml /var/ossec/etc/rules/
sudo cp deploy/wazuh/09[0-6]*.xml                 /var/ossec/etc/rules/   # marco (opcional)
sudo /var/ossec/bin/wazuh-logtest -t              # comprueba la sintaxis antes de reiniciar
sudo systemctl restart wazuh-manager
```

   Por que hay mas reglas XML que reglas Sigma: Wazuh combina con **AND** todas
   las condiciones de una regla, no tiene OR dentro de una. Una condicion Sigma
   como `1 of selection_*` se pasa a forma normal disyuntiva (aplicando De
   Morgan a las negaciones) y se emite **una regla por cada termino**. Por eso
   las descripciones acaban en `[1/5]`, `[2/5]`…: son partes de la misma
   deteccion.

**B) Hunting en el indexador — es lo que busca hacia atras.** Las consultas
   Lucene de `deploy/elastic/*-lucene.txt` van directamente al Discover de
   Wazuh/OpenSearch. **No alertan**: sirven para cazar sobre lo ya indexado
   cuando llega un IOC nuevo o hay que revisar una ventana pasada. Una consulta
   Lucene no es una deteccion desplegada, y es un error frecuente confundirlas.

### Lo que no se convierte, y hay que saberlo

Cinco reglas no tienen equivalente en Wazuh, y `tools/build.py` lo dice cada vez
que se ejecuta en lugar de generar algo que parezca equivalente:

| Regla | Motivo |
|---|---|
| Password spraying contra Entra ID | Correlacion `value_count`: Wazuh cuenta disparos de regla con `<frequency>`, no valores distintos de un campo |
| Reutilizacion de sesion desde redes distintas | Igual |
| Envio masivo desde una cuenta interna | Igual |
| Dispositivo no conforme | Compara contra `null` (campo ausente), que Wazuh no puede comprobar sobre un campo decodificado |
| Correo desde un dominio recien registrado | Usa el modificador `|lt` (comparacion numerica), que Wazuh no expresa |

Las tres correlaciones si estan disponibles en Splunk, y en Sentinel como KQL
escrito a mano en `deploy/sentinel/correlaciones.kql`.

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
