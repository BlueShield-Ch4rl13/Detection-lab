# Wazuh — instalacion

## Que hay en esta carpeta

| Carpeta | Contenido | Se regenera |
|---|---|---|
| `reglas/` | 260 reglas XML generadas desde Sigma + 73 de marco + 8 de inteligencia | Sí, con `tools/build.py` |
| `listas/` | Listas CDB de indicadores de News CTI | Sí, con `tools/sync_cti.py` |
| `consultas/` | Caza sobre el indexador (Discover / API) | No, escritas a mano |

## Series de identificadores

No se solapan, así que las tres vías conviven en el mismo manager:

| Serie | Origen |
|---|---|
| 100100 – 100699 | Detecciones Zero Trust escritas a mano |
| 100700 – 100799 | Detecciones de cumplimiento escritas a mano |
| 101000 – 101299 | Generadas desde `rules/` por `tools/sigma_to_wazuh.py` |
| 101300 – 101399 | Inteligencia de News CTI |

Si ya tienes reglas propias, comprueba antes que no pisan estos rangos:

```bash
grep -ho 'rule id="[0-9]*"' /var/ossec/etc/rules/*.xml | grep -o '[0-9]*' | sort -n | uniq -d
```

## 1. Reglas

```bash
sudo cp deploy/wazuh/reglas/*.xml /var/ossec/etc/rules/
sudo chown root:wazuh /var/ossec/etc/rules/*.xml
sudo chmod 660 /var/ossec/etc/rules/*.xml

# Validar ANTES de reiniciar: un XML roto deja el manager sin arrancar
sudo /var/ossec/bin/wazuh-logtest -t
```

Si `wazuh-logtest -t` sale limpio:

```bash
sudo systemctl restart wazuh-manager
sudo tail -f /var/ossec/logs/ossec.log
```

## 2. Listas de inteligencia

```bash
python3 tools/sync_cti.py                       # refresca desde News CTI
sudo cp intel/listas/wazuh/*.cdb /var/ossec/etc/lists/
sudo chown root:wazuh /var/ossec/etc/lists/cti_*.cdb
```

Declara cada lista en `/var/ossec/etc/ossec.conf`, dentro de `<ruleset>`:

```xml
<ruleset>
  <list>etc/lists/cti_hash</list>
  <list>etc/lists/cti_ip</list>
  <list>etc/lists/cti_dominio</list>
  <list>etc/lists/cti_url</list>
</ruleset>
```

Compila y reinicia:

```bash
sudo /var/ossec/bin/ossec-makelists
sudo systemctl restart wazuh-manager
```

**Ojo con el formato CDB.** `ossec-makelists` trata cada línea como una entrada,
comentarios incluidos. Por eso los `.cdb` que genera `sync_cti.py` no llevan
cabecera: una línea de comentario se convertiría en un indicador.

### Refresco periódico

Los indicadores caducan. Una IP de mando y control de hace un mes es hoy, con
frecuencia, un servidor legítimo reasignado. Programa el refresco:

```cron
0 6 * * * cd /opt/detection-lab && python3 tools/sync_cti.py --max-dias 30 \
          && cp intel/listas/wazuh/*.cdb /var/ossec/etc/lists/ \
          && /var/ossec/bin/ossec-makelists \
          && systemctl reload wazuh-manager
```

## 3. Telemetría que hace falta

Sin esto, las reglas están cargadas pero no ven nada.

**Windows — Sysmon.** El agente tiene que reenviar el canal:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Las reglas consumen EID 1 (proceso), 3 (red), 6 (driver), 7 (imagen), 8 (hilo
remoto), 10 (acceso a proceso), 11 (fichero), 12-14 (registro), 17-18 (tubería)
y 22 (DNS).

**Windows — canal Security.** Las 21 reglas de AD y de auditoría lo necesitan,
y varias exigen que la auditoría avanzada esté activada:

```powershell
auditpol /set /subcategory:"Directory Service Changes" /success:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"File Share" /success:enable
auditpol /set /subcategory:"Removable Storage" /success:enable
```

**Linux** — auditd o Falco. **macOS** — ESF vía el agente.

## 4. Comprobar que funciona

```bash
# ¿Cargaron las reglas?
sudo /var/ossec/bin/wazuh-logtest -t 2>&1 | grep -c "rules"

# ¿Se compilaron las listas?
ls -la /var/ossec/etc/lists/cti_*.cdb

# Probar una regla concreta con un evento de ejemplo
sudo /var/ossec/bin/wazuh-logtest
# y pegar un evento JSON de Sysmon
```

## Lo que Wazuh no puede hacer, y no se disimula

Cinco reglas de la biblioteca no tienen equivalente aquí. `tools/build.py` lo
avisa en cada ejecución:

| Regla | Motivo |
|---|---|
| Password spraying contra Entra ID | Correlación `value_count`: `<frequency>` cuenta disparos de regla, no valores distintos de un campo |
| Reutilización de sesión desde redes distintas | Igual |
| Envío masivo desde cuenta interna | Igual |
| Dispositivo no conforme | Compara contra `null`, que Wazuh no comprueba sobre un campo decodificado |
| Correo desde dominio recién registrado | Usa el modificador `\|lt`, comparación numérica que Wazuh no expresa |

Las tres correlaciones están en Splunk y en `deploy/sentinel/consultas/correlaciones.kql`.
