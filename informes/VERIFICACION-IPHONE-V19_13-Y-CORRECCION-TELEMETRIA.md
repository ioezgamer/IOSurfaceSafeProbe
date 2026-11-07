# Auditoría de los archivos iPhone v19.13 y corrección en v19.14

**Dispositivo:** iPhone14,3; iOS 27.0; build 24A437. **Hora local de captura:** 6 nov 2026, 21:50.

## Evidencia de los seis adjuntos

- `IOSurfacePreflight-log 20.txt` confirma la ejecución de v19.13 y de la opción TRIAGE en dos ocasiones. Revisión de archivos exportados desde la app.
- `IOSurfaceBootMonitor-trace 10.csv` contiene **126 eventos en 11 sesiones**; estados `NO_UPTIME_ROLLBACK_OBSERVED` (125), `BASELINE_CREATED` (1). No se observa pánico del kernel. El SHA-256 coincide con el manifiesto forense: `44b27f90174898790dbd7a25e7903b990e003b66edc23a80c885c4cc890041a7`.
- `IOSurfaceSecurityResearch-v19_13.json`: único hallazgo `REJECTED_RPC_WITH_USER_SPACE_OVERLAP`, clasificación `USER_SPACE_OVERLAP_WITH_REJECTED_CALLS`. Una fila SameClient recuperada, 174.167 μs de solapamiento en espacio de usuario, `call_kr=0x10000003` y `close_kr=0x00000000`, **0 llamadas aceptadas**. Sin evidencia de registro completado ni de liberación final del objeto.
- `IOSurfaceForensicEvidence-v19_10 3.json` conserva `mach_revocation.verdict=EXPECTED_REJECTION`, `async_observer.messages_received=0`, `uaf_proven=false`.
- `IOSurfaceForensicEvents-v19_10 3.csv` contiene **16 eventos en 3 sesiones**, todos `source=user_space`: 10 `BOOT_MONITOR`, 6 `FORENSIC_SNAPSHOT`. La única modificación reportada en la segunda ejecución de TRIAGE fue ese CSV, cuyo SHA-256 es `3d36cfeca0b80758c6a44814fd5d9d4e8e6b8a0e634d7c150320daf55f639694`.

## Diagnóstico y reparación

**Falso positivo de novedad documental:** al ejecutar TRIAGE, la propia opción actualiza el registro `FORENSIC_SNAPSHOT`. Su CSV cambia de hash aunque las pruebas IOSurface no se hayan repetido. v19.13 reportaba `modified_sources=["IOSurfaceForensicEvents-v19_10.csv"]` y `new_boot_monitor_events=0`; era actividad de la aplicación, no evidencia de anomalía en IOSurface.

v19.14 (build 33) preserva todos los hashes, pero segrega tres archivos de mantenimiento normal (`IOSurfaceForensicEvents-v19_10.csv`, `IOSurfaceBootMonitor-trace.csv`, `IOSurfaceBootMonitor-checkpoint.json`) como telemetría `modified_telemetry_sources`, `new_telemetry_sources`, `removed_telemetry_sources`. Los archivos experimentales quedan bajo `modified_sources`, `new_sources` y `removed_sources`. Se añade `no_substantive_source_changes` para detectar casos sin novedades experimentales, sin alterar la semántica estricta de `identical_source_set`. Las observaciones de arranque se analizan separadamente para no ocultar un posible retroceso de uptime.

El lector acepta informes de referencia v19.13 y v19.14, evitando perder historial en la actualización. La corrección está cubierta por **11 pruebas unitarias**, incluyendo regresión del caso iPhone y distinción entre archivos retirados de ambos tipos.

**Conclusión:** los seis adjuntos confirman correcto funcionamiento básico y un error real de clasificación de autorregistro. **No hay un exploit de IOSurface, UAF ni KernelRW demostrado**. No es necesario repetir las campañas previas.
