# Verificación en iPhone de IOSurfacePreflight v19.11

**Fecha local de la captura:** 2026-11-06 21:25 (Nicaragua).  
**Dispositivo:** iPhone14,3, iOS 27.0, build 24A437.  
**Estado:** `FORENSIC_EXPORT_WORKS__UAF_NOT_ESTABLISHED`.

Se analizaron cinco archivos exportados por el usuario desde la app instalada: `IOSurfacePreflight-log 19.txt`, `IOSurfaceForensicEvents-v19_10 2.csv`, `IOSurfaceForensicEvidence-v19_10 2.json`, `IOSurfaceBootMonitor-trace 9.csv` e `IOSurfaceBootMonitor-checkpoint 9.json`. Los archivos privados originales no se publican aquí.

## Resultado: se solucionó la regresión SameClient de v19.10

La versión registrada en el log es `IOSurfacePreflight-v19.11`. El informe generado lee **correctamente el CSV original de 11 columnas**, con:

- `csv_schema=11_columns_original`
- `trials=1`, `invalid_rows=0`
- `overlapping_trails_user_space=1`
- `max_overlap_microseconds=174.167`
- `call_result=0x10000003`, `close_result=0x00000000`
- `successful_api_calls=0`

Esto **reconstruye un ensayo histórico de espacio de usuario**, no un nuevo registro de notificación que se haya ejecutado con éxito. El resultado de la llamada fue no exitoso y no se puede atribuir un `IOSurfaceRootUserClient` concreto.

## Monitor

- `IOSurfaceBootMonitor-trace 9.csv`: 122 filas de eventos de aplicación, en 10 sesiones.
- Estados: `NO_UPTIME_ROLLBACK_OBSERVED` en 121 observaciones y `BASELINE_CREATED` en 1.
- Cero filas inválidas en la interpretación del informe, sin evidencia de reinicio en las observaciones recogidas.
- El sello `bootEpochSeconds=1793078961.282180` se mantiene; esto no equivale a una traza de pánico o memoria del kernel.

## Eventos forenses

El CSV `IOSurfaceForensicEvents-v19_10 2.csv` contiene diez eventos de aplicación, entre dos sesiones, con marca `source=user_space`. La sesión actual `7C4CFEE3-AC07-435D-AC99-00FFEE6EA0C4` incluye dos `BOOT_MONITOR` y dos `FORENSIC_SNAPSHOT`.

El informe automático encontró diez fuentes locales, incluida la evidencia SameClient histórica y las pruebas Mach. La revocación sigue en `EXPECTED_REJECTION`. El observador asíncrono previo muestra `messages_received=0`. No aparecen nuevos eventos de entrega de notificación del kernel.

## Verificación de integridad del intercambio

El SHA-256 declarado en el manifiesto para el BootMonitor CSV coincide con el archivo recibido:
`eac9a2857442d23049722c54d2faaeec17b68404082e75fe63393898c0d911c8`.

El SHA-256 declarado para el CSV forense también coincide con el archivo recibido:
`a5586c4f91994e5e1ea20d4fcf303c4cb97d54a57b694d0642a30d6d77d63a8b`.

Los identificadores de sesión del informe y del checkpoint de BootMonitor concuerdan.

## Dictamen

Los valores `kernel_last_release_observed=false`, `notification_survived_final_release_observed=false`, `post_free_dispatch_observed=false` y `uaf_proven=false` reflejan fielmente el alcance de las API públicas de iOS.

**La corrección de lectura está confirmada en el iPhone; no se ha demostrado un UAF, KernelRW ni una última liberación seguida de un acceso.** Repetir la prueba de revocación o crear otra captura idéntica no resolvería ese límite.
