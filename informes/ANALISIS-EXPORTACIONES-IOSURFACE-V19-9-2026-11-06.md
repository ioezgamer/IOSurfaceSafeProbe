# Análisis de exportaciones reales de IOSurfacePreflight v19.9

**Dispositivo:** iPhone14,3, iOS 27.0, build 24A437. **Análisis:** 2026-11-06, hora Nicaragua.  
**Evidencia:** ocho archivos adjuntos a la conversación, seis contenidos únicos tras detectar un JSON duplicado y versiones incrementales de logs/trazas. Se verificaron sus contenidos y SHA-256; los adjuntos completos no se publican en el repositorio.

## Resumen

No se identificó ninguna secuencia experimental `last_release(cliente) -> notificación_viva -> dereference(cliente)`. **No se demuestra UAF, corrupción de kernel ni KernelRW.**

| Archivo | SHA-256 | Resultado |
|---|---|---|
| `IOSurfaceBootMonitor-trace 6.csv` | `13759a5a9c6e9289c1a999181b1706e91028d27ec69877a8732d6c36346fef5a` | 110 eventos en 8 sesiones |
| `IOSurfaceBootMonitor-trace 7.csv` | `85995f14925c0d2c104537882c75255fb3a8c14f92d648700e1d9ce546453b86` | 114 eventos en 8 sesiones; los primeros 110 son idénticos a trace 6 |
| `IOSurfaceBootMonitor-checkpoint 6.json` | `89c65bfba10eb74825f48a30a10856843fb935b8af361eb088d88834df1a6c4a` | uptime 394825.700; sin rollback observado |
| `IOSurfaceBootMonitor-checkpoint 7.json` | `ca5528e5a9d304c731f52d86a550686abd04246fc4be3175792344a76a15bcbd` | uptime 401483.115; sin rollback observado |
| `IOSurfacePortRevocation-v19_9(1).json` | `bba66017cf989f0c7095ebf604e07f5b375c96aae18686b7928d9b696799f76a` | `EXPECTED_REJECTION` |
| `IOSurfacePortRevocation-v19_9 2.json` | `bba66017cf989f0c7095ebf604e07f5b375c96aae18686b7928d9b696799f76a` | **copia idéntica** del JSON anterior |
| `IOSurfacePreflight-log 16.txt` | `889f94ae6bd204c8220ff1830fe2cda6b65f03d5a22377d579dd2e326a9a395b` | 27 líneas; registra revocación esperada |
| `IOSurfacePreflight-log 17.txt` | `cf7084880f1cf3600fd8d09ecf0cbc8fc3106d62ebca8da09c7dea5b2b8e266b` | 31 líneas; añade observaciones de primer/segundo plano |

## Comprobaciones

- **BootMonitor:** en el CSV más reciente se observaron 114 eventos, 8 sesiones, 1 `BASELINE_CREATED` y 113 `NO_UPTIME_ROLLBACK_OBSERVED`. No hubo retrocesos del contador de actividad. El valor `boot_epoch_seconds = 1793078961.282180` es constante. Esto **no demuestra** por sí solo que no haya ocurrido ningún reinicio no observado; no hay diagnóstico `panic-full`.
- **Diferencia incremental:** trace 7 añade al trace 6 solo `WILL_RESIGN_ACTIVE`, `DID_ENTER_BACKGROUND`, `WILL_ENTER_FOREGROUND`, `DID_BECOME_ACTIVE`; no agrega ensayos de kernel ni eventos de memoria.
- **Revocación Mach:** el mismo JSON registra `port_name_invalidated=true`, controles de derechos válidos `MATCH`, y consultas de puerto revocado/ajeno/nulo `NULL_REJECTED`. `use_after_free_proven=false`; `security_vulnerability_proven=false`; `kernel_read_write_proven=false`. El duplicado no suma una prueba independiente.
- **Historial same-client:** la cabecera del log contiene `SAMECLIENT: anterior=STOPPED_ON_API_ERROR intento=1 solapamiento=1`. Este es el **estado de un ensayo anterior**, no un hallazgo positivo de memoria en esta captura.
- **Observación de notificaciones:** el log recuerda `OBSERVE: previo status=DONE phase=FINISHED resultado=0x00000000 mensajes=0`. No hay evidencia de entrega posterior al cierre.
- **Campañas BRUTE/BOUNDARY:** son estados previos mostrados al iniciar la app, no nuevas ejecuciones; no deben sumarse como nuevos experimentos.

## Matriz mínima para demostrar la correlación solicitada

| Prueba necesaria sobre la misma instancia | Observada |
|---|---|
| Identidad/generación de `IOSurfaceRootUserClient` | No |
| Última liberación física del objeto | No |
| Notificación persistente después de la liberación | No |
| Despacho que utilice esa misma instancia después del `free` | No |

**Conclusión:** los archivos son válidos para descartar falsos positivos de reinicio/revocación y para reconstruir la actividad de la aplicación. No son suficientes para atribuir un acceso posterior a la liberación en el kernel. No se necesita repetir la misma prueba de revocación.
