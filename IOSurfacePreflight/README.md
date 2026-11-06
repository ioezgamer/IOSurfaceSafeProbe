# IOSurface Preflight
App iOS de diagnóstico no invasivo para comprobar creación y consulta de una IOSurface propia, y apertura/cierre único del servicio IOSurfaceRoot.

No ejecuta carreras, no llama a externalMethod, no accede a memoria liberada, y no proporciona KernelRW ni jailbreak.

## Compilación en GitHub Actions
Workflow: `.github/workflows/ios-preflight-ipa.yml`.
Una actualización de la rama `preflight-ipa` activa la compilación en macOS.
Artefacto de salida: `IOSurfacePreflight-unsigned-ipa`, que contiene `IOSurfacePreflight-unsigned.ipa`.

El IPA **no está firmado**. Para instalarlo necesitás firmarlo con tu propia cuenta/herramienta autorizada (por ejemplo SideStore). No incluye firma ni credenciales.

## Resultados
- PUBLIC: PASS create confirma la API pública.
- ROOT: SERVICE_VISIBLE indica que se pudo resolver el servicio.
- ROOT: OPEN kr=0x00000000 indica conexión concedida a esa aplicación.
Nada de ello prueba una vulnerabilidad o una primitiva KernelRW.


## Prueba 16 y 17: cierre controlado con una superficie viva (v13)

La opción **16** crea una IOSurface usando únicamente la API pública, conserva dos referencias válidas y abre una conexión **independiente** a IOSurfaceRoot. Se detiene en una barrera **de espacio de usuario**; pulsá **17** para cerrar esa conexión mientras la superficie continúa retenida. Hay cierre automático tras aproximadamente 30 segundos si no se pulsa el botón 17.

Se guardan en Documents:
- `IOSurfaceControlledClose-checkpoint.json` (se actualiza atómicamente en cada fase).
- `IOSurfaceControlledClose-trace.csv` (marcas temporales, apertura y cierre).

La opción **Exportar** incluye ambos archivos. Tras relanzar la app se informa si la ejecución anterior quedó incompleta.

**Alcance:** la conexión que abrimos explícitamente puede ser distinta de la conexión privada que usa internamente `IOSurfaceCreate`. La pausa ocurre **fuera** del kernel y la prueba no ejecuta carreras ni interrumpe una rutina interna a voluntad. Ni la conclusión PASS ni un cierre inesperado de la app demuestran liberación prematura del objeto, use-after-free, kernel panic o KernelRW. Para demostrar eso hace falta una traza interna del kernel que correlacione referencia y generación del objeto con `register`, `close`, `free` y `dereference`.



## Prueba 18: concurrencia de API publica (v14)

La opcion **18. Concurrencia publica controlada (256 x 2)** lanza dos hilos, comenzando a la vez:

1. Uno crea hasta 256 superficies validas de 32x32 pixeles, comprueba la referencia obtenida mediante `IOSurfaceLookup` y libera exclusivamente referencias propias.
2. El otro abre y cierra hasta 256 conexiones **independientes** a `IOSurfaceRoot` mediante IOKit publico.

La prueba no usa metodos privados, referencias caducadas ni escritura arbitraria en memoria. El boton **Detener prueba activa** solicita una salida limpia entre iteraciones.

Cuando `IOServiceClose` empieza y termina dentro de una misma llamada observable a `IOSurfaceCreate`, la aplicacion cuenta `observedCreateOverlap` en su checkpoint. Se registra con el numero de iteracion del hilo creador, que nunca representa una direccion de memoria.

Los archivos exportados son:
- `IOSurfaceConcurrency-checkpoint.json` (intentos, operaciones exitosas, errores y solapamientos).
- `IOSurfaceConcurrency-trace.csv` (resultados y marcas temporales de cada cierre).

**Interpretacion estricta:** `observedCreateOverlap > 0` demuestra como maximo un solapamiento temporal de dos llamadas desde la aplicacion. La conexion cerrada es **independiente** de la gestion interna de `IOSurfaceCreate`. No comprueba que `register` y `stop` se ejecutaran en el mismo `IOSurfaceRootUserClient`, no indica una liberacion de objeto del kernel y no constituye prueba de una carrera explotable, UAF, kernel panic ni KernelRW. El resultado `DONE_NO_APP_OVERLAP_OBSERVED` tampoco descarta una vulnerabilidad en otras circunstancias.


## v19: evidencia de reinicio sin falsos positivos

La v18 comparaba cadenas de `kern.boottime` exactamente y podía anunciar un reinicio cuando el sello cambiaba por un ajuste del reloj. Además, su checkpoint de integridad no guardaba `systemUptime`; ese historial queda explícitamente marcado como `LEGACY_INDETERMINATE`.

La v19 registra al abrir, entrar en segundo plano, volver a primer plano y cambiar de estado activo:
- `IOSurfaceBootMonitor-checkpoint.json`: última observación atómica (uptime del sistema, sello de arranque, sesión y diagnóstico).
- `IOSurfaceBootMonitor-trace.csv`: historial acotado de eventos, disponible con **Exportar registro, CSV y checkpoint**.

Resultados posibles: `BASELINE_CREATED`, `INDETERMINATE`, `NO_UPTIME_ROLLBACK_OBSERVED`, `BOOT_EPOCH_SHIFT_UNCONFIRMED`, `UPTIME_ROLLBACK_REBOOT_INDICATED`. Un retroceso de uptime indica que el dispositivo probablemente se reinició entre observaciones, pero ni la causa ni un kernel panic se pueden inferir con estos datos. Ausencia de retroceso tampoco excluye un reinicio si transcurrió mucho tiempo entre muestras.

**Privacidad:** la aplicación registra estas medidas localmente y solo las exporta cuando el usuario pulsa Exportar; el manifiesto declara las razones de uso de `systemUptime` y `UserDefaults` correspondientes al diagnóstico. No hay envío automático a servidores.

**Prueba del clasificador:**

```sh
clang -std=c11 -Wall -Wextra -Werror IOSurfacePreflight/Tests/PFBootClassifierTests.c -lm -o /tmp/pf-boot-tests
/tmp/pf-boot-tests
```

La compilación de la app iOS se ejecuta en GitHub Actions con `xcodebuild`. El artefacto no está firmado.

## v19.1: correlación temporal de cada campaña con el monitor

Una campaña de 100.000 casos ahora registra en el **mismo monitor de actividad**:
- `BOUNDARY_BEGIN_<run-uuid>` antes de iniciar la ejecución.
- `BOUNDARY_PROGRESS_<run-uuid>_<case>` en cada múltiplo de 10.000 casos.
- `BOUNDARY_END_<run-uuid>_<status>` cuando se completa o se detiene.
- `BOUNDARY_ERROR_<run-uuid>` si fallan las dependencias de API pública.

Estos eventos permiten cruzar el tiempo de actividad y el identificador de campaña con los archivos `IOSurfaceBruteForce-v18-trace.csv` y `IOSurfaceBruteForce-v18-checkpoint.json` (el nombre del CSV se conserva por compatibilidad). El hecho de que existan eventos `BEGIN` y `END` no demuestra ausencia de errores del kernel; solo mejora la trazabilidad de lo observado desde la aplicación. Los eventos del monitor no son trazas internas del kernel.

Para verificar esta mejora, ejecutar una campaña controlada y exportar `IOSurfaceBootMonitor-trace.csv`, `IOSurfaceBootMonitor-checkpoint.json`, la traza y el checkpoint de campaña. No repetir automáticamente el mismo conjunto de 100.000 casos salvo que se busque reproducibilidad.

## v19.2: cobertura agrupada de memoria propia

En la campaña v19.1 de 50,000 casos, hubo 1,166 superficies BGRA/4 candidatas según metadatos públicos, pero solo se verificaron 123. La v19.2 comprueba cada candidata (sin criterio `n % 8`) con un límite de 4,096 superficies por campaña, y tres posiciones de píxel por superficie: primer byte, canal del píxel central y último byte. Cada escritura es reversible y está limitada por `minimumSpan` y `IOSurfaceGetAllocSize` sobre superficies propias, con bloqueo y desbloqueo público.

Nuevos archivos exportables tras una campaña:
- `IOSurfaceCoverage-v19_2.json`: identificador y semilla de ejecución, cobertura, resultados de integridad, agrupación por entrada y clases observadas.
- `IOSurfaceCoverage-v19_2.csv`: resultados agregados por categoría de entrada solicitada.

En el checkpoint final se añaden `integrity_eligible`, `integrity_byte_checks`, `integrity_skipped_by_budget` e `integrity_coverage_pct`. Las categorías identifican atributos de entrada, NO causas demostradas de rechazo de la API. Los rechazos ordinarios NO se contabilizan como vulnerabilidades.

La app no obtiene acceso al kernel, no accede a memoria liberada y no añade llamadas privadas. El artefacto IPA de CI se genera **sin firma**; se requiere firma autorizada antes de instalar en iOS.
