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

## v19.3: cobertura separada por formato, exclusiones y archivos por campaña

La v19.3 conserva las comprobaciones de tres bytes de píxel por superficie BGRA propia, limitadas a 4,096 superficies elegibles. **No intenta verificar memoria de formatos ajenos a BGRA**: sus casos se cuentan como observaciones de aceptación y exclusión, sin acceso a bytes de esos formatos.

- Los formatos son **solicitados** por el diccionario de entrada, no formatos internos inferidos del driver: BGRA, RGBA, cero y AAAA.
- La clasificación de exclusión de lectura/escritura solo se aplica a superficies **aceptadas** por la API, con un orden de prioridad determinista: funciones de mapeo ausentes, ID cero, dimensiones cero, metadatos fuera de rango, stride demasiado corto, longitud insuficiente del último píxel, formato distinto de BGRA, bytes por elemento distintos de 4 y tamaños superiores a 256x256. El resto son elegibles. No indica el motivo real por el que el sistema rechazó una entrada.
- El checkpoint actual cambia de \`v18-pixel-span\` a \`v19.3-format-coverage\`. Los campos antiguos de conteo continúan disponibles.
- Se mantienen los archivos de cobertura \`IOSurfaceCoverage-v19_3.json\` y \`IOSurfaceCoverage-v19_3.csv\`, ahora con \`requested_format_groups\`, \`accepted_memory_eligibility\` y \`eligibility_by_requested_format\`. Se añaden \`IOSurfaceFormats-v19_3.csv\` y \`IOSurfaceExclusions-v19_3.csv\`.
- Cada nueva ejecución guarda su historial separado en \`Documents/IOSurfaceRuns/<UUID>/\`: \`manifest.json\`, \`checkpoint.json\`, \`boundary-trace.csv\`, \`coverage.json\`, \`input-groups.csv\`, \`formats.csv\` y \`eligibility.csv\`. El botón Exportar incluye los archivos del último UUID además de los tradicionales. **Las ejecuciones anteriores no se borran automáticamente.**

Antes de ejecutar, comprobá que tu dispositivo dispone de almacenamiento suficiente para un CSV de 50,000 casos. Los resultados son registros de espacio de usuario; no demuestran ni descartan una vulnerabilidad del kernel, UAF o KernelRW.

**Pruebas C11:**

\`\`\`sh
clang -std=c11 -Wall -Wextra -Werror IOSurfacePreflight/Tests/PFMemoryEligibilityTests.c -o /tmp/pf-memory-tests
/tmp/pf-memory-tests
\`\`\`

En iOS, los resultados archivados se pueden consultar en **Archivos → En mi iPhone → IOSurface Preflight → IOSurfaceRuns**, gracias a `UIFileSharingEnabled` y `LSSupportsOpeningDocumentsInPlace`. Si la instalación o la firma no habilitan esa carpeta, el botón **Exportar** sigue ofreciendo los archivos de la campaña más reciente.

## v19.4: fuerza bruta controlada por lotes sobre API pública

La opción **23. Fuerza bruta controlada: 3 x 50.000** ejecuta tres campañas secuenciales de 50,000 casos sobre la API pública de IOSurface con semillas únicas dentro del lote, máximo 150,000 casos. Cada ejecución usa las mismas reglas de generación y comprobación acotada que la v19.3. No realiza llamadas privadas, acceso a punteros liberados ni pruebas de escalada de privilegios.

- Presenta confirmación antes de iniciar la campaña; no admite solapamiento con otras pruebas.
- Revisa resultados entre lotes y detiene la secuencia si hay excepciones, errores de integridad, alertas de revisión o problemas de persistencia. Un error registrado durante un lote lo interrumpe al terminar la iteración actual.
- El botón **Detener prueba activa** cancela el lote en curso y evita que empiecen los restantes.
- Cada subcampaña queda archivada en \`Documents/IOSurfaceRuns/<run-uuid>/\` con su propia semilla, checkpoint, trazas, cobertura y formatos.
- La campaña agrupada se archiva en \`Documents/IOSurfaceBatches/<batch-uuid>/manifest.json\` y \`summary.csv\`. Sus últimas versiones también aparecen como \`IOSurfaceBruteForceBatch-v19_4.json\` y \`IOSurfaceBruteForceBatch-v19_4.csv\` en \`Documents/\`.
- La aplicación **no** reinicia automáticamente una campaña interrumpida después de cerrarse. Los archivos persistidos permiten revisar su último estado, que puede quedar \`RUNNING\` si la aplicación se cerró inesperadamente.

El archivo \`manifest.json\` conserva las semillas, los identificadores de cada subcampaña, los resultados y los totales para reproducibilidad. Todos los archivos permanecen locales hasta que el usuario los exporta.

**Precaución:** es una campaña de diagnóstico más extensa y puede afectar a la estabilidad o al espacio de almacenamiento disponible. Un resultado sin anomalías no demuestra que no existan vulnerabilidades, y ninguna anomalía aislada demuestra UAF, exploit ni KernelRW.

### Pruebas nuevas

\`\`\`sh
clang -std=c11 -Wall -Wextra -Werror IOSurfacePreflight/Tests/PFBoundedBatchTests.c -o /tmp/pf-batch-tests
/tmp/pf-batch-tests
\`\`\`

## v19.5: cobertura efectiva y fuerza bruta de entradas nuevas

La opción **24. Fuerza bruta de entradas nuevas (hasta 50.000)** analiza primero los CSV locales de hasta seis campañas anteriores recientes, con un límite de 250.000 filas de historial. Crea una tabla de claves exactas y, durante la campaña, **deduplica antes de llamar a IOSurfaceCreate**. Por ello un intento nuevo enviado representa una configuración de diccionario de entrada distinta de las ya cargadas y de las enviadas en esta ejecución. No es una medición interna de rutas del kernel.

Para comparar lo que efectivamente se envía, la clave incluye ancho, alto, bytes por elemento, formato solicitado; stride y tamaño de asignación solo cuando están presentes en el diccionario; e indicadores que distinguen una propiedad ausente de una propiedad presente con valor cero.

Las firmas se comparan por sus campos completos, incluso cuando chocan hashes. La tabla tiene 524.288 ranuras (aproximadamente 16 MiB), permite una ocupación máxima del 80 % y distingue duplicados históricos de duplicados producidos dentro de la campaña. El generador determinista usa SplitMix64, diferente al xorshift32 legado, y conserva la semilla para reproducir los candidatos. Las demás opciones mantienen sus generadores anteriores.

**Presupuestos:** máximo 50.000 nuevas llamadas efectivas; máximo 200.000 candidatos incluyendo los duplicados descartados; los seis CSV históricos más recientes como máximo, con 250.000 filas entre todos y 32 MiB por archivo. El botón de cancelación detiene el ensayo y la campaña se corta ante excepciones, alertas de revisión o fallos de integridad.

Si se agota el presupuesto de candidatos sin hallar 50.000 configuraciones diferentes, el estado es `NOVELTY_CANDIDATE_BUDGET_EXHAUSTED`. Esto no significa que se detectó una vulnerabilidad. La novedad se define exclusivamente respecto a la **ventana histórica cargada** y a la ejecución actual. Si el historial es más grande que el límite, `window_truncated` indica que no hay cobertura de todo el pasado.

**Archivos:** `IOSurfaceNovelty-v19_5.json` y `IOSurfaceNovelty-v19_5.csv` en Documents para la última campaña; y `Documents/IOSurfaceRuns/<UUID>/novelty.json`, `novelty-duplicates.csv`, checkpoint y trazas archivados. Los CSV de casos llevan `candidate_index` para reproducir el orden del generador.

**Alcance:** una configuración nueva no implica ejecutar una ruta nueva de kernel. Los rechazos y las excepciones de APIs públicas no prueban por sí solos UAF, corrupción del kernel, escalada de privilegios ni KernelRW. Esta opción opera solamente con APIs públicas y superficies propias.

**Prueba C11:**

```sh
clang -std=c11 -Wall -Wextra -Werror IOSurfacePreflight/Tests/PFNoveltyCoverageTests.c -o /tmp/pf-novelty-tests
/tmp/pf-novelty-tests
```


## v19.6: cobertura de entradas estratificada (build 25)

Después de una campaña con 200.000 candidatos y solo 40.218 diccionarios nuevos
ejecutados, la opción 24 diversifica **solo** las dimensiones de entrada:
50% de selecciones de ancho/alto mantienen los 16 valores límite originales,
25% toman un límite con desplazamiento de -8 a +8 (recortado a 0..256), y
25% toman un entero de 0..256. El resto de combinaciones y los topes de
50.000 llamadas/200.000 candidatos no cambian. El generador se reproduce
mediante la semilla de campaña y la prueba C11 comprueba 200.000 candidatos
sin efectuar ninguna llamada a IOSurface. Los informes nuevos se denominan
`IOSurfaceNovelty-v19_6.json` y `IOSurfaceNovelty-v19_6.csv`.
Los archivos archivados conservan sus nombres.

Esto mejora la **diversidad de entradas públicas**, no la cobertura de rutas
internas del kernel, y no implementa UAF, KernelRW ni exploits.


## v19.7: reproducción dirigida de una fila archivada

La opción **25. Reproducir caso del CSV local (3 veces)** lee únicamente los
archivos `Documents/IOSurfaceRuns/<UUID>/boundary-trace.csv` de la app.
Se selecciona por número de caso o, si se deja vacío, automáticamente una fila
aceptada de BGRA con dimensiones no nulas. El programa reutiliza **los parámetros
exactos** (incluidas omisiones de stride y alloc) y realiza hasta tres
`IOSurfaceCreate` mediante la API pública. Compara éxito/rechazo y dimensiones,
stride y alloc observados; detiene la repetición ante una discrepancia.

Solo en superficies propias BGRA elegibles realiza una comprobación mínima
de escritura/lectura de un byte, restaurando el valor original y liberando la
referencia. No usa selectores privados, punteros obsoletos ni acceso al kernel.

Los resultados se guardan después de cada repetición en
`Documents/IOSurfaceTargetedReplay-checkpoint.json` y
`Documents/IOSurfaceTargetedReplay-trace.csv`, que el botón Exportar comparte.
Un resultado `MATCH_3_OF_3` indica consistencia observada, no ausencia general de
vulnerabilidades; `DIVERGED` o un fallo de integridad requiere revisión y no
prueba un exploit. Si no hay CSV local válido, ejecutá antes la opción 24.

## v19.8: transferencia efectiva de IOSurface mediante un puerto Mach

El botón **26. Transferencia Mach real: imagen editable** realiza operaciones públicas reales, no un diagnóstico simulado:

1. Crea una IOSurface propia BGRA de 128×128 (65.536 bytes) y escribe un patrón determinista en su memoria.
2. Obtiene un puerto mediante `IOSurfaceCreateMachPort`; libera la referencia original y recupera otra mediante `IOSurfaceLookupFromMachPort`.
3. Libera el puerto Mach y comprueba que la referencia reconstruida conserva los bytes originales, comparando FNV-1a de 64 bits.
4. Dibuja un cuadrado cian en el búfer recuperado, contrasta cada byte con una imagen reconstruida de forma independiente, la muestra en pantalla y la guarda como PNG.
5. Archiva `Documents/IOSurfaceMachHandoff-v19_8.json` y `Documents/IOSurfaceMachHandoff-v19_8.png`, accesibles desde Archivos y el botón Exportar.

Si iOS no exporta esos símbolos públicos o niega la transferencia del puerto, la app informa `UNAVAILABLE`/`ERROR` y en qué etapa ocurrió; nunca devuelve `PASS` sin comparar los bytes. El código utiliza solamente memoria de su propia IOSurface, no provoca condiciones de carrera ni prueba una vulnerabilidad del kernel. Es una transferencia **dentro del mismo proceso**, no una prueba de acceso entre apps, escalada de privilegios, KernelRW ni jailbreak.

El archivo `Sources/PFMachPortPattern.h` separa la generación y el sello de píxeles para probarlos en C11 antes de la compilación de iOS:

```sh
clang -std=c11 -Wall -Wextra -Werror IOSurfacePreflight/Tests/PFMachPortPatternTests.c -o /tmp/pf-mach-pattern-tests
/tmp/pf-mach-pattern-tests
```

**Limitaciones:** requiere autorización de firma para instalar el IPA no firmado que entrega GitHub Actions. La funcionalidad real de transferencia debe validarse en el iPhone, ya que CI compila y ejecuta las pruebas C pero no dispone de un dispositivo iOS físico.


## v19.9: control de revocación de derechos Mach

El botón **27. Verificar revocación de derechos Mach (1 ensayo)** somete a prueba una propiedad concreta del control de acceso de \`IOSurfaceLookupFromMachPort\`, siempre utilizando una IOSurface propia y APIs públicas:

- Control positivo A: crear una IOSurface BGRA 64×64 y recuperar su mismo ID mediante un puerto Mach válido.
- Control positivo B: agregar una referencia al derecho de envío, liberar una referencia y comprobar que el derecho restante continúa siendo válido.
- Revocación: liberar el último derecho de envío, verificar que ese nombre ya no conserva un derecho SEND y comprobar una sola vez que \`IOSurfaceLookupFromMachPort\` no entrega una superficie a partir del nombre revocado.
- Dos controles negativos: un puerto Mach válido de un tipo ajeno (creado por nuestra aplicación) y \`MACH_PORT_NULL\`, que también deberían ser rechazados.

Los derechos y referencias propios se liberan al terminar. La IOSurface original se mantiene viva durante los controles para no confundir revocación del derecho de acceso con destrucción del objeto, reutilización de ID o cambios en el ciclo de vida del kernel. No se emplean servicios privados ni referencias sin dueño, y no se repiten casos en bucle.

El archivo \`Documents/IOSurfacePortRevocation-v19_9.json\` recoge los resultados por separado, los códigos de retorno, las condiciones comprobadas y el veredicto:

- \`EXPECTED_REJECTION\`: los controles positivos funcionaron, el nombre quedó inválido y los negativos fueron rechazados.
- \`REVIEW_UNEXPECTED_SURFACE\`: algún control negativo devolvió una IOSurface. Requiere revisión manual; no demuestra vulnerabilidad, UAF ni escalada.
- \`INCONCLUSIVE\`: falta un control necesario para evaluar la hipótesis.
- \`UNAVAILABLE\`: faltan funciones requeridas.
- \`BASELINE_FAILED\`: falló la prueba positiva inicial.

Prueba nativa del clasificador (sin iPhone):
\`\`\`sh
clang -std=c11 -Wall -Wextra -Werror \
    IOSurfacePreflight/Tests/PFPortRevocationClassifierTests.c \
    -o /tmp/pf-port-revocation-tests
/tmp/pf-port-revocation-tests
\`\`\`

**Limitación:** esta prueba solo comprueba autorización al consultar IOSurface desde el mismo proceso. No permite inferir acceso entre procesos, corrupción del kernel, KernelRW ni jailbreak. Un fallo inesperado de API se registrará para revisar si se produjo por permisos, transporte o semántica pública antes de atribuirlo al kernel.


## v19.10: informe forense generado directamente en la IPA

La opción **28. Correlacionar evidencia local (sin pruebas invasivas)** genera y guarda en Documentos el informe \`IOSurfaceForensicEvidence-v19_10.json\`. Al tocar **Exportar registro, CSV y checkpoint**, la aplicación actualiza automáticamente el informe y comparte ambos archivos nuevos:

- \`IOSurfaceForensicEvidence-v19_10.json\`: resumen con identificadores de sesión, sello de captura, información pública de dispositivo y versión, manifiesto SHA-256 de los archivos procesados, estado del BootMonitor, solapamiento medido de SameClient, controles de revocación y criterios de evidencia pendientes.
- \`IOSurfaceForensicEvents-v19_10.csv\`: eventos observables desde la app, con timestamp ISO 8601, sesión, uptime y origen \`user_space\`. El archivo se mantiene acotado.

El informe reutiliza los archivos propios del contenedor (no necesita computadora, acceso a Analytics ni conexión a un servidor) y **no ejecuta nuevas campañas ni fuerza condiciones de carrera**.

**Interpretación estricta:** la app normal no puede ver el último \`OSObject::release()\` real de \`IOSurfaceRootUserClient\` ni leer nodos de notificación del kernel. Por tanto, \`kernel_last_release_observed\`, \`notification_survived_final_release_observed\` y \`post_free_dispatch_observed\` permanecen en \`false\`. La existencia de solapamiento de llamadas y de una revocación Mach normal nunca se presenta como un UAF demostrado.

### Uso desde el iPhone

1. Abrir IOSurfacePreflight 0.19.10.
2. Tocar **28. Correlacionar evidencia local**. La app registra un resumen del diagnóstico ya guardado.
3. Tocar **Exportar registro, CSV y checkpoint** y compartir \`IOSurfaceForensicEvidence-v19_10.json\` y el CSV de eventos. No hace falta repetir los ensayos previos.

### Verificación

La ejecución de GitHub Actions compila y ejecuta \`PFForensicEvidenceTests.m\` en macOS, además de producir la IPA para iOS. La IPA exportada no está firmada: para instalarla en el iPhone hace falta una firma válida de la cuenta del usuario. El identificador \`org.iosurface.preflight\` se mantiene para conservar los Documentos existentes cuando la instalación sea una actualización compatible.
