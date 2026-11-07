# Informe de investigación estática: contrato IOSurfaceRootUserClient

**Fecha:** 2026-11-07  
**Objetivo:** `iPhone14,3` (iPhone 13 Pro Max), iOS `27.0`, build `24A437`.  
**Estado:** análisis comparativo completado; **sin binario IOSurface/kernelcache exacto de 24A437** y por tanto sin validación estática definitiva de los dispatchers en este build. No se ha demostrado vulnerabilidad, UAF ni KernelRW.

## 1. Evidencia medida en nuestro teléfono

Fuentes originales aportadas por el usuario (archivos de Apple IOKit Lab 1.0 y 1.1):

- `AppleIOKitLab-inventory.json`: de 12 nombres consultados, 5 permitieron `IOServiceOpen(..., type=0)`. `IOSurfaceRoot` fue visible y `openType0=0x00000000`. No se probó `IOServiceNameMatching("IOCoreSurfaceRoot")`.
- `AppleIOKitLab-checkpoint.json` y `AppleIOKitLab-session 2.txt`: 16/16 casos contra `IOSurfaceRoot` terminados con `0xe00002c2` = `kIOReturnBadArgument`. No hubo `callKR=0`.
- `AppleIOKitLab-public-baseline.json`: API pública `IOSurfaceCreate`, `IOSurfaceGetID`, `IOSurfaceLookup`, `IOSurfaceLock`, `IOSurfaceUnlock` funcionó, con superficie de 64x64, 16.384 bytes, ID 157, `lockKR=unlockKR=0`.
- **Interpretación:** el cliente IOKit acepta una conexión, la API pública funciona y nuestra matriz de métodos mal formados fue rechazada. Una respuesta `kIOReturnBadArgument` no acredita ni descarta defectos de memoria de rutas no alcanzadas.

## 2. Fuentes externas y versiones (NO equivalentes al objetivo)

| Fuente | Build / plataforma | Evidencia útil | Nivel de transferencia a 24A437 |
|---|---|---|---|
| [Kurt-228/ios27-research, journal §102](https://github.com/Kurt-228/ios27-research/blob/main/docs/SPTM_research_journal_part17.md) y [run-v109.log](https://github.com/Kurt-228/ios27-research/blob/main/results/run-v109.log) | iOS 27 beta 4 `24A5390f`, hardware ajeno | `IOCoreSurfaceRoot`, apertura tipo 0, selector 13 de consulta, selector 6 create y 2/3 lock/unlock funcionaron; referencian 60 selectores, 17 y 40 asíncronos | **Media** para número/función de métodos; **baja** para layouts definitivos del build objetivo |
| [Kurt-228/ios27-research, iosurface_sel_formats.md](https://github.com/Kurt-228/ios27-research/blob/main/docs/iosurface_sel_formats.md) | macOS 27 beta `26A5388g` | Tabla de 63 métodos `IOExternalMethodDispatch2022` y sus límites; investigación de propiedad de superficies por cliente | **Media-baja**: misma familia de driver, NO mismo kernelcache ni versión |
| [time_waste, IOSurface_stuff.h](https://github.com/jakeajames/time_waste/blob/master/time_waste/IOSurface_stuff.h) | iOS histórico | Enumera selectores 6 crear, 9/10/11 valores, 14/15 use-count y 17 `set_notify` | **Baja**: etiquetas históricas; requiere confirmar en iOS 27 |
| [Electra, async_wake.c](https://github.com/coolstar/electra/blob/master/electra/exploit/async_wake.c) | iOS antiguo | Utilizaba `IOConnectCallAsyncMethod` para la ruta 17 `s_set_surface_notify` | **Baja**: no proporciona contrato confirmado para 24A437 |

**Precaución:** `24A5390f` y `24A437` son builds diferentes. Una referencia de macOS o de un jailbreak antiguo nunca es una declaración de compatibilidad con nuestro iPhone.

## 3. Causa probable de los 16 errores

Apple IOKit Lab v1.0 envió 4 variantes por selector. En todos los casos proporcionó una **capacidad de salida de 4 escalares y 256 bytes de estructura**, aunque el controlador puede exigir conteos/tamaños exactos. En las cuatro variantes, el número de escalares de entrada era 0, 1, 1 o 2; solo la cuarta variante enviaba una estructura de 16 bytes.

| Selector | Descripción atribuida por la tabla **macOS 27** | Contrato macOS (scalarIn, structIn, scalarOut, structOut) | Diferencia respecto a v1.0 |
|---|---|---|---|
| 0 | `s_create_surface` | `(1, variable, 0, 3176)` | se solicitaba salida de 4 escalares/256 bytes y no un lock-result de 3176 bytes |
| 1 | `s_release_surface` | `(1, 0, 0, 0)` | salida 4/256, pese a que el contrato de referencia no admite ninguna |
| 2 | `s_lock_surface` | `(0, 12, 0, 3176)` | nunca se envió la estructura de 12 bytes; salida incorrecta |
| 17 | `s_set_surface_notify` | `(0, 24, 0, 0)` más notificación asíncrona | método síncrono y carga estructurada 0 o 16 bytes, en vez de 24 bytes |

Estas diferencias son suficientes para **explicar plausiblemente** un rechazo por validación de argumentos antes de llegar al handler, si el build objetivo conserva esa ABI. No conocemos la instrucción exacta del dispatcher de `24A437`, por lo que **no afirmamos** que las 16 llamadas se detuvieran en la misma instrucción ni que el dispatcher de iOS sea idéntico a macOS.

En concreto, el tamaño `out=4/256` mostrado por v1.0 era la **capacidad inicialmente proporcionada**, no una salida significativa del kernel: todas las llamadas fallaron. Este error de telemetría se corrigió en v1.1.

## 4. Un detalle importante: IOCoreSurfaceRoot vs IOSurfaceRoot

En el registro de `Kurt-228` sobre iOS 27 beta 4, `IOCoreSurfaceRoot` aparece como nombre de servicio, mientras `IOSurfaceRoot` funciona como clase para `IOServiceMatching`. La búsqueda por **clase** (`IOServiceMatching`) y por **nombre** (`IOServiceNameMatching`) son operaciones diferentes.

Nuestro inventario v1.0 solo consultaba por clase. Por eso **no se debe concluir** a partir de `IOSurfaceRoot match=YES` que el nombre real de instancia del registro sea `IOSurfaceRoot`; tampoco hay motivos para tratar las dos cadenas como dos dispositivos independientes.

## 5. Verificación adicional implementada en Apple IOKit Lab v1.2

Botón **“Contrato IOSurface (selector 13, una consulta)”**:

1. Compara `IOServiceMatching` y `IOServiceNameMatching` con `IOSurfaceRoot` y `IOCoreSurfaceRoot`.
2. Recoge nombre de instancia, clase e identificador persistente de entrada de I/O Registry cuando están disponibles. Compara IDs para determinar si ambas búsquedas apuntan a la misma instancia.
3. Abre solo un cliente tipo 0, mediante el primer servicio accesible.
4. Ejecuta **una única consulta** del selector 13, sin datos de entrada y con 40 bytes de capacidad de salida, tal como lo documenta el investigador de iOS 27 beta 4.
5. Guarda `AppleIOKitLab-contract.json` con fases `DISCOVERY_COMPLETE`, `IN_FLIGHT` y `COMPLETED`, resultado IOKit y bytes retornados **solo si hubo éxito**.

**Riesgo y límites:** a diferencia del inventario, la última operación involucra un método externo del kernel y no puede garantizarse exenta de fallos. Se solicita confirmación explícita y no hay bucles, carreras ni acceso a memoria liberada. El resultado exitoso de selector 13 solo valida esa consulta de lectura; no demuestra que otros selectores compartan contrato ni que exista un exploit.

## 6. Qué aún falta para auditoría ESTÁTICA del build exacto

- Adquirir una copia confiable de `com.apple.iokit.IOSurface` y `IOSurface.framework` del **build 24A437 correspondiente a iPhone14,3**; registrar SHA-256 y Mach-O LC_UUID.
- Identificar la tabla real de dispatch `IOSurfaceRootUserClient::externalMethod`, entradas de cada selector, verificaciones de recuentos y restricciones según entitlement para esa versión.
- Trazar específicamente las operaciones que la API pública de creación/lock/unlock usa en ese mismo build. La baseline v1.1 valida el resultado, pero no captura la llamada interna o el número de selector.
- Investigar relaciones de referencias, validaciones y serialización con análisis de binarios en laboratorio, separando observaciones estáticas y dinámicas.
- Para atribuir cualquier panic a una falla de seguridad, correlacionar log `.ips` con build, instrucción, registro y entrada. Evitar asignar UAF/OOB por una simple excepción o reinicio.

### Dictamen

**Resultado demostrado:** IOSurface funciona mediante API pública en el dispositivo, y el cliente IOKit tipo 0 de `IOSurfaceRoot` puede abrirse; las 16 llamadas de v1.0 estaban mal alineadas respecto de los contratos históricos.

**Resultado condicionado:** la correspondencia probable de selectores 0, 1, 2, 13 y 17 se deriva de macOS 27 e iOS 27 beta 4 y **no es aún un mapa exacto confirmado de iOS 24A437**.

**Siguiente evidencia concreta:** `AppleIOKitLab-contract.json` de v1.2, seguida de comparación contra un binario exacto del build 24A437. No es útil repetir fuzzing ciego de 16 llamadas cuya forma ya sabemos que no coincide con las ABI de referencia.

## 7. Validación experimental posterior: Apple IOKit Lab v1.2 en 24A437

**Entrada recibida:** archivo `AppleIOKitLab-contract.json`, generado desde el dispositivo `iPhone14,3`, iOS `27.0`, compilación `24A437`.

**La inspección de registro resolvió la duda entre clase y nombre:**

| Mecanismo | Consulta | Encontrado | Clase real | Nombre real | RegistryEntryID | Open type 0 |
|---|---|---|---|---|---|---|
| `IOServiceMatching` | `IOSurfaceRoot` | Sí | `IOSurfaceRoot` | `IOCoreSurfaceRoot` | `0000000100000579` | `0x00000000` |
| `IOServiceMatching` | `IOCoreSurfaceRoot` | No | — | — | — | N/A |
| `IOServiceNameMatching` | `IOSurfaceRoot` | No | — | — | — | N/A |
| `IOServiceNameMatching` | `IOCoreSurfaceRoot` | Sí | `IOSurfaceRoot` | `IOCoreSurfaceRoot` | `0000000100000579` | `0x00000000` |

**Conclusión directa:** ambas rutas exitosas resuelven la MISMA entrada de registro. No son dos drivers distintos. La aplicación pudo abrir el cliente tipo 0 por ambas búsquedas.

**Consulta única del selector 13 (s_get_limits, etiqueta histórica):**

- `IOConnectCallMethod`, selector `13`.
- Escalares y estructura de entrada: **cero**.
- Capacidad de salida: **cero escalares y 40 bytes** de estructura.
- `openKR=0x00000000`, `callKR=0x00000000`, `phase=COMPLETED`.
- Salida: **40 bytes realmente reportados**, a diferencia de los conteos aparentes de los casos fallidos en v1.0.
- Coincide en tamaño y ausencia de entradas con la documentación externa de iOS 27 beta 4, pero este resultado es **ahora una medida real de 24A437**.

Hexadecimal exacto (40 bytes):
```text
ff3f00007f0000000080000000000000004000000000000000400000000000000000010000000000
```

Decodificación observacional little-endian, sin atribuir campos que no se hayan verificado en el binario `24A437`:

| Offset | U32 little-endian | Nota |
|---|---|---|
| 0x00 | `0x00003fff` = 16383 | posible máscara de alineación de dirección |
| 0x04 | `0x0000007f` = 127 | posible máscara de alineación de fila |
| 0x08 | `0x00008000` = 32768 | comienzo del primer valor u64 desde offset 0x08 |
| 0x10 | `0x00004000` = 16384 | segundo valor u64 |
| 0x18 | `0x00004000` = 16384 | tercer valor u64 |
| 0x20 | `0x00010000` = 65536 | cuarto valor u64 |

Las cuatro cantidades desde `0x08` ocupan **8 bytes cada una**, con mitades altas cero en esta ejecución. Los nombres propuestos para las máscaras se apoyan en estructuras históricas de IOSurface (véase [iocoresurfaceroot.h](https://github.com/userlandkernel/iokitstuff/blob/master/Zeroday/iocoresurfaceroot.h)), pero la ABI exacta de 40 bytes y las semánticas de los valores restantes requieren desensamblado o símbolos del build objetivo.

**Estado epistemológico actualizado:** en `iPhone14,3 / 24A437` quedaron confirmados (a) el nombre y la clase efectivos del servicio y (b) el éxito del selector 13, con tamaño y contenido de salida reproducibles. No quedaron demostrados los contratos de otros selectores, vulnerabilidad de memoria, fuga de dirección, exploit, jailbreak o KernelRW.

**Siguiente paso razonable:** comparar este resultado con `IOSurface.framework` y `com.apple.iokit.IOSurface` extraídos del firmware exacto 24A437; para pruebas dinámicas posteriores, usar únicamente parámetros de contrato verificados y aislar los cambios de estado del controlador. No hay justificación para repetir las 16 llamadas deliberadamente mal formadas.

## 8. Resultado posterior: ciclo funcional directo sobre una IOSurface propia

**Evidencia del teléfono:** `AppleIOKitLab-direct-roundtrip.json`, ejecutado en `iPhone14,3`, `24A437`, `iOS 27.0`, generado con Apple IOKit Lab v1.3.

El selector 6 creó la superficie **ID 156**, con `callKR=0` y un registro de creación de **3176 bytes**. Con esa misma conexión, `selector2 lock`, `selector3 unlock`, `selector9 set_value` y `selector10 get_value` devolvieron `0`. La lectura devolvió **64 bytes**, se decodificó con éxito y el valor recuperado coincidió con el escrito; la API pública `IOSurfaceCopyValue` confirmó por separado ese mismo valor. La conexión se cerró con `0`.

**La única operación rechazada fue `selector4 lookup_surface`**, que devolvió `0xe00002c2` aun con el ID de la superficie creada desde ese cliente. El resultado global `PARCIAL` en v1.3 provenía de exigir que también funcionara esta operación de búsqueda independiente. Una comparación externa en [Kurt-228, run-idprobe7.log](https://github.com/Kurt-228/ios27-research/blob/main/results/run-idprobe7.log) muestra exactamente el patrón `sel6=0` seguido por `sel4=0xe00002c2` sobre una superficie creada desde la misma conexión, en otro build de iOS 27. Esta coincidencia no identifica la condición de rechazo de `24A437`.

**Dictamen actualizado:** es una prueba real de interacción funcional mediante el user client del kernel, con creación de superficie y transferencia verificada de un valor **propio y controlado dentro del espacio autorizado por IOSurface**. No es un exploit; no existe evidencia de lectura o escritura arbitraria de memoria del kernel, UAF, escalada de privilegios o jailbreak.

**Ajuste de instrumentación v1.4:** `coreRoundTripConfirmed` representa creación + lock/unlock + roundtrip de propiedad + cierre. `completeCycleConfirmed` continúa representando *todos* los pasos, incluido `selector4`. Se registra `PASS_CORE_WITH_SELECTOR4_REJECTION` para distinguir ambos resultados sin esconder una verificación funcional positiva. La condición específica de `selector4` se mantiene como cuestión abierta de investigación estática.


## 9. Hallazgo confirmado por análisis del binario exacto

**Se cerró la incógnita del selector 4.** Se extrajo el kernelcache exacto del iPhone14,3 / 24A437 desde el IPSW de Apple, se identificó el KEXT de IOSurface por SHA-256 y se verificó la ruta del selector 4 en código máquina ARM64e.

- Kernel SHA-256: 742714192f267bf7fbfe3de8c5437b534d7f305bf87c8b77c4d1ad9dd7446385.
- KEXT SHA-256: 3f95c45f629a8749775765980434ee927552e1cad4e568743062bf901aa018d8.
- Dos tablas de 60 selectores, 40 bytes por entrada: 0x46638 (normal), 0x46f98 (restringida).
- El selector 4 acepta 1 escalar y salida estructurada de 3176 bytes, exactamente como los proporcionó nuestra app.
- Puntero autenticado del selector 4: 0x8050bcad02c1503c, que resuelve al thunk 0xfffffff009c1903c sobre la base __TEXT del kernelcache 0xfffffff007004000.
- La implementación de búsqueda comienza en 0xfffffff009c1bbc0. En 0xfffffff009c1bc18 llama al ayudante 0xfffffff009c1f5dc, que comprueba si el ID ya está indexado en el cliente. En 0xfffffff009c1bc1c, la instrucción tbnz toma el camino de rechazo si el ayudante devuelve verdadero.
- La rama de rechazo añade 5 al retorno inicial 0xe00002bd, obteniendo exactamente **0xe00002c2**. Ese es el resultado que observamos con nuestra superficie ID 156.

**Dictamen:** el selector 4 rechaza explícitamente la búsqueda por ID de una superficie ya registrada en el mismo user-client. No se trataba de un tamaño de argumento mal especificado, y este caso no aporta indicios de corrupción de memoria.

La verificación independiente automatizada pasó 12 huellas de instrucciones del binario original en [GitHub Actions 42384252470](https://github.com/ioezgamer/IOSurfaceSafeProbe/actions/runs/42384252470). Código de comprobación: AppleIOKitLab/tools/iosurface_dispatch_audit.py.

**Informe técnico completo:** [CAUSA-SELECTOR4-IOSURFACE-24A437.md](CAUSA-SELECTOR4-IOSURFACE-24A437.md).

En el mismo controlador se encontraron diferencias de forma de argumentos en los selectores 43-59 frente al mapa histórico de macOS 27; se confirma que la comparación exacta de versiones es necesaria. No se ha hallado ni demostrado una primitiva KernelRW, UAF o jailbreak.
