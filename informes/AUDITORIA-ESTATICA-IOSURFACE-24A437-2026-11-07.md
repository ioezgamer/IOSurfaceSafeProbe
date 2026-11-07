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
