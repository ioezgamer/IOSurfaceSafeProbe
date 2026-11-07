# Apple IOKit Lab v1

Integración experimental basada en la **idea de enumeración y fuzzing IOKit** del repositorio [dawgyg/AppleResearch](https://github.com/dawgyg/AppleResearch). Este código es **una implementación independiente**, no una copia literal de ese fuzzer.

## Estado

- Código de laboratorio de iPhone añadido en **rama separada** `research/apple-iokit-lab-20261107`.
- XcodeGen: `AppleIOKitLab/project.yml`.
- CI: `.github/workflows/apple-iokit-lab-ipa.yml`.
- App: inventario de 12 nombres de servicio; enumera presencia, apertura de user-client tipo 0 y cierre.
- Campaña activa: **16 casos deterministas** (4 selectores x 4 formas de entrada), una conexión por caso, un solo hilo, con checkpoint antes de cada invocación.
- Reproduce un caso concreto con el mismo selector, forma de entrada y semilla.
- No hace KernelRW, no escapa del sandbox, no evade firma ni ofrece jailbreak.

## Riesgo de la prueba activa

La llamada a `IOConnectCallMethod` involucra el kernel; entradas que el controlador no espera pueden provocar **kernel panic, reinicio o pérdida de datos no guardados**. Realizar copia de seguridad, conectar el equipo a alimentación y ejecutar con supervisión. Una confirmación explícita en pantalla precede la ejecución activa. El modo inventario no usa `IOConnectCallMethod`.

La app no puede limitar el tiempo que una llamada se quede bloqueada en el kernel; el botón Detener solo actúa **entre** casos. La persistencia de un checkpoint antes de la llamada se hace con escritura atómica y `fsync`, pero puede perderse información en un fallo de almacenamiento/energía. Un registro `IN_FLIGHT` no prueba por sí solo que esa llamada causó un panic.

## Qué prueba y qué NO

- `matched = true`: existe un servicio en la I/O Registry que coincide con ese nombre.
- `open_kr = 0`: esta aplicación pudo abrir un cliente de tipo 0. **No significa que tenga acceso a todos los métodos ni a otros tipos de usuario.**
- `call_kr = 0`: ese método respondió sin error de IOKit en esta ejecución; el contenido se representa solo por tamaño y huella.
- Reinicio o `panic-full*.ips`: requiere correlación temporal y lectura del backtrace; el resultado no demuestra UAF, OOB ni capacidad de lectura/escritura del kernel.
- Un controlador ausente o no abierto **no se considera inmune** a otras rutas de ataque.

Nota: `IOSurfaceRoot` es el nombre de servicio que se consulta. `IOSurfaceRootUserClient` es un nombre de clase de usuario distinto; confundir ambos genera falsos negativos. Los 12 nombres son candidatos, no se supone que existan en un modelo específico. El iPhone 13 Pro Max utiliza A15, de modo que nombres de controladores de otros SoC pueden estar ausentes.

## Cómo construir

1. En GitHub abrir **Actions > Compilar Apple IOKit Lab IPA** y ejecutar el workflow o actualizar los archivos de la rama.
2. Descargar artefacto `AppleIOKitLab-unsigned-ipa`.
3. Extraer el IPA del ZIP de Actions. El IPA **no viene firmado**: firmar e instalar con cuenta de desarrollo, SideStore u otro flujo autorizado. Es necesario habilitar Modo Desarrollador cuando corresponda.

Alternativa con Mac y Xcode: `cd AppleIOKitLab && brew install xcodegen && xcodegen generate`. Después configurar firma de la aplicación y abrir `AppleIOKitLab.xcodeproj`.

## Uso

1. Pulsar **Inventariar servicios y permisos reales**. Verificar si algún servicio es visible y se abre.
2. Elegir uno de los servicios accesibles. El preferido será `IOSurfaceRoot` cuando esté disponible.
3. Exportar `inventory.json` como línea base antes de cualquier prueba activa.
4. Solo con copia de seguridad y consentimiento explícito: ejecutar campaña de 16 casos.
5. Si hubo cierre/reinicio, **no ejecutar otra campaña** antes de obtener `panic-full*.ips` (Ajustes > Privacidad y seguridad > Análisis y mejoras > Datos de análisis), y exportar el checkpoint. La última fase `IN_FLIGHT` señala el caso en curso, **no causalidad comprobada**.
6. Con los logs, comparar build, clase, selector, argumentos, código IOKit y tiempo; si algo destaca, repetir el caso solo bajo condiciones controladas.

## Archivos exportados

- `AppleIOKitLab-inventory.json`: nombres de servicios, coincidencia y resultado de apertura.
- `AppleIOKitLab-lastcase.json`: último caso preparado, incluso tras un cierre.
- `AppleIOKitLab-checkpoint.json`: fase `IN_FLIGHT`, `COMPLETED`, `STOPPED` o `FINISHED`.
- `AppleIOKitLab-trace.csv`: fila PRE y POST por caso, huella de salida en caso de éxito.
- `AppleIOKitLab-session.txt`: bitácora de la UI y resultado visible.

## Datos de referencia

Para las comparaciones de esta investigación, el dispositivo previamente documentado es `iPhone14,3` (iPhone 13 Pro Max), `iOS 27.0`, build `24A437`. La app muestra el build real de la instalación y avisa si difiere.

Este módulo es compatible en principio con iOS 16+ pero **todavía debe compilarse y verificarse** antes de afirmar funcionamiento en un dispositivo concreto.

## v1.1: corrección tras primera ejecución en iPhone14,3

El inventario real registró 5/12 servicios con apertura tipo 0 exitosa. La campaña para `IOSurfaceRoot` terminó los 16/16 casos (selectores 0,1,2,17 y cuatro modalidades) y **las 16 llamadas devolvieron `0xe00002c2` (`kIOReturnBadArgument`)**. Ningún caso devolvió éxito. No se observó una vulnerabilidad explotable en estos resultados. Las llamadas fallidas de v1.0 tenían buffers inicializados a 4 escalares y 256 bytes; esos valores **no eran respuestas del controlador**.

Cambios en v1.1:
- Muestra `out=N/A` y conteos cero cuando la llamada devuelve error; solo se calculan digest y longitudes si hubo éxito.
- Registra nombre de error y el campo `outputValid` en `lastcase.json`, que ahora se actualiza a `COMPLETED` para no confundir el último caso con un cuelgue.
- Guarda `AppleIOKitLab-summary.json` con conteos de retorno.
- Añade `Baseline pública IOSurface (64x64)` con create/ID/lookup/lock/unlock y su `AppleIOKitLab-public-baseline.json`.
- Accede a esa API pública mediante `dlopen/dlsym` por compatibilidad con SDK de iOS que no expone la cabecera de IOSurface.

Recomendación: ejecutar primero la baseline pública y compartir su JSON. No repetir automáticamente las mismas 16 llamadas fallidas ni lanzar carreras contra controladores privilegiados basándose solo en errores `kIOReturnBadArgument`.

## v1.2: contrato IOSurfaceRootUserClient y nombre de servicio

Se agregó el botón **3. Contrato IOSurface (selector 13, una consulta)**. Hace dos tipos de búsqueda pasiva en I/O Registry para identificar correctamente la instancia (por nombre `IOCoreSurfaceRoot` o por clase `IOSurfaceRoot`) y registra clase, nombre, ID de registro y resultado de apertura tipo 0. A continuación, bajo confirmación, ejecuta **una sola consulta** del selector 13 sin datos de entrada y con 40 bytes de salida, basada en resultados publicados para iOS 27 beta 4. No ejecuta carreras ni genera una cadena de explotación.

Exportar: `AppleIOKitLab-contract.json`.

**Importante:** el contrato en 24A437 puede diferir del publicado para `24A5390f`; un error del selector no equivale a vulnerabilidad. Consultá también [el informe de comparación estática](../informes/AUDITORIA-ESTATICA-IOSURFACE-24A437-2026-11-07.md), que documenta las discrepancias de las 16 llamadas fallidas y las evidencias aún pendientes.

## v1.3: prueba funcional real en iPhone14,3 / iOS 27.0 (24A437)

En lugar de probar números aleatorios, `IOSurfaceDirectRoundTrip.m` ejecuta **una sola secuencia determinista** sobre su propia superficie:

1. Abre `IOSurfaceRoot` como cliente IOKit tipo 0.
2. **Selector 6:** solicita crear una superficie BGRA 64×64, 16.384 bytes (estructura de entrada de 32 bytes y salida de 3.176 bytes). Solo continúa si la creación devuelve éxito y un ID válido.
3. **Selector 4:** busca ese mismo ID mediante **la misma conexión** y comprueba la concordancia con la salida de creación.
4. **Selectores 2 y 3:** intenta bloquear y desbloquear exclusivamente esa superficie, con tamaño exacto de entrada de referencia.
5. **Selectores 9 y 10:** registra una propiedad propia con un valor de prueba aleatorio y lee esa misma propiedad. No se cuentan éxitos por códigos de retorno únicamente: cuando hay salida se intenta **decodificar el valor**, y se coteja también con `IOSurfaceCopyValue` de la API pública si la superficie es visible desde ella.
6. Cierra la conexión y guarda `AppleIOKitLab-direct-roundtrip.json`.

**Controles:** no usa punteros caducados, valores de memoria del kernel, escritura fuera de la superficie, brute force, carreras ni modificación de permisos. Solo se habilita en `iPhone14,3` build `24A437`; exige confirmación del usuario porque las llamadas al controlador siguen pudiendo provocar un panic. El informe expone fases y devuelve `PARCIAL` si algún paso no se cumple; un `PASS` indica únicamente la ruta funcional de la superficie propia.

La referencia de layout proviene de [Kurt-228/ios27-research](https://github.com/Kurt-228/ios27-research/blob/main/docs/iosurface_sel_formats.md), validada en macOS 27/iOS 27 beta 4. **No se garantiza** que sea idéntica en `24A437`: el propósito del nuevo botón es medirlo directamente y documentar cualquier discrepancia. **No es jailbreak ni demuestra KernelRW.**

## v1.4: resultado observado en iPhone14,3 build 24A437

Archivo real aportado por el dispositivo: `AppleIOKitLab-direct-roundtrip.json`, generado en v1.3.

| Paso del cliente IOKit | Resultado de la ejecución real |
|---|---|
| `IOServiceOpen` tipo 0 | `0x00000000` |
| Selector 6: crear BGRA 64×64 | `0x00000000`, ID `156`, 3176 bytes de salida |
| Selector 4: buscar SID 156 | `0xe00002c2` (`kIOReturnBadArgument`) |
| Selector 2: bloquear | `0x00000000` |
| Selector 3: desbloquear | `0x00000000` |
| Selector 9: escribir propiedad propia | `0x00000000` |
| Selector 10: recuperar propiedad | `0x00000000`, 64 bytes |
| Deserializar y comparar valor | Coincide exactamente |
| `IOSurfaceCopyValue`: comparación independiente | Coincide exactamente |
| `IOServiceClose` | `0x00000000` |

**Interpretación:** hay una prueba real de creación, lock/unlock y roundtrip de propiedades sobre una superficie propia desde un cliente IOKit. La consulta del selector 4 fue rechazada. El `PARCIAL` de v1.3 mezclaba la utilidad funcional de la superficie propia con una operación de búsqueda separada.

**Corrección de v1.4:** ahora se exportan `coreRoundTripConfirmed`, `completeCycleConfirmed`, `selector4Diagnostic`, `publicLookupConfirmed` y `verdict`. Con evidencia equivalente, `verdict` debe ser `PASS_CORE_WITH_SELECTOR4_REJECTION` si el ciclo de propiedad funciona aunque `selector4` devuelva `kIOReturnBadArgument`. `completeCycleConfirmed` permanece falso cuando falla el selector 4.

**Corroboración externa, no prueba de causa:** la investigación [Kurt-228, run-idprobe7.log](https://github.com/Kurt-228/ios27-research/blob/main/results/run-idprobe7.log) también registra que una superficie creada mediante el selector 6, consultada desde la misma conexión mediante el selector 4, devuelve `0xe00002c2`. El motivo exacto de rechazo requiere analizar el binario y controles del build objetivo.

**No extrapolar:** que una aplicación pueda modificar propiedades de su propia IOSurface no implica memoria del kernel arbitraria, fuga de direcciones, UAF, escalada de privilegios o jailbreak. Las verificaciones de versión anteriores se han mantenido; la consulta del selector 4 sigue siendo diagnóstica, no un requisito para demostrar el intercambio de propiedades.

## v1.5: prueba secuencial del ciclo de notificaciones IOSurface

El boton **5. Notificaciones IOSurface (secuencial)** agrega una prueba puntual de los selectores 17 y 18 para iPhone14,3 / 24A437. No ejecuta carreras ni intenta alterar memoria arbitraria del kernel.

1. Abre IOSurfaceRoot (cliente tipo 0) y crea UNA superficie propia BGRA 64 x 64 (selector 6).
2. Crea UN puerto Mach propio con derechos de envio/recepcion.
3. Invoca UNA vez el selector 17 mediante IOConnectCallAsyncMethod, con estructura de 24 bytes e ID de la superficie propia. No se han confirmado todos los campos internos del argumento y el driver puede rechazarlo.
4. Solo si el registro fue aceptado, intenta retirarlo UNA vez con selector 18.
5. Cierra secuencialmente la conexion, destruye el puerto y registra los codigos devueltos.

Exporta **AppleIOKitLab-notification-lifecycle.json** con etapas, timestamps, return codes, intentos y veredicto. Un codigo de exito no implica callback recibido ni una corrupcion de memoria. Un JSON IN_FLIGHT tras un reinicio requiere examinar un panic del sistema; no es prueba por si solo.

La nueva funcion requiere confirmacion. Ninguna llamada es deliberadamente concurrente, no duplica registros ni utiliza IDs o puertos liberados. Una llamada a IOKit puede ocasionar un panic, incluso con los controles anteriores. Este experimento verifica aceptacion de contratos, NO reproduce la carrera ni demuestra KernelRW.

Contexto: [informe de notificaciones 24A437](../informes/RUTA-CANDIDATA-IOSURFACE-NOTIFICACIONES-24A437.md).

## v1.6: recepcion real de mensajes en el puerto Mach

La prueba usa el boton **5. Recibir notificacion IOSurface (1,5 s)**. Solo esta habilitada para `iPhone14,3 / 24A437` y requiere confirmacion. Crea una superficie BGRA propia, abre un puerto Mach de recepcion, registra la notificacion con selector 17 una sola vez y espera hasta 100 ms por un mensaje inmediato.

Si la API publica esta disponible y permite recuperar la superficie propia, ejecuta `IOSurfaceIncrementUseCount` y `IOSurfaceDecrementUseCount` UNA vez cada una, leyendo el contador antes, entre ambas y despues. Entre las transiciones intenta recibir mensajes con ventanas de 200 ms y 1200 ms. Usa `mach_msg(... MACH_RCV_TIMEOUT ...)` y limita la recepcion a un buffer de 2048 bytes. Retira el registro con selector 18, cierra el cliente y destruye el puerto en ese orden.

El archivo **AppleIOKitLab-notification-delivery.json** registra: `messageDeliveryObserved`, `notificationOriginVerified` (siempre false por falta de autenticacion independiente), `usageTransitionPerformed`, `usageCountRestored`, y `receivedMessages` con status, tiempo, ID y tamano de cualquier mensaje. El programa no interpreta el contenido ni presenta mensajes recibidos como prueba de origen kernel.

Veredictos posibles: `MESSAGE_ON_REGISTERED_PORT_ORIGIN_UNVERIFIED`, `NO_CALLBACK_OBSERVED_AFTER_USECOUNT_TRANSITION`, `NO_CALLBACK_OBSERVED_WITHOUT_STIMULUS`, `REGISTER_REJECTED_NO_RACE` o avisos de cierre/retirada. La ausencia de un mensaje NO niega que existan notificaciones en otros estados; la recepcion tampoco prueba UAF, KernelRW o CVE.

Este experimento no ejecuta operaciones concurrentes, carreras de cierre, repeticion intensiva, ni usa superficies o puertos liberados. Aunque es acotado, una llamada al kernel puede provocar reinicio; no ejecutar de nuevo si la app deja un checkpoint `IN_FLIGHT` hasta revisar datos de analisis del sistema.

## v1.7: prueba A-B-A de dependencia de la suscripcion

Se agrega el botón **5. Comprobar notificaciones A-B-A**. La IPA genera `AppleIOKitLab-notification-causality.json` con las fases A/B/A de un unico ensayo, siempre sobre una sola IOSurface propia y sin carreras deliberadas.

- **A1, sin registro:** una transicion 0->1->0 del contador de uso y una escucha de 250 ms al puerto Mach antes de invocar el selector 17.
- **B, registro activo:** selector 17 una sola vez, escucha inmediata 100 ms; una sola transicion del contador de uso, con escucha tras incremento (200 ms) y decremento (1200 ms), igual al protocolo que produjo un mensaje 53 de 120 bytes en v1.6.
- **A2, despues de retirar:** selector 18, una comprobacion no bloqueante de si quedaron mensajes pendientes en cola, una transicion 0->1->0 y escucha de 350 ms solo si la cola estaba vacia. Si habia mensajes pendientes, el control posterior queda inconcluso y se preserva su resultado.
- **Cierre:** liberar los recursos en orden, guardar todo y calcular `causalControlSupported` solo si se cumplen todos los controles. La entrega se considera asociada al registro cuando no se observa antes de suscribirse, aparece tras el decremento durante el registro y no aparece tras retirar la notificacion, con el contador restaurado y la limpieza exitosa.

Se incluyen resultados detallados con retorno de mach_msg, informacion de cabeceras, tiempos y conteos de uso. El veredicto `ABA_CONTROL_SUPPORTS_SUBSCRIPTION_DEPENDENCE` es EVIDENCIA DE DEPENDENCIA DE SUSCRIPCION, no prueba que el contenido sea una notificacion autentificada del kernel. No se analizan contenidos ni punteros, no hay UAF, no hay KernelRW y no hay jailbreak.

En el caso de un mensaje de la fase B pendiente despues de selector 18, la app no exige un resultado negativo ni lo califica como fallo del controlador: clasifica la causalidad como inconclusa. Si recibe un mensaje fuera de la ventana observada o no se puede recuperar la superficie propia, tambien queda inconclusa.

El ensayo dura aproximadamente 2,1 segundos de tiempo de recepcion maximo ademas de las llamadas sincrónicas y requiere confirmacion. No repetirlo ante un reinicio hasta revisar el registro de datos de analisis de iOS.

## v1.8: GPU entre búferes del mismo proceso, inspiración F1OOB

Esta prueba está inspirada en la demostración F1OOB, pero ejecuta únicamente la parte que la auditoría independiente considera verificable: lectura y escritura a través de direcciones GPU entre **dos búferes Metal independientes propiedad de la misma app**. No utiliza el plano comprimido F1 de IOSurface ni llama a selectores privados de AGX. La investigación pública mostró en un control que el acceso cross-buffer también ocurre sin F1.

**Objetivo de la versión:** iPhone 13 Pro Max, `iPhone14,3`, iOS 27.0 compilación `24A437`. Guarda `AppleIOKitLab-gpu-owned-buffer.json` y solo reporta éxito cuando constatan las lecturas reales desde CPU.

1. Crea dos MTLBuffer de 64 KiB en `MTLResourceStorageModeShared` y un búfer de respuesta.
2. Escribe en CPU el marcador preexistente `victim[0]=0x11223344` y usa el shader de calentamiento para escribir `victim[1]=0x47474747`, confirmado por CPU.
3. Obtiene `gpuAddress` de ambos. Solo continúa cuando la VA de la víctima es superior a la base, separada por 64 KiB a 2 MiB y alineada en 4 bytes. No escanea, busca ni modifica recursos ajenos.
4. Un shader `gpu_owned_cross_read` intenta leer `victim[0]` mediante el índice calculado desde la base GPU del primer búfer, con `victim` declarado residente. Comprueba por CPU la respuesta frente a un dato que nunca se escribió a través del primer búfer.
5. Otro shader `gpu_owned_cross_write` intenta escribir `0x57524954` en `victim[0]` por esa misma dirección GPU; lee el contenido desde CPU. Guarda errores, códigos MTLCommandBuffer y los valores reales.

El código **no** fuerza que el resultado sea exitoso. Si la dirección no está disponible, el orden de asignación es distinto o Metal impide el acceso, informa un veredicto de fallo. El shader no utiliza ninguna dirección inventada; todos los valores salen de los búferes propios recién creados.

**Limitaciones:** en el material público de F1OOB, la escritura entre búferes fue reproducible sin F1 y no demostró un fallo de kernel. Los resultados de esta prueba están limitados a un contexto GPU propiedad de la app y no son evidencia de acceso a otros procesos, corrupción del kernel, KASAN, KernelRW ni jailbreak. La pantalla de referencia mostraba `iPhone18,1` con A19 Pro y `24A446`; sus direcciones y clases AGX no son las de nuestro A15.

**Precaución:** acceder más allá del tamaño lógico del búfer de referencia puede provocar fallos de ejecución GPU o reinicios. La app solo ejecuta una vez, se limita a direcciones del propio proceso y registra checkpoints antes de cada fase.
