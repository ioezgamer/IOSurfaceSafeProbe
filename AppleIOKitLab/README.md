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
