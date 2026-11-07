# Auditoría del ciclo de vida de referencias de notificación de IOSurface

**Dispositivo:** iPhone14,3. **Firmwares:** iOS 27.0 (24A437) e iOS 27.2 (24B119).  
**Estado:** recorrido de referencias confirmado; uso después de destrucción NO confirmado.

## Pregunta

¿Puede una notificación conservar una referencia a `IOSurfaceRootUserClient` después de que el cliente sea destruido, y puede una ruta posterior utilizar esa referencia sin retención válida?

**Resultado:** encontramos almacenamiento y uso posterior de un puntero al cliente, pero no demostramos que exista un momento en el que el cliente ya haya sido liberado y la entrada siga siendo accesible.

## Flujo real confirmado mediante ARM64

1. **Registro:** una rutina toma el puntero al cliente proporcionado como argumento, lo guarda en una entrada de la lista de notificaciones y enlaza la entrada a la lista del objeto raíz. La inserción es directa; en esa ruta no se observa una retención explícita del cliente.
2. **Despacho:** otra rutina, mientras recorre la lista, carga el puntero almacenado y lo pasa a la función que procesa la notificación.
3. **Uso:** el procesador accede a un miembro del objeto cliente antes de realizar otra llamada directa. No hay una retención explícita visible en este intervalo local.
4. **Retirada:** una tercera rutina busca entradas con el puntero del cliente y las desenlaza, liberando sus entradas.
5. **Cierre:** la versión antigua ejecuta la retirada después de otras operaciones de limpieza; la corregida la adelanta y utiliza un estado de cierre para evitar registros tardíos.

Las cinco propiedades anteriores se observaron en los KEXT originales extraídos de IPSW de Apple para el mismo modelo. Un verificador estático local examinó **10 invariantes por build, 20/20 satisfechas**, incluyendo las cargas, almacenamientos, llamada a la rutina de despacho y cambio de orden de cierre.

### Interpretación de propiedad

- El nodo contiene un puntero al cliente, pero el desensamblado no demuestra que **posea una referencia con incremento de contador**.
- Que las dos funciones observadas no hagan `retain` localmente **no excluye** que una referencia válida se mantenga por IOKit o el gestor de conexiones durante la operación.
- Las funciones que recorren o modifican la lista usan una región crítica compartida. El análisis debe distinguir protección de la lista, vida útil del cliente y vida útil de otros miembros internos.

## Hipótesis y prueba ausente

**Hipótesis respaldada:** una alta tardía puede competir con la retirada del cliente durante el cierre. La protección de iOS 27.2 introduce un control de estado y cambia el orden de limpieza para impedir dicha condición.

**No demostrado en los binarios disponibles:** que una entrada siga viva **después de la última liberación efectiva del cliente**, que un despacho posterior recorra esa entrada, que no exista ninguna retención en otras rutas del kernel, o que se produzca una lectura/escritura en memoria realmente liberada.

El `write-after-free` de nuestro modelo en C **no es evidencia del comportamiento del kernel de Apple**.

## Qué evidencia permitiría cerrar la cuestión

- La ubicación y semántica de la última liberación del cliente.
- Las garantías reales de exclusión mutua y retención de IOKit mientras hay llamadas en curso.
- Una relación de orden reproducible que pruebe acceso posterior a esa liberación, o la demostración de que las referencias impiden tal acceso.

## Resultado final de auditoría

`DIRECT_POINTER_STORAGE_AND_LATER_USE_CONFIRMED__POST_DESTRUCTION_USE_UNPROVEN`

**No se ha demostrado UAF, corrupción del kernel, ni relación causal inequívoca con CVE-2026-112477.** El aviso de Apple identifica la CVE como carrera corregida con mejor sincronización, pero no publica la ruta exacta: https://support.apple.com/en-us/149230

Fuente reproducible: [GitHub Actions 42328640652](https://github.com/ioezgamer/IOSurfaceSafeProbe/actions/runs/42328640652). Desensamblado completo disponible como artefacto privado temporal de la ejecución, sin agregarse a la rama del repositorio.
