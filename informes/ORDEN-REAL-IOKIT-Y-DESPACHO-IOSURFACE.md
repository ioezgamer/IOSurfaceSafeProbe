# Orden de retirada, ultima liberacion y despacho en IOSurface

**Dispositivo:** iPhone14,3, iOS 27.0 `24A437` e iOS 27.2 `24B119`  
**Estado:** 26 comprobaciones sobre desensamblado original: 13/13 por version. El ultimo `release` efectivo del cliente y un acceso posterior sobre memoria liberada **no** se han observado.

## Hechos que verifica el desensamblado

- La insercion de notificaciones, la eliminacion de registros de un cliente y el despacho recorren la misma lista del objeto IOSurfaceRoot, usando la misma pareja de operaciones de sincronizacion sobre `root+0x150`. Las secciones criticas se excluyen entre si.
- Durante el despacho, la entrada proporciona un puntero al cliente; la rutina llamada lee un campo de ese objeto. No existe una operacion `retain` **localmente visible** entre la carga y el primer uso.
- La retirada del cliente, llamada desde la ruta de cierre del `IOSurfaceRootUserClient`, elimina las entradas correspondientes antes de retornar de esa ruta.
- La rutina de despacho tiene un llamador directo dentro de una ruta que modifica el contador de referencias de una IOSurface. No requiere una nueva consulta Mach del puerto del cliente por cada entrega.
- En iOS 27.0, la retirada no establece una marca que el registro compruebe. En 27.2, la retirada marca el estado del cliente y el registro rechaza nuevas altas si dicho estado esta activo.

## Relaciones de orden que quedan demostradas

| Intercalacion de operaciones | Consecuencia demostrable |
|---|---|
| Despacho entra primero en la seccion critica | La retirada no puede tocar la misma lista hasta que termine el recorrido |
| Retirada entra primero y no hay nuevas altas | La entrada eliminada ya no puede ser recuperada por ese recorrido |
| Retirada termina y una nueva alta llega al registro de 27.0 | La ruta local no comprueba un estado de cliente en retirada; su aceptacion general depende de otras condiciones de IOKit |
| Retirada termina y una nueva alta llega al registro de 27.2 | La ruta corregida comprueba la marca de cierre y la rechaza |
| Ultima liberacion real del cliente frente a entrega | **No demostrado:** el desensamblado de IOSurface no establece el instante final del ultimo `release` de `IOUserClient` |

Por tanto queda **descartada** como prueba de UAF la hipotesis simple de liberacion concurrente de un nodo de lista durante un recorrido protegido por el mismo bloqueo. La diferencia de seguridad interesante es que la version corregida bloquea el registro posterior al inicio del cierre.

## Garantias publicas de IOKit y limites

1. El codigo de XNU de Apple establece que al buscar una conexion valida mediante `iokit_lookup_connect_port` o `iokit_lookup_connect_ref_current_task` se adquiere una referencia al objeto; el resultado debe liberarse posteriormente.
2. `IOUserClient::ipcEnter/ipcExit` mantienen una cuenta de operaciones activas, relevante para demorar determinadas finalizaciones.
3. La ruta de cierre `iokit_connect_no_senders` invoca `clientDied()` con bloqueo de escritura del cliente.
4. `IOUserClient2022` documenta opciones de bloqueo que permiten serializar `IOServiceClose` con `externalMethod`. Esto **no** prueba que la subclase IOSurface de esos builds utilice esa configuracion.
5. Una referencia obtenida para una llamada IPC **no es** una retencion automatica que proteja los punteros almacenados en las entradas de notificacion para toda su vida util. La entrega de notificaciones sigue otra ruta.

**Importante:** `clientClose()` no equivale a destruccion de memoria: una ultima referencia puede perdurar despues del cierre. Tampoco se puede declarar que exista una entrada colgante sin acreditar que la ultima referencia se libero mientras la entrada seguia accesible.

Fuentes de IOKit/XNU (su rama publica no sustituye la configuracion exacta de los firmware auditados):
- https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/device/iokit_rpc.c
- https://github.com/apple-oss-distributions/xnu/blob/main/iokit/Kernel/IOUserClient.cpp
- https://github.com/apple-oss-distributions/xnu/blob/main/iokit/IOKit/IOUserClient.h

## Veredicto

`SHARED_LOCK_AND_DEFERRED_DISPATCH_CONFIRMED__POST_DESTRUCTION_USE_NOT_PROVEN`

Se confirma **un orden parcial**, no una secuencia cronologica unica de una ejecucion real. El control del ultimo `release` depende de referencias y rutas IOKit que aun no pueden deducirse de estas secciones del binario. Los registros existentes de IOSurfacePreflight no incluyen una traza de destruccion del objeto. No es valido presentar este resultado como un UAF del kernel, corrupcion de memoria, KernelRW ni prueba de la CVE.

**Reproduccion:** `audit_iosurface_order.py` (auditado offline), el JSON `IOSurface_orden_y_garantias_IOKit.json` y los dos `.asm.gz` del artefacto de [GitHub Actions 42328640652](https://github.com/ioezgamer/IOSurfaceSafeProbe/actions/runs/42328640652). Se conserva la comparacion binaria en la rama de investigacion sin modificar el IPA.
