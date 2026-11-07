# Configuración efectiva de bloqueo y referencias: IOSurfaceRootUserClient

**Modelo:** iPhone14,3. **Firmwares:** 24A437 (iOS 27.0) y 24B119 (iOS 27.2).  
**Método:** análisis estático de los KEXT extraídos de los IPSW oficiales de Apple, contraste con el código público de XNU. No se ha usado instrumentación ni ejecución privilegiada en el dispositivo.

## 1. Propiedades de bloqueo: hallazgo en los dos binarios

**Se corrigió la hipótesis anterior de que podría no haber configuración explícita.** El binario contiene las cuatro claves y su inicializador las configura mediante cuatro llamadas indirectas al método de establecimiento de propiedad (vtable, desplazamiento `0xc8`).

| Propiedad | Argumento del objeto booleano en la rutina | Valor inferido |
|---|---|---|
| `IOUserClientEntitlements` | `[x20]` | `kOSBooleanFalse` |
| `IOUserClientDefaultLocking` | `[x20]` | `false` |
| `IOUserClientDefaultLockingSetProperties` | `[x8]` (otra constante) | `true` |
| `IOUserClientDefaultLockingSingleThreadExternalMethod` | `[x20]` | `false` |

Esto es idéntico en las dos versiones comparadas. Se verificaron ocho referencias exactas `adrp + add` hacia las cuatro cadenas Mach-O, cada una seguida por una llamada de establecimiento de propiedad, y que las tres propiedades citadas reutilizan el mismo objeto booleano. Para los binarios `24A437` y `24B119` los SHA-256 del KEXT fueron, respectivamente, `3f95c45f629a8749775765980434ee927552e1cad4e568743062bf901aa018d8` y `a1d255c31648eb54385b32cb51277a262b7d99c246a5195e591ae8d827b3275c`.

**Interpretación de los valores:** en XNU, la propiedad `IOUserClientEntitlements` admite explícitamente `kOSBooleanFalse` para permitir la apertura sin un entitlement específico, o una cadena para exigirlo. La misma constante enlazada se utiliza para `DefaultLocking` y `SingleThreadExternalMethod`, por lo que ambas se infieren en `false`. El tercer ajuste utiliza el otro booleano y se infiere en `true`. La identidad de los símbolos booleanos no pudo recuperarse directamente del KEXT sin tabla de símbolos; se trata de una inferencia estructural contrastada con la validación de XNU, no de una lectura dinámica del bit.

**Consecuencia operativa:** `IOUserClient::callExternalMethod()` usa `ipcEnter(kIPCLockNone)` cuando `defaultLocking == false`. Por eso no toma el bloqueo de lectura del cliente que normalmente lo serializaría frente a un cierre con bloqueo de escritura. El ajuste `DefaultLockingSetProperties` no altera este hecho.

La excepción del bloqueo automático aplicada por XNU a extensiones dependientes de IOSurface deja de ser la cuestión decisiva aquí: **el propio binario del cliente configura los valores explícitamente**.

## 2. Contabilidad de referencias de una llamada aceptada

En la ruta pública de IOKit:

| Fase | Referencias OSObject sobre el cliente | Cuenta de llamadas `__ipc` |
|---|---|---|
| Puerto Mach vinculado a cliente | `IOMachPort::withObject` conserva una referencia con `taggedRetain` | Sin aumento por ese evento |
| Resolución de conexión para RPC | La consulta IPC entrega una referencia temporal extra `+1` | Todavía sin aumentar |
| Entrada en `IOUserClient::callExternalMethod` | La referencia temporal sigue viva | `ipcEnter(kIPCLockNone)` incrementa |
| Método externo en ejecución | La referencia temporal protege al objeto de destrucción final | `__ipc > 0` por esa llamada |
| Salida de método | Referencia temporal todavía válida | `ipcExit` decrementa, puede reprogramar finalización |
| Limpieza de RPC | Se libera la referencia temporal `-1` | El método ya salió |
| Notificación `no-senders` del puerto | `clientDied` se llama mientras el puerto mantiene una referencia; luego se libera la referencia del puerto | Independiente de la cuenta de RPC activas |

Los símbolos `+1`/`-1` expresan **deltas** documentados, no el recuento absoluto de todas las referencias del sistema.

El código de XNU muestra que `ipcEnter` incrementa `__ipc` incluso cuando el bloqueo elegido es `kIPCLockNone`. También usa `__ipcFinal` y `scheduleFinalize` para aplazar ciertas finalizaciones. **No** hay que confundir la cuenta `__ipc` con el contador de referencias del objeto `OSObject`.

## 3. Orden parcial confirmado y su efecto

- `iokit_connect_no_senders` toma el bloqueo de escritura para `clientDied`; el puerto retiene al cliente hasta completar ese cierre.
- Como `defaultLocking == false`, el método externo previamente admitido no adquiere por defecto el bloqueo complementario de lectura; **es posible el solapamiento** entre cierre y método admitido.
- Un método admitido conserva una referencia propia hasta su retorno. **La destrucción final del cliente no puede suceder antes del retorno de esa llamada por esa misma vía**.
- El registro, retirada y despacho de notificaciones de IOSurface utilizan un bloqueo específico de la lista; esto impide que modifiquen simultáneamente esa lista dentro de las regiones examinadas.
- iOS 27.2 añade una marca de cierre que impide una alta posterior a la retirada. iOS 27.0 no contiene ese control.
- La entrega de notificaciones puede tener origen en una ruta distinta de la llamada IPC registrada, por lo que las garantías de vida útil del método no prueban automáticamente las del puntero almacenado para un uso futuro.

**Conclusión:** se ha resuelto la configuración efectiva inferida y la contabilidad de referencias relativa de una llamada ya admitida. El orden muestra que una llamada puede estar activa durante el cierre y seguir manteniendo vivo al cliente. Aún no se ha demostrado una notificación que use el puntero después de la última liberación, ni corrupción de memoria ni que ésta sea la causa exacta de CVE-2026-112477.

## 4. Reproducibilidad y fuentes

- [Ejecución GitHub Actions que extrajo los KEXT exactos, cadenas y símbolos](https://github.com/ioezgamer/IOSurfaceSafeProbe/actions/runs/42330210172).
- `scripts/inspect_iosurface_locking_metadata.py`, presente en esta rama.
- [XNU IOUserClient.cpp: inicialización de propiedades, ipcEnter/Exit y no-senders](https://github.com/apple-oss-distributions/xnu/blob/main/iokit/Kernel/IOUserClient.cpp).
- [XNU iokit_rpc.c: adquisición de referencias para conexión IPC](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/device/iokit_rpc.c).
- [XNU IOUserClient.h: semántica de defaultLocking](https://github.com/apple-oss-distributions/xnu/blob/main/iokit/IOKit/IOUserClient.h).
- El código XNU público permite razonar sobre sus garantías, pero no se ha validado una coincidencia byte a byte de toda su implementación con los dos kernelcache cerrados de Apple.
