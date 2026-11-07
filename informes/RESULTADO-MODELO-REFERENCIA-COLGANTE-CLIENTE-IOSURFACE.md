# ¿Una notificación de IOSurface puede utilizar un cliente después de su última liberación?

**Investigación 2026-11-06. Dispositivo:** iPhone14,3; builds 24A437 y 24B119.  
**Veredicto:** **alcanzable en un modelo abstracto bajo hipótesis explícitas; NO demostrado en el kernel real**.

## Hechos del código revisado
- La entrada de notificación guarda un puntero al cliente y el despacho puede volver a utilizarlo.
- Registro, retirada y despacho están serializados mediante el mismo bloqueo de lista; una retirada simultánea no libera un nodo mientras está siendo recorrido bajo ese bloqueo.
- El cliente de IOSurface configura explícitamente `defaultLocking=false` (inferencia estática respaldada por referencias a las propiedades del binario y verificada en CI). Un método externo ya admitido y el cierre no reciben serialización automática mediante esa propiedad.
- IOKit obtiene una referencia adicional durante la llamada IPC; al terminar la llamada esa referencia deja de proteger al cliente.
- `IOMachPort` conserva otra referencia hasta completar el cierre por no-senders.
- `IOUserClient::registerOwner` guarda un puntero en la lista de propietarios de tareas, sin incrementar directamente el contador de referencias en ese método.
- En 27.2 se añade un indicador que impide aceptar nuevas notificaciones durante el cierre.

## Comprobación de estados: contraejemplo condicional
Se exploraron combinaciones de eventos simbólicos, no operaciones ejecutadas en un iPhone. El modelo permite un registro pendiente antes del cierre, serializa las operaciones sobre la lista y contabiliza dos propietarios fuertes (puerto y llamada RPC). Considera, como supuesto **no confirmado**, que el nodo no mantiene una retención fuerte y no existen otras retenciones ocultas.

| Configuración abstracta | ¿Estado de puntero colgante alcanzable? | Estados explorados |
|---|---|---:|
| 27.0, sin comprobación de cierre y sin referencia del nodo | **Sí** | 25 |
| 27.2, con comprobación de cierre | No | 18 |
| Nodo con referencia fuerte al cliente | No | 26 |
| Cierre serializado con la llamada RPC | No | 12 |

Secuencia testigo resumida para el modelo 27.0: llamada admitida → retirada de notificaciones al cerrar → termina la referencia del puerto → se admite un nodo tardío mientras la llamada todavía retiene el cliente → termina la referencia de la llamada → el despachador intenta usar la dirección almacenada.

**Este testigo depende de una hipótesis de propiedad, no confirma que una ejecución concreta alcance el último release en iOS.** Si existe cualquier otro propietario fuerte de la instancia, no puede inferirse la destrucción final. Tampoco se ha observado un despacho real después de la destrucción.

## Qué está descartado y qué no
- **Descartado como prueba:** que el mero retorno de `clientClose` implique liberación final; que un nodo almacenando un puntero sea necesariamente UAF; y que el modelo reproduzca un fallo real del kernel.
- **Confirmado:** la sincronización de la lista no basta, por sí sola, para demostrar protección de toda la vida útil del cliente; la comprobación nueva en 27.2 elimina esta intercalación del modelo.
- **No confirmado:** contabilidad absoluta de todas las referencias del cliente en iOS 27.0, último `OSObject::release` efectivo y entrega posterior al mismo objeto.

## Evidencia requerida para un veredicto de corrupción real
Se necesita una correlación verificable de identidad de objeto, último release y entrega posterior. Los datos históricos de IOSurfacePreflight y los binarios estáticos no contienen esa traza. Sin esa correlación, la conclusión correcta sigue siendo **POSIBILIDAD CONDICIONAL, NO UAF DEMOSTRADO**.

## Fuentes
- `iokit/Kernel/IOUserClient.cpp`: implementación pública de `IOMachPort::withObject`, `registerOwner`, `ipcEnter`, `ipcExit` y cierre por no-senders.
- `osfmk/device/iokit_rpc.c`: obtención y devolución de referencias durante consultas de conexión.
- `informes/AUDITORIA-REFERENCIAS-NOTIFICACIONES-IOSURFACE.md` y `informes/IOUSERCLIENT-LOCKING-EFECTIVO-Y-REFERENCIAS.md`.
- Aviso Apple: https://support.apple.com/en-us/149230, CVE-2026-112477.
