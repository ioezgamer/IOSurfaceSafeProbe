# Correlación forense: última liberación de un cliente y uso posterior en IOSurface

**Fecha de revisión:** 2026-11-06 (America/Managua).  
**Dispositivo investigado:** iPhone14,3, iOS 27.0 / build 24A437.  
**Veredicto:** `NO_OBJECT_IDENTITY_MATCH__NO_LAST_RELEASE_EVENT__NO_POST_FREE_DISPATCH_EVENT`.

## Cuestión concreta

Correlacionar, para **la misma instancia de `IOSurfaceRootUserClient`**, una última liberación efectiva, la supervivencia de una notificación y una entrega posterior que lea el puntero almacenado.

Se han contrastado los resultados de IOSurfacePreflight y el dictamen de la traza KDebug con las auditorías estáticas del kernelcache. No se afirma haber inspeccionado directamente la traza KDebug bruta: el resumen de esa fuente procede del dictamen forense anterior `DICTAMEN-CUATRO-CONDICIONES-v60.md`.

## 1. Observaciones cronológicas verificadas

| Fuente | Evidencia real | Observaciones ausentes |
|---|---|---|
| `IOSurfaceSameClient-trace.csv` | Una llamada con intervalo [0, 537.833] µs, y un cierre con [21.458, 195.625] µs. Solapamiento **174.167 µs**. La llamada devuelve `0x10000003` y el cierre `0x00000000`. | No tiene identidad del objeto kernel, contador de referencias, evento de deasignación ni despacho de notificación. El solapamiento es de usuario. |
| `IOSurfacePreflight-log 3.txt` / v11 | Una llamada asíncrona al selector 17 devolvió `0x00000000`, seguida de **cero mensajes** durante tres segundos. | No se observó ninguna entrega de notificación. Un resultado vacío no demuestra que nunca ocurra fuera de la ventana. |
| `IOSurfacePortRevocation-v19_9.json` | Las búsquedas de puerto revocado, no relacionado o nulo fueron rechazadas como era de esperar (`EXPECTED_REJECTION`). | No ensaya la vida útil del puntero de cliente de las notificaciones; `use_after_free_proven=false`. |
| Dictamen previo `DICTAMEN-CUATRO-CONDICIONES-v60.md` | Una revisión anterior de KDebug documentó **61 eventos** con ID genérico de categoría IOKit: 30 × `0x52d8000`, 22 × `0x5420020`, 9 × `0x5420010`. | No se verificó una identidad de `IOSurfaceRootUserClient` ni `free(O) -> N pendiente -> dispatch(N,O)`. La traza bruta no se adjunta a este informe. |

### Cálculo del único intervalo de concurrencia medido

Intersección = `[max(0,21.458), min(537.833,195.625)] = [21.458,195.625]` µs.  
Duración = `195.625 - 21.458 = 174.167` µs.

La respuesta `0x10000003` de la llamada impide asumir que el método de registro de notificaciones se haya ejecutado con éxito. Estos timestamps no contienen un reloj de eventos de memoria del kernel.

## 2. Correlación por instancia: matriz de requisitos

| Requisito | Prueba disponible | Estado |
|---|---|---|
| Identificar el mismo `IOSurfaceRootUserClient` en todas las etapas | No hay identificador de instancia/generación del kernel en los registros | **No acreditado** |
| Demostrar `last_release` y la desasignación efectiva de la instancia | Se conocen rutas de destrucción por análisis estático, no un evento ejecutado de última liberación | **No acreditado** |
| Mostrar que un nodo de notificación continúa asociado a esa instancia después de la desasignación | El binario tiene escritura/lectura de puntero y el modelo permite un intercalado condicional | **No acreditado en ejecución real** |
| Registrar una entrega que utilice exactamente ese nodo y esa instancia **después** de la desasignación | El despacho existe en el código, pero no hay evento real con identidad de objeto y secuencia posterior | **No acreditado** |

Por tanto, **no se puede calcular un retraso `t_dispatch - t_last_release` observado**. No existe `t_last_release` identificado ni `t_dispatch` asociado a esa misma instancia. Tampoco es válido inferir eventos ausentes por la sola diferencia de las dos versiones.

## 3. Garantías de vida útil ya comprobadas

- Las consultas IPC conservan una referencia fuerte temporal; la referencia protege el objeto durante esa llamada, y el contador de operaciones `__ipc` es una magnitud distinta del contador de `OSObject`.
- `IOMachPort` retiene al cliente durante la ruta `no-senders` y lo libera después de llamar a `clientDied`.
- El binario de `IOSurfaceRootUserClient` configura `DefaultLocking=false`; por tanto la serialización genérica no obliga al método externo a esperar el cierre. **Solapamiento posible no significa desasignación efectiva demostrada**.
- El registro, retirada y despacho protegen la lista mediante un bloqueo propio; el cierre de 27.2 agrega estado que rechaza altas tardías.
- El modelo finito previo halló un puntero potencialmente colgante **bajo hipótesis no verificadas sobre referencias adicionales**. Ese resultado no es una observación de UAF en kernel real.

Fuentes: `informes/IOUSERCLIENT-LOCKING-EFECTIVO-Y-REFERENCIAS.md`, `informes/ORDEN-REAL-IOKIT-Y-DESPACHO-IOSURFACE.md`, `informes/RESULTADO-MODELO-REFERENCIA-COLGANTE-CLIENTE-IOSURFACE.md` y código XNU público.

## 4. Dictamen

**La correlación cronológica solicitada no es demostrable con los eventos registrados.** Lo único cuantificable en las trazas revisadas es el solapamiento de llamada/cierre en usuario. No existe un registro de última liberación del cliente y posterior uso del puntero de la misma instancia. El parche en 27.2 y la prueba abstracta no sustituyen ese dato.

No se ha demostrado un *use-after-free* real del kernel, ni corrupción de memoria, ni acceso KernelRW. El dictamen es sobre la **suficiencia de evidencias disponibles**, no una afirmación de que la vulnerabilidad sea inexistente.

## 5. Archivos de evidencia relacionados

- `IOSurfaceSameClient-trace.csv` (fuente Library)
- `IOSurfacePreflight-log 3.txt` (fuente Library)
- `IOSurfacePortRevocation-v19_9.json` (adjunto de conversación)
- `DICTAMEN-CUATRO-CONDICIONES-v60.md` (dictamen previo en Library)
- [PR #12](https://github.com/ioezgamer/IOSurfaceSafeProbe/pull/12) y [workflow con análisis de binarios](https://github.com/ioezgamer/IOSurfaceSafeProbe/actions/runs/42330515067)

**Ningún artefacto nuevo del teléfono fue generado ni se ejecutó una explotación.**
