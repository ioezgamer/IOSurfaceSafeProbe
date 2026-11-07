# IOSurface: barrera de ciclo de vida verificada por binarios exactos

**Equipo:** iPhone14,3. **Versiones comparadas:** iOS 27.0 (24A437) e iOS 27.2 (24B119).
**Fecha:** 2026-11-07. **Alcance:** auditoría estática, sin explotación.

## Resultado

La versión 24B119 introduce una barrera de estado que rechaza el registro tardío de notificaciones de un cliente mientras ese cliente está desmontándose. Se identifica el mismo byte de estado en la función que comprueba el registro y en la función que retira los registros del cliente. Ambas operaciones trabajan bajo el mismo bloqueo del gestor de notificaciones.

Los tres cambios de comportamiento están en las entradas 799, 802 y 945 de LC_FUNCTION_STARTS del KEXT IOSurface del mismo hardware.

| Evidencia | 24A437 | 24B119 |
|---|---|---|
| KEXT SHA-256 | 3f95c45f629a8749775765980434ee927552e1cad4e568743062bf901aa018d8 | a1d255c31648eb54385b32cb51277a262b7d99c246a5195e591ae8d827b3275c |
| Función 799, registro | sin guarda de estado del cliente | lee byte en cliente+0xf1 y rechaza si está marcado |
| Función 802, barrido de registros | retira registros sin marcar ese byte | escribe 1 en cliente+0xf1 antes de recorrer lista |
| Función 945, cierre | hace otras llamadas antes del barrido | hace el barrido antes de otras llamadas |

### Asociación de punteros con el mismo objeto

El wrapper de registro recibe el cliente en x0, carga el gestor de cliente+0xe8 y pasa el cliente original como x3 a la función 799. En dicha función, x21 guarda x3. Por eso la instrucción ldrb w8, [x21, #0xf1] lee el estado del **cliente**, no del gestor.

La función 945 guarda el cliente en x20 y llama a la 802 con x0=gestor y x1=cliente. La 802 conserva x1 como x20, de modo que strb w8, [x20, #0xf1] escribe el **mismo** byte de estado del cliente.

El gestor se localiza en cliente+0xe8. El campo del bloqueo está en gestor+0x150, y la lista de registros en gestor+0x188. Las funciones 799 y 802 llaman al mismo par de rutinas de bloqueo y desbloqueo.

### Fragmentos ARM64e verificados

**24A437, registro (799):**
~~~asm
fffffff009c15e38: ldr x0, [x0, #0x150]
fffffff009c15e3c: bl 0xfffffff009c29b4c
fffffff009c15e40: ldr x8, [x19, #0x188]
~~~

**24B119, registro (799):**
~~~asm
fffffff009c55dc8: ldr x0, [x0, #0x150]
fffffff009c55dcc: bl 0xfffffff009c69af4
fffffff009c55dd0: ldrb w8, [x21, #0xf1]
fffffff009c55dd4: tbz w8, #0x0, 0xfffffff009c55de0
fffffff009c55dd8: add w20, w20, #0x1b
fffffff009c55ddc: b 0xfffffff009c55e78
fffffff009c55de0: ldr x8, [x19, #0x188]
~~~

**24B119, barrido (802):**
~~~asm
fffffff009c56038: ldr x0, [x0, #0x150]
fffffff009c5603c: bl 0xfffffff009c69af4
fffffff009c56040: mov w8, #0x1
fffffff009c56044: strb w8, [x20, #0xf1]
fffffff009c56048: ldr x21, [x19, #0x188]
~~~

En el cierre 24A437 el barrido ocurre tras dos llamadas; en 24B119 el barrido se adelanta. El nuevo código devuelve el valor calculado 0xe00002d8 cuando el indicador ya está marcado.

## Invariante de seguridad reconstruido

**Después de marcar un cliente para retirada de notificaciones, no debe poder incorporarse una suscripción nueva de ese cliente a la lista mientras se mantiene el bloqueo del gestor.** La versión corregida comprueba esta condición antes de recorrer/modificar la lista; la anterior carece de esa guarda.

La reconstrucción está respaldada por bytes de máquina, no solo nombres de métodos. El verificador comprueba identidad, direcciones, registros, estado y orden; también rechaza una combinación incorrecta de binarios.

## Límites

- **Confirmado:** relación entre tres funciones, estado cliente+0xf1, mismo bloqueo en gestor+0x150, lista gestor+0x188 y reordenamiento del cierre.
- **Interpretación probable:** la modificación previene registros tardíos durante el desmontaje.
- **No demostrado:** intercalado alcanzable con acceso indebido a memoria liberada, corrupción del kernel, KernelRW o jailbreak.
- **Atribución CVE no confirmada:** Apple informó CVE-2026-112477 como una condición de carrera de IOSurface corregida en iOS 27.2, pero no atribuyó públicamente estas instrucciones a dicha CVE.

El registro exitoso mediante selector 17 o la recepción de un mensaje Mach no prueban que se pueda violar este invariante. Para demostrar corrupción real se requiere evidencia causal adicional en un entorno con instrumentación.

## Verificación reproducible

Ambos KEXT originales se extrajeron del kernelcache del mismo hardware y contienen 1330 entradas LC_FUNCTION_STARTS. La verificación local con llvm-objdump concluyó:

- PASS: SHA-256 de ambas versiones, función 799/802/945, wrapper de cliente en x3.
- PASS: mismo campo de estado y mismo bloqueo para registro y retirada.
- PASS: comprobación y marca de cliente+0xf1 en 24B119.
- PASS: barrido adelantado en la limpieza de 24B119.
- PASS: prueba negativa con binario 24A437 usado en lugar del corregido rechazada.

Fuentes de extracción:
- https://github.com/ioezgamer/IOSurfaceSafeProbe/actions/runs/42384252470
- https://github.com/ioezgamer/IOSurfaceSafeProbe/actions/runs/42385356974

**No es un exploit ni demuestra corrupción de memoria.**
