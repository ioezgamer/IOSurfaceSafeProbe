# Auditoría exacta IOSurface y AGX A15, 7 de noviembre de 2026

**Dispositivo:** iPhone14,3, iOS 27.0 (24A437), Apple A15 GPU.
**Dictamen:** diferencia de ciclo de vida IOSurface y lectura/escritura entre buffers GPU propios confirmadas; corrupción de memoria kernel, KernelRW y jailbreak **no demostrados**.

## Prueba 1: código original de IOSurface vs parche

Se desensamblaron los KEXT reales y se validaron sus SHA256:

| Build | SHA-256 KEXT |
|---|---|
| 24A437 | 3f95c45f629a8749775765980434ee927552e1cad4e568743062bf901aa018d8 |
| 24B119 | a1d255c31648eb54385b32cb51277a262b7d99c246a5195e591ae8d827b3275c |

En 24A437, la rutina de registro en `0xfffffff009c15e00` guarda un puntero del cliente en el nodo, offset `+0x58`: `stp x8, x21, [x24,#0x50]` (dirección `0xfffffff009c15e98`). La búsqueda del nodo carga esa dirección (`ldr x10, [x8,#0x58]`, `0xfffffff009c15e58`) y **la compara** con `x21` inmediatamente después (`cmp x10,x21`). La retirada también carga `+0x58` y compara con `x20` (`0xfffffff009c160b4` y `...b8`). Estas operaciones **no desreferencian el objeto cliente**.

En 24B119, el registro lee el estado del cliente `+0xf1` (`ldrb w8,[x21,#0xf1]`, dirección `0xfffffff009c55dd0`) y cambia su control de flujo si está marcado. La retirada escribe ese mismo byte bajo el bloqueo de gestión (`strb w8,[x20,#0xf1]`, `0xfffffff009c56044`).

El coordinador de cierre también cambia su orden: **antes** llama a otras rutinas y después al barrido de notificaciones (`...1b058`, `...1b090`, `...1b09c`). **Después**, en 24B119, barre primero (`...5afc8`) y realiza las otras dos llamadas después (`...5b00c`, `...5b044`).

**PASS:** se comprobaron hashes, instrucciones, offsets, mutex, orden de llamadas. La prueba negativa con el binario 24A437 presentado en el lugar del parche fue rechazada. **Sin evidencia:** destrucción final del cliente antes de un acceso posterior, traza UAF o atribución inequívoca a CVE-2026-112477.

## Prueba 2: resultado de Apple A15 GPU

El JSON original exportado de Apple IOKit Lab v1.8 indicó dos buffers **propios** de 65536 bytes, con GPU VA `0x1500068000` y `0x1500080000` (distancia 98304 bytes, más allá de los límites del primero). El shader leyó `0x11223344` del segundo y escribió `0x57524954`, posteriormente confirmado desde CPU. Los tres command buffers completaron correctamente.

**PASS:** aritmética independiente, marcador previo y readback desde CPU. **NO:** acceso a otro proceso, kernel, sandbox ajeno, estructura IOSurface F1, UAF o KernelRW. El shader declaró ambos recursos como pertenecientes a la misma aplicación.

## Información nueva de terceros, sin extrapolación

- Apple confirmó [CVE-2026-112477](https://support.apple.com/en-us/149230), carrera en IOSurface que puede corromper memoria del kernel; corrigió el problema en iOS 27.2.
- Apple confirmó también [CVE-2026-112507](https://support.apple.com/en-us/149230), escritura fuera de límites con impacto de escritura en memoria del kernel, y [CVE-2026-112665](https://support.apple.com/en-us/149230), divulgación de disposición de memoria del kernel. El aviso no publica sus disparadores.
- [Dopamine](https://github.com/opa334/Dopamine) no publica compatibilidad con iPhone14,3/iOS27.0.
- [Apple SoC security](https://support.apple.com/guide/security-pdf/apple-soc-security-sec87716a080/web): SPTM es compatible con A15 y posteriores; aun con KRW, un jailbreak completo requeriría superar protecciones adicionales.
- [Investigación F1OOB](https://github.com/SKVLENT/ANE-Exploit/blob/main/F1OOB_ANALYSIS.md): su control con búfer Metal corriente consigue lecturas/escrituras dentro del mismo contexto GPU sin F1, por lo que no debe confundirse con una primitiva de kernel.

## Límite cerrado para esta fase

No seguir creando IPA para repetir que selector 17 registra notificaciones o que dos buffers propios se leen/escriben. Una demostración de UAF exige correlación de **misma instancia + última referencia + liberación real + desreferencia posterior**. El análisis disponible no la aporta. No se ha fabricado KASAN ni se ha afirmado jailbreak.

Los scripts de verificación, JSON y prueba negativa se entregaron en el paquete de investigación de esta conversación. No redistribuye los binarios propietarios de Apple.