# Auditoría estática de evidencia pública: CVE-2026-112688

Fecha: 2026-11-05. Alcance: revisión documental, sin ejecución de cargas.

## Confirmación externa
Apple documenta CVE-2026-112688 en CoreMedia en el boletín de iOS 27.2:
https://support.apple.com/en-us/149230
Apple describe corrupción de memoria al procesar archivos, potencialmente capaz de provocar cierre o ejecución arbitraria de código. Apple no confirma en el boletín el mapeo a la función específica del repositorio.

## Evidencia pública inspeccionada
Repositorio: https://github.com/0xjohnnydev/CVE-2026-112688-backboardd

### Registro de fallo de dirección de retorno
Archivo: \`evidence/return-address/backboardd-2026-10-28-113235.ips\`.
- Proceso: \`backboardd\`, PID 73, padre \`launchd\`.
- Sistema del autor: iPhone19,4, iOS 27.1, build 24A94425.
- Excepción: \`EXC_BAD_ACCESS\`, subtipo \`EXC_ARM_PAC_FAIL\`.
- Terminación: \`PAC_EXCEPTION\`.
- Registro LR del hilo afectado: \`0x4141414141414141\` (valor también declarado por el autor en \`receipt.txt\`).
- Interpretación: evidencia consistente con alteración del retorno del flujo de control rechazada por PAC, **no ejecución de código**.

### Registro de lectura posterior de la prueba del autor
Archivo: \`evidence/fixed-byte-write/readback-backboardd-2026-10-29-003655.ips\`.
- Proceso: \`backboardd\`, PID 794, padre \`launchd\`.
- Excepción: \`EXC_BAD_ACCESS\`, \`SIGSEGV\`.
- Subtipo: \`KERN_INVALID_ADDRESS at 0x0000000000000009\`.
- El autor relaciona este registro con una comprobación de lectura y una escritura limitada de byte; el registro por sí solo prueba el fallo, **no verifica una escritura arbitraria**.
- El archivo \`receipt.json\` documenta que la comprobación de cero se realizó en un PID distinto: no hay comparación directa antes/después en el mismo proceso.

## Comparación con nuestro dispositivo
El único crash de nuestra aplicación local reportado hasta aquí es \`EXC_CRASH / SIGABRT\` en \`BackboarddEvidence\`, acompañado por un checkpoint anterior a \`abort()\`.
El dispositivo local es \`iPhone14,3\`, iOS 27.0 build 24A437.
No se ha observado \`EXC_BAD_ACCESS\` de \`backboardd\` ni corrupción de memoria en ese dispositivo mediante este proyecto.
El hecho de que la versión sea anterior a iOS 27.2 **no prueba reproducibilidad ni compatibilidad de una carga concreta**.

## Dictamen
1. La vulnerabilidad de CoreMedia está documentada oficialmente por Apple.
2. Los archivos públicos aportan evidencia textual de fallos de memoria y PAC en \`backboardd\` bajo iOS 27.1.
3. La atribución exacta de los fallos públicos a esa CVE es una hipótesis técnica del autor, no una confirmación individual de Apple.
4. Los fallos públicos no acreditan KernelRW, jailbreak ni ejecución de código.
5. La app local de diagnóstico no reproduce ese fallo y no debe presentarse como exploit.

Este informe no contiene instrucciones para activar la vulnerabilidad ni cargas de explotación.
