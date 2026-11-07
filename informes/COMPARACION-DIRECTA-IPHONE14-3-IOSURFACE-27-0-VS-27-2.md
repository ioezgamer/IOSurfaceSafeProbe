# Comparación real de IOSurface: iPhone14,3 / iOS 27.0 y 27.2
**Fecha del análisis:** 2026-11-06 (Nicaragua)  
**Dispositivo:** iPhone 13 Pro Max (iPhone14,3, Apple A15 / T8110)  
**Alcance:** comparación defensiva de código y metadatos. La CVE-2026-112477 no ha sido atribuida a ninguna función.

## Resumen comprobado

Se extrajeron por HTTPS Range dos kernelcache oficiales desde los IPSW de Apple correspondientes **al mismo modelo**:

| Campo | iOS 27.0 | iOS 27.2 |
|---|---|---|
| Build | 24A437 | 24B119 |
| Darwin kernel | 27.0.0 | 27.2.0 |
| Versión XNU | xnu-13432.2.10~2 | xnu-13432.42.3~28 |
| IOSurface, según lista de KEXT | 402.8 | 403.1 |
| SHA256 kernelcache extraído | `742714192f267bf7fbfe3de8c5437b534d7f305bf87c8b77c4d1ad9dd7446385` | `eca347bf3b221b3e048a5ef7a7988cf2db46b4be895483d90e11281729865561` |
| SHA256 IOSurface KEXT extraído | `3f95c45f629a8749775765980434ee927552e1cad4e568743062bf901aa018d8` | `a1d255c31648eb54385b32cb51277a262b7d99c246a5195e591ae8d827b3275c` |
| Tamaño del archivo KEXT extraído | 314,376 B | 314,376 B |
| Tamaño de `__TEXT_EXEC.__text` | 214,556 B | 214,580 B |

**Diferencia comprobada del código: +24 bytes** (seis instrucciones ARM64 de cuatro bytes equivalentes como diferencia neta de tamaño). Esto coincide con el crecimiento neto de sección documentado antes para otro modelo, pero no basta para afirmar que son los mismos cambios de función.

## Comparación de secciones Mach-O

| Sección | Bytes 27.0 | Bytes 27.2 | Diferencia de tamaño | Hash de contenido |
|---|---:|---:|---:|---|
| `__TEXT_EXEC.__text` | 214556 | 214580 | **+24** | Diferente |
| `__TEXT_EXEC.__auth_stubs` | 2368 | 2368 | 0 | Diferente |
| `__DATA_CONST.__const` | 18168 | 18168 | 0 | Diferente |
| `__DATA_CONST.__auth_got` | 1184 | 1184 | 0 | Diferente |
| `__DATA_CONST.__got` | 208 | 208 | 0 | Diferente |
| `__DATA_CONST.__kalloc_type` | 3328 | 3328 | 0 | Diferente |
| `__DATA_CONST.__kalloc_var` | 2720 | 2720 | 0 | Diferente |
| `__DATA.__data` | 376 | 376 | 0 | Diferente |
| `__DATA.__common` | 1120 | 1120 | 0 | Diferente |

Otras secciones de metadatos se conservaron en tamaño, con diferencias de hash. Una sección que cambia de hash **no implica** que se haya corregido allí una vulnerabilidad: las direcciones, referencias y la vinculación pueden variar.

## Inventario global de instrucciones ARM64 observadas

| Mnemónico | 27.0 | 27.2 |
|---|---:|---:|
| `bl` | 3034 | 3034 |
| `ret` | 313 | 313 |
| `cas` | 5 | 5 |
| `casal` | 1 | 1 |
| `ldadd` | 4 | 4 |
| `ldxr` / `ldaxr` / `stxr` / `stlxr` | 0 | 0 |
| `dmb` / `dsb` / `isb` | 0 | 0 |

El conteo global no revela si se movió o modificó una llamada de bloqueo ni identifica una región específica de código. Incluso sin cambios en estos contadores podría haberse modificado la sincronización de la implementación.

## Alineación de instrucciones ARM64

La segunda ejecución de GitHub Actions alineó las instrucciones del KEXT (comparación por mnemónicos, normalizando direcciones). Se obtuvieron **53,639 instrucciones** en `24A437` y **53,645 instrucciones** en `24B119`, una diferencia de **6 instrucciones**.

Se detectaron **4 regiones de diferencias**:

| Región | Ubicación aproximada dentro de las instrucciones desensambladas | Cambio visible |
|---|---|---|
| 1 | 33,365 | Inserción de `ldrb, tbz, add, b` (4 instrucciones = 16 bytes) |
| 2 | 33,517 | Inserción de `mov, strb` (2 instrucciones = 8 bytes) |
| 3 | 38,602 | Sustitución/reordenación de acceso a bytes y una llamada (`strb, ldr, mov, bl` observados) |
| 4 | 38,634 | Supresión/reordenación de `ldr, mov, bl` en el alineamiento |

El detalle completo está en `mnemonic-hunks.txt` del artefacto de la ejecución [#2](https://github.com/ioezgamer/IOSurfaceSafeProbe/actions/runs/42321261453). Estas son diferencias **a nivel de opcode**, no un mapeo validado a métodos con nombres semánticos. La concordancia +16/+8 es interesante pero no prueba que se corresponda exactamente con los dos `sub_*` del otro dispositivo ni que alguno sea el parche de la CVE.

**Precaución:** el algoritmo de diferencias puede alinear equivocadamente bloques con mnemónicos repetidos. La evidencia debe interpretarse como regiones aproximadas hasta contrastarla con el flujo completo de instrucciones y sus operandos.

## Ubicaciones exactas de las regiones alineadas

La tercera ejecución de CI obtuvo la posición de los opcode directamente del desensamblado del KEXT, conservando una tabla de correspondencia entre número de instrucción y dirección virtual **estática**. Estas direcciones no deben interpretarse como direcciones de memoria del dispositivo en ejecución ni como nombres de función.

| Región | Ubicación en 27.0 `24A437` | Ubicación en 27.2 `24B119` | Cambio según alineamiento |
|---|---|---|---|
| 1 | `0xfffffff009c15e20` | `0xfffffff009c55db0` | +4 instrucciones (`ldrb, tbz, add, b`) |
| 2 | `0xfffffff009c16080` | `0xfffffff009c56020` | +2 instrucciones (`mov, strb`) |
| 3 | `0xfffffff009c1aff4` | `0xfffffff009c5af9c` | Alteración local de instrucciones de acceso a memoria y llamada |
| 4 | `0xfffffff009c1b074` | `0xfffffff009c5b028` | Eliminación/reordenación de `ldr, mov, bl` según el alineamiento |

Estas ubicaciones corresponden al primer opcode del contexto de cada hunk (no necesariamente al primer opcode modificado ni al comienzo de una función). Para la región 3/4, la ubicación y el contexto no deben leerse como método o ruta de error específicos.

**Fuente:** [Ejecución #3 de GitHub Actions](https://github.com/ioezgamer/IOSurfaceSafeProbe/actions/runs/42321360686), archivo `hunk-addresses.json`. Se generó a partir de los dos KEXT extraídos de kernelcache oficiales correspondientes a `iPhone14,3`.

La exactitud de esta comparación se limita a **instrucciones y sus posiciones**; aún no conocemos nombres de las funciones propietarias, operandos completos con semántica verificada ni el parche atribuido a CVE-2026-112477.

## Comparación con diferencial público de otro modelo

La diferencia publicada para `iPhone18,1` entre `24A437` y `24B5084k` muestra dos funciones anónimas cuyos tamaños cambian en **+16** y **+8 bytes** respectivamente. La suma coincide con el **+24 bytes** detectado ahora en iPhone14,3 entre la versión original 27.0 y la 27.2 final, pero los pares comparan diferentes dispositivos y diferentes builds de destino. **No es correcto trasladar direcciones virtuales ni atribuir esas funciones a nuestra versión sin una correspondencia de instrucciones.**

[Comparación pública KEXT IOSurface](https://raw.githubusercontent.com/ipsw-diffs/ios-27/4c6365c2a47e18ff126ba1bd9743c73fa52d2e40/diffs/27_0_24A437_vs_27_2_24B5084k/KEXTS/com.apple.iokit.IOSurface.md)

## Fuentes y reproducibilidad

- Aviso Apple sobre iOS 27.2: https://support.apple.com/en-us/149230
- IPSW original 27.0, iPhone14,3: https://updates.cdn-apple.com/2026FallFCS/73d1826d-b08b-404a-92b6-94249593de65/iPhone14%2C3_27.0_24A437_Restore.ipsw
- IPSW corregido 27.2, iPhone14,3: https://updates.cdn-apple.com/2026FallFCS/59db57ab-bf39-4722-ae2c-930079835914/iPhone14%2C3_27.2_24B119_Restore.ipsw
- Workflow reproducible: `.github/workflows/iosurface-iphone14-3-compare.yml`
- [Ejecución de GitHub Actions #1 con resultado verificado](https://github.com/ioezgamer/IOSurfaceSafeProbe/actions/runs/42321139306)
- [Artefacto ZIP de métricas, JSON de secciones, inventario de KEXTs y versiones del kernel](https://github.com/ioezgamer/IOSurfaceSafeProbe/actions/runs/42321139306/artifacts/13553705392)

Los kernelcache y KEXT extraídos no se publicaron en GitHub: solo se publicó el resumen de sus metadatos, hashes e inventario de instrucciones.

## Conclusión

**Comparación real completada** sobre el mismo modelo de dispositivo y firmwares públicos correctos: se comprobó un crecimiento neto de 24 bytes de código ejecutable de IOSurface y diferencias de contenido en varias secciones. **Todavía no es una identificación del parche exacto, de la función vulnerable o de una primitiva de explotación de CVE-2026-112477.** Para eso se necesita correlación a nivel de función e instrucciones con una atribución independiente a la CVE.
