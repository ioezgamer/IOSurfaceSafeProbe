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
