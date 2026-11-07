# AppleAVE2 A15: auditoria exacta de codigo entre 24A437 y 24B119

Fecha: 2026-11-07. Modelo exacto: `iPhone14,3` (Apple A15). Ninguna ejecucion de codigo kernel ni disparo de fallos en el telefono forma parte de esta auditoria.

## 1. Binarios originales verificados

| Dato | 24A437 | 24B119 |
|---|---|---|
| KEXT | `com.apple.driver.AppleAVE2` | `com.apple.driver.AppleAVE2` |
| Tamano bytes | 3020688 | 3037072 |
| SHA256 | `dc1ccfb04fc2ff8b600228dde2c5d83f3695ebe119774e285d511e8da4425ea3` | `b5b187861ad9287fd3b976d872a89029991acdfcd8bd445a6ebfb2f560cf499c` |
| ARM64 `__TEXT_EXEC` bytes | 1916928 | 1933312 |
| `LC_FUNCTION_STARTS` entries | 2995 | 2998 |
| Instrucciones decodificadas | 475134 | 479154 |

Ambos controladores se extrajeron de kernelcache distribuidos por Apple usando `ipsw` y GitHub Actions, run [42408583861](https://github.com/ioezgamer/IOSurfaceSafeProbe/actions/runs/42408583861). El ejecutable nuevo crecio **16384 bytes**.

## 2. Cambios en funciones (metodo reproducible)

Se obtuvieron los limites desde `LC_FUNCTION_STARTS`, se desensamblo `__TEXT_EXEC` con LLVM y se alinearon secuencias completas de mnemonicos ARM64 por funcion, sin operandos, mediante LCS. Se obtuvieron **2963 funciones de secuencia identica** y **26 regiones de cambio**. Se detectaron **71 cadenas nuevas y 17 retiradas** en `__cstring` / `__oslogstring`. La huella de mnemonicos ignora los operandos: no afirma equivalencia semantica ni que haya 26 vulnerabilidades.

## 3. Sitio concreto: validacion nueva de capas temporales

Funcion del build corregido: `0xfffffff008443a34` (entrada 810). Secuencia validada por palabra ARM64 de 32 bits directamente desde el archivo:

```asm
0xfffffff008443e04  ldr w8, [x20, #0x510] 
0xfffffff008443e08  sub w8, w8, #0x1
0xfffffff008443e0c  cmp w8, #0x7
0xfffffff008443e10  b.hs 0xfffffff008443ff0
0xfffffff008443e14  ldr w8, [x20, #0x768]
0xfffffff008443e18  cmp w8, #0x8
0xfffffff008443e1c  b.hs 0xfffffff0084440cc
```

La nueva cadena `number of temporal layers (prop) is out of range` esta presente en `24B119`, ausente en `24A437`, y su direccion VM `0xfffffff0072ee13f` se construye en codigo con `ADRP` + `ADD` en `0xfffffff00844412c/130`. La funcion antigua en `0xfffffff008416de0` tiene cargas comprobadas de `#0x510` pero no esa misma pareja local de comparacion/rechazo. Los dos caminos se localizan en los grupos de funciones 809-812 antiguo y 809-813 nuevo.

Ademas aparecen mensajes y aserciones nuevas sobre contadores y limites `HEVC VPS/SPS/PPS/RPS`, `AVC PPS`, `vps_max_layers_minus1`, `layer_id_in_nuh`, conjunto de capas, MCTF y buffers internos `MB/CTU`.

## 4. Falsos positivos controlados

- Validacion SHA256 de cada KEXT antes del analisis.
- Nueve instrucciones exactas del firmware parcheado y dos cargas de referencia de firmware antiguo verificadas byte a byte.
- Prueba negativa: presentar KEXT antiguo como corregido produce `Unexpected SHA-256` y se rechaza.

## 5. Dictamen

**Demostrado:** Apple agrego una pareja de validaciones de rango y numerosas comprobaciones nuevas en AppleAVE2 para el modelo exacto A15. Es consistente con el aviso Apple sobre CVE-2026-112705 y los fallos de AVEVideoEncoder corregidos en iOS 27.2. Atribuir un conjunto de instrucciones a una CVE en particular sin mas evidencia sigue siendo una inferencia.

**No demostrado:** corrupcion de memoria en el dispositivo, KASAN, accesibilidad de todas las rutas desde apps sin privilegios, valor/direccion arbitrarios en una escritura del kernel, KernelRW o jailbreak. Un panic de AppleAVE2 en otro iPhone seria evidencia de fallo, no explotacion controlada.

Fuentes: [Apple iOS 27.2 security content](https://support.apple.com/en-us/149230), [PoC publico AVETemporalPoC](https://github.com/Frollir/avetemporalpoc-cve-2026-112705).
