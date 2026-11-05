# Compatibilidad de la investigación con iPhone14,3 / iOS 27.0 (24A437)

**Fecha:** 5 de noviembre de 2026  
**Dispositivo:** iPhone 13 Pro Max, `iPhone14,3`  
**Versión reportada por el dispositivo:** iOS 27.0, compilación `24A437`  
**Estado (actualizado 2026-11-05):** comparación de UUIDs medida en el dispositivo mediante Backboardd Evidence v3. QuartzCore no coincide con la referencia pública de iOS 27.1. No hay exploit ni jailbreak demostrado.

## 1. No confundir dos vulnerabilidades

- **CVE-2026-112688:** CoreMedia. Apple informa que procesar un archivo puede provocar cierre inesperado o ejecución arbitraria de código. Está corregida en iOS 27.2.
- **CVE-2026-112477:** IOSurface. Apple informa riesgo de terminación inesperada o corrupción de memoria del kernel debido a una condición de carrera. También corregida en iOS 27.2.
- Son investigaciones diferentes: los cambios estáticos de IOSurface que examinamos **no validan** la ruta CoreMedia/backboardd del repositorio público.

Fuente: https://support.apple.com/en-us/149230

## 2. Qué demuestra realmente el repositorio público

Referencia: https://github.com/0xjohnnydev/CVE-2026-112688-backboardd

El autor documenta ensayos en **iOS 27.1, build 24A94425, iPhone19,4**, y publica registros de `backboardd`:

- `evidence/return-address/backboardd-2026-10-28-113235.ips`: `EXC_BAD_ACCESS`, `EXC_ARM_PAC_FAIL`, proceso `backboardd`. La dirección de retorno alterada fue rechazada por PAC. Esto **no** demuestra ejecución de código.
- `evidence/fixed-byte-write/readback-backboardd-2026-10-29-003655.ips`: `EXC_BAD_ACCESS`, `SIGSEGV`, acceso a una dirección inválida en `backboardd`. El autor lo interpreta junto a otra evidencia como una operación de escritura restringida, no escritura arbitraria.
- El código del repositorio restringe una modalidad a una **UUID concreta de QuartzCore** y rechaza UUID distintas. Su comportamiento bajo iOS 27.0 no se ha demostrado.

Apple confirma la CVE general, pero **no confirma** la correspondencia de esa función concreta con la CVE.

## 3. Resultados de nuestras pruebas anteriores en el dispositivo

- **IOSurface Preflight v12:** 256 pruebas de integridad completadas, 0 diferencias y 0 errores API. Se verificaron accesos públicos, no el ciclo de vida interno del kernel.
- **Backboardd Evidence v2:** la aplicación provocó su propio cierre intencional con `SIGABRT`. El sistema generó un registro `.ips` de esa app. No fue un error de memoria de `backboardd`.
- **Comparación histórica de KernelCache de iOS 27.0 y 27.2:** informes previos documentaron modificaciones de sincronización relacionadas con IOSurface. Esto no implica por sí solo una vulnerabilidad reproducible o un UAF.

## 4. Qué hace la nueva IPA v3

Código: https://github.com/ioezgamer/IOSurfaceSafeProbe/blob/main/BackboarddEvidence/Sources/main.m

La acción **5. Comparar frameworks de mi iOS** consulta, en el proceso de la aplicación, la versión del sistema y el comando Mach-O `LC_UUID` de:

- QuartzCore
- CoreMedia
- IOSurface

Se compara únicamente la UUID de QuartzCore con la referencia publicada por el autor. La aplicación **no** llama a métodos privados para activar el fallo, no envía datos malformados a `backboardd` y no lee ni escribe memoria del kernel.

El resultado se incorpora al campo `frameworkCompatibility` del archivo exportable `BackboarddEvidence-dictamen.json`.

## 5. Cómo interpretar la comparación

| Resultado | Qué significa | Qué no demuestra |
|---|---|---|
| UUID de QuartzCore coincide | La identidad Mach-O local es igual a la referencia | Vulnerabilidad, ejecución de código, KernelRW |
| UUID de QuartzCore difiere | Es una compilación de ese framework distinta a la referencia | Ausencia de la CVE o imposibilidad general de explotación |
| UUID no disponible | Esta app no pudo resolver el identificador | Nada concluyente sobre la versión vulnerable |

El parche oficial de iOS 27.2 permite establecer el riesgo general, pero no sustituye una reproducción verificada en este dispositivo.

## 6. Resultado real de la prueba en iPhone14,3

El usuario compartió `BackboarddEvidence-dictamen 2.json`, generado por Backboardd Evidence v3 en el propio equipo.

| Componente | UUID Mach-O observada |
|---|---|
| QuartzCore | `76CE2A6E-DBA4-335D-A5AC-77A1C1B286A6` |
| CoreMedia | `A1E3885B-22BE-3C76-95C1-7821276212F6` |
| IOSurface | `5933A7C7-F136-3DE3-83F4-34A5451F9C1E` |

La referencia QuartzCore declarada en el proyecto público es:
`21FA0104-F308-3BB3-8F3F-E9DE66F7CDEC`.

**Resultado:** las UUID de QuartzCore son distintas. La rutina pública `SupportedQuartzCore` del autor compara con la UUID de referencia y la función `FixedByteRPU` rechaza una compilación distinta antes de preparar las modalidades de escritura limitada y lectura posterior.

**Distinción importante:** esta comprobación no alcanza automáticamente al modo de prueba de dirección de retorno, que el código fuente selecciona de otra manera. La desigualdad de UUID tampoco prueba ausencia de CVE-2026-112688, ni demuestra que otra carga sea compatible, ni valida corrupción de memoria.

## 7. Alcance que permanece pendiente

- No existe aún una reproducción independiente y comprobada de un fallo de memoria en `backboardd` en `24A437`.
- No tenemos comparaciones instrucción por instrucción entre QuartzCore y CoreMedia de ambas compilaciones en esta revisión.
- La IPA v3 se limitó a lectura de identificadores Mach-O de frameworks en su propio proceso.
- El checkpoint histórico de SIGABRT pertenece a la app de diagnóstico, no a `backboardd`.

**Dictamen actualizado:** confirmada la diferencia de identidad de QuartzCore; una modalidad concreta del PoC público no supera su control de compatibilidad en el dispositivo. No es prueba de explotación ni de inmunidad.
