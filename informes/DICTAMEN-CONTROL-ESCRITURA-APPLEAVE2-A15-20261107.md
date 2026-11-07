# Dictamen del posible control de escritura de kernel en AppleAVE2 del A15

**Modelo:** iPhone14,3, iOS 27.0 (`24A437`) frente a iOS 27.2 (`24B119`). **Evidencia:** instrucciones ARM64 verificadas byte a byte de KEXT originales. **Dictamen:** NO SE HA DEMOSTRADO una primitiva controlada de escritura de memoria kernel.

## Nueva correccion encontrada al analizar el firmware antiguo

El controlador original ya tenia un control de rango para el campo `+0x510`: 

```asm
24A437: 0xfffffff00841715c  ldr w8, [x21, #0x510]
24A437: 0xfffffff008417160  cmp w8, #0x9
24A437: 0xfffffff008417164  b.hs 0xfffffff008417210
```

Por lo tanto, ese chequeo local permitia valores unsigned de 0 a 8; **no** era una ausencia completa de validacion.

En el firmware corregido se observan las siguientes instrucciones exactas:

```asm
24B119: 0xfffffff008443e04  ldr w8, [x20, #0x510]
24B119: 0xfffffff008443e08  sub w8, w8, #0x1
24B119: 0xfffffff008443e0c  cmp w8, #0x7
24B119: 0xfffffff008443e10  b.hs 0xfffffff008443ff0
24B119: 0xfffffff008443e14  ldr w8, [x20, #0x768]
24B119: 0xfffffff008443e18  cmp w8, #0x8
24B119: 0xfffffff008443e1c  b.hs 0xfffffff0084440cc
```

El primer chequeo corregido admite localmente valores unsigned 1..7 y la segunda condicion requiere el campo `+0x768` inferior a 8. Esto confirma **endurecimiento de limites**, no un `store` controlado.

Los SHA-256 verificados de los KEXT son:

- `24A437`: `dc1ccfb04fc2ff8b600228dde2c5d83f3695ebe119774e285d511e8da4425ea3`.
- `24B119`: `b5b187861ad9287fd3b976d872a89029991acdfcd8bd445a6ebfb2f560cf499c`.

La auditoria independiente valido **11 opcodes ARM64** y un control negativo que rechaza el KEXT antiguo en el puesto del corregido. El paquete de la conversacion incluye script Python, JSON reproducible, informe completo y salida de prueba negativa.

## Diferenciar corrupcion posible de direccion y valor controlados

La documentacion oficial [iOS 27.2](https://support.apple.com/en-us/149230) clasifica CVE-2026-112705 como un problema de escritura fuera de limites que puede detener el sistema; el [PoC publico](https://github.com/Frollir/avetemporalpoc-cve-2026-112705) lo reproduce como un fallo kernel en otro modelo y declara que no da lectura/escritura arbitraria.

Apple tambien confirma CVE-2026-112689 y CVE-2026-112470/469/468 como fallos de AVEVideoEncoder que pueden corromper memoria kernel, pero el aviso no revela el `store` vulnerable, su fuente ni su destino. No tenemos una traza sobre el A15 que demuestre control del contenido y direccion de escritura.

**Resultado positivo:** parche ARM64 exacto demostrado y chequeo antiguo corregido en la interpretacion. **Resultado negativo:** no se verifico escritura kernel ni control de destino/valor; no se obtuvo KernelRW. No es una demostracion de ausencia global de vulnerabilidades en AppleAVE2.
