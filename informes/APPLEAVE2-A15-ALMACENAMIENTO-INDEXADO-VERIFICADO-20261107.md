# AppleAVE2 iPhone14,3: primer store indexado verificado byte a byte

**Firmwares exactos:** 24A437 e iOS 27.2 24B119. Este informe no afirma KernelRW.

En el firmware original, funcion `0xfffffff0084c2114`, la instruccion `0xfffffff0084c235c` ejecuta `str w24, [x10, x9, lsl #2]` (opcode `0xb8297958`). La base `x10` se calcula como `x8 + 0x4678`, donde `x8` es una referencia obtenida de `[x23 + 8]`; el contador limite se carga de `[x8 + 0x3760]`. El valor escrito es `w24` calculado en una ruta anterior.

En 24B119, funcion `0xfffffff0084f2158`, el store **persiste con el mismo opcode** en `0xfffffff0084f23a0`. La base se desplazo a `x8+0x4680` y el campo contador a `[x8+0x3768]`.

Se validaron directamente desde los Mach-O originales, con SHA256 comprobados, cinco palabras ARM64 en cada build (10 pruebas positivas). La prueba negativa sustituyendo el binario parcheado por el antiguo fue rechazada.

La auditoria de las 26 regiones modificadas verifico que la funcion de validacion de capas temporales del build original (`0xfffffff008416de0`) hace 63 stores **solo a pila**; la funcion parcheada (`0xfffffff008443a34`) hace 152 stores **solo a pila**. Esto no describe los efectos de funciones a las que llaman.

**Conclusion:** store indexado de un objeto del controlador confirmado, **NO** escritura arbitraria de kernel confirmada. Falta verificar la capacidad real del arreglo, la validacion del contador y su procedencia desde llamadas de aplicaciones; el almacenamiento indexado por si solo no demuestra desbordamiento. El hecho de que la misma instruccion siga existiendo en el parche impide atribuirle automaticamente una CVE.

Hashes: `24A437 = dc1ccfb04fc2ff8b600228dde2c5d83f3695ebe119774e285d511e8da4425ea3`; `24B119 = b5b187861ad9287fd3b976d872a89029991acdfcd8bd445a6ebfb2f560cf499c`.

Fuente: extracciones exactas AppleAVE2 [GitHub Actions](https://github.com/ioezgamer/IOSurfaceSafeProbe/actions/runs/42408583861). Evidencia ampliada y scripts: paquete descargable en la conversacion.

## Seguimiento del límite del bucle (16 comprobaciones de opcodes)

El campo de límite no aparece sin procedencia: en `24A437` se carga `w9` desde `[x19+0xdf8]` (`0xfffffff008542af0`), se calcula `w9-1` (`0xfffffff008542b04`) y se conserva en `[x19+0x3760]` (`0xfffffff008542b0c`). En `24B119` la misma lógica obtiene `[x19+0xe00]`, resta uno y guarda `[x19+0x3768]` (`0xfffffff00857304c`, `...3060`, `...3068`). Estas seis instrucciones adicionales se verificaron byte por byte junto a las diez anteriores, con una prueba negativa que rechazó un build sustituido.

El bucle del `str` usa condición inclusiva (`b.lo` tras incrementar el contador que empieza en -1). Si el campo original representa la cantidad de entradas `N`, el almacén del límite `N-1` es compatible con efectuar **exactamente N iteraciones**, no con un desbordamiento de una posición. No se ha probado una discrepancia entre la capacidad reservada y el número de escrituras. Este candidato sigue siendo un `store` real, **pero no un fallo OOB demostrado**.
