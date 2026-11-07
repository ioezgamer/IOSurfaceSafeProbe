# Causa del rechazo del selector 4 en IOSurface 24A437

Fecha: 2026-11-07. Objetivo: iPhone14,3 / iOS 27.0 / 24A437.

## Resumen ejecutivo

El selector 4 no sirve para recuperar nuevamente por ID una IOSurface ya registrada en el mismo user-client. El handler del kernel detecta esta condición en un índice específico del cliente y responde 0xe00002c2 (kIOReturnBadArgument). El resultado coincide con el registro de nuestra app usando ID 156. Este comportamiento no constituye vulnerabilidad.

## Procedencia exacta de los bytes

Extracción reproducible: .github/workflows/iosurface-firmware-24a437.yml. Ejecutar el comando de descarga parcial ipsw download ipsw --device iPhone14,3 --build 24A437 --kernel --confirm, seguido por ipsw kernel extract.

- IPSW de Apple: iPhone14,3_27.0_24A437_Restore.ipsw
- Kernelcache: kernelcache.release.iPhone14,3, 67108864 bytes, UUID CCE3FBC8-E292-6A87-BC3A-7A4722DFAFB7
- Kernelcache SHA-256: 742714192f267bf7fbfe3de8c5437b534d7f305bf87c8b77c4d1ad9dd7446385
- Kernelcache base de __TEXT: 0xfffffff007004000
- KEXT: com.apple.iokit.IOSurface, 314376 bytes, UUID E97FA303-AD9E-3266-86CB-C690F105334F
- KEXT SHA-256: 3f95c45f629a8749775765980434ee927552e1cad4e568743062bf901aa018d8
- LC_SYMTAB: 0 símbolos; los nombres provienen de la semántica y referencias históricas, no de un símbolo presente en el binario.

## Tabla real de despacho de 24A437

El Mach-O contiene DOS tablas de 60 entradas y 40 bytes cada una, en __DATA_CONST,__const:

- Normal: offset de archivo 0x46638, dirección virtual 0xfffffff0080648c0
- Restringida: offset de archivo 0x46f98, dirección virtual 0xfffffff008065220
- Selector 4 normal: 1 escalar entrante, 0 bytes de estructura entrante, 0 escalares salientes, 3176 bytes de estructura saliente.
- Selector 6 normal: 32 bytes de estructura entrante y 3176 bytes de estructura saliente.
- Selector 13 normal: ninguna entrada, 40 bytes de estructura saliente.
- Selectores 17 y 40 tienen indicador asíncrono.
- Veinticuatro entradas de función difieren entre ambas tablas, entre ellas las posiciones 4 y 6.

La variante restringida no es atribuible a nuestra app sin más datos. El éxito del selector 6 es compatible con la tabla normal. Los formatos desde selector 43 a 59 no coinciden con la tabla macOS 27 publicada en https://github.com/Kurt-228/ios27-research/blob/main/docs/iosurface_sel_formats.md, por lo que esa ABI ajena no debe suponerse idéntica.

## Método 4: puntero autenticado y salto

La tabla normal contiene la palabra de puntero ARM64e 0x8050bcad02c1503c. Interpretada como DYLD_CHAINED_PTR_64_KERNEL_CACHE, el objetivo de 30 bits es 0x02c1503c, cacheLevel 0. Sumado a la base de __TEXT del kernelcache, resuelve el thunk en 0xfffffff009c1903c.

~~~asm
0xfffffff009c1903c: hint #0x22
0xfffffff009c19040: ldr x8, [x2, #0x20]
0xfffffff009c19044: ldr w1, [x8]
0xfffffff009c19048: ldr x2, [x2, #0x58]
0xfffffff009c1904c: b 0xfffffff009c1bbc0
~~~

La implementación en 0xfffffff009c1bbc0 inicializa un código de retorno y comprueba primero si el cliente ya conoce el ID:

~~~asm
0xfffffff009c1bbfc: mov w19, #0x2bd
0xfffffff009c1bc00: movk w19, #0xe000, lsl #16
0xfffffff009c1bc18: bl 0xfffffff009c1f5dc
0xfffffff009c1bc1c: tbnz w0, #0, 0xfffffff009c1bd04
~~~

El ayudante en 0xfffffff009c1f5dc compara el ID con el tamaño del índice en client+0x110; consulta client+0x108 y su entrada indexada por ID, comprueba que el puntero exista y compara la identidad del objeto en object+0x10 con la identidad en client+0x118. En el caso encontrado:

~~~asm
0xfffffff009c1f69c: str x16, [x2]
0xfffffff009c1f6a0: mov w0, #0x1
~~~

Al recibir w0=1, el tbnz deriva a la rama de rechazo, que modifica el valor previo y lo devuelve:

~~~asm
0xfffffff009c1bd04: ldr x0, [x20, #0xd8]
0xfffffff009c1bd08: bl 0xfffffff009c29b6c
0xfffffff009c1bd0c: add w19, w19, #0x5
0xfffffff009c1bd28: mov x0, x19
~~~

Cálculo: 0xe00002bd + 5 = 0xe00002c2.

Para los IDs que no están registrados en este cliente, el método toma otra ruta de búsqueda, con controles adicionales. Este análisis NO demuestra acceso a superficies ajenas.

## Correlación con el ensayo real

AppleIOKitLab-direct-roundtrip.json, observado en iPhone14,3/24A437:

- Apertura del user-client tipo 0: éxito.
- Selector 6: creó superficie ID 156, salida de 3176 bytes.
- Selector 4: rechazó ese mismo ID con 0xe00002c2.
- Selectores 2 y 3: bloquear/desbloquear con éxito.
- Selector 9: propiedad propia escrita con éxito.
- Selector 10: propiedad recuperada; 64 bytes y valor exacto al decodificar.
- IOSurfaceCopyValue: contraste independiente del mismo valor, correcto.
- Cierre de conexión: éxito.

El argumento del selector 4 sí coincide con el tamaño impuesto por la tabla real, por tanto el rechazo no se explica por conteos de entrada/salida erróneos. La rama condicional encontrada proporciona una causa específica y coherente con el caso observado.

## Criterio de evidencia

CONFIRMADO ESTÁTICAMENTE: contenido de la tabla, puntero del método, thunk, función de índice propio, rama y código de retorno en 24A437. El script de verificación valida el hash del KEXT y doce huellas de instrucciones en sus direcciones virtuales.

CONFIRMADO DINÁMICAMENTE: el usuario logró creación, lock/unlock y roundtrip de propiedades de superficie propia, mientras el lookup del propio ID devolvió 0xe00002c2.

NO DEMOSTRADO: UAF, desbordamiento, primitivas de memoria kernel arbitraria, escalada de permisos ni jailbreak.

Siguiente investigación razonable: auditoría de límites y ciclo de vida de métodos accesibles en el mismo binario, documentando validaciones e invariantes y evitando atribuir un exploit a operaciones normales del controlador.
