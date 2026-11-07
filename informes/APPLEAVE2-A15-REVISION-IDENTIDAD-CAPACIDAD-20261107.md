# AppleAVE2 A15: revision de identidad de objeto y capacidad del indexed store

**Fecha:** 2026-11-07. **Firmware:** AppleAVE2 original de iPhone14,3 (`24A437`) y corregido (`24B119`).
**Resultado:** la capacidad real de la tabla no esta demostrada; tampoco una identidad unica entre las tres rutas del contador ni una ejecucion `N > C` desde una app.

## Verificaciones exactas

- 23 instrucciones ARM64 del 24A437 y 15 del 24B119 cotejadas contra SHA-256 oficiales de los KEXT extraidos previamente.
- El bucle consumidor realiza `L+1` stores para el limite cargado `L` (bajo ejecucion normal). Si un productor valido preparo `L=N-1`, ejecuta `N` stores, no `N+1`.
- La preparadora **no actualiza incondicionalmente** el limite: cuando lee un contador menor que 2 en una rama, salta la escritura de `L`.
- La productora candidata incorpora una comprobacion con maximo firmado de 16, pero no existe prueba de que su contador se use por el consumidor en la misma instancia y bajo todas las rutas.
- Los llamadores directos de las tres funciones obtienen las bases por caminos distintos. La igualdad de los punteros de objeto no se verifica en los fragmentos analizados.
- La productora del parche escribe en `+0xdf8` desde su propia base de subobjeto, mientras la preparadora carga `+0xe00` desde la suya. Comparar offsets no basta para establecer identidad ni diferencia: la relacion entre las bases sigue abierta.
- La base de la tabla es un desplazamiento fijo dentro de un contexto interno, sin metadatos de tipo o reserva confirmados para acotar **su capacidad exacta**. No se infiere una capacidad de 16 solo por la validacion de un recuento.
- El control negativo rechazo el archivo del firmware antiguo al presentarlo como el corregido.

## Lo que no ha sido verificado

No existe evidencia de `C` exacto, de `N > C` en un mismo objeto, de camino de API publica a esa escritura, ni de corrupcion de memoria del kernel. No se disparo una escritura fuera de limites en el iPhone ni se fabrico evidencia KASAN.

El paquete reproducible adjunto a la conversacion contiene `audit_appleave2_relation_y_capacidad.py`, salida JSON (38 comprobaciones), prueba negativa y dictamen tecnico extenso. Esta verificacion es solo de lectura y no interactua con el dispositivo.

## Conclusion

El informe anterior suponia que el limite de 16 y el indice de escritura pertenecian al mismo objeto. Este supuesto **no esta probado** y se registra aqui expresamente. La ruta investigada no puede clasificarse como un OOB del kernel sin una prueba de su capacidad y del aliasing de los objetos.