# Dictamen de capacidad y alcanzabilidad del indexed store AppleAVE2 A15

**Dispositivo:** iPhone14,3 · iOS 27.0 `24A437` frente a iOS 27.2 `24B119`.

**Veredicto:** `MISMATCH_AND_APP_REACHABILITY_NOT_DEMONSTRATED`.

La auditoria exacta de los dos KEXT muestra que una ruta que produce el contador de entrada lo limita a un maximo con signo de **16**. El bucle de escritura indexada se conserva en la version corregida y toma un limite que, cuando se inicializa como `N-1`, es compatible con **N stores** (no N+1). Bajo la hipotesis de que ambos caminos operan sobre la misma instancia y que este es el productor efectivo, el volumen maximo seria 16 escrituras de 4 bytes: **64 bytes**.

**Sin resolver:** capacidad real y layout del subarreglo de destino; identidad del objeto entre productor y consumidor; otros productores directos/indirectos; trazado completo desde API de una aplicacion hasta el mismo almacen; control de la direccion y del valor. El hecho de que un PoC publico llegue a *otra* ruta AppleAVE2 no prueba que llegue a este store.

### Evidencia reproducida

- KEXT `24A437`: SHA-256 `dc1ccfb04fc2ff8b600228dde2c5d83f3695ebe119774e285d511e8da4425ea3`, 13/13 instrucciones cotejadas.
- KEXT `24B119`: SHA-256 `b5b187861ad9287fd3b976d872a89029991acdfcd8bd445a6ebfb2f560cf499c`, 13/13 instrucciones cotejadas.
- Prueba negativa: se rechazo el binario 24A437 cuando fue utilizado como supuesto 24B119.
- Ningun experimento de escritura kernel fue ejecutado en el iPhone.

**Interpretacion:** no existe evidencia suficiente para afirmar que `C < N` sea alcanzable con esa ruta ni que este store sea la falla de escritura fuera de limites. El resultado negativo no demuestra que todos los caminos del controlador sean seguros.

El paquete reproducible de la conversacion contiene `verify_appleave2_capacity_reachability.py`, JSON original del analizador, reporte de prueba negativa y dictamen amplio.

Contexto: [Apple iOS 27.2](https://support.apple.com/en-us/149230), [PoC publico de AppleAVE2 (otra ruta)](https://github.com/Frollir/avetemporalpoc-cve-2026-112705).
