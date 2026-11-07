# Protocolo de captura y criterio de correlación: IOSurface

**Revisión:** 2026-11-06  
**Dispositivo objetivo:** iPhone14,3; iOS 27.0 / 24A437.  
**Dictamen actual:** `KERNEL_UAF_NOT_ESTABLISHED`.

## Verificación efectivamente realizada

Se ejecutó un correlador forense de solo lectura con **cuatro fuentes previamente guardadas**: `IOSurfaceSameClient-trace.csv`, `IOSurfacePreflight-log 13.txt`, `IOSurfacePortRevocation-v19_9.json` y `DICTAMEN-CUATRO-CONDICIONES-v60.md`. El informe Markdown es una fuente documental y el programa procesó como datos de diagnóstico los otros **tres** archivos con extensión CSV, TXT y JSON.

**Resultado automatizado:**

- Intervalo medido en el CSV: llamada `[0,537.833]` µs y cierre `[21.458,195.625]` µs, con **174.167 µs** de solapamiento.
- Resultado de la llamada: `call_kr=0x10000003` (no debe tratarse como confirmación de registro de notificaciones); cierre `close_kr=0x00000000`.
- **0 eventos explícitos** de liberación final del cliente, nodo vivo después de liberación y uso posterior con identidad de instancia.
- **0 secuencias de vida útil** autenticadas o candidatas provenientes de estos registros.
- La revisión v19.9 de puertos produjo `EXPECTED_REJECTION`, no UAF.
- Cinco pruebas del correlador verificaron el rechazo de identidades incompatibles, el tratamiento de reutilización de direcciones como ambiguo, la interpretación no concluyente de archivos de panic y el cálculo correcto del solapamiento.

El dictamen preexistente sobre la traza KDebug indica 61 eventos genéricos, sin identidad verificada de `IOSurfaceRootUserClient` ni la secuencia de `last_release -> node_live -> dereference`. Ese archivo de KDebug bruto no fue parte de la nueva ejecución automatizada.

## Qué capturas podemos obtener sin alterar el kernel

- En el iPhone: `Configuración > Privacidad y seguridad > Análisis y mejoras > Datos de análisis`. Exportar los archivos existentes `panic-full-*.ips`, `IOSurfacePreflight_*.ips` o `sysdiagnose_*`, si están presentes. No deben fabricarse ni inferirse eventos ausentes.
- En la app `IOSurfacePreflight`: exportar trazas y checkpoints existentes desde el botón Exportar.
- En Mac: Xcode > Window > Devices and Simulators > View Device Logs, o la aplicación Consola para inspeccionar los eventos visibles del dispositivo.
- En Windows: transferir informes desde Archivos en iPhone o el directorio de informes de fallos de Apple MobileDevice cuando esté disponible.

Fuentes Apple:
- https://developer.apple.com/documentation/xcode/acquiring-crash-reports-and-diagnostic-logs
- https://developer.apple.com/documentation/xcode/diagnosing-issues-using-crash-reports-and-device-logs
- https://it-training.apple.com/support/tutorials/course/sup270/

**Límite de visibilidad:** estas fuentes no garantizan disponer de un evento de última liberación de `OSObject` ni la identidad/generación de un nodo del kernel. Una ejecución sin pánico o sin evento de liberación no demuestra ausencia de defecto.

## Criterio para una correlación real

Se requiere un conjunto **con origen verificable** que vincule el mismo `boot_id`, instancia de `IOSurfaceRootUserClient`, generación y nodo de notificación. Debe contener (1) desasignación efectiva después de la última referencia, (2) confirmación posterior de nodo persistente apuntando a la misma instancia, (3) acceso posterior a través de ese nodo y (4) descarte de reutilización de la dirección. Un JSON de eventos creado manualmente no autentica los hechos.

Una línea de tiempo con solo llamadas y cierres de aplicación no puede satisfacer los cuatro criterios. Si no existe un registro del kernel de esas transiciones, no se puede afirmar que el orden se observó realmente.

## Artefacto de análisis

Se preparó un paquete local `IOSurface_kit_correlacion_evidencia.zip` que incluye un correlador sin dependencias externas (`correlate.py`), cinco pruebas automáticas, guía Windows/macOS y el dictamen de datos existentes. No ejecuta operaciones sobre el dispositivo. El ZIP se entrega como archivo adjunto de la conversación y **no** se publica con datos de diagnóstico privados en GitHub.

**Resultado actual: `KERNEL_UAF_NOT_ESTABLISHED`.** La investigación sigue siendo una atribución de condiciones estructurales, no una demostración experimental de UAF o corrupción de memoria.
