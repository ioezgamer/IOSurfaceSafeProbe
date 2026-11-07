# Ruta candidata de corrupcion IOSurface: notificaciones y cierre del cliente

**Fecha:** 7 noviembre 2026. **Objetivo:** iPhone14,3 / iOS 27.0 / 24A437.

## Resultado de ingenieria inversa verificada

Se trazaron los dos controladores originales, hashes SHA-256:
- 24A437: `3f95c45f629a8749775765980434ee927552e1cad4e568743062bf901aa018d8`
- 24B119: `a1d255c31648eb54385b32cb51277a262b7d99c246a5195e591ae8d827b3275c`

La tabla de despacho de ambas versiones confirma la asociacion de **selector 17** al registro asincrono de notificaciones (`s_set_surface_notify`, etiqueta historica) y **selector 18** a su retirada. El primero es asincrono y exige una estructura de 24 bytes.

En la version corregida 24B119, la funcion de registro comprueba un byte de estado nuevo en `cliente+0xf1`. Otra funcion, invocada en la limpieza del cliente, marca este estado antes de retirar las inscripciones. La rutina de cierre se reorganizo para efectuar esa limpieza antes de otras operaciones.

La version 24A437 no presenta esa comprobacion ni esa marca. Por ello, **la candidata principal es una interaccion entre el registro asincrono de notificaciones y el desmontaje del cliente IOSurface**. Esta conclusion procede de comprobar el destino de los punteros de la tabla y las instrucciones concretas del Mach-O de cada build, no de copiar una tabla de macOS.

## Calidad de la evidencia

- **Confirmado estaticamente:** selectores 17/18, saltos a sus handlers, codigo de estado introducido en 24B119 y nueva llamada de limpieza.
- **Hipotesis:** la funcion del cambio es impedir una operacion tardia cuando el cliente se esta desmontando.
- **No comprobado:** que el estado corresponda concretamente a CVE-2026-112477, que exista un intercalado explotable en 24A437, o que una app sin privilegios consiga corrupcion de memoria.
- **No generado:** prueba de explotacion en el iPhone, lectura/escritura arbitraria del kernel, KernelRW o jailbreak.

Apple solo confirma una carrera de IOSurface corregida mediante **mejoras de bloqueo**, sin publicar el disparador: https://support.apple.com/en-us/149230.

## Verificacion

La herramienta local `iosurface_notification_path_audit.py` valida los dos hashes, las entradas 17/18, los destinos de los saltos, la lectura/establecimiento de estado y la llamada de limpieza. Rechaza cualquier cambio inesperado. Sus resultados se incluyen en el paquete de evidencias compartido en esta conversacion.

La siguiente confirmacion valida requeriria evidencia dinamica del registro asincrono y de un conflicto de ciclo de vida en un entorno de kernel instrumentado. **Un panic aislado en un iPhone sin instrumentacion no probaria la causa.**
