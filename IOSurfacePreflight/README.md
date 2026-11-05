# IOSurface Preflight
App iOS de diagnóstico no invasivo para comprobar creación y consulta de una IOSurface propia, y apertura/cierre único del servicio IOSurfaceRoot.

No ejecuta carreras, no llama a externalMethod, no accede a memoria liberada, y no proporciona KernelRW ni jailbreak.

## Compilación en GitHub Actions
Workflow: `.github/workflows/ios-preflight-ipa.yml`.
Una actualización de la rama `preflight-ipa` activa la compilación en macOS.
Artefacto de salida: `IOSurfacePreflight-unsigned-ipa`, que contiene `IOSurfacePreflight-unsigned.ipa`.

El IPA **no está firmado**. Para instalarlo necesitás firmarlo con tu propia cuenta/herramienta autorizada (por ejemplo SideStore). No incluye firma ni credenciales.

## Resultados
- PUBLIC: PASS create confirma la API pública.
- ROOT: SERVICE_VISIBLE indica que se pudo resolver el servicio.
- ROOT: OPEN kr=0x00000000 indica conexión concedida a esa aplicación.
Nada de ello prueba una vulnerabilidad o una primitiva KernelRW.


## Prueba 16 y 17: cierre controlado con una superficie viva (v13)

La opción **16** crea una IOSurface usando únicamente la API pública, conserva dos referencias válidas y abre una conexión **independiente** a IOSurfaceRoot. Se detiene en una barrera **de espacio de usuario**; pulsá **17** para cerrar esa conexión mientras la superficie continúa retenida. Hay cierre automático tras aproximadamente 30 segundos si no se pulsa el botón 17.

Se guardan en Documents:
- `IOSurfaceControlledClose-checkpoint.json` (se actualiza atómicamente en cada fase).
- `IOSurfaceControlledClose-trace.csv` (marcas temporales, apertura y cierre).

La opción **Exportar** incluye ambos archivos. Tras relanzar la app se informa si la ejecución anterior quedó incompleta.

**Alcance:** la conexión que abrimos explícitamente puede ser distinta de la conexión privada que usa internamente `IOSurfaceCreate`. La pausa ocurre **fuera** del kernel y la prueba no ejecuta carreras ni interrumpe una rutina interna a voluntad. Ni la conclusión PASS ni un cierre inesperado de la app demuestran liberación prematura del objeto, use-after-free, kernel panic o KernelRW. Para demostrar eso hace falta una traza interna del kernel que correlacione referencia y generación del objeto con `register`, `close`, `free` y `dereference`.

