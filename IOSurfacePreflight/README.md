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
