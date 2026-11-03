# IOSurface Safe Probe para iPhone

Proyecto SwiftUI minimo. Ejecuta solo operaciones documentadas de IOSurface con parametros validos: crear una superficie de 64 x 64, consultar ID/dimensiones, bloquear/desbloquear y buscar el ID propio.

**No prueba una vulnerabilidad**. No llama a metodos privados de IOKit, no intenta forzar x2=0, no causa intencionalmente fallos ni puede leer registros del kernel. Una ejecucion correcta demuestra solamente que esas APIs publicas funcionan en ese dispositivo.

## Compilar sin Mac desde GitHub Actions

1. Crea un repositorio en tu cuenta de GitHub y sube todo el contenido de esta carpeta, incluido `.github/workflows/ipa.yml`.
2. En el repositorio, ve a Actions > Compilar IPA para SideStore > Run workflow.
3. Al terminar, descarga el artefacto `IOSurfaceSafeProbe-unsigned` de esa ejecucion y extrae el `.ipa`.
4. Firma e instala el IPA en tu iPhone con SideStore o tu flujo habitual de sideload. La firma es necesaria porque el IPA de CI no esta firmado.
5. En la app, pulsa `Ejecutar prueba segura` y `Compartir registro`. Copia el resultado para analizarlo.

## En Mac con Xcode

```sh
brew install xcodegen
xcodegen generate
open IOSurfaceSafeProbe.xcodeproj
```

Configura el equipo de firma en Xcode para instalarlo mediante modo desarrollador en tu iPhone.

## Interpretacion

- IOSurfaceCreate: OK = creacion mediante API publica.
- IOSurfaceLock / Unlock: 0 = resultado correcto de operaciones de superficie.
- IOSurfaceLookup: nil = la busqueda por ID no dio objeto. No se interpreta como evidencia de vulnerabilidad.

## Comprobacion de firmware y seguridad

Comprueba antes el numero de compilacion del iPhone en Ajustes > General > Informacion > Version de iOS. La referencia estatica de esta investigacion es iOS 27.0 build 24A437 en iPhone14,3. Cualquier otra version puede tener cambios en el kernelcache.

No uses el movil como banco de pruebas para accesos nulos al kernel, especialmente si contiene datos que no estan respaldados. Para verificar el valor de `x2` en el metodo virtual hacen falta trazas privilegiadas del kernel; una app normal y un sysdiagnose no lo revelan directamente. Realiza esa instrumentacion sobre QEMU y compara luego los resultados funcionales del movil.
