# Resultado GPU real en iPhone 13 Pro Max: lectura y escritura entre buffers propios

**Fecha:** 2026-11-07.
**Origen de la evidencia:** AppleIOKitLab-gpu-owned-buffer.json compartido por el propietario del dispositivo, generado por Apple IOKit Lab 1.8.
**Equipo:** iPhone14,3, Apple A15 GPU, iOS 27.0, build 24A437.
**Veredicto de la app:** OWN_CONTEXT_GPU_CROSS_BUFFER_READ_AND_WRITE_CONFIRMED.

## Datos concretos registrados

| Variable | Valor |
|---|---|
| Dirección GPU del primer búfer | 0x0000001500068000 |
| Dirección GPU del segundo búfer | 0x0000001500080000 |
| Distancia | 98304 bytes, 0x18000, 96 KiB |
| Tamaño de cada búfer | 65536 bytes, 64 KiB |
| Índice usado en uint32 | 24576 |
| Datos preexistentes del segundo búfer | 0x11223344 |
| Lectura vía primer búfer | 0x11223344 |
| Marcador escrito | 0x57524954 |
| Valor leído desde CPU después de escritura | 0x57524954 |
| Estados de los tres command buffers | 4, 4, 4 (completed) |
| IOSurface F1 usado | No |

La dirección del segundo recurso está a 98304 bytes del primero, 32768 bytes más allá del tamaño lógico del primero. El shader leyó el marcador ya existente del segundo búfer y lo modificó; la aplicación leyó los resultados desde CPU. Estos valores proceden del JSON de la aplicación, no de una traza externa del kernel.

## Dictamen verificable

**CONFIRMADO POR REGISTRO DE APLICACIÓN:** lectura y escritura entre dos asignaciones Metal creadas y controladas por el mismo proceso, dentro de su propio espacio de direcciones virtual GPU.

**NO CONFIRMADO:** daño de memoria del kernel, uso de memoria liberada, acceso entre procesos o dominios GPU, lectura de páginas que no pertenezcan a la app, explotación de IOSurface F1, bypass de sandbox, bypass de IOMMU/UAT, KernelRW, jailbreak o un informe KASAN.

La auditoría pública F1OOB sección 19 incluye un control con un búfer Metal ordinario y describe que el acceso entre objetos del mismo contexto no depende de IOSurface F1. Nuestro experimento usa dos recursos de la propia app y no ejecuta F1.

Fuente de contraste: https://github.com/SKVLENT/ANE-Exploit/blob/main/F1OOB_ANALYSIS.md

## Frontera de investigación

El siguiente objetivo significativo es demostrar un cruce de límites entre dominios de seguridad, no repetir acceso entre búferes de una misma app. A falta de esa evidencia, el resultado no debe describirse como acceso arbitrario a memoria del kernel.

Fuentes del experimento: AppleIOKitLab/Sources/GPUOwnedBufferProbe.m y AppleIOKitLab/Sources/GPUOwnedBuffer.metal.
