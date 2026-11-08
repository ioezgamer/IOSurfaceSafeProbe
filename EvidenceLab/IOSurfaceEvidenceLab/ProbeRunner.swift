import Foundation
import CoreFoundation
import IOSurface
import UIKit

struct ProbeStep: Codable, Identifiable {
    let id: String
    let result: String
    let detail: String
}

struct ProbeReport: Codable {
    let schema: String
    let timestamp: Date
    let iosVersion: String
    let iosurfaceID: UInt32?
    let allocationBytes: Int?
    let steps: [ProbeStep]
    let interpretation: [String]
}

// Pruebas de APIs publicas sobre buffers de titularidad de la aplicacion.
// No usa referencias invalidas, carreras, memoria del kernel ni offsets privados.
enum ProbeRunner {
    private struct LocalRun {
        let id: UInt32
        let allocation: Int
    }

    static func run() -> ProbeReport {
        var steps: [ProbeStep] = []
        func log(_ id: String, _ result: String, _ detail: String) {
            steps.append(ProbeStep(id: id, result: result, detail: detail))
        }

        let local: LocalRun? = autoreleasepool {
            // Construir el diccionario CF con tipos CoreFoundation explicitos,
            // evitando conversiones fragiles entre NSDictionary y CFDictionary.
            var keyCallbacks = kCFTypeDictionaryKeyCallBacks
            var valueCallbacks = kCFTypeDictionaryValueCallBacks
            guard let properties = CFDictionaryCreateMutable(kCFAllocatorDefault, 4,
                                        &keyCallbacks, &valueCallbacks) else {
                log("properties", "FAIL", "No se pudo crear el diccionario de propiedades.")
                return nil
            }
            let keys: [CFString] = [kIOSurfaceWidth, kIOSurfaceHeight,
                                    kIOSurfaceBytesPerElement, kIOSurfacePixelFormat]
            let rawValues: [Int32] = [64, 64, 4, 0x42475241] // 'BGRA'
            for (key, rawValue) in zip(keys, rawValues) {
                var number = rawValue
                guard let cfNumber = CFNumberCreate(kCFAllocatorDefault, .sInt32Type, &number) else {
                    log("properties", "FAIL", "No se pudo convertir una propiedad numerica.")
                    return nil
                }
                CFDictionarySetValue(properties,
                    Unmanaged.passUnretained(key).toOpaque(),
                    Unmanaged.passUnretained(cfNumber).toOpaque())
            }
            guard let owner = IOSurfaceCreate(properties) else {
                log("iosurface_create", "FAIL", "IOSurfaceCreate devolvio nil.")
                return nil
            }
            let id = IOSurfaceGetID(owner)
            let allocation = IOSurfaceGetAllocSize(owner)
            log("iosurface_create", "PASS", "Superficie propia creada con ID \(id); tamano \(allocation) bytes.")

            // Leer y escribir solo dentro de la memoria de pixel propia, con el lock adecuado.
            let token = UInt64.random(in: UInt64.min...UInt64.max)
            if allocation >= MemoryLayout<UInt64>.size && IOSurfaceLock(owner, [], nil) == 0 {
                IOSurfaceGetBaseAddress(owner).storeBytes(of: token, as: UInt64.self)
                IOSurfaceUnlock(owner, [], nil)
                log("write_owned_buffer", "PASS", "8 bytes escritos en un buffer de esta aplicacion. NO es kernel write.")
            } else {
                log("write_owned_buffer", "FAIL", "No fue posible bloquear o escribir el buffer propio.")
            }

            // IOSurfaceLookup retiene atomicamente una referencia valida, NO una referencia colgante.
            if let lookup = IOSurfaceLookup(id) {
                log("lookup_live_id", "PASS", "IOSurfaceLookup(\(id)) encontro una superficie viva.")
                let size = IOSurfaceGetAllocSize(lookup)
                if size >= MemoryLayout<UInt64>.size && IOSurfaceLock(lookup, [], nil) == 0 {
                    let observed = IOSurfaceGetBaseAddress(lookup).load(as: UInt64.self)
                    IOSurfaceUnlock(lookup, [], nil)
                    log("read_owned_buffer", observed == token ? "PASS" : "FAIL",
                        observed == token ? "Token identico a traves de dos referencias validas; NO es kernel read." : "Token diferente; no coincide el contenido.")
                } else {
                    log("read_owned_buffer", "FAIL", "La superficie encontrada no se pudo leer de forma segura.")
                }
            } else {
                log("lookup_live_id", "UNAVAILABLE", "IOSurfaceLookup no devolvio referencia. La API o configuracion de iOS puede limitar busquedas; no demuestra UAF.")
            }
            return LocalRun(id: id, allocation: allocation)
        }

        // Esta consulta se hace fuera del bloque en que existieron las referencias propias.
        // Su resultado nunca se interpreta como reutilizacion de una direccion del kernel.
        if let local {
            let foundAfterRelease = IOSurfaceLookup(local.id) != nil
            log("lookup_after_scope", "OBSERVED", foundAfterRelease ?
                "El ID aun se puede resolver. Puede haber otras referencias o retencion del sistema; NO prueba UAF." :
                "El ID ya no se resuelve. Esto NO prueba que la memoria del kernel se haya reutilizado.")
        }
        log("kernel_address", "NOT_TESTED", "Sin instrumentacion autorizada no se observa la direccion real de un objeto del kernel.")
        log("kernel_read_write", "NOT_TESTED", "No se intenta acceso a memoria del kernel.")
        log("sptm", "NOT_TESTED", "No se realiza ningun bypass de SPTM.")

        return ProbeReport(schema: "iosurface-evidence-lab/v1", timestamp: Date(),
                           iosVersion: UIDevice.current.systemVersion,
                           iosurfaceID: local?.id, allocationBytes: local?.allocation,
                           steps: steps,
                           interpretation: [
                             "La coincidencia de un token solo valida dos referencias legitimas al mismo buffer de pixeles.",
                             "Un IOSurfaceID no identifica por si mismo una direccion fisica o virtual del kernel.",
                             "No se puede deducir un UAF, derrota de KASLR, kread, kwrite o bypass SPTM de estas APIs publicas."
                           ])
    }
}
