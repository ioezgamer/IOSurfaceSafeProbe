import Foundation

// Este analizador solo verifica lo que un registro afirma. No valida una
// direccion del kernel ni convierte una afirmacion de exito en una prueba.
struct AuditFinding: Codable, Identifiable {
    let key: String
    let title: String
    let status: String
    let explanation: String
    let evidence: [String]
    var id: String { key }
}

struct LogAuditor {
    static func analyze(_ text: String) -> [AuditFinding] {
        let lines = text.components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        let lower = text.lowercased()
        func selected(_ patterns: [String]) -> [String] {
            Array(lines.filter { line in
                patterns.contains { line.range(of: $0, options: [.caseInsensitive, .regularExpression]) != nil }
            }.prefix(5))
        }
        func flag(_ name: String) -> Bool? {
            let pattern = "\\b" + NSRegularExpression.escapedPattern(for: name) + "\\s*=\\s*(yes|no)\\b"
            guard let regex = try? NSRegularExpression(pattern: pattern, options: .caseInsensitive) else { return nil }
            let range = NSRange(text.startIndex..<text.endIndex, in: text)
            guard let match = regex.matches(in: text, range: range).last,
                  let valueRange = Range(match.range(at: 1), in: text) else { return nil }
            return text[valueRange].lowercased() == "yes"
        }
        func item(_ key: String, _ title: String, _ status: String,
                  _ explanation: String, _ patterns: [String]) -> AuditFinding {
            AuditFinding(key: key, title: title, status: status,
                         explanation: explanation, evidence: selected(patterns))
        }
        var output: [AuditFinding] = []
        let dangling = flag("dangling")
        let realloc = flag("realloc")
        let uafLine = lower.contains("uaf exploit")
        let uafStatus = (dangling == true && realloc == true) ? "AFIRMADO, NO VERIFICADO" :
            (uafLine || dangling != nil || realloc != nil ? "INCOMPLETO" : "SIN EVIDENCIA")
        output.append(item("uaf", "UAF de IOSurface", uafStatus,
                           "Los indicadores dangling/realloc son declaraciones del programa. No prueban que un objeto del kernel haya sido liberado y accedido posteriormente.",
                           ["uaf exploit", "dangling=", "realloc="]))

        output.append(item("spray", "Reutilizacion de zona", lower.contains("spray reclaimed") ? "AFIRMADA, NO VERIFICADA" : "SIN EVIDENCIA",
                           "Un identificador, un recuento de superficies o un 'zone hit' no establecen identidad de direccion ni solapamiento real de objetos del kernel.",
                           ["spray reclaimed", "surface spray", "dual spray", "zone hit"]))

        let successKASLR = lower.contains("kaslr defeated")
        let failKASLR = lower.contains("kaslr not defeated")
        let contradictory = successKASLR && failKASLR
        let kaslrStatus = contradictory ? "CONTRADICTORIO" : successKASLR ? "AFIRMADO, NO VERIFICADO" :
            failKASLR ? "FALLO DECLARADO" : flag("kaslr") == true ? "AFIRMADO, NO VERIFICADO" : "SIN PRUEBA"
        output.append(item("kaslr", "Derrota de KASLR", kaslrStatus,
                           "La direccion y el slide deben contrastarse con una fuente independiente y autorizada; la salida de la app por si sola no los certifica.",
                           ["kaslr defeated", "kaslr not defeated", "slide=", "method=vm_read", "kaslr="]))

        let failedRW = lower.contains("r/w setup failed") || lower.contains("r/w primitive setup failed")
        let read = flag("kread")
        let write = flag("kwrite")
        output.append(item("kread", "Lectura del kernel",
                           read == true ? "AFIRMADA, NO VERIFICADA" : read == false ? "NO CONSEGUIDA" : "SIN PRUEBA",
                           "kread=no descarta una lectura demostrada en esta ejecucion; kread=yes exigiria datos verificables, no solo un mensaje.",
                           ["kread=", "r/w setup failed", "r/w primitive setup failed"]))
        output.append(item("kwrite", "Escritura del kernel",
                           write == true ? "AFIRMADA, NO VERIFICADA" : write == false ? "NO CONSEGUIDA" : "SIN PRUEBA",
                           "kwrite=no descarta una escritura demostrada en esta ejecucion; no inferirla de un UAF o spray.",
                           ["kwrite=", "r/w setup failed", "r/w primitive setup failed"]))
        output.append(item("sptm", "Bypass de SPTM", "NO DEMOSTRADO",
                           "Ni el titulo de una herramienta ni los mensajes de KASLR/UAF certifican eludir SPTM. No hay evidencia de control de paginas protegidas.",
                           ["sptm", "result:"]))
        output.append(item("overall", "Conclusion",
                           failedRW || read == false || write == false ? "PARCIAL, SIN kR/W" : "NO VERIFICABLE",
                           "Esta auditoria procesa texto suministrado y nunca accede al kernel. Sus hallazgos no equivalen a validacion dinamica de un exploit.",
                           ["result:", "r/w setup failed", "r/w primitive setup failed", "kread=", "kwrite="]))
        return output
    }
}
