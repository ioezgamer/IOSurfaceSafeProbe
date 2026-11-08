import SwiftUI
import UIKit

private struct SharedFile: Identifiable {
    let id = UUID()
    let url: URL
}

struct ContentView: View {
    @State private var report: ProbeReport?
    @State private var logInput = ""
    @State private var findings: [AuditFinding] = []
    @State private var sharedFile: SharedFile?
    @State private var error: String?

    var body: some View {
        TabView {
            NavigationStack {
                Form {
                    Section {
                        Text("Verificacion de APIs publicas sobre un buffer IOSurface propio. No intenta vulnerar iOS.")
                            .font(.subheadline)
                        Button("Ejecutar prueba reproducible") {
                            report = ProbeRunner.run()
                        }
                        .buttonStyle(.borderedProminent)
                    } header: { Text("Prueba local") }

                    if let report {
                        Section("Resultados") {
                            LabeledContent("iOS", value: report.iosVersion)
                            LabeledContent("IOSurface ID", value: report.iosurfaceID.map(String.init) ?? "N/D")
                            LabeledContent("Asignacion", value: report.allocationBytes.map { "\($0) bytes" } ?? "N/D")
                            ForEach(report.steps) { step in
                                VStack(alignment: .leading, spacing: 5) {
                                    HStack {
                                        Text(step.id).font(.subheadline.monospaced()).bold()
                                        Spacer()
                                        Text(step.result).font(.caption).foregroundStyle(step.result == "PASS" ? .green : .secondary)
                                    }
                                    Text(step.detail).font(.caption).foregroundStyle(.secondary)
                                }
                                .padding(.vertical, 3)
                            }
                        }
                        Section("Alcance") {
                            ForEach(report.interpretation, id: \.self) { item in
                                Text(item).font(.footnote)
                            }
                        }
                        Section {
                            Button("Exportar evidencia JSON") { export(report) }
                        }
                    }
                }
                .navigationTitle("IOSurface Evidence")
            }
            .tabItem { Label("Prueba", systemImage: "checkmark.shield") }

            NavigationStack {
                Form {
                    Section("Pegar registro") {
                        Text("Pega el texto original de una ejecucion. El analizador distingue las afirmaciones de las pruebas independientes.")
                            .font(.footnote)
                        TextEditor(text: $logInput)
                            .font(.system(.caption, design: .monospaced))
                            .frame(minHeight: 210)
                            .accessibilityLabel("Registro a auditar")
                        Button("Auditar afirmaciones") {
                            findings = LogAuditor.analyze(logInput)
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(logInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    }
                    if !findings.isEmpty {
                        Section("Dictamen por componente") {
                            ForEach(findings) { finding in
                                VStack(alignment: .leading, spacing: 5) {
                                    Text(finding.title).bold()
                                    Text(finding.status).font(.caption).foregroundStyle(.orange)
                                    Text(finding.explanation).font(.footnote)
                                    ForEach(finding.evidence, id: \.self) { evidence in
                                        Text(evidence).font(.system(.caption2, design: .monospaced))
                                            .foregroundStyle(.secondary).textSelection(.enabled)
                                    }
                                }.padding(.vertical, 6)
                            }
                        }
                    }
                }
                .navigationTitle("Auditar registro")
            }
            .tabItem { Label("Registro", systemImage: "doc.text.magnifyingglass") }
        }
        .sheet(item: $sharedFile) { file in ShareSheet(file: file.url) }
        .alert("No se pudo exportar", isPresented: Binding(
            get: { error != nil }, set: { if !$0 { error = nil } }
        )) { Button("Aceptar", role: .cancel) { error = nil } } message: {
            Text(error ?? "Error desconocido")
        }
    }

    private func export(_ report: ProbeReport) {
        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            encoder.dateEncodingStrategy = .iso8601
            let data = try encoder.encode(report)
            let url = FileManager.default.temporaryDirectory
                .appendingPathComponent("iosurface-evidence-\(UUID().uuidString.prefix(8)).json")
            try data.write(to: url, options: .atomic)
            sharedFile = SharedFile(url: url)
        } catch {
            self.error = error.localizedDescription
        }
    }
}

private struct ShareSheet: UIViewControllerRepresentable {
    let file: URL
    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: [file], applicationActivities: nil)
    }
    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}
