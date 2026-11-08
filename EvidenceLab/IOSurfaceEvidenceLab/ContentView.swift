import SwiftUI
import UIKit

private struct SharedFile: Identifiable {
    let id = UUID()
    let url: URL
}

struct ContentView: View {
    @State private var report: ProbeReport?
    @State private var campaign: CampaignReport?
    @State private var campaignRunning = false
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
                        Button(campaignRunning ? "Ejecutando..." : "Campaña de 20 ciclos") {
                            campaignRunning = true
                            DispatchQueue.global(qos: .userInitiated).async {
                                let result = CampaignReport.execute()
                                DispatchQueue.main.async {
                                    campaign = result
                                    campaignRunning = false
                                }
                            }
                        }.disabled(campaignRunning)
                    } header: { Text("Prueba local") }

                    if let campaign {
                        Section("Campaña de ciclo de vida") {
                            LabeledContent("Ciclos", value: String(campaign.runs.count))
                            LabeledContent("Creaciones", value: String(campaign.created))
                            LabeledContent("Lecturas correctas", value: String(campaign.verified))
                            LabeledContent("IDs no resueltos tras cierre", value: String(campaign.unresolvedAfterScope))
                            LabeledContent("Fallos o ausencias", value: String(campaign.failedOrUnavailable))
                            Text("Solo son comprobaciones de buffers propios. Esto no demuestra un UAF de kernel ni un bypass SPTM.")
                                .font(.footnote)
                            Button("Exportar campaña JSON") { export(campaign) }
                        }
                    }

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

    private func export<T: Encodable>(_ report: T) {
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

private struct CampaignReport: Encodable {
    let schema = "iosurface-evidence-lab/campaign-v2"
    let timestamp: Date
    let runs: [ProbeReport]
    let created: Int
    let verified: Int
    let unresolvedAfterScope: Int
    let failedOrUnavailable: Int

    static func execute() -> CampaignReport {
        var runs: [ProbeReport] = []
        for _ in 0..<20 {
            runs.append(ProbeRunner.run())
        }
        func count(_ key: String, _ state: String) -> Int {
            runs.filter { run in
                run.steps.contains { $0.id == key && $0.result == state }
            }.count
        }
        let failed = runs.reduce(0) { total, run in
            total + run.steps.filter { $0.result == "FAIL" || $0.result == "UNAVAILABLE" }.count
        }
        return CampaignReport(timestamp: Date(), runs: runs,
            created: count("iosurface_create", "PASS"),
            verified: count("read_owned_buffer", "PASS"),
            unresolvedAfterScope: runs.filter {
                $0.steps.contains { $0.id == "lookup_after_scope" && $0.detail.hasPrefix("El ID ya no") }
            }.count,
            failedOrUnavailable: failed)
    }
}
