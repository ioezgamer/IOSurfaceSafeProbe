import SwiftUI

struct JailbreakView: View {
    @State private var log = ""
    @State private var running = false

    private let primitives: [(name: String, status: PrimitiveStatus, round: String)] = [
        ("Reserved Key Override", .confirmed, "R14"),
        ("Stride OOB Write", .confirmed, "R15"),
        ("Mach Port Signatures", .confirmed, "R16"),
        ("Stable Heap Groom (60%)", .confirmed, "R18"),
        ("Stale Read Post-Destroy", .confirmed, "R20"),
        ("Zone Isolation Confirmed", .confirmed, "R21"),
        ("IOKit Selector Fuzzing", .confirmed, "R23"),
        ("GPU/Metal Service Access", .confirmed, "R24"),
        ("Service Exploit Chain", .confirmed, "R25"),
        ("VM Remap + Syscall", .confirmed, "R26"),
        ("Kernel Address Leak", .confirmed, "R26"),
        ("OOB Heap Read", .confirmed, "R26"),
        ("KASLR Slide Defeated", .confirmed, "R27"),
        ("Cross-Surface Data Leak", .confirmed, "R27"),
        ("154 Kernel Ptr Leak", .confirmed, "R27"),
        ("Cross-Surface Sentinel", .confirmed, "R28"),
        ("7 Vtable Candidates", .confirmed, "R28"),
        ("Vtable Confusion", .notFound, "R29"),
        ("Controlled UAF", .notFound, "R29"),
        ("Pipe Kernel R/W", .notFound, "R29"),
        ("Mach OOL Heap Control", .pending, "R30"),
        ("IOKit Method Exploit", .pending, "R30"),
        ("Kernel Info Harvest", .pending, "R30"),
        ("Kernel R/W Primitive", .pending, "R30"),
    ]

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    headerSection
                    primitivesSection
                    exploitButton
                    if !log.isEmpty { logSection }
                }
                .padding(.horizontal)
                .padding(.bottom, 30)
            }
            .background(Color.black)
            .navigationTitle("Jailbreak")
            .navigationBarTitleDisplayMode(.inline)
        }
    }

    private var headerSection: some View {
        VStack(spacing: 8) {
            Image(systemName: "lock.open.trianglebadge.exclamationmark.fill")
                .font(.system(size: 48))
                .foregroundStyle(
                    LinearGradient(colors: [.red, .orange], startPoint: .topLeading, endPoint: .bottomTrailing)
                )

            Text("IOSurface Exploit Chain")
                .font(.title2.bold())
                .foregroundStyle(.white)

            Text("iOS 27.0 — iPhone 13 Pro Max")
                .font(.caption)
                .foregroundStyle(.gray)

            Text("Investigación educativa de seguridad")
                .font(.caption2)
                .foregroundStyle(.gray.opacity(0.6))
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 20)
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(Color.white.opacity(0.03))
                .overlay(
                    RoundedRectangle(cornerRadius: 16)
                        .stroke(Color.red.opacity(0.3), lineWidth: 1)
                )
        )
    }

    private var primitivesSection: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Primitivas Confirmadas")
                .font(.headline)
                .foregroundStyle(.white)
                .padding(.bottom, 6)

            ForEach(primitives, id: \.name) { prim in
                HStack(spacing: 12) {
                    Image(systemName: prim.status.icon)
                        .font(.body)
                        .foregroundStyle(prim.status.color)
                        .frame(width: 24)

                    Text(prim.name)
                        .font(.subheadline)
                        .foregroundStyle(prim.status == .notFound ? .gray : .white)

                    Spacer()

                    Text(prim.round)
                        .font(.caption2.monospaced())
                        .foregroundStyle(.gray)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 2)
                        .background(
                            Capsule().fill(Color.white.opacity(0.06))
                        )
                }
                .padding(.vertical, 8)
                .padding(.horizontal, 12)
                .background(
                    RoundedRectangle(cornerRadius: 10)
                        .fill(prim.status == .confirmed
                              ? Color.green.opacity(0.05)
                              : prim.status == .pending
                                ? Color.yellow.opacity(0.04)
                                : Color.red.opacity(0.03))
                )
            }
        }
        .padding()
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(Color.white.opacity(0.03))
                .overlay(
                    RoundedRectangle(cornerRadius: 16)
                        .stroke(Color.white.opacity(0.08), lineWidth: 1)
                )
        )
    }

    private var exploitButton: some View {
        VStack(spacing: 8) {
            Button {
                appendLog("[*] Exploit chain no disponible — requiere kernel R/W primitiva")
            } label: {
                HStack(spacing: 10) {
                    Image(systemName: "bolt.fill")
                        .font(.title3)
                    Text("Ejecutar Cadena de Exploit")
                        .font(.headline)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 16)
                .background(
                    RoundedRectangle(cornerRadius: 14)
                        .fill(Color.red.opacity(0.15))
                        .overlay(
                            RoundedRectangle(cornerRadius: 14)
                                .stroke(Color.red.opacity(0.4), lineWidth: 1)
                        )
                )
                .foregroundStyle(.red.opacity(0.5))
            }
            .disabled(true)

            Text("Requiere kernel R/W primitiva — Round 30 en progreso")
                .font(.caption2)
                .foregroundStyle(.gray.opacity(0.5))
        }
    }

    private var logSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Image(systemName: "terminal.fill")
                    .foregroundStyle(.green)
                Text("Log")
                    .font(.headline)
                    .foregroundStyle(.white)
                Spacer()
                Button("Limpiar") {
                    log = ""
                }
                .font(.caption)
                .foregroundStyle(.green)
            }
            ScrollView {
                Text(log)
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(.green)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(height: 200)
        }
        .padding()
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(Color.black)
                .overlay(
                    RoundedRectangle(cornerRadius: 16)
                        .stroke(Color.green.opacity(0.3), lineWidth: 1)
                )
        )
    }

    private func appendLog(_ msg: String) {
        DispatchQueue.main.async {
            log += msg + "\n"
        }
    }
}

enum PrimitiveStatus {
    case confirmed, pending, notFound

    var icon: String {
        switch self {
        case .confirmed: return "checkmark.circle.fill"
        case .pending: return "clock.fill"
        case .notFound: return "xmark.circle.fill"
        }
    }

    var color: Color {
        switch self {
        case .confirmed: return .green
        case .pending: return .yellow
        case .notFound: return .red
        }
    }
}

#Preview {
    JailbreakView()
}
