import AppKit
import Foundation
import PDFKit
import SwiftUI
import UniformTypeIdentifiers

// MARK: - Models

struct InspectResponse: Decodable {
    let meta: FileMeta
    let kind: String
    let preview: PreviewData
    let safety: SafetyReport
}

struct FileMeta: Decodable {
    let name: String
    let path: String
    let extensionName: String
    let size: Int
    let sizeHuman: String
    let mime: String
    let magic: String
    let executable: Bool
    let sha256: String

    enum CodingKeys: String, CodingKey {
        case name, path, size, mime, magic, executable, sha256
        case extensionName = "extension"
        case sizeHuman = "size_human"
    }
}

struct PreviewData: Decodable {
    let content: String?
    let language: String?
    let lineCount: Int?
    let width: Int?
    let height: Int?
    let format: String?
    let version: String?
    let pageCount: Int?
    let title: String?
    let entryCount: Int?
    let totalUncompressedHuman: String?
    let compressionRatio: Double?
    let entries: [ArchiveEntry]?
    let codec: String?
    let durationSecs: Double?
    let sampleRate: Int?
    let channels: Int?
    let hexHead: String?

    enum CodingKeys: String, CodingKey {
        case content, language, width, height, format, version, title, entries, codec, channels
        case lineCount = "line_count"
        case pageCount = "page_count"
        case entryCount = "entry_count"
        case totalUncompressedHuman = "total_uncompressed_human"
        case compressionRatio = "compression_ratio"
        case durationSecs = "duration_secs"
        case sampleRate = "sample_rate"
        case hexHead = "hex_head"
    }
}

struct ArchiveEntry: Decodable, Identifiable {
    var id: String { name }
    let name: String
    let isDir: Bool
    let size: Int
    let flags: [String]

    enum CodingKeys: String, CodingKey {
        case name, size, flags
        case isDir = "is_dir"
    }
}

struct SafetyReport: Decodable {
    let verdict: String
    let score: Int
    let summary: String
    let rulesLoaded: Int?
    let findings: [SafetyFinding]

    enum CodingKeys: String, CodingKey {
        case verdict, score, summary, findings
        case rulesLoaded = "rules_loaded"
    }
}

struct SafetyFinding: Decodable, Identifiable {
    var id: String { code + title }
    let severity: String
    let code: String
    let title: String
    let detail: String
}

// MARK: - ViewModel

@MainActor
final class OmaPeekViewModel: ObservableObject {
    @Published var result: InspectResponse?
    @Published var errorMessage: String?
    @Published var showSafetyDetails = true
    @Published var confirmUnsafeOpen = false
    @Published var samples: [URL] = []

    let repoRoot: URL

    init() {
        let exeURL = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath()
        // If running inside OmaPeek.app/Contents/MacOS/OmaPeek, walk up to repo root
        let candidate = exeURL
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        if FileManager.default.fileExists(atPath: candidate.appendingPathComponent("bin/omapeek-inspect").path) {
            self.repoRoot = candidate
        } else {
            self.repoRoot = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        }
        loadSamples()

        if CommandLine.arguments.count > 1 {
            let argURL = URL(fileURLWithPath: CommandLine.arguments[1])
            inspect(url: argURL)
        } else if let first = samples.first {
            inspect(url: first)
        }
    }

    func loadSamples() {
        let samplesDir = repoRoot.appendingPathComponent("samples")
        if let items = try? FileManager.default.contentsOfDirectory(at: samplesDir, includingPropertiesForKeys: nil) {
            self.samples = items
                .filter { !$0.lastPathComponent.hasPrefix(".") }
                .sorted { $0.lastPathComponent < $1.lastPathComponent }
        }
    }

    func inspect(url: URL) {
        errorMessage = nil
        confirmUnsafeOpen = false
        let bin = repoRoot.appendingPathComponent("bin/omapeek-inspect").path
        let target = url.path

        Task.detached {
            let proc = Process()
            proc.executableURL = URL(fileURLWithPath: bin)
            proc.arguments = [target]
            let outPipe = Pipe()
            let errPipe = Pipe()
            proc.standardOutput = outPipe
            proc.standardError = errPipe

            do {
                try proc.run()
                proc.waitUntilExit()
                let data = outPipe.fileHandleForReading.readDataToEndOfFile()
                if proc.terminationStatus == 0 {
                    let decoded = try JSONDecoder().decode(InspectResponse.self, from: data)
                    await MainActor.run {
                        self.result = decoded
                        self.showSafetyDetails = !decoded.safety.findings.isEmpty
                    }
                } else {
                    let errStr = String(data: errPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? "Inspector failed"
                    await MainActor.run { self.errorMessage = errStr }
                }
            } catch {
                await MainActor.run { self.errorMessage = error.localizedDescription }
            }
        }
    }

    func runQuarantine(_ subcommand: String) {
        guard let path = result?.meta.path else { return }
        let script = repoRoot.appendingPathComponent("bin/omapeek-quarantine").path
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: script)
        proc.arguments = [subcommand, path]
        try? proc.run()
    }

    func openDefault() {
        guard let path = result?.meta.path else { return }
        NSWorkspace.shared.open(URL(fileURLWithPath: path))
    }

    func copyToClipboard(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}

// MARK: - Native PDFView Wrapper

struct NativePDFView: NSViewRepresentable {
    let url: URL

    func makeNSView(context: Context) -> PDFView {
        let view = PDFView()
        view.autoScales = true
        view.displayMode = .singlePageContinuous
        view.backgroundColor = .clear
        return view
    }

    func updateNSView(_ nsView: PDFView, context: Context) {
        nsView.document = PDFDocument(url: url)
    }
}

// MARK: - Views

struct ContentView: View {
    @StateObject private var vm = OmaPeekViewModel()
    @State private var isTargeted = false
    @State private var archiveFilter = ""
    @State private var showActionMenu = false

    var body: some View {
        NavigationSplitView {
            VStack(alignment: .leading, spacing: 10) {
                Text("SAMPLES")
                    .font(.caption.bold())
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 12)
                    .padding(.top, 8)

                List(vm.samples, id: \.self, selection: Binding(
                    get: { vm.result.map { URL(fileURLWithPath: $0.meta.path) } },
                    set: { if let u = $0 { vm.inspect(url: u) } }
                )) { url in
                    Text(url.lastPathComponent)
                        .font(.system(.callout, design: .monospaced))
                        .lineLimit(1)
                        .onTapGesture { vm.inspect(url: url) }
                }
                .listStyle(.sidebar)
            }
            .frame(minWidth: 210)
        } detail: {
            VStack(spacing: 0) {
                if let res = vm.result {
                    headerBar(res)
                    if vm.showSafetyDetails && !res.safety.findings.isEmpty {
                        safetyBanner(res.safety)
                    }
                    Divider()
                    previewBody(res)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                    Divider()
                    footerBar(res)
                } else if let err = vm.errorMessage {
                    Text(err).foregroundStyle(.red).padding()
                } else {
                    Text("Drop any file here to inspect")
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
            .background(Color(nsColor: .windowBackgroundColor))
            .overlay {
                if isTargeted {
                    RoundedRectangle(cornerRadius: 12)
                        .strokeBorder(Color.accentColor, style: StrokeStyle(lineWidth: 2, dash: [6]))
                        .padding(8)
                }
            }
            .onDrop(of: [.fileURL], isTargeted: $isTargeted) { providers in
                guard let provider = providers.first else { return false }
                _ = provider.loadObject(ofClass: URL.self) { url, _ in
                    if let url {
                        Task { @MainActor in vm.inspect(url: url) }
                    }
                }
                return true
            }
        }
        .frame(minWidth: 880, minHeight: 580)
    }

    @ViewBuilder
    private func headerBar(_ res: InspectResponse) -> some View {
        HStack(spacing: 12) {
            Text(res.meta.name)
                .font(.headline)
                .lineLimit(1)
            Spacer()
            Text("\(res.meta.sizeHuman) · \(res.kind.uppercased()) · \(res.meta.magic)")
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.secondary)
            Button {
                vm.showSafetyDetails.toggle()
            } label: {
                Text("\(res.safety.verdict.uppercased()) (\(res.safety.score)/100)")
                    .font(.caption.bold())
                    .padding(.horizontal, 10)
                    .padding(.vertical, 4)
                    .background(verdictColor(res.safety.verdict).opacity(0.18))
                    .foregroundStyle(verdictColor(res.safety.verdict))
                    .clipShape(Capsule())
            }
            .buttonStyle(.plain)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .background(Color(nsColor: .controlBackgroundColor))
    }

    @ViewBuilder
    private func safetyBanner(_ safety: SafetyReport) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(safety.summary)
                .font(.caption.bold())
            ForEach(safety.findings) { f in
                HStack(alignment: .top, spacing: 8) {
                    Text(f.severity.uppercased())
                        .font(.system(size: 10, weight: .bold, design: .monospaced))
                        .padding(.horizontal, 5)
                        .padding(.vertical, 2)
                        .background(verdictColor(f.severity == "high" ? "danger" : f.severity == "medium" ? "caution" : "safe").opacity(0.2))
                        .cornerRadius(4)
                    Text("\(f.title) — \(f.detail)")
                        .font(.caption)
                        .foregroundStyle(.primary)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
        .background(Color.red.opacity(0.06))
    }

    @ViewBuilder
    private func previewBody(_ res: InspectResponse) -> some View {
        switch res.kind {
        case "image":
            if let nsImg = NSImage(contentsOfFile: res.meta.path) {
                Image(nsImage: nsImg)
                    .resizable()
                    .scaledToFit()
                    .padding(20)
            } else {
                Text("Unable to decode image").foregroundStyle(.secondary)
            }
        case "code", "markdown":
            ScrollView {
                let lines = (res.preview.content ?? "").components(separatedBy: "\n")
                LazyVStack(alignment: .leading, spacing: 2) {
                    ForEach(Array(lines.enumerated()), id: \.offset) { idx, line in
                        HStack(alignment: .top, spacing: 12) {
                            Text("\(idx + 1)")
                                .font(.system(size: 11.5, design: .monospaced))
                                .foregroundStyle(.secondary.opacity(0.6))
                                .frame(width: 38, alignment: .trailing)
                            Text(line.isEmpty ? " " : line)
                                .font(.system(size: 12.5, design: .monospaced))
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                }
                .padding(16)
            }
        case "archive":
            VStack(spacing: 0) {
                HStack(spacing: 8) {
                    Image(systemName: "magnifyingglass")
                        .foregroundStyle(.secondary)
                    TextField("Filter archive entries…", text: $archiveFilter)
                        .textFieldStyle(.plain)
                        .font(.system(.callout, design: .monospaced))
                    if !archiveFilter.isEmpty {
                        Button("Clear") { archiveFilter = "" }
                            .buttonStyle(.plain)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(.horizontal, 14)
                .padding(.vertical, 8)
                .background(Color(nsColor: .controlBackgroundColor))
                Divider()
                let filtered = (res.preview.entries ?? []).filter {
                    archiveFilter.isEmpty || $0.name.localizedCaseInsensitiveContains(archiveFilter)
                }
                List(filtered) { entry in
                    HStack {
                        Text((entry.isDir ? "📁 " : "📄 ") + entry.name)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(entry.flags.isEmpty ? Color.primary : Color.red)
                        Spacer()
                        if !entry.flags.isEmpty {
                            Text(entry.flags.joined(separator: ", ").uppercased())
                                .font(.caption2.bold())
                                .foregroundStyle(.red)
                        }
                        Text("\(entry.size) B")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
            }
        case "pdf":
            NativePDFView(url: URL(fileURLWithPath: res.meta.path))
        case "audio", "video":
            VStack(spacing: 10) {
                Text(res.kind == "video" ? "🎬 Video Media" : "🎵 Audio Media")
                    .font(.title3.bold())
                Text([
                    res.preview.codec,
                    res.preview.durationSecs.map { String(format: "%.2fs", $0) },
                    res.preview.sampleRate.map { "\($0) Hz" },
                    res.preview.channels.map { "\($0) ch" },
                ].compactMap { $0 }.joined(separator: " · "))
                    .font(.system(.callout, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
        default:
            Text(res.preview.hexHead ?? "Binary file")
                .font(.system(.caption, design: .monospaced))
                .padding()
        }
    }

    @ViewBuilder
    private func footerBar(_ res: InspectResponse) -> some View {
        HStack(spacing: 10) {
            Button("Copy Path (C)") { vm.copyToClipboard(res.meta.path) }
                .keyboardShortcut("c", modifiers: [])
            Button("SHA-256: \(res.meta.sha256.prefix(10))… (H)") { vm.copyToClipboard(res.meta.sha256) }
                .keyboardShortcut("h", modifiers: [])
            Button("Safety (S)") { vm.showSafetyDetails.toggle() }
                .keyboardShortcut("s", modifiers: [])
                .opacity(0)
                .frame(width: 0)
            Spacer()
            if res.safety.verdict != "safe" {
                Button("🛡 Sandbox Open") { vm.runQuarantine("open") }
                Button("🔒 Quarantine") { vm.runQuarantine("vault") }
            }
            if res.safety.verdict == "danger" {
                Button(vm.confirmUnsafeOpen ? "Click Again to Confirm" : "⚠ Open Anyway (Unsafe)") {
                    if vm.confirmUnsafeOpen {
                        vm.confirmUnsafeOpen = false
                        vm.openDefault()
                    } else {
                        vm.confirmUnsafeOpen = true
                    }
                }
                .foregroundStyle(.red)
            } else {
                Button("Open Default") { vm.openDefault() }
            }

            Button("⌘K Actions") { showActionMenu.toggle() }
                .keyboardShortcut("k", modifiers: .command)
                .popover(isPresented: $showActionMenu) {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Actions").font(.caption.bold()).foregroundStyle(.secondary)
                        Divider()
                        Button("Copy Path (C)") { vm.copyToClipboard(res.meta.path); showActionMenu = false }
                        Button("Copy SHA-256 (H)") { vm.copyToClipboard(res.meta.sha256); showActionMenu = false }
                        Button("Reveal in Finder") {
                            NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: res.meta.path)])
                            showActionMenu = false
                        }
                        if res.safety.verdict != "safe" {
                            Divider()
                            Button("🛡 Sandbox Open") { vm.runQuarantine("open"); showActionMenu = false }
                            Button("🔒 Move to Quarantine") { vm.runQuarantine("vault"); showActionMenu = false }
                        }
                    }
                    .buttonStyle(.plain)
                    .padding(12)
                    .frame(minWidth: 200)
                }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .background(Color(nsColor: .controlBackgroundColor))
    }

    private func verdictColor(_ verdict: String) -> Color {
        switch verdict {
        case "danger": return .red
        case "caution": return .orange
        default: return .green
        }
    }
}

@main
struct OmaPeekMacApp: App {
    var body: some Scene {
        WindowGroup("OmaPeek") {
            ContentView()
        }
    }
}
