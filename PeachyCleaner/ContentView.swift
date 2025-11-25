import SwiftUI
import Combine
import AppKit
import CryptoKit
import LocalAuthentication

import GoogleSignIn
import GoogleSignInSwift

// MARK: - Theme

enum PeachyTheme {
    static let bg = Color.black
    static let bgPanel = Color(red: 0.12, green: 0.12, blue: 0.13)
    static let bgPanel2 = Color(red: 0.16, green: 0.16, blue: 0.17)

    static let stroke = Color.white.opacity(0.12)
    static let strokeStrong = Color.white.opacity(0.22)

    static let textPrimary = Color.white
    static let textSecondary = Color.white.opacity(0.65)

    static let accentGreen = Color(red: 0.35, green: 0.85, blue: 0.55)
    static let accentBlue = Color(red: 0.45, green: 0.75, blue: 1.0)
    static let accentRed = Color(red: 0.95, green: 0.45, blue: 0.45)
}

// MARK: - Models

enum PeachyScanMode: String, CaseIterable, Identifiable {
    case basic = "Basic (Surface)"
    case full = "Full (Deep, Safe)"

    var id: String { rawValue }

    var description: String {
        switch self {
        case .basic:
            return "Quick scan of common folders like Downloads, Desktop, Movies, Pictures and user caches."
        case .full:
            return "Deeper scan including Application Support and Logs. Still avoids critical system files."
        }
    }
}

enum PeachySection: String, CaseIterable, Identifiable {
    case dashboard = "Dashboard"
    case largeFiles = "Large Files"
    case duplicates = "Duplicates"
    case settings = "Settings"
    case account = "Account"

    var id: String { rawValue }
}

struct PeachyFolderResult: Identifiable, Equatable {
    let id = UUID()
    let name: String
    let url: URL
    let sizeBytes: Int64
}

enum PeachyRiskGrade: String {
    case safe = "Safe to delete"
    case review = "Review first"
    case leaveAlone = "Leave alone"

    var color: Color {
        switch self {
        case .safe: return .green
        case .review: return .yellow
        case .leaveAlone: return .red
        }
    }

    var symbol: String {
        switch self {
        case .safe: return "checkmark.circle.fill"
        case .review: return "exclamationmark.triangle.fill"
        case .leaveAlone: return "xmark.octagon.fill"
        }
    }
}

struct PeachySafetyResult {
    let grade: PeachyRiskGrade
    let reason: String
}

struct PeachySafetyAnalyzer {
    static func analyze(url: URL, isDirectory: Bool) -> PeachySafetyResult {
        let path = url.path.lowercased()
        let ext = url.pathExtension.lowercased()
        let home = FileManager.default.homeDirectoryForCurrentUser.path.lowercased()

        let redPrefixes = [
            "/system/",
            "/library/",
            "/applications/",
            "/usr/",
            "/bin/",
            "/sbin/",
            "/private/var/"
        ]
        if redPrefixes.contains(where: { path.hasPrefix($0) }) && !path.hasPrefix(home) {
            return PeachySafetyResult(
                grade: .leaveAlone,
                reason: "Protected system area. Deleting could break macOS or apps."
            )
        }

        if path.contains(".app/") || ext == "app" {
            return PeachySafetyResult(
                grade: .leaveAlone,
                reason: "Application bundle. Removing it can break the app."
            )
        }

        let safeContains = [
            "/library/caches/",
            "/library/logs/",
            "/tmp/",
            "/temporaryitems/",
            "/application support/crashreporter/"
        ]
        if safeContains.contains(where: { path.contains($0) }) {
            return PeachySafetyResult(
                grade: .safe,
                reason: "Cache/log/temp data. Regeneratable and safe to remove."
            )
        }

        let safeExtensions = ["dmg", "zip", "rar", "7z", "pkg", "iso"]
        if safeExtensions.contains(ext) && path.contains("/downloads/") {
            return PeachySafetyResult(
                grade: .safe,
                reason: "Installer/archive in Downloads. Safe if you’re done with it."
            )
        }

        let reviewExtensions = ["mov", "mp4", "m4v", "mp3", "wav", "psd", "blend", "aep"]
        if reviewExtensions.contains(ext) {
            return PeachySafetyResult(
                grade: .review,
                reason: "Large media / project file. Keep unless you’re sure."
            )
        }

        let reviewContains = [
            "/library/application support/",
            "/library/preferences/",
            "/library/containers/"
        ]
        if reviewContains.contains(where: { path.contains($0) }) {
            return PeachySafetyResult(
                grade: .review,
                reason: "App data / preferences. Deleting may reset apps or remove content."
            )
        }

        if isDirectory {
            return PeachySafetyResult(
                grade: .review,
                reason: "Folder contents vary. Review before deleting."
            )
        }

        return PeachySafetyResult(
            grade: .safe,
            reason: "User-space file not in protected area. Safe if unwanted."
        )
    }
}

struct PeachyItem: Identifiable, Equatable {
    let id = UUID()
    let url: URL
    let sizeBytes: Int64
    let isDirectory: Bool
    let risk: PeachyRiskGrade
    let riskReason: String
}

struct PeachyDuplicateGroup: Identifiable {
    let id = UUID()
    let sizeBytes: Int64
    let items: [URL]
}

// MARK: - Delete-all audit log

struct PeachyDeleteAllLog: Identifiable, Codable {
    let id: UUID
    let date: Date
    let itemCount: Int
    let totalBytes: Int64
    let authMethod: String
}

final class PeachyAuditLogStore: ObservableObject {
    @Published private(set) var logs: [PeachyDeleteAllLog] = []
    private let key = "peachy.deleteAll.logs"

    init() { load() }

    func add(authMethod: String, items: [PeachyItem]) {
        let total = items.reduce(Int64(0)) { $0 + $1.sizeBytes }
        let entry = PeachyDeleteAllLog(
            id: UUID(),
            date: Date(),
            itemCount: items.count,
            totalBytes: total,
            authMethod: authMethod
        )
        logs.insert(entry, at: 0)
        save()
    }

    private func save() {
        if let data = try? JSONEncoder().encode(logs) {
            UserDefaults.standard.set(data, forKey: key)
        }
    }

    private func load() {
        guard let data = UserDefaults.standard.data(forKey: key),
              let decoded = try? JSONDecoder().decode([PeachyDeleteAllLog].self, from: data)
        else { return }
        logs = decoded
    }
}

// MARK: - Scanner

final class PeachyScanner: ObservableObject {
    @Published var isScanning = false
    @Published var scanProgress: Double = 0
    @Published var scanResults: [PeachyFolderResult] = []
    @Published var largeItems: [PeachyItem] = []
    @Published var duplicateGroups: [PeachyDuplicateGroup] = []
    @Published var statusMessage: String = "Ready."
    @Published var lastScanDate: Date? = nil
    @Published var lastDuplicateScanDate: Date? = nil
    @Published var errorMessage: String? = nil

    @Published var selectedFolder: PeachyFolderResult? = nil
    @Published var folderBreakdown: [PeachyItem] = []

    private let fm = FileManager.default

    func targetFolders(for mode: PeachyScanMode) -> [(String, URL)] {
        let home = fm.homeDirectoryForCurrentUser
        var folders: [(String, URL)] = [
            ("Downloads", home.appendingPathComponent("Downloads")),
            ("Desktop", home.appendingPathComponent("Desktop")),
            ("Movies", home.appendingPathComponent("Movies")),
            ("Pictures", home.appendingPathComponent("Pictures")),
            ("User Caches", home.appendingPathComponent("Library/Caches"))
        ]
        if mode == .full {
            folders += [
                ("Application Support", home.appendingPathComponent("Library/Application Support")),
                ("Logs", home.appendingPathComponent("Library/Logs"))
            ]
        }
        return folders
    }

    func scan(mode: PeachyScanMode) {
        guard !isScanning else { return }
        isScanning = true
        scanProgress = 0
        statusMessage = "Scanning..."
        scanResults = []
        largeItems = []
        duplicateGroups = []
        errorMessage = nil
        selectedFolder = nil
        folderBreakdown = []

        let folders = targetFolders(for: mode)
        let folderCount = Double(max(folders.count, 1))

        Task.detached(priority: .userInitiated) { [weak self] in
            guard let self else { return }

            var folderResults: [PeachyFolderResult] = []
            var allItems: [(URL, Int64, Bool)] = []
            var completed = 0.0

            for (name, folderURL) in folders {
                let (size, items) = self.folderSizeAndItems(folderURL)
                folderResults.append(PeachyFolderResult(name: name, url: folderURL, sizeBytes: size))
                allItems.append(contentsOf: items)

                completed += 1
                await MainActor.run { self.scanProgress = completed / folderCount }
            }

            allItems.sort { $0.1 > $1.1 }
            let top = allItems.prefix(20).map {
                let analysis = PeachySafetyAnalyzer.analyze(url: $0.0, isDirectory: $0.2)
                return PeachyItem(
                    url: $0.0,
                    sizeBytes: $0.1,
                    isDirectory: $0.2,
                    risk: analysis.grade,
                    riskReason: analysis.reason
                )
            }

            await MainActor.run {
                self.scanResults = folderResults
                self.largeItems = Array(top)
                self.isScanning = false
                self.lastScanDate = Date()
                self.statusMessage = "Scan complete."
                self.scanProgress = 1
            }
        }
    }

    private func folderSizeAndItems(_ folderURL: URL) -> (Int64, [(URL, Int64, Bool)]) {
        var total: Int64 = 0
        var items: [(URL, Int64, Bool)] = []

        guard let enumerator = fm.enumerator(
            at: folderURL,
            includingPropertiesForKeys: [.isRegularFileKey, .fileSizeKey, .isDirectoryKey],
            options: [.skipsHiddenFiles, .skipsPackageDescendants]
        ) else { return (0, []) }

        for case let fileURL as URL in enumerator {
            do {
                let values = try fileURL.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey, .isDirectoryKey])
                let isDir = values.isDirectory ?? false
                if values.isRegularFile == true || isDir {
                    let size = isDir ? recursiveFolderSize(fileURL) : Int64(values.fileSize ?? 0)
                    total += size
                    items.append((fileURL, size, isDir))
                }
            } catch { continue }
        }
        return (total, items)
    }

    func loadFolderBreakdown(_ folder: PeachyFolderResult) {
        selectedFolder = folder
        folderBreakdown = []
        statusMessage = "Calculating \(folder.name)…"
        isScanning = true
        scanProgress = 0

        Task.detached(priority: .userInitiated) { [weak self] in
            guard let self else { return }

            do {
                let children = try self.fm.contentsOfDirectory(
                    at: folder.url,
                    includingPropertiesForKeys: [.isDirectoryKey, .isRegularFileKey, .fileSizeKey],
                    options: [.skipsHiddenFiles]
                )

                let totalChildren = Double(max(children.count, 1))
                var completed = 0.0
                var breakdown: [PeachyItem] = []

                for child in children {
                    let isDir = (try? child.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) ?? false
                    let size: Int64

                    if isDir {
                        size = self.recursiveFolderSize(child)
                    } else {
                        let fileSize = (try? child.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
                        size = Int64(fileSize)
                    }

                    let analysis = PeachySafetyAnalyzer.analyze(url: child, isDirectory: isDir)
                    breakdown.append(
                        PeachyItem(
                            url: child,
                            sizeBytes: size,
                            isDirectory: isDir,
                            risk: analysis.grade,
                            riskReason: analysis.reason
                        )
                    )

                    completed += 1
                    await MainActor.run { self.scanProgress = completed / totalChildren }
                }

                breakdown.sort { $0.sizeBytes > $1.sizeBytes }

                await MainActor.run {
                    self.folderBreakdown = breakdown
                    self.statusMessage = "Showing contents of \(folder.name)."
                    self.isScanning = false
                    self.scanProgress = 1
                    self.lastScanDate = self.lastScanDate ?? Date()
                }

            } catch {
                await MainActor.run {
                    self.errorMessage = error.localizedDescription
                    self.statusMessage = "Couldn’t read folder."
                    self.isScanning = false
                }
            }
        }
    }

    private func recursiveFolderSize(_ folderURL: URL) -> Int64 {
        var total: Int64 = 0
        guard let enumerator = fm.enumerator(
            at: folderURL,
            includingPropertiesForKeys: [.isRegularFileKey, .fileSizeKey],
            options: [.skipsHiddenFiles, .skipsPackageDescendants]
        ) else { return 0 }

        for case let fileURL as URL in enumerator {
            do {
                let values = try fileURL.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
                if values.isRegularFile == true {
                    total += Int64(values.fileSize ?? 0)
                }
            } catch { continue }
        }
        return total
    }

    func deletePermanently(_ url: URL) {
        statusMessage = "Deleting..."
        errorMessage = nil

        Task.detached(priority: .userInitiated) { [weak self] in
            guard let self else { return }
            do {
                try self.fm.removeItem(at: url)
                await MainActor.run {
                    self.largeItems.removeAll { $0.url == url }
                    self.folderBreakdown.removeAll { $0.url == url }
                    self.statusMessage = "Deleted permanently."
                }
            } catch {
                await MainActor.run {
                    self.errorMessage = error.localizedDescription
                    self.statusMessage = "Delete failed."
                }
            }
        }
    }

    func cleanUserCaches() {
        let cachesURL = fm.homeDirectoryForCurrentUser.appendingPathComponent("Library/Caches")
        statusMessage = "Cleaning caches..."
        errorMessage = nil

        Task.detached(priority: .userInitiated) { [weak self] in
            guard let self else { return }
            do {
                let contents = try self.fm.contentsOfDirectory(at: cachesURL, includingPropertiesForKeys: nil)
                for item in contents { try? self.fm.removeItem(at: item) }
                await MainActor.run { self.statusMessage = "User caches cleaned." }
            } catch {
                await MainActor.run {
                    self.errorMessage = error.localizedDescription
                    self.statusMessage = "Cleaning failed."
                }
            }
        }
    }

    func scanDuplicates(mode: PeachyScanMode) {
        guard !isScanning else { return }
        isScanning = true
        statusMessage = "Scanning duplicates..."
        duplicateGroups = []
        errorMessage = nil
        scanProgress = 0

        let folders = targetFolders(for: mode)
        let folderCount = Double(max(folders.count, 1))

        Task.detached(priority: .userInitiated) { [weak self] in
            guard let self else { return }
            var completed = 0.0
            var filesBySize: [Int64: [URL]] = [:]

            for (_, folderURL) in folders {
                guard let enumerator = self.fm.enumerator(
                    at: folderURL,
                    includingPropertiesForKeys: [.isRegularFileKey, .fileSizeKey],
                    options: [.skipsHiddenFiles, .skipsPackageDescendants]
                ) else { continue }

                for case let fileURL as URL in enumerator {
                    do {
                        let values = try fileURL.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
                        if values.isRegularFile == true {
                            let size = Int64(values.fileSize ?? 0)
                            if size > 0 { filesBySize[size, default: []].append(fileURL) }
                        }
                    } catch { continue }
                }

                completed += 1
                await MainActor.run { self.scanProgress = completed / folderCount }
            }

            var groups: [PeachyDuplicateGroup] = []
            for (size, urls) in filesBySize where urls.count > 1 {
                var hashMap: [String: [URL]] = [:]
                for url in urls {
                    if let h = self.sha256(for: url) {
                        hashMap[h, default: []].append(url)
                    }
                }
                for (_, items) in hashMap where items.count > 1 {
                    groups.append(PeachyDuplicateGroup(sizeBytes: size, items: items))
                }
            }

            groups.sort { $0.sizeBytes > $1.sizeBytes }

            await MainActor.run {
                self.duplicateGroups = groups
                self.isScanning = false
                self.lastDuplicateScanDate = Date()
                self.statusMessage = "Duplicate scan complete."
                self.scanProgress = 1
            }
        }
    }

    private func sha256(for url: URL) -> String? {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? handle.close() }

        var hasher = SHA256()
        while autoreleasepool(invoking: {
            let data = handle.readData(ofLength: 1024 * 1024)
            if data.isEmpty { return false }
            hasher.update(data: data)
            return true
        }) {}

        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    func openFullDiskAccessSettings() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles") {
            NSWorkspace.shared.open(url)
        }
    }
}

// MARK: - Helpers

extension Int64 {
    func peachyBytes() -> String {
        let f = ByteCountFormatter()
        f.countStyle = .file
        return f.string(fromByteCount: self)
    }
}

// MARK: - Smart summary (local AI placeholder)

struct PeachySmartSummary {
    static func summarize(items: [PeachyItem]) -> String {
        guard !items.isEmpty else { return "No safe files selected." }

        let totalBytes = items.reduce(Int64(0)) { $0 + $1.sizeBytes }
        var folderMap: [String: Int64] = [:]
        var extMap: [String: Int64] = [:]

        for i in items {
            let comps = i.url.pathComponents
            let bucket = comps.first(where: { ["Downloads","Desktop","Movies","Pictures","Library"].contains($0) }) ?? "Other"
            folderMap[bucket, default: 0] += i.sizeBytes

            let ext = i.url.pathExtension.lowercased()
            let extKey = ext.isEmpty ? "no-extension" : ext
            extMap[extKey, default: 0] += i.sizeBytes
        }

        let topFolders = folderMap.sorted { $0.value > $1.value }.prefix(3)
        let topExts = extMap.sorted { $0.value > $1.value }.prefix(4)

        var lines: [String] = []
        lines.append("Smart Summary of Safe Deletions")
        lines.append("• Total safe size: \(totalBytes.peachyBytes()) across \(items.count) items.")

        if !topFolders.isEmpty {
            lines.append("• Biggest locations:")
            for (f, b) in topFolders { lines.append("  – \(f): \(b.peachyBytes())") }
        }

        if !topExts.isEmpty {
            lines.append("• Main file types:")
            for (e, b) in topExts { lines.append("  – .\(e): \(b.peachyBytes())") }
        }

        lines.append("This is a local summary. Later we can swap in real AI.")
        return lines.joined(separator: "\n")
    }
}

// MARK: - Disk & Volumes

struct PeachyDiskInfo {
    let total: Int64
    let free: Int64
    let used: Int64
    let purgeable: Int64
    var usedPercent: Double {
        guard total > 0 else { return 0 }
        return Double(used) / Double(total)
    }
}

struct PeachyVolume: Identifiable, Equatable {
    let id = UUID()
    let name: String
    let url: URL
}

final class PeachyDiskProvider: ObservableObject {
    @Published var info = PeachyDiskInfo(total: 0, free: 0, used: 0, purgeable: 0)
    @Published var volumes: [PeachyVolume] = []
    @Published var selectedVolume: PeachyVolume?

    func refresh() {
        let fm = FileManager.default
        let keys: [URLResourceKey] = [.volumeNameKey, .isVolumeKey]
        var newVolumes: [PeachyVolume] = []

        if let urls = fm.mountedVolumeURLs(includingResourceValuesForKeys: keys, options: [.skipHiddenVolumes]) {
            for url in urls {
                if let values = try? url.resourceValues(forKeys: Set(keys)),
                   values.isVolume == true {
                    let name = values.volumeName ?? url.lastPathComponent
                    newVolumes.append(PeachyVolume(name: name, url: url))
                }
            }
        }

        newVolumes.sort { $0.name < $1.name }
        volumes = newVolumes

        if selectedVolume == nil {
            // Pick Macintosh HD or first volume by default
            if let macHD = volumes.first(where: { $0.name.contains("Macintosh") }) {
                selectedVolume = macHD
            } else {
                selectedVolume = volumes.first
            }
        }

        if let selected = selectedVolume {
            updateInfo(for: selected)
        }
    }

    func select(_ volume: PeachyVolume) {
        selectedVolume = volume
        updateInfo(for: volume)
    }

    private func updateInfo(for volume: PeachyVolume) {
        do {
            let values = try volume.url.resourceValues(forKeys: [
                .volumeTotalCapacityKey,
                .volumeAvailableCapacityKey,
                .volumeAvailableCapacityForImportantUsageKey
            ])
            let total = Int64(values.volumeTotalCapacity ?? 0)
            let free = Int64(values.volumeAvailableCapacity ?? 0)
            let importantFree = Int64(values.volumeAvailableCapacityForImportantUsage ?? 0)
            let purgeable = max(0, importantFree - free)
            let used = max(0, total - free)
            info = PeachyDiskInfo(total: total, free: free, used: used, purgeable: purgeable)
        } catch {
            info = PeachyDiskInfo(total: 0, free: 0, used: 0, purgeable: 0)
        }
    }
}

struct PeachyDiskCard: View {
    let info: PeachyDiskInfo
    let name: String

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 12) {
                RoundedRectangle(cornerRadius: 8)
                    .fill(PeachyTheme.bgPanel2)
                    .frame(width: 52, height: 52)
                    .overlay(Image(systemName: "internaldrive.fill")
                        .font(.system(size: 26)).foregroundStyle(.white))

                VStack(alignment: .leading, spacing: 4) {
                    Text(name).font(.title2).bold()
                        .foregroundStyle(PeachyTheme.textPrimary)
                    Text("Location: \(name == "Macintosh HD" ? "/" : "")")
                        .font(.caption)
                        .foregroundStyle(PeachyTheme.textSecondary)
                    Text("Available: \(info.free.peachyBytes())")
                        .font(.caption).foregroundStyle(PeachyTheme.textPrimary)
                    Text("Purgeable: \(info.purgeable.peachyBytes())")
                        .font(.caption).foregroundStyle(PeachyTheme.textSecondary)
                }

                Spacer()

                Text("\(Int(info.usedPercent * 100))% full")
                    .font(.caption)
                    .foregroundStyle(PeachyTheme.textSecondary)
            }

            ProgressView(value: info.usedPercent)
                .progressViewStyle(.linear)
                .tint(PeachyTheme.accentGreen)

            HStack {
                Text("\(info.used.peachyBytes()) used")
                Spacer()
                Text("\(info.total.peachyBytes()) total")
            }
            .font(.caption2)
            .foregroundStyle(PeachyTheme.textSecondary)
        }
        .padding(18)
        .background(RoundedRectangle(cornerRadius: 14).fill(PeachyTheme.bgPanel))
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(PeachyTheme.stroke))
        .frame(width: 520)
        .shadow(radius: 8)
    }
}

// MARK: - Sidebar & risk badge

struct PeachyFileIcon: View {
    let url: URL
    var body: some View {
        let icon = NSWorkspace.shared.icon(forFile: url.path)
        Image(nsImage: icon).resizable().scaledToFit()
    }
}

struct PeachySidebarRow: View {
    let url: URL
    let size: Int64
    let isSelected: Bool

    var body: some View {
        HStack(spacing: 10) {
            PeachyFileIcon(url: url).frame(width: 24, height: 24)

            Text(url.lastPathComponent)
                .lineLimit(1)
                .truncationMode(.middle)
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(PeachyTheme.textPrimary)

            Spacer()

            Text(size.peachyBytes())
                .font(.system(size: 11))
                .foregroundStyle(PeachyTheme.textSecondary)
        }
        .padding(.vertical, 7)
        .padding(.horizontal, 8)
        .background(isSelected ? PeachyTheme.bgPanel2 : PeachyTheme.bgPanel)
        .cornerRadius(10)
        .overlay(RoundedRectangle(cornerRadius: 10)
            .stroke(isSelected ? PeachyTheme.strokeStrong : PeachyTheme.stroke))
    }
}

struct PeachyRiskBadge: View {
    let risk: PeachyRiskGrade
    let reason: String
    @State private var showReason = false

    var body: some View {
        Button { showReason.toggle() } label: {
            Image(systemName: risk.symbol)
                .foregroundStyle(risk.color)
                .font(.system(size: 14))
        }
        .buttonStyle(.plain)
        .popover(isPresented: $showReason) {
            VStack(alignment: .leading, spacing: 8) {
                Text(risk.rawValue).font(.headline)
                Text(reason).font(.callout).foregroundStyle(.secondary)
            }
            .padding(12)
            .frame(width: 280)
        }
    }
}

// MARK: - Delete-all sheet

struct PeachyDeleteAllSheet: View {
    let items: [PeachyItem]
    @Binding var selectedIDs: Set<UUID>
    let summaryText: String
    @Binding var isAuthInProgress: Bool
    @Binding var isPreparing: Bool
    let onCancel: () -> Void
    let onConfirm: () -> Void

    var totalSelectedBytes: Int64 {
        items.filter { selectedIDs.contains($0.id) }.reduce(0) { $0 + $1.sizeBytes }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Delete All Safe Files")
                .font(.title2).bold()
                .foregroundStyle(PeachyTheme.textPrimary)

            GroupBox("Smart Summary") {
                if isPreparing {
                    Text("Preparing safe files…")
                        .font(.callout)
                        .foregroundStyle(PeachyTheme.textSecondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.vertical, 4)
                } else {
                    Text(summaryText)
                        .font(.callout)
                        .foregroundStyle(PeachyTheme.textPrimary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.vertical, 4)
                }
            }
            .background(PeachyTheme.bgPanel)
            .cornerRadius(8)

            if isPreparing {
                VStack(spacing: 10) {
                    ProgressView()
                        .progressViewStyle(.circular)
                    Text("Loading safe file list…")
                        .foregroundStyle(PeachyTheme.textSecondary)
                        .font(.callout)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                Text("Safe items are pre-selected. Uncheck anything you want to keep.")
                    .font(.callout)
                    .foregroundStyle(PeachyTheme.textSecondary)

                List(items) { item in
                    HStack {
                        Toggle(isOn: Binding(
                            get: { selectedIDs.contains(item.id) },
                            set: { isOn in
                                if isOn { selectedIDs.insert(item.id) }
                                else { selectedIDs.remove(item.id) }
                            }
                        )) {
                            HStack {
                                PeachyFileIcon(url: item.url).frame(width: 18, height: 18)
                                Text(item.url.lastPathComponent)
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                                    .foregroundStyle(PeachyTheme.textPrimary)
                            }
                        }
                        .toggleStyle(.checkbox)

                        Spacer()

                        PeachyRiskBadge(risk: item.risk, reason: item.riskReason)

                        Text(item.sizeBytes.peachyBytes())
                            .monospacedDigit()
                            .foregroundStyle(PeachyTheme.textSecondary)
                    }
                    .padding(.vertical, 2)
                }
                .scrollContentBackground(.hidden)
                .background(PeachyTheme.bgPanel)
                .cornerRadius(10)

                HStack {
                    Text("Selected: \(totalSelectedBytes.peachyBytes())")
                        .font(.headline)
                        .foregroundStyle(PeachyTheme.textPrimary)

                    Spacer()

                    Button("Cancel", role: .cancel) { onCancel() }

                    Button(isAuthInProgress ? "Authenticating..." : "Authenticate & Delete Permanently") {
                        onConfirm()
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(PeachyTheme.accentRed)
                    .disabled(selectedIDs.isEmpty || isAuthInProgress)
                }
            }
        }
        .padding(16)
        .frame(width: 760, height: 560)
        .background(PeachyTheme.bg)
    }
}

// MARK: - Auth mode

enum PeachyAuthMode: String {
    case google
    case simple
    case emailPassword
}

// MARK: - Onboarding

struct PeachyOnboardingView: View {
    @Binding var isSignedIn: Bool
    @Binding var preferredName: String
    @Binding var userEmail: String
    @Binding var authProvider: String
    @Binding var scanModeRaw: String
    @Binding var authModeRaw: String

    @State private var donateAlert = false
    @State private var authError: String? = nil
    @State private var googleLoading = false

    // Email/password local simulation
    @State private var emailAddr = ""
    @State private var emailPassword = ""
    @State private var emailPasswordConfirm = ""
    @State private var generatedCode: String? = nil
    @State private var enteredCode: String = ""
    @State private var emailVerified = false
    @State private var showCodeAlert = false

    private let googleClientID = "207461181526-9k155cesoseiot03j9p3ab1qhsaailjg.apps.googleusercontent.com"

    private var scanMode: PeachyScanMode {
        PeachyScanMode(rawValue: scanModeRaw) ?? .basic
    }

    private var authMode: PeachyAuthMode? {
        PeachyAuthMode(rawValue: authModeRaw)
    }

    var body: some View {
        ZStack {
            PeachyTheme.bg.ignoresSafeArea()

            VStack(alignment: .leading, spacing: 18) {
                Spacer()

                HStack(spacing: 16) {
                    Image("Image")
                        .resizable()
                        .scaledToFit()
                        .frame(width: 110, height: 110)
                        .shadow(radius: 8)

                    VStack(alignment: .leading, spacing: 8) {
                        Text("Welcome to PeachyCleaner!")
                            .font(.system(size: 28, weight: .bold))
                            .foregroundStyle(PeachyTheme.textPrimary)
                        Text("A friendly Mac cleaner built by a single dev.")
                            .font(.callout)
                            .foregroundStyle(PeachyTheme.textSecondary)
                    }
                }

                // Name
                VStack(alignment: .leading, spacing: 6) {
                    Text("What is a good name we should call you?")
                        .font(.headline)
                        .foregroundStyle(PeachyTheme.textPrimary)
                    TextField("Name", text: $preferredName)
                        .textFieldStyle(.roundedBorder)
                        .frame(maxWidth: 320)
                }

                // Donate
                VStack(alignment: .leading, spacing: 6) {
                    Text("Support the project (optional)")
                        .font(.headline)
                        .foregroundStyle(PeachyTheme.textPrimary)
                    Text("I’m a single dev working hard to bring you a good experience. Donations will be added in a future version.")
                        .font(.callout)
                        .foregroundStyle(PeachyTheme.textSecondary)
                    Button("I’d like to donate") { donateAlert = true }
                        .buttonStyle(.bordered)
                        .tint(PeachyTheme.accentGreen)
                }

                Divider().padding(.vertical, 4)

                // Account options
                VStack(alignment: .leading, spacing: 8) {
                    Text("How would you like to set up your PeachyCleaner account?")
                        .font(.headline)
                        .foregroundStyle(PeachyTheme.textPrimary)

                    Text("Choose one option below. Google saves info across Macs. Simple account stays on this Mac only. Email + password uses a verification code (local simulation for now).")
                        .font(.callout)
                        .foregroundStyle(PeachyTheme.textSecondary)

                    HStack(spacing: 12) {
                        Button {
                            signInGoogle()
                        } label: {
                            HStack {
                                Image(systemName: "g.circle.fill")
                                Text(googleLoading ? "Signing in..." : "Sign up with Google")
                            }
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(PeachyTheme.accentBlue)
                        .disabled(googleLoading)

                        Button {
                            // Simple local account (no login)
                            authProvider = "Simple local account"
                            authModeRaw = PeachyAuthMode.simple.rawValue
                            emailVerified = false
                            isSignedIn = true
                        } label: {
                            Text("Simple account (no login)")
                        }
                        .buttonStyle(.bordered)

                        Button {
                            authModeRaw = PeachyAuthMode.emailPassword.rawValue
                        } label: {
                            Text("Email + password")
                        }
                        .buttonStyle(.bordered)
                    }

                    if authMode == .emailPassword {
                        emailPasswordSection
                    }
                }

                Divider().padding(.vertical, 4)

                // Scan depth
                VStack(alignment: .leading, spacing: 6) {
                    Text("Scan depth")
                        .font(.headline)
                        .foregroundStyle(PeachyTheme.textPrimary)

                    Picker("Mode", selection: $scanModeRaw) {
                        ForEach(PeachyScanMode.allCases) { mode in
                            Text(mode.rawValue).tag(mode.rawValue)
                        }
                    }
                    .pickerStyle(.segmented)
                    .frame(maxWidth: 420)

                    Text(scanMode.description)
                        .font(.callout)
                        .foregroundStyle(PeachyTheme.textSecondary)
                        .frame(maxWidth: 600, alignment: .leading)
                }

                // Full Disk Access note
                GroupBox("Full Disk Access (optional, recommended)") {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("For the deepest clean on all locations (Macintosh HD, external drives, etc.), macOS requires Full Disk Access.")
                            .font(.callout)
                            .foregroundStyle(PeachyTheme.textSecondary)
                        Button("Open Full Disk Access Settings") {
                            if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles") {
                                NSWorkspace.shared.open(url)
                            }
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(PeachyTheme.accentBlue)

                        Text("After enabling, quit and reopen PeachyCleaner for best results.")
                            .font(.caption)
                            .foregroundStyle(PeachyTheme.textSecondary)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxWidth: 680)

                Spacer()
            }
            .padding(24)
        }
        .alert("Thank you!", isPresented: $donateAlert) {
            Button("OK", role: .cancel) {}
        } message: {
            Text("Thank you for attempting to dontate we do not have this feature up yet but thank you so much!!")
        }
        .alert("Sign-in Error", isPresented: Binding(
            get: { authError != nil },
            set: { if !$0 { authError = nil } }
        )) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(authError ?? "")
        }
        .alert("Verification Code", isPresented: $showCodeAlert) {
            Button("OK", role: .cancel) {}
        } message: {
            Text("For now, your verification code is: \(generatedCode ?? "000000")\n\nIn a future version this would be emailed to you.")
        }
    }

    private var emailPasswordSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Email + password (local demo)")
                .font(.subheadline).bold()
                .foregroundStyle(PeachyTheme.textPrimary)

            HStack(spacing: 16) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Email")
                        .font(.caption)
                        .foregroundStyle(PeachyTheme.textSecondary)
                    TextField("you@example.com", text: $emailAddr)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 260)
                }

                VStack(alignment: .leading, spacing: 4) {
                    Text("Password")
                        .font(.caption)
                        .foregroundStyle(PeachyTheme.textSecondary)
                    SecureField("Password", text: $emailPassword)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 200)
                    SecureField("Confirm password", text: $emailPasswordConfirm)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 200)
                }
            }

            HStack(spacing: 10) {
                Button("Send verification code") {
                    guard !emailAddr.isEmpty else {
                        authError = "Enter an email first."
                        return
                    }
                    guard !emailPassword.isEmpty, emailPassword == emailPasswordConfirm else {
                        authError = "Passwords must match and not be empty."
                        return
                    }
                    let code = String(Int.random(in: 100_000...999_999))
                    generatedCode = code
                    emailVerified = false
                    enteredCode = ""
                    showCodeAlert = true
                }
                .buttonStyle(.bordered)

                TextField("Enter verification code", text: $enteredCode)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 160)

                Button(emailVerified ? "Verified" : "Verify code") {
                    guard let gen = generatedCode else {
                        authError = "Send a code first."
                        return
                    }
                    if enteredCode == gen {
                        emailVerified = true
                    } else {
                        authError = "Verification code does not match."
                    }
                }
                .buttonStyle(.borderedProminent)
                .tint(emailVerified ? PeachyTheme.accentGreen : PeachyTheme.accentBlue)
            }

            Button("Create account and continue") {
                guard emailVerified else {
                    authError = "Please verify your email code first."
                    return
                }
                userEmail = emailAddr
                authProvider = "Email + password"
                authModeRaw = PeachyAuthMode.emailPassword.rawValue
                isSignedIn = true
            }
            .buttonStyle(.borderedProminent)
            .tint(PeachyTheme.accentGreen)
        }
        .padding(.top, 6)
    }

    private func signInGoogle() {
        googleLoading = true
        authError = nil

        let config = GIDConfiguration(clientID: googleClientID)
        GIDSignIn.sharedInstance.configuration = config

        guard let window = NSApplication.shared.keyWindow ?? NSApplication.shared.windows.first else {
            googleLoading = false
            authError = "Unable to find an active window to present Google sign-in."
            return
        }

        GIDSignIn.sharedInstance.signIn(withPresenting: window) { signInResult, error in
            DispatchQueue.main.async {
                googleLoading = false

                if let error = error {
                    authError = error.localizedDescription
                    return
                }

                guard let user = signInResult?.user else {
                    authError = "Google sign-in failed."
                    return
                }

                let profile = user.profile
                if let name = profile?.givenName, !name.isEmpty { preferredName = name }
                if let email = profile?.email, !email.isEmpty { userEmail = email }

                authProvider = "Google"
                authModeRaw = PeachyAuthMode.google.rawValue
                isSignedIn = true
            }
        }
    }
}

// MARK: - Root ContentView

struct ContentView: View {

    @AppStorage("isSignedIn") private var isSignedIn: Bool = false
    @AppStorage("preferredName") private var preferredName: String = "carson"
    @AppStorage("userEmail") private var userEmail: String = ""
    @AppStorage("authProvider") private var authProvider: String = ""
    @AppStorage("scanModeRaw") private var scanModeRaw: String = PeachyScanMode.basic.rawValue
    @AppStorage("authModeRaw") private var authModeRaw: String = ""

    var body: some View {
        if !isSignedIn {
            PeachyOnboardingView(
                isSignedIn: $isSignedIn,
                preferredName: $preferredName,
                userEmail: $userEmail,
                authProvider: $authProvider,
                scanModeRaw: $scanModeRaw,
                authModeRaw: $authModeRaw
            )
        } else {
            PeachyMainAppView(
                preferredName: preferredName,
                authProvider: authProvider,
                scanModeRaw: scanModeRaw
            )
        }
    }
}

// MARK: - Main app view

struct PeachyMainAppView: View {
    let preferredName: String
    let authProvider: String
    let scanModeRaw: String

    @StateObject private var scanner = PeachyScanner()
    @StateObject private var disk = PeachyDiskProvider()
    @StateObject private var audit = PeachyAuditLogStore()

    @AppStorage("windowedQuickLook") private var windowedQuickLook: Bool = false

    @State private var section: PeachySection = .dashboard
    @State private var sidebarSearch = ""
    @State private var showCleanConfirm = false

    @State private var showDeleteAllSheet = false
    @State private var deleteAllCandidates: [PeachyItem] = []
    @State private var deleteAllSelectedIDs: Set<UUID> = []
    @State private var deleteAllSummaryText: String = ""
    @State private var authError: String? = nil
    @State private var noScanAlert = false
    @State private var isAuthInProgress = false
    @State private var isPreparingDeleteAll = false

    @State private var windowIsSmall: Bool = false

    private var scanMode: PeachyScanMode {
        PeachyScanMode(rawValue: scanModeRaw) ?? .basic
    }

    private var visibleSections: [PeachySection] {
        windowedQuickLook ? [.dashboard, .largeFiles, .duplicates] : PeachySection.allCases
    }

    var body: some View {
        GeometryReader { geo in
            ZStack {
                PeachyTheme.bg.ignoresSafeArea()

                NavigationSplitView {
                    sidebar.frame(minWidth: 260, idealWidth: 280)
                } detail: {
                    mainPanel
                }

                if windowIsSmall && !windowedQuickLook {
                    smallWindowBanner
                        .transition(.move(edge: .top).combined(with: .opacity))
                }
            }
            .onAppear {
                updateWindowSize(geo.size)
                disk.refresh()
            }
            .onChange(of: geo.size) { _, newSize in updateWindowSize(newSize) }
        }
        .toolbar {
            ToolbarItem(placement: .navigation) {
                HStack(spacing: 8) {
                    Image("Image")
                        .resizable()
                        .scaledToFit()
                        .frame(width: 22, height: 22)
                        .cornerRadius(4)

                    Text("PeachyCleaner")
                        .font(.system(size: 16, weight: .bold))
                        .foregroundStyle(PeachyTheme.textPrimary)

                    Text(preferredName)
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(PeachyTheme.textSecondary)
                }
            }

            ToolbarItem(placement: .principal) {
                Picker("", selection: $section) {
                    ForEach(visibleSections) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
                .frame(width: 520)
            }

            ToolbarItemGroup(placement: .automatic) {
                if section != .settings && section != .account {
                    Button(scanner.isScanning ? "Scanning..." : "Scan") {
                        scanner.scan(mode: scanMode)
                        disk.refresh()
                    }
                    .disabled(scanner.isScanning)

                    Button("Clean Caches") { showCleanConfirm = true }
                        .disabled(scanner.isScanning)

                    Button("Delete All Safe") { startDeleteAllFlow() }
                        .disabled(scanner.isScanning)
                }
            }
        }
        .alert("Clean User Caches?", isPresented: $showCleanConfirm) {
            Button("Cancel", role: .cancel) {}
            Button("Clean", role: .destructive) { scanner.cleanUserCaches() }
        } message: {
            Text("Safe cache cleanup. Apps rebuild these automatically.")
        }
        .alert("No scan completed", isPresented: $noScanAlert) {
            Button("OK", role: .cancel) { }
        } message: {
            Text("Run a scan first, then try Delete All Safe again.")
        }
        .sheet(isPresented: $showDeleteAllSheet) {
            PeachyDeleteAllSheet(
                items: deleteAllCandidates,
                selectedIDs: $deleteAllSelectedIDs,
                summaryText: deleteAllSummaryText,
                isAuthInProgress: $isAuthInProgress,
                isPreparing: $isPreparingDeleteAll,
                onCancel: {
                    showDeleteAllSheet = false
                    isPreparingDeleteAll = false
                },
                onConfirm: { authenticateAndDeleteAll() }
            )
        }
        .alert("Authentication Failed", isPresented: Binding(
            get: { authError != nil },
            set: { if !$0 { authError = nil } }
        )) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(authError ?? "")
        }
        .frame(minWidth: 980, minHeight: 640)
    }

    // MARK: - Window banner

    private var smallWindowBanner: some View {
        VStack {
            HStack(spacing: 10) {
                Image(systemName: "arrow.up.left.and.arrow.down.right")
                    .foregroundStyle(PeachyTheme.textPrimary)

                Text("Please full screen the app to get the most. If you prefer not to, click")
                    .foregroundStyle(PeachyTheme.textPrimary)
                    .font(.callout)

                Button("Here") {
                    windowedQuickLook = true
                    if !visibleSections.contains(section) { section = .dashboard }
                }
                .buttonStyle(.borderedProminent)
                .tint(PeachyTheme.accentBlue)

                Spacer()
            }
            .padding(12)
            .background(PeachyTheme.bgPanel2)
            .cornerRadius(12)
            .overlay(RoundedRectangle(cornerRadius: 12).stroke(PeachyTheme.strokeStrong))
            .shadow(radius: 8)

            Spacer()
        }
        .padding(.top, 8)
        .padding(.horizontal, 12)
    }

    private func updateWindowSize(_ size: CGSize) {
        windowIsSmall = size.width < 950 || size.height < 620
    }

    // MARK: - Sidebar

    private var sidebar: some View {
        ZStack {
            PeachyTheme.bgPanel.ignoresSafeArea()

            VStack(alignment: .leading, spacing: 12) {

                HStack {
                    TextField("Search…", text: $sidebarSearch)
                        .textFieldStyle(.roundedBorder)

                    Button { sidebarSearch = "" } label: {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundStyle(PeachyTheme.textSecondary)
                    }
                    .buttonStyle(.plain)
                }
                .padding(.top, 10)

                Text(section == .largeFiles ? "Large Items" :
                        section == .duplicates ? "Duplicates" :
                        section == .account ? "History" :
                        "Folders")
                    .font(.caption)
                    .foregroundStyle(PeachyTheme.textSecondary)
                    .padding(.top, 6)

                ScrollView {
                    VStack(alignment: .leading, spacing: 8) {
                        switch section {
                        case .dashboard:
                            ForEach(filteredFolders) { folder in
                                Button { scanner.loadFolderBreakdown(folder) } label: {
                                    PeachySidebarRow(
                                        url: folder.url,
                                        size: folder.sizeBytes,
                                        isSelected: scanner.selectedFolder?.id == folder.id
                                    )
                                }
                                .buttonStyle(.plain)
                            }

                        case .largeFiles:
                            ForEach(filteredLargeItems) { item in
                                Button {
                                    if item.risk != .leaveAlone {
                                        scanner.deletePermanently(item.url)
                                    }
                                } label: {
                                    PeachySidebarRow(url: item.url, size: item.sizeBytes, isSelected: false)
                                }
                                .buttonStyle(.plain)
                            }

                        case .duplicates:
                            ForEach(scanner.duplicateGroups) { group in
                                VStack(alignment: .leading, spacing: 6) {
                                    Text("Group · \(group.sizeBytes.peachyBytes()) each")
                                        .font(.caption2)
                                        .foregroundStyle(PeachyTheme.textSecondary)

                                    ForEach(group.items, id: \.self) { url in
                                        Button {
                                            let analysis = PeachySafetyAnalyzer.analyze(url: url, isDirectory: false)
                                            if analysis.grade != .leaveAlone {
                                                scanner.deletePermanently(url)
                                            }
                                        } label: {
                                            PeachySidebarRow(url: url, size: group.sizeBytes, isSelected: false)
                                        }
                                        .buttonStyle(.plain)
                                    }
                                }
                                .padding(.bottom, 6)
                            }

                        case .settings:
                            settingsShortcuts

                        case .account:
                            accountSidebar
                        }
                    }
                    .padding(.vertical, 6)
                }

                Spacer()

                Text(scanner.statusMessage)
                    .font(.caption2)
                    .foregroundStyle(PeachyTheme.textSecondary)
                    .padding(.bottom, 8)
            }
            .padding(.horizontal, 12)
        }
    }

    private var settingsShortcuts: some View {
        VStack(alignment: .leading, spacing: 8) {
            Button("Open Full Disk Access") { scanner.openFullDiskAccessSettings() }
                .buttonStyle(.link)

            if windowedQuickLook {
                Button("Exit Windowed Mode") { windowedQuickLook = false }
                    .buttonStyle(.bordered)
            }
        }
        .font(.system(size: 13))
        .padding(.top, 6)
    }

    private var accountSidebar: some View {
        VStack(alignment: .leading, spacing: 8) {
            if audit.logs.isEmpty {
                Text("No Delete-All events yet.")
                    .font(.caption)
                    .foregroundStyle(PeachyTheme.textSecondary)
            } else {
                ForEach(audit.logs.prefix(10)) { log in
                    VStack(alignment: .leading, spacing: 4) {
                        Text(log.date.formatted(date: .abbreviated, time: .shortened))
                            .font(.caption).bold()
                            .foregroundStyle(PeachyTheme.textPrimary)
                        Text("\(log.itemCount) items · \(log.totalBytes.peachyBytes())")
                            .font(.caption2)
                            .foregroundStyle(PeachyTheme.textSecondary)
                        Text(log.authMethod)
                            .font(.caption2)
                            .foregroundStyle(PeachyTheme.textSecondary)
                    }
                    .padding(8)
                    .background(PeachyTheme.bgPanel2)
                    .cornerRadius(8)
                    .overlay(RoundedRectangle(cornerRadius: 8).stroke(PeachyTheme.stroke))
                }
            }
        }
    }

    private var filteredFolders: [PeachyFolderResult] {
        guard !sidebarSearch.isEmpty else { return scanner.scanResults }
        return scanner.scanResults.filter { $0.name.lowercased().contains(sidebarSearch.lowercased()) }
    }

    private var filteredLargeItems: [PeachyItem] {
        guard !sidebarSearch.isEmpty else { return scanner.largeItems }
        return scanner.largeItems.filter { $0.url.lastPathComponent.lowercased().contains(sidebarSearch.lowercased()) }
    }

    // MARK: - Main panel

    private var mainPanel: some View {
        switch section {
        case .dashboard: return AnyView(dashboardPanel)
        case .largeFiles: return AnyView(largeFilesPanel)
        case .duplicates: return AnyView(duplicatesPanel)
        case .settings: return AnyView(settingsPanel)
        case .account: return AnyView(accountPanel)
        }
    }

    private var dashboardPanel: some View {
        VStack(alignment: .leading, spacing: 12) {
            // Volume picker row (iCloud, Macintosh HD, DMGs, etc.)
            if !disk.volumes.isEmpty {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        ForEach(disk.volumes) { volume in
                            let isSelected = disk.selectedVolume == volume
                            Button {
                                disk.select(volume)
                                let pseudo = PeachyFolderResult(
                                    name: volume.name,
                                    url: volume.url,
                                    sizeBytes: 0
                                )
                                scanner.loadFolderBreakdown(pseudo)
                            } label: {
                                Text(volume.name)
                                    .font(.caption)
                                    .padding(.horizontal, 10)
                                    .padding(.vertical, 6)
                                    .background(isSelected ? PeachyTheme.bgPanel2 : PeachyTheme.bgPanel)
                                    .foregroundStyle(PeachyTheme.textPrimary)
                                    .cornerRadius(10)
                                    .overlay(RoundedRectangle(cornerRadius: 10)
                                        .stroke(isSelected ? PeachyTheme.strokeStrong : PeachyTheme.stroke))
                            }
                            .buttonStyle(.plain)
                        }
                    }
                    .padding(.bottom, 6)
                }
            }

            if let selected = scanner.selectedFolder {
                HStack {
                    VStack(alignment: .leading) {
                        Text(selected.name).font(.title2).bold()
                            .foregroundStyle(PeachyTheme.textPrimary)
                        Text(selected.url.path)
                            .font(.caption)
                            .foregroundStyle(PeachyTheme.textSecondary)
                    }
                    Spacer()
                    Button("Back to Disk Overview") {
                        scanner.selectedFolder = nil
                        scanner.folderBreakdown = []
                    }
                    .buttonStyle(.bordered)
                }

                if scanner.isScanning {
                    ProgressView(value: scanner.scanProgress)
                        .progressViewStyle(.linear)
                        .tint(PeachyTheme.accentGreen)
                }

                if scanner.folderBreakdown.isEmpty && !scanner.isScanning {
                    emptyState("No items found here.")
                } else {
                    List(scanner.folderBreakdown) { item in
                        HStack {
                            PeachyFileIcon(url: item.url).frame(width: 22, height: 22)

                            VStack(alignment: .leading) {
                                Text(item.url.lastPathComponent)
                                    .font(.headline)
                                    .foregroundStyle(PeachyTheme.textPrimary)
                                Text(item.isDirectory ? "Folder" : "File")
                                    .font(.caption2)
                                    .foregroundStyle(PeachyTheme.textSecondary)
                            }

                            Spacer()

                            PeachyRiskBadge(risk: item.risk, reason: item.riskReason)

                            Text(item.sizeBytes.peachyBytes())
                                .monospacedDigit()
                                .foregroundStyle(PeachyTheme.textSecondary)

                            Button("Delete") {
                                if item.risk != .leaveAlone {
                                    scanner.deletePermanently(item.url)
                                }
                            }
                            .buttonStyle(.borderedProminent)
                            .tint(PeachyTheme.accentRed)
                            .disabled(item.risk == .leaveAlone)
                        }
                        .padding(.vertical, 4)
                    }
                    .scrollContentBackground(.hidden)
                    .background(PeachyTheme.bgPanel)
                    .cornerRadius(12)
                    .overlay(RoundedRectangle(cornerRadius: 12).stroke(PeachyTheme.stroke))
                }

            } else {
                VStack(spacing: 14) {
                    Spacer()
                    PeachyDiskCard(
                        info: disk.info,
                        name: disk.selectedVolume?.name ?? "Macintosh HD"
                    )

                    if scanner.isScanning {
                        ProgressView(value: scanner.scanProgress)
                            .progressViewStyle(.linear)
                            .tint(PeachyTheme.accentGreen)
                            .frame(width: 520)
                        Text("Scanning… \(Int(scanner.scanProgress * 100))%")
                            .font(.caption)
                            .foregroundStyle(PeachyTheme.textSecondary)
                    } else {
                        Text(scanner.lastScanDate == nil
                             ? "Click Scan to begin, or click a volume above to explore it."
                             : "Scan complete. Select a folder on the left, or click a volume above.")
                            .font(.caption)
                            .foregroundStyle(PeachyTheme.textSecondary)
                    }
                    Spacer()
                }
            }
        }
        .padding(18)
    }

    private var largeFilesPanel: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Top 20 Biggest Items")
                .font(.title2).bold()
                .foregroundStyle(PeachyTheme.textPrimary)

            if scanner.largeItems.isEmpty {
                emptyState("Run a scan to populate large items.")
            } else {
                List(scanner.largeItems) { item in
                    HStack {
                        PeachyFileIcon(url: item.url).frame(width: 26, height: 26)

                        VStack(alignment: .leading) {
                            Text(item.url.lastPathComponent)
                                .font(.headline)
                                .foregroundStyle(PeachyTheme.textPrimary)

                            Text(item.url.path)
                                .font(.caption)
                                .foregroundStyle(PeachyTheme.textSecondary)
                        }

                        Spacer()

                        PeachyRiskBadge(risk: item.risk, reason: item.riskReason)

                        Text(item.sizeBytes.peachyBytes())
                            .monospacedDigit()
                            .foregroundStyle(PeachyTheme.textSecondary)

                        Button("Delete") {
                            if item.risk != .leaveAlone {
                                scanner.deletePermanently(item.url)
                            }
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(PeachyTheme.accentRed)
                        .disabled(item.risk == .leaveAlone)
                    }
                    .padding(.vertical, 4)
                }
                .scrollContentBackground(.hidden)
                .background(PeachyTheme.bgPanel)
                .cornerRadius(12)
                .overlay(RoundedRectangle(cornerRadius: 12).stroke(PeachyTheme.stroke))
            }
        }
        .padding(18)
    }

    private var duplicatesPanel: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("Duplicate Finder")
                    .font(.title2).bold()
                    .foregroundStyle(PeachyTheme.textPrimary)
                Spacer()
                Button(scanner.isScanning ? "Scanning..." : "Scan Duplicates") {
                    scanner.scanDuplicates(mode: scanMode)
                }
                .buttonStyle(.borderedProminent)
                .tint(PeachyTheme.accentBlue)
                .disabled(scanner.isScanning)
            }

            if scanner.duplicateGroups.isEmpty {
                emptyState("No duplicates found yet.")
            } else {
                List(scanner.duplicateGroups) { group in
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Group — \(group.sizeBytes.peachyBytes()) each")
                            .font(.headline)
                            .foregroundStyle(PeachyTheme.textPrimary)

                        ForEach(group.items, id: \.self) { url in
                            let analysis = PeachySafetyAnalyzer.analyze(url: url, isDirectory: false)

                            HStack {
                                PeachyFileIcon(url: url).frame(width: 20, height: 20)
                                Text(url.lastPathComponent)
                                    .foregroundStyle(PeachyTheme.textPrimary)
                                Spacer()
                                PeachyRiskBadge(risk: analysis.grade, reason: analysis.reason)

                                Button("Delete") {
                                    if analysis.grade != .leaveAlone {
                                        scanner.deletePermanently(url)
                                    }
                                }
                                .buttonStyle(.bordered)
                                .disabled(analysis.grade == .leaveAlone)
                            }
                            .font(.caption)
                        }
                    }
                    .padding(.vertical, 6)
                }
                .scrollContentBackground(.hidden)
                .background(PeachyTheme.bgPanel)
                .cornerRadius(12)
                .overlay(RoundedRectangle(cornerRadius: 12).stroke(PeachyTheme.stroke))
            }
        }
        .padding(18)
    }

    private var settingsPanel: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Settings")
                .font(.title2).bold()
                .foregroundStyle(PeachyTheme.textPrimary)

            GroupBox("Full Disk Access") {
                Text("Full scans work best if you enable Full Disk Access.")
                    .font(.callout)
                    .foregroundStyle(PeachyTheme.textSecondary)

                Button("Open Full Disk Access Settings") {
                    scanner.openFullDiskAccessSettings()
                }
                .buttonStyle(.borderedProminent)
                .tint(PeachyTheme.accentBlue)

                Text("After enabling, restart PeachyCleaner.")
                    .font(.caption)
                    .foregroundStyle(PeachyTheme.textSecondary)
            }
            .background(PeachyTheme.bgPanel)
            .cornerRadius(8)

            Spacer()
        }
        .padding(18)
    }

    private var accountPanel: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Account & Safety History")
                .font(.title2).bold()
                .foregroundStyle(PeachyTheme.textPrimary)

            Text("Signed in via \(authProvider).")
                .font(.callout)
                .foregroundStyle(PeachyTheme.textSecondary)

            if audit.logs.isEmpty {
                emptyState("No Delete-All events yet.")
            } else {
                List(audit.logs) { log in
                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(log.date.formatted(date: .abbreviated, time: .shortened))
                                .font(.headline)
                                .foregroundStyle(PeachyTheme.textPrimary)
                            Text("\(log.itemCount) items · \(log.totalBytes.peachyBytes())")
                                .font(.caption)
                                .foregroundStyle(PeachyTheme.textSecondary)
                        }
                        Spacer()
                        Text(log.authMethod)
                            .font(.caption)
                            .foregroundStyle(PeachyTheme.textSecondary)
                    }
                    .padding(.vertical, 6)
                }
                .scrollContentBackground(.hidden)
                .background(PeachyTheme.bgPanel)
                .cornerRadius(12)
                .overlay(RoundedRectangle(cornerRadius: 12).stroke(PeachyTheme.stroke))
            }

            Spacer()
        }
        .padding(18)
    }

    private func emptyState(_ text: String) -> some View {
        VStack(spacing: 8) {
            Image(systemName: "sparkles")
                .font(.system(size: 40))
                .foregroundStyle(PeachyTheme.textSecondary)
            Text(text).foregroundStyle(PeachyTheme.textSecondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - Delete-all helpers

    private func safeItemsForDeleteAll() -> [PeachyItem] {
        if scanner.selectedFolder != nil && !scanner.folderBreakdown.isEmpty {
            return scanner.folderBreakdown.filter { $0.risk == .safe }
        }
        return scanner.largeItems.filter { $0.risk == .safe }
    }

    private func startDeleteAllFlow() {
        if scanner.lastScanDate == nil {
            noScanAlert = true
            return
        }

        isPreparingDeleteAll = true
        deleteAllCandidates = []
        deleteAllSelectedIDs = []
        deleteAllSummaryText = ""
        showDeleteAllSheet = true

        Task.detached(priority: .userInitiated) {
            let safe = safeItemsForDeleteAll()

            await MainActor.run {
                guard !safe.isEmpty else {
                    self.showDeleteAllSheet = false
                    self.isPreparingDeleteAll = false
                    self.noScanAlert = true
                    return
                }

                self.deleteAllCandidates = safe
                self.deleteAllSelectedIDs = Set(safe.map { $0.id })
                self.deleteAllSummaryText = PeachySmartSummary.summarize(items: safe)
                self.isPreparingDeleteAll = false
            }
        }
    }

    private func authenticateAndDeleteAll() {
        guard !isAuthInProgress else { return }
        isAuthInProgress = true
        authError = nil

        let itemsToDelete = deleteAllCandidates.filter { deleteAllSelectedIDs.contains($0.id) }
        guard !itemsToDelete.isEmpty else {
            isAuthInProgress = false
            return
        }

        let context = LAContext()
        context.localizedCancelTitle = "Cancel"

        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            authError = "Your Mac can’t authenticate right now. Enable Touch ID or password auth."
            isAuthInProgress = false
            return
        }

        context.evaluatePolicy(
            .deviceOwnerAuthentication,
            localizedReason: "Confirm permanent deletion of \(itemsToDelete.count) safe items."
        ) { success, evalError in
            DispatchQueue.main.async {
                self.isAuthInProgress = false

                guard success else {
                    self.authError = evalError?.localizedDescription ?? "Authentication failed."
                    return
                }

                let method = context.biometryType == .touchID ? "Touch ID"
                            : context.biometryType == .faceID ? "Face ID"
                            : "Password"

                for item in itemsToDelete where item.risk != .leaveAlone {
                    self.scanner.deletePermanently(item.url)
                }

                self.audit.add(authMethod: method, items: itemsToDelete)
                self.showDeleteAllSheet = false
            }
        }
    }
}

