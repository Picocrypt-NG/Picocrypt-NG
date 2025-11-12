import AppKit
import UniformTypeIdentifiers

final class ShareRequestHandler: NSViewController {

    override func viewDidAppear() {
        super.viewDidAppear()
        view.alphaValue = 0
        DispatchQueue.main.async { self.handleItems() }
    }

    private func handleItems() {
        guard let ctx = extensionContext else { return }

        var urls: [URL] = []
        let group = DispatchGroup()

        for item in ctx.inputItems as? [NSExtensionItem] ?? [] {
            for provider in item.attachments ?? [] {
                if provider.hasItemConformingToTypeIdentifier("public.file-url") {
                    group.enter()
                    provider.loadInPlaceFileRepresentation(forTypeIdentifier: "public.file-url") { tempURL, inPlace, error in
                        defer { group.leave() }

                        guard let tempURL = tempURL else {
                            if let error = error { NSLog("load error %@", error.localizedDescription) }
                            return
                        }

                        // The temp file contains the string "file:///.file/id=..."
                        if let txt = try? String(contentsOf: tempURL, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines),
                           let refURL = URL(string: txt),
                           let resolved = self.realURL(fromReference: refURL) {
                            urls.append(resolved)
                        } else {
                            NSLog("ShareExt: could not decode file reference at %@", tempURL.path)
                        }
                    }
                }
            }
        }

        group.notify(queue: .main) {
            NSLog("ShareExt: resolved %ld urls: %@", urls.count, urls.map(\.path))
            self.launchHostApp(with: urls)
            ctx.completeRequest(returningItems: nil)
        }
    }

    /// Translate file:///.file/id=... into an actual path
    private func realURL(fromReference ref: URL) -> URL? {
        // Create a temporary bookmark to force path resolution
        guard let bookmark = try? ref.bookmarkData(options: .suitableForBookmarkFile,
                                                   includingResourceValuesForKeys: nil,
                                                   relativeTo: nil) else {
            return ref
        }

        var stale = false
        if let resolved = try? URL(resolvingBookmarkData: bookmark,
                                   options: [.withoutUI, .withoutMounting],
                                   relativeTo: nil,
                                   bookmarkDataIsStale: &stale) {
            return resolved.standardizedFileURL
        }

        // Fallback—return something usable even if the above failed
        return ref.standardizedFileURL
    }

    private func launchHostApp(with urls: [URL]) {
        guard !urls.isEmpty else {
            NSLog("ShareExt: no files received")
            return
        }

        let hostAppURL = Bundle.main.bundleURL
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()

        let config = NSWorkspace.OpenConfiguration()
        config.arguments = urls.map(\.path)
        config.activates = true

        NSWorkspace.shared.open(urls, withApplicationAt: hostAppURL,
                                configuration: NSWorkspace.OpenConfiguration(),
                                completionHandler: nil)
    }
}
