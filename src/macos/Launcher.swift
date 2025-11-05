import Cocoa
import Foundation

let binaryName = "Picocrypt-NG"
let appName = binaryName

class LauncherDelegate: NSObject, NSApplicationDelegate {
    private var pendingFiles = [String]()
    private var launchTimer: Timer?
    private var goTask: Process?
    private var relaunching = false

    func applicationDidFinishLaunching(_ notification: Notification) {
        buildMenuBar()
        restartLaunchTimer()
    }

    func application(_ sender: NSApplication, openFiles filenames: [String]) {
        // Add to the queue of pending files
        pendingFiles.append(contentsOf: filenames)

        // Cancel any existing relaunch timer
        launchTimer?.invalidate()

        // Wait a bit before processing to allow more files to arrive
        launchTimer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: false) { _ in
            if let task = self.goTask, task.isRunning {
                // All file events have now been coalesced; show single relaunch dialog
                self.showRelaunchDialog(with: self.pendingFiles)
            } else {
                // Normal launch
                self.restartLaunchTimer()
            }
        }
    }

    @objc private func showAbout(_ sender: Any?) {
        let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "Unknown"
        let alert = NSAlert()
        alert.alertStyle = .informational
        alert.messageText = "Picocrypt-NG v\(version)"
        alert.informativeText = "macOS Standalone Launcher"
        alert.runModal()
    }

    @objc private func quitApp(_ sender: Any?) {
        if let task = goTask, task.isRunning {
            task.terminate()
        }
        NSApp.terminate(nil)
    }

    private func buildMenuBar() {
        let mainMenu = NSMenu()
        let appMenuItem = NSMenuItem()
        mainMenu.addItem(appMenuItem)

        let appMenu = NSMenu()
        appMenu.addItem(NSMenuItem(title: "About \(appName)",
                                   action: #selector(showAbout(_:)),
                                   keyEquivalent: ""))
        appMenu.addItem(NSMenuItem.separator())
        appMenu.addItem(NSMenuItem(title: "Quit \(appName)",
                                   action: #selector(quitApp(_:)),
                                   keyEquivalent: "q"))
        appMenuItem.submenu = appMenu
        NSApp.mainMenu = mainMenu
    }

    private func restartLaunchTimer() {
        launchTimer?.invalidate()
        launchTimer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: false) { _ in
            self.launchGoBinary()
        }
    }

    private func launchGoBinary() {
        guard goTask == nil || goTask?.isRunning == false else { return }
        let binPath = (Bundle.main.bundlePath as NSString)
            .appendingPathComponent("Contents/MacOS/\(binaryName)")

        let task = Process()
        task.launchPath = binPath
        task.arguments = pendingFiles
        task.terminationHandler = { _ in
            // Quit launcher when the Go process exits
            DispatchQueue.main.async {
                if !self.relaunching {
                    NSApp.terminate(nil) 
                } else {
                    self.relaunching = false
                }
            }
        }

        do {
            try task.run()
            goTask = task
            relaunching = false
            // Reset file list
            pendingFiles = [String]()
        } catch {
            print("Failed to launch Go binary: \(error)")
            NSApp.terminate(nil)
        }
    }

    private func showRelaunchDialog(with newFiles: [String]) {
        // This includes the about panel for this launcher (not the app)
        if NSApp.modalWindow != nil { return }
        let alert = NSAlert()
        alert.messageText = "Relaunch \(appName) with new files?"
        alert.informativeText = """
        This is required due to how the launcher provides file lists to the app.
        Drop files into the app window to avoid relaunching.
        """
        alert.addButton(withTitle: "Confirm")
        alert.addButton(withTitle: "Cancel")

        let response = alert.runModal()
        if response == .alertFirstButtonReturn {
            // Relaunch confirmed — stop old process and restart
            self.relaunching = true
            goTask?.terminate()
            // Launch again with new arguments
            pendingFiles = newFiles
            restartLaunchTimer()
        }
    }
}

// --- Entry Point ---
let app = NSApplication.shared
//app.setActivationPolicy(.accessory)
let delegate = LauncherDelegate()
app.delegate = delegate
app.run()
