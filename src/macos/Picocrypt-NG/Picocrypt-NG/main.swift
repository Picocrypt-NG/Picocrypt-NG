import Cocoa

// --- Entry Point ---
let app = NSApplication.shared
//app.setActivationPolicy(.accessory)
let delegate = LauncherDelegate()
app.delegate = delegate
app.run()
