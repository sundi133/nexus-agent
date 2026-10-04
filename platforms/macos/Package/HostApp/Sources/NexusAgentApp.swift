import SwiftUI

@main
struct NexusAgentApp: App {
    @StateObject private var extensionManager = SystemExtensionManager()

    var body: some Scene {
        WindowGroup {
            ContentView(manager: extensionManager)
                .frame(minWidth: 520, minHeight: 280)
        }
    }
}

private struct ContentView: View {
    @ObservedObject var manager: SystemExtensionManager

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Nexus Agent")
                .font(.largeTitle)
            Text("Endpoint Security system extension")
                .font(.headline)
            Text(manager.status)
                .textSelection(.enabled)

            HStack {
                Button("Activate Extension") {
                    manager.activate()
                }
                Button("Deactivate Extension") {
                    manager.deactivate()
                }
            }

            Text("Production deployments should activate and approve the extension through managed enterprise configuration where appropriate.")
                .font(.caption)
        }
        .padding(24)
    }
}
