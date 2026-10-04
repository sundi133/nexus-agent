import SwiftUI

@main
struct NexusAgentApp: App {
    @StateObject private var extensionManager = SystemExtensionManager()
    @StateObject private var contentFilterManager = ContentFilterManager()

    var body: some Scene {
        WindowGroup {
            ContentView(
                manager: extensionManager,
                filterManager: contentFilterManager
            )
            .frame(minWidth: 620, minHeight: 420)
        }
    }
}

private struct ContentView: View {
    @ObservedObject var manager: SystemExtensionManager
    @ObservedObject var filterManager: ContentFilterManager

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("Nexus Agent")
                .font(.largeTitle)

            GroupBox("Endpoint Security") {
                VStack(alignment: .leading, spacing: 10) {
                    Text(manager.status)
                        .textSelection(.enabled)
                    HStack {
                        Button("Activate Security Extensions") {
                            manager.activate()
                        }
                        Button("Deactivate Security Extensions") {
                            manager.deactivate()
                        }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }

            GroupBox("Network Content Filter") {
                VStack(alignment: .leading, spacing: 10) {
                    Text(filterManager.status)
                        .textSelection(.enabled)

                    TextField(
                        "Exact development host to block, e.g. blocked.example",
                        text: $filterManager.testBlockedHost
                    )

                    HStack {
                        Button("Enable Filter") {
                            filterManager.enable()
                        }
                        Button("Disable Filter") {
                            filterManager.disable()
                        }
                    }

                    Text("The development filter blocks only an exact configured hostname. Leave the field empty for allow-only mode.")
                        .font(.caption)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }

            Text("Production deployments should use MDM approval, Developer ID signing, and signed policy rather than manually configured test rules.")
                .font(.caption)
        }
        .padding(24)
    }
}
