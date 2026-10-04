import Foundation
import NetworkExtension

@MainActor
final class ContentFilterManager: ObservableObject {
    @Published private(set) var status = "Network filter not configured"
    @Published var testBlockedHost = ""

    private let manager = NEFilterManager.shared()

    func enable() {
        status = "Loading network filter preferences…"

        manager.loadFromPreferences { [weak self] error in
            Task { @MainActor in
                guard let self else { return }
                if let error {
                    self.status = "Load failed: \(error.localizedDescription)"
                    return
                }

                let configuration = NEFilterProviderConfiguration()
                configuration.filterSockets = true
                configuration.filterDataProviderBundleIdentifier =
                    SystemExtensionManager.filterExtensionIdentifier

                let host = self.testBlockedHost
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                    .lowercased()
                configuration.vendorConfiguration = [
                    "blockedHosts": host.isEmpty ? [] : [host]
                ]

                self.manager.providerConfiguration = configuration
                self.manager.localizedDescription = "Votal Nexus Network Filter"
                self.manager.isEnabled = true
                self.status = "Saving network filter configuration…"

                self.manager.saveToPreferences { error in
                    Task { @MainActor in
                        if let error {
                            self.status = "Enable failed: \(error.localizedDescription)"
                        } else {
                            self.status = host.isEmpty
                                ? "Network filter enabled in allow mode"
                                : "Network filter enabled; exact test host configured"
                        }
                    }
                }
            }
        }
    }

    func disable() {
        status = "Loading network filter preferences…"

        manager.loadFromPreferences { [weak self] error in
            Task { @MainActor in
                guard let self else { return }
                if let error {
                    self.status = "Load failed: \(error.localizedDescription)"
                    return
                }

                self.manager.isEnabled = false
                self.status = "Disabling network filter…"
                self.manager.saveToPreferences { error in
                    Task { @MainActor in
                        self.status = error == nil
                            ? "Network filter disabled"
                            : "Disable failed: \(error!.localizedDescription)"
                    }
                }
            }
        }
    }
}
