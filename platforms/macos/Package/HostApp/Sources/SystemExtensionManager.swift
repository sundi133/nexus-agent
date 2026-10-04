import Foundation
import SystemExtensions

@MainActor
final class SystemExtensionManager: NSObject, ObservableObject {
    static let endpointExtensionIdentifier = "ai.votal.nexus.agent.endpoint"
    static let filterExtensionIdentifier = "ai.votal.nexus.agent.filter-data"

    private static let extensionIdentifiers = [
        endpointExtensionIdentifier,
        filterExtensionIdentifier,
    ]

    @Published private(set) var status = "Extensions not requested"

    func activate() {
        status = "Requesting security extension activation…"
        submitRequests(activation: true)
    }

    func deactivate() {
        status = "Requesting security extension deactivation…"
        submitRequests(activation: false)
    }

    private func submitRequests(activation: Bool) {
        for identifier in Self.extensionIdentifiers {
            let request: OSSystemExtensionRequest
            if activation {
                request = .activationRequest(
                    forExtensionWithIdentifier: identifier,
                    queue: .main
                )
            } else {
                request = .deactivationRequest(
                    forExtensionWithIdentifier: identifier,
                    queue: .main
                )
            }

            request.delegate = self
            OSSystemExtensionManager.shared.submitRequest(request)
        }
    }
}

extension SystemExtensionManager: OSSystemExtensionRequestDelegate {
    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        Task { @MainActor in
            self.status = "System extension approval required in Privacy & Security"
        }
    }

    nonisolated func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        Task { @MainActor in
            self.status = "System extension request completed: \(result.rawValue)"
        }
    }

    nonisolated func request(
        _ request: OSSystemExtensionRequest,
        didFailWithError error: Error
    ) {
        Task { @MainActor in
            self.status = "System extension request failed: \(error.localizedDescription)"
        }
    }

    nonisolated func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }
}
