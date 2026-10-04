import NetworkExtension
import os

final class FilterControlProvider: NEFilterControlProvider {
    private let logger = Logger(
        subsystem: "ai.votal.nexus.agent.network",
        category: "filter-control"
    )

    override func startFilter(
        completionHandler: @escaping (Error?) -> Void
    ) {
        logger.log("Network filter control provider started")
        completionHandler(nil)
    }

    override func stopFilter(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        logger.log("Network filter control provider stopped reason=\(reason.rawValue)")
        completionHandler()
    }

    override func handleNewFlow(
        _ flow: NEFilterFlow,
        completionHandler: @escaping (NEFilterControlVerdict) -> Void
    ) {
        // Development invariant: the control provider never invents a deny rule.
        // Rules are written explicitly by the host/control-plane path.
        completionHandler(.allow(withUpdateRules: false))
    }
}
