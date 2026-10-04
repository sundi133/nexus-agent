import Foundation
import NetworkExtension
import os

final class FilterDataProvider: NEFilterDataProvider {
    private let logger = Logger(
        subsystem: "ai.votal.nexus.agent.network",
        category: "filter-data"
    )

    private let appGroup = "group.ai.votal.nexus.agent"
    private let blockedHostsKey = "network.blockedHosts"
    private var blockedHosts = Set<String>()

    override func startFilter(
        completionHandler: @escaping (Error?) -> Void
    ) {
        reloadRules()

        let settings = NEFilterSettings(
            rules: [],
            defaultAction: .filterData
        )

        apply(settings) { [weak self] error in
            if let error {
                self?.logger.error(
                    "Failed applying filter settings: \(error.localizedDescription, privacy: .public)"
                )
            } else {
                self?.logger.log(
                    "Network filter started blocked_hosts=\(self?.blockedHosts.count ?? 0)"
                )
            }
            completionHandler(error)
        }
    }

    override func stopFilter(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        logger.log("Network filter stopped reason=\(reason.rawValue)")
        completionHandler()
    }

    override func handleNewFlow(
        _ flow: NEFilterFlow
    ) -> NEFilterNewFlowVerdict {
        guard let host = remoteHost(for: flow)?.lowercased() else {
            return .allow()
        }

        if blockedHosts.contains(host) {
            logger.error(
                "Blocking exact hostname host=\(host, privacy: .private(mask: .hash))"
            )
            return .drop()
        }

        return .allow()
    }

    override func handleRulesChanged() {
        reloadRules()
        logger.log("Reloaded network rules blocked_hosts=\(blockedHosts.count)")
    }

    private func reloadRules() {
        guard let defaults = UserDefaults(suiteName: appGroup) else {
            blockedHosts = []
            return
        }

        let persisted = defaults.stringArray(forKey: blockedHostsKey) ?? []
        let configured =
            filterConfiguration.vendorConfiguration?["blockedHosts"] as? [String] ?? []
        let hosts = configured + persisted
        blockedHosts = Set(
            hosts
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
                .filter { !$0.isEmpty }
        )
    }

    private func remoteHost(for flow: NEFilterFlow) -> String? {
        if let host = flow.url?.host {
            return host
        }

        if let socketFlow = flow as? NEFilterSocketFlow {
            if let host = socketFlow.remoteHostname, !host.isEmpty {
                return host
            }

            if let endpoint = socketFlow.remoteFlowEndpoint {
                switch endpoint {
                case .hostPort(let host, _):
                    return String(describing: host)
                default:
                    break
                }
            }
        }

        return nil
    }
}
