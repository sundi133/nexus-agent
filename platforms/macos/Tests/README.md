# macOS adapter tests

Native Endpoint Security integration tests require a macOS runner/device with the appropriate entitlement and permissions.

The repository CI can still compile-check portable code, while native tests should cover:

- collector startup and explicit entitlement failure reporting;
- exec/fork/exit event normalization;
- create/rename/unlink normalization;
- event bursts and dropped-event accounting once the bounded queue is added;
- clean shutdown/unsubscription;
- later authorization tests proving audit mode never blocks.

Do not test ransomware blocking against a developer's normal home directory. Use an isolated disposable test directory/VM and synthetic file operations.
