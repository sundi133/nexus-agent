# AUTH_EXEC shadow-mode validation

Shadow mode exists to validate the authorization path without blocking applications.

## Invariants

- Every `AUTH_EXEC` request receives `ES_AUTH_RESULT_ALLOW`.
- A configured exact path can produce `would_deny=true` telemetry only.
- No remote API, filesystem read, DNS lookup, or model inference occurs in the authorization callback.
- Failure to load a policy must not silently switch shadow mode into enforcement.

## Manual isolated-device test

Build the shadow executable, run it on an entitled macOS test device, then configure a harmless executable path such as a purpose-built test binary. Confirm the log contains `would_deny=true action=allow` and the executable still starts.

Do not use system-critical executables as future deny targets.
