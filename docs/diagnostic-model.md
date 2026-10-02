# Diagnostic model

Evidence is the direct observation from a probe, such as resolved addresses, a socket error, certificate identity or HTTP status. Each observation is held in a `DiagnosticResult` with its own status, duration, details and optional structured error.

Interpretation is emitted as a `DiagnosticFinding`. A finding has an ID, severity, explanation, evidence and suggested recommendations. Recommendations are possible investigative actions, not claims that a particular Azure resource is misconfigured.

`DiagnosticStatus` describes execution (`Passed`, `Failed`, `Warning`, `Skipped`, `NotApplicable`, `Inconclusive`). `FindingSeverity` independently describes the importance of a finding. The report summary separately records overall status, network connectivity and authentication state. For example, an HTTP 401 produces healthy network connectivity and a warning that authentication was not supplied or accepted.

Reports serialize with schema version `1.0`. The command exit code is 0 for completed checks without blocking failures, 1 for connectivity failure, 2 for invalid input, 3 for cancellation/inconclusive execution and 4 for unexpected internal errors.