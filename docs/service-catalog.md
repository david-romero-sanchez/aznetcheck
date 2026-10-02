# Service catalog

The initial catalog is the embedded `service-catalog.json` resource in `AzNetCheck.Azure`. Each service definition provides a stable ID, display name, hostname patterns, Private Link patterns, default protocol, optional Entra ID scope, safe HTTP method metadata and one or more transports. A transport records name, protocol, port, whether it is required, and a description; `portEnd` can represent a range.

Patterns beginning with `*.` match a non-empty subdomain followed by the exact suffix. Matching is case-insensitive. A hostname can match multiple services: the detector returns `Ambiguous` rather than guessing. An explicit service override accepts the catalog ID, display name or compact alias such as `keyvault`.

Transport lists allow a service to expose more than one path. Azure Files includes HTTPS and optional SMB/TCP 445. Service Bus and Event Hubs include HTTPS/TCP 443, AMQP/TLS 5671 and AMQP over WebSockets/TCP 443. The initial automatic plan probes the required transport only; optional transports are informational.

Catalog entries may describe future TLS requirements, OAuth scopes, private zones, probe rules and documentation links as the schema evolves. Runtime custom catalogs are not enabled in this release; catalog JSON is versioned with the application and embedded for offline use.