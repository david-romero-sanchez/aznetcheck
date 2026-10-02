# Adding a service

1. Add an entry to `src/AzNetCheck.Azure/service-catalog.json` with a stable ID and display name.
2. Add verified public hostname and Private Link patterns. Keep ambiguous suffixes ambiguous unless other evidence distinguishes them.
3. Describe each transport with its documented protocol, port, required/optional state and purpose. Do not infer undocumented ports.
4. Set the default protocol and safe HTTP method metadata; use `tcp` for services such as Azure SQL that do not use HTTP on their data endpoint.
5. Add an authentication scope only when verified. Do not make authentication automatic.
6. Add detection and transport tests under `tests/AzNetCheck.Azure.Tests` and Core parser/rule tests as appropriate.
7. Add a specialized `IServiceDiagnosticProbe` only when generic DNS/TCP/TLS/HTTP evidence cannot answer a service-specific question.
8. Update the supported-services table in the README and run `dotnet build AzNetCheck.sln` and `dotnet test AzNetCheck.sln`.