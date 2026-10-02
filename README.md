# AzNetCheck

AzNetCheck is a .NET 10 command-line tool for diagnosing connectivity from the current machine to Microsoft Azure endpoints. It evaluates DNS, IP addresses, TCP, TLS, certificate validation, and HTTP as separate layers, then turns the observations into findings and suggested checks.

The central diagnostic rule is that connectivity, authentication, and authorization are different outcomes. An HTTP `401` or `403` means an HTTP endpoint responded; neither status by itself means that TCP connectivity failed.

AzNetCheck is a local, read-only diagnostic tool. It does not modify Azure resources or local network configuration, does not scan address ranges, does not send credentials, and does not send telemetry. Authentication with Azure is not implemented in this version.

## Requirements

- .NET 10 SDK to build and run from source.
- Windows is the primary target. The implementation uses cross-platform .NET networking APIs and the CI workflow builds and tests on Windows and Linux.

## Build and test

```powershell
dotnet build AzNetCheck.sln --configuration Release
dotnet test AzNetCheck.sln --configuration Release
```

The integration-test project is included in `dotnet test`, but its public DNS test is opt-in. It runs only when `AZNETCHECK_RUN_INTEGRATION=1`; ordinary unit and CLI tests do not require Internet access.

The production solution is organized into four projects:

- `src/AzNetCheck.Cli`: System.CommandLine command parsing, dependency composition, Spectre.Console rendering, JSON output, and exit codes.
- `src/AzNetCheck.Core`: diagnostic models, interfaces, orchestration, findings, and summaries.
- `src/AzNetCheck.Networking`: DNS, TCP, TLS/certificate, and HTTP implementations.
- `src/AzNetCheck.Azure`: embedded Azure service catalog and service detection.

Tests are under `tests/`, including CLI process tests in `AzNetCheck.Cli.Tests`.

## Getting started

Running `aznetcheck` with no arguments displays an overview of the capabilities, commands, options, and examples. `aznetcheck --help` displays the concise command-tree help.

To run from the repository with the .NET SDK:

```powershell
dotnet run --project src/AzNetCheck.Cli -- check contoso.vault.azure.net
```

## Commands

```text
aznetcheck check <target> [--service <id>] [--port <port>] [--timeout <seconds>] [--ipv4 | --ipv6] [--json] [--verbose] [--no-color] [--debug]
aznetcheck detect <target> [--service <id>] [--json] [--no-color] [--debug]
aznetcheck dns <target> [--timeout <seconds>] [--ipv4 | --ipv6] [--json] [--no-color] [--debug]
aznetcheck tcp <target> [--service <id>] [--port <port>] [--timeout <seconds>] [--ipv4 | --ipv6] [--json] [--no-color] [--debug]
aznetcheck tls <target> [--port <port>] [--timeout <seconds>] [--ipv4 | --ipv6] [--json] [--no-color] [--debug]
aznetcheck http <url> [--port <port>] [--timeout <seconds>] [--json] [--no-color] [--debug]
aznetcheck catalog [list] [--json] [--no-color] [--debug]
aznetcheck catalog show <service> [--json] [--no-color] [--debug]
aznetcheck version
```

`aznetcheck catalog` and `aznetcheck catalog list` both list the embedded profiles. Use `catalog show` to inspect a profile's transports and authentication scope.

### Options

- `--service <id>` forces a known service profile for a custom hostname or DNS alias. Supported by `check`, `detect`, and `tcp`.
- `--port <port>` overrides the effective port. The value must be from 1 to 65535.
- `--timeout <seconds>` sets the same per-stage timeout for the command. The value must be greater than 0 and no more than 300 seconds. `check` applies it to DNS, TCP, TLS, and HTTP stages.
- `--ipv4` or `--ipv6` limits address selection to one family. Do not specify both. If no address in that family is available, the diagnostic is inconclusive and dependent tests are skipped.
- `--json` writes machine-readable JSON to standard output without the human-readable renderer. The diagnostic report uses schema version `1.0`.
- `--verbose` adds diagnostic evidence to the `check` display.
- `--no-color` disables ANSI styling in human-readable output.
- `--debug` includes the exception type for unexpected internal errors. It does not print secrets or credentials.
- `--help` displays help for the root command or an individual command.

## Examples

```powershell
aznetcheck check contoso.vault.azure.net
aznetcheck check https://contoso.vault.azure.net --json
aznetcheck check internal-vault.corp --service keyvault --port 443
aznetcheck check contoso.vault.azure.net --ipv4 --verbose
aznetcheck dns contoso.vault.azure.net
aznetcheck tcp myserver.database.windows.net --port 1433
aznetcheck tls contoso.vault.azure.net --port 443
aznetcheck http https://example.com
aznetcheck catalog
aznetcheck catalog show keyvault
```

Targets may be hostnames, `hostname:port`, HTTP/HTTPS URLs, IPv4 addresses, or IPv6 addresses. IPv6 literals with a port use brackets, for example `[2001:db8::1]:443`.

## Diagnostic behavior

The `check` pipeline identifies the Azure service when the hostname matches the embedded catalog, resolves DNS A/AAAA records and CNAMEs, classifies resolved addresses, detects Private Link indicators, tests TCP, validates TLS/certificates when applicable, and makes a non-destructive HTTP GET when the service uses HTTP.

Dependent tests are marked `Skipped` when a prerequisite fails. If several addresses resolve, TCP attempts are retained per address. A mixture of successful and failed attempts is reported as partial connectivity rather than as total failure. TLS connects to an address that passed TCP while retaining the original hostname for SNI and certificate validation.

The summary and findings distinguish evidence from interpretation and recommendations. For example:

- HTTP `401 Unauthorized`: the HTTPS endpoint responded; network connectivity is successful and authentication is reported as a warning. The result does not establish an RBAC problem.
- HTTP `403 Forbidden`: the endpoint responded but denied the request. Authorization settings and service network restrictions are possible causes; the status alone does not identify the cause.
- TCP `Connection refused`: the host actively rejected the selected port. This is reported separately from a timeout.
- Private Link CNAME or private IP followed by TCP failure: the report suggests investigating DNS links/forwarding, routing, VPN/ExpressRoute, and firewalls without claiming which component is misconfigured.

## Azure service catalog

The embedded JSON catalog includes:

- Azure Key Vault.
- Azure Blob, File, Queue, and Table Storage.
- Azure Data Lake Storage.
- Azure SQL Database.
- Azure Service Bus and Azure Event Hubs.
- Azure Container Registry.
- Azure App Service.

Service Bus and Event Hubs share a DNS suffix, so hostname-only detection may return `Ambiguous`. Use `--service` to choose a profile when diagnosing a custom alias. Unknown hostnames remain `Unknown` and can still use generic diagnostics.

The catalog represents multiple transports, including HTTPS/TCP 443, SQL/TCP 1433, SMB/TCP 445, and AMQP/TCP 5671 or 443. The automatic check probes the required transport; optional SMB and AMQP transports are catalog information and are not automatically tested. Use the `tcp` command with an explicit port to test a specific port.

## Output and exit codes

Human-readable output uses Spectre.Console tables and status labels. The status text remains meaningful when color is disabled. JSON mode bypasses that renderer and writes only the structured result to standard output.

Exit codes:

- `0`: diagnostics completed without a blocking failure; warnings do not automatically fail the command.
- `1`: one or more connectivity checks failed.
- `2`: invalid command, argument, option, or value.
- `3`: diagnostics were cancelled or inconclusive.
- `4`: unexpected internal error.

Ctrl+C is propagated through the System.CommandLine invocation cancellation token to asynchronous diagnostic operations.

## Security and limitations

- Network requests are diagnostic and non-destructive. HTTP uses GET; redirects are reported and are not followed.
- HTTP uses the platform-configured `HttpClient` proxy. TCP and TLS tests connect directly, so the results may differ when a proxy is present.
- Certificate validation uses the platform's normal trust and hostname validation. Certificate validation is not disabled by default.
- AzNetCheck does not print Authorization headers, cookies, tokens, client secrets, or HTTP query strings in diagnostic reports.
- This release does not implement Azure Identity authentication, interactive login, service-specific authorization probes, custom catalog loading, explicit proxy diagnostics, Windows WinHTTP inspection, or Azure Resource Manager configuration inspection.
- Optional Azure Files SMB and Service Bus/Event Hubs AMQP transports are not part of the automatic `check` sequence.

## Publishing for Windows

Publish a self-contained, single-file `win-x64` executable:

```powershell
dotnet publish src/AzNetCheck.Cli/AzNetCheck.Cli.csproj `
  --configuration Release `
  --runtime win-x64 `
  --self-contained true `
  -p:PublishSingleFile=true `
  -p:PublishTrimmed=false
```

The output includes `aznetcheck.exe` under `src/AzNetCheck.Cli/bin/Release/net10.0/win-x64/publish/`. A publish profile is also available:

```powershell
dotnet publish src/AzNetCheck.Cli/AzNetCheck.Cli.csproj -p:PublishProfile=win-x64
```

Trimming is intentionally disabled (`PublishTrimmed=false`). The application uses JSON serialization and console libraries, and the current release prioritizes reliable single-file publishing over a smaller executable. Do not enable trimming for production artifacts until the trimmed publish and all CLI/catalog/JSON flows have dedicated validation. The project is prepared for future runtime identifiers, but only `win-x64` is currently configured and verified for single-file publishing.