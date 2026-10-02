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

The GitHub-only update implementation is isolated in `src/AzNetCheck.Updater`; it does not depend on an update service or a third-party updater framework.

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
aznetcheck update check [--force] [--json] [--no-color]
aznetcheck update apply [--force] [--json] [--no-color]
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
- `aznetcheck update check` verifies the latest stable GitHub release manifest and reports whether an update exists. Checks are normally throttled for 24 hours; `--force` bypasses the interval and failed-version cooldown.
- `aznetcheck update apply` downloads and verifies the asset, then starts the same executable in a private updater mode. `--force` allows retrying a version that previously failed its first-start check.
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
aznetcheck update check
aznetcheck update apply
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

### Self-update safety

Self-update is supported only by the published, self-contained Windows `win-x64` `aznetcheck.exe`, running from a directory writable by the current user. Running under `dotnet`, a renamed executable, a non-Windows runtime, or a protected/non-writable install directory is refused before downloading or changing files. The updater does not request UAC elevation. A user-writable location such as `%LOCALAPPDATA%\Programs\AzNetCheck` or a writable portable folder is recommended.

The updater reads a small local state file below the current user's application data directory. It checks GitHub at most once per 24 hours by default, remembers versions that failed the first-start check for seven days, and permits a manual retry with `--force`. Installation takes a per-installation named lock. It stages and hashes the signed asset before launching the downloaded executable in a private internal mode, waits for the old process, creates a same-directory backup, atomically replaces the executable where the filesystem supports `File.Replace`, and waits for a first-start health handshake. If replacement or health confirmation fails, it restores the backup and attempts to restart the previous version. Interrupted transactions are recorded locally and recovery is attempted on the next normal launch, provided a runnable AzNetCheck executable starts. If the newly installed executable cannot start at all after a machine restart, the previous `.old` backup may require manual restoration. File and process operations are tested through fakes; filesystem/platform behavior can still vary by Windows filesystem and security policy.

Release assets use deterministic names. The current manifest supports `win-x64` only. `update.json.sig` is the Base64 encoding of an RSA PKCS#1 v1.5 SHA-256 signature followed by a newline. The signature covers the exact UTF-8 bytes of `update.json`; the client verifies it with the embedded PEM public key before parsing the manifest. It then validates the versioned GitHub release URL, expected runtime identifier, filename, declared size, and SHA-256 before executing the downloaded program. Stable clients use the GitHub `/releases/latest/download/` endpoint and do not consume prereleases.

### Configure release signing once

Generate a 3072-bit RSA keypair. The private key is written outside the repository under the current user's profile; the public key is written to the embedded resource path. Do this once and keep a secure backup of the private key.

```powershell
.\scripts\New-UpdateSigningKey.ps1
```

The script calls the .NET 10 key generator at `scripts/UpdateKeyGenerator`. If local PowerShell policy blocks scripts, invoke the generator directly instead:

```powershell
$privateKey = Join-Path $HOME ".aznetcheck\update-signing-private.pem"
$publicKey = "src\AzNetCheck.Updater\Keys\update-signing-public.pem"
dotnet run --project scripts/UpdateKeyGenerator/UpdateKeyGenerator.csproj -c Release -- $privateKey $publicKey
```

Commit only `src/AzNetCheck.Updater/Keys/update-signing-public.pem`. Never commit the private key. In GitHub, open **Repository Settings > Secrets and variables > Actions > New repository secret** and create the secret named exactly `UPDATE_SIGNING_PRIVATE_KEY_PEM` with the contents of the private PEM file. The release workflow refuses to publish without it and verifies the generated signature using the embedded public key, so a mismatched keypair fails before a release is created.

### Publish a release

After the public key and GitHub Actions secret are configured, create a SemVer tag and push it:

```powershell
git tag v1.4.0
git push origin v1.4.0
```

The release workflow validates the tag, runs restore/tests on Windows and Linux, then publishes `win-x64` as Release, self-contained, single-file, and untrimmed. It derives assembly/file/informational versions from the tag without the leading `v`, calculates the executable size and SHA-256, writes `update.json`, signs its exact bytes, verifies the signature, and creates the GitHub Release using the repository's `GITHUB_TOKEN` (`contents: write`). Tags such as `v1.4.0-beta.1` create prereleases; stable clients do not discover them through the `latest` endpoint.

The release assets are `aznetcheck-win-x64.exe`, `update.json`, and `update.json.sig`. Manifest URLs point to the version-specific release, never to `latest`.

```text
tag v1.4.0
  |
  v
GitHub Actions
  +--> validate tag and test
  +--> publish single-file win-x64
  +--> hash executable and create update.json
  +--> sign exact manifest bytes
  +--> verify signature with embedded public key
  |
  v
GitHub Release
  +--> aznetcheck-win-x64.exe
  +--> update.json
  +--> update.json.sig

Installed app
  +--> download and verify signed manifest
  +--> download and verify size and SHA-256
  +--> run downloaded executable as private updater
  +--> wait for old process and back up installation
  +--> replace and restart installed executable
  +--> confirm first start, or roll back
```

## Publishing for Windows

Publish a self-contained, single-file, untrimmed `win-x64` executable:

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

Trimming is intentionally disabled (`PublishTrimmed=false`) in both publish profiles. The application uses JSON serialization and console libraries, and the current release prioritizes reliable single-file publishing over a smaller executable. Do not enable trimming for production artifacts until the trimmed publish and all CLI/catalog/JSON/update flows have dedicated validation. Only `win-x64` is currently configured for self-update and release publishing.