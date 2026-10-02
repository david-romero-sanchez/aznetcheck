# AzNetCheck

AzNetCheck is a .NET 10 command-line diagnostic tool for investigating connectivity to Microsoft Azure endpoints. It examines DNS, address classification, TCP, TLS certificate validation and HTTP independently, then explains what the observations do and do not establish. An HTTP 401 or 403 is an application-layer response, not a TCP failure.

The initial release is local and read-only. It does not sign in to Azure, change resources, modify network configuration or send telemetry.

## Build and test

```powershell
dotnet build AzNetCheck.sln
dotnet test AzNetCheck.sln
```

The integration test project is separate. Its public DNS check runs only when `AZNETCHECK_RUN_INTEGRATION=1` is set.

## Usage

```text
aznetcheck check <target> [--service <id>] [--port <port>] [--timeout <seconds>] [--json] [--verbose]
aznetcheck detect <target> [--service <id>] [--json]
aznetcheck dns <target> [--timeout <seconds>] [--json]
aznetcheck tcp <target> [--port <port>] [--timeout <seconds>] [--json]
aznetcheck tls <target> [--port <port>] [--timeout <seconds>] [--json]
aznetcheck http <url> [--timeout <seconds>] [--json]
aznetcheck catalog list
aznetcheck catalog show <service>
aznetcheck version
```

Examples:

```powershell
dotnet run --project src/AzNetCheck.Cli -- check contoso.vault.azure.net
dotnet run --project src/AzNetCheck.Cli -- check https://contoso.vault.azure.net --json
dotnet run --project src/AzNetCheck.Cli -- check internal-vault.corp --service keyvault --port 443
dotnet run --project src/AzNetCheck.Cli -- tcp myserver.database.windows.net --port 1433
```

Targets can be hostnames, `hostname:port`, HTTP(S) URLs, IPv4 or bracketed IPv6 with a port. `--timeout` applies the same per-stage timeout in seconds (maximum 300). `--no-color` is accepted; the initial renderer is plain text and never depends on color. JSON mode emits only the versioned report on standard output. Diagnostics exit with `0` when completed without blocking failures (warnings included), `1` for a connectivity failure, `2` for invalid input, `3` for cancellation/inconclusive completion, and `4` for an unexpected internal error.

## Supported services

The embedded JSON catalog recognizes Azure Key Vault, Blob/File/Queue/Table Storage, Data Lake Storage, Azure SQL Database, Service Bus, Event Hubs, Container Registry and App Service. Service Bus and Event Hubs share a DNS suffix, so hostname-only detection may correctly report ambiguity. Unknown hostnames continue with generic diagnostics. `--service` forces a profile for custom DNS aliases.

The automatic check tests HTTPS/TCP transports. Azure Files SMB and AMQP ports are represented in the catalog but are not automatically probed; choose an explicit port with `tcp` when needed. Authentication and service-specific authorization probes are not implemented in this first increment.

## Security and limitations

AzNetCheck does not invoke shell commands, scan address ranges, send credentials, print HTTP request secrets or disable certificate validation. HTTP uses a non-destructive GET and the platform-configured `HttpClient` proxy; direct TCP/TLS checks do not use that proxy, so their outcomes can differ. HTTP redirects are reported rather than followed. The `--debug` option is reserved for internal details and should never be used to expose credentials; diagnostic requests currently send no credentials.

The initial version uses standard system trust and hostname validation. It does not yet support custom catalog files, Azure Identity, interactive authentication, Windows WinHTTP inspection or Azure Resource Manager configuration inspection.

## Publishing

Publish the self-contained single-file Windows executable without trimming:

```powershell
dotnet publish src/AzNetCheck.Cli/AzNetCheck.Cli.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:PublishTrimmed=false
```

The executable is `aznetcheck.exe` under `src/AzNetCheck.Cli/bin/Release/net10.0/win-x64/publish/`. The `win-x64` publish profile is also available through `-p:PublishProfile=win-x64`.# aznetcheck