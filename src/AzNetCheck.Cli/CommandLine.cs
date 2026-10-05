using System.CommandLine;
using System.Globalization;
using System.Net;
using AzNetCheck.Azure;
using AzNetCheck.Core;
using AzNetCheck.Updater;
using Spectre.Console;

namespace AzNetCheck.Cli;

internal static partial class Program
{
    private sealed record OutputOptions(Option<bool> Json, Option<bool> NoColor, Option<bool> Debug);

    private sealed record DiagnosticOptions(
        OutputOptions Output,
        Option<string?>? Service = null,
        Option<string?>? Port = null,
        Option<string?>? Timeout = null,
        Option<bool>? Ipv4 = null,
        Option<bool>? Ipv6 = null,
        Option<bool>? Verbose = null);

    private static async Task<int> RunCommandLineAsync(string[] args, string? postUpdateTransactionPath = null)
    {
        if (args.Length == 0 && postUpdateTransactionPath is null)
        {
            RenderOverview();
            return 0;
        }

        var root = BuildRootCommand();
        if (postUpdateTransactionPath is not null)
        {
            if (args.Length == 0)
            {
                RenderOverview();
                return await CreateUpdateInstaller().ConfirmHealthAsync(postUpdateTransactionPath).ConfigureAwait(false)
                    ? 0 : 4;
            }
            if (!await CreateUpdateInstaller().ConfirmHealthAsync(postUpdateTransactionPath).ConfigureAwait(false)) return 4;
        }
        var parseResult = root.Parse(args);
        if (parseResult.Errors.Count > 0)
        {
            var noColor = args.Contains("--no-color", StringComparer.Ordinal);
            foreach (var error in parseResult.Errors)
            {
                if (noColor) Console.Error.WriteLine($"Error: {error.Message}");
                else CreateConsole(noColor, Console.Error).MarkupLine($"[red]Error:[/] {Markup.Escape(error.Message)}");
            }
            return 2;
        }

        var invocationConfiguration = new InvocationConfiguration
        {
            EnableDefaultExceptionHandler = false,
            ProcessTerminationTimeout = TimeSpan.FromSeconds(2)
        };
        return await parseResult.InvokeAsync(invocationConfiguration).ConfigureAwait(false);
    }

    private static void RenderOverview()
    {
        var console = CreateConsole(noColor: false);
        console.MarkupLine($"[bold deepskyblue1]AzNetCheck[/] [grey]{GetCurrentVersion()}[/]");
        console.MarkupLine("Diagnoses connectivity from this machine to Microsoft Azure services.");
        console.MarkupLine("Interprets each layer independently: HTTP 401/403 confirms the endpoint was reached; it is not a TCP failure.");

        var capabilities = new Table().Border(TableBorder.Rounded).Title("What it checks");
        capabilities.AddColumn("Capability");
        capabilities.AddColumn("Details");
        capabilities.AddRow("Azure service detection", "Recognizes known profiles; use --service for custom DNS aliases.");
        capabilities.AddRow("DNS and Private Link", "Queries A/AAAA, preserves CNAME chains, and reports Private Link indicators.");
        capabilities.AddRow("Network", "Classifies IP addresses and records TCP attempts per address, including partial connectivity.");
        capabilities.AddRow("TLS and certificates", "Validates the handshake, hostname, and chain; reports protocol and certificate details.");
        capabilities.AddRow("HTTP", "Sends a non-destructive GET and interprets 401, 403, and other statuses separately from network connectivity.");
        capabilities.AddRow("Results", "Provides findings, recommendations, versioned JSON, and exit codes.");
        console.Write(capabilities);

        var commands = new Table().Border(TableBorder.Rounded).Title("Commands");
        commands.AddColumn("Command");
        commands.AddColumn("Purpose");
        commands.AddRow("check <target>", "Runs the complete layered diagnostic.");
        commands.AddRow("detect <target>", "Detects an Azure profile or reports Unknown/Ambiguous.");
        commands.AddRow("dns <target>", "Resolves A/AAAA records and displays the CNAME chain.");
        commands.AddRow("tcp <target>", "Tests TCP connectivity; supports --port and --service.");
        commands.AddRow("tls <target>", "Tests TLS and validates the server certificate.");
        commands.AddRow("http <url>", "Sends a safe GET request and displays the HTTP status.");
        commands.AddRow("catalog", "Lists profiles; equivalent to catalog list.");
        commands.AddRow("catalog show <service>", "Displays profile transports and authentication scope.");
        commands.AddRow("update check (optional --force)", "Checks GitHub Releases for a newer signed stable version.");
        commands.AddRow("update apply (optional --force)", "Downloads, verifies, installs, and rolls back if first start fails.");
        commands.AddRow("version", "Displays the application version.");
        console.Write(commands);

        var options = new Table().Border(TableBorder.Rounded).Title("Options");
        options.AddColumn("Option");
        options.AddColumn("Available for");
        options.AddColumn("Purpose");
        options.AddRow("--json", "Diagnostic, catalog, and update commands", "Writes JSON without tables or additional text.");
        options.AddRow("--no-color", "Diagnostic, catalog, and update commands", "Disables ANSI styling.");
        options.AddRow("--debug", "Diagnostic, catalog, and update commands", "Adds a safe exception type to internal error output.");
        options.AddRow("--timeout <seconds>", "check, dns, tcp, tls, http", "Per-stage timeout; greater than 0 and at most 300 seconds.");
        options.AddRow("--service <id>", "check, detect, tcp", "Forces a profile for a DNS alias.");
        options.AddRow("--port <port>", "check, tcp, tls, http", "Overrides the port (1-65535).");
        options.AddRow("--ipv4 / --ipv6", "check, dns, tcp, tls", "Restricts addresses to one family; do not combine.");
        options.AddRow("--verbose", "check", "Includes detailed diagnostic evidence.");
        options.AddRow("--force", "update check/apply", "Bypasses the check interval; apply can retry a failed version.");
        options.AddRow("--help", "All commands", "Displays concise help and command options.");
        console.Write(options);

        console.MarkupLine("\n[bold]Examples[/]");
        console.MarkupLine("  aznetcheck check contoso.vault.azure.net");
        console.MarkupLine("  aznetcheck check https://contoso.vault.azure.net --json");
        console.MarkupLine("  aznetcheck check internal-vault.corp --service keyvault --ipv4");
        console.MarkupLine("  aznetcheck tcp myserver.database.windows.net --port 1433");
        console.MarkupLine("  aznetcheck catalog show keyvault");
        console.MarkupLine("  aznetcheck update check");
        console.MarkupLine("  aznetcheck update apply");
        console.MarkupLine("\n[grey]Read-only diagnostics; Azure authentication is not started and resources are not modified.[/]");
    }

    private static RootCommand BuildRootCommand()
    {
        var catalog = new AzureServiceCatalog();
        var root = new RootCommand("Diagnose connectivity from this machine to Microsoft Azure endpoints.");

        var check = new Command("check", "Run the layered connectivity diagnostic.");
        var checkTarget = AddTarget(check);
        var checkOptions = AddDiagnosticOptions(check, service: true, port: true, timeout: true,
            addressFamily: true, verbose: true);
        check.SetAction(async (parse, cancellationToken) =>
        {
            if (!TryReadTarget(parse, checkTarget, checkOptions.Port, out var target, out var error))
                return UsageError(error!, parse.GetValue(checkOptions.Output.NoColor));
            if (!TryReadAddressFamily(parse, checkOptions, out var family))
                return UsageError("Use only one of --ipv4 or --ipv6.", parse.GetValue(checkOptions.Output.NoColor));
            var values = ReadOptions(parse, checkOptions);
            return await CheckAsync(target!, values, catalog, GetTimeout(parse, checkOptions), family,
                cancellationToken).ConfigureAwait(false);
        });

        var detect = new Command("detect", "Identify a matching Azure service profile.");
        var detectTarget = AddTarget(detect);
        var detectOptions = AddDiagnosticOptions(detect, service: true);
        detect.SetAction(parse =>
        {
            if (!TryReadTarget(parse, detectTarget, null, out var target, out var error))
                return UsageError(error!, parse.GetValue(detectOptions.Output.NoColor));
            return DetectCommand(target!, ReadOptions(parse, detectOptions), catalog);
        });

        var dns = new Command("dns", "Resolve A/AAAA addresses and CNAMEs.");
        var dnsTarget = AddTarget(dns);
        var dnsOptions = AddDiagnosticOptions(dns, timeout: true, addressFamily: true);
        dns.SetAction(async (parse, cancellationToken) =>
        {
            if (!TryReadTarget(parse, dnsTarget, null, out var target, out var error))
                return UsageError(error!, parse.GetValue(dnsOptions.Output.NoColor));
            if (!TryReadAddressFamily(parse, dnsOptions, out var family))
                return UsageError("Use only one of --ipv4 or --ipv6.", parse.GetValue(dnsOptions.Output.NoColor));
            return await DnsCommandAsync(target!, ReadOptions(parse, dnsOptions), GetTimeout(parse, dnsOptions),
                family, cancellationToken).ConfigureAwait(false);
        });

        var tcp = new Command("tcp", "Test a TCP connection to the target port.");
        var tcpTarget = AddTarget(tcp);
        var tcpOptions = AddDiagnosticOptions(tcp, service: true, port: true, timeout: true, addressFamily: true);
        tcp.SetAction(async (parse, cancellationToken) =>
        {
            if (!TryReadTarget(parse, tcpTarget, tcpOptions.Port, out var target, out var error))
                return UsageError(error!, parse.GetValue(tcpOptions.Output.NoColor));
            if (!TryReadAddressFamily(parse, tcpOptions, out var family))
                return UsageError("Use only one of --ipv4 or --ipv6.", parse.GetValue(tcpOptions.Output.NoColor));
            return await TcpCommandAsync(target!, ReadOptions(parse, tcpOptions), catalog,
                GetTimeout(parse, tcpOptions), family, cancellationToken).ConfigureAwait(false);
        });

        var tls = new Command("tls", "Perform a validated TLS handshake and inspect the certificate.");
        var tlsTarget = AddTarget(tls);
        var tlsOptions = AddDiagnosticOptions(tls, port: true, timeout: true, addressFamily: true);
        tls.SetAction(async (parse, cancellationToken) =>
        {
            if (!TryReadTarget(parse, tlsTarget, tlsOptions.Port, out var target, out var error))
                return UsageError(error!, parse.GetValue(tlsOptions.Output.NoColor));
            if (!TryReadAddressFamily(parse, tlsOptions, out var family))
                return UsageError("Use only one of --ipv4 or --ipv6.", parse.GetValue(tlsOptions.Output.NoColor));
            return await TlsCommandAsync(target!, ReadOptions(parse, tlsOptions), GetTimeout(parse, tlsOptions),
                family, cancellationToken).ConfigureAwait(false);
        });

        var http = new Command("http", "Send a non-destructive HTTP GET request.");
        var httpTarget = AddTarget(http);
        var httpOptions = AddDiagnosticOptions(http, port: true, timeout: true);
        http.SetAction(async (parse, cancellationToken) =>
        {
            if (!TryReadTarget(parse, httpTarget, httpOptions.Port, out var target, out var error))
                return UsageError(error!, parse.GetValue(httpOptions.Output.NoColor));
            return await HttpCommandAsync(target!, ReadOptions(parse, httpOptions), GetTimeout(parse, httpOptions),
                cancellationToken).ConfigureAwait(false);
        });

        var catalogCommand = new Command("catalog", "List or inspect embedded Azure service profiles.");
        var catalogOutput = AddOutputOptions(catalogCommand);
        catalogCommand.SetAction(parse => CatalogList(catalog, parse.GetValue(catalogOutput.Json),
            parse.GetValue(catalogOutput.NoColor)));
        var list = new Command("list", "List all known service profiles.");
        var listOutput = AddOutputOptions(list);
        list.SetAction(parse => CatalogList(catalog, parse.GetValue(listOutput.Json),
            parse.GetValue(listOutput.NoColor)));
        var show = new Command("show", "Show a service profile by ID or alias.");
        var serviceName = new Argument<string>("service") { Description = "Service ID or alias, for example keyvault." };
        show.Arguments.Add(serviceName);
        var showOutput = AddOutputOptions(show);
        show.SetAction(parse => CatalogShow(catalog, parse.GetValue(serviceName) ?? string.Empty,
            parse.GetValue(showOutput.Json), parse.GetValue(showOutput.NoColor)));
        catalogCommand.Subcommands.Add(list);
        catalogCommand.Subcommands.Add(show);

        var updateCommand = new Command("update", "Check for and apply verified updates from GitHub Releases.");
        var updateCheck = new Command("check", "Check GitHub Releases for a newer stable version.");
        var updateCheckOutput = AddOutputOptions(updateCheck);
        var updateCheckForce = new Option<bool>("--force") { Description = "Ignore the check interval and failed-version block." };
        updateCheck.Options.Add(updateCheckForce);
        updateCheck.SetAction(async (parse, cancellationToken) =>
        {
            var result = await CreateUpdateManager().CheckForUpdatesAsync(parse.GetValue(updateCheckForce), cancellationToken)
                .ConfigureAwait(false);
            return RenderUpdateCheckResult(result, parse.GetValue(updateCheckOutput.Json),
                parse.GetValue(updateCheckOutput.NoColor));
        });

        var updateApply = new Command("apply", "Download, verify, and transactionally install the latest stable release.");
        var updateApplyOutput = AddOutputOptions(updateApply);
        var updateApplyForce = new Option<bool>("--force") { Description = "Retry a version previously marked as failed." };
        updateApply.Options.Add(updateApplyForce);
        updateApply.SetAction(async (parse, cancellationToken) =>
        {
            var result = await CreateUpdateManager().ApplyLatestAsync(parse.GetValue(updateApplyForce), cancellationToken)
                .ConfigureAwait(false);
            return RenderUpdateApplyResult(result, parse.GetValue(updateApplyOutput.Json),
                parse.GetValue(updateApplyOutput.NoColor));
        });
        updateCommand.Subcommands.Add(updateCheck);
        updateCommand.Subcommands.Add(updateApply);

        var version = new Command("version", "Display the AzNetCheck version.");
        version.SetAction(_ =>
        {
            Console.Out.WriteLine($"AzNetCheck {GetCurrentVersion()}");
            return 0;
        });

        root.Subcommands.Add(check);
        root.Subcommands.Add(detect);
        root.Subcommands.Add(dns);
        root.Subcommands.Add(tcp);
        root.Subcommands.Add(tls);
        root.Subcommands.Add(http);
        root.Subcommands.Add(catalogCommand);
        root.Subcommands.Add(updateCommand);
        root.Subcommands.Add(version);
        return root;
    }

    private static Argument<string> AddTarget(Command command)
    {
        var target = new Argument<string>("target") { Description = "Hostname, hostname:port, HTTP(S) URL, IPv4 or IPv6." };
        command.Arguments.Add(target);
        return target;
    }

    private static DiagnosticOptions AddDiagnosticOptions(Command command, bool service = false, bool port = false,
        bool timeout = false, bool addressFamily = false, bool verbose = false)
    {
        var output = AddOutputOptions(command);
        Option<string?>? serviceOption = null;
        Option<string?>? portOption = null;
        Option<string?>? timeoutOption = null;
        Option<bool>? ipv4Option = null;
        Option<bool>? ipv6Option = null;
        Option<bool>? verboseOption = null;

        if (service)
        {
            serviceOption = new Option<string?>("--service") { Description = "Force a catalog service profile." };
            command.Options.Add(serviceOption);
        }
        if (port)
        {
            portOption = new Option<string?>("--port") { Description = "Override the target port (1-65535)." };
            portOption.Validators.Add(result =>
            {
                var value = result.GetValueOrDefault<string?>();
                if (value is not null && (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var portValue) ||
                    portValue is < 1 or > 65535))
                    result.AddError("Port must be an integer between 1 and 65535.");
            });
            command.Options.Add(portOption);
        }
        if (timeout)
        {
            timeoutOption = new Option<string?>("--timeout")
            {
                Description = "Per-stage timeout in seconds (greater than 0, maximum 300)."
            };
            timeoutOption.Validators.Add(result =>
            {
                var value = result.GetValueOrDefault<string?>();
                if (value is not null && (!double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out var seconds) ||
                    seconds <= 0 || seconds > 300))
                    result.AddError("Timeout must be a number greater than 0 and at most 300 seconds.");
            });
            command.Options.Add(timeoutOption);
        }
        if (addressFamily)
        {
            ipv4Option = new Option<bool>("--ipv4") { Description = "Only test IPv4 addresses." };
            ipv6Option = new Option<bool>("--ipv6") { Description = "Only test IPv6 addresses." };
            command.Options.Add(ipv4Option);
            command.Options.Add(ipv6Option);
        }
        if (verbose)
        {
            verboseOption = new Option<bool>("--verbose") { Description = "Show detailed diagnostic evidence." };
            command.Options.Add(verboseOption);
        }
        return new DiagnosticOptions(output, serviceOption, portOption, timeoutOption, ipv4Option, ipv6Option, verboseOption);
    }

    private static OutputOptions AddOutputOptions(Command command)
    {
        var json = new Option<bool>("--json") { Description = "Write machine-readable JSON to stdout." };
        var noColor = new Option<bool>("--no-color") { Description = "Disable terminal styling." };
        var debug = new Option<bool>("--debug") { Description = "Include safe internal diagnostic context on errors." };
        command.Options.Add(json);
        command.Options.Add(noColor);
        command.Options.Add(debug);
        return new OutputOptions(json, noColor, debug);
    }

    private static Dictionary<string, string?> ReadOptions(System.CommandLine.ParseResult parse,
        DiagnosticOptions options)
    {
        var values = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        if (parse.GetValue(options.Output.Json)) values["json"] = null;
        if (parse.GetValue(options.Output.NoColor)) values["no-color"] = null;
        if (parse.GetValue(options.Output.Debug)) values["debug"] = null;
        if (options.Service is not null && parse.GetValue(options.Service) is { } service) values["service"] = service;
        if (options.Port is not null && parse.GetValue(options.Port) is { } port)
            values["port"] = port;
        if (options.Timeout is not null)
            values["timeout"] = parse.GetValue(options.Timeout);
        if (options.Ipv4 is not null && parse.GetValue(options.Ipv4)) values["ipv4"] = null;
        if (options.Ipv6 is not null && parse.GetValue(options.Ipv6)) values["ipv6"] = null;
        if (options.Verbose is not null && parse.GetValue(options.Verbose)) values["verbose"] = null;
        return values;
    }

    private static bool TryReadTarget(System.CommandLine.ParseResult parse, Argument<string> argument,
        Option<string?>? portOption, out DiagnosticTarget? target, out string? error)
    {
        var input = parse.GetValue(argument);
        if (input is null)
        {
            target = null;
            error = "A target is required.";
            return false;
        }
        if (!DiagnosticTargetParser.TryParse(input, out target, out error)) return false;
        if (portOption is not null && parse.GetValue(portOption) is { } portText &&
            int.TryParse(portText, NumberStyles.None, CultureInfo.InvariantCulture, out var port))
            target = target! with { ExplicitPort = port, EffectivePort = port };
        return true;
    }

    private static bool TryReadAddressFamily(System.CommandLine.ParseResult parse, DiagnosticOptions options,
        out DiagnosticAddressFamily addressFamily)
    {
        var ipv4 = options.Ipv4 is not null && parse.GetValue(options.Ipv4);
        var ipv6 = options.Ipv6 is not null && parse.GetValue(options.Ipv6);
        addressFamily = ipv4 ? DiagnosticAddressFamily.IPv4 : ipv6 ? DiagnosticAddressFamily.IPv6 : DiagnosticAddressFamily.Any;
        return !(ipv4 && ipv6);
    }

    private static TimeSpan GetTimeout(System.CommandLine.ParseResult parse, DiagnosticOptions options) =>
        TimeSpan.FromSeconds(options.Timeout is not null && double.TryParse(parse.GetValue(options.Timeout),
            NumberStyles.Float, CultureInfo.InvariantCulture, out var seconds) ? seconds : 4);

    private static int CatalogList(AzureServiceCatalog catalog, bool json, bool noColor)
    {
        if (json)
        {
            Console.Out.WriteLine(SerializeJson(catalog.Services));
            return 0;
        }
        var table = new Table().Border(TableBorder.Rounded);
        table.AddColumn("ID");
        table.AddColumn("Service");
        foreach (var service in catalog.Services)
            table.AddRow(Markup.Escape(service.Id), Markup.Escape(service.DisplayName));
        CreateConsole(noColor).Write(table);
        return 0;
    }

    private static int CatalogShow(AzureServiceCatalog catalog, string name, bool json, bool noColor)
    {
        var normalized = NormalizeServiceName(name);
        var service = catalog.Services.FirstOrDefault(candidate =>
            NormalizeServiceName(candidate.Id) == normalized || NormalizeServiceName(candidate.DisplayName) == normalized);
        if (service is null) return UsageError($"No catalog service matches '{name}'.", noColor);
        if (json) Console.Out.WriteLine(SerializeJson(service));
        else
        {
            if (noColor)
            {
                Console.Out.WriteLine($" {service.DisplayName}");
                Console.Out.WriteLine("Transport | Protocol | Port | Required");
                foreach (var transport in service.Transports)
                    Console.Out.WriteLine($"{transport.Name} | {transport.Protocol} | " +
                        $"{(transport.PortEnd is int end ? $"{transport.Port}-{end}" : transport.Port.ToString(CultureInfo.InvariantCulture))} | " +
                        (transport.Required ? "yes" : "optional"));
                if (service.AuthenticationScope is not null)
                    Console.Out.WriteLine($"Authentication scope: {service.AuthenticationScope}");
                return 0;
            }

            var console = CreateConsole(noColor);
            console.MarkupLine($"[bold] {Markup.Escape(service.DisplayName)}[/]");
            var table = new Table().Border(TableBorder.Rounded);
            table.AddColumn("Transport");
            table.AddColumn("Protocol");
            table.AddColumn("Port");
            table.AddColumn("Required");
            foreach (var transport in service.Transports)
                table.AddRow(Markup.Escape(transport.Name), Markup.Escape(transport.Protocol),
                    transport.PortEnd is int end ? $"{transport.Port}-{end}" : transport.Port.ToString(CultureInfo.InvariantCulture),
                    transport.Required ? "yes" : "optional");
            console.Write(table);
            if (service.AuthenticationScope is not null)
                console.MarkupLine($"Authentication scope: {Markup.Escape(service.AuthenticationScope)}");
        }
        return 0;
    }

    private static string NormalizeServiceName(string value)
    {
        var normalized = string.Concat(value.Where(char.IsLetterOrDigit));
        return normalized.StartsWith("azure", StringComparison.OrdinalIgnoreCase) ? normalized[5..] : normalized;
    }

    private static int RenderUpdateCheckResult(UpdateCheckResult result, bool json, bool noColor)
    {
        if (json) Console.Out.WriteLine(SerializeJson(result));
        else
        {
            var console = CreateConsole(noColor);
            switch (result.Status)
            {
                case UpdateCheckStatus.UpdateAvailable:
                    console.MarkupLine($"[green]Update available:[/] AzNetCheck {Markup.Escape(result.Manifest!.Version)}");
                    console.MarkupLine("Run 'aznetcheck update apply' to download, verify, and install it.");
                    break;
                case UpdateCheckStatus.UpToDate:
                    console.MarkupLine("[green]AzNetCheck is up to date.[/]");
                    break;
                case UpdateCheckStatus.CheckSkippedRecently:
                    console.MarkupLine("Update check skipped; the last check is within its interval. Use --force to check now.");
                    break;
                case UpdateCheckStatus.UpdateBlockedAfterFailure:
                    console.MarkupLine($"[yellow]Update blocked:[/] {Markup.Escape(result.Error ?? "This version previously failed.")}");
                    break;
                case UpdateCheckStatus.UnsupportedPlatform:
                    console.MarkupLine($"[yellow]Unsupported platform:[/] {Markup.Escape(result.Error ?? "No update asset is configured.")}");
                    break;
                default:
                    console.MarkupLine($"[red]Update check failed:[/] {Markup.Escape(result.Error ?? result.Status.ToString())}");
                    break;
            }
        }
        return result.Status switch
        {
            UpdateCheckStatus.CheckFailed or UpdateCheckStatus.InvalidManifest => 3,
            UpdateCheckStatus.UnsupportedPlatform => 2,
            _ => 0
        };
    }

    private static int RenderUpdateApplyResult(UpdateApplyResult result, bool json, bool noColor)
    {
        if (json) Console.Out.WriteLine(SerializeJson(result));
        else
        {
            var console = CreateConsole(noColor);
            var message = result.Message ?? result.Error ?? result.Status.ToString();
            var successful = result.Status is UpdateApplyStatus.Started or UpdateApplyStatus.AlreadyCurrent;
            console.MarkupLine(successful
                ? $"[green]{Markup.Escape(message)}[/]"
                : $"[red]Update failed:[/] {Markup.Escape(message)}");
        }
        return result.Status switch
        {
            UpdateApplyStatus.Started or UpdateApplyStatus.AlreadyCurrent => 0,
            UpdateApplyStatus.InstallationNotSupported or UpdateApplyStatus.UnsupportedPlatform => 2,
            UpdateApplyStatus.CheckFailed or UpdateApplyStatus.InvalidManifest => 3,
            _ => 1
        };
    }

    private static void RenderReport(DiagnosticReport report, bool verbose, bool noColor)
    {
        var console = CreateConsole(noColor);
        console.MarkupLine("[bold]AzNetCheck[/]");
        console.Write(new Rule());
        console.MarkupLine($"[bold]Target[/]  {Markup.Escape(report.Target.OriginalInput)}");
        console.MarkupLine($"[bold]Service[/] {Markup.Escape(report.Service.Service?.DisplayName ?? "Unknown")}");
        if (report.Service.Service is null) console.MarkupLine("Generic diagnostics will be performed.");

        var table = new Table().Border(TableBorder.None);
        table.AddColumn("Test");
        table.AddColumn("Status");
        table.AddColumn(new TableColumn("Duration").RightAligned());
        foreach (var result in report.Results)
        {
            var duration = result.Duration > TimeSpan.Zero ? $"{result.Duration.TotalMilliseconds:0} ms" : "";
            table.AddRow(Markup.Escape(result.DisplayName), StatusMarkup(result.Status), duration);
            if (result.Summary is not null)
                table.AddRow("", Markup.Escape(result.Summary), "");
            if (verbose)
                foreach (var detail in result.Details)
                    table.AddRow("", Markup.Escape($"{detail.Key}: {FormatDetailValue(detail.Value)}"), "");
        }
        console.Write(table);

        if (report.Findings.Count > 0)
        {
            console.MarkupLine("\n[bold]Findings[/]");
            foreach (var finding in report.Findings)
            {
                console.MarkupLine($"{SeverityMarkup(finding.Severity)} {Markup.Escape(finding.Title)}");
                console.MarkupLine($"  {Markup.Escape(finding.Description)}");
                foreach (var recommendation in finding.Recommendations)
                    console.MarkupLine($"  Suggested check: {Markup.Escape(recommendation.Text)}");
            }
        }

        console.MarkupLine($"\n[bold]Overall result[/] {StatusMarkup(report.Summary.OverallStatus)}");
        console.MarkupLine($"Network connectivity: {StatusMarkup(report.Summary.NetworkConnectivity)}");
        console.MarkupLine(Markup.Escape(report.Summary.Message));
    }

    private static void RenderDetection(ServiceDetectionResult result, bool noColor)
    {
        var console = CreateConsole(noColor);
        console.MarkupLine($"[bold]Service[/] {Markup.Escape(result.Service?.DisplayName ?? result.Status.ToString())}");
        console.MarkupLine(Markup.Escape(result.Reason));
        if (result.Candidates.Count > 1)
            foreach (var candidate in result.Candidates)
                console.MarkupLine($"  - {Markup.Escape(candidate.DisplayName)}");
    }

    private static void RenderStandalone<T>(T result, bool noColor)
    {
        var console = CreateConsole(noColor);
        switch (result)
        {
            case DnsResolutionResult dns:
                console.MarkupLine($"[bold]DNS[/] {StatusMarkup(dns.Status)} ({dns.Duration.TotalMilliseconds:0} ms)");
                foreach (var cname in dns.CnameChain) console.MarkupLine($"  CNAME {Markup.Escape(cname)}");
                foreach (var address in dns.Addresses) console.MarkupLine($"  {Markup.Escape(address)}");
                if (dns.ErrorMessage is not null) console.MarkupLine($"  {Markup.Escape(dns.ErrorMessage)}");
                break;
            case IEnumerable<TcpProbeResult> attempts:
                foreach (var attempt in attempts)
                    console.MarkupLine($"TCP {Markup.Escape(attempt.Address)}:{attempt.Port} {StatusMarkup(attempt.Status)} " +
                        $"{attempt.Duration.TotalMilliseconds:0} ms {Markup.Escape(attempt.ErrorMessage ?? string.Empty)}");
                break;
            case TcpProbeResult tcp:
                console.MarkupLine($"TCP {Markup.Escape(tcp.Address)}:{tcp.Port} {StatusMarkup(tcp.Status)} " +
                    $"{tcp.Duration.TotalMilliseconds:0} ms {Markup.Escape(tcp.ErrorMessage ?? string.Empty)}");
                break;
            case TlsProbeResult tls:
                console.MarkupLine($"TLS {StatusMarkup(tls.Status)}: {Markup.Escape(tls.Protocol ?? tls.ErrorMessage ?? "unknown")}");
                if (tls.Subject is not null) console.MarkupLine($"  Certificate: {Markup.Escape(tls.Subject)}");
                if (tls.SubjectAlternativeNames is not null) console.MarkupLine($"  SAN: {Markup.Escape(tls.SubjectAlternativeNames)}");
                if (tls.NotAfter is not null) console.MarkupLine($"  Expires: {tls.NotAfter:O}");
                break;
            case HttpProbeResult http:
                console.MarkupLine($"HTTP {StatusMarkup(http.Status)} {http.StatusCode?.ToString(CultureInfo.InvariantCulture) ?? "failed"} " +
                    $"{Markup.Escape(http.ReasonPhrase ?? http.ErrorMessage ?? string.Empty)} ({http.Duration.TotalMilliseconds:0} ms)");
                if (http.RedirectLocation is not null) console.MarkupLine($"  Redirect: {Markup.Escape(http.RedirectLocation)}");
                break;
            default:
                console.WriteLine(result?.ToString() ?? string.Empty);
                break;
        }
    }

    private static IAnsiConsole CreateConsole(bool noColor, TextWriter? output = null) => AnsiConsole.Create(new AnsiConsoleSettings
    {
        Ansi = noColor ? AnsiSupport.No : AnsiSupport.Detect,
        ColorSystem = noColor ? ColorSystemSupport.Standard : ColorSystemSupport.Detect,
        Out = new AnsiConsoleOutput(output ?? Console.Out)
    });

    private static string StatusMarkup(DiagnosticStatus status) => status switch
    {
        DiagnosticStatus.Passed => "[green]PASS[/]",
        DiagnosticStatus.Failed => "[red]FAIL[/]",
        DiagnosticStatus.Warning => "[yellow]WARNING[/]",
        DiagnosticStatus.Skipped => "[grey]SKIPPED[/]",
        DiagnosticStatus.NotApplicable => "[aqua]N/A[/]",
        _ => "[grey]INCONCLUSIVE[/]"
    };

    private static string SeverityMarkup(FindingSeverity severity) => severity switch
    {
        FindingSeverity.Error => "[red]ERROR[/]",
        FindingSeverity.Warning => "[yellow]WARNING[/]",
        _ => "[grey]INFO[/]"
    };
}
