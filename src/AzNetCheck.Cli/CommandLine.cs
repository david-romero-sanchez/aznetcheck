using System.CommandLine;
using System.Globalization;
using System.Net;
using System.Text.Json;
using AzNetCheck.Azure;
using AzNetCheck.Core;
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

    private static async Task<int> RunCommandLineAsync(string[] args)
    {
        var root = BuildRootCommand();
        var parseArguments = args.Length == 0 ? ["--help"] : args;
        var parseResult = root.Parse(parseArguments);
        if (parseResult.Errors.Count > 0)
        {
            var errorConsole = CreateConsole(args.Contains("--no-color", StringComparer.Ordinal), Console.Error);
            foreach (var error in parseResult.Errors)
                errorConsole.MarkupLine($"[red]Error:[/] {Markup.Escape(error.Message)}");
            return 2;
        }

        var invocationConfiguration = new InvocationConfiguration
        {
            EnableDefaultExceptionHandler = false,
            ProcessTerminationTimeout = TimeSpan.FromSeconds(2)
        };
        return await parseResult.InvokeAsync(invocationConfiguration).ConfigureAwait(false);
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

        var version = new Command("version", "Display the AzNetCheck version.");
        version.SetAction(_ =>
        {
            Console.Out.WriteLine("AzNetCheck 0.1.0");
            return 0;
        });

        root.Subcommands.Add(check);
        root.Subcommands.Add(detect);
        root.Subcommands.Add(dns);
        root.Subcommands.Add(tcp);
        root.Subcommands.Add(tls);
        root.Subcommands.Add(http);
        root.Subcommands.Add(catalogCommand);
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
            Console.Out.WriteLine(JsonSerializer.Serialize(catalog.Services, JsonOptions));
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
        if (json) Console.Out.WriteLine(JsonSerializer.Serialize(service, JsonOptions));
        else
        {
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
                    table.AddRow("", Markup.Escape($"{detail.Key}: {JsonSerializer.Serialize(detail.Value, JsonOptions)}"), "");
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