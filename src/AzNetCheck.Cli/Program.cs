using System.Text.Json;
using System.Text.Json.Serialization;
using AzNetCheck.Azure;
using AzNetCheck.Core;
using AzNetCheck.Networking;

namespace AzNetCheck.Cli;

internal static class Program
{
    private static readonly JsonSerializerOptions JsonOptions = CreateJsonOptions();

    public static async Task<int> Main(string[] args)
    {
        try
        {
            if (args.Length == 0 || args[0] is "--help" or "-h" or "help")
            {
                PrintHelp();
                return 0;
            }
            if (args[0] is "version" or "--version")
            {
                Console.WriteLine("AzNetCheck 0.1.0");
                return 0;
            }

            var catalog = new AzureServiceCatalog();
            if (args[0] == "catalog") return CatalogCommand(args.Skip(1).ToArray(), catalog);

            var command = args[0];
            if (args.Length < 2)
                return UsageError($"'{command}' requires a target.");
            var targetText = args[1];
            var options = ParseOptions(args.Skip(2).ToArray());
            if (!DiagnosticTargetParser.TryParse(targetText, out var target, out var parseError))
                return UsageError(parseError ?? "Invalid target.");
            var current = target!;
            if (options.TryGetValue("port", out var portValue))
            {
                if (!int.TryParse(portValue, out var port) || port is < 1 or > 65535)
                    return UsageError("--port must be between 1 and 65535.");
                current = current with { ExplicitPort = port, EffectivePort = port };
            }
            var timeout = TimeSpan.FromSeconds(4);
            if (options.TryGetValue("timeout", out var timeoutValue))
            {
                if (!double.TryParse(timeoutValue, System.Globalization.NumberStyles.Float,
                    System.Globalization.CultureInfo.InvariantCulture, out var seconds) || seconds <= 0 || seconds > 300)
                    return UsageError("--timeout must be a number of seconds between 0 and 300.");
                timeout = TimeSpan.FromSeconds(seconds);
            }
            using var cancellation = new CancellationTokenSource();
            Console.CancelKeyPress += (_, eventArgs) => { eventArgs.Cancel = true; cancellation.Cancel(); };

            return command switch
            {
                "check" => await CheckAsync(current, options, catalog, timeout, cancellation.Token).ConfigureAwait(false),
                "detect" => DetectCommand(current, options, catalog),
                "dns" => await DnsCommandAsync(current, options, timeout, cancellation.Token).ConfigureAwait(false),
                "tcp" => await TcpCommandAsync(current, options, catalog, timeout, cancellation.Token).ConfigureAwait(false),
                "tls" => await TlsCommandAsync(current, options, timeout, cancellation.Token).ConfigureAwait(false),
                "http" => await HttpCommandAsync(current, options, timeout, cancellation.Token).ConfigureAwait(false),
                _ => UsageError($"Unknown command '{command}'.")
            };
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("Diagnostic cancelled.");
            return 3;
        }
        catch (ArgumentException exception)
        {
            return UsageError(exception.Message);
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine("Unexpected diagnostic error.");
            if (args.Contains("--debug", StringComparer.Ordinal)) Console.Error.WriteLine($"Exception type: {exception.GetType().Name}");
            return 4;
        }
    }

    private static async Task<int> CheckAsync(DiagnosticTarget target, IReadOnlyDictionary<string, string?> options,
        AzureServiceCatalog catalog, TimeSpan timeout, CancellationToken cancellationToken)
    {
        using var http = new HttpClientDiagnostic();
        var engine = new DiagnosticEngine(catalog, new DnsClientDiagnostic(), new TcpSocketDiagnostic(),
            new TlsStreamDiagnostic(), http);
        var report = await engine.RunAsync(target, options.GetValueOrDefault("service"),
            new DiagnosticTimeouts(timeout, timeout, timeout, timeout), cancellationToken).ConfigureAwait(false);
        if (options.ContainsKey("json"))
        {
            Console.WriteLine(JsonSerializer.Serialize(report, JsonOptions));
        }
        else
        {
            PrintReport(report, options.ContainsKey("verbose"));
        }
        return report.Summary.OverallStatus == DiagnosticStatus.Failed ? 1 :
            report.Summary.OverallStatus == DiagnosticStatus.Inconclusive ? 3 : 0;
    }

    private static int DetectCommand(DiagnosticTarget target, IReadOnlyDictionary<string, string?> options, AzureServiceCatalog catalog)
    {
        var result = catalog.Detect(target.Hostname, options.GetValueOrDefault("service"));
        if (options.ContainsKey("json")) Console.WriteLine(JsonSerializer.Serialize(result, JsonOptions));
        else Console.WriteLine(result.Service is null ? $"Service: {result.Status}\n{result.Reason}" : $"Service: {result.Service.DisplayName}\n{result.Reason}");
        return result.Status == ServiceDetectionStatus.Unknown && options.ContainsKey("service") ? 2 : 0;
    }

    private static async Task<int> DnsCommandAsync(DiagnosticTarget target, IReadOnlyDictionary<string, string?> options,
        TimeSpan timeout, CancellationToken cancellationToken)
    {
        var result = await new DnsClientDiagnostic().ResolveAsync(target.Hostname, timeout, cancellationToken).ConfigureAwait(false);
        PrintOrSerialize(result, options);
        return result.Status == DiagnosticStatus.Failed ? 1 : 0;
    }

    private static async Task<int> TcpCommandAsync(DiagnosticTarget target, IReadOnlyDictionary<string, string?> options,
        AzureServiceCatalog catalog, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var dns = await new DnsClientDiagnostic().ResolveAsync(target.Hostname, timeout, cancellationToken).ConfigureAwait(false);
        var addresses = target.IpAddress is null ? dns.Addresses : [target.IpAddress.ToString()];
        var results = new List<TcpProbeResult>();
        var port = target.ExplicitPort ?? catalog.Detect(target.Hostname, options.GetValueOrDefault("service"))
            .Service?.Transports.FirstOrDefault(transport => transport.Required)?.Port ?? target.EffectivePort;
        foreach (var value in addresses.Take(8))
            if (System.Net.IPAddress.TryParse(value, out var address))
                results.Add(await new TcpSocketDiagnostic().ConnectAsync(address, port, timeout, cancellationToken).ConfigureAwait(false));
        PrintOrSerialize(results, options);
        return results.Any(result => result.Status == DiagnosticStatus.Passed) ? 0 : 1;
    }

    private static async Task<int> TlsCommandAsync(DiagnosticTarget target, IReadOnlyDictionary<string, string?> options,
        TimeSpan timeout, CancellationToken cancellationToken)
    {
        var result = await new TlsStreamDiagnostic().HandshakeAsync(target.Hostname, target.EffectivePort, timeout, cancellationToken).ConfigureAwait(false);
        PrintOrSerialize(result, options);
        return result.Status == DiagnosticStatus.Passed ? 0 : 1;
    }

    private static async Task<int> HttpCommandAsync(DiagnosticTarget target, IReadOnlyDictionary<string, string?> options,
        TimeSpan timeout, CancellationToken cancellationToken)
    {
        using var http = new HttpClientDiagnostic();
        var result = await http.ProbeAsync(target, timeout, cancellationToken).ConfigureAwait(false);
        PrintOrSerialize(result, options);
        return result.StatusCode is not null ? 0 : 1;
    }

    private static int CatalogCommand(string[] args, AzureServiceCatalog catalog)
    {
        if (args.Length == 0 || args[0] == "list")
        {
            foreach (var service in catalog.Services) Console.WriteLine($"{service.Id,-28} {service.DisplayName}");
            return 0;
        }
        if (args[0] == "show" && args.Length > 1)
        {
            var match = catalog.Services.FirstOrDefault(service => service.Id.Contains(args[1], StringComparison.OrdinalIgnoreCase) ||
                service.DisplayName.Contains(args[1], StringComparison.OrdinalIgnoreCase));
            if (match is null) return UsageError($"No catalog service matches '{args[1]}'.");
            Console.WriteLine(JsonSerializer.Serialize(match, JsonOptions));
            return 0;
        }
        return UsageError("Usage: aznetcheck catalog list | catalog show <service>");
    }

    private static void PrintReport(DiagnosticReport report, bool verbose)
    {
        Console.WriteLine("AzNetCheck\n");
        Console.WriteLine($"Target: {report.Target.OriginalInput}");
        Console.WriteLine($"Service: {report.Service.Service?.DisplayName ?? "Unknown"}");
        if (report.Service.Service is null) Console.WriteLine("Generic diagnostics performed.");
        Console.WriteLine("\nTests");
        foreach (var result in report.Results)
        {
            var duration = result.Duration > TimeSpan.Zero ? $" {result.Duration.TotalMilliseconds:0} ms" : "";
            Console.WriteLine($"  {result.DisplayName,-30} {result.Status.ToString().ToUpperInvariant(),-12}{duration}");
            if (result.Summary is not null) Console.WriteLine($"    {result.Summary}");
            if (verbose)
                foreach (var detail in result.Details)
                    Console.WriteLine($"    {detail.Key}: {JsonSerializer.Serialize(detail.Value, JsonOptions)}");
        }
        if (report.Findings.Count > 0)
        {
            Console.WriteLine("\nFindings");
            foreach (var finding in report.Findings)
            {
                Console.WriteLine($"  {finding.Severity.ToString().ToUpperInvariant()}: {finding.Title}");
                Console.WriteLine($"    {finding.Description}");
                foreach (var recommendation in finding.Recommendations) Console.WriteLine($"    Suggested check: {recommendation.Text}");
            }
        }
        Console.WriteLine($"\nOverall: {report.Summary.OverallStatus.ToString().ToUpperInvariant()}");
        Console.WriteLine($"Network connectivity: {report.Summary.NetworkConnectivity.ToString().ToUpperInvariant()}");
        Console.WriteLine(report.Summary.Message);
    }

    private static void PrintOrSerialize<T>(T result, IReadOnlyDictionary<string, string?> options)
    {
        if (options.ContainsKey("json")) Console.WriteLine(JsonSerializer.Serialize(result, JsonOptions));
        else if (result is DnsResolutionResult dns)
        {
            Console.WriteLine($"DNS: {dns.Status} ({dns.Duration.TotalMilliseconds:0} ms)");
            foreach (var cname in dns.CnameChain) Console.WriteLine($"  CNAME {cname}");
            foreach (var address in dns.Addresses) Console.WriteLine($"  {address}");
            if (dns.ErrorMessage is not null) Console.WriteLine($"  {dns.ErrorMessage}");
        }
        else if (result is IEnumerable<TcpProbeResult> attempts)
        {
            foreach (var attempt in attempts) Console.WriteLine($"TCP {attempt.Address}:{attempt.Port} {attempt.Status} {attempt.Duration.TotalMilliseconds:0} ms {attempt.ErrorMessage}");
        }
        else if (result is TcpProbeResult tcp)
            Console.WriteLine($"TCP {tcp.Address}:{tcp.Port} {tcp.Status} {tcp.Duration.TotalMilliseconds:0} ms {tcp.ErrorMessage}");
        else if (result is TlsProbeResult tls)
            Console.WriteLine($"TLS {tls.Status}: {tls.Protocol ?? tls.ErrorMessage}\n  Certificate: {tls.Subject ?? "unavailable"}");
        else if (result is HttpProbeResult http)
            Console.WriteLine($"HTTP {http.StatusCode?.ToString() ?? "failed"} {http.ReasonPhrase} ({http.Duration.TotalMilliseconds:0} ms)\n  {http.ErrorMessage}");
        else Console.WriteLine(JsonSerializer.Serialize(result, JsonOptions));
    }

    private static Dictionary<string, string?> ParseOptions(string[] args)
    {
        var options = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        for (var index = 0; index < args.Length; index++)
        {
            if (!args[index].StartsWith("--", StringComparison.Ordinal)) throw new ArgumentException($"Unexpected argument '{args[index]}'.");
            var name = args[index][2..];
            if (name is "json" or "verbose" or "debug" or "no-color") options[name] = null;
            else if (name is "port" or "timeout" or "service")
            {
                if (++index >= args.Length || args[index].StartsWith("--", StringComparison.Ordinal))
                    throw new ArgumentException($"Option --{name} requires a value.");
                options[name] = args[index];
            }
            else throw new ArgumentException($"Unknown option '--{name}'.");
        }
        return options;
    }

    private static JsonSerializerOptions CreateJsonOptions()
    {
        var options = new JsonSerializerOptions { WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
        options.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.CamelCase));
        return options;
    }

    private static int UsageError(string message)
    {
        Console.Error.WriteLine(message);
        Console.Error.WriteLine("Run 'aznetcheck --help' for usage.");
        return 2;
    }

    private static void PrintHelp() => Console.WriteLine("""
AzNetCheck 0.1.0
Usage:
  aznetcheck check <target> [--service <id>] [--port <port>] [--timeout <seconds>] [--json] [--verbose]
  aznetcheck detect <target> [--service <id>] [--json]
  aznetcheck dns <target> [--timeout <seconds>] [--json]
  aznetcheck tcp <target> [--port <port>] [--timeout <seconds>] [--json]
  aznetcheck tls <target> [--port <port>] [--timeout <seconds>] [--json]
  aznetcheck http <url> [--timeout <seconds>] [--json]
  aznetcheck catalog list | catalog show <service>
  aznetcheck version

Options: --debug --no-color
Timeout is specified in seconds. Diagnostics do not authenticate or modify Azure resources.
""");
}