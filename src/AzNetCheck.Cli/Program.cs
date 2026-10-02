using System.Text.Json;
using System.Text.Json.Serialization;
using System.Net;
using AzNetCheck.Azure;
using AzNetCheck.Core;
using AzNetCheck.Networking;
using Spectre.Console;

namespace AzNetCheck.Cli;

internal static partial class Program
{
    private static readonly JsonSerializerOptions JsonOptions = CreateJsonOptions();

    public static async Task<int> Main(string[] args)
    {
        try
        {
            return await RunCommandLineAsync(args).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("Diagnostic cancelled.");
            return 3;
        }
        catch (ArgumentException exception)
        {
            return UsageError(exception.Message, args.Contains("--no-color", StringComparer.Ordinal));
        }
        catch (Exception exception)
        {
            CreateConsole(args.Contains("--no-color", StringComparer.Ordinal), Console.Error)
                .MarkupLine("[red]Error:[/] Unexpected diagnostic error.");
            if (args.Contains("--debug", StringComparer.Ordinal)) Console.Error.WriteLine($"Exception type: {exception.GetType().Name}");
            return 4;
        }
    }

    private static async Task<int> CheckAsync(DiagnosticTarget target, IReadOnlyDictionary<string, string?> options,
        AzureServiceCatalog catalog, TimeSpan timeout, DiagnosticAddressFamily addressFamily,
        CancellationToken cancellationToken)
    {
        var serviceOverride = options.GetValueOrDefault("service");
        if (serviceOverride is not null && catalog.Detect(target.Hostname, serviceOverride).Status != ServiceDetectionStatus.Detected)
            return UsageError($"Unknown Azure service '{serviceOverride}'.", options.ContainsKey("no-color"));
        using var http = new HttpClientDiagnostic();
        var engine = new DiagnosticEngine(catalog, new DnsClientDiagnostic(), new TcpSocketDiagnostic(),
            new TlsStreamDiagnostic(), http);
        var report = await engine.RunAsync(target, serviceOverride,
            new DiagnosticTimeouts(timeout, timeout, timeout, timeout), cancellationToken, addressFamily).ConfigureAwait(false);
        if (options.ContainsKey("json"))
        {
            Console.Out.WriteLine(JsonSerializer.Serialize(report, JsonOptions));
        }
        else
        {
            RenderReport(report, options.ContainsKey("verbose"), options.ContainsKey("no-color"));
        }
        return report.Summary.OverallStatus == DiagnosticStatus.Failed ? 1 :
            report.Summary.OverallStatus == DiagnosticStatus.Inconclusive ? 3 : 0;
    }

    private static int DetectCommand(DiagnosticTarget target, IReadOnlyDictionary<string, string?> options, AzureServiceCatalog catalog)
    {
        var result = catalog.Detect(target.Hostname, options.GetValueOrDefault("service"));
        if (options.ContainsKey("json")) Console.Out.WriteLine(JsonSerializer.Serialize(result, JsonOptions));
        else RenderDetection(result, options.ContainsKey("no-color"));
        return result.Status == ServiceDetectionStatus.Unknown && options.ContainsKey("service") ? 2 : 0;
    }

    private static async Task<int> DnsCommandAsync(DiagnosticTarget target, IReadOnlyDictionary<string, string?> options,
        TimeSpan timeout, DiagnosticAddressFamily addressFamily, CancellationToken cancellationToken)
    {
        var result = target.IpAddress is not null
            ? new DnsResolutionResult(DiagnosticStatus.NotApplicable, [target.IpAddress.ToString()], [], TimeSpan.Zero,
                ErrorMessage: "The target is already an IP address; DNS resolution was not required.")
            : await new DnsClientDiagnostic().ResolveAsync(target.Hostname, timeout, cancellationToken).ConfigureAwait(false);
        var filteredAddresses = FilterAddresses(result.Addresses, addressFamily);
        result = result with
        {
            Addresses = filteredAddresses,
            Status = result.Addresses.Count > 0 && filteredAddresses.Count == 0 ? DiagnosticStatus.Inconclusive : result.Status,
            ErrorCode = result.Addresses.Count > 0 && filteredAddresses.Count == 0 ? "AddressFamilyUnavailable" : result.ErrorCode,
            ErrorMessage = result.Addresses.Count > 0 && filteredAddresses.Count == 0
                ? $"No resolved address matches the requested {addressFamily} family."
                : result.ErrorMessage
        };
        PrintOrSerialize(result, options);
        return result.Status switch
        {
            DiagnosticStatus.Failed => 1,
            DiagnosticStatus.Inconclusive => 3,
            _ => 0
        };
    }

    private static async Task<int> TcpCommandAsync(DiagnosticTarget target, IReadOnlyDictionary<string, string?> options,
        AzureServiceCatalog catalog, TimeSpan timeout, DiagnosticAddressFamily addressFamily,
        CancellationToken cancellationToken)
    {
        var serviceOverride = options.GetValueOrDefault("service");
        if (serviceOverride is not null && catalog.Detect(target.Hostname, serviceOverride).Status != ServiceDetectionStatus.Detected)
            return UsageError($"Unknown Azure service '{serviceOverride}'.", options.ContainsKey("no-color"));
        var dns = target.IpAddress is not null
            ? new DnsResolutionResult(DiagnosticStatus.NotApplicable, [target.IpAddress.ToString()], [], TimeSpan.Zero,
                ErrorMessage: "The target is already an IP address; DNS resolution was not required.")
            : await new DnsClientDiagnostic().ResolveAsync(target.Hostname, timeout, cancellationToken).ConfigureAwait(false);
        if (dns.Status != DiagnosticStatus.Passed && !(target.IpAddress is not null && dns.Status == DiagnosticStatus.NotApplicable))
        {
            PrintOrSerialize(dns, options);
            return dns.Status == DiagnosticStatus.Inconclusive ? 3 : 1;
        }
        var addresses = FilterAddresses(target.IpAddress is null ? dns.Addresses : [target.IpAddress.ToString()], addressFamily);
        if (addresses.Count == 0)
        {
            PrintOrSerialize(new DnsResolutionResult(DiagnosticStatus.Inconclusive, [], dns.CnameChain, dns.Duration,
                "AddressFamilyUnavailable", $"No resolved address matches the requested {addressFamily} family."), options);
            return 3;
        }
        var results = new List<TcpProbeResult>();
        var port = target.ExplicitPort ?? catalog.Detect(target.Hostname, serviceOverride)
            .Service?.Transports.FirstOrDefault(transport => transport.Required)?.Port ?? target.EffectivePort;
        foreach (var value in addresses.Take(8))
            if (System.Net.IPAddress.TryParse(value, out var address))
                results.Add(await new TcpSocketDiagnostic().ConnectAsync(address, port, timeout, cancellationToken).ConfigureAwait(false));
        PrintOrSerialize(results, options);
        return results.Any(result => result.Status == DiagnosticStatus.Passed) ? 0 : 1;
    }

    private static async Task<int> TlsCommandAsync(DiagnosticTarget target, IReadOnlyDictionary<string, string?> options,
        TimeSpan timeout, DiagnosticAddressFamily addressFamily, CancellationToken cancellationToken)
    {
        var dns = target.IpAddress is null
            ? await new DnsClientDiagnostic().ResolveAsync(target.Hostname, timeout, cancellationToken).ConfigureAwait(false)
            : new DnsResolutionResult(DiagnosticStatus.NotApplicable, [target.IpAddress.ToString()], [], TimeSpan.Zero,
                ErrorMessage: "The target is already an IP address; DNS resolution was not required.");
        if (dns.Status != DiagnosticStatus.Passed && !(target.IpAddress is not null && dns.Status == DiagnosticStatus.NotApplicable))
        {
            PrintOrSerialize(dns, options);
            return dns.Status == DiagnosticStatus.Inconclusive ? 3 : 1;
        }
        var selected = FilterAddresses(dns.Addresses, addressFamily);
        if (selected.Count == 0)
        {
            PrintOrSerialize(new DnsResolutionResult(DiagnosticStatus.Inconclusive, [], dns.CnameChain, dns.Duration,
                "AddressFamilyUnavailable", $"No resolved address matches the requested {addressFamily} family."), options);
            return 3;
        }
        var tls = new TlsStreamDiagnostic();
        var results = new List<TlsProbeResult>();
        foreach (var value in selected)
        {
            if (!System.Net.IPAddress.TryParse(value, out var address)) continue;
            var result = await tls.HandshakeAsync(target.Hostname, address, target.EffectivePort, timeout, cancellationToken).ConfigureAwait(false);
            results.Add(result);
            if (result.Status == DiagnosticStatus.Passed) break;
        }
        var finalResult = results.FirstOrDefault(result => result.Status == DiagnosticStatus.Passed) ?? results.Last();
        var selectedResult = finalResult;
        PrintOrSerialize(selectedResult, options);
        return selectedResult.Status == DiagnosticStatus.Passed ? 0 : 1;
    }

    private static async Task<int> HttpCommandAsync(DiagnosticTarget target, IReadOnlyDictionary<string, string?> options,
        TimeSpan timeout, CancellationToken cancellationToken)
    {
        using var http = new HttpClientDiagnostic();
        var result = await http.ProbeAsync(target, timeout, cancellationToken).ConfigureAwait(false);
        PrintOrSerialize(result, options);
        return result.StatusCode is not null ? 0 : 1;
    }

    private static void PrintOrSerialize<T>(T result, IReadOnlyDictionary<string, string?> options)
    {
        if (options.ContainsKey("json"))
            Console.Out.WriteLine(JsonSerializer.Serialize(result, JsonOptions));
        else
            RenderStandalone(result, options.ContainsKey("no-color"));
    }

    private static IReadOnlyList<string> FilterAddresses(IEnumerable<string> addresses, DiagnosticAddressFamily family) =>
        addresses.Where(value => System.Net.IPAddress.TryParse(value, out var address) && family switch
        {
            DiagnosticAddressFamily.IPv4 => address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork,
            DiagnosticAddressFamily.IPv6 => address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6,
            _ => true
        }).ToArray();

    private static JsonSerializerOptions CreateJsonOptions()
    {
        var options = new JsonSerializerOptions { WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
        options.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.CamelCase));
        options.Converters.Add(new IpAddressJsonConverter());
        return options;
    }

    private sealed class IpAddressJsonConverter : JsonConverter<IPAddress>
    {
        public override IPAddress? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
            IPAddress.TryParse(reader.GetString(), out var address) ? address : null;

        public override void Write(Utf8JsonWriter writer, IPAddress value, JsonSerializerOptions options) =>
            writer.WriteStringValue(value.ToString());
    }

    private static int UsageError(string message, bool noColor = false)
    {
        var console = CreateConsole(noColor, Console.Error);
        console.MarkupLine($"[red]Error:[/] {Spectre.Console.Markup.Escape(message)}");
        console.MarkupLine("Run 'aznetcheck --help' for usage.");
        return 2;
    }

}