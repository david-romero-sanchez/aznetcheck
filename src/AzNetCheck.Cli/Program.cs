using System.Net;
using System.Text;
using System.Text.Json;
using AzNetCheck.Azure;
using AzNetCheck.Core;
using AzNetCheck.Networking;
using AzNetCheck.Updater;
using Spectre.Console;

namespace AzNetCheck.Cli;

internal static partial class Program
{

    public static async Task<int> Main(string[] args)
    {
        try
        {
            var internalCommand = await TryRunInternalUpdateCommandAsync(args).ConfigureAwait(false);
            if (internalCommand is { Handled: true })
            {
                if (internalCommand.Error is not null)
                    Console.Error.WriteLine("Internal updater arguments are invalid.");
                if (internalCommand.PostUpdateTransactionPath is not null)
                    return await RunCommandLineAsync([], internalCommand.PostUpdateTransactionPath).ConfigureAwait(false);
                return internalCommand.ExitCode;
            }

            try
            {
                if (await CreateUpdateInstaller().RecoverPendingAsync().ConfigureAwait(false)) return 0;
            }
            catch (Exception exception)
            {
                new ConsoleUpdateLogger().Log("update-recovery-failed", exception.GetType().Name);
            }
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
                .MarkupLine($"[red]Error:[/] Unexpected diagnostic error ({Markup.Escape(exception.GetType().Name)}).");
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
            Console.Out.WriteLine(SerializeJson(report));
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
        if (options.ContainsKey("json")) Console.Out.WriteLine(SerializeJson(result));
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
            Console.Out.WriteLine(SerializeJson(result));
        else
            RenderStandalone(result, options.ContainsKey("no-color"));
    }

    private static string SerializeJson<T>(T result) => result switch
    {
        DiagnosticReport report => SerializeJsonDocument(writer => WriteDiagnosticReport(writer, report)),
        IReadOnlyList<AzureServiceDefinition> services => SerializeJsonDocument(writer => WriteAzureServiceDefinitions(writer, services)),
        AzureServiceDefinition service => SerializeJsonDocument(writer => WriteAzureServiceDefinition(writer, service)),
        ServiceDetectionResult detection => SerializeJsonDocument(writer => WriteServiceDetectionResult(writer, detection)),
        DnsResolutionResult dns => SerializeJsonDocument(writer => WriteDnsResolutionResult(writer, dns)),
        List<TcpProbeResult> tcpResults => SerializeJsonDocument(writer => WriteTcpProbeResults(writer, tcpResults)),
        IReadOnlyList<TcpProbeResult> tcpResults => SerializeJsonDocument(writer => WriteTcpProbeResults(writer, tcpResults)),
        TcpProbeResult tcp => SerializeJsonDocument(writer => WriteTcpProbeResult(writer, tcp)),
        TlsProbeResult tls => SerializeJsonDocument(writer => WriteTlsProbeResult(writer, tls)),
        HttpProbeResult http => SerializeJsonDocument(writer => WriteHttpProbeResult(writer, http)),
        UpdateCheckResult updateCheck => SerializeUpdateJson(updateCheck),
        UpdateApplyResult updateApply => SerializeUpdateJson(updateApply),
        _ => throw new NotSupportedException($"JSON output is not supported for type '{typeof(T).FullName}'.")
    };

    private static string SerializeJsonDocument(Action<Utf8JsonWriter> write)
    {
        using var stream = new MemoryStream();
        using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true });
        write(writer);
        writer.Flush();
        return Encoding.UTF8.GetString(stream.ToArray());
    }

    private static void WriteDiagnosticReport(Utf8JsonWriter writer, DiagnosticReport report)
    {
        writer.WriteStartObject();
        writer.WriteString("schemaVersion", report.SchemaVersion);
        writer.WritePropertyName("target");
        WriteDiagnosticTarget(writer, report.Target);
        writer.WritePropertyName("service");
        WriteServiceDetectionResult(writer, report.Service);
        writer.WritePropertyName("plan");
        WriteDiagnosticPlan(writer, report.Plan);
        writer.WritePropertyName("results");
        writer.WriteStartArray();
        foreach (var result in report.Results) WriteDiagnosticResult(writer, result);
        writer.WriteEndArray();
        writer.WritePropertyName("findings");
        writer.WriteStartArray();
        foreach (var finding in report.Findings) WriteDiagnosticFinding(writer, finding);
        writer.WriteEndArray();
        writer.WritePropertyName("summary");
        WriteDiagnosticSummary(writer, report.Summary);
        writer.WriteEndObject();
    }

    private static void WriteDiagnosticTarget(Utf8JsonWriter writer, DiagnosticTarget target)
    {
        writer.WriteStartObject();
        writer.WriteString("originalInput", target.OriginalInput);
        WriteNullableString(writer, "scheme", target.Scheme);
        writer.WriteString("hostname", target.Hostname);
        WriteNullableNumber(writer, "explicitPort", target.ExplicitPort);
        writer.WriteNumber("effectivePort", target.EffectivePort);
        writer.WriteString("path", target.Path);
        WriteNullableString(writer, "ipAddress", target.IpAddress?.ToString());
        writer.WriteEndObject();
    }

    private static void WriteServiceDetectionResult(Utf8JsonWriter writer, ServiceDetectionResult result)
    {
        writer.WriteStartObject();
        writer.WriteString("status", ToJsonEnum(result.Status));
        writer.WritePropertyName("service");
        if (result.Service is null) writer.WriteNullValue();
        else WriteAzureServiceDefinition(writer, result.Service);
        writer.WritePropertyName("candidates");
        writer.WriteStartArray();
        foreach (var candidate in result.Candidates) WriteAzureServiceDefinition(writer, candidate);
        writer.WriteEndArray();
        writer.WriteString("reason", result.Reason);
        writer.WriteEndObject();
    }

    private static void WriteAzureServiceDefinitions(Utf8JsonWriter writer, IReadOnlyList<AzureServiceDefinition> services)
    {
        writer.WriteStartArray();
        foreach (var service in services) WriteAzureServiceDefinition(writer, service);
        writer.WriteEndArray();
    }

    private static void WriteAzureServiceDefinition(Utf8JsonWriter writer, AzureServiceDefinition service)
    {
        writer.WriteStartObject();
        writer.WriteString("id", service.Id);
        writer.WriteString("displayName", service.DisplayName);
        writer.WritePropertyName("hostnamePatterns");
        writer.WriteStartArray();
        foreach (var pattern in service.HostnamePatterns) writer.WriteStringValue(pattern);
        writer.WriteEndArray();
        writer.WritePropertyName("privateLinkPatterns");
        writer.WriteStartArray();
        foreach (var pattern in service.PrivateLinkPatterns) writer.WriteStringValue(pattern);
        writer.WriteEndArray();
        writer.WritePropertyName("transports");
        writer.WriteStartArray();
        foreach (var transport in service.Transports) WriteServiceTransport(writer, transport);
        writer.WriteEndArray();
        writer.WriteString("defaultProtocol", service.DefaultProtocol);
        WriteNullableString(writer, "authenticationScope", service.AuthenticationScope);
        writer.WriteString("httpMethod", service.HttpMethod);
        writer.WriteEndObject();
    }

    private static void WriteServiceTransport(Utf8JsonWriter writer, ServiceTransport transport)
    {
        writer.WriteStartObject();
        writer.WriteString("name", transport.Name);
        writer.WriteString("protocol", transport.Protocol);
        writer.WriteNumber("port", transport.Port);
        writer.WriteBoolean("required", transport.Required);
        writer.WriteString("description", transport.Description);
        WriteNullableNumber(writer, "portEnd", transport.PortEnd);
        writer.WriteEndObject();
    }

    private static void WriteDnsResolutionResult(Utf8JsonWriter writer, DnsResolutionResult result)
    {
        writer.WriteStartObject();
        writer.WriteString("status", ToJsonEnum(result.Status));
        writer.WritePropertyName("addresses");
        writer.WriteStartArray();
        foreach (var address in result.Addresses) writer.WriteStringValue(address);
        writer.WriteEndArray();
        writer.WritePropertyName("cnameChain");
        writer.WriteStartArray();
        foreach (var item in result.CnameChain) writer.WriteStringValue(item);
        writer.WriteEndArray();
        writer.WriteString("duration", result.Duration.ToString("c"));
        WriteNullableString(writer, "errorCode", result.ErrorCode);
        WriteNullableString(writer, "errorMessage", result.ErrorMessage);
        writer.WriteEndObject();
    }

    private static void WriteDiagnosticPlan(Utf8JsonWriter writer, DiagnosticPlan plan)
    {
        writer.WriteStartObject();
        writer.WritePropertyName("stepIds");
        writer.WriteStartArray();
        foreach (var stepId in plan.StepIds) writer.WriteStringValue(stepId);
        writer.WriteEndArray();
        writer.WriteEndObject();
    }

    private static void WriteDiagnosticResult(Utf8JsonWriter writer, DiagnosticResult result)
    {
        writer.WriteStartObject();
        writer.WriteString("testId", result.TestId);
        writer.WriteString("displayName", result.DisplayName);
        writer.WriteString("status", ToJsonEnum(result.Status));
        WriteNullableString(writer, "summary", result.Summary);
        writer.WriteString("duration", result.Duration.ToString("c"));
        writer.WritePropertyName("details");
        writer.WriteStartObject();
        foreach (var detail in result.Details)
        {
            writer.WritePropertyName(detail.Key);
            WriteDetailValue(writer, detail.Value);
        }
        writer.WriteEndObject();
        writer.WritePropertyName("error");
        if (result.Error is null) writer.WriteNullValue();
        else WriteDiagnosticError(writer, result.Error);
        writer.WriteEndObject();
    }

    private static void WriteDiagnosticError(Utf8JsonWriter writer, DiagnosticError error)
    {
        writer.WriteStartObject();
        writer.WriteString("code", error.Code);
        writer.WriteString("message", error.Message);
        WriteNullableString(writer, "exceptionType", error.ExceptionType);
        writer.WriteEndObject();
    }

    private static void WriteDiagnosticFinding(Utf8JsonWriter writer, DiagnosticFinding finding)
    {
        writer.WriteStartObject();
        writer.WriteString("id", finding.Id);
        writer.WriteString("title", finding.Title);
        writer.WriteString("severity", ToJsonEnum(finding.Severity));
        writer.WriteString("description", finding.Description);
        writer.WritePropertyName("evidence");
        writer.WriteStartArray();
        foreach (var evidence in finding.Evidence) writer.WriteStringValue(evidence);
        writer.WriteEndArray();
        writer.WritePropertyName("recommendations");
        writer.WriteStartArray();
        foreach (var recommendation in finding.Recommendations) WriteDiagnosticRecommendation(writer, recommendation);
        writer.WriteEndArray();
        writer.WritePropertyName("documentationLinks");
        if (finding.DocumentationLinks is null) writer.WriteNullValue();
        else
        {
            writer.WriteStartArray();
            foreach (var link in finding.DocumentationLinks) writer.WriteStringValue(link);
            writer.WriteEndArray();
        }
        writer.WriteEndObject();
    }

    private static void WriteDiagnosticRecommendation(Utf8JsonWriter writer, DiagnosticRecommendation recommendation)
    {
        writer.WriteStartObject();
        writer.WriteString("id", recommendation.Id);
        writer.WriteString("text", recommendation.Text);
        writer.WriteEndObject();
    }

    private static void WriteDiagnosticSummary(Utf8JsonWriter writer, DiagnosticSummary summary)
    {
        writer.WriteStartObject();
        writer.WriteString("overallStatus", ToJsonEnum(summary.OverallStatus));
        writer.WriteString("networkConnectivity", ToJsonEnum(summary.NetworkConnectivity));
        writer.WriteString("authentication", ToJsonEnum(summary.Authentication));
        writer.WriteString("message", summary.Message);
        writer.WriteEndObject();
    }

    private static void WriteDetailValue(Utf8JsonWriter writer, object? value)
    {
        switch (value)
        {
            case null:
                writer.WriteNullValue();
                break;
            case string text:
                writer.WriteStringValue(text);
                break;
            case bool flag:
                writer.WriteBooleanValue(flag);
                break;
            case int number:
                writer.WriteNumberValue(number);
                break;
            case long number:
                writer.WriteNumberValue(number);
                break;
            case DateTimeOffset timestamp:
                writer.WriteStringValue(timestamp);
                break;
            case IEnumerable<string> values:
                writer.WriteStartArray();
                foreach (var item in values) writer.WriteStringValue(item);
                writer.WriteEndArray();
                break;
            case IEnumerable<ResolvedAddressInfo> values:
                writer.WriteStartArray();
                foreach (var item in values) WriteResolvedAddressInfo(writer, item);
                writer.WriteEndArray();
                break;
            case IEnumerable<TcpProbeResult> values:
                writer.WriteStartArray();
                foreach (var item in values) WriteTcpProbeResult(writer, item);
                writer.WriteEndArray();
                break;
            default:
                throw new NotSupportedException($"Unsupported diagnostic detail value type '{value.GetType().FullName}'.");
        }
    }

    private static void WriteResolvedAddressInfo(Utf8JsonWriter writer, ResolvedAddressInfo value)
    {
        writer.WriteStartObject();
        writer.WriteString("address", value.Address);
        writer.WriteString("kind", value.Kind);
        writer.WriteEndObject();
    }

    private static void WriteTcpProbeResults(Utf8JsonWriter writer, IReadOnlyList<TcpProbeResult> results)
    {
        writer.WriteStartArray();
        foreach (var result in results) WriteTcpProbeResult(writer, result);
        writer.WriteEndArray();
    }

    private static void WriteTcpProbeResult(Utf8JsonWriter writer, TcpProbeResult result)
    {
        writer.WriteStartObject();
        writer.WriteString("status", ToJsonEnum(result.Status));
        writer.WriteString("address", result.Address);
        writer.WriteNumber("port", result.Port);
        writer.WriteString("duration", result.Duration.ToString("c"));
        WriteNullableString(writer, "socketError", result.SocketError);
        WriteNullableString(writer, "errorMessage", result.ErrorMessage);
        writer.WriteEndObject();
    }

    private static void WriteTlsProbeResult(Utf8JsonWriter writer, TlsProbeResult result)
    {
        writer.WriteStartObject();
        writer.WriteString("status", ToJsonEnum(result.Status));
        writer.WriteString("hostname", result.Hostname);
        writer.WriteNumber("port", result.Port);
        writer.WriteString("duration", result.Duration.ToString("c"));
        WriteNullableString(writer, "protocol", result.Protocol);
        WriteNullableString(writer, "cipher", result.Cipher);
        WriteNullableString(writer, "subject", result.Subject);
        WriteNullableString(writer, "issuer", result.Issuer);
        WriteNullableDateTimeOffset(writer, "notAfter", result.NotAfter);
        WriteNullableBoolean(writer, "hostnameMatches", result.HostnameMatches);
        WriteNullableBoolean(writer, "chainValid", result.ChainValid);
        WriteNullableString(writer, "errorMessage", result.ErrorMessage);
        WriteNullableDateTimeOffset(writer, "notBefore", result.NotBefore);
        WriteNullableString(writer, "subjectAlternativeNames", result.SubjectAlternativeNames);
        writer.WriteEndObject();
    }

    private static void WriteHttpProbeResult(Utf8JsonWriter writer, HttpProbeResult result)
    {
        writer.WriteStartObject();
        writer.WriteString("status", ToJsonEnum(result.Status));
        writer.WriteString("uri", result.Uri);
        WriteNullableNumber(writer, "statusCode", result.StatusCode);
        WriteNullableString(writer, "reasonPhrase", result.ReasonPhrase);
        writer.WriteString("duration", result.Duration.ToString("c"));
        WriteNullableString(writer, "redirectLocation", result.RedirectLocation);
        WriteNullableString(writer, "errorMessage", result.ErrorMessage);
        writer.WriteEndObject();
    }

    private static string FormatDetailValue(object? value) => value switch
    {
        null => "null",
        string text => text,
        bool flag => flag ? "true" : "false",
        int number => number.ToString(),
        long number => number.ToString(),
        DateTimeOffset timestamp => timestamp.ToString("O"),
        IEnumerable<string> values => string.Join(", ", values),
        IEnumerable<ResolvedAddressInfo> values => string.Join(", ", values.Select(item => $"{item.Address} ({item.Kind})")),
        IEnumerable<TcpProbeResult> values => string.Join("; ", values.Select(item => $"{item.Address}:{item.Port}={ToJsonEnum(item.Status)}")),
        _ => value.ToString() ?? string.Empty
    };

    private static void WriteNullableString(Utf8JsonWriter writer, string propertyName, string? value)
    {
        writer.WritePropertyName(propertyName);
        if (value is null) writer.WriteNullValue();
        else writer.WriteStringValue(value);
    }

    private static void WriteNullableNumber(Utf8JsonWriter writer, string propertyName, int? value)
    {
        writer.WritePropertyName(propertyName);
        if (value is int number) writer.WriteNumberValue(number);
        else writer.WriteNullValue();
    }

    private static void WriteNullableBoolean(Utf8JsonWriter writer, string propertyName, bool? value)
    {
        writer.WritePropertyName(propertyName);
        if (value is bool flag) writer.WriteBooleanValue(flag);
        else writer.WriteNullValue();
    }

    private static void WriteNullableDateTimeOffset(Utf8JsonWriter writer, string propertyName, DateTimeOffset? value)
    {
        writer.WritePropertyName(propertyName);
        if (value is DateTimeOffset timestamp) writer.WriteStringValue(timestamp);
        else writer.WriteNullValue();
    }

    private static string ToJsonEnum<TEnum>(TEnum value) where TEnum : struct, Enum => JsonNamingPolicy.CamelCase.ConvertName(value.ToString());

    private static IReadOnlyList<string> FilterAddresses(IEnumerable<string> addresses, DiagnosticAddressFamily family) =>
        addresses.Where(value => System.Net.IPAddress.TryParse(value, out var address) && family switch
        {
            DiagnosticAddressFamily.IPv4 => address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork,
            DiagnosticAddressFamily.IPv6 => address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6,
            _ => true
        }).ToArray();

    private static int UsageError(string message, bool noColor = false)
    {
        var console = CreateConsole(noColor, Console.Error);
        console.MarkupLine($"[red]Error:[/] {Spectre.Console.Markup.Escape(message)}");
        console.MarkupLine("Run 'aznetcheck --help' for usage.");
        return 2;
    }

}
