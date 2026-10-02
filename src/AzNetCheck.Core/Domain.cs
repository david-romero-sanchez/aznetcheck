using System.Net;

namespace AzNetCheck.Core;

public enum DiagnosticStatus { Passed, Failed, Warning, Skipped, NotApplicable, Inconclusive }
public enum FindingSeverity { Info, Warning, Error }
public enum ServiceDetectionStatus { Detected, Unknown, Ambiguous }
public enum IpAddressKind { Public, Private, IPv6, Loopback, LinkLocal, Unspecified }
public enum DiagnosticAddressFamily { Any, IPv4, IPv6 }

public sealed record DiagnosticTarget(
    string OriginalInput,
    string? Scheme,
    string Hostname,
    int? ExplicitPort,
    int EffectivePort,
    string Path,
    IPAddress? IpAddress)
{
    public bool IsIpAddress => IpAddress is not null;
    public string Authority => IpAddress?.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
        ? $"[{Hostname}]:{EffectivePort}"
        : $"{Hostname}:{EffectivePort}";
}

public static class DiagnosticTargetParser
{
    public static bool TryParse(string input, out DiagnosticTarget? target, out string? error)
    {
        target = null;
        error = null;
        if (string.IsNullOrWhiteSpace(input))
        {
            error = "Target cannot be empty.";
            return false;
        }

        var value = input.Trim();
        string? scheme = null;
        string host;
        int? port = null;
        var path = "/";
        if (value.Contains("://", StringComparison.Ordinal))
        {
            if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
                (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps) ||
                string.IsNullOrWhiteSpace(uri.Host))
            {
                error = "Only valid HTTP and HTTPS URLs are supported.";
                return false;
            }

            scheme = uri.Scheme.ToLowerInvariant();
            host = uri.Host;
            port = TryGetExplicitPort(value, out var explicitPort) ? explicitPort : null;
            path = string.IsNullOrEmpty(uri.PathAndQuery) ? "/" : uri.PathAndQuery;
        }
        else if (value.StartsWith("[", StringComparison.Ordinal))
        {
            var close = value.IndexOf(']');
            if (close < 0 || !IPAddress.TryParse(value[1..close], out var parsedIp))
            {
                error = "Invalid bracketed IPv6 target.";
                return false;
            }
            host = parsedIp.ToString();
            if (close + 1 < value.Length)
            {
                if (value[close + 1] != ':' || !TryPort(value[(close + 2)..], out var bracketPort))
                {
                    error = "Port must be between 1 and 65535.";
                    return false;
                }
                port = bracketPort;
            }
        }
        else if (IPAddress.TryParse(value, out var directIp))
        {
            host = directIp.ToString();
        }
        else
        {
            var colon = value.LastIndexOf(':');
            if (colon > 0 && value.IndexOf(':') == colon)
            {
                if (!TryPort(value[(colon + 1)..], out var parsedPort))
                {
                    error = "Port must be between 1 and 65535.";
                    return false;
                }
                port = parsedPort;
                value = value[..colon];
            }
            host = value;
        }

        if (host.Length == 0 || host.Any(char.IsWhiteSpace))
        {
            error = "Target hostname is invalid.";
            return false;
        }

        IPAddress? address = IPAddress.TryParse(host, out var ipAddress) ? ipAddress : null;
        if (address is not null)
        {
            host = address.ToString();
        }
        else
        {
            try { host = new System.Globalization.IdnMapping().GetAscii(host.TrimEnd('.')).ToLowerInvariant(); }
            catch (ArgumentException)
            {
                error = "Target hostname is invalid.";
                return false;
            }
        }
        var defaultPort = scheme == Uri.UriSchemeHttp ? 80 : 443;
        target = new DiagnosticTarget(input, scheme, host, port, port ?? defaultPort, path, address);
        return true;
    }

    private static bool TryPort(string text, out int port) =>
        int.TryParse(text, out port) && port is > 0 and <= 65535;

    private static bool TryGetExplicitPort(string value, out int port)
    {
        port = 0;
        var authorityStart = value.IndexOf("://", StringComparison.Ordinal) + 3;
        var authorityEnd = value.IndexOfAny(['/','?','#'], authorityStart);
        var authority = authorityEnd < 0 ? value[authorityStart..] : value[authorityStart..authorityEnd];
        var userInfoEnd = authority.LastIndexOf('@');
        if (userInfoEnd >= 0) authority = authority[(userInfoEnd + 1)..];
        if (authority.StartsWith("[", StringComparison.Ordinal))
        {
            var closingBracket = authority.IndexOf(']');
            return closingBracket >= 0 && closingBracket + 1 < authority.Length && authority[closingBracket + 1] == ':' &&
                TryPort(authority[(closingBracket + 2)..], out port);
        }
        var colon = authority.LastIndexOf(':');
        return colon > 0 && authority.IndexOf(':') == colon && TryPort(authority[(colon + 1)..], out port);
    }
}

public sealed record ServiceTransport(string Name, string Protocol, int Port, bool Required, string Description, int? PortEnd = null);
public sealed record AzureServiceDefinition(
    string Id,
    string DisplayName,
    IReadOnlyList<string> HostnamePatterns,
    IReadOnlyList<string> PrivateLinkPatterns,
    IReadOnlyList<ServiceTransport> Transports,
    string DefaultProtocol = "https",
    string? AuthenticationScope = null,
    string HttpMethod = "GET");
public sealed record ServiceDetectionResult(ServiceDetectionStatus Status, AzureServiceDefinition? Service, IReadOnlyList<AzureServiceDefinition> Candidates, string Reason);

public interface IAzureServiceDetector
{
    ServiceDetectionResult Detect(string hostname, string? serviceOverride = null);
}

public sealed record DiagnosticTimeouts(TimeSpan Dns, TimeSpan Tcp, TimeSpan Tls, TimeSpan Http)
{
    public static DiagnosticTimeouts Default { get; } = new(TimeSpan.FromSeconds(4), TimeSpan.FromSeconds(3),
        TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(8));
}

public sealed record DnsResolutionResult(DiagnosticStatus Status, IReadOnlyList<string> Addresses,
    IReadOnlyList<string> CnameChain, TimeSpan Duration, string? ErrorCode = null, string? ErrorMessage = null);
public sealed record TcpProbeResult(DiagnosticStatus Status, string Address, int Port, TimeSpan Duration,
    string? SocketError = null, string? ErrorMessage = null);
public sealed record TlsProbeResult(DiagnosticStatus Status, string Hostname, int Port, TimeSpan Duration,
    string? Protocol = null, string? Cipher = null, string? Subject = null, string? Issuer = null,
    DateTimeOffset? NotAfter = null, bool? HostnameMatches = null, bool? ChainValid = null,
    string? ErrorMessage = null, DateTimeOffset? NotBefore = null, string? SubjectAlternativeNames = null);
public sealed record HttpProbeResult(DiagnosticStatus Status, string Uri, int? StatusCode, string? ReasonPhrase,
    TimeSpan Duration, string? RedirectLocation = null, string? ErrorMessage = null);

public interface IDnsDiagnostic
{
    Task<DnsResolutionResult> ResolveAsync(string hostname, TimeSpan timeout, CancellationToken cancellationToken);
}
public interface ITcpDiagnostic
{
    Task<TcpProbeResult> ConnectAsync(IPAddress address, int port, TimeSpan timeout, CancellationToken cancellationToken);
}
public interface ITlsDiagnostic
{
    Task<TlsProbeResult> HandshakeAsync(string hostname, IPAddress address, int port, TimeSpan timeout,
        CancellationToken cancellationToken);
}
public interface IHttpDiagnostic
{
    Task<HttpProbeResult> ProbeAsync(DiagnosticTarget target, TimeSpan timeout, CancellationToken cancellationToken);
}

public sealed record DiagnosticError(string Code, string Message, string? ExceptionType = null);
public sealed record DiagnosticResult
{
    public required string TestId { get; init; }
    public required string DisplayName { get; init; }
    public required DiagnosticStatus Status { get; init; }
    public string? Summary { get; init; }
    public TimeSpan Duration { get; init; }
    public IReadOnlyDictionary<string, object?> Details { get; init; } = new Dictionary<string, object?>();
    public DiagnosticError? Error { get; init; }
}
public sealed record DiagnosticRecommendation(string Id, string Text);
public sealed record DiagnosticFinding(string Id, string Title, FindingSeverity Severity, string Description,
    IReadOnlyList<string> Evidence, IReadOnlyList<DiagnosticRecommendation> Recommendations,
    IReadOnlyList<string>? DocumentationLinks = null);
public sealed record DiagnosticSummary(DiagnosticStatus OverallStatus, DiagnosticStatus NetworkConnectivity,
    DiagnosticStatus Authentication, string Message);
public sealed record DiagnosticPlan(IReadOnlyList<string> StepIds);
public sealed record DiagnosticReport(string SchemaVersion, DiagnosticTarget Target,
    ServiceDetectionResult Service, DiagnosticPlan Plan, IReadOnlyList<DiagnosticResult> Results,
    IReadOnlyList<DiagnosticFinding> Findings, DiagnosticSummary Summary);

public static class IpAddressClassifier
{
    public static IpAddressKind Classify(IPAddress address)
    {
        if (IPAddress.IsLoopback(address)) return IpAddressKind.Loopback;
        if (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any)) return IpAddressKind.Unspecified;
        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            if (address.IsIPv6LinkLocal) return IpAddressKind.LinkLocal;
            return IpAddressKind.IPv6;
        }

        var bytes = address.GetAddressBytes();
        if (bytes[0] == 10 || bytes[0] == 192 && bytes[1] == 168 ||
            bytes[0] == 172 && bytes[1] is >= 16 and <= 31)
            return IpAddressKind.Private;
        if (bytes[0] == 169 && bytes[1] == 254) return IpAddressKind.LinkLocal;
        return IpAddressKind.Public;
    }
}