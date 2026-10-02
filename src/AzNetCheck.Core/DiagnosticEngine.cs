using System.Diagnostics;
using System.Net;

namespace AzNetCheck.Core;

public sealed class DiagnosticEngine(
    IAzureServiceDetector serviceDetector,
    IDnsDiagnostic dns,
    ITcpDiagnostic tcp,
    ITlsDiagnostic tls,
    IHttpDiagnostic http)
{
    public async Task<DiagnosticReport> RunAsync(DiagnosticTarget target, string? serviceOverride = null,
        DiagnosticTimeouts? timeouts = null, CancellationToken cancellationToken = default,
        DiagnosticAddressFamily addressFamily = DiagnosticAddressFamily.Any)
    {
        var limits = timeouts ?? DiagnosticTimeouts.Default;
        var service = serviceDetector.Detect(target.Hostname, serviceOverride);
        var results = new List<DiagnosticResult>();
        var findings = new List<DiagnosticFinding>();
        var dnsResult = target.IpAddress is null
            ? await dns.ResolveAsync(target.Hostname, limits.Dns, cancellationToken).ConfigureAwait(false)
            : new DnsResolutionResult(DiagnosticStatus.NotApplicable, [target.IpAddress.ToString()], [], TimeSpan.Zero,
                ErrorMessage: "The target is already an IP address; DNS resolution was not required.");
        results.Add(ToResult("dns", "DNS resolution", dnsResult.Status,
            target.IpAddress is null ? $"{dnsResult.Addresses.Count} address(es) resolved" :
                "The target is already an IP address; DNS resolution was not required.", dnsResult.Duration,
            ("addresses", dnsResult.Addresses), ("cnameChain", dnsResult.CnameChain), ("errorCode", dnsResult.ErrorCode)));

        var resolvedAddresses = target.IpAddress is not null ? [target.IpAddress] : dnsResult.Addresses
            .Select(value => IPAddress.TryParse(value, out var address) ? address : null).Where(value => value is not null)
            .Cast<IPAddress>().Distinct().Take(8).ToArray();
        var addresses = resolvedAddresses.Where(address => MatchesAddressFamily(address, addressFamily)).ToArray();
        var privateLink = service.Service?.PrivateLinkPatterns.Any(pattern => HostMatches(target.Hostname, pattern)) == true ||
            service.Service?.PrivateLinkPatterns.Any(pattern =>
            dnsResult.CnameChain.Any(name => HostMatches(name, pattern))) == true ||
            dnsResult.CnameChain.Any(name => name.Contains("privatelink.", StringComparison.OrdinalIgnoreCase));
        var privateAddresses = addresses.Where(address => IpAddressClassifier.Classify(address) == IpAddressKind.Private).ToArray();
        var ipStatus = resolvedAddresses.Length == 0 || addresses.Length == 0 ? DiagnosticStatus.Inconclusive : DiagnosticStatus.Passed;
        results.Add(ToResult("ip-analysis", "IP analysis", ipStatus,
            addresses.Length == 0 ? $"No resolved address matches the {addressFamily} selection" :
                privateAddresses.Length > 0 ? "Private IP address detected" : $"{addresses.Length} address(es) selected",
            TimeSpan.Zero, ("resolvedAddresses", resolvedAddresses.Select(address => new ResolvedAddressInfo(address.ToString(), IpAddressClassifier.Classify(address).ToString())).ToArray()),
            ("selectedAddresses", addresses.Select(address => address.ToString()).ToArray()), ("privateLinkIndicators", privateLink)));
        if (privateLink || privateAddresses.Length > 0)
            findings.Add(new("private-link-indicators", "Private Link indicators detected", FindingSeverity.Info,
                "The DNS chain or resolved addresses indicate a possible private endpoint path.",
                dnsResult.CnameChain.Concat(privateAddresses.Select(address => address.ToString())).ToArray(),
                [new("check-private-dns", "Check the Private DNS zone and VNet link."),
                 new("check-routing", "Check DNS forwarding and routing to the VNet containing the Private Endpoint."),
                 new("check-private-endpoint", "Check the Private Endpoint connection state and relevant firewall rules.")]));

        var port = target.ExplicitPort ?? (target.Scheme == Uri.UriSchemeHttp ? 80 :
            service.Service?.Transports.FirstOrDefault(transport => transport.Required)?.Port ?? target.EffectivePort);
        var dnsAvailable = dnsResult.Status is DiagnosticStatus.Passed or DiagnosticStatus.NotApplicable;
        var canContinue = dnsAvailable && addresses.Length > 0;
        if (!canContinue)
        {
            var reason = addresses.Length == 0 && dnsAvailable
                ? $"No resolved address matches the requested {addressFamily} family."
                : "DNS did not provide a usable address.";
            results.Add(Skipped("tcp", "TCP", reason));
            results.Add(Skipped("tls", "TLS", "TCP connectivity was not established."));
            results.Add(Skipped("certificate", "Certificate", "TLS was not attempted."));
            results.Add(Skipped("http", "HTTP", "The endpoint could not be reached at the lower layers."));
            if (dnsAvailable && addresses.Length == 0)
            {
                findings.Add(new("address-family-unavailable", "No address matches the selected family", FindingSeverity.Warning,
                    reason, resolvedAddresses.Select(address => address.ToString()).ToArray(), []));
                return CreateReport(target, service, results, findings, DiagnosticStatus.Inconclusive,
                    DiagnosticStatus.Inconclusive, reason);
            }
            if (dnsResult.Status == DiagnosticStatus.Failed)
                findings.Add(new("dns-resolution-failed", "DNS resolution failed", FindingSeverity.Error,
                    dnsResult.ErrorMessage ?? "The target hostname could not be resolved.", [target.Hostname],
                    [new("check-dns", "Check the hostname, configured DNS servers, and DNS forwarding." )]));
            else if (dnsResult.Status == DiagnosticStatus.Inconclusive)
                findings.Add(new("dns-resolution-inconclusive", "DNS resolution was inconclusive", FindingSeverity.Warning,
                    dnsResult.ErrorMessage ?? "DNS did not provide a complete result.", [target.Hostname],
                    [new("check-dns-chain", "Check the DNS response and CNAME chain for this hostname.")]));
            var failureStatus = dnsResult.Status == DiagnosticStatus.Inconclusive
                ? DiagnosticStatus.Inconclusive : DiagnosticStatus.Failed;
            return CreateReport(target, service, results, findings, failureStatus, failureStatus,
                dnsResult.Status == DiagnosticStatus.Inconclusive
                    ? "DNS resolution was inconclusive; higher-layer tests were skipped."
                    : "DNS resolution failed; higher-layer tests were skipped.");
        }

        var tcpWatch = Stopwatch.StartNew();
        var tcpAttempts = new List<TcpProbeResult>();
        foreach (var address in addresses)
        {
            cancellationToken.ThrowIfCancellationRequested();
            tcpAttempts.Add(await tcp.ConnectAsync(address, port, limits.Tcp, cancellationToken).ConfigureAwait(false));
        }
        tcpWatch.Stop();
        var tcpPassed = tcpAttempts.Any(attempt => attempt.Status == DiagnosticStatus.Passed);
        var successfulAddress = tcpAttempts.FirstOrDefault(attempt => attempt.Status == DiagnosticStatus.Passed);
        var tcpStatus = tcpPassed
            ? tcpAttempts.Any(attempt => attempt.Status != DiagnosticStatus.Passed) ? DiagnosticStatus.Warning : DiagnosticStatus.Passed
            : DiagnosticStatus.Failed;
        results.Add(ToResult("tcp", $"TCP :{port}", tcpStatus, tcpPassed ? "At least one address accepted a connection" : "No address accepted a connection",
            tcpWatch.Elapsed, ("attempts", tcpAttempts)));
        if (tcpStatus == DiagnosticStatus.Warning)
            findings.Add(new("tcp-partial-connectivity", "Some resolved addresses were unreachable", FindingSeverity.Warning,
                "At least one resolved address accepted a TCP connection while one or more other address attempts failed.",
                tcpAttempts.Where(attempt => attempt.Status != DiagnosticStatus.Passed)
                    .Select(attempt => $"{attempt.Address}:{attempt.Port}: {attempt.ErrorMessage ?? attempt.Status.ToString()}").ToArray(),
                [new("review-address-paths", "Check routing and firewall policy for each resolved address and address family.")]));
        if (!tcpPassed)
        {
            results.Add(Skipped("tls", "TLS", "TCP connection failed."));
            results.Add(Skipped("certificate", "Certificate", "TLS was not attempted."));
            results.Add(Skipped("http", "HTTP", "TLS connection was not established."));
            var connectionRefused = tcpAttempts.All(attempt => attempt.SocketError == "ConnectionRefused");
            var tcpDescription = connectionRefused
                ? "The target host was reached, but the TCP connection to the selected port was actively refused."
                : privateLink && privateAddresses.Length > 0
                    ? "TCP connectivity to a private address failed; the cause cannot be determined from this endpoint alone."
                    : "The target did not accept a TCP connection on the selected port.";
            findings.Add(new("tcp-connectivity-failed", "TCP connectivity failed", FindingSeverity.Error,
                tcpDescription,
                tcpAttempts.Select(attempt => $"{attempt.Address}:{attempt.Port}: {attempt.ErrorMessage ?? attempt.Status.ToString()}").ToArray(),
                [new("check-network-path", connectionRefused
                    ? "Verify that the service is listening on this port and that the selected endpoint and port are correct."
                    : "Check routing, VPN or ExpressRoute, firewalls, NSGs, and the destination service endpoint.")]));
            return CreateReport(target, service, results, findings, DiagnosticStatus.Failed, DiagnosticStatus.Failed,
                "DNS succeeded, but TCP connectivity failed.");
        }

        var usesHttp = service.Service?.DefaultProtocol != "tcp";
        if (!usesHttp)
        {
            results.Add(Skipped("tls", "TLS", "The detected transport is not HTTPS."));
            results.Add(Skipped("certificate", "Certificate", "The detected transport does not use TLS."));
            results.Add(Skipped("http", "HTTP", "This service transport does not use HTTP."));
            return CreateReport(target, service, results, findings, DiagnosticStatus.Passed, DiagnosticStatus.Passed,
                "Network connectivity to the selected TCP endpoint is working.");
        }

        if (target.Scheme == Uri.UriSchemeHttp)
        {
            results.Add(Skipped("tls", "TLS", "The target explicitly uses plain HTTP."));
            results.Add(Skipped("certificate", "Certificate", "The target explicitly uses plain HTTP."));
        }
        else
        {
            var tlsAddress = IPAddress.Parse(successfulAddress!.Address);
            var tlsResult = await tls.HandshakeAsync(target.Hostname, tlsAddress, port, limits.Tls, cancellationToken).ConfigureAwait(false);
            results.Add(ToResult("tls", "TLS handshake", tlsResult.Status,
                tlsResult.ErrorMessage ?? tlsResult.Protocol ?? "TLS handshake completed", tlsResult.Duration,
                ("protocol", tlsResult.Protocol), ("cipher", tlsResult.Cipher)));
            var certificateStatus = tlsResult.Status == DiagnosticStatus.Passed ? DiagnosticStatus.Passed :
                tlsResult.Subject is null ? DiagnosticStatus.Inconclusive : DiagnosticStatus.Failed;
            results.Add(ToResult("certificate", "Certificate validation", certificateStatus,
                tlsResult.Subject is null ? tlsResult.ErrorMessage ?? "No server certificate was available." :
                tlsResult.HostnameMatches == false ? "Certificate hostname mismatch" :
                tlsResult.ChainValid == false ? "Certificate chain validation failed" : "Certificate identity and chain validated",
                TimeSpan.Zero, ("subject", tlsResult.Subject), ("issuer", tlsResult.Issuer),
                ("notBefore", tlsResult.NotBefore), ("expires", tlsResult.NotAfter),
                ("subjectAlternativeNames", tlsResult.SubjectAlternativeNames),
                ("hostnameMatches", tlsResult.HostnameMatches), ("chainValid", tlsResult.ChainValid)));
            if (tlsResult.Status != DiagnosticStatus.Passed)
            {
                results.Add(Skipped("http", "HTTP", "TLS validation failed."));
                findings.Add(new("tls-validation-failed", "TLS validation failed", FindingSeverity.Error,
                    tlsResult.ErrorMessage ?? "The TLS handshake or certificate validation failed.", [target.Hostname],
                    [new("check-tls-path", "Check DNS destination, proxy settings, certificate trust, and possible TLS inspection.")]));
                return CreateReport(target, service, results, findings, DiagnosticStatus.Failed, DiagnosticStatus.Passed,
                    "TCP connectivity works, but TLS validation failed.");
            }
        }

        var httpResult = await http.ProbeAsync(target, limits.Http, cancellationToken).ConfigureAwait(false);
        var httpStatus = httpResult.StatusCode is null ? httpResult.Status :
            httpResult.StatusCode is >= 200 and < 400 ? DiagnosticStatus.Passed : DiagnosticStatus.Warning;
        results.Add(ToResult("http", "HTTP connectivity", httpStatus,
            httpResult.StatusCode is null ? httpResult.ErrorMessage : $"HTTP {httpResult.StatusCode} {httpResult.ReasonPhrase}",
            httpResult.Duration, ("uri", SafeAuthority(httpResult.Uri)), ("statusCode", httpResult.StatusCode),
            ("redirectLocation", httpResult.RedirectLocation is null ? null : SafeAuthority(httpResult.RedirectLocation))));
        if (httpResult.StatusCode == 401)
            findings.Add(new("http-authentication-required", "Endpoint reachable; authentication is required", FindingSeverity.Warning,
                "The HTTPS endpoint responded with 401 Unauthorized. Authentication was not supplied or was not accepted.",
                ["HTTP status = 401"], [new("verify-identity", "Verify the expected Microsoft Entra ID tenant and credential availability.")]));
        else if (httpResult.StatusCode == 403)
            findings.Add(new("http-access-denied", "Endpoint reachable; request was denied", FindingSeverity.Warning,
                "The service returned HTTP 403. Possible causes include authorization or service network access restrictions; the status alone does not identify which.",
                ["HTTP status = 403"], [new("review-service-access", "Review service permissions and network access configuration.")]));
        else if (httpResult.StatusCode is >= 400)
            findings.Add(new("http-application-response", "Endpoint returned an HTTP error response", FindingSeverity.Warning,
                $"The HTTPS endpoint is reachable and returned HTTP {httpResult.StatusCode} {httpResult.ReasonPhrase}.",
                [$"HTTP status = {httpResult.StatusCode}"], []));
        else if (httpResult.StatusCode is null || httpResult.Status == DiagnosticStatus.Failed)
            findings.Add(new("http-connectivity-failed", "HTTP probe did not receive a response", FindingSeverity.Error,
                httpResult.ErrorMessage ?? "The HTTP request failed before an HTTP status was received.",
                [httpResult.Uri],
                [new("check-http-path", "Check proxy configuration and the HTTP path from this machine to the endpoint.")]));

        var overall = findings.Any(finding => finding.Severity == FindingSeverity.Error) ? DiagnosticStatus.Failed :
            findings.Any(finding => finding.Severity == FindingSeverity.Warning) || results.Any(result => result.Status == DiagnosticStatus.Warning)
                ? DiagnosticStatus.Warning : DiagnosticStatus.Passed;
        var httpFailed = httpResult.StatusCode is null || httpResult.Status == DiagnosticStatus.Failed;
        var message = httpFailed
            ? "Direct TCP and TLS connectivity succeeded, but the HTTP probe did not receive a response."
            : tcpStatus == DiagnosticStatus.Warning
                ? "TCP succeeded for some resolved addresses; other address attempts failed."
                : overall == DiagnosticStatus.Warning
                    ? "Network connectivity is working; the service returned an application-level warning."
                    : "Network connectivity to the endpoint is working.";
        return CreateReport(target, service, results, findings, overall,
            httpFailed || tcpStatus == DiagnosticStatus.Warning
                ? DiagnosticStatus.Warning : DiagnosticStatus.Passed, message,
            httpResult.StatusCode is 401 or 403 ? DiagnosticStatus.Warning : DiagnosticStatus.Skipped);
    }

    private static bool HostMatches(string hostname, string pattern) => pattern.StartsWith("*.", StringComparison.Ordinal)
        ? hostname.EndsWith(pattern[1..], StringComparison.OrdinalIgnoreCase)
        : hostname.Equals(pattern, StringComparison.OrdinalIgnoreCase);

    private static bool MatchesAddressFamily(IPAddress address, DiagnosticAddressFamily family) => family switch
    {
        DiagnosticAddressFamily.IPv4 => address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork,
        DiagnosticAddressFamily.IPv6 => address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6,
        _ => true
    };

    private static string SafeAuthority(string value) => Uri.TryCreate(value, UriKind.Absolute, out var uri)
        ? uri.GetLeftPart(UriPartial.Authority)
        : string.Empty;

    private static DiagnosticResult ToResult(string id, string name, DiagnosticStatus status, string? summary,
        TimeSpan duration, params (string Key, object? Value)[] details) => new()
        {
            TestId = id, DisplayName = name, Status = status, Summary = summary, Duration = duration,
            Details = details.ToDictionary(item => item.Key, item => item.Value)
        };

    private static DiagnosticResult Skipped(string id, string name, string reason) =>
        ToResult(id, name, DiagnosticStatus.Skipped, reason, TimeSpan.Zero);

    private static DiagnosticReport CreateReport(DiagnosticTarget target, ServiceDetectionResult service,
        IReadOnlyList<DiagnosticResult> results, IReadOnlyList<DiagnosticFinding> findings,
        DiagnosticStatus overall, DiagnosticStatus connectivity, string message,
        DiagnosticStatus authentication = DiagnosticStatus.Skipped) =>
        new("1.0", target with { OriginalInput = SafeTargetInput(target), Path = "/" }, service,
            new DiagnosticPlan(results.Select(result => result.TestId).ToArray()),
            results, findings, new DiagnosticSummary(overall, connectivity, authentication, message));

    private static string SafeTargetInput(DiagnosticTarget target)
    {
        var host = target.IpAddress?.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
            ? $"[{target.Hostname}]" : target.Hostname;
        var port = target.ExplicitPort is int explicitPort ? $":{explicitPort}" : string.Empty;
        return target.Scheme is null ? $"{host}{port}" : $"{target.Scheme}://{host}{port}";
    }
}
