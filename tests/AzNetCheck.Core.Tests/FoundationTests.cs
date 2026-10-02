using System.Net;
using System.Text.Json;
using AzNetCheck.Azure;
using AzNetCheck.Core;
using Xunit;

namespace AzNetCheck.Core.Tests;

public sealed class FoundationTests
{
    [Theory]
    [InlineData("contoso.vault.azure.net", "contoso.vault.azure.net", 443, null)]
    [InlineData("https://contoso.vault.azure.net/secrets?api=1", "contoso.vault.azure.net", 443, "/secrets?api=1")]
    [InlineData("myserver.database.windows.net:1433", "myserver.database.windows.net", 1433, null)]
    [InlineData("10.0.1.5:443", "10.0.1.5", 443, null)]
    [InlineData("[2001:db8::1]:8443", "2001:db8::1", 8443, null)]
    [InlineData("https://[2001:db8::1]:8443/path", "2001:db8::1", 8443, "/path")]
    public void Parses_supported_target_forms(string input, string expectedHost, int expectedPort, string? expectedPath)
    {
        Assert.True(DiagnosticTargetParser.TryParse(input, out var target, out var error), error);
        Assert.Equal(expectedHost, target!.Hostname);
        Assert.Equal(expectedPort, target.EffectivePort);
        if (expectedPath is not null) Assert.Equal(expectedPath, target.Path);
    }

    [Fact]
    public void Preserves_an_explicit_https_default_port()
    {
        Assert.True(DiagnosticTargetParser.TryParse("https://contoso.vault.azure.net:443", out var target, out _));
        Assert.Equal(443, target!.ExplicitPort);
        Assert.Equal(443, target.EffectivePort);
    }

    [Theory]
    [InlineData("10.1.2.3", IpAddressKind.Private)]
    [InlineData("172.15.1.1", IpAddressKind.Public)]
    [InlineData("172.16.1.1", IpAddressKind.Private)]
    [InlineData("172.31.255.255", IpAddressKind.Private)]
    [InlineData("172.32.0.1", IpAddressKind.Public)]
    [InlineData("192.168.1.10", IpAddressKind.Private)]
    public void Classifies_ipv4_ranges(string value, IpAddressKind expected) =>
        Assert.Equal(expected, IpAddressClassifier.Classify(IPAddress.Parse(value)));

    [Theory]
    [InlineData("foo.vault.azure.net", "azure-key-vault")]
    [InlineData("foo.blob.core.windows.net", "azure-blob-storage")]
    [InlineData("foo.queue.core.windows.net", "azure-queue-storage")]
    [InlineData("foo.table.core.windows.net", "azure-table-storage")]
    [InlineData("foo.file.core.windows.net", "azure-file-storage")]
    [InlineData("foo.privatelink.vaultcore.azure.net", "azure-key-vault")]
    public void Detects_catalog_services_including_private_link(string hostname, string expectedService)
    {
        var result = new AzureServiceCatalog().Detect(hostname);
        Assert.Equal(ServiceDetectionStatus.Detected, result.Status);
        Assert.Equal(expectedService, result.Service!.Id);
    }

    [Fact]
    public void Leaves_unknown_hostnames_unknown() =>
        Assert.Equal(ServiceDetectionStatus.Unknown, new AzureServiceCatalog().Detect("internal-api.contoso.local").Status);

    [Fact]
    public async Task Http_401_keeps_network_connectivity_healthy_and_adds_authentication_finding()
    {
        var report = await CreateEngine(new DnsResolutionResult(DiagnosticStatus.Passed, ["203.0.113.10"], [], TimeSpan.Zero),
            new HttpProbeResult(DiagnosticStatus.Passed, "https://vault.vault.azure.net/", 401, "Unauthorized", TimeSpan.Zero))
            .RunAsync(Parse("vault.vault.azure.net"));
        Assert.Equal(DiagnosticStatus.Warning, report.Summary.OverallStatus);
        Assert.Equal(DiagnosticStatus.Passed, report.Summary.NetworkConnectivity);
        Assert.Equal(DiagnosticStatus.Warning, report.Summary.Authentication);
        Assert.Contains(report.Findings, finding => finding.Id == "http-authentication-required");
    }

    [Fact]
    public async Task Http_403_does_not_claim_that_rbac_is_the_cause()
    {
        var report = await CreateEngine(new DnsResolutionResult(DiagnosticStatus.Passed, ["203.0.113.10"], [], TimeSpan.Zero),
            new HttpProbeResult(DiagnosticStatus.Passed, "https://vault.vault.azure.net/", 403, "Forbidden", TimeSpan.Zero))
            .RunAsync(Parse("vault.vault.azure.net"));
        Assert.Equal(DiagnosticStatus.Passed, report.Summary.NetworkConnectivity);
        Assert.Equal(DiagnosticStatus.Warning, report.Summary.Authentication);
        Assert.Contains("Possible causes", report.Findings.Single(finding => finding.Id == "http-access-denied").Description);
    }

    [Fact]
    public async Task Http_transport_failure_is_not_aggregated_as_success()
    {
        var report = await CreateEngine(new DnsResolutionResult(DiagnosticStatus.Passed, ["203.0.113.10"], [], TimeSpan.Zero),
            new HttpProbeResult(DiagnosticStatus.Failed, "https://vault.vault.azure.net", null, null, TimeSpan.Zero,
                ErrorMessage: "HTTP request timed out.")).RunAsync(Parse("vault.vault.azure.net"));

        Assert.Equal(DiagnosticStatus.Failed, report.Summary.OverallStatus);
        Assert.Equal(DiagnosticStatus.Warning, report.Summary.NetworkConnectivity);
        Assert.Contains("HTTP probe did not receive a response", report.Summary.Message);
        Assert.Contains(report.Findings, finding => finding.Id == "http-connectivity-failed");
    }

    [Fact]
    public async Task Tcp_connection_refused_is_interpreted_as_an_active_refusal()
    {
        var report = await CreateEngine(new DnsResolutionResult(DiagnosticStatus.Passed, ["203.0.113.10"], [], TimeSpan.Zero),
            new HttpProbeResult(DiagnosticStatus.Skipped, "", null, null, TimeSpan.Zero),
            [DiagnosticStatus.Failed], "ConnectionRefused").RunAsync(Parse("vault.vault.azure.net"));

        var finding = report.Findings.Single(item => item.Id == "tcp-connectivity-failed");
        Assert.Contains("actively refused", finding.Description);
        Assert.Contains("listening", finding.Recommendations[0].Text);
    }

    [Fact]
    public async Task Private_link_tcp_timeout_suggests_network_checks_without_claiming_a_cause()
    {
        var report = await CreateEngine(
            new DnsResolutionResult(DiagnosticStatus.Passed, ["10.20.30.40"], ["vault.privatelink.vaultcore.azure.net"], TimeSpan.Zero),
            new HttpProbeResult(DiagnosticStatus.Skipped, "", null, null, TimeSpan.Zero), [DiagnosticStatus.Failed])
            .RunAsync(Parse("vault.vault.azure.net"));
        var finding = report.Findings.Single(item => item.Id == "tcp-connectivity-failed");
        Assert.Equal(DiagnosticStatus.Failed, report.Summary.NetworkConnectivity);
        Assert.Contains("cannot be determined", finding.Description);
        Assert.Contains(finding.Recommendations, recommendation => recommendation.Text.Contains("routing", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Dns_failure_skips_dependent_tests()
    {
        var report = await CreateEngine(new DnsResolutionResult(DiagnosticStatus.Failed, [], [], TimeSpan.Zero,
            "NXDOMAIN", "Name does not exist."), new HttpProbeResult(DiagnosticStatus.Skipped, "", null, null, TimeSpan.Zero))
            .RunAsync(Parse("missing.vault.azure.net"));
        Assert.Equal(DiagnosticStatus.Failed, report.Results.Single(result => result.TestId == "dns").Status);
        Assert.All(report.Results.Where(result => result.TestId is "tcp" or "tls" or "certificate" or "http"),
            result => Assert.Equal(DiagnosticStatus.Skipped, result.Status));
    }

    [Fact]
    public async Task Partial_tcp_success_is_a_warning_and_does_not_hide_a_valid_certificate()
    {
        var report = await CreateEngine(
            new DnsResolutionResult(DiagnosticStatus.Passed, ["203.0.113.10", "203.0.113.11"], [], TimeSpan.Zero),
            new HttpProbeResult(DiagnosticStatus.Passed, "https://vault.vault.azure.net/", 200, "OK", TimeSpan.Zero),
            [DiagnosticStatus.Passed, DiagnosticStatus.Failed]).RunAsync(Parse("vault.vault.azure.net"));

        Assert.Equal(DiagnosticStatus.Warning, report.Summary.OverallStatus);
        Assert.Equal(DiagnosticStatus.Warning, report.Summary.NetworkConnectivity);
        Assert.Equal(DiagnosticStatus.Passed, report.Results.Single(result => result.TestId == "certificate").Status);
        Assert.Contains(report.Findings, finding => finding.Id == "tcp-partial-connectivity");
    }

    [Fact]
    public async Task Tls_uses_the_same_address_that_passed_tcp()
    {
        var tls = new FakeTls();
        var engine = new DiagnosticEngine(new AzureServiceCatalog(),
            new FakeDns(new DnsResolutionResult(DiagnosticStatus.Passed, ["192.0.2.10", "2001:db8::10"], [], TimeSpan.Zero)),
            new FakeTcp([DiagnosticStatus.Failed, DiagnosticStatus.Passed]), tls,
            new FakeHttp(new HttpProbeResult(DiagnosticStatus.Passed, "https://vault.vault.azure.net", 200, "OK", TimeSpan.Zero)));

        await engine.RunAsync(Parse("vault.vault.azure.net"));

        Assert.Equal(IPAddress.Parse("2001:db8::10"), tls.Address);
    }

    [Fact]
    public async Task Address_family_filter_limits_tcp_attempts()
    {
        var engine = CreateEngine(new DnsResolutionResult(DiagnosticStatus.Passed,
            ["192.0.2.10", "2001:db8::10"], [], TimeSpan.Zero),
            new HttpProbeResult(DiagnosticStatus.Passed, "https://vault.vault.azure.net", 200, "OK", TimeSpan.Zero));

        var report = await engine.RunAsync(Parse("vault.vault.azure.net"), addressFamily: DiagnosticAddressFamily.IPv4);

        var attempts = Assert.IsAssignableFrom<IEnumerable<TcpProbeResult>>(
            report.Results.Single(result => result.TestId == "tcp").Details["attempts"]).ToArray();
        Assert.Single(attempts);
        Assert.Equal("192.0.2.10", attempts[0].Address);
    }

    [Fact]
    public async Task Address_family_without_matching_addresses_is_inconclusive_and_skips_network_tests()
    {
        var engine = CreateEngine(new DnsResolutionResult(DiagnosticStatus.Passed, ["192.0.2.10"], [], TimeSpan.Zero),
            new HttpProbeResult(DiagnosticStatus.Skipped, "", null, null, TimeSpan.Zero));

        var report = await engine.RunAsync(Parse("vault.vault.azure.net"), addressFamily: DiagnosticAddressFamily.IPv6);

        Assert.Equal(DiagnosticStatus.Inconclusive, report.Summary.OverallStatus);
        Assert.Equal(DiagnosticStatus.Skipped, report.Results.Single(result => result.TestId == "tcp").Status);
    }

    [Fact]
    public async Task Azure_sql_uses_tcp_1433_and_skips_tls_and_http()
    {
        var tls = new FakeTls();
        var http = new FakeHttp(new HttpProbeResult(DiagnosticStatus.Passed, "", 200, "OK", TimeSpan.Zero));
        var engine = new DiagnosticEngine(new AzureServiceCatalog(),
            new FakeDns(new DnsResolutionResult(DiagnosticStatus.Passed, ["10.2.3.4"], [], TimeSpan.Zero)),
            new FakeTcp(null), tls, http);

        var report = await engine.RunAsync(Parse("sql.database.windows.net"));
        var tcpAttempts = Assert.IsAssignableFrom<IEnumerable<TcpProbeResult>>(
            report.Results.Single(result => result.TestId == "tcp").Details["attempts"]);

        Assert.Equal(1433, Assert.Single(tcpAttempts).Port);
        Assert.Equal(DiagnosticStatus.Skipped, report.Results.Single(result => result.TestId == "tls").Status);
        Assert.Equal(DiagnosticStatus.Skipped, report.Results.Single(result => result.TestId == "http").Status);
        Assert.Equal(0, tls.CallCount);
        Assert.Equal(0, http.CallCount);
    }

    [Fact]
    public async Task Ip_literal_skips_dns_but_still_runs_tcp_diagnostics()
    {
        var dns = new FakeDns(new DnsResolutionResult(DiagnosticStatus.Failed, [], [], TimeSpan.Zero,
            "Unexpected", "DNS must not run for an IP literal."));
        var engine = new DiagnosticEngine(new AzureServiceCatalog(), dns, new FakeTcp(null), new FakeTls(),
            new FakeHttp(new HttpProbeResult(DiagnosticStatus.Passed, "https://192.0.2.1", 200, "OK", TimeSpan.Zero)));

        var report = await engine.RunAsync(Parse("192.0.2.1:443"));

        Assert.Equal(0, dns.CallCount);
        var dnsResult = report.Results.Single(result => result.TestId == "dns");
        Assert.Equal(DiagnosticStatus.NotApplicable, dnsResult.Status);
        Assert.Contains("not required", dnsResult.Summary);
        Assert.Equal(DiagnosticStatus.Passed, report.Results.Single(result => result.TestId == "tcp").Status);
    }

    [Fact]
    public async Task Json_report_is_versioned_and_does_not_expose_target_query_parameters()
    {
        const string secretValue = "test-signature-value";
        var report = await CreateEngine(
            new DnsResolutionResult(DiagnosticStatus.Passed, ["203.0.113.10"], [], TimeSpan.Zero),
            new HttpProbeResult(DiagnosticStatus.Passed,
                $"https://vault.vault.azure.net/secrets?sig={secretValue}", 200, "OK", TimeSpan.Zero))
            .RunAsync(Parse($"https://vault.vault.azure.net/secrets?sig={secretValue}"));

        var json = JsonSerializer.Serialize(report, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
        Assert.Contains("\"schemaVersion\":\"1.0\"", json);
        Assert.DoesNotContain(secretValue, json);
        Assert.DoesNotContain("sig=", json);
    }

    [Fact]
    public async Task Json_target_keeps_scheme_and_explicit_port_but_omits_path_and_query()
    {
        const string secretValue = "sensitive-value";
        var report = await CreateEngine(
            new DnsResolutionResult(DiagnosticStatus.Passed, ["203.0.113.10"], [], TimeSpan.Zero),
            new HttpProbeResult(DiagnosticStatus.Passed, "https://vault.vault.azure.net:9443", 200, "OK", TimeSpan.Zero))
            .RunAsync(Parse($"https://vault.vault.azure.net:9443/secrets?sig={secretValue}"));
        var json = JsonSerializer.Serialize(report, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });

        Assert.Equal("https://vault.vault.azure.net:9443", report.Target.OriginalInput);
        Assert.Equal("/", report.Target.Path);
        Assert.Contains("9443", json);
        Assert.DoesNotContain(secretValue, json);
        Assert.DoesNotContain("/secrets", json);
    }

    private static DiagnosticTarget Parse(string value)
    {
        Assert.True(DiagnosticTargetParser.TryParse(value, out var target, out _));
        return target!;
    }

    private static DiagnosticEngine CreateEngine(DnsResolutionResult dnsResult, HttpProbeResult httpResult,
        IReadOnlyList<DiagnosticStatus>? tcpStatuses = null, string? tcpSocketError = null) =>
        new(new AzureServiceCatalog(), new FakeDns(dnsResult), new FakeTcp(tcpStatuses, tcpSocketError), new FakeTls(), new FakeHttp(httpResult));

    private sealed class FakeDns(DnsResolutionResult result) : IDnsDiagnostic
    {
        public int CallCount { get; private set; }

        public Task<DnsResolutionResult> ResolveAsync(string hostname, TimeSpan timeout, CancellationToken cancellationToken)
        {
            CallCount++;
            return Task.FromResult(result);
        }
    }

    private sealed class FakeTcp(IReadOnlyList<DiagnosticStatus>? statuses, string? socketError = null) : ITcpDiagnostic
    {
        private int _attempt;

        public Task<TcpProbeResult> ConnectAsync(IPAddress address, int port, TimeSpan timeout, CancellationToken cancellationToken)
        {
            var status = statuses is { Count: > 0 } ? statuses[Math.Min(_attempt++, statuses.Count - 1)] : DiagnosticStatus.Passed;
            return Task.FromResult(new TcpProbeResult(status, address.ToString(), port, TimeSpan.Zero,
                status == DiagnosticStatus.Failed ? socketError ?? "TimedOut" : null,
                status == DiagnosticStatus.Failed ? socketError == "ConnectionRefused" ? "Connection refused." : "Connection timed out." : null));
        }
    }

    private sealed class FakeTls : ITlsDiagnostic
    {
        public IPAddress? Address { get; private set; }
        public int CallCount { get; private set; }

        public Task<TlsProbeResult> HandshakeAsync(string hostname, IPAddress address, int port, TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            Address = address;
            CallCount++;
            return Task.FromResult(new TlsProbeResult(DiagnosticStatus.Passed, hostname, port, TimeSpan.Zero,
                "Tls13", ChainValid: true, HostnameMatches: true));
        }
    }

    private sealed class FakeHttp(HttpProbeResult result) : IHttpDiagnostic
    {
        public int CallCount { get; private set; }

        public Task<HttpProbeResult> ProbeAsync(DiagnosticTarget target, TimeSpan timeout, CancellationToken cancellationToken)
        {
            CallCount++;
            return Task.FromResult(result);
        }
    }
}