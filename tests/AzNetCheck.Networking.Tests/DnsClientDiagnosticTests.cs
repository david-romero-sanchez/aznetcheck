using System.Net;
using AzNetCheck.Core;
using AzNetCheck.Networking;
using Xunit;

namespace AzNetCheck.Networking.Tests;

public sealed class DnsClientDiagnosticTests
{
    [Fact]
    public async Task Resolves_A_and_AAAA_through_a_cname_chain()
    {
        var queries = new FakeDnsQueryClient((hostname, type, _) => Task.FromResult((hostname, type) switch
        {
            ("service.test", DnsRecordType.A) => new DnsQueryResult("NoError", [], "edge.test"),
            ("edge.test", DnsRecordType.A) => new DnsQueryResult("NoError", [IPAddress.Parse("10.2.3.4")]),
            ("edge.test", DnsRecordType.AAAA) => new DnsQueryResult("NoError", [IPAddress.Parse("2001:db8::4")]),
            _ => new DnsQueryResult("NoError", [])
        }));

        var result = await new DnsClientDiagnostic(queries).ResolveAsync("service.test", TimeSpan.FromSeconds(1),
            CancellationToken.None);

        Assert.Equal(DiagnosticStatus.Passed, result.Status);
        Assert.Equal(["edge.test"], result.CnameChain);
        Assert.Contains("10.2.3.4", result.Addresses);
        Assert.Contains("2001:db8::4", result.Addresses);
    }

    [Fact]
    public async Task Detects_cname_loops()
    {
        var queries = new FakeDnsQueryClient((hostname, type, _) => Task.FromResult(
            type == DnsRecordType.A && hostname == "first.test"
                ? new DnsQueryResult("NoError", [], "second.test")
                : type == DnsRecordType.A && hostname == "second.test"
                    ? new DnsQueryResult("NoError", [], "first.test")
                    : new DnsQueryResult("NoError", [])));

        var result = await new DnsClientDiagnostic(queries).ResolveAsync("first.test", TimeSpan.FromSeconds(1),
            CancellationToken.None);

        Assert.Equal(DiagnosticStatus.Failed, result.Status);
        Assert.Equal("CnameLoop", result.ErrorCode);
    }

    [Fact]
    public async Task Reports_cname_depth_limit_as_inconclusive_not_success()
    {
        var queries = new FakeDnsQueryClient((hostname, type, _) => Task.FromResult(
            type == DnsRecordType.A
                ? new DnsQueryResult("NoError", [], $"node{int.Parse(hostname[4..].Split('.')[0]) + 1}.test")
                : new DnsQueryResult("NoError", [])));

        var result = await new DnsClientDiagnostic(queries).ResolveAsync("node0.test", TimeSpan.FromSeconds(1),
            CancellationToken.None);

        Assert.Equal(DiagnosticStatus.Inconclusive, result.Status);
        Assert.Equal("CnameDepthExceeded", result.ErrorCode);
        Assert.Equal(12, result.CnameChain.Count);
    }

    [Fact]
    public async Task Distinguishes_nxdomain_from_an_empty_successful_response()
    {
        var queries = new FakeDnsQueryClient((_, _, _) => Task.FromResult(new DnsQueryResult("NxDomain", [])));

        var result = await new DnsClientDiagnostic(queries).ResolveAsync("missing.test", TimeSpan.FromSeconds(1),
            CancellationToken.None);

        Assert.Equal(DiagnosticStatus.Failed, result.Status);
        Assert.Equal("NxDomain", result.ErrorCode);
        Assert.Contains("NXDOMAIN", result.ErrorMessage);
    }

    [Fact]
    public async Task Reports_empty_noerror_response_separately_from_servfail()
    {
        var emptyQueries = new FakeDnsQueryClient((_, _, _) => Task.FromResult(new DnsQueryResult("NoError", [])));
        var emptyResult = await new DnsClientDiagnostic(emptyQueries).ResolveAsync("empty.test", TimeSpan.FromSeconds(1),
            CancellationToken.None);
        var failedQueries = new FakeDnsQueryClient((_, _, _) => Task.FromResult(new DnsQueryResult("ServerFailure", [])));
        var failedResult = await new DnsClientDiagnostic(failedQueries).ResolveAsync("servfail.test", TimeSpan.FromSeconds(1),
            CancellationToken.None);

        Assert.Equal("NoRecords", emptyResult.ErrorCode);
        Assert.Contains("no A or AAAA", emptyResult.ErrorMessage);
        Assert.Equal("ServerFailure", failedResult.ErrorCode);
        Assert.Contains("SERVFAIL", failedResult.ErrorMessage);
    }

    [Fact]
    public async Task Converts_dns_timeout_into_a_result()
    {
        var queries = new FakeDnsQueryClient((_, _, token) => Task.Delay(Timeout.InfiniteTimeSpan, token)
            .ContinueWith<DnsQueryResult>(_ => new DnsQueryResult("NoError", []), token,
                TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default));

        var result = await new DnsClientDiagnostic(queries).ResolveAsync("slow.test", TimeSpan.FromMilliseconds(20),
            CancellationToken.None);

        Assert.Equal(DiagnosticStatus.Failed, result.Status);
        Assert.Equal("Timeout", result.ErrorCode);
    }

    private sealed class FakeDnsQueryClient(
        Func<string, DnsRecordType, CancellationToken, Task<DnsQueryResult>> query) : IDnsQueryClient
    {
        public Task<DnsQueryResult> QueryAsync(string hostname, DnsRecordType recordType,
            CancellationToken cancellationToken) => query(hostname, recordType, cancellationToken);
    }
}