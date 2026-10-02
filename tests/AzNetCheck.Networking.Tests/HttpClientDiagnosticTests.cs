using System.Net;
using AzNetCheck.Core;
using AzNetCheck.Networking;
using Xunit;

namespace AzNetCheck.Networking.Tests;

public sealed class HttpClientDiagnosticTests
{
    [Fact]
    public async Task Uses_get_and_reports_redirect_without_following_or_exposing_query()
    {
        HttpRequestMessage? observedRequest = null;
        using var client = new HttpClient(new StubHandler((request, _) =>
        {
            observedRequest = request;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Redirect)
            {
                Headers = { Location = new Uri("https://redirect.example/path?sig=secret") }
            });
        }));
        using var diagnostic = new HttpClientDiagnostic(client);

        var result = await diagnostic.ProbeAsync(Parse("https://endpoint.example/path?sig=input-secret"),
            TimeSpan.FromSeconds(1), CancellationToken.None);

        Assert.Equal(HttpMethod.Get, observedRequest!.Method);
        Assert.Equal("input-secret", System.Web.HttpUtility.ParseQueryString(observedRequest.RequestUri!.Query)["sig"]);
        Assert.Equal((int)HttpStatusCode.Redirect, result.StatusCode);
        Assert.Equal("https://endpoint.example", result.Uri);
        Assert.Equal("https://redirect.example", result.RedirectLocation);
        Assert.DoesNotContain("secret", result.Uri);
        Assert.DoesNotContain("secret", result.RedirectLocation);
    }

    [Fact]
    public async Task Converts_http_timeout_to_a_structured_failure()
    {
        using var client = new HttpClient(new StubHandler(async (_, cancellationToken) =>
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.OK);
        }));
        using var diagnostic = new HttpClientDiagnostic(client);

        var result = await diagnostic.ProbeAsync(Parse("https://endpoint.example"),
            TimeSpan.FromMilliseconds(20), CancellationToken.None);

        Assert.Equal(DiagnosticStatus.Failed, result.Status);
        Assert.Equal("HTTP request timed out.", result.ErrorMessage);
        Assert.Null(result.StatusCode);
    }

    private static DiagnosticTarget Parse(string input)
    {
        Assert.True(DiagnosticTargetParser.TryParse(input, out var target, out var error), error);
        return target!;
    }

    private sealed class StubHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send)
        : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            send(request, cancellationToken);
    }
}