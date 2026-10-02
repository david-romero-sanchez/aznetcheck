using AzNetCheck.Core;
using AzNetCheck.Networking;
using Xunit;

namespace AzNetCheck.IntegrationTests;

public sealed class PublicDnsIntegrationTests
{
    [Fact]
    [Trait("Category", "Integration")]
    public async Task Resolves_example_com_when_network_access_is_available()
    {
        if (Environment.GetEnvironmentVariable("AZNETCHECK_RUN_INTEGRATION") != "1") return;
        var result = await new DnsClientDiagnostic().ResolveAsync("example.com", TimeSpan.FromSeconds(5), CancellationToken.None);
        Assert.NotEmpty(result.Addresses);
    }
}