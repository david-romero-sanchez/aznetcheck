using AzNetCheck.Azure;
using AzNetCheck.Core;
using Xunit;

namespace AzNetCheck.Azure.Tests;

public sealed class ServiceCatalogTests
{
    [Fact]
    public void Service_override_selects_a_catalog_profile_for_custom_aliases()
    {
        var result = new AzureServiceCatalog().Detect("vault.internal.example", "keyvault");
        Assert.Equal(ServiceDetectionStatus.Detected, result.Status);
        Assert.Equal("azure-key-vault", result.Service!.Id);
    }

    [Fact]
    public void Storage_and_messaging_profiles_retain_multiple_transports()
    {
        var catalog = new AzureServiceCatalog();
        Assert.Contains(catalog.Services.Single(service => service.Id == "azure-file-storage").Transports,
            transport => transport.Port == 445 && !transport.Required);
        Assert.Equal(3, catalog.Services.Single(service => service.Id == "azure-service-bus").Transports.Count);
    }

    [Fact]
    public void Shared_servicebus_suffix_is_reported_as_ambiguous()
    {
        var result = new AzureServiceCatalog().Detect("namespace.servicebus.windows.net");

        Assert.Equal(ServiceDetectionStatus.Ambiguous, result.Status);
        Assert.Contains(result.Candidates, service => service.Id == "azure-service-bus");
        Assert.Contains(result.Candidates, service => service.Id == "azure-event-hubs");
    }
}