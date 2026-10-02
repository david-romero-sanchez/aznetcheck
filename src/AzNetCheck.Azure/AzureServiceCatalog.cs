using AzNetCheck.Core;
using System.Reflection;
using System.Text.Json;

namespace AzNetCheck.Azure;

public sealed class AzureServiceCatalog : IAzureServiceDetector
{
    private readonly IReadOnlyList<AzureServiceDefinition> _services;

    public AzureServiceCatalog() : this(LoadEmbeddedCatalog()) { }
    public AzureServiceCatalog(IReadOnlyList<AzureServiceDefinition> services) => _services = services;
    public IReadOnlyList<AzureServiceDefinition> Services => _services;

    public ServiceDetectionResult Detect(string hostname, string? serviceOverride = null)
    {
        if (!string.IsNullOrWhiteSpace(serviceOverride))
        {
            static string NormalizeAlias(string value) => string.Concat(value.Where(char.IsLetterOrDigit));
            var requested = NormalizeAlias(serviceOverride);
            var forced = _services.FirstOrDefault(service =>
                NormalizeAlias(service.Id) == requested ||
                NormalizeAlias(service.Id.Replace("azure-", "", StringComparison.OrdinalIgnoreCase)) == requested ||
                NormalizeAlias(service.DisplayName) == requested);
            return forced is null
                ? new(ServiceDetectionStatus.Unknown, null, [], $"Unknown service override '{serviceOverride}'.")
                : new(ServiceDetectionStatus.Detected, forced, [forced], "Service selected by explicit override.");
        }

        var normalized = hostname.TrimEnd('.').ToLowerInvariant();
        var matches = _services.Where(service => service.HostnamePatterns.Concat(service.PrivateLinkPatterns)
            .Any(pattern => Matches(normalized, pattern))).ToArray();
        return matches.Length switch
        {
            1 => new(ServiceDetectionStatus.Detected, matches[0], matches, "Hostname matches a known Azure service pattern."),
            > 1 => new(ServiceDetectionStatus.Ambiguous, null, matches, "Hostname matches multiple Azure service patterns."),
            _ => new(ServiceDetectionStatus.Unknown, null, [], "No known Azure service pattern matched; generic diagnostics can be used.")
        };
    }

    private static bool Matches(string hostname, string pattern)
    {
        var normalizedPattern = pattern.ToLowerInvariant();
        if (normalizedPattern.StartsWith("*.", StringComparison.Ordinal))
        {
            var suffix = normalizedPattern[1..];
            return hostname.EndsWith(suffix, StringComparison.Ordinal) && hostname.Length > suffix.Length;
        }
        return hostname.Equals(normalizedPattern, StringComparison.Ordinal);
    }

    private static IReadOnlyList<AzureServiceDefinition> LoadEmbeddedCatalog()
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("AzNetCheck.Azure.service-catalog.json")
            ?? throw new InvalidOperationException("Embedded Azure service catalog was not found.");
        return JsonSerializer.Deserialize<List<AzureServiceDefinition>>(stream,
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
            ?? throw new InvalidDataException("Embedded Azure service catalog is empty.");
    }
}