using AzNetCheck.Core;
using System.Text.Json.Serialization;

namespace AzNetCheck.Azure;

[JsonSourceGenerationOptions(PropertyNameCaseInsensitive = true)]
[JsonSerializable(typeof(List<AzureServiceDefinition>))]
internal sealed partial class AzureServiceCatalogJsonSerializerContext : JsonSerializerContext
{
}
