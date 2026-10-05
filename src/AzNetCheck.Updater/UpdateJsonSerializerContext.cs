using System.Text.Json.Serialization;

namespace AzNetCheck.Updater;

[JsonSourceGenerationOptions(WriteIndented = true)]
[JsonSerializable(typeof(UpdateState))]
[JsonSerializable(typeof(UpdateTransaction))]
[JsonSerializable(typeof(UpdateManifest))]
internal sealed partial class UpdateJsonSerializerContext : JsonSerializerContext
{
}