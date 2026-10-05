using System.Text.Json.Serialization;
using AzNetCheck.Updater;

namespace AzNetCheck.Cli;

[JsonSerializable(typeof(UpdateCheckResult))]
[JsonSerializable(typeof(UpdateApplyResult))]
internal sealed partial class UpdateJsonSerializerContext : JsonSerializerContext
{
}