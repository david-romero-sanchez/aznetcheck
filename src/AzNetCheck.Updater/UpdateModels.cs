using System.Text.Json.Serialization;

namespace AzNetCheck.Updater;

public sealed record UpdateManifest
{
    [JsonPropertyName("manifestVersion")]
    public required int ManifestVersion { get; init; }

    [JsonPropertyName("version")]
    public required string Version { get; init; }

    [JsonPropertyName("publishedAtUtc")]
    public required DateTimeOffset PublishedAtUtc { get; init; }

    [JsonPropertyName("assets")]
    public required Dictionary<string, UpdateAsset> Assets { get; init; }
}

public sealed record UpdateAsset
{
    [JsonPropertyName("fileName")]
    public required string FileName { get; init; }

    [JsonPropertyName("url")]
    public required string Url { get; init; }

    [JsonPropertyName("sha256")]
    public required string Sha256 { get; init; }

    [JsonPropertyName("size")]
    public required long Size { get; init; }
}

public enum UpdateCheckStatus
{
    UpdateAvailable,
    UpToDate,
    CheckSkippedRecently,
    CheckFailed,
    InvalidManifest,
    UnsupportedPlatform,
    UpdateBlockedAfterFailure
}

public sealed record UpdateCheckResult(UpdateCheckStatus Status, UpdateManifest? Manifest = null,
    UpdateAsset? Asset = null, string? Error = null);

public enum UpdateApplyStatus
{
    Started,
    AlreadyCurrent,
    CheckFailed,
    InvalidManifest,
    UnsupportedPlatform,
    InstallationNotSupported,
    UpdateBlockedAfterFailure,
    Failed
}

public sealed record UpdateApplyResult(UpdateApplyStatus Status, string? Message = null, string? Error = null);

public sealed record UpdateOptions(string Owner, string Repository, string CurrentVersion, TimeSpan CheckInterval,
    string? SupportedRid = null, string? StateDirectory = null, bool IncludePrerelease = false)
{
    public static UpdateOptions Default(string currentVersion, string? stateDirectory = null) =>
        new("david-romero-sanchez", "aznetcheck", currentVersion, TimeSpan.FromHours(24),
            UpdatePlatform.GetSupportedRid(), stateDirectory);
}

public static class UpdatePlatform
{
    public static string? GetSupportedRid()
    {
        if (OperatingSystem.IsWindows() && System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture ==
            System.Runtime.InteropServices.Architecture.X64)
            return "win-x64";
        return null;
    }
}

public interface IUpdateLogger
{
    void Log(string eventName, string? detail = null);
}

public sealed class NullUpdateLogger : IUpdateLogger
{
    public static NullUpdateLogger Instance { get; } = new();
    private NullUpdateLogger() { }
    public void Log(string eventName, string? detail = null) { }
}

public sealed record FailedUpdate(DateTimeOffset FailedAtUtc, string Reason);

public sealed record UpdateState
{
    public int SchemaVersion { get; init; } = 1;
    public DateTimeOffset? LastCheckUtc { get; init; }
    public Dictionary<string, FailedUpdate> FailedVersions { get; init; } = new(StringComparer.OrdinalIgnoreCase);
}

public enum UpdateTransactionStatus
{
    Downloaded,
    Applying,
    AwaitingHealthCheck,
    Succeeded,
    RollingBack,
    RolledBack,
    Failed
}

public sealed record UpdateTransaction
{
    public int SchemaVersion { get; init; } = 1;
    public required string TransactionId { get; init; }
    public required string FromVersion { get; init; }
    public required string ToVersion { get; init; }
    public required string TargetExecutablePath { get; init; }
    public required string StagedExecutablePath { get; init; }
    public required string BackupExecutablePath { get; init; }
    public required string FailedExecutablePath { get; init; }
    public required string Sha256 { get; init; }
    public required int OldProcessId { get; init; }
    public required DateTimeOffset OldProcessStartedUtc { get; init; }
    public required DateTimeOffset CreatedAtUtc { get; init; }
    public UpdateTransactionStatus Status { get; init; } = UpdateTransactionStatus.Downloaded;
    public string? FailureReason { get; init; }
}

public sealed record ProcessIdentity(int ProcessId, DateTimeOffset StartedAtUtc, string ExecutablePath);