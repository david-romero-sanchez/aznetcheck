namespace AzNetCheck.Updater;

public sealed class UpdateManager(GitHubUpdateClient client, UpdateInstaller installer, IUpdateLogger? logger = null)
{
    private readonly IUpdateLogger _logger = logger ?? NullUpdateLogger.Instance;

    public Task<UpdateCheckResult> CheckForUpdatesAsync(bool force = false,
        CancellationToken cancellationToken = default) =>
        client.CheckForUpdatesAsync(force, allowFailedVersionRetry: force, cancellationToken: cancellationToken);

    public async Task<UpdateApplyResult> ApplyLatestAsync(bool force = false,
        CancellationToken cancellationToken = default)
    {
        if (!installer.TryGetWritableInstallation(out _, out var installError))
            return new(UpdateApplyStatus.InstallationNotSupported, Error: installError);

        var check = await client.CheckForUpdatesAsync(force: true, allowFailedVersionRetry: force,
            cancellationToken: cancellationToken)
            .ConfigureAwait(false);
        switch (check.Status)
        {
            case UpdateCheckStatus.UpToDate:
            case UpdateCheckStatus.CheckSkippedRecently:
                return new(UpdateApplyStatus.AlreadyCurrent, "AzNetCheck is already up to date.");
            case UpdateCheckStatus.CheckFailed:
                return new(UpdateApplyStatus.CheckFailed, Error: check.Error);
            case UpdateCheckStatus.InvalidManifest:
                return new(UpdateApplyStatus.InvalidManifest, Error: check.Error);
            case UpdateCheckStatus.UnsupportedPlatform:
                return new(UpdateApplyStatus.UnsupportedPlatform, Error: check.Error);
            case UpdateCheckStatus.UpdateBlockedAfterFailure:
                return new(UpdateApplyStatus.UpdateBlockedAfterFailure, Error: check.Error);
            case UpdateCheckStatus.UpdateAvailable:
                break;
            default:
                return new(UpdateApplyStatus.Failed, Error: "Unexpected update check result.");
        }

        try
        {
            var manifest = check.Manifest!;
            var asset = check.Asset!;
            var stagedPath = await client.DownloadVerifiedAssetAsync(manifest, asset, cancellationToken).ConfigureAwait(false);
            return await installer.StartApplyAsync(stagedPath, client.CurrentVersion, manifest.Version, asset.Sha256, asset.Size,
                cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception exception) when (exception is IOException or HttpRequestException or InvalidDataException or TimeoutException)
        {
            _logger.Log("update-download-failed", exception.GetType().Name);
            return new(UpdateApplyStatus.Failed, Error: "The update could not be downloaded and verified.");
        }
    }
}