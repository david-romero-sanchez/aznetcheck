using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NuGet.Versioning;

namespace AzNetCheck.Updater;

public sealed class GitHubUpdateClient(
    HttpClient httpClient,
    UpdateOptions options,
    UpdateManifestVerifier manifestVerifier,
    UpdateStateStore stateStore,
    IUpdateLogger? logger = null,
    Func<DateTimeOffset>? utcNow = null)
{
    private const int MaximumManifestBytes = 1024 * 1024;
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(20);
    private static readonly TimeSpan FailedVersionCooldown = TimeSpan.FromDays(7);
    private readonly IUpdateLogger _logger = logger ?? NullUpdateLogger.Instance;
    private readonly Func<DateTimeOffset> _utcNow = utcNow ?? (() => DateTimeOffset.UtcNow);
    public string CurrentVersion => options.CurrentVersion;

    public async Task<UpdateCheckResult> CheckForUpdatesAsync(bool force = false,
        bool allowFailedVersionRetry = false,
        CancellationToken cancellationToken = default)
    {
        var rid = options.SupportedRid ?? UpdatePlatform.GetSupportedRid();
        if (rid is null) return new(UpdateCheckStatus.UnsupportedPlatform, Error: "No updater asset is configured for this platform.");
        if (!NuGetVersion.TryParse(options.CurrentVersion, out var currentVersion))
            return new(UpdateCheckStatus.CheckFailed, Error: "The running application version is not valid SemVer.");

        UpdateState state;
        try { state = await stateStore.LoadAsync(cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) { throw; }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            _logger.Log("update-state-read-failed", exception.GetType().Name);
            state = new UpdateState();
        }

        if (!force && state.LastCheckUtc is DateTimeOffset lastCheck && _utcNow() - lastCheck < options.CheckInterval)
            return new(UpdateCheckStatus.CheckSkippedRecently);

        _logger.Log("checking-for-update", options.Repository);
        var result = await FetchAndValidateAsync(rid, currentVersion, state, allowFailedVersionRetry,
            cancellationToken).ConfigureAwait(false);
        try
        {
            await stateStore.SaveAsync(state with { LastCheckUtc = _utcNow() }, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            _logger.Log("update-state-write-failed", exception.GetType().Name);
        }
        return result;
    }

    public async Task<string> DownloadVerifiedAssetAsync(UpdateManifest manifest, UpdateAsset asset,
        CancellationToken cancellationToken = default)
    {
        var rid = options.SupportedRid ?? UpdatePlatform.GetSupportedRid();
        if (rid is null) throw new InvalidDataException("No update asset is configured for this runtime.");
        if (!UpdateManifestVerifier.TrySelectAsset(manifest, rid, options.Owner, options.Repository,
                out var selectedAsset, out var assetError))
            throw new InvalidDataException(assetError ?? "Update asset is invalid.");
        if (selectedAsset != asset)
            throw new InvalidDataException("Update asset does not match the signed manifest and current runtime.");
        var versionDirectory = stateStore.Paths.GetVersionDownloadDirectory(manifest.Version);
        Directory.CreateDirectory(versionDirectory);
        var finalPath = Path.Combine(versionDirectory, asset.FileName);
        if (File.Exists(finalPath))
        {
            if (await FileMatchesAssetAsync(finalPath, asset, cancellationToken).ConfigureAwait(false))
                return finalPath;
            File.Delete(finalPath);
        }

        var partialPath = finalPath + ".download";
        TryDelete(partialPath);
        _logger.Log("download-started", $"{manifest.Version}/{asset.FileName}");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromMinutes(30));
        try
        {
            using var request = CreateRequest(asset.Url);
            using var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead,
                timeout.Token).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
            ValidateFinalHttpsUri(response.RequestMessage?.RequestUri);
            if (response.Content.Headers.ContentLength is long contentLength && contentLength != asset.Size)
                throw new InvalidDataException("Downloaded asset Content-Length does not match the signed manifest.");

            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            await using (var source = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false))
            await using (var destination = new FileStream(partialPath, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                             128 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                var buffer = new byte[128 * 1024];
                long total = 0;
                while (true)
                {
                    var read = await source.ReadAsync(buffer, timeout.Token).ConfigureAwait(false);
                    if (read == 0) break;
                    total += read;
                    if (total > asset.Size || total > 1024L * 1024 * 1024)
                        throw new InvalidDataException("Downloaded asset exceeded its signed size limit.");
                    hash.AppendData(buffer, 0, read);
                    await destination.WriteAsync(buffer.AsMemory(0, read), timeout.Token).ConfigureAwait(false);
                }
                await destination.FlushAsync(timeout.Token).ConfigureAwait(false);
                if (total != asset.Size)
                    throw new InvalidDataException("Downloaded asset size does not match the signed manifest.");
            }

            var actualHash = hash.GetHashAndReset();
            var expectedHash = Convert.FromHexString(asset.Sha256);
            if (!CryptographicOperations.FixedTimeEquals(actualHash, expectedHash))
                throw new InvalidDataException("Downloaded asset SHA-256 does not match the signed manifest.");

            File.Move(partialPath, finalPath);
            _logger.Log("download-completed", $"{manifest.Version}/{asset.FileName}");
            return finalPath;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            TryDelete(partialPath);
            throw;
        }
        catch (OperationCanceledException)
        {
            TryDelete(partialPath);
            throw new TimeoutException("Update asset download timed out.");
        }
        catch
        {
            TryDelete(partialPath);
            throw;
        }
    }

    private async Task<UpdateCheckResult> FetchAndValidateAsync(string rid, NuGetVersion currentVersion,
        UpdateState state, bool allowFailedVersionRetry, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(RequestTimeout);
        try
        {
            var baseUrl = $"https://github.com/{options.Owner}/{options.Repository}/releases/latest/download/";
            var manifestBytes = await GetBytesAsync(baseUrl + "update.json", MaximumManifestBytes, timeout.Token).ConfigureAwait(false);
            var signatureBytes = await GetBytesAsync(baseUrl + "update.json.sig", 16 * 1024, timeout.Token).ConfigureAwait(false);
            var signature = Encoding.ASCII.GetString(signatureBytes).Trim();
            if (!manifestVerifier.TryDeserializeVerified(manifestBytes, signature, out var manifest, out var signatureError))
            {
                if (signatureError?.Contains("signature", StringComparison.OrdinalIgnoreCase) == true)
                    _logger.Log("manifest-signature-invalid");
                return new(UpdateCheckStatus.InvalidManifest, Error: signatureError);
            }

            if (!options.IncludePrerelease && NuGetVersion.Parse(manifest!.Version).IsPrerelease)
                return new(UpdateCheckStatus.InvalidManifest, Error: "Stable clients do not accept prerelease manifests.");

            if (!UpdateManifestVerifier.TrySelectAsset(manifest!, rid, options.Owner, options.Repository,
                    out var asset, out var assetError))
            {
                var unsupported = assetError?.Contains("No update asset", StringComparison.Ordinal) == true;
                return new(unsupported ? UpdateCheckStatus.UnsupportedPlatform : UpdateCheckStatus.InvalidManifest,
                    Manifest: manifest, Error: assetError);
            }

            var candidateVersion = NuGetVersion.Parse(manifest!.Version);
            var comparison = VersionComparer.VersionRelease.Compare(candidateVersion, currentVersion);
            if (comparison <= 0)
            {
                _logger.Log("update-not-available", options.CurrentVersion);
                return new(UpdateCheckStatus.UpToDate, manifest, asset);
            }

            if (!allowFailedVersionRetry && state.FailedVersions.TryGetValue(manifest.Version, out var failedUpdate) &&
                _utcNow() - failedUpdate.FailedAtUtc < FailedVersionCooldown)
                return new(UpdateCheckStatus.UpdateBlockedAfterFailure, manifest, asset,
                    "This version failed its first-start health check within the last 7 days. Use --force to retry manually.");

            _logger.Log("update-available", manifest.Version);
            return new(UpdateCheckStatus.UpdateAvailable, manifest, asset);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            _logger.Log("checking-for-update-failed", "timeout");
            return new(UpdateCheckStatus.CheckFailed, Error: "GitHub update check timed out.");
        }
        catch (HttpRequestException exception)
        {
            _logger.Log("checking-for-update-failed", exception.StatusCode?.ToString() ?? exception.GetType().Name);
            return new(UpdateCheckStatus.CheckFailed, Error: exception.StatusCode is HttpStatusCode.NotFound
                ? "No stable update manifest is available on the latest GitHub release."
                : "Could not retrieve the update manifest from GitHub.");
        }
        catch (Exception exception) when (exception is IOException or InvalidDataException or FormatException or JsonException)
        {
            _logger.Log("checking-for-update-failed", exception.GetType().Name);
            return new(UpdateCheckStatus.InvalidManifest, Error: exception is InvalidDataException
                ? exception.Message : "The GitHub update manifest could not be processed.");
        }
    }

    private async Task<byte[]> GetBytesAsync(string url, int maximumBytes, CancellationToken cancellationToken)
    {
        using var request = CreateRequest(url);
        using var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
            .ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        ValidateFinalHttpsUri(response.RequestMessage?.RequestUri);
        if (response.Content.Headers.ContentLength is long contentLength && contentLength > maximumBytes)
            throw new InvalidDataException("GitHub update metadata exceeded the maximum allowed size.");

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var memory = new MemoryStream();
        var buffer = new byte[8192];
        while (true)
        {
            var read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0) break;
            if (memory.Length + read > maximumBytes)
                throw new InvalidDataException("GitHub update metadata exceeded the maximum allowed size.");
            memory.Write(buffer, 0, read);
        }
        return memory.ToArray();
    }

    private HttpRequestMessage CreateRequest(string url)
    {
        var uri = new Uri(url, UriKind.Absolute);
        if (uri.Scheme != Uri.UriSchemeHttps)
            throw new InvalidDataException("Update requests require HTTPS.");
        var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.UserAgent.ParseAdd($"AzNetCheck-Updater/{options.CurrentVersion}");
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/octet-stream"));
        return request;
    }

    private static void ValidateFinalHttpsUri(Uri? uri)
    {
        if (uri is null || uri.Scheme != Uri.UriSchemeHttps)
            throw new InvalidDataException("GitHub redirected an update request to a non-HTTPS URL.");
        var allowedHost = uri.Host.Equals("github.com", StringComparison.OrdinalIgnoreCase) ||
            uri.Host.EndsWith(".githubusercontent.com", StringComparison.OrdinalIgnoreCase);
        if (!allowedHost)
            throw new InvalidDataException("GitHub redirected an update request to an unexpected host.");
    }

    private async Task<bool> FileMatchesAssetAsync(string path, UpdateAsset asset, CancellationToken cancellationToken)
    {
        var info = new FileInfo(path);
        if (info.Length != asset.Size) return false;
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
            128 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        var hash = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
        return CryptographicOperations.FixedTimeEquals(hash, Convert.FromHexString(asset.Sha256));
    }

    private void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); }
        catch (IOException exception) { _logger.Log("update-cleanup-failed", exception.GetType().Name); }
        catch (UnauthorizedAccessException exception) { _logger.Log("update-cleanup-failed", exception.GetType().Name); }
    }
}