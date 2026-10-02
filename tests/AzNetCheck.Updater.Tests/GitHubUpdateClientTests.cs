using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AzNetCheck.Updater;
using Xunit;

namespace AzNetCheck.Updater.Tests;

public sealed class GitHubUpdateClientTests
{
    [Fact]
    public async Task Checks_signed_latest_manifest_and_selects_exact_rid()
    {
        using var signingKey = RSA.Create(2048);
        var manifestBytes = BuildManifest([1, 2, 3]);
        var signature = Convert.ToBase64String(signingKey.SignData(manifestBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        var handler = new StubHandler((request, _) => Task.FromResult(request.RequestUri!.AbsolutePath.EndsWith("update.json.sig", StringComparison.Ordinal)
            ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(signature) }
            : new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(manifestBytes) }));
        using var client = new HttpClient(handler);
        var (updater, root, _) = CreateUpdater(client, signingKey.ExportSubjectPublicKeyInfoPem());
        try
        {
            var result = await updater.CheckForUpdatesAsync(force: true);
            Assert.Equal(UpdateCheckStatus.UpdateAvailable, result.Status);
            Assert.Equal("1.4.0", result.Manifest!.Version);
            Assert.Equal("win-x64", result.Manifest.Assets.Keys.Single());
            Assert.All(handler.Requests, request => Assert.StartsWith("https://github.com/owner/repo/releases/latest/download/", request));
        }
        finally { DeleteDirectory(root); }
    }

    [Fact]
    public async Task Rejects_invalid_signature_and_does_not_parse_manifest()
    {
        using var signingKey = RSA.Create(2048);
        var bytes = BuildManifest([1, 2, 3]);
        var handler = new StubHandler((request, _) => Task.FromResult(request.RequestUri!.AbsolutePath.EndsWith("update.json.sig", StringComparison.Ordinal)
            ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(Convert.ToBase64String(new byte[256])) }
            : new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(bytes) }));
        using var client = new HttpClient(handler);
        var (updater, root, _) = CreateUpdater(client, signingKey.ExportSubjectPublicKeyInfoPem());
        try
        {
            var result = await updater.CheckForUpdatesAsync(force: true);
            Assert.Equal(UpdateCheckStatus.InvalidManifest, result.Status);
            Assert.Contains("signature", result.Error, StringComparison.OrdinalIgnoreCase);
        }
        finally { DeleteDirectory(root); }
    }

    [Fact]
    public async Task Does_not_offer_a_downgrade()
    {
        using var signingKey = RSA.Create(2048);
        var lower = BuildManifest([1, 2, 3], version: "1.2.9");
        var lowerSignature = Convert.ToBase64String(signingKey.SignData(lower, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        var handler = CreateManifestHandler(lower, lowerSignature);
        using var client = new HttpClient(handler);
        var (updater, root, stateStore) = CreateUpdater(client, signingKey.ExportSubjectPublicKeyInfoPem());
        try
        {
            Assert.Equal(UpdateCheckStatus.UpToDate, (await updater.CheckForUpdatesAsync(force: true)).Status);

            Assert.Empty((await stateStore.LoadAsync()).FailedVersions);
        }
        finally { DeleteDirectory(root); }
    }

    [Fact]
    public async Task Blocks_a_failed_version_until_a_forced_manual_retry()
    {
        using var signingKey = RSA.Create(2048);
        var bytes = BuildManifest([1, 2, 3]);
        var signature = Convert.ToBase64String(signingKey.SignData(bytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        var handler = CreateManifestHandler(bytes, signature);
        using var client = new HttpClient(handler);
        var (updater, root, store) = CreateUpdater(client, signingKey.ExportSubjectPublicKeyInfoPem());
        try
        {
            await store.SaveAsync(new UpdateState
            {
                FailedVersions = new() { ["1.4.0"] = new FailedUpdate(DateTimeOffset.UtcNow, "health-check-failed") }
            });
            Assert.Equal(UpdateCheckStatus.UpdateBlockedAfterFailure,
                (await updater.CheckForUpdatesAsync()).Status);
            Assert.Equal(UpdateCheckStatus.UpdateAvailable,
                (await updater.CheckForUpdatesAsync(force: true, allowFailedVersionRetry: true)).Status);
        }
        finally { DeleteDirectory(root); }
    }

    [Fact]
    public async Task Allows_a_failed_version_again_after_the_retry_cooldown_expires()
    {
        using var signingKey = RSA.Create(2048);
        var bytes = BuildManifest([1, 2, 3]);
        var signature = Convert.ToBase64String(signingKey.SignData(bytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        var handler = CreateManifestHandler(bytes, signature);
        using var client = new HttpClient(handler);
        var root = Path.Combine(Path.GetTempPath(), "AzNetCheck-updater-tests", Guid.NewGuid().ToString("N"));
        var paths = new UpdatePaths(Path.Combine(root, "state"));
        var store = new UpdateStateStore(paths);
        var now = DateTimeOffset.UtcNow;
        var options = new UpdateOptions("owner", "repo", "1.3.0", TimeSpan.FromHours(24), "win-x64", paths.Root);
        var updater = new GitHubUpdateClient(client, options,
            new UpdateManifestVerifier(signingKey.ExportSubjectPublicKeyInfoPem()), store, utcNow: () => now);
        try
        {
            await store.SaveAsync(new UpdateState
            {
                FailedVersions = new() { ["1.4.0"] = new FailedUpdate(now.AddDays(-8), "health-check-failed") }
            });
            Assert.Equal(UpdateCheckStatus.UpdateAvailable, (await updater.CheckForUpdatesAsync()).Status);
        }
        finally { DeleteDirectory(root); }
    }

    [Fact]
    public async Task Skips_network_check_inside_interval_unless_forced()
    {
        using var signingKey = RSA.Create(2048);
        var bytes = BuildManifest([1, 2, 3]);
        var signature = Convert.ToBase64String(signingKey.SignData(bytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        var handler = CreateManifestHandler(bytes, signature);
        using var client = new HttpClient(handler);
        var (updater, root, store) = CreateUpdater(client, signingKey.ExportSubjectPublicKeyInfoPem());
        try
        {
            await store.SaveAsync(new UpdateState { LastCheckUtc = DateTimeOffset.UtcNow });
            Assert.Equal(UpdateCheckStatus.CheckSkippedRecently, (await updater.CheckForUpdatesAsync()).Status);
            Assert.Empty(handler.Requests);
            Assert.Equal(UpdateCheckStatus.UpdateAvailable, (await updater.CheckForUpdatesAsync(force: true)).Status);
            Assert.Equal(2, handler.Requests.Count);
        }
        finally { DeleteDirectory(root); }
    }

    [Fact]
    public async Task Downloads_only_when_sha256_and_signed_size_match()
    {
        using var signingKey = RSA.Create(2048);
        var bytes = new byte[] { 8, 7, 6, 5 };
        var manifestBytes = BuildManifest(bytes);
        var signature = Convert.ToBase64String(signingKey.SignData(manifestBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        var handler = CreateManifestHandler(manifestBytes, signature, bytes);
        using var client = new HttpClient(handler);
        var (updater, root, _) = CreateUpdater(client, signingKey.ExportSubjectPublicKeyInfoPem());
        try
        {
            var checkedUpdate = await updater.CheckForUpdatesAsync(force: true);
            var file = await updater.DownloadVerifiedAssetAsync(checkedUpdate.Manifest!, checkedUpdate.Asset!);
            Assert.Equal(bytes, await File.ReadAllBytesAsync(file));
            Assert.False(File.Exists(file + ".download"));

            var badAsset = checkedUpdate.Asset! with { Sha256 = new string('0', 64) };
            await Assert.ThrowsAsync<InvalidDataException>(() => updater.DownloadVerifiedAssetAsync(
                checkedUpdate.Manifest!, badAsset));
            Assert.True(File.Exists(file));
        }
        finally { DeleteDirectory(root); }
    }

    [Fact]
    public async Task Deletes_partial_download_when_signed_manifest_hash_does_not_match_asset()
    {
        using var signingKey = RSA.Create(2048);
        var bytes = new byte[] { 8, 7, 6, 5 };
        var manifestBytes = BuildManifest(bytes, shaOverride: new string('0', 64));
        var signature = Convert.ToBase64String(signingKey.SignData(manifestBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        using var client = new HttpClient(CreateManifestHandler(manifestBytes, signature, bytes));
        var (updater, root, _) = CreateUpdater(client, signingKey.ExportSubjectPublicKeyInfoPem());
        try
        {
            var check = await updater.CheckForUpdatesAsync(force: true);
            await Assert.ThrowsAsync<InvalidDataException>(() =>
                updater.DownloadVerifiedAssetAsync(check.Manifest!, check.Asset!));
            var versionDirectory = new UpdatePaths(Path.Combine(root, "state"), Path.Combine(root, "downloads"))
                .GetVersionDownloadDirectory("1.4.0");
            Assert.Empty(Directory.GetFiles(versionDirectory));
        }
        finally { DeleteDirectory(root); }
    }

    [Fact]
    public async Task Network_failure_is_a_result_not_an_exception()
    {
        var handler = new StubHandler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.InternalServerError)));
        using var client = new HttpClient(handler);
        using var key = RSA.Create(2048);
        var (updater, root, _) = CreateUpdater(client, key.ExportSubjectPublicKeyInfoPem());
        try
        {
            var result = await updater.CheckForUpdatesAsync(force: true);
            Assert.Equal(UpdateCheckStatus.CheckFailed, result.Status);
        }
        finally { DeleteDirectory(root); }
    }

    [Fact]
    public async Task Stable_client_rejects_a_signed_prerelease_manifest()
    {
        using var signingKey = RSA.Create(2048);
        var bytes = BuildManifest([1, 2, 3], version: "1.4.0-beta.1");
        var signature = Convert.ToBase64String(signingKey.SignData(bytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        using var client = new HttpClient(CreateManifestHandler(bytes, signature));
        var (updater, root, _) = CreateUpdater(client, signingKey.ExportSubjectPublicKeyInfoPem());
        try
        {
            var result = await updater.CheckForUpdatesAsync(force: true);
            Assert.Equal(UpdateCheckStatus.InvalidManifest, result.Status);
            Assert.Contains("prerelease", result.Error, StringComparison.OrdinalIgnoreCase);
        }
        finally { DeleteDirectory(root); }
    }

    private static (GitHubUpdateClient Client, string Root, UpdateStateStore Store) CreateUpdater(HttpClient http,
        string publicKey)
    {
        var root = Path.Combine(Path.GetTempPath(), "AzNetCheck-updater-tests", Guid.NewGuid().ToString("N"));
        var paths = new UpdatePaths(Path.Combine(root, "state"), Path.Combine(root, "downloads"));
        var store = new UpdateStateStore(paths);
        var options = new UpdateOptions("owner", "repo", "1.3.0", TimeSpan.FromHours(24), "win-x64", paths.Root);
        var client = new GitHubUpdateClient(http, options, new UpdateManifestVerifier(publicKey), store,
            utcNow: () => DateTimeOffset.UtcNow);
        return (client, root, store);
    }

    private static StubHandler CreateManifestHandler(byte[] manifest, string signature, byte[]? asset = null) =>
        new((request, _) =>
        {
            if (request.RequestUri!.AbsolutePath.EndsWith("update.json.sig", StringComparison.Ordinal))
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(signature) });
            if (request.RequestUri.AbsolutePath.EndsWith("update.json", StringComparison.Ordinal))
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(manifest) });
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(asset ?? []) });
        });

    private static byte[] BuildManifest(byte[] asset, string version = "1.4.0", string? shaOverride = null)
    {
        var digest = Convert.ToHexString(SHA256.HashData(asset)).ToLowerInvariant();
        var manifest = new UpdateManifest
        {
            ManifestVersion = 1,
            Version = version,
            PublishedAtUtc = DateTimeOffset.UtcNow,
            Assets = new Dictionary<string, UpdateAsset>
            {
                ["win-x64"] = new UpdateAsset
                {
                    FileName = "aznetcheck-win-x64.exe",
                    Url = $"https://github.com/owner/repo/releases/download/v{version}/aznetcheck-win-x64.exe",
                    Sha256 = shaOverride ?? digest,
                    Size = asset.LongLength
                }
            }
        };
        return JsonSerializer.SerializeToUtf8Bytes(manifest);
    }

    private static void DeleteDirectory(string path)
    {
        if (Directory.Exists(path)) Directory.Delete(path, recursive: true);
    }

    private sealed class StubHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> handler)
        : HttpMessageHandler
    {
        public List<string> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request.RequestUri!.ToString());
            return SendAndAttachRequestAsync(request, cancellationToken);
        }

        private async Task<HttpResponseMessage> SendAndAttachRequestAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var response = await handler(request, cancellationToken).ConfigureAwait(false);
            response.RequestMessage ??= request;
            return response;
        }
    }
}