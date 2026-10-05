using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NuGet.Versioning;

namespace AzNetCheck.Updater;

public sealed record SignedUpdateManifest(byte[] ManifestBytes, string SignatureBase64);

public static class UpdateManifestBuilder
{
    public static async Task<SignedUpdateManifest> CreateAsync(string version, string rid, string owner,
        string repository, string assetPath, string privateKeyPem, DateTimeOffset publishedAtUtc,
        CancellationToken cancellationToken = default)
    {
        if (!NuGetVersion.TryParse(version, out _) ||
            !System.Text.RegularExpressions.Regex.IsMatch(version,
                @"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?$",
                System.Text.RegularExpressions.RegexOptions.CultureInvariant))
            throw new ArgumentException("Version must be SemVer without a leading v.", nameof(version));
        if (rid != "win-x64") throw new ArgumentException("Only win-x64 is currently configured for releases.", nameof(rid));
        if (!System.Text.RegularExpressions.Regex.IsMatch(owner, "^[A-Za-z0-9-]+$") ||
            !System.Text.RegularExpressions.Regex.IsMatch(repository, "^[A-Za-z0-9_.-]+$"))
            throw new ArgumentException("Repository owner or name is invalid.");

        const string fileName = "aznetcheck-win-x64.exe";
        var info = new FileInfo(assetPath);
        if (!info.Exists || info.Length <= 0 || info.Length > 1024L * 1024 * 1024)
            throw new InvalidDataException("Published executable is missing or outside the supported size range.");
        await using var stream = new FileStream(assetPath, FileMode.Open, FileAccess.Read, FileShare.Read,
            128 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        var hash = Convert.ToHexString(await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false)).ToLowerInvariant();
        var manifest = new UpdateManifest
        {
            ManifestVersion = 1,
            Version = version,
            PublishedAtUtc = publishedAtUtc.ToUniversalTime(),
            Assets = new Dictionary<string, UpdateAsset>(StringComparer.Ordinal)
            {
                [rid] = new UpdateAsset
                {
                    FileName = fileName,
                    Url = $"https://github.com/{owner}/{repository}/releases/download/v{version}/{fileName}",
                    Sha256 = hash,
                    Size = info.Length
                }
            }
        };

        var bytes = JsonSerializer.SerializeToUtf8Bytes(manifest, UpdateJsonSerializerContext.Default.UpdateManifest);
        using var rsa = RSA.Create();
        rsa.ImportFromPem(privateKeyPem);
        var signature = rsa.SignData(bytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return new SignedUpdateManifest(bytes, Convert.ToBase64String(signature) + "\n");
    }
}