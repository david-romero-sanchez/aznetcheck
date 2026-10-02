using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using NuGet.Versioning;

namespace AzNetCheck.Updater;

public sealed class UpdateManifestVerifier
{
    private const int MaximumManifestBytes = 1024 * 1024;
    private const int MaximumSignatureBytes = 16 * 1024;
    private readonly string _publicKeyPem;

    public UpdateManifestVerifier()
    {
        using var stream = Assembly.GetExecutingAssembly()
            .GetManifestResourceStream("AzNetCheck.Updater.Keys.update-signing-public.pem")
            ?? throw new InvalidOperationException("Embedded update verification key was not found.");
        using var reader = new StreamReader(stream, Encoding.UTF8);
        _publicKeyPem = reader.ReadToEnd();
    }

    public UpdateManifestVerifier(string publicKeyPem) => _publicKeyPem = publicKeyPem;

    public bool VerifySignature(ReadOnlySpan<byte> manifestBytes, string base64Signature)
    {
        if (manifestBytes.Length is 0 or > MaximumManifestBytes || base64Signature.Length > MaximumSignatureBytes)
            return false;
        try
        {
            var signature = Convert.FromBase64String(base64Signature.Trim());
            using var rsa = RSA.Create();
            rsa.ImportFromPem(_publicKeyPem);
            return rsa.VerifyData(manifestBytes, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch (Exception exception) when (exception is FormatException or CryptographicException)
        {
            return false;
        }
    }

    public bool TryDeserializeVerified(ReadOnlySpan<byte> manifestBytes, string base64Signature,
        out UpdateManifest? manifest, out string? error)
    {
        manifest = null;
        error = null;
        if (!VerifySignature(manifestBytes, base64Signature))
        {
            error = "Manifest signature verification failed.";
            return false;
        }

        try
        {
            manifest = JsonSerializer.Deserialize<UpdateManifest>(manifestBytes, JsonOptions);
            if (manifest is null)
            {
                error = "Manifest JSON was empty.";
                return false;
            }
            if (manifest.ManifestVersion != 1)
            {
                error = $"Unsupported manifest version: {manifest.ManifestVersion}.";
                manifest = null;
                return false;
            }
            if (!NuGetVersion.TryParse(manifest.Version, out _) || !Regex.IsMatch(manifest.Version,
                @"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?$", RegexOptions.CultureInvariant))
            {
                error = "Manifest version is not a valid SemVer version.";
                manifest = null;
                return false;
            }
            if (manifest.PublishedAtUtc.Offset != TimeSpan.Zero || manifest.Assets is null || manifest.Assets.Count == 0)
            {
                error = "Manifest publication timestamp or assets are invalid.";
                manifest = null;
                return false;
            }
            return true;
        }
        catch (JsonException)
        {
            error = "Signed manifest contains invalid JSON or is missing required fields.";
            manifest = null;
            return false;
        }
    }

    public static bool TrySelectAsset(UpdateManifest manifest, string rid, string owner, string repository,
        out UpdateAsset? asset, out string? error)
    {
        asset = null;
        error = null;
        if (!manifest.Assets.TryGetValue(rid, out asset))
        {
            error = $"No update asset is available for runtime identifier '{rid}'.";
            return false;
        }

        var expectedFileName = $"aznetcheck-{rid}.exe";
        if (!string.Equals(asset.FileName, expectedFileName, StringComparison.Ordinal) ||
            asset.FileName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 ||
            asset.FileName.Contains("..", StringComparison.Ordinal))
        {
            error = "Manifest asset filename is invalid for this runtime identifier.";
            asset = null;
            return false;
        }
        if (asset.Size is <= 0 or > 1024L * 1024 * 1024 || !Regex.IsMatch(asset.Sha256, "^[a-fA-F0-9]{64}$", RegexOptions.CultureInvariant))
        {
            error = "Manifest asset size or SHA-256 value is invalid.";
            asset = null;
            return false;
        }

        var expectedTag = $"v{manifest.Version}";
        if (!Uri.TryCreate(asset.Url, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps ||
            !uri.Host.Equals("github.com", StringComparison.OrdinalIgnoreCase) || uri.UserInfo.Length != 0 ||
            uri.Port != 443 || uri.Query.Length != 0 || uri.Fragment.Length != 0)
        {
            error = "Manifest asset URL must be a direct HTTPS GitHub release URL.";
            asset = null;
            return false;
        }
        var expectedPath = $"/{owner}/{repository}/releases/download/{expectedTag}/{expectedFileName}";
        if (!uri.AbsolutePath.Equals(expectedPath, StringComparison.Ordinal))
        {
            error = "Manifest asset URL does not match the versioned repository release path.";
            asset = null;
            return false;
        }
        return true;
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow
    };
}