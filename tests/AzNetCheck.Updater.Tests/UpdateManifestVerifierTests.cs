using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AzNetCheck.Updater;
using Xunit;

namespace AzNetCheck.Updater.Tests;

public sealed class UpdateManifestVerifierTests
{
    [Fact]
    public void Verifies_exact_manifest_bytes_before_deserializing()
    {
        using var rsa = RSA.Create(2048);
        var verifier = new UpdateManifestVerifier(rsa.ExportSubjectPublicKeyInfoPem());
        var bytes = CreateManifestBytes();
        var signature = Convert.ToBase64String(rsa.SignData(bytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));

        Assert.True(verifier.TryDeserializeVerified(bytes, signature, out var manifest, out var error), error);
        Assert.Equal("1.4.0", manifest!.Version);
    }

    [Fact]
    public void Rejects_a_manifest_changed_after_signing()
    {
        using var rsa = RSA.Create(2048);
        var verifier = new UpdateManifestVerifier(rsa.ExportSubjectPublicKeyInfoPem());
        var bytes = CreateManifestBytes();
        var signature = Convert.ToBase64String(rsa.SignData(bytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        bytes[^2] ^= 1;

        Assert.False(verifier.TryDeserializeVerified(bytes, signature, out var manifest, out _));
        Assert.Null(manifest);
    }

    [Fact]
    public void Rejects_truncated_signature_and_wrong_key()
    {
        using var signer = RSA.Create(2048);
        using var differentKey = RSA.Create(2048);
        var bytes = CreateManifestBytes();
        var signature = signer.SignData(bytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var verifier = new UpdateManifestVerifier(differentKey.ExportSubjectPublicKeyInfoPem());

        Assert.False(verifier.VerifySignature(bytes, Convert.ToBase64String(signature.AsSpan(0, signature.Length / 2))));
        Assert.False(verifier.VerifySignature(bytes, Convert.ToBase64String(signature)));
        Assert.False(verifier.VerifySignature(bytes, "not-base64!"));
    }

    [Fact]
    public async Task Manifest_builder_hashes_the_published_bytes_and_signs_the_exact_output()
    {
        using var rsa = RSA.Create(2048);
        var assetPath = Path.Combine(Path.GetTempPath(), $"aznetcheck-{Guid.NewGuid():N}.exe");
        var assetBytes = RandomNumberGenerator.GetBytes(4096);
        await File.WriteAllBytesAsync(assetPath, assetBytes);
        try
        {
            var signed = await UpdateManifestBuilder.CreateAsync("1.4.0-rc.1", "win-x64", "owner", "repo",
                assetPath, rsa.ExportPkcs8PrivateKeyPem(), DateTimeOffset.Parse("2026-10-02T12:00:00Z"));
            var verifier = new UpdateManifestVerifier(rsa.ExportSubjectPublicKeyInfoPem());
            Assert.True(verifier.TryDeserializeVerified(signed.ManifestBytes, signed.SignatureBase64,
                out var manifest, out var error), error);
            var asset = manifest!.Assets["win-x64"];
            Assert.Equal(assetBytes.LongLength, asset.Size);
            Assert.Equal(Convert.ToHexString(SHA256.HashData(assetBytes)).ToLowerInvariant(), asset.Sha256);
            Assert.Contains("/releases/download/v1.4.0-rc.1/", asset.Url);
        }
        finally { File.Delete(assetPath); }
    }

    [Fact]
    public async Task Manifest_builder_requires_version_without_git_tag_prefix()
    {
        var assetPath = Path.Combine(Path.GetTempPath(), $"aznetcheck-{Guid.NewGuid():N}.exe");
        await File.WriteAllBytesAsync(assetPath, [1, 2, 3]);
        try
        {
            using var rsa = RSA.Create(2048);
            await Assert.ThrowsAsync<ArgumentException>(() => UpdateManifestBuilder.CreateAsync("v1.4.0", "win-x64",
                "owner", "repo", assetPath, rsa.ExportPkcs8PrivateKeyPem(), DateTimeOffset.UtcNow));
        }
        finally { File.Delete(assetPath); }
    }

    [Fact]
    public async Task Generated_signature_verifies_and_modified_manifest_is_rejected()
    {
        using var rsa = RSA.Create(3072);
        var privatePath = Path.Combine(Path.GetTempPath(), $"update-key-{Guid.NewGuid():N}.pem");
        var assetPath = Path.Combine(Path.GetTempPath(), $"aznetcheck-{Guid.NewGuid():N}.exe");
        var publicPath = Path.Combine(Path.GetTempPath(), $"update-public-{Guid.NewGuid():N}.pem");
        await File.WriteAllTextAsync(privatePath, rsa.ExportPkcs8PrivateKeyPem());
        await File.WriteAllTextAsync(publicPath, rsa.ExportSubjectPublicKeyInfoPem());
        await File.WriteAllBytesAsync(assetPath, [1, 3, 3, 7]);
        try
        {
            var generated = await UpdateManifestBuilder.CreateAsync("1.4.0", "win-x64", "owner", "repo",
                assetPath, await File.ReadAllTextAsync(privatePath), DateTimeOffset.UtcNow);
            var verification = new UpdateManifestVerifier(await File.ReadAllTextAsync(publicPath));
            Assert.True(verification.TryDeserializeVerified(generated.ManifestBytes, generated.SignatureBase64,
                out _, out var error), error);

            generated.ManifestBytes[10] ^= 0x01;
            Assert.False(verification.TryDeserializeVerified(generated.ManifestBytes, generated.SignatureBase64,
                out _, out _));
        }
        finally
        {
            File.Delete(privatePath);
            File.Delete(publicPath);
            File.Delete(assetPath);
        }
    }

    [Fact]
    public void Rejects_unknown_manifest_version_and_malformed_json_when_signed()
    {
        using var rsa = RSA.Create(2048);
        var verifier = new UpdateManifestVerifier(rsa.ExportSubjectPublicKeyInfoPem());
        var unsupported = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(CreateManifestBytes()).Replace("\"manifestVersion\":1", "\"manifestVersion\":2", StringComparison.Ordinal));
        Assert.False(verifier.TryDeserializeVerified(unsupported, Sign(rsa, unsupported), out _, out var versionError));
        Assert.Contains("Unsupported manifest version", versionError);

        var malformed = Encoding.UTF8.GetBytes("{broken-json}");
        Assert.False(verifier.TryDeserializeVerified(malformed, Sign(rsa, malformed), out _, out var jsonError));
        Assert.Contains("invalid JSON", jsonError);
    }

    [Fact]
    public void Selects_only_the_exact_rid_asset_and_versioned_https_github_url()
    {
        var manifest = JsonSerializer.Deserialize<UpdateManifest>(CreateManifestBytes())!;
        Assert.True(UpdateManifestVerifier.TrySelectAsset(manifest, "win-x64", "owner", "repo", out var asset, out var error), error);
        Assert.Equal("aznetcheck-win-x64.exe", asset!.FileName);
        Assert.False(UpdateManifestVerifier.TrySelectAsset(manifest, "linux-x64", "owner", "repo", out _, out _));

        var httpAsset = asset with { Url = asset.Url.Replace("https://", "http://", StringComparison.Ordinal) };
        Assert.False(UpdateManifestVerifier.TrySelectAsset(manifest with { Assets = new() { ["win-x64"] = httpAsset } },
            "win-x64", "owner", "repo", out _, out _));

        var latestAsset = asset with { Url = "https://github.com/owner/repo/releases/latest/download/aznetcheck-win-x64.exe" };
        Assert.False(UpdateManifestVerifier.TrySelectAsset(manifest with { Assets = new() { ["win-x64"] = latestAsset } },
            "win-x64", "owner", "repo", out _, out _));
    }

    [Theory]
    [InlineData("1.0.0", "1.0.1", true)]
    [InlineData("1.9.9", "2.0.0", true)]
    [InlineData("1.4.0", "1.4.0", false)]
    [InlineData("2.0.0", "1.9.9", false)]
    [InlineData("1.4.0-beta.1", "1.4.0", true)]
    [InlineData("1.4.0-beta.1", "1.4.0-rc.1", true)]
    public void Compares_semver_versions(string current, string candidate, bool isNewer) =>
        Assert.Equal(isNewer, UpdateVersionComparer.IsNewer(candidate, current));

    private static byte[] CreateManifestBytes()
    {
        var sha256 = Convert.ToHexString(SHA256.HashData([1, 2, 3])).ToLowerInvariant();
        var manifest = new UpdateManifest
        {
            ManifestVersion = 1,
            Version = "1.4.0",
            PublishedAtUtc = new DateTimeOffset(2026, 10, 2, 12, 0, 0, TimeSpan.Zero),
            Assets = new Dictionary<string, UpdateAsset>
            {
                ["win-x64"] = new UpdateAsset
                {
                    FileName = "aznetcheck-win-x64.exe",
                    Url = "https://github.com/owner/repo/releases/download/v1.4.0/aznetcheck-win-x64.exe",
                    Sha256 = sha256,
                    Size = 3
                }
            }
        };
        return JsonSerializer.SerializeToUtf8Bytes(manifest);
    }

    private static string Sign(RSA rsa, byte[] bytes) =>
        Convert.ToBase64String(rsa.SignData(bytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
}