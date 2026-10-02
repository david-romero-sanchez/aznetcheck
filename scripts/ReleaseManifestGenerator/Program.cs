using AzNetCheck.Updater;
using System.Security.Cryptography;

if (args.Length == 3 && args[0] == "--verify")
{
    try
    {
        var manifestBytes = await File.ReadAllBytesAsync(Path.GetFullPath(args[1]));
        var signature = (await File.ReadAllTextAsync(Path.GetFullPath(args[2]))).Trim();
        var verifier = new UpdateManifestVerifier();
        if (!verifier.TryDeserializeVerified(manifestBytes, signature, out var manifest, out var error))
        {
            Console.Error.WriteLine($"Manifest verification failed: {error}");
            return 1;
        }
        Console.WriteLine($"Manifest signature verified for version {manifest!.Version}.");
        return 0;
    }
    catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
    {
        Console.Error.WriteLine("Manifest or signature file could not be read.");
        return 1;
    }
}

if (args.Length != 6)
{
    Console.Error.WriteLine("Usage: ReleaseManifestGenerator <version> <rid> <owner> <repository> <asset-path> <private-key-path>");
    Console.Error.WriteLine("   or: ReleaseManifestGenerator --verify <manifest-path> <signature-path>");
    return 2;
}

var version = args[0];
var rid = args[1];
var owner = args[2];
var repository = args[3];
var assetPath = Path.GetFullPath(args[4]);
var privateKeyPath = Path.GetFullPath(args[5]);
if (!File.Exists(privateKeyPath))
{
    Console.Error.WriteLine("Signing private key file was not found.");
    return 2;
}

try
{
    var privateKeyPem = await File.ReadAllTextAsync(privateKeyPath);
    var signed = await UpdateManifestBuilder.CreateAsync(version, rid, owner, repository, assetPath,
        privateKeyPem, DateTimeOffset.UtcNow);
    var verifier = new UpdateManifestVerifier();
    if (!verifier.TryDeserializeVerified(signed.ManifestBytes, signed.SignatureBase64, out _, out var verifyError))
        throw new CryptographicException($"Generated manifest signature does not match the embedded public key: {verifyError}");
    var outputDirectory = Path.GetDirectoryName(assetPath)!;
    await File.WriteAllBytesAsync(Path.Combine(outputDirectory, "update.json"), signed.ManifestBytes);
    await File.WriteAllTextAsync(Path.Combine(outputDirectory, "update.json.sig"), signed.SignatureBase64,
        new System.Text.UTF8Encoding(false));
    Console.WriteLine($"Manifest and signature generated for {version} ({rid}).");
    return 0;
}
catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or InvalidDataException or System.Security.Cryptography.CryptographicException)
{
    Console.Error.WriteLine($"Manifest generation failed: {exception.Message}");
    return 1;
}