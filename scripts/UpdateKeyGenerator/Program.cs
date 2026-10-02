using System.Security.Cryptography;
using System.Text;

if (args.Length != 2)
{
    Console.Error.WriteLine("Usage: UpdateKeyGenerator <private-key-path> <public-key-path>");
    return 2;
}

var privatePath = Path.GetFullPath(args[0]);
var publicPath = Path.GetFullPath(args[1]);
if (File.Exists(privatePath) || File.Exists(publicPath))
{
    Console.Error.WriteLine("Refusing to overwrite an existing signing key file.");
    return 2;
}

Directory.CreateDirectory(Path.GetDirectoryName(privatePath)!);
Directory.CreateDirectory(Path.GetDirectoryName(publicPath)!);
using var rsa = RSA.Create(3072);
var privatePem = Encoding.UTF8.GetBytes(rsa.ExportPkcs8PrivateKeyPem());
var publicPem = Encoding.UTF8.GetBytes(rsa.ExportSubjectPublicKeyInfoPem());

try
{
    await using (var privateFile = new FileStream(privatePath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
    {
        await privateFile.WriteAsync(privatePem);
        await privateFile.FlushAsync();
    }

    await using (var publicFile = new FileStream(publicPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
    {
        await publicFile.WriteAsync(publicPem);
        await publicFile.FlushAsync();
    }
}
catch
{
    if (File.Exists(privatePath)) File.Delete(privatePath);
    if (File.Exists(publicPath)) File.Delete(publicPath);
    throw;
}
finally
{
    CryptographicOperations.ZeroMemory(privatePem);
}

Console.WriteLine($"Public key written to: {publicPath}");
return 0;