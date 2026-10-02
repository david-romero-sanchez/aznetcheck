using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AzNetCheck.Core;
using AzNetCheck.Networking;
using Xunit;

namespace AzNetCheck.Networking.Tests;

public sealed class TcpDiagnosticTests
{
    [Fact]
    public async Task Connects_to_a_local_listener()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var accepting = listener.AcceptTcpClientAsync();
        var result = await new TcpSocketDiagnostic().ConnectAsync(IPAddress.Loopback, port,
            TimeSpan.FromSeconds(2), CancellationToken.None);
        using var accepted = await accepting;
        Assert.Equal(DiagnosticStatus.Passed, result.Status);
        Assert.Equal(port, result.Port);
    }

    [Fact]
    public async Task Reports_certificate_hostname_and_chain_errors_as_structured_tls_failure()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=other.example", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var subjectAlternativeNames = new SubjectAlternativeNameBuilder();
        subjectAlternativeNames.AddDnsName("other.example");
        request.CertificateExtensions.Add(subjectAlternativeNames.Build());
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddHours(1));
        using var serverCertificate = X509CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pfx), null,
            X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        string? serverError = null;
        var serverTask = Task.Run(async () =>
        {
            using var accepted = await listener.AcceptTcpClientAsync();
            await using var stream = new SslStream(accepted.GetStream());
            try
            {
                await stream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = serverCertificate,
                    EnabledSslProtocols = SslProtocols.Tls12
                });
            }
            catch (AuthenticationException exception)
            {
                serverError = exception.Message;
            }
            catch (IOException exception)
            {
                serverError = exception.Message;
            }
        });

        var result = await new TlsStreamDiagnostic().HandshakeAsync("requested.example", IPAddress.Loopback,
            port, TimeSpan.FromSeconds(5), CancellationToken.None);
        await serverTask;

        Assert.Equal(DiagnosticStatus.Failed, result.Status);
        Assert.True(result.Subject is not null, $"{result.ErrorMessage}; server: {serverError}");
        Assert.False(result.HostnameMatches);
        Assert.False(result.ChainValid);
        Assert.Contains("hostname", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }
}