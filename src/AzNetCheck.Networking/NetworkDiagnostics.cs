using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using AzNetCheck.Core;
using DnsClient;
using DnsClient.Protocol;

namespace AzNetCheck.Networking;

public sealed class DnsClientDiagnostic : IDnsDiagnostic
{
    private readonly LookupClient _lookup = new(new LookupClientOptions { UseCache = true, ThrowDnsErrors = false });

    public async Task<DnsResolutionResult> ResolveAsync(string hostname, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var watch = Stopwatch.StartNew();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        var chain = new List<string>();
        var addresses = new HashSet<IPAddress>();
        var current = hostname.TrimEnd('.');
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string? responseCode = null;
        try
        {
            for (var depth = 0; depth < 12; depth++)
            {
                if (!visited.Add(current))
                {
                    watch.Stop();
                    return new(DiagnosticStatus.Failed, addresses.Select(address => address.ToString()).ToArray(), chain,
                        watch.Elapsed, "CnameLoop", "DNS CNAME loop detected.");
                }
                var responseA = await _lookup.QueryAsync(current, QueryType.A, QueryClass.IN, deadline.Token).ConfigureAwait(false);
                var responseAaaa = await _lookup.QueryAsync(current, QueryType.AAAA, QueryClass.IN, deadline.Token).ConfigureAwait(false);
                addresses.UnionWith(responseA.Answers.ARecords().Select(record => record.Address));
                addresses.UnionWith(responseAaaa.Answers.AaaaRecords().Select(record => record.Address));
                responseCode = responseA.Header.ResponseCode.ToString();
                var cname = responseA.Answers.CnameRecords().Concat(responseAaaa.Answers.CnameRecords())
                    .FirstOrDefault()?.CanonicalName.Value.TrimEnd('.');
                if (string.IsNullOrWhiteSpace(cname)) break;
                chain.Add(cname);
                current = cname;
            }
            watch.Stop();
            return addresses.Count > 0
                ? new(DiagnosticStatus.Passed, addresses.Select(address => address.ToString()).ToArray(), chain, watch.Elapsed)
                : new(DiagnosticStatus.Failed, [], chain, watch.Elapsed, responseCode ?? "NoRecords",
                    responseCode == "NxDomain" ? "DNS returned NXDOMAIN; the hostname does not exist." : "DNS returned no A or AAAA records.");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            watch.Stop();
            return new(DiagnosticStatus.Failed, [], chain, watch.Elapsed, "Timeout", $"DNS resolution timed out after {timeout.TotalMilliseconds:0} ms.");
        }
        catch (DnsResponseException exception)
        {
            watch.Stop();
            return new(DiagnosticStatus.Failed, [], chain, watch.Elapsed, exception.Code.ToString(), exception.Message);
        }
        catch (SocketException exception)
        {
            watch.Stop();
            return new(DiagnosticStatus.Failed, [], chain, watch.Elapsed, exception.SocketErrorCode.ToString(), "DNS query failed.");
        }
    }
}

public sealed class TcpSocketDiagnostic : ITcpDiagnostic
{
    public async Task<TcpProbeResult> ConnectAsync(IPAddress address, int port, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var watch = Stopwatch.StartNew();
        using var client = new TcpClient(address.AddressFamily);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        try
        {
            await client.ConnectAsync(address, port, deadline.Token).ConfigureAwait(false);
            watch.Stop();
            return new(DiagnosticStatus.Passed, address.ToString(), port, watch.Elapsed);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            watch.Stop();
            return new(DiagnosticStatus.Failed, address.ToString(), port, watch.Elapsed, "TimedOut", $"Connection timed out after {timeout.TotalMilliseconds:0} ms.");
        }
        catch (SocketException exception)
        {
            watch.Stop();
            return new(DiagnosticStatus.Failed, address.ToString(), port, watch.Elapsed, exception.SocketErrorCode.ToString(), exception.SocketErrorCode switch
            {
                SocketError.ConnectionRefused => "Connection refused.",
                SocketError.HostUnreachable or SocketError.NetworkUnreachable => "The destination is unreachable.",
                SocketError.TimedOut => "Connection timed out.",
                _ => "TCP connection failed."
            });
        }
    }
}

public sealed class TlsStreamDiagnostic : ITlsDiagnostic
{
    public async Task<TlsProbeResult> HandshakeAsync(string hostname, int port, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var watch = Stopwatch.StartNew();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        X509Certificate2? certificate = null;
        SslPolicyErrors policyErrors = SslPolicyErrors.None;
        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync(hostname, port, deadline.Token).ConfigureAwait(false);
            await using var stream = new SslStream(client.GetStream(), leaveInnerStreamOpen: false, (_, cert, _, errors) =>
            {
                policyErrors = errors;
                if (cert is not null) certificate = new X509Certificate2(cert);
                return errors == SslPolicyErrors.None;
            });
            await stream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = hostname }, deadline.Token).ConfigureAwait(false);
            watch.Stop();
            return new(DiagnosticStatus.Passed, hostname, port, watch.Elapsed, stream.SslProtocol.ToString(),
                stream.NegotiatedCipherSuite.ToString(), certificate?.Subject, certificate?.Issuer,
                certificate is null ? null : new DateTimeOffset(certificate.NotAfter), true, true,
                NotBefore: certificate is null ? null : new DateTimeOffset(certificate.NotBefore),
                SubjectAlternativeNames: GetSubjectAlternativeNames(certificate));
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            watch.Stop();
            return new(DiagnosticStatus.Failed, hostname, port, watch.Elapsed, ErrorMessage: "TLS handshake timed out.");
        }
        catch (AuthenticationException)
        {
            watch.Stop();
            var hostnameMismatch = policyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch);
            var chainInvalid = policyErrors.HasFlag(SslPolicyErrors.RemoteCertificateChainErrors);
            var now = DateTime.Now;
            var certificateError = certificate is not null && certificate.NotAfter < now ? "Server certificate has expired." :
                certificate is not null && certificate.NotBefore > now ? "Server certificate is not yet valid." :
                hostnameMismatch ? "Certificate hostname does not match the requested host." :
                chainInvalid ? "Certificate chain validation failed." : "TLS authentication failed.";
            return new(DiagnosticStatus.Failed, hostname, port, watch.Elapsed, Subject: certificate?.Subject,
                Issuer: certificate?.Issuer, NotAfter: certificate is null ? null : new DateTimeOffset(certificate.NotAfter),
                HostnameMatches: certificate is null ? null : !hostnameMismatch, ChainValid: certificate is null ? null : !chainInvalid,
                ErrorMessage: certificateError, NotBefore: certificate is null ? null : new DateTimeOffset(certificate.NotBefore),
                SubjectAlternativeNames: GetSubjectAlternativeNames(certificate));
        }
        catch (Exception exception) when (exception is IOException or SocketException)
        {
            watch.Stop();
            return new(DiagnosticStatus.Failed, hostname, port, watch.Elapsed, ErrorMessage: "TLS connection failed.");
        }
        finally { certificate?.Dispose(); }
    }

    private static string? GetSubjectAlternativeNames(X509Certificate2? certificate) =>
        certificate?.Extensions.Cast<X509Extension>()
            .FirstOrDefault(extension => extension.Oid?.Value == "2.5.29.17")?.Format(multiLine: false);
}

public sealed class HttpClientDiagnostic : IHttpDiagnostic, IDisposable
{
    private readonly HttpClient _client = new(new HttpClientHandler { AllowAutoRedirect = false });

    public async Task<HttpProbeResult> ProbeAsync(DiagnosticTarget target, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var scheme = target.Scheme ?? "https";
        var uri = new UriBuilder(scheme, target.Hostname, target.EffectivePort, target.Path).Uri;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.UserAgent.ParseAdd("AzNetCheck/0.1.0");
        var watch = Stopwatch.StartNew();
        try
        {
            using var response = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
            watch.Stop();
            return new(DiagnosticStatus.Passed, uri.GetLeftPart(UriPartial.Authority), (int)response.StatusCode, response.ReasonPhrase,
                watch.Elapsed, response.Headers.Location is null ? null : new Uri(uri, response.Headers.Location).GetLeftPart(UriPartial.Authority));
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            watch.Stop();
            return new(DiagnosticStatus.Failed, uri.GetLeftPart(UriPartial.Authority), null, null, watch.Elapsed, ErrorMessage: "HTTP request timed out.");
        }
        catch (HttpRequestException)
        {
            watch.Stop();
            return new(DiagnosticStatus.Failed, uri.GetLeftPart(UriPartial.Authority), null, null, watch.Elapsed, ErrorMessage: "HTTP request failed.");
        }
    }

    public void Dispose() => _client.Dispose();
}