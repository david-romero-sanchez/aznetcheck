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

public enum DnsRecordType { A, AAAA }

public sealed record DnsQueryResult(string ResponseCode, IReadOnlyList<IPAddress> Addresses, string? CanonicalName = null);

public interface IDnsQueryClient
{
    Task<DnsQueryResult> QueryAsync(string hostname, DnsRecordType recordType, CancellationToken cancellationToken);
}

public sealed class DnsClientQueryClient : IDnsQueryClient
{
    private readonly LookupClient _lookup = new(new LookupClientOptions { UseCache = true, ThrowDnsErrors = false });

    public async Task<DnsQueryResult> QueryAsync(string hostname, DnsRecordType recordType, CancellationToken cancellationToken)
    {
        var queryType = recordType == DnsRecordType.A ? QueryType.A : QueryType.AAAA;
        var response = await _lookup.QueryAsync(hostname, queryType, QueryClass.IN, cancellationToken).ConfigureAwait(false);
        var records = recordType == DnsRecordType.A
            ? response.Answers.ARecords().Select(record => record.Address).ToArray()
            : response.Answers.AaaaRecords().Select(record => record.Address).ToArray();
        var cname = response.Answers.CnameRecords().FirstOrDefault()?.CanonicalName.Value.TrimEnd('.');
        return new DnsQueryResult(response.Header.ResponseCode.ToString(), records, cname);
    }
}

public sealed class DnsClientDiagnostic : IDnsDiagnostic
{
    private const int MaximumCnameDepth = 12;
    private readonly IDnsQueryClient _queryClient;

    public DnsClientDiagnostic() : this(new DnsClientQueryClient())
    {
    }

    public DnsClientDiagnostic(IDnsQueryClient queryClient) => _queryClient = queryClient;

    public async Task<DnsResolutionResult> ResolveAsync(string hostname, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var watch = Stopwatch.StartNew();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        var chain = new List<string>();
        var addresses = new HashSet<IPAddress>();
        var current = hostname.TrimEnd('.');
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string? addressResponseCode = null;
        string? address6ResponseCode = null;
        try
        {
            for (var depth = 0; depth <= MaximumCnameDepth; depth++)
            {
                if (!visited.Add(current))
                {
                    watch.Stop();
                    return new(DiagnosticStatus.Failed, addresses.Select(address => address.ToString()).ToArray(), chain,
                        watch.Elapsed, "CnameLoop", "DNS CNAME loop detected.");
                }
                var responseA = await _queryClient.QueryAsync(current, DnsRecordType.A, deadline.Token).ConfigureAwait(false);
                var responseAaaa = await _queryClient.QueryAsync(current, DnsRecordType.AAAA, deadline.Token).ConfigureAwait(false);
                addresses.UnionWith(responseA.Addresses);
                addresses.UnionWith(responseAaaa.Addresses);
                addressResponseCode = responseA.ResponseCode;
                address6ResponseCode = responseAaaa.ResponseCode;
                var cname = responseA.CanonicalName ?? responseAaaa.CanonicalName;
                if (string.IsNullOrWhiteSpace(cname)) break;
                if (chain.Count == MaximumCnameDepth)
                {
                    watch.Stop();
                    return new(DiagnosticStatus.Inconclusive, addresses.Select(address => address.ToString()).ToArray(), chain,
                        watch.Elapsed, "CnameDepthExceeded", $"DNS CNAME chain exceeded the maximum depth of {MaximumCnameDepth}.");
                }
                chain.Add(cname);
                current = cname;
            }
            watch.Stop();
            return addresses.Count > 0
                ? new(DiagnosticStatus.Passed, addresses.Select(address => address.ToString()).ToArray(), chain, watch.Elapsed)
                : new(DiagnosticStatus.Failed, [], chain, watch.Elapsed,
                    addressResponseCode == "ServerFailure" || address6ResponseCode == "ServerFailure" ? "ServerFailure" :
                    addressResponseCode == "NxDomain" || address6ResponseCode == "NxDomain" ? "NxDomain" : "NoRecords",
                    addressResponseCode == "NxDomain" || address6ResponseCode == "NxDomain" ? "DNS returned NXDOMAIN; the hostname does not exist." :
                    addressResponseCode == "ServerFailure" || address6ResponseCode == "ServerFailure" ? "The DNS server returned SERVFAIL." :
                    "DNS returned no A or AAAA records.");
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
    public async Task<TlsProbeResult> HandshakeAsync(string hostname, IPAddress address, int port, TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var watch = Stopwatch.StartNew();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        X509Certificate2? certificate = null;
        SslPolicyErrors policyErrors = SslPolicyErrors.None;
        try
        {
            using var client = new TcpClient(address.AddressFamily);
            await client.ConnectAsync(address, port, deadline.Token).ConfigureAwait(false);
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
    private readonly HttpClient _client;
    private readonly bool _ownsClient;

    public HttpClientDiagnostic()
        : this(new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }), ownsClient: true)
    {
    }

    public HttpClientDiagnostic(HttpClient client)
        : this(client, ownsClient: false)
    {
    }

    private HttpClientDiagnostic(HttpClient client, bool ownsClient)
    {
        _client = client;
        _ownsClient = ownsClient;
    }

    public async Task<HttpProbeResult> ProbeAsync(DiagnosticTarget target, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var scheme = target.Scheme ?? "https";
        var queryStart = target.Path.IndexOf('?');
        var path = queryStart < 0 ? target.Path : target.Path[..queryStart];
        var query = queryStart < 0 ? string.Empty : target.Path[(queryStart + 1)..];
        var uri = new UriBuilder(scheme, target.Hostname, target.EffectivePort)
        {
            Path = path,
            Query = query
        }.Uri;
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

    public void Dispose()
    {
        if (_ownsClient) _client.Dispose();
    }
}