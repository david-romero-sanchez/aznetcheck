using System.Net;
using System.Net.Sockets;
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
}