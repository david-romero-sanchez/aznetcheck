using System.Diagnostics;
using System.Text.Json;
using Xunit;

namespace AzNetCheck.Cli.Tests;

public sealed class CommandLineTests
{
    [Fact]
    public async Task Help_lists_the_command_tree()
    {
        var result = await RunAsync("--help");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("check <target>", result.StandardOutput);
        Assert.Contains("catalog", result.StandardOutput);
    }

    [Fact]
    public async Task Invalid_timeout_is_a_usage_error()
    {
        var result = await RunAsync("check", "example.com", "--timeout", "invalid", "--no-color");

        Assert.Equal(2, result.ExitCode);
        Assert.Contains("Timeout must be a number", result.StandardError);
        Assert.DoesNotContain("Unexpected diagnostic error", result.StandardError);
        Assert.DoesNotContain("\u001b[", result.StandardError);
    }

    [Fact]
    public async Task Catalog_alias_renders_without_ansi_when_no_color_is_set()
    {
        var result = await RunAsync("catalog", "show", "keyvault", "--no-color");

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Azure Key Vault", result.StandardOutput);
        Assert.DoesNotContain("\u001b[", result.StandardOutput);
    }

    [Fact]
    public async Task Json_check_has_no_human_output_and_reports_ip_family_mismatch()
    {
        var result = await RunAsync("check", "192.0.2.1", "--ipv6", "--json", "--timeout", "1");

        Assert.Equal(3, result.ExitCode);
        Assert.Empty(result.StandardError);
        using var document = JsonDocument.Parse(result.StandardOutput);
        var report = document.RootElement;
        Assert.Equal("1.0", report.GetProperty("schemaVersion").GetString());
        Assert.Equal("inconclusive", report.GetProperty("summary").GetProperty("overallStatus").GetString());
        Assert.Equal("skipped", report.GetProperty("results")[2].GetProperty("status").GetString());
    }

    private static async Task<ProcessResult> RunAsync(params string[] arguments)
    {
        var repositoryRoot = FindRepositoryRoot();
        var configuration = Directory.GetParent(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar))!.Name;
        var cliAssembly = Path.Combine(repositoryRoot, "src", "AzNetCheck.Cli", "bin", configuration,
            "net10.0", "aznetcheck.dll");
        Assert.True(File.Exists(cliAssembly), $"CLI assembly not found: {cliAssembly}");

        var startInfo = new ProcessStartInfo("dotnet")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        startInfo.ArgumentList.Add(cliAssembly);
        foreach (var argument in arguments) startInfo.ArgumentList.Add(argument);

        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("Could not start CLI process.");
        var standardOutput = process.StandardOutput.ReadToEndAsync();
        var standardError = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        return new ProcessResult(process.ExitCode, await standardOutput, await standardError);
    }

    private static string FindRepositoryRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
            if (File.Exists(Path.Combine(directory.FullName, "AzNetCheck.sln"))) return directory.FullName;
        throw new DirectoryNotFoundException("Could not find AzNetCheck.sln from the test output directory.");
    }

    private sealed record ProcessResult(int ExitCode, string StandardOutput, string StandardError);
}