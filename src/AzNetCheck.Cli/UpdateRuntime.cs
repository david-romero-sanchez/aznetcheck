using System.CommandLine;
using System.Net.Http.Headers;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using AzNetCheck.Updater;

namespace AzNetCheck.Cli;

internal static partial class Program
{
    private static readonly HttpClient UpdateHttpClient = CreateUpdateHttpClient();

    private static string GetCurrentVersion()
    {
        var informational = Assembly.GetEntryAssembly()?.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (!string.IsNullOrWhiteSpace(informational)) return informational.Split('+', 2)[0];
        return Assembly.GetEntryAssembly()?.GetName().Version?.ToString(3) ?? "0.0.0";
    }

    private static UpdateStateStore CreateUpdateStateStore() =>
        new(new UpdatePaths(GetUpdateStateDirectory()), new ConsoleUpdateLogger());

    private static UpdateInstaller CreateUpdateInstaller(UpdateStateStore? stateStore = null) =>
        new(stateStore ?? CreateUpdateStateStore(), logger: new ConsoleUpdateLogger());

    private static UpdateManager CreateUpdateManager()
    {
        var logger = new ConsoleUpdateLogger();
        var options = UpdateOptions.Default(GetCurrentVersion(), GetUpdateStateDirectory());
        var state = new UpdateStateStore(new UpdatePaths(options.StateDirectory), logger);
        var verifier = new UpdateManifestVerifier();
        var client = new GitHubUpdateClient(UpdateHttpClient, options, verifier, state, logger);
        var installer = new UpdateInstaller(state, logger: logger);
        return new UpdateManager(client, installer, logger);
    }

    private static string GetUpdateStateDirectory()
    {
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(local))
            local = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "share");
        var executableIdentity = Path.GetFullPath(Environment.ProcessPath ?? AppContext.BaseDirectory);
        var instanceId = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(executableIdentity)))[..16].ToLowerInvariant();
        return Path.Combine(local, "AzNetCheck", "Updater", instanceId);
    }

    private static HttpClient CreateUpdateHttpClient()
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = true,
            MaxAutomaticRedirections = 5,
            AutomaticDecompression = System.Net.DecompressionMethods.GZip | System.Net.DecompressionMethods.Deflate
        };
        return new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
    }

    private static async Task<InternalUpdateCommandResult?> TryRunInternalUpdateCommandAsync(string[] args)
    {
        if (args.Length == 0 || args[0] is not ("--internal-apply-update" or "--internal-post-update" or "--internal-rollback-update"))
            return null;

        var installer = CreateUpdateInstaller();
        var root = new RootCommand();
        var transaction = new Argument<string>("transaction") { Description = "Private updater transaction file." };
        root.Arguments.Add(transaction);
        var mode = args[0];
        if (mode == "--internal-apply-update")
        {
            root.SetAction(async (parse, cancellationToken) =>
            {
                var transactionPath = parse.GetValue(transaction);
                return transactionPath is null ? 2 :
                    await installer.ApplyTransactionAsync(transactionPath, cancellationToken).ConfigureAwait(false);
            });
        }
        else if (mode == "--internal-post-update")
        {
            root.SetAction(_ => 0);
        }
        else
        {
            var processId = new Option<int>("--old-pid") { Required = true };
            var processStart = new Option<long>("--old-start") { Required = true };
            root.Options.Add(processId);
            root.Options.Add(processStart);
            root.SetAction(async (parse, cancellationToken) =>
            {
                var transactionPath = parse.GetValue(transaction);
                return transactionPath is null ? 2 :
                    await installer.RollbackInterruptedAsync(transactionPath, parse.GetValue(processId),
                        parse.GetValue(processStart), cancellationToken).ConfigureAwait(false);
            });
        }

        var parseResult = root.Parse(args.Skip(1).ToArray());
        if (parseResult.Errors.Count > 0)
            return new InternalUpdateCommandResult(true, 2, Error: string.Join(" ", parseResult.Errors.Select(item => item.Message)));
        if (mode == "--internal-post-update")
        {
            if (args.Length != 2)
                return new InternalUpdateCommandResult(true, 2, Error: "Unexpected internal post-update arguments.");
            return new InternalUpdateCommandResult(true, 0, PostUpdateTransactionPath: parseResult.GetValue(transaction));
        }
        var invocation = new InvocationConfiguration { EnableDefaultExceptionHandler = false };
        return new InternalUpdateCommandResult(true, await parseResult.InvokeAsync(invocation).ConfigureAwait(false));
    }

    private static string SerializeUpdateJson<T>(T value)
    {
        var options = new JsonSerializerOptions { WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
        options.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.CamelCase));
        return JsonSerializer.Serialize(value, options);
    }

    private sealed class ConsoleUpdateLogger : IUpdateLogger
    {
        public void Log(string eventName, string? detail = null) =>
            Console.Error.WriteLine(detail is null ? $"[update] {eventName}" : $"[update] {eventName}: {detail}");
    }
}

internal sealed record InternalUpdateCommandResult(bool Handled, int ExitCode,
    string? PostUpdateTransactionPath = null, string? Error = null);