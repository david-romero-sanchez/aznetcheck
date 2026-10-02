using System.Text.Json;
using System.Security.Cryptography;
using System.Text;

namespace AzNetCheck.Updater;

public sealed class UpdatePaths(string? rootOverride = null, string? downloadRootOverride = null)
{
    public string Root { get; } = Path.GetFullPath(rootOverride ?? GetDefaultRoot());
    private string DownloadRoot { get; } = Path.GetFullPath(downloadRootOverride ?? GetDefaultDownloadRoot(rootOverride));
    public string StatePath => Path.Combine(Root, "state.json");
    public string TransactionPath => Path.Combine(Root, "pending-transaction.json");

    public string GetVersionDownloadDirectory(string version)
    {
        var safeVersion = string.Concat(version.Where(character => char.IsAsciiLetterOrDigit(character) || character is '.' or '-' or '+'));
        if (safeVersion.Length == 0 || safeVersion != version)
            throw new ArgumentException("Version contains invalid path characters.", nameof(version));
        return Path.Combine(DownloadRoot, safeVersion);
    }

    public bool IsUnderStateRoot(string path)
    {
        var fullPath = Path.GetFullPath(path);
        var rootWithSeparator = Root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
        return fullPath.StartsWith(rootWithSeparator, OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
    }

    private static string GetDefaultRoot()
    {
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(local))
            local = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "share");
        return Path.Combine(local, "AzNetCheck", "Updater");
    }

    private static string GetDefaultDownloadRoot(string? rootOverride)
    {
        var localRoot = Path.GetFullPath(rootOverride ?? GetDefaultRoot());
        var instanceHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(localRoot)))[..16].ToLowerInvariant();
        return Path.Combine(Path.GetTempPath(), "AzNetCheck", "updates", instanceHash);
    }
}

public sealed class UpdateStateStore(UpdatePaths paths, IUpdateLogger? logger = null)
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
    private readonly IUpdateLogger _logger = logger ?? NullUpdateLogger.Instance;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public UpdatePaths Paths => paths;

    public async Task<UpdateState> LoadAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!File.Exists(paths.StatePath)) return new UpdateState();
            try
            {
                await using var stream = new FileStream(paths.StatePath, FileMode.Open, FileAccess.Read, FileShare.Read,
                    16 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
                return await JsonSerializer.DeserializeAsync<UpdateState>(stream, JsonOptions, cancellationToken).ConfigureAwait(false)
                    ?? new UpdateState();
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
            {
                _logger.Log("update-state-corrupt", exception.GetType().Name);
                return new UpdateState();
            }
        }
        finally { _gate.Release(); }
    }

    public async Task SaveAsync(UpdateState state, CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await WriteAtomicAsync(paths.StatePath, state, cancellationToken).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    public async Task<UpdateTransaction?> LoadTransactionAsync(CancellationToken cancellationToken = default)
    {
        if (!File.Exists(paths.TransactionPath)) return null;
        try
        {
            await using var stream = new FileStream(paths.TransactionPath, FileMode.Open, FileAccess.Read, FileShare.Read,
                16 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
            return await JsonSerializer.DeserializeAsync<UpdateTransaction>(stream, JsonOptions, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            _logger.Log("update-transaction-corrupt", exception.GetType().Name);
            return null;
        }
    }

    public async Task SaveTransactionAsync(UpdateTransaction transaction, CancellationToken cancellationToken = default) =>
        await WriteAtomicAsync(paths.TransactionPath, transaction, cancellationToken).ConfigureAwait(false);

    public Task DeleteTransactionAsync() 
    {
        try { if (File.Exists(paths.TransactionPath)) File.Delete(paths.TransactionPath); }
        catch (IOException exception) { _logger.Log("update-cleanup-failed", exception.GetType().Name); }
        catch (UnauthorizedAccessException exception) { _logger.Log("update-cleanup-failed", exception.GetType().Name); }
        return Task.CompletedTask;
    }

    private static async Task WriteAtomicAsync<T>(string path, T value, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            await using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                16 * 1024, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                await JsonSerializer.SerializeAsync(stream, value, JsonOptions, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            File.Move(temporary, path, overwrite: true);
        }
        finally
        {
            try { if (File.Exists(temporary)) File.Delete(temporary); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }
}