using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace AzNetCheck.Updater;

public interface IUpdateChildProcess : IDisposable
{
    int Id { get; }
    bool HasExited { get; }
    void Kill();
}

public interface IUpdateInstallEnvironment
{
    bool SupportsSelfUpdate { get; }
    string? RuntimeIdentifier { get; }
    string? CurrentExecutablePath { get; }
    int CurrentProcessId { get; }
    DateTimeOffset CurrentProcessStartedUtc { get; }
    ProcessIdentity? GetProcessIdentity(int processId);
    Task<bool> WaitForExitAsync(ProcessIdentity identity, TimeSpan timeout, CancellationToken cancellationToken);
    bool IsDirectoryWritable(string directory);
    bool FileExists(string path);
    long GetFileLength(string path);
    Task<byte[]> GetSha256Async(string path, CancellationToken cancellationToken);
    void CopyFile(string sourcePath, string destinationPath);
    void ReplaceFile(string replacementPath, string targetPath, string backupPath);
    void DeleteFile(string path);
    IUpdateChildProcess StartProcess(string executablePath, IReadOnlyList<string> arguments, string workingDirectory);
    Task<bool> WaitForChildExitAsync(IUpdateChildProcess process, TimeSpan timeout, CancellationToken cancellationToken);
}

public sealed class SystemUpdateInstallEnvironment : IUpdateInstallEnvironment
{
    public bool SupportsSelfUpdate => OperatingSystem.IsWindows();
    public string? RuntimeIdentifier => UpdatePlatform.GetSupportedRid();
    public string? CurrentExecutablePath => Environment.ProcessPath;
    public int CurrentProcessId => Environment.ProcessId;
    public DateTimeOffset CurrentProcessStartedUtc => new(Process.GetCurrentProcess().StartTime.ToUniversalTime(), TimeSpan.Zero);

    public ProcessIdentity? GetProcessIdentity(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            if (process.HasExited) return null;
            var executable = process.MainModule?.FileName;
            if (string.IsNullOrWhiteSpace(executable)) return null;
            return new ProcessIdentity(processId, new DateTimeOffset(process.StartTime.ToUniversalTime(), TimeSpan.Zero),
                Path.GetFullPath(executable));
        }
        catch (ArgumentException) { return null; }
        catch (InvalidOperationException) { return null; }
        catch (System.ComponentModel.Win32Exception) { return null; }
    }

    public async Task<bool> WaitForExitAsync(ProcessIdentity identity, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var process = GetProcessIdentity(identity.ProcessId);
        if (process is null) return true;
        if (!SameProcess(process, identity)) return true;
        try
        {
            using var handle = Process.GetProcessById(identity.ProcessId);
            if (handle.HasExited) return true;
            var actualPath = handle.MainModule?.FileName;
            var actualStart = new DateTimeOffset(handle.StartTime.ToUniversalTime(), TimeSpan.Zero);
            if (string.IsNullOrWhiteSpace(actualPath) || !PathEquals(actualPath, identity.ExecutablePath) ||
                Math.Abs((actualStart - identity.StartedAtUtc).TotalSeconds) >= 2)
                return true;
            using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutSource.CancelAfter(timeout);
            await handle.WaitForExitAsync(timeoutSource.Token).ConfigureAwait(false);
            return true;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { return false; }
        catch (ArgumentException) { return true; }
        catch (InvalidOperationException) { return true; }
        catch (System.ComponentModel.Win32Exception) { return false; }
    }

    public bool IsDirectoryWritable(string directory)
    {
        var probe = Path.Combine(directory, $".aznetcheck-write-test-{Guid.NewGuid():N}");
        try
        {
            using (new FileStream(probe, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1, FileOptions.DeleteOnClose)) { }
            return true;
        }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
        finally
        {
            try { if (File.Exists(probe)) File.Delete(probe); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    public bool FileExists(string path) => File.Exists(path);
    public long GetFileLength(string path) => new FileInfo(path).Length;

    public async Task<byte[]> GetSha256Async(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
            128 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        return await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
    }

    public void CopyFile(string sourcePath, string destinationPath) => File.Copy(sourcePath, destinationPath, overwrite: false);

    public void ReplaceFile(string replacementPath, string targetPath, string backupPath) =>
        File.Replace(replacementPath, targetPath, backupPath, ignoreMetadataErrors: true);

    public void DeleteFile(string path)
    {
        if (File.Exists(path)) File.Delete(path);
    }

    public IUpdateChildProcess StartProcess(string executablePath, IReadOnlyList<string> arguments, string workingDirectory)
    {
        var startInfo = new ProcessStartInfo(executablePath)
        {
            UseShellExecute = false,
            WorkingDirectory = workingDirectory
        };
        foreach (var argument in arguments) startInfo.ArgumentList.Add(argument);
        var process = Process.Start(startInfo) ?? throw new InvalidOperationException("Failed to start update process.");
        return new SystemUpdateChildProcess(process);
    }

    public async Task<bool> WaitForChildExitAsync(IUpdateChildProcess child, TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        if (child.HasExited) return true;
        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);
        try
        {
            if (child is SystemUpdateChildProcess process)
                await process.WaitForExitAsync(timeoutSource.Token).ConfigureAwait(false);
            else
                while (!child.HasExited) await Task.Delay(100, timeoutSource.Token).ConfigureAwait(false);
            return true;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { return false; }
    }

    private static bool SameProcess(ProcessIdentity actual, ProcessIdentity expected) =>
        actual.ProcessId == expected.ProcessId &&
        Math.Abs((actual.StartedAtUtc - expected.StartedAtUtc).TotalSeconds) < 2 &&
        PathEquals(actual.ExecutablePath, expected.ExecutablePath);

    private static bool PathEquals(string left, string right) =>
        string.Equals(Path.GetFullPath(left), Path.GetFullPath(right), OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);

    private sealed class SystemUpdateChildProcess(Process process) : IUpdateChildProcess
    {
        public int Id => process.Id;
        public bool HasExited
        {
            get
            {
                try { return process.HasExited; }
                catch (InvalidOperationException) { return true; }
            }
        }

        public void Kill()
        {
            if (!HasExited) process.Kill(entireProcessTree: false);
        }

        public Task WaitForExitAsync(CancellationToken cancellationToken) => process.WaitForExitAsync(cancellationToken);
        public void Dispose() => process.Dispose();
    }
}

public sealed class UpdateInstaller(UpdateStateStore stateStore, IUpdateInstallEnvironment? environment = null,
    IUpdateLogger? logger = null, IUpdateInstallLockProvider? lockProvider = null)
{
    private static readonly TimeSpan OldProcessTimeout = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan HealthTimeout = TimeSpan.FromSeconds(90);
    private static readonly TimeSpan FailedVersionCooldown = TimeSpan.FromDays(7);
    private static readonly TimeSpan DownloadedTransactionStartupGrace = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan StaleDownloadCleanupAge = TimeSpan.FromDays(1);


    private readonly IUpdateInstallEnvironment _environment = environment ?? new SystemUpdateInstallEnvironment();
    private readonly IUpdateLogger _logger = logger ?? NullUpdateLogger.Instance;
    private readonly IUpdateInstallLockProvider _lockProvider = lockProvider ?? new NamedSemaphoreUpdateLockProvider();

    public bool TryGetWritableInstallation(out string? executablePath, out string? error)
    {
        executablePath = null;
        error = null;
        var current = _environment.CurrentExecutablePath;
        if (string.IsNullOrWhiteSpace(current) || !Path.IsPathRooted(current) ||
            !Path.GetExtension(current).Equals(".exe", StringComparison.OrdinalIgnoreCase))
        {
            error = "Self-update requires the published self-contained aznetcheck.exe; running through dotnet is not supported.";
            return false;
        }
        current = Path.GetFullPath(current);
        if (!Path.GetFileName(current).Equals("aznetcheck.exe", StringComparison.OrdinalIgnoreCase))
        {
            error = "Self-update requires the published self-contained aznetcheck.exe; running through dotnet or another host is not supported.";
            return false;
        }
        if (!_environment.SupportsSelfUpdate || _environment.RuntimeIdentifier != "win-x64")
        {
            error = "Self-update installation is currently supported only by the published Windows x64 executable.";
            return false;
        }
        var directory = Path.GetDirectoryName(current);
        if (directory is null || !_environment.FileExists(current) || !_environment.IsDirectoryWritable(directory))
        {
            error = "The installation directory is not writable. Install AzNetCheck under a user-writable folder, such as %LOCALAPPDATA%\\Programs\\AzNetCheck, or use a writable portable folder.";
            return false;
        }
        executablePath = current;
        return true;
    }

    public async Task<UpdateApplyResult> StartApplyAsync(string stagedExecutablePath, string fromVersion,
        string toVersion, string expectedSha256, long expectedSize, CancellationToken cancellationToken = default)
    {
        if (!TryGetWritableInstallation(out var target, out var error))
            return new(UpdateApplyStatus.InstallationNotSupported, Error: error);
        if (!Regex.IsMatch(expectedSha256, "^[a-fA-F0-9]{64}$", RegexOptions.CultureInvariant) || expectedSize <= 0)
            return new(UpdateApplyStatus.Failed, Error: "The verified update asset metadata is invalid.");

        var stageDirectory = stateStore.Paths.GetVersionDownloadDirectory(toVersion);
        var fullStage = Path.GetFullPath(stagedExecutablePath);
        var expectedStage = Path.GetFullPath(Path.Combine(stageDirectory, "aznetcheck-win-x64.exe"));
        if (!PathEquals(fullStage, expectedStage) || !_environment.FileExists(fullStage) ||
            _environment.GetFileLength(fullStage) != expectedSize)
            return new(UpdateApplyStatus.Failed, Error: "The staged update executable is missing or outside its expected temporary directory.");

        UpdateTransaction? pendingTransaction = null;
        using var updateLock = _lockProvider.TryAcquire(target!);
        if (updateLock is null) return new(UpdateApplyStatus.Failed, Error: "Another update transaction is already running.");
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (await _environment.GetSha256Async(fullStage, cancellationToken).ConfigureAwait(false) is var stagedHash &&
                !CryptographicOperations.FixedTimeEquals(stagedHash, Convert.FromHexString(expectedSha256)))
                return new(UpdateApplyStatus.Failed, Error: "The staged update executable failed SHA-256 verification.");
            if (await stateStore.LoadTransactionAsync(cancellationToken).ConfigureAwait(false) is { Status: not UpdateTransactionStatus.Succeeded and not UpdateTransactionStatus.RolledBack and not UpdateTransactionStatus.Failed })
                return new(UpdateApplyStatus.Failed, Error: "An update transaction is already pending recovery.");
            var oldProcess = new ProcessIdentity(_environment.CurrentProcessId,
                _environment.CurrentProcessStartedUtc, target!);
            var transaction = new UpdateTransaction
            {
                TransactionId = Guid.NewGuid().ToString("N"),
                FromVersion = fromVersion,
                ToVersion = toVersion,
                TargetExecutablePath = target!,
                StagedExecutablePath = fullStage,
                BackupExecutablePath = target + ".old",
                FailedExecutablePath = target + ".failed-" + Guid.NewGuid().ToString("N"),
                Sha256 = expectedSha256.ToLowerInvariant(),
                OldProcessId = oldProcess.ProcessId,
                OldProcessStartedUtc = oldProcess.StartedAtUtc,
                CreatedAtUtc = DateTimeOffset.UtcNow,
                Status = UpdateTransactionStatus.Downloaded
            };
            if (_environment.FileExists(transaction.BackupExecutablePath))
                return new(UpdateApplyStatus.Failed, Error: "A previous update backup exists; recover or remove it before updating again.");
            pendingTransaction = transaction;
            await stateStore.SaveTransactionAsync(transaction, cancellationToken).ConfigureAwait(false);
            _environment.StartProcess(fullStage, ["--internal-apply-update", stateStore.Paths.TransactionPath], stageDirectory);
            _logger.Log("update-process-started", toVersion);
            return new(UpdateApplyStatus.Started, $"Update to {toVersion} started. This process will close while the update is applied.");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            _logger.Log("update-process-start-failed", exception.GetType().Name);
            if (pendingTransaction is not null)
            {
                await MarkFailedAsync(pendingTransaction, "updater-process-start-failed").ConfigureAwait(false);
                await stateStore.DeleteTransactionAsync().ConfigureAwait(false);
            }
            return new(UpdateApplyStatus.Failed, Error: "Could not start the verified updater process.");
        }
    }

    public async Task<int> ApplyTransactionAsync(string transactionPath, CancellationToken cancellationToken = default)
    {
        if (!_environment.SupportsSelfUpdate) return 2;
        if (!PathEquals(transactionPath, stateStore.Paths.TransactionPath)) return 2;
        var transaction = await stateStore.LoadTransactionAsync(cancellationToken).ConfigureAwait(false);
        var validationError = transaction is null ? "Update transaction was not found." : null;
        if (transaction is null || !ValidateTransaction(transaction, out validationError))
        {
            _logger.Log("update-transaction-invalid", validationError);
            return 2;
        }

        using var updateLock = _lockProvider.Acquire(transaction.TargetExecutablePath, TimeSpan.FromSeconds(30));
        if (updateLock is null) return 2;
        var current = _environment.CurrentExecutablePath;
        if (string.IsNullOrWhiteSpace(current) || !PathEquals(current, transaction.StagedExecutablePath)) return 2;
        try
        {
            await VerifyFileAsync(transaction.StagedExecutablePath, transaction, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is IOException or InvalidDataException)
        {
            _logger.Log("hash-validation-failed", "running-updater");
            await MarkFailedAsync(transaction, "running-updater-hash-invalid").ConfigureAwait(false);
            return 1;
        }

        var identity = new ProcessIdentity(transaction.OldProcessId, transaction.OldProcessStartedUtc,
            transaction.TargetExecutablePath);
        var activeIdentity = _environment.GetProcessIdentity(identity.ProcessId);
        if (activeIdentity is null || !SameProcess(activeIdentity, identity)) return 2;
        _logger.Log("waiting-for-old-process", transaction.OldProcessId.ToString(CultureInfo.InvariantCulture));
        if (!await _environment.WaitForExitAsync(identity, OldProcessTimeout, cancellationToken).ConfigureAwait(false))
        {
            await MarkFailedAsync(transaction, "old-process-timeout").ConfigureAwait(false);
            return 1;
        }

        var targetDirectory = Path.GetDirectoryName(transaction.TargetExecutablePath)!;
        if (!_environment.IsDirectoryWritable(targetDirectory) || !_environment.FileExists(transaction.TargetExecutablePath))
        {
            await MarkFailedAsync(transaction, "install-directory-not-writable").ConfigureAwait(false);
            return 1;
        }

        IUpdateChildProcess? newProcess = null;
        var replacementPath = Path.Combine(targetDirectory, $".aznetcheck-{transaction.TransactionId}.new.exe");
        try
        {
            await stateStore.SaveTransactionAsync(transaction with { Status = UpdateTransactionStatus.Applying }, CancellationToken.None)
                .ConfigureAwait(false);
            _environment.CopyFile(transaction.StagedExecutablePath, replacementPath);
            await VerifyFileAsync(replacementPath, transaction, CancellationToken.None).ConfigureAwait(false);
            if (_environment.FileExists(transaction.BackupExecutablePath))
                throw new IOException("A backup file already exists; refusing to overwrite it.");
            _environment.ReplaceFile(replacementPath, transaction.TargetExecutablePath, transaction.BackupExecutablePath);
            _logger.Log("backup-created", transaction.BackupExecutablePath);
            transaction = transaction with { Status = UpdateTransactionStatus.AwaitingHealthCheck };
            await stateStore.SaveTransactionAsync(transaction, CancellationToken.None).ConfigureAwait(false);
            _logger.Log("executable-replaced", transaction.ToVersion);

            newProcess = _environment.StartProcess(transaction.TargetExecutablePath,
                ["--internal-post-update", stateStore.Paths.TransactionPath], targetDirectory);
            _logger.Log("new-version-started", transaction.ToVersion);
            var deadline = DateTimeOffset.UtcNow + HealthTimeout;
            while (DateTimeOffset.UtcNow < deadline)
            {
                var currentTransaction = await stateStore.LoadTransactionAsync(CancellationToken.None).ConfigureAwait(false);
                if (currentTransaction?.Status == UpdateTransactionStatus.Succeeded)
                {
                    _logger.Log("health-check-succeeded", transaction.ToVersion);
                    await CleanupSuccessfulUpdateAsync(transaction).ConfigureAwait(false);
                    return 0;
                }
                if (newProcess.HasExited) break;
                await Task.Delay(200, CancellationToken.None).ConfigureAwait(false);
            }

            if (!newProcess.HasExited)
            {
                _logger.Log("health-check-failed", "timeout");
                newProcess.Kill();
                await _environment.WaitForChildExitAsync(newProcess, TimeSpan.FromSeconds(10), CancellationToken.None)
                    .ConfigureAwait(false);
            }
            _logger.Log("health-check-failed", "new-process-exited-before-confirmation");
            await RollbackAsync(transaction, "health-check-failed").ConfigureAwait(false);
            _environment.StartProcess(transaction.TargetExecutablePath, [], targetDirectory);
            return 1;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidOperationException or TimeoutException or System.ComponentModel.Win32Exception)
        {
            _logger.Log("update-apply-failed", exception.GetType().Name);
            if (newProcess is not null && !newProcess.HasExited)
            {
                try { newProcess.Kill(); } catch (InvalidOperationException) { }
                await _environment.WaitForChildExitAsync(newProcess, TimeSpan.FromSeconds(10), CancellationToken.None)
                    .ConfigureAwait(false);
            }
            if (_environment.FileExists(transaction.BackupExecutablePath))
            {
                await RollbackAsync(transaction, "replace-failed").ConfigureAwait(false);
                try { _environment.StartProcess(transaction.TargetExecutablePath, [], targetDirectory); }
                catch (Exception launchException) when (launchException is IOException or InvalidOperationException or System.ComponentModel.Win32Exception)
                {
                    _logger.Log("rollback-relaunch-failed", launchException.GetType().Name);
                }
            }
            else
            {
                await MarkFailedAsync(transaction, "apply-failed-before-replacement").ConfigureAwait(false);
            }
            return 1;
        }
        finally
        {
            newProcess?.Dispose();
            try { _environment.DeleteFile(replacementPath); }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                _logger.Log("update-cleanup-failed", exception.GetType().Name);
            }
        }
    }

    public async Task<bool> ConfirmHealthAsync(string transactionPath, CancellationToken cancellationToken = default)
    {
        if (!PathEquals(transactionPath, stateStore.Paths.TransactionPath)) return false;
        var transaction = await stateStore.LoadTransactionAsync(cancellationToken).ConfigureAwait(false);
        if (transaction is null || transaction.Status != UpdateTransactionStatus.AwaitingHealthCheck ||
            string.IsNullOrWhiteSpace(_environment.CurrentExecutablePath) ||
            !PathEquals(_environment.CurrentExecutablePath, transaction.TargetExecutablePath))
            return false;
        try { await VerifyFileAsync(transaction.TargetExecutablePath, transaction, cancellationToken).ConfigureAwait(false); }
        catch (Exception exception) when (exception is IOException or InvalidDataException)
        {
            _logger.Log("health-check-failed", "installed-hash-mismatch");
            return false;
        }
        await stateStore.SaveTransactionAsync(transaction with { Status = UpdateTransactionStatus.Succeeded }, cancellationToken)
            .ConfigureAwait(false);
        _logger.Log("health-check-succeeded", transaction.ToVersion);
        return true;
    }

    public async Task<bool> RecoverPendingAsync(CancellationToken cancellationToken = default)
    {
        var transaction = await stateStore.LoadTransactionAsync(cancellationToken).ConfigureAwait(false);
        if (transaction is null) return false;
        if (!ValidateTransaction(transaction, out var validationError))
        {
            _logger.Log("update-transaction-invalid", validationError);
            return false;
        }
        var lockedTargetPath = transaction.TargetExecutablePath;
        using var updateLock = _lockProvider.TryAcquire(lockedTargetPath);
        if (updateLock is null) return false;
        transaction = await stateStore.LoadTransactionAsync(cancellationToken).ConfigureAwait(false);
        if (transaction is null || !ValidateTransaction(transaction, out _) ||
            !PathEquals(transaction.TargetExecutablePath, lockedTargetPath)) return false;
        if (transaction.Status == UpdateTransactionStatus.Succeeded)
        {
            if (string.IsNullOrWhiteSpace(_environment.CurrentExecutablePath) ||
                !PathEquals(_environment.CurrentExecutablePath, transaction.TargetExecutablePath))
                return false;
            await CleanupSuccessfulUpdateAsync(transaction).ConfigureAwait(false);
            return false;
        }
        if (transaction.Status == UpdateTransactionStatus.Downloaded)
        {
            if (DateTimeOffset.UtcNow - transaction.CreatedAtUtc < DownloadedTransactionStartupGrace)
                return false;
            await stateStore.DeleteTransactionAsync().ConfigureAwait(false);
            _logger.Log("interrupted-download-cleaned", transaction.TransactionId);
            return false;
        }
        if (transaction.Status is UpdateTransactionStatus.RolledBack or UpdateTransactionStatus.Failed)
            return false;
        if (!_environment.SupportsSelfUpdate || string.IsNullOrWhiteSpace(_environment.CurrentExecutablePath) ||
            !PathEquals(_environment.CurrentExecutablePath, transaction.TargetExecutablePath))
            return false;
        _logger.Log("interrupted-update-detected", transaction.Status.ToString());
        _environment.StartProcess(transaction.StagedExecutablePath,
            ["--internal-rollback-update", stateStore.Paths.TransactionPath,
             "--old-pid", _environment.CurrentProcessId.ToString(CultureInfo.InvariantCulture),
             "--old-start", _environment.CurrentProcessStartedUtc.UtcTicks.ToString(CultureInfo.InvariantCulture)],
            Path.GetDirectoryName(transaction.StagedExecutablePath)!);
        return true;
    }

    public async Task<int> RollbackInterruptedAsync(string transactionPath, int currentProcessId,
        long currentProcessStartUtcTicks, CancellationToken cancellationToken = default)
    {
        if (!_environment.SupportsSelfUpdate || !PathEquals(transactionPath, stateStore.Paths.TransactionPath)) return 2;
        var transaction = await stateStore.LoadTransactionAsync(cancellationToken).ConfigureAwait(false);
        if (transaction is null || !ValidateTransaction(transaction, out _)) return 2;
        if (string.IsNullOrWhiteSpace(_environment.CurrentExecutablePath) ||
            !PathEquals(_environment.CurrentExecutablePath, transaction.StagedExecutablePath)) return 2;
        using var updateLock = _lockProvider.Acquire(transaction.TargetExecutablePath, TimeSpan.FromSeconds(30));
        if (updateLock is null) return 2;
        var identity = new ProcessIdentity(currentProcessId,
            new DateTimeOffset(currentProcessStartUtcTicks, TimeSpan.Zero), transaction.TargetExecutablePath);
        var actual = _environment.GetProcessIdentity(currentProcessId);
        if (actual is not null && !SameProcess(actual, identity)) return 2;
        if (!await _environment.WaitForExitAsync(identity, OldProcessTimeout, cancellationToken).ConfigureAwait(false)) return 1;
        if (!_environment.FileExists(transaction.BackupExecutablePath))
        {
            if (!_environment.FileExists(transaction.TargetExecutablePath)) return 1;
            await MarkFailedAsync(transaction, "interrupted-before-replacement").ConfigureAwait(false);
            _environment.StartProcess(transaction.TargetExecutablePath, [], Path.GetDirectoryName(transaction.TargetExecutablePath)!);
            return 0;
        }
        await RollbackAsync(transaction, "interrupted-transaction").ConfigureAwait(false);
        _environment.StartProcess(transaction.TargetExecutablePath, [], Path.GetDirectoryName(transaction.TargetExecutablePath)!);
        return 0;
    }

    private bool ValidateTransaction(UpdateTransaction transaction, out string? error)
    {
        error = null;
        if (transaction.SchemaVersion != 1 || !Guid.TryParseExact(transaction.TransactionId, "N", out _) ||
            !UpdateVersionComparer.TryParse(transaction.FromVersion, out _) || !UpdateVersionComparer.TryParse(transaction.ToVersion, out _) ||
            !Regex.IsMatch(transaction.Sha256, "^[a-fA-F0-9]{64}$", RegexOptions.CultureInvariant))
        {
            error = "Transaction metadata is invalid.";
            return false;
        }
        if (!Path.IsPathRooted(transaction.TargetExecutablePath) || !Path.IsPathRooted(transaction.StagedExecutablePath) ||
            !Path.IsPathRooted(transaction.BackupExecutablePath) || !Path.IsPathRooted(transaction.FailedExecutablePath))
        {
            error = "Transaction paths must be absolute.";
            return false;
        }
        var target = Path.GetFullPath(transaction.TargetExecutablePath);
        if (!Path.GetExtension(target).Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
            !Path.GetFileName(target).Equals("aznetcheck.exe", StringComparison.OrdinalIgnoreCase) ||
            !Path.GetDirectoryName(target)!.Equals(Path.GetFullPath(Path.GetDirectoryName(target)!), StringComparison.OrdinalIgnoreCase) ||
            PathEquals(target, transaction.StagedExecutablePath) ||
            !PathEquals(transaction.BackupExecutablePath, target + ".old") ||
            !PathEquals(transaction.FailedExecutablePath, target + ".failed-" + transaction.TransactionId))
        {
            error = "Transaction target, staged, backup, or failed paths violate updater invariants.";
            return false;
        }
        var expectedStage = Path.GetFullPath(Path.Combine(stateStore.Paths.GetVersionDownloadDirectory(transaction.ToVersion),
            "aznetcheck-win-x64.exe"));
        if (!PathEquals(expectedStage, transaction.StagedExecutablePath))
        {
            error = "Staged executable is outside the application update directory.";
            return false;
        }
        if (transaction.OldProcessId <= 0 || transaction.OldProcessStartedUtc.Offset != TimeSpan.Zero)
        {
            error = "Original process identity is invalid.";
            return false;
        }
        return true;
    }

    private async Task VerifyFileAsync(string path, UpdateTransaction transaction, CancellationToken cancellationToken)
    {
        if (!_environment.FileExists(path)) throw new FileNotFoundException("Verified update file is missing.", path);
        var hash = await _environment.GetSha256Async(path, cancellationToken).ConfigureAwait(false);
        if (!CryptographicOperations.FixedTimeEquals(hash, Convert.FromHexString(transaction.Sha256)))
            throw new InvalidDataException("Update executable SHA-256 does not match the signed manifest.");
    }

    private async Task RollbackAsync(UpdateTransaction transaction, string reason)
    {
        _logger.Log("rollback-started", reason);
        try
        {
            await stateStore.SaveTransactionAsync(transaction with
            {
                Status = UpdateTransactionStatus.RollingBack,
                FailureReason = reason
            }, CancellationToken.None).ConfigureAwait(false);
            var failedPath = transaction.FailedExecutablePath;
            _environment.ReplaceFile(transaction.BackupExecutablePath, transaction.TargetExecutablePath, failedPath);
            try { _environment.DeleteFile(failedPath); }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                _logger.Log("update-cleanup-failed", exception.GetType().Name);
            }
            await RecordFailedVersionAsync(transaction.ToVersion, reason).ConfigureAwait(false);
            await stateStore.SaveTransactionAsync(transaction with
            {
                Status = UpdateTransactionStatus.RolledBack,
                FailureReason = reason
            }, CancellationToken.None).ConfigureAwait(false);
            _logger.Log("rollback-succeeded", transaction.FromVersion);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            _logger.Log("rollback-failed", exception.GetType().Name);
            throw;
        }
    }

    private async Task MarkFailedAsync(UpdateTransaction transaction, string reason)
    {
        await RecordFailedVersionAsync(transaction.ToVersion, reason).ConfigureAwait(false);
        await stateStore.SaveTransactionAsync(transaction with
        {
            Status = UpdateTransactionStatus.Failed,
            FailureReason = reason
        }, CancellationToken.None).ConfigureAwait(false);
    }

    private async Task RecordFailedVersionAsync(string version, string reason)
    {
        var state = await stateStore.LoadAsync(CancellationToken.None).ConfigureAwait(false);
        var now = DateTimeOffset.UtcNow;
        var failed = state.FailedVersions
            .Where(item => now - item.Value.FailedAtUtc < FailedVersionCooldown)
            .ToDictionary(item => item.Key, item => item.Value, StringComparer.OrdinalIgnoreCase);
        failed[version] = new FailedUpdate(now, reason);
        await stateStore.SaveAsync(state with { FailedVersions = failed }, CancellationToken.None).ConfigureAwait(false);
    }

    private async Task CleanupSuccessfulUpdateAsync(UpdateTransaction transaction)
    {
        try
        {
            _environment.DeleteFile(transaction.BackupExecutablePath);
            _environment.DeleteFile(transaction.StagedExecutablePath);
            await stateStore.DeleteTransactionAsync().ConfigureAwait(false);
            TryCleanOldDownloads(transaction.ToVersion);
            _logger.Log("cleanup-completed", transaction.TransactionId);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            _logger.Log("update-cleanup-failed", exception.GetType().Name);
        }
    }

    private void TryCleanOldDownloads(string currentVersion)
    {
        try
        {
            var parent = Directory.GetParent(stateStore.Paths.GetVersionDownloadDirectory(currentVersion))?.FullName;
            if (parent is null || !Directory.Exists(parent)) return;
            foreach (var directory in Directory.EnumerateDirectories(parent))
            {
                if (Path.GetFileName(directory).Equals(currentVersion, StringComparison.OrdinalIgnoreCase)) continue;
                if (DateTime.UtcNow - Directory.GetLastWriteTimeUtc(directory) < StaleDownloadCleanupAge) continue;
                try { Directory.Delete(directory, recursive: true); }
                catch (IOException exception) { _logger.Log("update-cleanup-failed", exception.GetType().Name); }
                catch (UnauthorizedAccessException exception) { _logger.Log("update-cleanup-failed", exception.GetType().Name); }
            }
            foreach (var download in Directory.EnumerateFiles(parent, "*.download", SearchOption.AllDirectories))
            {
                if (DateTime.UtcNow - File.GetLastWriteTimeUtc(download) < StaleDownloadCleanupAge) continue;
                try { File.Delete(download); }
                catch (IOException exception) { _logger.Log("update-cleanup-failed", exception.GetType().Name); }
                catch (UnauthorizedAccessException exception) { _logger.Log("update-cleanup-failed", exception.GetType().Name); }
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
        {
            _logger.Log("update-cleanup-failed", exception.GetType().Name);
        }
    }

    private static bool SameProcess(ProcessIdentity actual, ProcessIdentity expected) =>
        actual.ProcessId == expected.ProcessId &&
        Math.Abs((actual.StartedAtUtc - expected.StartedAtUtc).TotalSeconds) < 2 &&
        PathEquals(actual.ExecutablePath, expected.ExecutablePath);

    private static bool PathEquals(string left, string right) =>
        string.Equals(Path.GetFullPath(left), Path.GetFullPath(right), OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);

}