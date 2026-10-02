using System.Security.Cryptography;
using AzNetCheck.Updater;
using Xunit;

namespace AzNetCheck.Updater.Tests;

public sealed class UpdateInstallerTests
{
    [Fact]
    public async Task StartApply_requires_supported_writable_self_contained_executable()
    {
        using var fixture = new InstallerFixture();
        fixture.Environment.CurrentExecutablePath = Path.Combine(fixture.InstallDirectory, "aznetcheck.exe");
        fixture.Environment.AddFile(fixture.Environment.CurrentExecutablePath, [4, 5, 6]);
        fixture.Environment.Writable = false;

        var installer = fixture.CreateInstaller();
        var result = await installer.StartApplyAsync(fixture.StagedPath, "1.3.0", "1.4.0",
            fixture.StagedHash, fixture.StagedSize);

        Assert.Equal(UpdateApplyStatus.InstallationNotSupported, result.Status);
        Assert.Empty(fixture.Environment.StartedProcesses);
    }

    [Fact]
    public async Task Rejects_a_staged_executable_outside_the_expected_version_directory()
    {
        using var fixture = new InstallerFixture();
        fixture.Environment.CurrentExecutablePath = fixture.TargetPath;
        fixture.Environment.AddFile(fixture.TargetPath, [4, 5, 6]);
        var installer = fixture.CreateInstaller();

        var result = await installer.StartApplyAsync(Path.Combine(fixture.Root, "attacker.exe"), "1.3.0", "1.4.0",
            fixture.StagedHash, fixture.StagedSize);

        Assert.Equal(UpdateApplyStatus.Failed, result.Status);
        Assert.Empty(fixture.Environment.StartedProcesses);
    }

    [Fact]
    public async Task StartApply_refuses_to_start_when_another_instance_holds_the_install_lock()
    {
        using var fixture = new InstallerFixture();
        fixture.Environment.CurrentExecutablePath = fixture.TargetPath;
        using var heldLock = fixture.AcquireInstallLock();

        var result = await fixture.CreateInstaller().StartApplyAsync(fixture.StagedPath, "1.3.0", "1.4.0",
            fixture.StagedHash, fixture.StagedSize);

        Assert.Equal(UpdateApplyStatus.Failed, result.Status);
        Assert.Contains("already running", result.Error);
        Assert.Empty(fixture.Environment.StartedProcesses);
        Assert.Null(await fixture.Store.LoadTransactionAsync());
    }

    [Fact]
    public async Task Apply_waits_for_matching_old_process_creates_backup_and_commits_after_health_handshake()
    {
        using var fixture = new InstallerFixture();
        var transaction = fixture.CreateTransaction();
        await fixture.Store.SaveTransactionAsync(transaction);
        fixture.Environment.CurrentExecutablePath = fixture.StagedPath;
        fixture.Environment.Processes[transaction.OldProcessId] = new ProcessIdentity(transaction.OldProcessId,
            transaction.OldProcessStartedUtc, transaction.TargetExecutablePath);
        fixture.Environment.OnStart = async (path, args) =>
        {
            if (args.FirstOrDefault() == "--internal-post-update")
                await fixture.Store.SaveTransactionAsync(transaction with { Status = UpdateTransactionStatus.Succeeded });
            return new FakeChildProcess(fixture.Environment.NextChildId++, exited: false);
        };

        var installer = fixture.CreateInstaller();
        var result = await installer.ApplyTransactionAsync(fixture.Paths.TransactionPath);

        Assert.Equal(0, result);
        Assert.True(fixture.Environment.WaitedForOldProcess);
        Assert.True(fixture.Environment.BackupWasCreated);
        Assert.Equal([9, 9, 9, 9], fixture.Environment.GetFile(transaction.TargetExecutablePath));
        Assert.False(fixture.Environment.Contains(transaction.BackupExecutablePath));
        Assert.Null(await fixture.Store.LoadTransactionAsync());
    }

    [Fact]
    public async Task Apply_rolls_back_if_the_new_process_exits_before_health_confirmation()
    {
        using var fixture = new InstallerFixture();
        var transaction = fixture.CreateTransaction();
        await fixture.Store.SaveTransactionAsync(transaction);
        fixture.Environment.CurrentExecutablePath = fixture.StagedPath;
        fixture.Environment.Processes[transaction.OldProcessId] = new ProcessIdentity(transaction.OldProcessId,
            transaction.OldProcessStartedUtc, transaction.TargetExecutablePath);
        fixture.Environment.OnStart = (_, _) => Task.FromResult<IUpdateChildProcess>(
            new FakeChildProcess(fixture.Environment.NextChildId++, exited: true));

        var installer = fixture.CreateInstaller();
        var result = await installer.ApplyTransactionAsync(fixture.Paths.TransactionPath);

        Assert.Equal(1, result);
        Assert.Equal([1, 2, 3], fixture.Environment.GetFile(transaction.TargetExecutablePath));
        Assert.False(fixture.Environment.Contains(transaction.BackupExecutablePath));
        var finalState = await fixture.Store.LoadTransactionAsync();
        Assert.Equal(UpdateTransactionStatus.RolledBack, finalState!.Status);
        Assert.Contains("1.4.0", (await fixture.Store.LoadAsync()).FailedVersions.Keys);
    }

    [Fact]
    public async Task Apply_refuses_a_pid_reused_by_an_unrelated_process()
    {
        using var fixture = new InstallerFixture();
        var transaction = fixture.CreateTransaction();
        await fixture.Store.SaveTransactionAsync(transaction);
        fixture.Environment.CurrentExecutablePath = fixture.StagedPath;
        fixture.Environment.Processes[transaction.OldProcessId] = new ProcessIdentity(transaction.OldProcessId,
            transaction.OldProcessStartedUtc.AddMinutes(2), Path.Combine(fixture.Root, "unrelated.exe"));

        var result = await fixture.CreateInstaller().ApplyTransactionAsync(fixture.Paths.TransactionPath);

        Assert.Equal(2, result);
        Assert.Equal([1, 2, 3], fixture.Environment.GetFile(transaction.TargetExecutablePath));
        Assert.False(fixture.Environment.Contains(transaction.BackupExecutablePath));
    }

    [Fact]
    public async Task Apply_preserves_installation_when_old_process_times_out()
    {
        using var fixture = new InstallerFixture();
        var transaction = fixture.CreateTransaction();
        await fixture.Store.SaveTransactionAsync(transaction);
        fixture.Environment.CurrentExecutablePath = fixture.StagedPath;
        fixture.Environment.WaitResult = false;
        fixture.Environment.Processes[transaction.OldProcessId] = new ProcessIdentity(transaction.OldProcessId,
            transaction.OldProcessStartedUtc, transaction.TargetExecutablePath);

        var result = await fixture.CreateInstaller().ApplyTransactionAsync(fixture.Paths.TransactionPath);

        Assert.Equal(1, result);
        Assert.Equal([1, 2, 3], fixture.Environment.GetFile(transaction.TargetExecutablePath));
        Assert.False(fixture.Environment.Contains(transaction.BackupExecutablePath));
        Assert.Equal(UpdateTransactionStatus.Failed, (await fixture.Store.LoadTransactionAsync())!.Status);
    }

    [Fact]
    public async Task Apply_preserves_installation_when_file_replace_fails_before_backup()
    {
        using var fixture = new InstallerFixture();
        var transaction = fixture.CreateTransaction();
        await fixture.Store.SaveTransactionAsync(transaction);
        fixture.Environment.CurrentExecutablePath = fixture.StagedPath;
        fixture.Environment.Processes[transaction.OldProcessId] = new ProcessIdentity(transaction.OldProcessId,
            transaction.OldProcessStartedUtc, transaction.TargetExecutablePath);
        fixture.Environment.FailReplace = true;

        var result = await fixture.CreateInstaller().ApplyTransactionAsync(fixture.Paths.TransactionPath);

        Assert.Equal(1, result);
        Assert.Equal([1, 2, 3], fixture.Environment.GetFile(transaction.TargetExecutablePath));
        Assert.False(fixture.Environment.Contains(transaction.BackupExecutablePath));
        Assert.Equal(UpdateTransactionStatus.Failed, (await fixture.Store.LoadTransactionAsync())!.Status);
    }

    [Fact]
    public async Task Apply_rejects_manipulated_target_paths()
    {
        using var fixture = new InstallerFixture();
        var transaction = fixture.CreateTransaction() with
        {
            TargetExecutablePath = Path.Combine(fixture.Root, "unrelated.exe"),
            BackupExecutablePath = Path.Combine(fixture.Root, "unrelated.exe.old")
        };
        await fixture.Store.SaveTransactionAsync(transaction);
        fixture.Environment.CurrentExecutablePath = fixture.StagedPath;

        var result = await fixture.CreateInstaller().ApplyTransactionAsync(fixture.Paths.TransactionPath);

        Assert.Equal(2, result);
        Assert.False(fixture.Environment.Contains(transaction.TargetExecutablePath));
    }

    [Fact]
    public async Task Recovery_does_not_clean_a_succeeded_transaction_for_another_installation_path()
    {
        using var fixture = new InstallerFixture();
        var transaction = fixture.CreateTransaction() with { Status = UpdateTransactionStatus.Succeeded };
        await fixture.Store.SaveTransactionAsync(transaction);
        fixture.Environment.CurrentExecutablePath = Path.Combine(fixture.Root, "different-install", "aznetcheck.exe");
        fixture.Environment.AddFile(transaction.BackupExecutablePath, [1, 2, 3]);

        var recovered = await fixture.CreateInstaller().RecoverPendingAsync();

        Assert.False(recovered);
        Assert.True(fixture.Environment.Contains(transaction.BackupExecutablePath));
        Assert.NotNull(await fixture.Store.LoadTransactionAsync());
    }

    [Fact]
    public async Task Recovery_ignores_transaction_with_manipulated_paths()
    {
        using var fixture = new InstallerFixture();
        var outsideTarget = Path.Combine(fixture.Root, "outside", "aznetcheck.exe");
        var transaction = fixture.CreateTransaction() with
        {
            TargetExecutablePath = outsideTarget,
            BackupExecutablePath = outsideTarget + ".old",
            Status = UpdateTransactionStatus.Succeeded
        };
        await fixture.Store.SaveTransactionAsync(transaction);
        fixture.Environment.CurrentExecutablePath = fixture.TargetPath;
        fixture.Environment.AddFile(outsideTarget + ".old", [7, 7, 7]);

        await fixture.CreateInstaller().RecoverPendingAsync();

        Assert.True(fixture.Environment.Contains(outsideTarget + ".old"));
    }

    [Fact]
    public async Task Recovery_preserves_a_fresh_downloaded_transaction_during_helper_startup_grace()
    {
        using var fixture = new InstallerFixture();
        var transaction = fixture.CreateTransaction() with { Status = UpdateTransactionStatus.Downloaded };
        await fixture.Store.SaveTransactionAsync(transaction);
        fixture.Environment.CurrentExecutablePath = transaction.TargetExecutablePath;

        var recovered = await fixture.CreateInstaller().RecoverPendingAsync();

        Assert.False(recovered);
        Assert.NotNull(await fixture.Store.LoadTransactionAsync());
    }

    [Fact]
    public async Task Recovery_cleans_a_stale_downloaded_transaction_without_touching_installation()
    {
        using var fixture = new InstallerFixture();
        var transaction = fixture.CreateTransaction() with
        {
            Status = UpdateTransactionStatus.Downloaded,
            CreatedAtUtc = DateTimeOffset.UtcNow.AddMinutes(-3)
        };
        await fixture.Store.SaveTransactionAsync(transaction);
        fixture.Environment.CurrentExecutablePath = transaction.TargetExecutablePath;

        var recovered = await fixture.CreateInstaller().RecoverPendingAsync();

        Assert.False(recovered);
        Assert.Null(await fixture.Store.LoadTransactionAsync());
        Assert.Equal([1, 2, 3], fixture.Environment.GetFile(transaction.TargetExecutablePath));
    }

    private sealed class InstallerFixture : IDisposable
    {
        public InstallerFixture()
        {
            Root = Path.Combine(Path.GetTempPath(), "AzNetCheck-installer-tests", Guid.NewGuid().ToString("N"));
            InstallDirectory = Path.Combine(Root, "install");
            Directory.CreateDirectory(InstallDirectory);
            var downloadRoot = Path.Combine(Root, "downloads");
            Paths = new UpdatePaths(Path.Combine(Root, "state"), downloadRoot);
            Store = new UpdateStateStore(Paths);
            StagedPath = Path.Combine(Paths.GetVersionDownloadDirectory("1.4.0"), "aznetcheck-win-x64.exe");
            Directory.CreateDirectory(Path.GetDirectoryName(StagedPath)!);
            File.WriteAllBytes(StagedPath, StagedBytes);
            TargetPath = Path.Combine(InstallDirectory, "aznetcheck.exe");
            StagedHash = Convert.ToHexString(SHA256.HashData(StagedBytes)).ToLowerInvariant();
            StagedSize = StagedBytes.LongLength;
            Environment.AddFile(TargetPath, [1, 2, 3]);
            Environment.AddFile(StagedPath, StagedBytes);
        }

        public string Root { get; }
        public string InstallDirectory { get; }
        public string TargetPath { get; }
        public string StagedPath { get; }
        public string StagedHash { get; }
        public long StagedSize { get; }
        public byte[] StagedBytes { get; } = [9, 9, 9, 9];
        public UpdatePaths Paths { get; }
        public UpdateStateStore Store { get; }
        public FakeInstallEnvironment Environment { get; } = new();
        private FakeUpdateInstallLockProvider LockProvider { get; } = new();

        public UpdateTransaction CreateTransaction()
        {
            var transactionId = Guid.NewGuid().ToString("N");
            return new UpdateTransaction
            {
                TransactionId = transactionId,
                FromVersion = "1.3.0",
                ToVersion = "1.4.0",
                TargetExecutablePath = TargetPath,
                StagedExecutablePath = StagedPath,
                BackupExecutablePath = TargetPath + ".old",
                FailedExecutablePath = TargetPath + ".failed-" + transactionId,
                Sha256 = StagedHash,
                OldProcessId = 101,
                OldProcessStartedUtc = Environment.CurrentProcessStartedUtc,
                CreatedAtUtc = DateTimeOffset.UtcNow
            };
        }

        public UpdateInstaller CreateInstaller() => new(Store, Environment, lockProvider: LockProvider);
        public IDisposable AcquireInstallLock() => LockProvider.TryAcquire(TargetPath)!;

        public void Dispose()
        {
            try { if (Directory.Exists(Root)) Directory.Delete(Root, recursive: true); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }

    }

    private sealed class FakeUpdateInstallLockProvider : IUpdateInstallLockProvider
    {
        private int _held;

        public IDisposable? TryAcquire(string targetExecutablePath) =>
            Interlocked.CompareExchange(ref _held, 1, 0) == 0 ? new Lease(this) : null;

        public IDisposable? Acquire(string targetExecutablePath, TimeSpan timeout) => TryAcquire(targetExecutablePath);

        private sealed class Lease(FakeUpdateInstallLockProvider owner) : IDisposable
        {
            private FakeUpdateInstallLockProvider? _owner = owner;

            public void Dispose()
            {
                if (Interlocked.Exchange(ref _owner, null) is { } held)
                    Volatile.Write(ref held._held, 0);
            }
        }
    }

    private sealed class FakeInstallEnvironment : IUpdateInstallEnvironment
    {
        private readonly Dictionary<string, byte[]> _files = new(PathComparer);
        public bool SupportsSelfUpdate => true;
        public string? RuntimeIdentifier => "win-x64";
        public string? CurrentExecutablePath { get; set; }
        public int CurrentProcessId => 100;
        public DateTimeOffset CurrentProcessStartedUtc { get; } = DateTimeOffset.UtcNow.AddMinutes(-1);
        public bool Writable { get; set; } = true;
        public bool WaitResult { get; set; } = true;
        public bool FailReplace { get; set; }
        public bool BackupWasCreated { get; private set; }
        public bool WaitedForOldProcess { get; private set; }
        public int NextChildId { get; set; } = 200;
        public Dictionary<int, ProcessIdentity> Processes { get; } = [];
        public List<(string Path, IReadOnlyList<string> Arguments)> StartedProcesses { get; } = [];
        public Func<string, IReadOnlyList<string>, Task<IUpdateChildProcess>>? OnStart { get; set; }

        public void AddFile(string path, byte[] data) => _files[Path.GetFullPath(path)] = data.ToArray();
        public bool Contains(string path) => _files.ContainsKey(Path.GetFullPath(path));
        public byte[] GetFile(string path) => _files[Path.GetFullPath(path)];
        public bool FileExists(string path) => Contains(path);
        public long GetFileLength(string path) => GetFile(path).LongLength;
        public Task<byte[]> GetSha256Async(string path, CancellationToken cancellationToken) =>
            Task.FromResult(SHA256.HashData(GetFile(path)));
        public bool IsDirectoryWritable(string directory) => Writable;

        public ProcessIdentity? GetProcessIdentity(int processId) => Processes.GetValueOrDefault(processId);

        public Task<bool> WaitForExitAsync(ProcessIdentity identity, TimeSpan timeout, CancellationToken cancellationToken)
        {
            WaitedForOldProcess = true;
            return Task.FromResult(WaitResult);
        }

        public void CopyFile(string sourcePath, string destinationPath)
        {
            if (_files.ContainsKey(Path.GetFullPath(destinationPath))) throw new IOException("Destination exists.");
            _files[Path.GetFullPath(destinationPath)] = GetFile(sourcePath).ToArray();
        }

        public void ReplaceFile(string replacementPath, string targetPath, string backupPath)
        {
            if (FailReplace) throw new IOException("Injected replacement failure.");
            var replacement = Path.GetFullPath(replacementPath);
            var target = Path.GetFullPath(targetPath);
            var backup = Path.GetFullPath(backupPath);
            if (!_files.TryGetValue(replacement, out var replacementBytes) || !_files.TryGetValue(target, out var targetBytes))
                throw new IOException("Replacement or target is missing.");
            if (_files.ContainsKey(backup)) throw new IOException("Backup exists.");
            _files.Remove(replacement);
            _files.Remove(target);
            _files[backup] = targetBytes;
            BackupWasCreated = true;
            _files[target] = replacementBytes;
        }

        public void DeleteFile(string path) => _files.Remove(Path.GetFullPath(path));

        public IUpdateChildProcess StartProcess(string executablePath, IReadOnlyList<string> arguments, string workingDirectory)
        {
            StartedProcesses.Add((Path.GetFullPath(executablePath), arguments.ToArray()));
            if (OnStart is not null) return OnStart(executablePath, arguments).GetAwaiter().GetResult();
            return new FakeChildProcess(NextChildId++, exited: false);
        }

        public Task<bool> WaitForChildExitAsync(IUpdateChildProcess process, TimeSpan timeout, CancellationToken cancellationToken) =>
            Task.FromResult(process.HasExited);

        private static StringComparer PathComparer => OperatingSystem.IsWindows()
            ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
    }

    private sealed class FakeChildProcess(int id, bool exited) : IUpdateChildProcess
    {
        public int Id => id;
        public bool HasExited { get; private set; } = exited;
        public void Kill() => HasExited = true;
        public void Dispose() { }
    }
}