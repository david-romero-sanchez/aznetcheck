using System.Security.Cryptography;
using System.Text;

namespace AzNetCheck.Updater;

public interface IUpdateInstallLockProvider
{
    IDisposable? TryAcquire(string targetExecutablePath);
    IDisposable? Acquire(string targetExecutablePath, TimeSpan timeout);
}

public sealed class NamedSemaphoreUpdateLockProvider : IUpdateInstallLockProvider
{
    public IDisposable? TryAcquire(string targetExecutablePath) => AcquireCore(targetExecutablePath, TimeSpan.Zero);

    public IDisposable? Acquire(string targetExecutablePath, TimeSpan timeout) => AcquireCore(targetExecutablePath, timeout);

    private static IDisposable? AcquireCore(string targetExecutablePath, TimeSpan timeout)
    {
        var fullPath = Path.GetFullPath(targetExecutablePath);
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(fullPath)))[..24];
        var semaphore = new Semaphore(1, 1, "Local\\AzNetCheck.Update." + hash);
        try
        {
            if (!semaphore.WaitOne(timeout))
            {
                semaphore.Dispose();
                return null;
            }
            return new SemaphoreLease(semaphore);
        }
        catch
        {
            semaphore.Dispose();
            throw;
        }
    }

    private sealed class SemaphoreLease(Semaphore semaphore) : IDisposable
    {
        private Semaphore? _semaphore = semaphore;

        public void Dispose()
        {
            var held = Interlocked.Exchange(ref _semaphore, null);
            if (held is null) return;
            try { held.Release(); }
            catch (SemaphoreFullException) { }
            finally { held.Dispose(); }
        }
    }
}
