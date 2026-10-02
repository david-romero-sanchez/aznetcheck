using AzNetCheck.Updater;
using Xunit;

namespace AzNetCheck.Updater.Tests;

public sealed class UpdateStateStoreTests
{
    [Fact]
    public async Task Missing_state_starts_empty_and_saved_state_round_trips()
    {
        var root = Path.Combine(Path.GetTempPath(), "AzNetCheck-tests", Guid.NewGuid().ToString("N"));
        try
        {
            var store = new UpdateStateStore(new UpdatePaths(root));
            Assert.Null((await store.LoadAsync()).LastCheckUtc);
            var state = new UpdateState
            {
                LastCheckUtc = DateTimeOffset.UtcNow,
                FailedVersions = new() { ["1.4.0"] = new FailedUpdate(DateTimeOffset.UtcNow, "health-check-failed") }
            };
            await store.SaveAsync(state);

            var reloaded = await store.LoadAsync();
            Assert.Equal(state.LastCheckUtc, reloaded.LastCheckUtc);
            Assert.Equal("health-check-failed", reloaded.FailedVersions["1.4.0"].Reason);
            Assert.True(store.Paths.IsUnderStateRoot(store.Paths.TransactionPath));
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Corrupt_state_is_ignored()
    {
        var root = Path.Combine(Path.GetTempPath(), "AzNetCheck-tests", Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(root);
            await File.WriteAllTextAsync(Path.Combine(root, "state.json"), "{corrupt");
            var state = await new UpdateStateStore(new UpdatePaths(root)).LoadAsync();
            Assert.Null(state.LastCheckUtc);
            Assert.Empty(state.FailedVersions);
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }
}