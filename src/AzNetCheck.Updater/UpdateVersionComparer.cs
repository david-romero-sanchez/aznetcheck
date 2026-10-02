using NuGet.Versioning;

namespace AzNetCheck.Updater;

public static class UpdateVersionComparer
{
    public static bool TryParse(string? value, out NuGetVersion? version) =>
        NuGetVersion.TryParse(value, out version);

    public static int Compare(string left, string right)
    {
        if (!NuGetVersion.TryParse(left, out var leftVersion))
            throw new ArgumentException("Version is not valid SemVer.", nameof(left));
        if (!NuGetVersion.TryParse(right, out var rightVersion))
            throw new ArgumentException("Version is not valid SemVer.", nameof(right));
        return VersionComparer.VersionRelease.Compare(leftVersion, rightVersion);
    }

    public static bool IsNewer(string candidate, string current) => Compare(candidate, current) > 0;
}